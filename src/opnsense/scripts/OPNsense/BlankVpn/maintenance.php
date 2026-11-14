<?php

require_once('/usr/local/etc/inc/config.inc');

use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\DeviceBindings;
use OPNsense\BlankVpn\Diagnostics;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\NativeVpn;
use OPNsense\BlankVpn\OnDemand;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\ProxyCatalog;
use OPNsense\BlankVpn\ProxyCores;
use OPNsense\BlankVpn\ProxyRuntime;
use OPNsense\BlankVpn\Resolver;
use OPNsense\BlankVpn\SmartRouting;
use OPNsense\BlankVpn\WireGuard;

try {
    switch ($argv[1] ?? '') {
        case 'loaded':
            $rules = Firewall::parseLoadedRules(Resolver::command(['/sbin/pfctl', '-sr']));
            echo json_encode((object)$rules, JSON_THROW_ON_ERROR), "\n";
            break;
        case 'loaded_nat':
            echo Resolver::command(['/sbin/pfctl', '-sn']);
            break;
        case 'test_service_dns':
            $port = (int)($argv[2] ?? '');
            echo json_encode(Resolver::testAddresses($port, $argv[3] ?? ''), JSON_THROW_ON_ERROR), "\n";
            break;
        case 'matched_service_addresses':
            echo json_encode(SmartRouting::testLearnedAddresses($argv[2] ?? '', $argv[3] ?? ''),
                JSON_THROW_ON_ERROR), "\n";
            break;
        case 'proxies':
            $model = new BlankVpn();
            $activeProxies = array_fill_keys(ProxyRuntime::reconcile($model)['active'], true);
            $onDemand = OnDemand::exits($model);
            OnDemand::reconcileWireGuard($model, $onDemand);
            if ($onDemand !== []) {
                $proxies = ProxyRuntime::routes($model);
                $old = Firewall::health();
                $health = $old;
                foreach (array_keys($onDemand) as $id) {
                    if (!isset($proxies[$id]) || isset($activeProxies[$id])) {
                        $health[$id] = ['onDemand' => true];
                    }
                }
                if ($health !== $old) {
                    Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
                }
            }
            echo "ok\n";
            break;
        case 'resolver':
            Resolver::reconcile(new BlankVpn());
            echo "ok\n";
            break;
        case 'smart_status':
            $model = new BlankVpn();
            echo json_encode((object)SmartRouting::countLearned(Policy::effectiveRouting($model),
                SmartRouting::services($model)), JSON_THROW_ON_ERROR), "\n";
            break;
        case 'reset_ip':
            $ip = $argv[2] ?? '';
            $network = str_contains($ip, '/') ? Policy::cidr($ip) : null;
            if (!filter_var($ip, FILTER_VALIDATE_IP) && $network === null) {
                exit(64);
            }
            Resolver::command(['/sbin/pfctl', '-k', $network ?? $ip]);
            echo "ok\n";
            break;
        case 'reset_tailnet':
            $source = $argv[2] ?? '';
            if (!in_array($source, [Policy::TAILSCALE_V4, Policy::TAILSCALE_V6], true) &&
                !Policy::tailnetAddress($source) && !Policy::tailnetAddress($source, true)) {
                exit(64);
            }
            echo Diagnostics::resetTailnetStates($source) ? "ok\n" : "failed\n";
            break;
        case 'reload':
            $response = Resolver::command(['/usr/local/etc/rc.filter_configure', 'skip_alias']);
            if (!preg_match('/\bdone\.\s*$/', $response)) {
                throw new RuntimeException('Filter reload did not finish successfully.');
            }
            echo "ok\n";
            break;
        case 'post_install':
            Operations::exclusive(function () {
                $model = new BlankVpn();
                $settings = Policy::settings($model);
                if ($settings['dashboardBind'] === 'tailnet') {
                    $hostname = Resolver::magicDnsName();
                    if ($hostname !== '') {
                        $config = \OPNsense\Core\Config::getInstance();
                        $config->lock();
                        try {
                            if (Resolver::allowDashboardHostname($config->object(), $hostname)) {
                                $config->save(['description' => 'Allow the Blank VPN & Proxy Tailscale dashboard hostname']);
                            }
                        } finally {
                            $config->unlock();
                        }
                    }
                }
                if (Policy::anyEnabled($settings) || Policy::profiles($model) !== [] || NativeVpn::routes($model) !== [] ||
                    (string)(\OPNsense\Core\Config::getInstance()->object()->OPNsense->tailscale->settings->enabled ?? '') === '1') {
                    Operations::sync($model);
                }
            });
            break;
        case 'maintain':
            Operations::exclusive(function () {
                $model = new BlankVpn();
                $settings = Policy::effectiveRouting($model);
                // The root maintenance worker can read PF directly, without an IPC timeout
                // masquerading as an empty ruleset and failing every tunnel health check.
                $loaded = Firewall::parseLoadedRules(Resolver::command(['/sbin/pfctl', '-sr']));
                Policy::refreshMacConflicts($model);
                $assignments = Policy::deviceAssignments($settings,
                    Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()));
                $bindings = DeviceBindings::pending($model, $loaded);
                $bindingsChanged = $bindings['reset'] !== [] || $bindings['changed'];
                ProxyCores::recover($model);
                $proxyRoutes = ProxyRuntime::routes($model);
                ProxyCatalog::refreshDue(array_column($proxyRoutes, 'node'));
                $previousProxies = ProxyRuntime::lastStatus()['active'];
                $runningProxies = ProxyRuntime::reconcile($model, background: true)['active'];
                $onDemand = OnDemand::exits($model);
                OnDemand::reconcileWireGuard($model, $onDemand);
                $hourly = gmdate('i') === '00';
                if ($hourly) {
                    try {
                        Operations::pruneTableFiles();
                    } catch (RuntimeException) {
                        syslog(LOG_WARNING, 'Blank VPN could not check for obsolete firewall table files.');
                    }
                }
                if (!$settings['enabled']) {
                    if ($bindingsChanged || Operations::pathReloadPending()) {
                        Operations::reloadRoutingPaths($model, $settings, $assignments, $loaded, bindings: $bindings);
                    }
                    if ($hourly) {
                        Resolver::reconcile($model);
                        SmartRouting::pruneLearnedTables($settings, []);
                    }
                    return;
                }
                $services = SmartRouting::services($model);
                if ($hourly) {
                    SmartRouting::expire($settings, $services);
                    try {
                        (new Mullvad())->relays();
                    } catch (Throwable) {
                        syslog(LOG_WARNING, 'Blank VPN could not refresh the Mullvad catalog.');
                    }
                }
                $runningProxySet = array_fill_keys($runningProxies, true);
                $previousProxySet = array_fill_keys($previousProxies, true);
                $forward = SmartRouting::forwardServices($settings, $services);
                $selected = Operations::policyProbeExits($settings, $assignments, $forward);
                $watchedExits = array_fill_keys(Operations::killSwitchProbeExits(
                    $settings, $assignments, $forward
                ), true);
                $failedExits = [];
                $old = Firewall::health();
                $routes = Policy::routes($model);
                $health = array_intersect_key($old, $routes);
                $changed = $runningProxies !== $previousProxies ||
                    @file_get_contents(Policy::STATE_DIR . '/local-networks') !==
                        implode("\n", Policy::localNetworks($settings)) . "\n";
                foreach ($routes as $id => $profile) {
                    if (!isset($selected[$id]) || !empty($profile['disabled'])) {
                        continue;
                    }
                    if (isset($onDemand[$id]) &&
                        (($profile['kind'] ?? '') !== 'proxy' || isset($runningProxySet[$id]))) {
                        // A routed first packet starts the tunnel. An old probe failure
                        // must not prevent the client from reaching an idle exit again.
                        $changed = $changed || (($health[$id]['reachable'] ?? true) === false);
                        if (($profile['kind'] ?? '') === 'native' && ($health[$id]['source'] ?? null) !== $profile['address']) {
                            $changed = true;
                        }
                        $health[$id] = ['onDemand' => true];
                        if (($profile['kind'] ?? '') === 'native') {
                            $health[$id]['source'] = $profile['address'];
                        }
                        continue;
                    }
                    if (($profile['kind'] ?? '') === 'proxy') {
                        if ($profile['slot'] % 4 !== (int)gmdate('i') % 4 &&
                            isset($runningProxySet[$id], $previousProxySet[$id]) &&
                            empty($old[$id]['onDemand'])) {
                            continue;
                        }
                        $probe = ProxyRuntime::probe($profile);
                    } else {
                        $verified = Firewall::probePathInstalled($profile, $loaded);
                        if (!$verified && ($profile['address'] ?? '') !== '' && (int)gmdate('i') % 4 === 0) {
                            // Rebuild a missing pin after a tunnel starts late. Never send an unpinned probe.
                            $changed = true;
                        }
                        $probe = ($profile['kind'] ?? '') === 'native'
                            ? WireGuard::probeSource($verified ? $profile['address'] : '')
                            : WireGuard::probe($profile, $verified);
                    }
                    $observation = Operations::probeObservation(
                        $old[$id] ?? [], $profile, $probe['reachable'] ?? null, isset($watchedExits[$id]), time()
                    );
                    if ($observation['health'] !== []) {
                        $health[$id] = $observation['health'];
                    }
                    $changed = $changed || $observation['reload'];
                    if ($observation['failed']) {
                        $failedExits[] = $id;
                    }
                }
                if ($changed || $bindingsChanged || Operations::pathReloadPending()) {
                    Operations::reloadRoutingPaths($model, $settings, $assignments, $loaded,
                        bindings: $bindings, failedExits: $failedExits, health: $health);
                } else {
                    if ($health !== $old) {
                        Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
                    }
                    Resolver::reconcile($model);
                }
                if ($hourly) {
                    SmartRouting::pruneLearnedTables($settings, $services);
                }
            }, true);
            break;
        default:
            exit(64);
    }
} catch (Throwable) {
    syslog(LOG_ERR, 'Blank VPN maintenance could not finish.');
    exit(1);
}
