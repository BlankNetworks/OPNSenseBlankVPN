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
                if ($settings['enabled'] || Policy::profiles($model) !== [] || NativeVpn::routes($model) !== [] ||
                    (string)(\OPNsense\Core\Config::getInstance()->object()->OPNsense->tailscale->settings->enabled ?? '') === '1') {
                    Operations::sync($model);
                }
            });
            break;
        case 'maintain':
            Operations::exclusive(function () {
                $model = new BlankVpn();
                $settings = Policy::effectiveRouting($model);
                $loaded = Firewall::loadedRules();
                Policy::refreshMacConflicts($model);
                $bindings = DeviceBindings::pending($model, $loaded);
                if ($bindings['reset'] !== [] || $bindings['changed']) {
                    Firewall::reload($model);
                    DeviceBindings::finish($bindings);
                    $loaded = Firewall::loadedRules();
                }
                ProxyCores::recover($model);
                $proxyRoutes = ProxyRuntime::routes($model);
                ProxyCatalog::refreshDue(array_column($proxyRoutes, 'node'));
                $previousProxies = ProxyRuntime::lastStatus()['active'];
                $runningProxies = ProxyRuntime::reconcile($model)['active'];
                $onDemand = OnDemand::exits($model);
                OnDemand::reconcileWireGuard($model, $onDemand);
                if (!$settings['enabled']) {
                    return;
                }
                Resolver::reconcile($model);
                $services = SmartRouting::services($model);
                if (gmdate('i') === '00') {
                    SmartRouting::expire($settings, $services);
                    try {
                        (new Mullvad())->relays();
                    } catch (Throwable) {
                        syslog(LOG_WARNING, 'Blank VPN could not refresh the Mullvad catalog.');
                    }
                }
                $assignments = $settings['coverage'] === 'device'
                    ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
                $runningProxySet = array_fill_keys($runningProxies, true);
                $watchOutages = Operations::watchMultiPathOutages($settings, $assignments);
                $watchedExits = $watchOutages
                    ? array_fill_keys(array_column(SmartRouting::forwardServices($settings, $services), 'profile'), true)
                    : [];
                $observedOutage = false;
                $old = Firewall::health();
                $routes = Policy::routes($model);
                $health = array_intersect_key($old, $routes);
                $changed = $runningProxies !== $previousProxies ||
                    @file_get_contents(Policy::STATE_DIR . '/local-networks') !==
                        implode("\n", Policy::localNetworks($settings)) . "\n";
                $assignedProxies = ProxyRuntime::assignedRoutes($model);
                foreach ($routes as $id => $profile) {
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
                        if (!isset($assignedProxies[$id])) {
                            unset($health[$id]);
                            continue;
                        }
                        if ($profile['slot'] % 4 !== (int)gmdate('i') % 4 && isset($runningProxySet[$id]) &&
                            empty($old[$id]['onDemand'])) {
                            continue;
                        }
                        $probe = ProxyRuntime::probe($profile);
                    } elseif (($profile['kind'] ?? '') === 'native') {
                        $source = $profile['address'];
                        $changed = $changed || ($old[$id]['source'] ?? '') !== $source;
                        $verified = Firewall::probePathInstalled($profile, $loaded ?? []);
                        $probe = WireGuard::probeSource($verified ? $source : '');
                    } else {
                        $probe = WireGuard::probe($profile, Firewall::probePathInstalled($profile, $loaded ?? []));
                    }
                    $previous = $old[$id] ?? [];
                    $success = !empty($probe['reachable']);
                    $failures = $success ? 0 : min(2, ($previous['failures'] ?? 0) + 1);
                    $reachable = $success || ($failures < 2 && ($previous['reachable'] ?? true));
                    $health[$id] = [
                        'reachable' => $reachable, 'failures' => $failures, 'checkedAt' => time(),
                        'probeSucceeded' => $success
                    ];
                    if (($profile['kind'] ?? '') === 'native') {
                        $health[$id]['source'] = $source;
                    }
                    $probeChanged = ($previous['probeSucceeded'] ?? false) !== $success;
                    $watchExit = isset($watchedExits[$id]);
                    $observedOutage = $observedOutage || ($watchExit && $probeChanged && !$success);
                    $changed = $changed || ($previous['reachable'] ?? true) !== $reachable ||
                        ($watchExit && ($probeChanged || ($success && time() - ($previous['checkedAt'] ?? 0) >
                            (($profile['kind'] ?? '') === 'proxy' ? 300 : 180))));
                }
                Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
                $pending = Policy::STATE_DIR . '/health-reload';
                $retry = is_file($pending);
                if ($changed || $retry) {
                    Policy::writeState('health-reload', '1');
                    Firewall::reload($model);
                    $after = Firewall::loadedRules();
                    if ($watchOutages) {
                        // A native reload can install the guard while older direct connections still exist.
                        $beforeOutage = $retry || $observedOutage ? [] : ($loaded ?? []);
                        Operations::resetOutageStates($settings, $assignments, $beforeOutage, $after);
                    }
                    $combined = Policy::combinedProfiles($settings, $assignments);
                    if ($combined !== []) {
                        $changedPath = $retry;
                        foreach ($settings['smartInterfaces'] as $interface) {
                            foreach (SmartRouting::forwardServices($settings, $services) as $service) {
                                $marker = Policy::marker('service', $service['id'] . ':' . $interface);
                                $changedPath = $changedPath || ($loaded[$marker] ?? null) !== ($after[$marker] ?? null);
                            }
                        }
                        if ($changedPath) {
                            foreach (Operations::combinedStateScopes($settings, $assignments) as $scope) {
                                Operations::resetKillSwitch($scope);
                            }
                        }
                    }
                    if ($after !== null) {
                        foreach (Policy::segmentNetworks(Operations::networkPathChanges($settings, $loaded ?? [], $after)) as $network) {
                            Operations::resetKillSwitch($network);
                        }
                    }
                    foreach ($assignments as $id => $row) {
                        if ($row['profile'] === '') {
                            continue;
                        }
                        $marker = Policy::marker('device', $id);
                        if (($loaded[$marker] ?? null) !== ($after[$marker] ?? null)) {
                            try {
                                if (Policy::killSwitch($row)) {
                                    foreach (array_filter([$row['ip'], $row['ipv6'] ?? '']) as $ip) {
                                        if (!in_array($ip, $bindings['reset'], true)) {
                                            Operations::resetKillSwitch($ip);
                                        }
                                    }
                                } elseif ($row['ip'] !== '' && !in_array($row['ip'], $bindings['reset'], true)) {
                                    Operations::switchDevice($row['ip'], $settings);
                                }
                            } catch (Throwable) {
                                syslog(LOG_WARNING, 'Blank VPN could not reset a client’s old failover sessions.');
                            }
                        }
                    }
                    unlink($pending);
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
