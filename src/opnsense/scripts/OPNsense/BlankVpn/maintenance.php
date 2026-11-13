<?php

require_once('/usr/local/etc/inc/config.inc');

use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\NativeVpn;
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
            $rules = [];
            $output = Resolver::command(['/sbin/pfctl', '-sr']);
            foreach (explode("\n", $output) as $line) {
                if (preg_match('/\blabel "(blankvpn_[a-z0-9_]+)"/', $line, $match)) {
                    preg_match('/\broute-to\s+[({\s]*(wg[0-9]+|ovpnc[0-9]+|tun20[0-7])\b/', $line, $gateway);
                    preg_match('/^(?:@\d+\s+)?(pass|block|match)\b/', ltrim($line), $action);
                    preg_match('/\bfrom\s+([0-9.]+)(?:\/32)?\s/', $line, $source);
                    $rules[$match[1]] = [
                        'gateway' => $gateway[1] ?? null, 'action' => $action[1] ?? null, 'source' => $source[1] ?? null
                    ];
                }
            }
            echo json_encode((object)$rules, JSON_THROW_ON_ERROR), "\n";
            break;
        case 'proxies':
            ProxyRuntime::reconcile(new BlankVpn());
            echo "ok\n";
            break;
        case 'resolver':
            Resolver::reconcile(new BlankVpn());
            echo "ok\n";
            break;
        case 'smart_status':
            echo json_encode((object)SmartRouting::countLearned(SmartRouting::services(new BlankVpn())), JSON_THROW_ON_ERROR), "\n";
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
                                $config->save(['description' => 'Allow the Blank VPN Tailscale dashboard hostname']);
                            }
                        } finally {
                            $config->unlock();
                        }
                    }
                }
                if ($settings['enabled'] || Policy::profiles($model) !== [] || NativeVpn::routes($model) !== []) {
                    Operations::sync($model);
                }
            });
            break;
        case 'maintain':
            Operations::exclusive(function () {
                $model = new BlankVpn();
                ProxyCores::recover($model);
                $settings = Policy::routingSettings(Policy::settings($model));
                $proxyRoutes = ProxyRuntime::routes($model);
                ProxyCatalog::refreshDue(array_column($proxyRoutes, 'node'));
                $previousProxies = ProxyRuntime::lastStatus()['active'];
                $runningProxies = ProxyRuntime::reconcile($model)['active'];
                if (!$settings['enabled']) {
                    return;
                }
                Resolver::reconcile($model);
                if (gmdate('i') === '00') {
                    $services = SmartRouting::services($model);
                    if (SmartRouting::active($settings, $services)) {
                        SmartRouting::expire($services);
                    }
                    try {
                        (new Mullvad())->relays();
                    } catch (Throwable) {
                        syslog(LOG_WARNING, 'Blank VPN could not refresh the Mullvad catalog.');
                    }
                }
                $loaded = Firewall::loadedRules();
                $assignments = $settings['coverage'] === 'device' ? Policy::assignments($model) : [];
                $watchOutages = Operations::watchMultiPathOutages($settings, $assignments);
                $watchedExits = $watchOutages
                    ? array_fill_keys(array_column(SmartRouting::boundServices(SmartRouting::services($model)), 'profile'), true)
                    : [];
                $observedOutage = false;
                $old = Firewall::health();
                $routes = Policy::routes($model);
                $health = array_intersect_key($old, $routes);
                $changed = $runningProxies !== $previousProxies ||
                    @file_get_contents(Policy::STATE_DIR . '/local-networks') !==
                        implode("\n", Policy::localNetworks($settings)) . "\n";
                foreach ($routes as $id => $profile) {
                    if (($profile['kind'] ?? '') === 'proxy') {
                        if ($profile['slot'] % 4 !== (int)gmdate('i') % 4 && in_array($id, $runningProxies, true)) {
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
                    $segments = [];
                    if ($settings['coverage'] === 'network' && $settings['networkMode'] === 'full') {
                        foreach ($settings['interfaces'] as $interface) {
                            $marker = Policy::marker('device', 'network:' . $interface);
                            if (($loaded[$marker] ?? null) !== ($after[$marker] ?? null)) {
                                $segments[] = $interface;
                            }
                        }
                    }
                    if ($segments !== []) {
                        try {
                            Operations::resetSegments($segments, $settings);
                        } catch (\Throwable) {
                            syslog(LOG_WARNING, 'Blank VPN could not reset old sessions under Whole-Network coverage.');
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
                                        Operations::resetKillSwitch($ip);
                                    }
                                } else {
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
