<?php

require_once('/usr/local/etc/inc/config.inc');

use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\Policy;
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
                    preg_match('/\broute-to\s+\(?\s*(wg[0-9]+)\b/', $line, $gateway);
                    preg_match('/^(?:@\d+\s+)?(pass|block|match)\b/', ltrim($line), $action);
                    $rules[$match[1]] = ['gateway' => $gateway[1] ?? null, 'action' => $action[1] ?? null];
                }
            }
            echo json_encode((object)$rules, JSON_THROW_ON_ERROR), "\n";
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
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                exit(64);
            }
            Resolver::command(['/sbin/pfctl', '-k', $ip]);
            echo "ok\n";
            break;
        case 'reload':
            $response = Resolver::command(['/usr/local/etc/rc.filter_configure', 'skip_alias']);
            if (!preg_match('/\bdone\.\s*$/', $response)) {
                throw new RuntimeException('Filter reload did not finish successfully.');
            }
            echo "ok\n";
            break;
        case 'maintain':
            Operations::exclusive(function () {
                $model = new BlankVpn();
                $settings = Policy::settings($model);
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
                $old = Firewall::health();
                $health = [];
                $changed = false;
                foreach (Policy::profiles($model) as $id => $profile) {
                    $marker = Policy::marker('probe', $id . Policy::PROBE_IP);
                    $verifiedRule = ($loaded[$marker]['gateway'] ?? null) === ($profile['interface'] ?? '');
                    $probe = WireGuard::probe($profile, $verifiedRule);
                    $previous = $old[$id] ?? [];
                    $success = !empty($probe['reachable']);
                    $failures = $success ? 0 : min(2, ($previous['failures'] ?? 0) + 1);
                    $reachable = $success || ($failures < 2 && ($previous['reachable'] ?? true));
                    $health[$id] = [
                        'reachable' => $reachable, 'failures' => $failures, 'checkedAt' => time(),
                        'probeSucceeded' => $success
                    ];
                    $changed = $changed || ($previous['reachable'] ?? true) !== $reachable;
                }
                Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
                $pending = Policy::STATE_DIR . '/health-reload';
                if ($changed || is_file($pending)) {
                    Policy::writeState('health-reload', '1');
                    Firewall::reload($model);
                    $after = Firewall::loadedRules();
                    foreach (Policy::assignments($model) as $id => $row) {
                        if ($row['profile'] === '') {
                            continue;
                        }
                        $marker = Policy::marker('device', $id);
                        if (($loaded[$marker] ?? null) !== ($after[$marker] ?? null)) {
                            try {
                                if ($row['failure'] === 'block') {
                                    Operations::resetKillSwitch($row['ip']);
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
