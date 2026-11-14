<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

final class OnDemand
{
    public static function exits(BlankVpn $model): array
    {
        $settings = Policy::effectiveRouting($model);
        $assignments = Policy::assignments($model, true);
        $services = SmartRouting::forwardServices($settings, SmartRouting::services($model));
        return self::selectExits($settings, $assignments, $services);
    }

    public static function selectExits(array $settings, array $assignments, array $activeServices): array
    {
        if (!$settings['enabled'] || $settings['coverage'] !== 'device') {
            return [];
        }
        $always = array_fill_keys(array_column($activeServices, 'profile'), true);
        $onDemand = [];
        foreach ($assignments as $row) {
            $profile = $row['profile'] ?? '';
            if ($profile === '' || !Policy::usesBase(Policy::mode($row)) ||
                !in_array($row['interface'], $settings['interfaces'], true)) {
                continue;
            }
            if (Policy::onDemand($row) && Policy::killSwitch($row) && ($row['failure'] ?? 'block') === 'block') {
                $onDemand[$profile] = true;
            } else {
                $always[$profile] = true;
            }
            if (($row['failure'] ?? '') === 'backup' && ($row['backup'] ?? '') !== '') {
                $always[$row['backup']] = true;
            }
        }
        return array_diff_key($onDemand, $always);
    }

    public static function reconcileWireGuard(BlankVpn $model, array $onDemand): bool
    {
        $profiles = Policy::profiles($model);
        if ($profiles === []) {
            return true;
        }
        // Query the local kernel directly. This also runs inside a configd action.
        $keys = self::records(Resolver::command(['/usr/bin/wg', 'show', 'all', 'public-key'], false), 2);
        $peers = self::records(Resolver::command(['/usr/bin/wg', 'show', 'all', 'persistent-keepalive'], false), 3);
        $complete = true;
        foreach ($profiles as $id => $profile) {
            $interface = $profile['interface'] ?? '';
            $peer = $profile['peerKey'] ?? '';
            if (!preg_match('/\Awg[0-9]+\z/', $interface) || !self::validKey($peer) ||
                ($keys[$interface] ?? null) !== ($profile['identityKey'] ?? '') || !isset($peers[$interface][$peer]) ||
                count($peers[$interface]) !== 1 || !empty($profile['disabled'])) {
                continue;
            }
            $current = $peers[$interface][$peer];
            if (!preg_match('/\A(?:off|[0-9]{1,5})\z/', $current)) {
                continue;
            }
            $keepalive = isset($onDemand[$id]) ? 0 : (int)($profile['keepalive'] ?? 25);
            if ($keepalive === (int)$current || $keepalive < 0 || $keepalive > 65535 || !WireGuard::check($profile)['ok']) {
                continue;
            }
            try {
                Resolver::command(['/usr/bin/wg', 'set', $interface, 'peer', $peer, 'persistent-keepalive', (string)$keepalive]);
            } catch (\RuntimeException) {
                syslog(LOG_WARNING, 'Blank VPN could not reconcile a managed WireGuard peer’s keepalive setting.');
                $complete = false;
            }
        }
        return $complete;
    }

    private static function records(string $output, int $fields): array
    {
        $records = [];
        foreach (explode("\n", trim($output)) as $line) {
            $row = explode("\t", $line);
            if (count($row) === $fields) {
                if ($fields === 2) {
                    $records[$row[0]] = $row[1];
                } else {
                    $records[$row[0]][$row[1]] = $row[2];
                }
            }
        }
        return $records;
    }

    private static function validKey(string $key): bool
    {
        $bytes = strlen($key) === 44 ? base64_decode($key, true) : false;
        return $bytes !== false && strlen($bytes) === 32 && $bytes !== str_repeat("\0", 32) && base64_encode($bytes) === $key;
    }
}
