<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

final class DeviceBindings
{
    private const FILE = 'device-bindings.json';

    /** Call with the operation lock held, before installing the new PF rules. */
    public static function pending(BlankVpn $model, ?array $loaded = null): array
    {
        $settings = Policy::effectiveRouting($model);
        $rows = Policy::assignments($model, true);
        $active = $settings['enabled'] && $settings['coverage'] === 'device';
        $assignments = $active ? Policy::routingAssignments($rows, new Diagnostics()) : [];
        $scopes = [];
        foreach ($assignments as $id => $row) {
            if (Policy::bindsMac($row) && in_array($row['interface'], $settings['interfaces'], true) &&
                in_array(Policy::mode($row), ['full', 'multi', 'full_multi', 'blocked'], true)) {
                $ip = self::address($row['ip'] ?? null);
                if ($ip !== null) {
                    $scopes[$id] = $ip;
                }
            }
        }

        $saved = self::read();
        $previous = $saved;
        foreach ($rows as $id => $row) {
            if (isset($previous[$id]) || !Policy::bindsMac($row)) {
                continue;
            }
            // A newly MAC-bound rule can replace an already installed fixed-IP rule.
            foreach (['device', 'kill'] as $kind) {
                $source = self::address($loaded[Policy::marker($kind, $id)]['source'] ?? null);
                if ($source !== null) {
                    $previous[$id] = $source;
                    break;
                }
            }
        }
        return ['scopes' => $scopes, 'reset' => self::changedAddresses($previous, $scopes), 'changed' => $saved !== $scopes];
    }

    public static function changedAddresses(array $previous, array $current): array
    {
        $reset = [];
        foreach (array_unique([...array_keys($previous), ...array_keys($current)]) as $id) {
            $before = self::address($previous[$id] ?? null);
            $after = self::address($current[$id] ?? null);
            if ($before !== $after) {
                foreach (array_filter([$before, $after]) as $ip) {
                    $reset[$ip] = true;
                }
            }
        }
        return array_keys($reset);
    }

    /** Call only after the new PF policy has been loaded and verified. */
    public static function finish(array $pending): void
    {
        foreach ($pending['reset'] as $ip) {
            Operations::resetKillSwitch($ip);
        }
        // Preserve the last verified map if an individual reset or reload failed.
        if ($pending['scopes'] !== self::read()) {
            Policy::writeState(self::FILE, json_encode((object)$pending['scopes'], JSON_THROW_ON_ERROR));
        }
    }

    private static function read(): array
    {
        $path = Policy::STATE_DIR . '/' . self::FILE;
        if (!file_exists($path) && !is_link($path)) {
            return [];
        }
        if (is_link($path) || !is_file($path) || (fileperms($path) & 0077) !== 0) {
            throw new \RuntimeException('Blank VPN’s device binding state has unsafe permissions.');
        }
        $raw = @file_get_contents($path, false, null, 0, 65537);
        $record = is_string($raw) && strlen($raw) <= 65536 ? json_decode($raw, true, 4) : null;
        if (!is_array($record) || array_filter($record, static fn ($ip): bool => self::address($ip) === null) !== []) {
            throw new \RuntimeException('Blank VPN’s device binding state is unreadable.');
        }
        return $record;
    }

    private static function address(mixed $input): ?string
    {
        return is_string($input) && filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $input : null;
    }
}
