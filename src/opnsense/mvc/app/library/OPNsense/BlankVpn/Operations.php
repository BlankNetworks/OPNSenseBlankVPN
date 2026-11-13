<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

final class Operations
{
    public static function exclusive(callable $work, bool $skipBusy = false): mixed
    {
        $path = Policy::stateDirectory() . '/operations.lock';
        $lock = fopen($path, 'ce');
        if ($lock === false) {
            throw new \RuntimeException('Blank VPN could not open its configuration lock.');
        }
        chmod($path, 0600);
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                if ($skipBusy) {
                    return null;
                }
                throw new \DomainException('Another Blank VPN operation is running. Try again shortly.');
            }
            return $work();
        } finally {
            fclose($lock);
        }
    }

    public static function change(callable $edit): array
    {
        $config = Config::getInstance();
        $config->lock();
        try {
            $original = $config->object()->asXML();
            $model = new BlankVpn();
            $result = $edit($model);
            $model->serializeToConfig();
            $config->save(['description' => 'Blank VPN configuration changed']);
            $expected = self::fingerprint($config->object());
        } finally {
            $config->unlock();
        }

        try {
            if (isset($result['added'])) {
                WireGuard::apply($result['added']);
            }
            if (isset($result['removed'])) {
                WireGuard::applyRemoval($result['removed']);
            }
            if (!empty($result['reload'])) {
                self::sync($model);
            }
            if (!empty($result['resetSegments'])) {
                self::resetSegments($result['resetSegments'], $result['settings']);
            }
            foreach ($result['killSwitchReset'] ?? [] as $ip) {
                self::resetKillSwitch($ip);
            }
        } catch (\Throwable $error) {
            try {
                self::rollback($original, $expected);
                if (isset($result['added']) || isset($result['removed'])) {
                    WireGuard::apply();
                }
                self::sync(new BlankVpn());
            } catch (\Throwable) {
                syslog(LOG_ERR, 'Blank VPN apply and rollback did not complete.');
                throw new \DomainException(
                    'Apply failed and automatic rollback could not be verified. Use the OPNsense console and configuration history to inspect the router.'
                );
            }
            $detail = $error instanceof \DomainException || $error::class === \RuntimeException::class
                ? ' ' . $error->getMessage() : '';
            throw new \DomainException('Apply failed. Blank VPN restored the preceding configuration and reloaded the firewall.' . $detail);
        }

        return $result;
    }

    private static function rollback(string $original, string $expected): void
    {
        $config = Config::getInstance();
        $config->forceReload()->lock();
        try {
            if (!hash_equals($expected, self::fingerprint($config->object()))) {
                throw new \RuntimeException('The native configuration changed during Blank VPN apply.');
            }
            $root = dom_import_simplexml($config->object());
            $snapshot = new \DOMDocument();
            if (!$snapshot->loadXML($original, LIBXML_NONET) || $root === false || $snapshot->documentElement === null) {
                throw new \RuntimeException('The Blank VPN rollback snapshot is invalid.');
            }
            while ($root->firstChild !== null) {
                $root->removeChild($root->firstChild);
            }
            foreach ($snapshot->documentElement->childNodes as $child) {
                $root->appendChild($root->ownerDocument->importNode($child, true));
            }
            $config->save(['description' => 'Blank VPN apply rolled back']);
        } finally {
            $config->unlock();
        }
    }

    private static function fingerprint(\SimpleXMLElement $root): string
    {
        $xml = dom_import_simplexml($root);
        return hash('sha256', (string)$xml->C14N());
    }

    public static function sync(BlankVpn $model): void
    {
        $backend = new Backend();
        if (trim($backend->configdRun('blankvpn proxies', false, 45)) !== 'ok') {
            throw new \RuntimeException('The Blank VPN proxy exits could not be reconciled.');
        }
        $settings = Policy::routingSettings(Policy::settings($model));
        $assignments = $settings['coverage'] === 'device' ? Policy::assignments($model) : [];
        $watchOutages = self::watchMultiPathOutages($settings, $assignments);
        $before = $watchOutages ? Firewall::loadedRules() : null;
        // Load DNS destination tables before a resolver can begin filling them.
        Firewall::reload($model);
        if ($watchOutages) {
            self::resetOutageStates($settings, $assignments, $before ?? [], Firewall::loadedRules());
        }
        if (trim($backend->configdRun('blankvpn resolver', false, 45)) !== 'ok') {
            throw new \RuntimeException('The Blank VPN DNS listeners could not be reconciled.');
        }
    }

    public static function watchMultiPathOutages(array $settings, array $assignments): bool
    {
        if (!$settings['enabled']) {
            return false;
        }
        if ($settings['coverage'] === 'network') {
            return $settings['networkMode'] === 'multi' && $settings['networkKillSwitch'];
        }
        foreach ($assignments as $row) {
            if (Policy::mode($row) === 'multi' && Policy::killSwitch($row)) {
                return true;
            }
        }
        return false;
    }

    public static function resetOutageStates(array $settings, array $assignments, array $before, ?array $after): void
    {
        if ($after === null) {
            throw new \RuntimeException('The active firewall rules could not be read after updating the kill switch.');
        }
        if ($settings['coverage'] === 'network') {
            $segments = [];
            foreach ($settings['interfaces'] as $interface) {
                $marker = Policy::marker('kill', 'network:' . $interface);
                if (($before[$marker]['action'] ?? '') !== 'block' && ($after[$marker]['action'] ?? '') === 'block') {
                    $segments[] = $interface;
                }
            }
            foreach (Policy::segmentNetworks($segments) as $network) {
                self::resetKillSwitch($network);
            }
            return;
        }
        foreach ($assignments as $id => $row) {
            if (Policy::mode($row) !== 'multi' || !Policy::killSwitch($row)) {
                continue;
            }
            $marker = Policy::marker('kill', $id);
            if (($before[$marker]['action'] ?? '') !== 'block' && ($after[$marker]['action'] ?? '') === 'block') {
                foreach (array_filter([$row['ip'], $row['ipv6'] ?? '']) as $ip) {
                    self::resetKillSwitch($ip);
                }
            }
        }
    }

    public static function resetKillSwitch(string $source): void
    {
        $network = str_contains($source, '/') ? Policy::cidr($source) : null;
        if ((!filter_var($source, FILTER_VALIDATE_IP) && $network === null) ||
            trim((new Backend())->configdpRun('blankvpn reset_ip', [$network ?? $source], false, 10)) !== 'ok') {
            throw new \RuntimeException('The firewall could not reset previous connections for this address or network.');
        }
    }

    public static function resetSegments(array $interfaces, array $settings): void
    {
        $networks = Policy::segmentNetworks($interfaces);
        $local = Policy::localNetworks($settings);
        $backend = new Backend();
        $raw = $backend->configdpRun('filter list states', ['', '2001', '0', '', ''], false, 12);
        $data = json_decode($raw, true);
        if (!is_array($data['details'] ?? null) || ($data['total_entries'] ?? 2001) > 2000) {
            throw new \RuntimeException('Too many firewall states to verify a scoped managed-segment activation.');
        }
        $states = [];
        foreach ($data['details'] as $state) {
            $source = (string)($state['src_addr'] ?? '');
            $destination = (string)($state['dst_addr'] ?? '');
            if (!self::inNetworks($networks, $source) ||
                ((int)($state['dst_port'] ?? 0) !== 53 && self::inNetworks($local, $destination))) {
                continue;
            }
            if (!preg_match('/^([0-9a-f]{16})\/([0-9a-f]{8})$/iD', (string)($state['id'] ?? ''), $match)) {
                throw new \RuntimeException('A managed-segment state could not be identified.');
            }
            $states[] = [$match[1], $match[2]];
        }
        if (count($states) > 128) {
            throw new \RuntimeException('Too many existing internet sessions on the newly managed segment.');
        }
        foreach ($states as $state) {
            $response = $backend->configdpRun('filter kill state', $state, false, 5);
            if (!preg_match('/\b[0-9]+ states? killed\b/i', $response)) {
                throw new \RuntimeException('An existing managed-segment session could not be reset.');
            }
        }
    }

    private static function inNetworks(array $networks, string $ip): bool
    {
        foreach ($networks as $network) {
            if (Policy::contains($network, $ip)) {
                return true;
            }
        }
        return false;
    }

    public static function switchDevice(string $ip, array $settings): array
    {
        $sessions = (new Diagnostics())->connections($ip);
        $networks = Policy::localNetworks($settings);
        $backend = new Backend();
        $count = 0;
        $failed = 0;
        foreach ($sessions['connections'] as $session) {
            $destination = $session['destination'];
            if ($session['source'] !== $ip || $destination === null || $session['stateId'] === null) {
                continue;
            }
            foreach ($networks as $network) {
                if ($session['destinationPort'] !== 53 && Policy::contains($network, $destination)) {
                    continue 2;
                }
            }
            $response = $backend->configdpRun('filter kill state', [$session['stateId'], $session['creatorId']], false, 5);
            if (preg_match('/\b([0-9]+) states? killed\b/i', $response, $match)) {
                $count += (int)$match[1];
            } else {
                $failed++;
            }
        }
        return ['closed' => $count, 'incomplete' => $failed > 0 || $sessions['truncated']];
    }
}
