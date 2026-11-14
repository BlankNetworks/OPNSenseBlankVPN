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
            throw new \RuntimeException('Blank VPN & Proxy could not open its configuration lock.');
        }
        chmod($path, 0600);
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                if ($skipBusy) {
                    return null;
                }
                throw new \DomainException('Another Blank VPN & Proxy operation is running. Try again shortly.');
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
            $config->save(['description' => 'Blank VPN & Proxy configuration changed']);
            $expected = self::fingerprint($config->object());
        } finally {
            $config->unlock();
        }

        try {
            if (!empty($result['dhcpProvider'])) {
                self::applyDhcpReservation($result['dhcpProvider']);
            }
            if (isset($result['added'])) {
                WireGuard::apply($result['added']);
            }
            if (isset($result['removed'])) {
                WireGuard::applyRemoval($result['removed']);
            }
            if (!empty($result['reload'])) {
                self::sync($model);
            }
            if (isset($result['networkProxy'])) {
                self::verifyNetworkProxy($result['networkProxy'], $result['settings']);
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
                if (!empty($result['dhcpProvider'])) {
                    self::applyDhcpReservation($result['dhcpProvider']);
                }
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
            throw new \DomainException('Apply failed. Blank VPN & Proxy restored the preceding configuration and reloaded the firewall.' . $detail);
        }

        return $result;
    }

    private static function applyDhcpReservation(string $provider): void
    {
        $backend = new Backend();
        if ($provider === 'Kea DHCPv4') {
            if (trim($backend->configdpRun('template reload', ['OPNsense/Kea'])) !== 'OK') {
                throw new \RuntimeException('OPNsense could not render the Kea DHCP configuration.');
            }
            $response = $backend->configdRun('kea restart', false, 20);
        } else {
            $response = $backend->configdRun('dnsmasq restart', false, 20);
        }
        if (trim($response) !== 'OK') {
            throw new \RuntimeException('OPNsense could not apply the DHCP reservation.');
        }
    }

    private static function verifyNetworkProxy(array $proxy, array $settings): void
    {
        if (!ProxyRuntime::ready($proxy)) {
            $status = ProxyRuntime::lastStatus();
            throw new \RuntimeException($status['errors'][$proxy['id']] ?? 'The selected proxy tunnel did not start.');
        }
        $loaded = Firewall::loadedRules();
        $routing = Policy::routingSettings($settings);
        foreach ($routing['interfaces'] as $interface) {
            $id = 'network:' . $interface;
            if (($loaded[Policy::marker('device', $id)]['gateway'] ?? null) !== $proxy['interface']) {
                throw new \RuntimeException('The selected proxy is unavailable for routing. Test the server in Proxies and try again.');
            }
            if (($loaded[Policy::marker('kill_v6', $id)]['action'] ?? null) !== 'block' ||
                ($routing['networkKillSwitch'] && ($loaded[Policy::marker('kill', $id)]['action'] ?? null) !== 'block')) {
                throw new \RuntimeException('OPNsense did not load the internet blocking rules for the selected proxy.');
            }
        }
    }

    private static function rollback(string $original, string $expected): void
    {
        $config = Config::getInstance();
        $config->forceReload()->lock();
        try {
            if (!hash_equals($expected, self::fingerprint($config->object()))) {
                throw new \RuntimeException('The native configuration changed during Blank VPN & Proxy apply.');
            }
            $root = dom_import_simplexml($config->object());
            $snapshot = new \DOMDocument();
            if (!$snapshot->loadXML($original, LIBXML_NONET) || $root === false || $snapshot->documentElement === null) {
                throw new \RuntimeException('The Blank VPN & Proxy rollback snapshot is invalid.');
            }
            while ($root->firstChild !== null) {
                $root->removeChild($root->firstChild);
            }
            foreach ($snapshot->documentElement->childNodes as $child) {
                $root->appendChild($root->ownerDocument->importNode($child, true));
            }
            $config->save(['description' => 'Blank VPN & Proxy apply rolled back']);
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
            throw new \RuntimeException('The Blank VPN & Proxy proxy exits could not be reconciled.');
        }
        $settings = Policy::effectiveRouting($model);
        Policy::refreshMacConflicts($model);
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
        $watchOutages = self::watchMultiPathOutages($settings, $assignments);
        $before = Firewall::loadedRules();
        $bindings = DeviceBindings::pending($model, $before ?? []);
        // Load DNS destination tables before a resolver can begin filling them.
        Firewall::reload($model);
        DeviceBindings::finish($bindings);
        if ($watchOutages) {
            self::resetOutageStates($settings, $assignments, $before ?? [], Firewall::loadedRules());
        }
        if (trim($backend->configdRun('blankvpn resolver', false, 45)) !== 'ok') {
            throw new \RuntimeException('The Blank VPN & Proxy DNS listeners could not be reconciled.');
        }
        // Upgrade the legacy Bypass policy without keeping states that could use an old base tunnel.
        $legacyBypass = array_filter($settings['interfaces'], static fn (string $interface): bool =>
            ($before[Policy::marker('bypass', 'network:' . $interface)]['action'] ?? '') === 'match');
        foreach (Policy::segmentNetworks($legacyBypass) as $network) {
            self::resetKillSwitch($network);
        }
    }

    public static function recordSuccessfulProbe(BlankVpn $model, array $route): void
    {
        $settings = Policy::effectiveRouting($model);
        if (!$settings['enabled']) {
            return;
        }
        $id = $route['id'];
        $health = Firewall::health();
        if (!empty($health[$id]['onDemand'])) {
            return;
        }
        $previous = $health[$id] ?? [];
        $health[$id] = ['reachable' => true, 'failures' => 0, 'checkedAt' => time(), 'probeSucceeded' => true];
        if (($route['kind'] ?? '') === 'native') {
            $health[$id]['source'] = $route['address'];
        }
        Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
        $recovering = ($previous['reachable'] ?? true) === false;
        $maxAge = ($route['kind'] ?? '') === 'proxy' ? 300 : 180;
        $services = SmartRouting::forwardServices($settings, SmartRouting::services($model));
        $clearOutage = self::watchMultiPathOutages($settings, $assignments) &&
            in_array($id, array_column($services, 'profile'), true) &&
            (empty($previous['probeSucceeded']) || time() - ($previous['checkedAt'] ?? 0) > $maxAge);
        if ($recovering || $clearOutage) {
            $before = Firewall::loadedRules() ?? [];
            Policy::writeState('health-reload', '1');
            Firewall::reload($model);
            $after = Firewall::loadedRules() ?? [];
            $scopes = Policy::segmentNetworks(self::networkPathChanges($settings, $before, $after));
            if ($recovering) {
                array_push($scopes, ...self::combinedStateScopes($settings, $assignments));
            }
            foreach (array_unique($scopes) as $scope) {
                self::resetKillSwitch($scope);
            }
            unlink(Policy::STATE_DIR . '/health-reload');
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

    public static function combinedStateScopes(array $settings, array $assignments): array
    {
        if (!$settings['enabled']) {
            return [];
        }
        if ($settings['coverage'] === 'network') {
            return $settings['networkMode'] === 'full_multi' ? Policy::segmentNetworks($settings['interfaces']) : [];
        }

        $scopes = [];
        foreach ($assignments as $row) {
            if (Policy::mode($row) === 'full_multi' && !Policy::assignmentPaused($row) &&
                in_array($row['interface'], $settings['interfaces'], true)) {
                array_push($scopes, $row['ip'], $row['ipv6'] ?? '');
            }
        }
        return array_values(array_unique(array_filter($scopes)));
    }

    public static function bypassStateScopes(array $settings, array $assignments): array
    {
        $scopes = [];
        foreach (Firewall::bypassScopes($settings, $assignments, new Diagnostics()) as $interface => $families) {
            if (($families['inet']['all'] ?? false) || ($families['inet6']['all'] ?? false)) {
                array_push($scopes, ...Policy::segmentNetworks([$interface]));
                continue;
            }
            foreach ($families as $scope) {
                array_push($scopes, ...$scope['sources']);
            }
        }
        return array_values(array_unique(array_filter($scopes)));
    }

    public static function networkPathChanges(array $settings, array $before, array $after): array
    {
        if ($settings['coverage'] !== 'network' || !Policy::usesBase($settings['networkMode'])) {
            return [];
        }
        return array_values(array_filter($settings['interfaces'], static function (string $interface) use ($before, $after): bool {
            $id = 'network:' . $interface;
            foreach ([
                Policy::marker('device', $id),
                Policy::marker('wan_fallback', $id . ':inet'),
                Policy::marker('wan_fallback', $id . ':inet6')
            ] as $marker) {
                if (($before[$marker] ?? null) !== ($after[$marker] ?? null)) {
                    return true;
                }
            }
            return false;
        }));
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
