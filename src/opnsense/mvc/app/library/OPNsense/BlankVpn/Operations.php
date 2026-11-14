<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

final class Operations
{
    private const PATH_RELOAD = 'health-reload';
    private const TABLE_FILE_MAX_AGE = 86400;

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
                self::sync($model, $result['killSwitchReset'] ?? []);
            }
            if (isset($result['networkProxy'])) {
                self::verifyNetworkProxy($result['networkProxy'], $result['settings']);
            }
            if (!empty($result['resetSegments'])) {
                self::resetSegments($result['resetSegments'], $result['settings']);
            }
            if (empty($result['reload'])) {
                foreach ($result['killSwitchReset'] ?? [] as $ip) {
                    self::resetKillSwitch($ip);
                }
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
        $loaded = Firewall::loadedRules();
        $routing = Policy::routingSettings($settings);
        $ready = ProxyRuntime::ready($proxy);
        foreach ($routing['interfaces'] as $interface) {
            $id = 'network:' . $interface;
            $route = ($loaded[Policy::marker('device', $id)]['gateway'] ?? null) === $proxy['interface'];
            $guarded = ($loaded[Policy::marker('kill_v6', $id)]['action'] ?? null) === 'block' &&
                ($loaded[Policy::marker('kill', $id)]['action'] ?? null) === 'block';
            if ($routing['networkKillSwitch'] && $guarded) {
                continue;
            }
            if (!$ready) {
                $status = ProxyRuntime::lastStatus();
                throw new \RuntimeException($status['errors'][$proxy['id']] ?? 'The selected proxy tunnel did not start.');
            }
            if (!$route) {
                throw new \RuntimeException('The selected proxy is unavailable for routing. Test the server in Proxies and try again.');
            }
            if (($loaded[Policy::marker('kill_v6', $id)]['action'] ?? null) !== 'block' ||
                $routing['networkKillSwitch']) {
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

    public static function sync(BlankVpn $model, array $reset = []): void
    {
        $backend = new Backend();
        if (trim($backend->configdRun('blankvpn proxies', false, 45)) !== 'ok') {
            throw new \RuntimeException('The Blank VPN & Proxy proxy exits could not be reconciled.');
        }
        $settings = Policy::effectiveRouting($model);
        Policy::refreshMacConflicts($model);
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
        $before = Firewall::loadedRules() ?? [];
        $bindings = DeviceBindings::pending($model, $before);
        // Load DNS destination tables before a resolver can begin filling them.
        self::reloadRoutingPaths($model, $settings, $assignments, $before, bindings: $bindings, reset: $reset);
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
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
        $recovering = ($previous['reachable'] ?? true) === false;
        $maxAge = ($route['kind'] ?? '') === 'proxy' ? 300 : 180;
        $services = SmartRouting::forwardServices($settings, SmartRouting::services($model));
        $clearOutage = in_array($id, self::killSwitchProbeExits($settings, $assignments, $services), true) &&
            (empty($previous['probeSucceeded']) || time() - ($previous['checkedAt'] ?? 0) > $maxAge);
        if ($recovering || $clearOutage || self::pathReloadPending()) {
            $before = Firewall::loadedRules() ?? [];
            self::reloadRoutingPaths($model, $settings, $assignments, $before, health: $health);
        } else {
            Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
        }
    }

    public static function killSwitchProbeExits(array $settings, array $assignments, array $services): array
    {
        if (!$settings['enabled']) {
            return [];
        }
        $exits = [];
        $watchServices = false;
        if ($settings['coverage'] === 'network') {
            $mode = $settings['networkMode'];
            if ($settings['networkKillSwitch']) {
                $watchServices = Policy::usesMultiPath($mode);
                if (Policy::usesBase($mode)) {
                    $exits[] = $settings['networkProfile'];
                }
            }
        } else {
            foreach ($assignments as $row) {
                if (Policy::assignmentPaused($row) || !in_array($row['interface'], $settings['interfaces'], true) ||
                    !Policy::killSwitch($row)) {
                    continue;
                }
                $mode = Policy::mode($row);
                $watchServices = $watchServices || Policy::usesMultiPath($mode);
                if (Policy::usesBase($mode)) {
                    $exits[] = $row['profile'];
                }
            }
        }
        if ($watchServices) {
            array_push($exits, ...array_column($services, 'profile'));
        }
        return array_values(array_unique(array_filter($exits)));
    }

    public static function policyProbeExits(array $settings, array $assignments, array $services): array
    {
        $selected = array_column($services, 'profile');
        if ($settings['coverage'] === 'network') {
            if (Policy::usesBase($settings['networkMode'])) {
                $selected[] = $settings['networkProfile'];
            }
        } else {
            foreach ($assignments as $row) {
                if (($row['ip'] ?? '') !== '' && !Policy::assignmentPaused($row) &&
                    in_array($row['interface'], $settings['interfaces'], true) &&
                    Policy::usesBase(Policy::mode($row))) {
                    $selected[] = $row['profile'];
                    if (!Policy::killSwitch($row) && ($row['failure'] ?? '') === 'backup') {
                        $selected[] = $row['backup'];
                    }
                }
            }
        }
        return array_fill_keys(array_filter($selected), true);
    }

    public static function pathReloadPending(): bool
    {
        return is_file(Policy::STATE_DIR . '/' . self::PATH_RELOAD);
    }

    public static function pruneTableFiles(): void
    {
        $output = Resolver::command(['/sbin/pfctl', '-s', 'Tables', '-v']);
        $tables = preg_split('/\s+/', trim($output), -1, PREG_SPLIT_NO_EMPTY);
        $seen = array_fill_keys($tables, true);
        $cutoff = time() - self::TABLE_FILE_MAX_AGE;
        foreach (new \FilesystemIterator(Policy::stateDirectory(), \FilesystemIterator::SKIP_DOTS) as $entry) {
            $name = $entry->getFilename();
            if (isset($seen[$name]) ||
                !self::tableCacheName($name) ||
                $entry->isLink() || !$entry->isFile()) {
                continue;
            }
            $path = $entry->getPathname();
            clearstatcache(true, $path);
            $modified = @filemtime($path);
            if ($modified !== false && $modified < $cutoff) {
                @unlink($path);
            }
        }
    }

    private static function tableCacheName(string $name): bool
    {
        return preg_match('/^(?:bv[ix]_[a-f0-9]{24}|blankvpn_(?:(?:cs|bi|be)_[a-f0-9]{19}|src_[a-f0-9]{18}))$/D', $name) === 1;
    }

    public static function reloadRoutingPaths(
        BlankVpn $model,
        array $settings,
        array $assignments,
        array $before,
        ?array $bindings = null,
        array $failedExits = [],
        ?array $health = null,
        array $reset = []
    ): void {
        $path = Policy::STATE_DIR . '/' . self::PATH_RELOAD;
        $raw = self::pathReloadPending() ? file_get_contents($path) : false;
        $pending = is_string($raw) ? json_decode($raw, true) : null;
        $originalRules = $pending['before'] ?? null;
        $priorReset = $pending['reset'] ?? [];
        $priorFailedExits = $pending['failedExits'] ?? [];
        // Retain the original loaded rules if a reload or any subsequent reset is interrupted.
        $before = is_array($originalRules) ? $originalRules : ($raw === false ? $before : []);
        $legacyReset = !empty($pending['legacyReset']) || !empty($pending['observedOutage']) ||
            (is_string($raw) && !is_array($originalRules));
        $failedExits = array_values(array_unique([...$failedExits, ...(is_array($priorFailedExits) ? $priorFailedExits : [])]));
        $reset = array_values(array_unique([...$reset, ...(is_array($priorReset) ? $priorReset : [])]));
        Policy::writeState(self::PATH_RELOAD,
            json_encode(compact('before', 'failedExits', 'legacyReset', 'reset'), JSON_THROW_ON_ERROR));
        if ($health !== null) {
            Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
        }
        Firewall::reload($model);
        $after = Firewall::loadedRules();
        if ($after === null) {
            throw new \RuntimeException('The active firewall rules could not be read after updating routing paths.');
        }
        $services = SmartRouting::forwardServices($settings, SmartRouting::services($model));
        $scopes = array_unique([
            ...$reset, ...self::killSwitchStateScopes($settings, $assignments, $services, $before, $after, $failedExits, $legacyReset)
        ]);
        if ($bindings !== null) {
            DeviceBindings::finish($bindings);
            $scopes = array_diff($scopes, $bindings['reset']);
        }
        foreach ($scopes as $scope) {
            self::resetKillSwitch($scope);
        }
        // Protected DNS verifies the newly installed PF pins before bringing listeners online.
        if (trim((new Backend())->configdRun('blankvpn resolver', false, 45)) !== 'ok') {
            throw new \RuntimeException('The Blank VPN & Proxy DNS listeners could not be reconciled.');
        }
        if (!unlink($path)) {
            throw new \RuntimeException('The routing paths changed, but the pending connection reset could not be cleared.');
        }
    }

    public static function killSwitchStateScopes(
        array $settings,
        array $assignments,
        array $services,
        array $before,
        array $after,
        array $failedExits = [],
        bool $legacyReset = false
    ): array {
        if (!$settings['enabled']) {
            return [];
        }
        $network = $settings['coverage'] === 'network';
        $segments = [];
        $ipv4Interfaces = [];
        $ipv6Interfaces = [];
        $scopes = [];
        $serviceOutage = array_intersect($failedExits, array_column($services, 'profile')) !== [];
        $byInterface = [];
        foreach ($assignments as $id => $row) {
            if (!Policy::assignmentPaused($row)) {
                $byInterface[$row['interface']][$id] = $row;
            }
        }
        foreach ($settings['interfaces'] as $interface) {
            $serviceChanged = false;
            $directRemoved = false;
            foreach (['inet', 'inet6'] as $family) {
                foreach (['static', 'learned'] as $type) {
                    $bypass = Policy::marker('bypass', $interface . ':' . $family . ':' . $type);
                    if (($before[$bypass]['action'] ?? '') === 'pass' && ($after[$bypass]['action'] ?? '') !== 'pass') {
                        $directRemoved = true;
                        break 2;
                    }
                }
            }
            if (in_array($interface, $settings['smartInterfaces'], true)) {
                foreach ($services as $service) {
                    foreach (['service', 'service_dns'] as $type) {
                        $marker = Policy::marker($type, $service['id'] . ':' . $interface);
                        if (($before[$marker] ?? null) !== ($after[$marker] ?? null)) {
                            $serviceChanged = true;
                            break 2;
                        }
                    }
                }
            }
            $sharedIpv6 = Policy::marker('kill_interface_v6', $interface);
            if (($after[$sharedIpv6]['action'] ?? '') === 'block' &&
                ($before[$sharedIpv6]['action'] ?? '') !== 'block') {
                $ipv6Interfaces[] = $interface;
            }
            $unbound = Policy::marker('kill_unbound_v4', $interface);
            if (($after[$unbound]['action'] ?? '') === 'block' &&
                ($before[$unbound]['action'] ?? '') !== 'block') {
                $ipv4Interfaces[] = $interface;
            }
            if ($network) {
                $id = 'network:' . $interface;
                $mode = $settings['networkMode'];
                $outage = $legacyReset || (Policy::usesBase($mode) && in_array($settings['networkProfile'], $failedExits, true)) ||
                    (Policy::usesMultiPath($mode) && $serviceOutage);
                if (self::routingPathChanged($id, $before, $after, $outage) ||
                    (Policy::usesMultiPath($mode) && $serviceChanged) ||
                    ($directRemoved && !empty($settings['networkKillSwitch']) &&
                        (Policy::usesBase($mode) || Policy::usesMultiPath($mode))) ||
                    ($before[Policy::marker('bypass', $id)]['action'] ?? '') === 'match') {
                    $segments[] = $interface;
                }
                continue;
            }
            foreach ($byInterface[$interface] ?? [] as $id => $row) {
                $mode = Policy::mode($row);
                $outage = $legacyReset || (Policy::usesBase($mode) && in_array($row['profile'] ?? '', $failedExits, true)) ||
                    (Policy::usesMultiPath($mode) && $serviceOutage);
                if (self::routingPathChanged($id, $before, $after, $outage) ||
                    ($directRemoved && Policy::killSwitch($row)) ||
                    ($serviceChanged && Policy::usesMultiPath($mode))) {
                    array_push($scopes, $row['ip'], $row['ipv6'] ?? '');
                }
            }
        }
        foreach ([$ipv4Interfaces, $ipv6Interfaces] as $v6 => $interfaces) {
            foreach (Policy::segmentNetworks($interfaces) as $prefix) {
                if (str_contains($prefix, ':') === (bool)$v6) {
                    $scopes[] = $prefix;
                }
            }
        }
        return array_values(array_unique(array_filter([...$scopes, ...Policy::segmentNetworks($segments)])));
    }

    private static function routingPathChanged(string $id, array $before, array $after, bool $observedOutage): bool
    {
        foreach (['device', 'kill', 'kill_v6'] as $type) {
            $marker = Policy::marker($type, $id);
            if (($before[$marker] ?? null) !== ($after[$marker] ?? null)) {
                return true;
            }
        }
        foreach (['inet', 'inet6'] as $family) {
            $fallback = Policy::marker('wan_fallback', $id . ':' . $family);
            $outage = Policy::marker('kill_outage', $id . ':' . $family);
            if (($before[$fallback] ?? null) !== ($after[$fallback] ?? null) ||
                ($before[$outage] ?? null) !== ($after[$outage] ?? null) ||
                ($observedOutage && ($after[$outage]['action'] ?? '') === 'block')) {
                return true;
            }
        }
        return false;
    }

    public static function serviceStateScopes(array $settings, array $assignments): array
    {
        if (!$settings['enabled']) {
            return [];
        }
        if ($settings['coverage'] === 'network') {
            return Policy::usesMultiPath($settings['networkMode']) ? Policy::segmentNetworks($settings['interfaces']) : [];
        }
        $scopes = [];
        foreach ($assignments as $row) {
            if (Policy::usesMultiPath(Policy::mode($row)) && Policy::killSwitch($row) &&
                !Policy::assignmentPaused($row) && in_array($row['interface'], $settings['interfaces'], true)) {
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
