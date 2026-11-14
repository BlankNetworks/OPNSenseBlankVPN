<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use JsonException;
use RuntimeException;

final class RoutingBackup
{
    public const MAX_BYTES = 2097152;
    private const FORMAT = 'blank-vpn-routing-settings';
    private const VERSION = 1;
    private const KEY = 'routing-backup-identity';
    private const SETTINGS = [
        'enabled', 'interfaces', 'coverage', 'networkMode', 'networkProfile', 'networkKillSwitch',
        'strictInterfaces', 'smartInterfaces', 'smartAssignedOnly', 'tailscaleInterfaces', 'localNetworks',
    ];
    private const ASSIGNMENT = [
        'ip', 'interface', 'mac', 'ipv6', 'paused', 'kind', 'mode', 'label', 'profile', 'backup', 'killSwitch',
        'failure', 'onDemand', 'bindMac',
    ];
    private const CATALOG = ['worldwide', 'countries', 'cities'];

    public static function export(BlankVpn $model): array
    {
        $key = self::identity(true);
        $policy = self::snapshot($model);
        return self::envelope($policy, $key);
    }

    public static function preview(BlankVpn $model, string $json, string $user): array
    {
        [$current, $incoming, $key] = self::inspect($model, $json);
        $preview = self::summary($current, $incoming);
        return [
            'preview' => $preview,
            'confirmation' => self::confirmation($key, $user, $json, $current),
        ];
    }

    /** Called while holding both the Blank VPN & Proxy operation lock and the native configuration lock. */
    public static function restore(BlankVpn $model, string $json, string $user, string $confirmation): array
    {
        [$current, $incoming, $key] = self::inspect($model, $json);
        if (
            !preg_match('/^[0-9a-f]{64}$/D', $confirmation) ||
            !hash_equals(self::confirmation($key, $user, $json, $current), $confirmation)
        ) {
            throw new DomainException('Preview this file again. The backup or router routing settings have changed.');
        }

        foreach ($incoming['settings'] as $field => $value) {
            $model->settings->$field = $field === 'enabled' ? '0' : $value;
        }
        foreach ($incoming['mullvadCatalog'] as $field => $value) {
            $model->mullvadCatalog->$field = $value;
        }
        foreach (array_keys(Policy::assignments($model)) as $id) {
            $model->assignments->assignment->del($id);
        }
        foreach ($incoming['assignments'] as $row) {
            $node = $model->assignments->assignment->add($row['id']);
            self::fillNode($node, $row);
        }
        foreach (array_keys(SmartRouting::services($model)) as $id) {
            $model->services->service->del($id);
        }
        foreach ($incoming['services'] as $row) {
            $node = $model->services->service->add($row['id']);
            $node->name = $row['name'];
            $node->domains = implode(',', $row['domains']);
            $node->profile = $row['profile'];
        }
        if (count($model->performValidation()) !== 0) {
            throw new DomainException('OPNsense rejected the routing settings. Review existing interfaces and routes.');
        }
        return ['message' => 'Routing settings restored. Blank VPN & Proxy routing is disabled. Review the settings before enabling it.']
            + self::summary($current, $incoming);
    }

    private static function fillNode(object $node, array $row): void
    {
        unset($row['id']);
        foreach ($row as $field => $value) {
            if (in_array($field, ['bindMac', 'onDemand'], true) && $node->getChild($field) === null) {
                continue;
            }
            $node->$field = $value;
        }
    }

    private static function summary(array $current, array $incoming): array
    {
        return [
            'assignments' => count($incoming['assignments']),
            'services' => count($incoming['services']),
            'routeCount' => count($incoming['routes']),
            'interfaces' => self::interfaces($incoming['settings']),
            'coverage' => $incoming['settings']['coverage'],
            'networkMode' => $incoming['settings']['networkMode'],
            'existingAssignments' => count($current['assignments']),
            'existingServices' => count($current['services']),
            'sourceEnabled' => $incoming['settings']['enabled'] === '1',
            'routingEnabled' => false,
        ];
    }

    private static function inspect(BlankVpn $model, string $json): array
    {
        $key = self::identity(false);
        $incoming = self::decode($json, $key);
        $current = self::snapshot($model, false);
        if (Policy::settings($model)['enabled']) {
            throw new DomainException('Disable Blank VPN & Proxy routing before restoring a backup.');
        }

        $interfaces = Policy::availableInterfaces();
        $list = self::interfaces($incoming['settings']);
        $strict = self::csv($incoming['settings']['strictInterfaces']);
        $smart = self::csv($incoming['settings']['smartInterfaces']);
        $transit = self::csv($incoming['settings']['tailscaleInterfaces']);
        if (
            array_diff($list, array_keys($interfaces)) || array_diff([...$strict, ...$smart, ...$transit], $list)
            || array_intersect($strict, [...$smart, ...$transit])
            || array_filter($transit, static fn (string $id): bool => !Policy::tailnetInterface($id))
        ) {
            throw new DomainException('This backup references a missing or changed LAN, VLAN, or Tailscale transit interface.');
        }
        foreach ($incoming['interfaces'] as $id => $signature) {
            if (!isset($interfaces[$id]) || !hash_equals(self::interfaceSignature($interfaces[$id]), $signature)) {
                throw new DomainException('A LAN or VLAN used in this backup has moved to a different router interface.');
            }
        }
        if ($strict !== []) {
            Policy::segmentNetworks($strict);
        }
        if ($incoming['settings']['coverage'] === 'network' && $incoming['settings']['networkMode'] !== 'disabled' &&
            ($incoming['settings']['enabled'] === '1' || $list !== [])) {
            $segments = array_values(array_diff($list, $transit));
            if ($segments === []) {
                throw new DomainException('The saved Whole-Network policy has no usable LAN or VLAN.');
            }
            Policy::segmentNetworks($segments);
        }

        $live = Policy::routes($model);
        $nodestore = null;
        $signatures = self::routeManifest($model, $live, array_keys($incoming['routes']));
        foreach ($incoming['routes'] as $id => $signature) {
            if (!isset($signatures[$id]) || !hash_equals($signatures[$id], $signature)) {
                throw new DomainException('A VPN or proxy exit used in this backup is missing or changed. Restore the original exit before trying again.');
            }
            $route = $live[$id];
            if (($route['kind'] ?? '') === 'proxy') {
                $nodestore ??= ProxyCatalog::read()['nodes'];
            }
            $valid = match ($route['kind'] ?? '') {
                'native' => $route['configured'],
                'proxy' => isset($nodestore[$route['node']]) && empty($nodestore[$route['node']]['disabled']),
                default => WireGuard::check($route)['ok'],
            };
            if (!$valid) {
                throw new DomainException('A VPN or proxy exit used in this backup is unavailable. Review the tunnel or proxy setup.');
            }
        }
        $combined = array_filter($incoming['assignments'], static fn (array $row): bool => $row['mode'] === 'full_multi');
        $dnsLists = array_filter($incoming['services'], static fn (array $list): bool =>
            SmartRouting::hasDomains($list['domains']));
        foreach ([$incoming['settings']['networkProfile'], ...array_column($dnsLists, 'profile'),
            ...array_column($combined, 'profile')] as $id) {
            if ($id !== '' && $id !== SmartRouting::BYPASS && !SmartRouting::canResolve($live[$id])) {
                throw new DomainException('A saved network or Multi-Path exit needs working IPv4 DNS.');
            }
        }

        $diagnostics = new Diagnostics();
        $tailnet = null;
        $tailnetReady = null;
        $reservationIndex = null;
        foreach ($incoming['assignments'] as $row) {
            $interface = $row['interface'];
            if ($row['kind'] === 'lan' && !in_array($interface, $list, true)) {
                throw new DomainException('A saved device rule refers to an unmanaged interface.');
            }
            if ($row['kind'] === 'lan') {
                $reservationIndex ??= DeviceIdentity::index($diagnostics->reservations());
                $address = DeviceIdentity::effective($row, $reservationIndex);
                if ($address === null || ($row['bindMac'] !== '1' && $row['ip'] !== $address)) {
                    throw new DomainException('A saved LAN device no longer has a matching DHCP reservation. Restore the reservation before importing settings.');
                }
                if ($row['bindMac'] === '1' && $row['ip'] !== $address) {
                    throw new DomainException('A saved MAC-bound device now has a different reserved address. Save a new backup after reviewing the current settings.');
                }
            }
            if ($row['kind'] === 'tailnet' && $interface === Policy::TAILSCALE_DEVICE) {
                $tailnet ??= $diagnostics->tailnetStatus();
                $tailnetReady ??= $diagnostics->nativeTailnetSetup($tailnet);
                if ($row['paused'] !== '1' && !$tailnetReady['ready']) {
                    throw new DomainException($tailnetReady['reason']);
                }
                $peer = $diagnostics->tailnetPeer($row['ip'], $tailnet);
                if ($peer === null || !in_array($row['ipv6'], $peer['ipv6'] ?? [], true)) {
                    throw new DomainException('A saved native Tailscale peer no longer matches its current IPv4 and IPv6 addresses.');
                }
            } elseif ($row['kind'] === 'tailnet' && !in_array($interface, $transit, true)) {
                throw new DomainException('A saved Tailscale device refers to an unmanaged transit interface.');
            }
            if ($row['mode'] === 'multi' && in_array($interface, $strict, true)) {
                throw new DomainException('A saved Multi-Path device rule conflicts with strict device blocking on its interface.');
            }
        }
        return [$current, $incoming, $key];
    }

    private static function snapshot(BlankVpn $model, bool $requireComplete = true): array
    {
        $settings = array_intersect_key(Policy::fields($model->settings), array_flip(self::SETTINGS));
        $mullvadCatalog = array_intersect_key(Policy::fields($model->mullvadCatalog), array_flip(self::CATALOG));
        $reservationIndex = null;
        $assignments = [];
        foreach (Policy::assignments($model) as $id => $row) {
            $row = array_intersect_key($row, array_flip(self::ASSIGNMENT));
            $row['kind'] = ($row['kind'] ?? '') ?: 'lan';
            $row['mode'] = Policy::mode($row);
            if (Policy::bindsMac($row)) {
                $reservationIndex ??= DeviceIdentity::index((new Diagnostics())->reservations());
                $row['ip'] = DeviceIdentity::effective($row, $reservationIndex) ?? $row['ip'];
            }
            $assignments[] = ['id' => $id] + $row;
        }
        $services = array_values(SmartRouting::services($model));
        $references = self::references($settings, $assignments, $services);
        $routes = self::routeManifest($model, Policy::routes($model), $references);
        if ($requireComplete && count($routes) !== count($references)) {
            throw new DomainException('A routing policy refers to a missing exit. Correct the policy before exporting it.');
        }
        $available = Policy::availableInterfaces();
        $interfaces = [];
        foreach (self::interfaces($settings) as $id) {
            if (isset($available[$id])) {
                $interfaces[$id] = self::interfaceSignature($available[$id]);
            } elseif ($requireComplete) {
                throw new DomainException('A routing policy refers to a missing interface. Correct it before exporting.');
            }
        }
        return compact('settings', 'mullvadCatalog', 'interfaces', 'assignments', 'services', 'routes');
    }

    private static function interfaceSignature(array $interface): string
    {
        return hash('sha256', $interface['id'] . "\0" . $interface['device']);
    }

    private static function routeManifest(BlankVpn $model, array $live, array $ids): array
    {
        $manifest = [];
        foreach ($ids as $id) {
            if (!isset($live[$id])) {
                continue;
            }
            $route = $live[$id];
            $kind = $route['kind'] ?? 'wireguard';
            $identity = match ($kind) {
                'native' => [
                    (string)$model->nativeRoutes->route->getChild($id)->gatewayId, $route['protocol'],
                    $route['logicalInterface'], $route['interface'], $route['gateway'], $route['dns'],
                ],
                'proxy' => [$route['node'], $route['protocol'], $route['core']],
                default => [
                    $route['instance'], $route['peer'], $route['identityKey'], $route['peerKey'],
                    $route['endpoint'], $route['port'], $route['address'], $route['address6'], $route['dns'] ?? [],
                ],
            };
            $manifest[$id] = hash('sha256', json_encode([$kind, $identity], JSON_THROW_ON_ERROR));
        }
        ksort($manifest);
        return $manifest;
    }

    public static function envelope(array $policy, string $key): array
    {
        $policy = self::validatePolicy($policy);
        $backup = [
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'router' => hash_hmac('sha256', self::FORMAT, $key),
            'integrity' => self::integrity($key, $policy),
        ] + $policy;
        if (strlen(json_encode($backup, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)) > self::MAX_BYTES) {
            throw new DomainException('These routing settings exceed the 2 MiB backup limit.');
        }
        return $backup;
    }

    public static function decode(string $json, string $key): array
    {
        if ($json === '' || strlen($json) > self::MAX_BYTES) {
            throw new DomainException('Choose a Blank VPN & Proxy settings backup of up to 2 MiB.');
        }
        try {
            $document = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new DomainException('The uploaded file is not valid Blank VPN & Proxy settings JSON.');
        }
        if (!is_array($document) || ($document['format'] ?? null) !== self::FORMAT || ($document['version'] ?? null) !== self::VERSION) {
            throw new DomainException('The uploaded file is not a supported Blank VPN & Proxy routing settings backup.');
        }
        $router = $document['router'] ?? null;
        if (!is_string($router) || !hash_equals(hash_hmac('sha256', self::FORMAT, $key), $router)) {
            throw new DomainException('This backup is bound to its original Blank VPN & Proxy installation.');
        }
        $integrity = $document['integrity'] ?? null;
        unset($document['format'], $document['version'], $document['router'], $document['integrity']);
        $policy = self::validatePolicy($document);
        if (!is_string($integrity) || !hash_equals(self::integrity($key, $policy), $integrity)) {
            throw new DomainException('The backup file has changed since it was exported. Select the original file.');
        }
        return $policy;
    }

    private static function validatePolicy(array $document): array
    {
        self::keys($document, ['settings', 'mullvadCatalog', 'interfaces', 'assignments', 'services', 'routes']);
        $settings = $document['settings'] ?? null;
        if (!is_array($settings)) {
            throw new DomainException('The backup routing settings are invalid.');
        }
        self::keys($settings, self::SETTINGS);
        foreach (self::SETTINGS as $name) {
            self::text($settings[$name] ?? null, 2048);
        }
        self::oneOf($settings['enabled'], ['0', '1']);
        self::oneOf($settings['coverage'], ['device', 'network']);
        self::oneOf($settings['networkMode'], ['disabled', 'full', 'multi', 'full_multi', 'blocked']);
        self::oneOf($settings['networkKillSwitch'], ['', '0', '1']);
        self::oneOf($settings['smartAssignedOnly'], ['0', '1']);
        if (
            ($settings['networkProfile'] !== '' && !self::uuid($settings['networkProfile'])) ||
            ($settings['networkProfile'] !== '' &&
                ($settings['coverage'] !== 'network' || !Policy::usesBase($settings['networkMode']))) ||
            ($settings['enabled'] === '1' && $settings['coverage'] === 'network' &&
                Policy::usesBase($settings['networkMode']) && $settings['networkProfile'] === '')
        ) {
            throw new DomainException('The backup has an invalid Whole-Network exit.');
        }
        foreach (['interfaces', 'strictInterfaces', 'smartInterfaces', 'tailscaleInterfaces'] as $name) {
            $ids = self::csv($settings[$name]);
            if (count($ids) > 32 || count(array_unique($ids)) !== count($ids) ||
                array_filter($ids, static fn (string $id): bool => !Policy::interfaceId($id))) {
                throw new DomainException('The backup contains an invalid interface list.');
            }
        }
        $local = self::csv($settings['localNetworks']);
        if (count($local) > 32 || array_filter($local, static fn (string $network): bool => Policy::cidr($network) !== $network)) {
            throw new DomainException('The backup contains an invalid local-network exclusion.');
        }

        $mullvadCatalog = $document['mullvadCatalog'] ?? null;
        if (!is_array($mullvadCatalog)) {
            throw new DomainException('The backup contains invalid Mullvad catalog preferences.');
        }
        self::keys($mullvadCatalog, self::CATALOG);
        self::oneOf(self::text($mullvadCatalog['worldwide'] ?? null, 1), ['0', '1']);
        self::text($mullvadCatalog['countries'] ?? null, 16384);
        self::text($mullvadCatalog['cities'] ?? null, 16384);

        $assignments = self::rows($document['assignments'] ?? null, 1024);
        $services = self::rows($document['services'] ?? null, SmartRouting::MAX_SERVICES);
        $used = [];
        foreach ($assignments as &$row) {
            self::keys($row, ['id', ...self::ASSIGNMENT]);
            $row += ['onDemand' => '1', 'bindMac' => '0'];
            foreach (self::ASSIGNMENT as $name) {
                self::text($row[$name] ?? null, 400);
            }
            self::oneOf($row['kind'], ['lan', 'tailnet']);
            self::oneOf($row['mode'], ['full', 'multi', 'full_multi', 'disabled', 'blocked', 'default']);
            self::oneOf($row['failure'], ['block', 'backup', 'wan']);
            self::oneOf($row['killSwitch'], ['', '0', '1']);
            foreach (['paused', 'onDemand', 'bindMac'] as $flag) {
                self::oneOf($row[$flag], ['0', '1']);
            }
            self::text($row['label'], 400, '/^[^\p{C}<>]{0,100}$/uD');
            $nativeTailnet = $row['kind'] === 'tailnet' && $row['interface'] === Policy::TAILSCALE_DEVICE;
            if (
                !filter_var($row['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                (!$nativeTailnet && !Policy::interfaceId($row['interface'])) ||
                ($row['kind'] === 'lan' && !Policy::validMac($row['mac'])) ||
                ($row['kind'] === 'tailnet' && ($row['mac'] !== '' || $row['bindMac'] === '1' ||
                    !Policy::tailnetAddress($row['ip']) || !Policy::tailnetAddress($row['ipv6'], true))) ||
                ($row['ipv6'] !== '' && Policy::ipv6Address($row['ipv6']) !== $row['ipv6']) ||
                (Policy::usesBase($row['mode']) ? !self::uuid($row['profile']) : $row['profile'] !== '') ||
                ($row['mode'] === 'full_multi' && ($row['failure'] !== 'block' || $row['killSwitch'] !== '1')) ||
                ($row['failure'] === 'backup'
                    ? ($row['mode'] !== 'full' || $row['backup'] === $row['profile'] || !self::uuid($row['backup']))
                    : $row['backup'] !== '')
            ) {
                throw new DomainException('The backup contains an invalid device rule or exit reference.');
            }
            $identity = $row['kind'] === 'lan' ? 'mac:' . $row['mac'] : 'peer:' . $row['ip'];
            foreach (array_filter(['ip:' . $row['ip'], $row['ipv6'] === '' ? '' : 'ipv6:' . $row['ipv6'], $identity]) as $value) {
                $id = $row['interface'] . '/' . $value;
                if (isset($used[$id])) {
                    throw new DomainException('The backup contains duplicate devices or addresses on one interface.');
                }
                $used[$id] = true;
            }
        }
        unset($row);
        $forward = [];
        $bypass = [];
        foreach ($services as $row) {
            self::keys($row, ['id', 'name', 'domains', 'profile']);
            self::text($row['name'] ?? null, 256, '/^[^\p{C}<>]{1,64}$/uD');
            $profile = self::text($row['profile'] ?? null, 64);
            if ($profile !== '' && $profile !== SmartRouting::BYPASS && !self::uuid($profile)) {
                throw new DomainException('The backup contains an invalid Multi-Path exit reference.');
            }
            $domains = $row['domains'] ?? null;
            if (!is_array($domains) || !array_is_list($domains) || count($domains) > SmartRouting::MAX_DOMAINS) {
                throw new DomainException('The backup contains an invalid Multi-Path domain list.');
            }
            foreach ($domains as $domain) {
                self::text($domain, 254);
            }
            if (SmartRouting::destinations(implode(',', $domains)) !== $domains) {
                throw new DomainException('The backup contains an improperly formatted Multi-Path domain list.');
            }
            if ($profile === SmartRouting::BYPASS) {
                SmartRouting::checkOverlap($bypass, '', $domains);
                $bypass[$row['id']] = $row;
            } elseif ($profile !== '') {
                SmartRouting::checkOverlap($forward, '', $domains);
                $forward[$row['id']] = $row;
            }
        }
        $interfaces = self::signatures($document['interfaces'] ?? null, self::interfaces($settings));
        $routes = self::signatures($document['routes'] ?? null, self::references($settings, $assignments, $services));
        return compact('settings', 'mullvadCatalog', 'interfaces', 'assignments', 'services', 'routes');
    }

    private static function references(array $settings, array $assignments, array $services): array
    {
        $ids = [$settings['networkProfile'] ?? '', ...array_column($assignments, 'profile'),
            ...array_column($assignments, 'backup'), ...array_column($services, 'profile')];
        $ids = array_values(array_unique(array_diff($ids, ['', SmartRouting::BYPASS])));
        sort($ids);
        return $ids;
    }

    private static function interfaces(array $settings): array
    {
        $ids = self::csv($settings['interfaces'] ?? '');
        sort($ids);
        return $ids;
    }

    private static function rows(mixed $input, int $max): array
    {
        if (!is_array($input) || !array_is_list($input) || count($input) > $max) {
            throw new DomainException('The backup contains an invalid list or exceeds its supported size.');
        }
        $seen = [];
        foreach ($input as $row) {
            if (!is_array($row) || !self::uuid($row['id'] ?? null) || isset($seen[$row['id']])) {
                throw new DomainException('The backup contains an invalid or duplicate policy identifier.');
            }
            $seen[$row['id']] = true;
        }
        return $input;
    }

    private static function signatures(mixed $input, array $ids): array
    {
        if (!is_array($input) || count($input) !== count($ids) || array_diff($ids, array_keys($input))) {
            throw new DomainException('The backup does not include valid references for its rules.');
        }
        foreach ($input as $signature) {
            self::text($signature, 64, '/^[0-9a-f]{64}$/D');
        }
        ksort($input);
        return $input;
    }

    private static function keys(array $item, array $allowed): void
    {
        if (array_diff(array_keys($item), $allowed)) {
            throw new DomainException('The backup contains unsupported fields.');
        }
    }

    private static function text(mixed $value, int $max, string $pattern = '/^[^\x00-\x1f\x7f]*$/D'): string
    {
        if (!is_string($value) || strlen($value) > $max || preg_match($pattern, $value) !== 1) {
            throw new DomainException('The backup contains an invalid field value.');
        }
        return $value;
    }

    private static function oneOf(string $value, array $options): void
    {
        if (!in_array($value, $options, true)) {
            throw new DomainException('The backup contains an unsupported routing mode or option.');
        }
    }

    private static function uuid(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $value) === 1;
    }

    private static function csv(string $value): array
    {
        return $value === '' ? [] : explode(',', $value);
    }

    private static function identity(bool $create): string
    {
        $path = Policy::stateDirectory() . '/' . self::KEY;
        if (!file_exists($path) && !is_link($path)) {
            if (!$create) {
                throw new DomainException('No routing backup identity exists for this Blank VPN & Proxy installation.');
            }
            Policy::writeState(self::KEY, bin2hex(random_bytes(32)));
        }
        $mode = @fileperms($path);
        $key = !is_link($path) && is_file($path) && $mode !== false && ($mode & 0077) === 0
            ? @file_get_contents($path, false, null, 0, 65) : false;
        if (!is_string($key) || !preg_match('/^[0-9a-f]{64}$/D', $key)) {
            throw new RuntimeException('The local Blank VPN & Proxy backup identity could not be verified.');
        }
        return $key;
    }

    private static function confirmation(string $key, string $user, string $json, array $current): string
    {
        return hash_hmac('sha256', json_encode([
            'restore', $user, hash('sha256', $json), $current,
        ], JSON_THROW_ON_ERROR), $key);
    }

    private static function integrity(string $key, array $settings): string
    {
        return hash_hmac('sha256', json_encode([$settings, self::VERSION], JSON_THROW_ON_ERROR), $key);
    }
}
