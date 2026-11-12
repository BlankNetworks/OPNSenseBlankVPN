<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Plugin;

final class Firewall
{
    public static function installRules(Plugin $firewall): void
    {
        $model = new BlankVpn();
        $settings = Policy::routingSettings(Policy::settings($model));
        if (!$settings['enabled']) {
            return;
        }

        $localFile = Policy::writeState('local-networks', implode("\n", Policy::localNetworks($settings)) . "\n");
        $firewall->registerTable(Policy::LOCAL_TABLE, true, $localFile);
        $profiles = Policy::routes($model);
        $health = self::health();
        $diagnostics = new Diagnostics();
        $interfaces = iterator_to_array($firewall->getInterfaceMapping());

        $proxyGateways = [];
        $pausedCore = ProxyCores::pausedCore();
        foreach ($profiles as &$profile) {
            if (($profile['kind'] ?? '') === 'proxy') {
                $profile['owned'] = ($pausedCore === null || !ProxyCores::uses($profile, $pausedCore)) &&
                    ProxyRuntime::ready($profile);
                if ($profile['owned']) {
                    $proxyGateways[$profile['gateway']] = [[
                        'ipprotocol' => 'inet', 'int' => $profile['interface'], 'gwip' => $profile['peer'], 'weight' => 1
                    ]];
                }
                continue;
            }
            $profile['owned'] = ($profile['kind'] ?? '') === 'native'
                ? $profile['configured'] && $profile['address'] !== ''
                : WireGuard::check($profile)['ok'];
            self::registerProfile($firewall, $profile);
        }
        $firewall->setGatewayGroups($proxyGateways);
        unset($profile);

        $services = SmartRouting::boundServices(SmartRouting::services($model));
        $multiOutage = self::multiPathOutage($firewall, $services, $profiles, $health);
        $assignments = [];
        if ($settings['coverage'] === 'network') {
            self::registerNetworkPolicy($firewall, $settings, $interfaces, $profiles, $health, $multiOutage);
        } else {
            $assignments = Policy::assignments($model);
            self::registerAssignments(
                $firewall, $settings, $interfaces, $assignments, $profiles, $health, $diagnostics, $multiOutage
            );
        }

        if (SmartRouting::active($settings, $services)) {
            self::registerSmartRoutes($firewall, $settings, $interfaces, $services, $profiles, $health, $assignments, $diagnostics);
        }

        foreach ($settings['strictInterfaces'] as $interface) {
            if (!Policy::interfaceId($interface) || empty($interfaces[$interface]['if'])) {
                continue;
            }
            self::redirectDns($firewall, $interface, 'any', Resolver::LOCAL_PORT, $interface, 70, true);
            $firewall->registerFilterRule(Policy::PRIORITY + 9, [
                'type' => 'block', 'interface' => $interface, 'ipprotocol' => 'inet46',
                'protocol' => 'tcp/udp', 'to_port' => '53', 'quick' => true,
                'label' => Policy::marker('block_dns', $interface),
                'descr' => 'Blank VPN prevents use of the default resolver'
            ]);
            $firewall->registerFilterRule(Policy::PRIORITY + 22, [
                'type' => 'block', 'interface' => $interface, 'ipprotocol' => 'inet46',
                'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true,
                'label' => Policy::marker('block', $interface),
                'descr' => 'Blank VPN managed segment default deny'
            ]);
        }
    }

    private static function registerNetworkPolicy(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $profiles,
        array $health,
        bool $multiOutage = false
    ): void {
        $mode = $settings['networkMode'];
        $killSwitch = $settings['networkKillSwitch'] ?? $mode === 'full';
        if ($mode === 'disabled' || ($mode === 'multi' && (!$killSwitch || !$multiOutage))) {
            return;
        }
        $profile = $mode === 'full'
            ? self::selectProfile($firewall, $profiles[$settings['networkProfile']] ?? [], [], $health)
            : null;
        foreach ($settings['interfaces'] as $interface) {
            if (!Policy::interfaceId($interface) || empty($interfaces[$interface]['if'])) {
                continue;
            }
            $id = 'network:' . $interface;
            if ($profile !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                    'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true,
                    'statetype' => 'keep', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN Whole-Network coverage'
                ] + self::stateOptions($profile));
                self::registerClientNat($firewall, $profile, $interface, 'any', 60);
                self::redirectDns($firewall, $interface, 'any', (int)$profile['dnsPort'], $id, 58);
            }
            if ($mode === 'multi') {
                self::registerOutageGuard($firewall, $id, $interface, 'any', 'any');
            } elseif ($mode === 'blocked' || $killSwitch) {
                self::registerGuard($firewall, $id, $interface, 'any', 'inet');
                self::registerGuard($firewall, $id, $interface, 'any', 'inet6');
            } elseif ($profile !== null) {
                self::registerGuard($firewall, $id, $interface, 'any', 'inet6');
            }
        }
    }

    private static function registerAssignments(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $assignments,
        array $profiles,
        array $health,
        Diagnostics $diagnostics,
        bool $multiOutage = false
    ): void {
        foreach ($assignments as $id => $row) {
            $interface = $row['interface'];
            $ip = $row['ip'];
            if (
                !in_array($interface, $settings['interfaces'], true) || empty($interfaces[$interface]['if']) ||
                !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            ) {
                continue;
            }

            $strict = in_array($interface, $settings['strictInterfaces'], true);
            $mode = Policy::mode($row);
            $ipv6 = filter_var($row['ipv6'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ?: '';
            $reserved = self::hasAssignmentIdentity($settings, $row, $diagnostics);
            $killSwitch = Policy::killSwitch($row);
            if ($mode === 'multi') {
                if ($killSwitch && ($multiOutage || !$reserved ||
                    !in_array($interface, $settings['smartInterfaces'], true))) {
                    self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6);
                }
                continue;
            }
            if ($mode === 'disabled' && in_array($interface, $settings['smartInterfaces'], true)) {
                self::bypassSmartDns($firewall, $interface, $ip, 'inet');
                if ($ipv6 !== '') {
                    self::bypassSmartDns($firewall, $interface, $ipv6, 'inet6');
                }
            }
            $rule = [
                'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet', 'from' => $ip,
                'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true
            ];
            $pass = [
                'type' => 'pass', 'statetype' => 'keep', 'label' => Policy::marker('device', $id),
                'descr' => 'Blank VPN device routing'
            ] + $rule;
            if ($mode === 'blocked') {
                self::redirectDns($firewall, $interface, $ip, Resolver::LOCAL_PORT, $id, 58);
                self::registerGuard($firewall, $id, $interface, $ip, 'inet');
                if ($ipv6 !== '') {
                    self::registerGuard($firewall, $id, $interface, $ipv6, 'inet6');
                }
                continue;
            }
            if ($mode === 'full' && $row['profile'] === '' && $killSwitch) {
                self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6);
                continue;
            }
            if ($mode === 'disabled' || $row['profile'] === '') {
                if ($strict && $reserved) {
                    self::allowNativeDns($firewall, $interface, $ip, $id);
                    $firewall->registerFilterRule(Policy::PRIORITY + 10, $pass);
                }
                continue;
            }

            $primary = $profiles[$row['profile']] ?? [];
            $backup = $row['failure'] === 'backup' ? ($profiles[$row['backup']] ?? []) : [];
            $selected = $reserved ? self::selectProfile($firewall, $primary, $backup, $health) : null;
            if ($selected !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'gateway' => $selected['gateway'], 'skip_rules_gw_down' => true
                ] + self::stateOptions($selected) + $pass);
                self::registerClientNat($firewall, $selected, $ip, 'any', 60);
                self::redirectDns($firewall, $interface, $ip, (int)$selected['dnsPort'], $id, 58);
            } elseif ($reserved && $row['failure'] === 'wan' && $primary !== []) {
                if ($strict) {
                    self::allowNativeDns($firewall, $interface, $ip, $id);
                    $firewall->registerFilterRule(Policy::PRIORITY + 10, $pass);
                }
                if (!$strict && in_array($interface, $settings['smartInterfaces'], true)) {
                    self::bypassSmartDns($firewall, $interface, $ip, 'inet');
                    if ($ipv6 !== '') {
                        self::bypassSmartDns($firewall, $interface, $ipv6, 'inet6');
                    }
                }
                continue;
            } elseif ($killSwitch) {
                self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6);
                continue;
            } else {
                self::redirectDns($firewall, $interface, $ip, Resolver::LOCAL_PORT, $id, 58);
            }

            if ($row['failure'] === 'wan' && $reserved) {
                continue;
            }
            self::registerGuard($firewall, $id, $interface, $ip, 'inet');
            if ($ipv6 !== '' && $row['failure'] !== 'wan') {
                self::registerGuard($firewall, $id, $interface, $ipv6, 'inet6');
            }
        }
    }

    private static function hasAssignmentIdentity(array $settings, array $row, Diagnostics $diagnostics): bool
    {
        if (($row['kind'] ?? '') === 'tailnet') {
            return in_array($row['interface'], $settings['tailscaleInterfaces'] ?? [], true) &&
                Policy::tailnetInterface($row['interface']) &&
                Policy::tailnetAddress($row['ip']) && Policy::tailnetAddress($row['ipv6'] ?? '', true);
        }
        return $diagnostics->hasReservation($row['interface'], $row['ip'], $row['mac']);
    }

    private static function registerOutageGuard(
        Plugin $firewall,
        string $id,
        string $interface,
        string $ip,
        string $ipv6
    ): void {
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                self::bypassSmartDns($firewall, $interface, $source, $family);
                self::registerGuard($firewall, $id, $interface, $source, $family);
            }
        }
    }

    private static function multiPathOutage(Plugin $firewall, array $services, array $profiles, array $health): bool
    {
        if ($services === []) {
            return true;
        }
        foreach (array_unique(array_column($services, 'profile')) as $id) {
            $profile = $profiles[$id] ?? [];
            $checked = $health[$id] ?? [];
            $maxAge = ($profile['kind'] ?? '') === 'proxy' ? 300 : 180;
            if (empty($checked['probeSucceeded']) || time() - ($checked['checkedAt'] ?? 0) > $maxAge ||
                self::selectProfile($firewall, $profile, [], $health) === null) {
                return true;
            }
        }
        return false;
    }

    private static function registerGuard(Plugin $firewall, string $id, string $interface, string $ip, string $family): void
    {
        $suffix = $family === 'inet6' ? '_v6' : '';
        $rule = [
            'type' => 'block', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
            'from' => $ip, 'quick' => true
        ];
        $firewall->registerFilterRule(Policy::PRIORITY + 11, [
            'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true,
            'label' => Policy::marker('kill' . $suffix, $id), 'descr' => 'Blank VPN device internet guard'
        ] + $rule);
        $firewall->registerFilterRule(Policy::PRIORITY + 7, [
            'protocol' => 'tcp/udp', 'to_port' => '53', 'label' => Policy::marker('kill_dns' . $suffix, $id)
        ] + $rule);
    }

    private static function registerSmartRoutes(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $services,
        array $profiles,
        array $health,
        array $assignments = [],
        ?Diagnostics $diagnostics = null
    ): void {
        foreach ($services as $service) {
            $firewall->registerTable(SmartRouting::table($service), true);
        }
        foreach ($settings['smartInterfaces'] as $interface) {
            if (
                !Policy::interfaceId($interface) || empty($interfaces[$interface]['if']) ||
                in_array($interface, $settings['strictInterfaces'], true)
            ) {
                continue;
            }
            $tag = Policy::marker('smart', $interface);
            $match = [
                'type' => 'match', 'interface' => $interface, 'ipprotocol' => 'inet46', 'quick' => false,
                'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'tag' => $tag,
                'descr' => 'Blank VPN Multi-Path source and destination scope'
            ];
            $assignedOnly = !empty($settings['smartAssignedOnly']);
            $sources = [];
            if (!$assignedOnly) {
                foreach (['inet', 'inet6'] as $family) {
                    self::redirectDns($firewall, $interface, 'any', SmartRouting::PORT, $interface, 64, true, $family);
                }
            }
            foreach ($assignments as $id => $row) {
                if ($row['interface'] !== $interface) {
                    continue;
                }
                $mode = Policy::mode($row);
                $included = $mode === 'multi' && $diagnostics !== null &&
                    self::hasAssignmentIdentity($settings, $row, $diagnostics);
                if ($assignedOnly ? !$included : ($included || $mode === 'default')) {
                    continue;
                }
                foreach (['inet' => $row['ip'], 'inet6' => $row['ipv6'] ?? ''] as $family => $source) {
                    if (!filter_var($source, FILTER_VALIDATE_IP, $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6)) {
                        continue;
                    }
                    $sources[] = $source;
                    if ($assignedOnly) {
                        self::redirectDns($firewall, $interface, $source, SmartRouting::PORT, $id, 64, false, $family);
                    }
                }
            }
            if ($sources !== []) {
                $table = Policy::marker('src', $interface);
                // PF table names are limited to 31 characters.
                $table = substr($table, 0, 31);
                $file = Policy::writeState($table, implode("\n", array_unique($sources)) . "\n");
                $firewall->registerTable($table, true, $file);
                $match += ['from' => '<' . $table . '>', 'from_not' => !$assignedOnly];
            }
            if (!$assignedOnly || $sources !== []) {
                $firewall->registerFilterRule(Policy::PRIORITY + 12, $match);
            }
            foreach (array_values($services) as $index => $service) {
                $id = $service['id'] . ':' . $interface;
                $table = '<' . SmartRouting::table($service) . '>';
                $base = [
                    'direction' => 'in', 'interface' => $interface, 'to' => $table,
                    'tagged' => $tag, 'quick' => true, 'disablereplyto' => true
                ];
                $priority = Policy::PRIORITY + 30 + $index * 2;
                $profile = self::selectProfile($firewall, $profiles[$service['profile']] ?? [], [], $health);
                if ($profile !== null) {
                    $firewall->registerFilterRule($priority, [
                        'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => $profile['gateway'],
                        'skip_rules_gw_down' => true, 'statetype' => 'keep',
                        'label' => Policy::marker('service', $id)
                    ] + self::stateOptions($profile) + $base);
                    self::registerClientNat($firewall, $profile, $interface, $table, 61);
                }
                // A learned destination never takes the native route when its selected tunnel is unavailable.
                // IPv6 for learned destinations is blocked until VPN egress supports it.
                $firewall->registerFilterRule($priority + 1, [
                    'type' => 'block', 'ipprotocol' => 'inet46',
                    'label' => Policy::marker('service_guard', $id)
                ] + $base);
            }
        }
    }

    private static function stateOptions(array $profile): array
    {
        return ($profile['kind'] ?? '') === 'proxy' ? ['state-policy' => 'floating'] : [];
    }

    private static function registerClientNat(
        Plugin $firewall,
        array $profile,
        string $source,
        string $destination,
        int $priority
    ): void {
        if (($profile['kind'] ?? '') === 'proxy') {
            return;
        }
        $firewall->registerSourceNatRule($priority, [
            'interface' => $profile['logicalInterface'], 'ipprotocol' => 'inet',
            'from' => $source, 'to' => $destination, 'target' => explode('/', $profile['address'])[0],
            'descr' => 'Blank VPN client source NAT'
        ]);
    }

    private static function bypassSmartDns(Plugin $firewall, string $interface, string $ip, string $family): void
    {
        if (self::dnsRedirectionAvailable()) {
            $firewall->registerDestinationNatRule(55, [
                'nordr' => true, 'interface' => $interface, 'ipprotocol' => $family,
                'from' => $ip, 'protocol' => 'tcp/udp', 'to_port' => '53', 'natreflection' => 'disable',
                'descr' => 'Blank VPN uses regular DNS for this address'
            ]);
        }
    }

    private static function allowNativeDns(Plugin $firewall, string $interface, string $ip, string $id): void
    {
        self::bypassSmartDns($firewall, $interface, $ip, 'inet');
        $dns = [
            'type' => 'pass', 'interface' => $interface, 'ipprotocol' => 'inet',
            'from' => $ip, 'protocol' => 'tcp/udp', 'to_port' => '53',
            'quick' => true, 'statetype' => 'keep', 'disablereplyto' => true
        ];
        $firewall->registerFilterRule(Policy::PRIORITY + 4, [
            'to' => $interface . 'ip', 'label' => Policy::marker('normal_dns', $id)
        ] + $dns);
        $firewall->registerFilterRule(Policy::PRIORITY + 4, [
            'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true,
            'label' => Policy::marker('normal_dns_external', $id)
        ] + $dns);
    }

    private static function redirectDns(
        Plugin $firewall,
        string $interface,
        string $ip,
        int $port,
        string $id,
        int $priority,
        bool $default = false,
        string $family = 'inet'
    ): void {
        if (!self::dnsRedirectionAvailable() || !Resolver::allowedPort($port)) {
            return;
        }
        $tag = Policy::marker('dns', $id . ':' . $family);
        $target = $family === 'inet6' ? '::1' : '127.0.0.1';
        $firewall->registerDestinationNatRule($priority, [
            'interface' => $interface, 'ipprotocol' => $family, 'protocol' => 'tcp/udp',
            'from' => $ip, 'to_port' => '53', 'target' => $target, 'local-port' => (string)$port,
            'tag' => $tag, 'natreflection' => 'disable', 'descr' => 'Blank VPN DNS redirection'
        ]);
        $firewall->registerFilterRule(Policy::PRIORITY + ($default ? 6 : 5), [
            'type' => 'pass', 'interface' => $interface, 'ipprotocol' => $family,
            'from' => $ip, 'to' => $target, 'to_port' => (string)$port, 'protocol' => 'tcp/udp',
            'tagged' => $tag, 'quick' => true, 'statetype' => 'keep', 'disablereplyto' => true,
            'label' => $tag
        ]);
    }

    public static function dnsRedirectionAvailable(): bool
    {
        return empty(Config::getInstance()->object()->system->enablenatreflectionhelper);
    }

    private static function gatewayAvailable(Plugin $firewall, array $profile): bool
    {
        if (($profile['kind'] ?? '') === 'proxy') {
            if (empty($profile['owned']) || !preg_match('/^tun20[0-7]$/D', $profile['interface'] ?? '')) {
                return false;
            }
            $gateway = @$firewall->getGateway($profile['gateway']) ?? [];
            return ($gateway['proto'] ?? null) === 'inet' && ($gateway['type'] ?? null) === 'group' &&
                str_contains($gateway['logic'] ?? '', $profile['interface'] . ' ' . $profile['peer']);
        }
        $device = $profile['interface'] ?? '';
        $validDevice = ($profile['kind'] ?? '') === 'native'
            ? NativeVpn::tunnelDevice($device)
            : preg_match('/^wg[0-9]+$/D', $device);
        if (
            empty($profile['owned']) || empty($profile['gateway']) || !$validDevice ||
            !Policy::interfaceId($profile['logicalInterface'] ?? '')
        ) {
            return false;
        }
        $gateway = @$firewall->getGateway($profile['gateway']) ?? [];
        return ($gateway['interface'] ?? null) === $profile['interface'] &&
            ($gateway['proto'] ?? null) === 'inet' && !empty($gateway['logic']);
    }

    private static function selectProfile(
        Plugin $firewall,
        array $primary,
        array $backup,
        array $health
    ): ?array {
        if (
            self::gatewayAvailable($firewall, $primary) &&
            ($health[$primary['id']]['reachable'] ?? true)
        ) {
            return $primary;
        }
        if (self::gatewayAvailable($firewall, $backup) && ($health[$backup['id']]['reachable'] ?? true)) {
            return $backup;
        }
        return null;
    }

    private static function registerProfile(Plugin $firewall, array $profile): void
    {
        $address = explode('/', $profile['address'] ?? '')[0];
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return;
        }

        $ready = self::gatewayAvailable($firewall, $profile);
        $destinations = [
            ['to' => self::probeIp(), 'to_port' => '443', 'protocol' => 'tcp', 'kind' => 'probe']
        ];
        foreach ($profile['dns'] ?? [] as $dns) {
            if (filter_var($dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $destinations[] = ['to' => $dns, 'to_port' => '53', 'protocol' => 'tcp/udp', 'kind' => 'dns_out'];
            }
        }
        foreach ($destinations as $destination) {
            $kind = $destination['kind'];
            unset($destination['kind']);
            $label = Policy::marker($kind, $profile['id'] . $destination['to']);
            $base = $destination + [
                'direction' => 'out', 'ipprotocol' => 'inet', 'from' => $address,
                'quick' => true, 'disablereplyto' => true
            ];
            if ($ready) {
                $firewall->registerFilterRule(Policy::PRIORITY, [
                    'type' => 'pass', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'statetype' => 'keep', 'label' => $label
                ] + $base);
            }
            $firewall->registerFilterRule(Policy::PRIORITY + 1, [
                'type' => 'block', 'label' => $label . '_block'
            ] + $base);
        }
    }

    public static function probeIp(): string
    {
        return Policy::PROBE_IP;
    }

    public static function health(): array
    {
        $path = Policy::STATE_DIR . '/health.json';
        if (!is_file($path)) {
            return [];
        }
        $data = json_decode((string)file_get_contents($path), true);
        return is_array($data) ? $data : [];
    }

    public static function probePathInstalled(array $profile, array $loaded): bool
    {
        $source = explode('/', $profile['address'] ?? '', 2)[0];
        if (!filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $marker = Policy::marker('probe', $profile['id'] . Policy::PROBE_IP);
        $pass = $loaded[$marker] ?? [];
        $guard = $loaded[$marker . '_block'] ?? [];
        return ($pass['action'] ?? '') === 'pass' && ($pass['source'] ?? '') === $source &&
            ($pass['gateway'] ?? null) === ($profile['interface'] ?? '') &&
            ($guard['action'] ?? '') === 'block' && ($guard['source'] ?? '') === $source;
    }

    public static function loadedRules(): ?array
    {
        $raw = (new Backend())->configdRun('blankvpn loaded', false, 15);
        $result = json_decode($raw, true);
        return is_array($result) ? $result : null;
    }

    public static function reload(BlankVpn $model): void
    {
        $response = trim((new Backend())->configdRun('blankvpn reload', false, 60));
        if ($response !== 'ok') {
            throw new \RuntimeException('OPNsense could not load the Blank VPN firewall policy.');
        }
        $loaded = self::loadedRules();
        if ($loaded === null) {
            throw new \RuntimeException('Blank VPN could not verify the loaded PF rules.');
        }
        $settings = Policy::settings($model);
        foreach ($settings['strictInterfaces'] as $interface) {
            $marker = Policy::marker('block', $interface);
            if ($settings['enabled'] !== (($loaded[$marker]['action'] ?? '') === 'block')) {
                throw new \RuntimeException('The loaded PF rules do not match the Blank VPN segment policy.');
            }
        }
        if (!$settings['enabled']) {
            return;
        }
        foreach (Policy::assignments($model) as $id => $row) {
            $mode = Policy::mode($row);
            if (($mode === 'blocked' || ($mode === 'full' && $row['failure'] !== 'wan')) &&
                (($loaded[Policy::marker('kill', $id)]['action'] ?? '') !== 'block' ||
                (!empty($row['ipv6']) && ($loaded[Policy::marker('kill_v6', $id)]['action'] ?? '') !== 'block'))) {
                throw new \RuntimeException('A per-IP fail-closed firewall guard is missing.');
            }
        }
        foreach (SmartRouting::services($model) as $id => $service) {
            foreach ($settings['smartInterfaces'] as $interface) {
                $marker = Policy::marker('service_guard', $id . ':' . $interface);
                if (($loaded[$marker]['action'] ?? '') !== 'block') {
                    throw new \RuntimeException('A Multi-Path destination guard is missing.');
                }
            }
        }
    }
}
