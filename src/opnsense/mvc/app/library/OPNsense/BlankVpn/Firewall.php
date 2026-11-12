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
        $settings = Policy::settings($model);
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
        foreach ($profiles as &$profile) {
            if (($profile['kind'] ?? '') === 'proxy') {
                $profile['owned'] = ProxyRuntime::ready($profile);
                if ($profile['owned']) {
                    $proxyGateways[$profile['gateway']] = [[
                        'ipprotocol' => 'inet', 'int' => $profile['interface'], 'gwip' => $profile['peer'], 'weight' => 1
                    ]];
                }
                continue;
            }
            $profile['owned'] = WireGuard::check($profile)['ok'];
            self::registerProfile($firewall, $profile);
        }
        $firewall->setGatewayGroups($proxyGateways);
        unset($profile);

        self::registerAssignments($firewall, $settings, $interfaces, Policy::assignments($model), $profiles, $health, $diagnostics);

        $services = SmartRouting::services($model);
        if (SmartRouting::active($settings, $services)) {
            self::registerSmartRoutes($firewall, $settings, $interfaces, $services, $profiles, $health);
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

    private static function registerAssignments(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $assignments,
        array $profiles,
        array $health,
        Diagnostics $diagnostics
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
            $reserved = $diagnostics->hasReservation($interface, $ip, $row['mac']);
            $rule = [
                'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet', 'from' => $ip,
                'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true
            ];
            $pass = [
                'type' => 'pass', 'statetype' => 'keep', 'label' => Policy::marker('device', $id),
                'descr' => 'Blank VPN device routing'
            ] + $rule;
            if ($row['profile'] === '') {
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
                // On a shared LAN, explicit fallback returns this IP to the native and Smart Routing policies.
                continue;
            } else {
                self::redirectDns($firewall, $interface, $ip, Resolver::LOCAL_PORT, $id, 58);
            }

            // This guard remains installed even when the tunnel, gateway, or reservation disappears.
            $firewall->registerFilterRule(Policy::PRIORITY + 11, [
                'type' => 'block', 'label' => Policy::marker('kill', $id),
                'descr' => 'Blank VPN per-IP fail-closed guard'
            ] + $rule);
            $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                'type' => 'block', 'interface' => $interface, 'ipprotocol' => 'inet', 'from' => $ip,
                'protocol' => 'tcp/udp', 'to_port' => '53', 'quick' => true,
                'label' => Policy::marker('kill_dns', $id)
            ]);
        }
    }

    private static function registerSmartRoutes(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $services,
        array $profiles,
        array $health
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
            foreach (['inet', 'inet6'] as $family) {
                self::redirectDns($firewall, $interface, 'any', SmartRouting::PORT, $interface, 64, true, $family);
            }
            $tag = Policy::marker('smart', $interface);
            $firewall->registerFilterRule(Policy::PRIORITY + 12, [
                'type' => 'match', 'interface' => $interface, 'ipprotocol' => 'inet46', 'quick' => false,
                'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'tag' => $tag,
                'descr' => 'Blank VPN Smart Routing excludes local destinations'
            ]);
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

    private static function allowNativeDns(Plugin $firewall, string $interface, string $ip, string $id): void
    {
        if (self::dnsRedirectionAvailable()) {
            $firewall->registerDestinationNatRule(55, [
                'nordr' => true, 'interface' => $interface, 'ipprotocol' => 'inet',
                'from' => $ip, 'protocol' => 'tcp/udp', 'to_port' => '53', 'natreflection' => 'disable',
                'descr' => 'Blank VPN explicitly permits regular DNS'
            ]);
        }
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
        if (!self::dnsRedirectionAvailable() || $port < Resolver::LOCAL_PORT ||
            $port >= ProxyRuntime::FIRST_DNS_PORT + ProxyRuntime::SLOTS) {
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
        if (
            empty($profile['owned']) || empty($profile['gateway']) || !preg_match('/^wg[0-9]+$/D', $profile['interface'] ?? '') ||
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
            if ($row['profile'] !== '' && $row['failure'] !== 'wan' &&
                ($loaded[Policy::marker('kill', $id)]['action'] ?? '') !== 'block') {
                throw new \RuntimeException('A per-IP fail-closed firewall guard is missing.');
            }
        }
        foreach (SmartRouting::services($model) as $id => $service) {
            foreach ($settings['smartInterfaces'] as $interface) {
                $marker = Policy::marker('service_guard', $id . ':' . $interface);
                if (($loaded[$marker]['action'] ?? '') !== 'block') {
                    throw new \RuntimeException('A Smart Routing destination guard is missing.');
                }
            }
        }
    }
}
