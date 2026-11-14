<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Plugin;

final class Firewall
{
    // All 16 service-specific pass/block pairs precede the combined policy's default route.
    private const COMBINED_BASE = Policy::PRIORITY + 30 + SmartRouting::MAX_SERVICES * 2 + 2;

    public static function installRules(Plugin $firewall): void
    {
        $model = new BlankVpn();
        $settings = Policy::effectiveRouting($model);
        $profiles = Policy::routes($model);
        $interfaces = iterator_to_array($firewall->getInterfaceMapping());
        if ((string)(Config::getInstance()->object()->OPNsense->tailscale->settings->enabled ?? '') === '1') {
            // Keep Tailscale's native NAT anchor after OPNsense and VPN source NAT rules.
            $firewall->registerAnchor('tailscale', 'nat');
            $firewall->registerAnchor('tailscale');
        }
        if (in_array(Policy::TAILSCALE_DEVICE, $settings['interfaces'], true)) {
            $interface = Policy::TAILSCALE_DEVICE;
            $interfaces[$interface] = [
                'if' => $interface, 'ifconfig' => $firewall->getIfconfigDetails()[$interface] ?? [],
                'descr' => 'Tailscale', 'virtual' => true
            ];
            $firewall->setInterfaceMapping($interfaces);
        }
        $proxyGateways = [];
        $pausedCore = $settings['enabled'] ? ProxyCores::pausedCore() : null;
        foreach ($profiles as &$profile) {
            if (!empty($profile['disabled'])) {
                continue;
            }
            if (($profile['kind'] ?? '') === 'proxy') {
                $profile['owned'] = $settings['enabled'] &&
                    ($pausedCore === null || !ProxyCores::uses($profile, $pausedCore)) &&
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
            self::registerProfile($firewall, $profile, $settings['enabled']);
        }
        unset($profile);
        if (!$settings['enabled']) {
            return;
        }

        $localFile = Policy::writeState('local-networks', implode("\n", Policy::localNetworks($settings)) . "\n");
        $firewall->registerTable(Policy::LOCAL_TABLE, true, $localFile);
        $firewall->setGatewayGroups($proxyGateways);
        $health = self::health();
        $diagnostics = new Diagnostics();
        $services = SmartRouting::activeServices($settings, SmartRouting::services($model));
        $bypass = SmartRouting::usesBypass($settings);
        $multiOutage = !$bypass && self::multiPathOutage($firewall, $services, $profiles, $health);
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model), $diagnostics) : [];
        $combinedInterfaces = self::combinedInterfaces($assignments);
        if (($settings['coverage'] === 'network' && $settings['networkMode'] === 'full_multi') || $combinedInterfaces !== []) {
            $combined = Policy::localNetworks(array_replace($settings, ['localNetworks' => []]));
            $combinedFile = Policy::writeState('combined-local-networks', implode("\n", $combined) . "\n");
            $firewall->registerTable(Policy::COMBINED_LOCAL_TABLE, true, $combinedFile);
        }
        if ($settings['coverage'] === 'network') {
            self::registerNetworkPolicy(
                $firewall, $settings, $interfaces, $profiles, $health, $multiOutage,
                $bypass && $services !== [] ? SmartRouting::bypassTable($services) : ''
            );
        } else {
            self::registerAssignments(
                $firewall, $settings, $interfaces, $assignments, $profiles, $health, $diagnostics, $multiOutage
            );
        }

        if (!$bypass && $services !== []) {
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
            $priority = isset($combinedInterfaces[$interface]) ? self::COMBINED_BASE + 2 : Policy::PRIORITY + 22;
            $firewall->registerFilterRule($priority, [
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
        bool $multiOutage = false,
        string $bypassTable = ''
    ): void {
        $mode = $settings['networkMode'];
        $killSwitch = $settings['networkKillSwitch'] ?? $mode === 'full';
        if ($mode === 'disabled' || ($mode === 'multi' && (!$killSwitch || !$multiOutage))) {
            return;
        }
        $base = Policy::usesBase($mode) ? ($profiles[$settings['networkProfile']] ?? []) : [];
        $profile = self::selectProfile($firewall, $base, [], $health);
        if ($profile !== null && $bypassTable !== '') {
            $firewall->registerTable($bypassTable, true);
        }
        foreach ($settings['interfaces'] as $interface) {
            if (!Policy::interfaceId($interface) || empty($interfaces[$interface]['if'])) {
                continue;
            }
            $id = 'network:' . $interface;
            if ($mode === 'full_multi') {
                self::registerCombinedPolicy($firewall, $id, $interface, 'any', 'any', $base, $profile);
                continue;
            }
            $scope = [];
            if ($profile !== null) {
                if ($bypassTable !== '') {
                    $tag = Policy::marker('network_tunnel', $id);
                    $firewall->registerFilterRule(Policy::PRIORITY + 8, [
                        'type' => 'match', 'direction' => 'in', 'interface' => $interface,
                        'ipprotocol' => 'inet46', 'to' => '<' . $bypassTable . '>', 'to_not' => true,
                        'quick' => false, 'tag' => $tag, 'label' => Policy::marker('bypass', $id),
                        'descr' => 'Blank VPN applies native policy to learned bypass destinations'
                    ]);
                    $scope = ['tagged' => $tag];
                }
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                    'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true,
                    'statetype' => 'keep', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN Whole-Network coverage'
                ] + $scope + self::stateOptions($profile));
                self::registerClientNat($firewall, $profile, $interface, 'any', 60);
                $port = $bypassTable === '' ? (int)$profile['dnsPort'] : SmartRouting::PORT;
                self::redirectDns($firewall, $interface, 'any', $port, $id, 58);
                if ($bypassTable !== '') {
                    self::redirectDns($firewall, $interface, 'any', $port, $id, 58, false, 'inet6');
                }
            }
            if ($mode === 'multi') {
                self::registerOutageGuard($firewall, $id, $interface, 'any', 'any');
            } elseif ($mode === 'blocked' || $killSwitch) {
                self::registerGuard($firewall, $id, $interface, 'any', 'inet', $scope);
                self::registerGuard($firewall, $id, $interface, 'any', 'inet6', $scope);
            } elseif ($profile !== null) {
                self::registerGuard($firewall, $id, $interface, 'any', 'inet6', $scope);
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
                Policy::assignmentPaused($row) || !in_array($interface, $settings['interfaces'], true) ||
                empty($interfaces[$interface]['if'])
            ) {
                continue;
            }

            $strict = in_array($interface, $settings['strictInterfaces'], true);
            $mode = Policy::mode($row);
            $ipv6 = filter_var($row['ipv6'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ?: '';
            $killSwitch = Policy::killSwitch($row);
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $blockIpv6 = $killSwitch || $mode === 'blocked' ||
                    ($mode === 'full' && $row['profile'] !== '' && $row['failure'] !== 'wan');
                if (Policy::bindsMac($row) && $blockIpv6) {
                    self::registerOutageGuard(
                        $firewall, $id, $interface, '', $ipv6,
                        $mode === 'full_multi' ? Policy::COMBINED_LOCAL_TABLE : Policy::LOCAL_TABLE
                    );
                }
                continue;
            }
            $reserved = self::hasAssignmentIdentity($settings, $row, $diagnostics);
            if ($mode === 'full_multi') {
                if (!$reserved) {
                    self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6, Policy::COMBINED_LOCAL_TABLE);
                    continue;
                }
                $base = $profiles[$row['profile']] ?? [];
                self::registerCombinedPolicy(
                    $firewall, $id, $interface, $ip, $ipv6, $base, self::selectProfile($firewall, $base, [], $health)
                );
                continue;
            }
            if ($reserved && $interface === Policy::TAILSCALE_DEVICE && $mode !== 'blocked') {
                self::registerTailnetInternet($firewall, $id, $ip, $ipv6);
            }
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

    private static function registerCombinedPolicy(
        Plugin $firewall,
        string $id,
        string $interface,
        string $ip,
        string $ipv6,
        array $base,
        ?array $profile
    ): void {
        if ($profile !== null) {
            $firewall->registerFilterRule(self::COMBINED_BASE, [
                'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                'from' => $ip, 'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true,
                'quick' => true, 'disablereplyto' => true, 'statetype' => 'keep',
                'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN base tunnel with Multi-Path'
            ] + self::stateOptions($profile));
            self::registerClientNat($firewall, $profile, $ip === 'any' ? $interface : $ip, 'any', 60);
        }
        // Keep DNS classification available for healthy overrides even when the base tunnel is down.
        $port = Resolver::combinedPort($base);
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                if ($port === 0) {
                    self::bypassSmartDns($firewall, $interface, $source, $family);
                } else {
                    self::redirectDns($firewall, $interface, $source, $port, $id, 57, false, $family);
                }
                self::registerGuard(
                    $firewall, $id, $interface, $source, $family, [], self::COMBINED_BASE + 1, Policy::COMBINED_LOCAL_TABLE
                );
            }
        }
    }

    private static function registerTailnetInternet(Plugin $firewall, string $id, string $ip, string $ipv6): void
    {
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            $firewall->registerFilterRule(490000, [
                'type' => 'pass', 'direction' => 'in', 'interface' => Policy::TAILSCALE_DEVICE,
                'ipprotocol' => $family, 'from' => $source, 'to' => '<' . Policy::LOCAL_TABLE . '>',
                'to_not' => true, 'quick' => false, 'statetype' => 'keep', 'disablereplyto' => true,
                'label' => Policy::marker('tailnet_internet', $id . ':' . $family)
            ]);
        }
    }

    private static function hasAssignmentIdentity(array $settings, array $row, Diagnostics $diagnostics): bool
    {
        if (($row['kind'] ?? '') === 'tailnet') {
            $interface = $row['interface'];
            $valid = $interface === Policy::TAILSCALE_DEVICE ? Policy::nativeTailnetConfigured() :
                in_array($interface, $settings['tailscaleInterfaces'] ?? [], true) && Policy::tailnetInterface($interface);
            return $valid && Policy::tailnetAddress($row['ip']) && Policy::tailnetAddress($row['ipv6'] ?? '', true);
        }
        return $diagnostics->hasReservation($row['interface'], $row['ip'], $row['mac']);
    }

    private static function registerOutageGuard(
        Plugin $firewall,
        string $id,
        string $interface,
        string $ip,
        string $ipv6,
        string $local = Policy::LOCAL_TABLE
    ): void {
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                self::bypassSmartDns($firewall, $interface, $source, $family);
                self::registerGuard($firewall, $id, $interface, $source, $family, [], Policy::PRIORITY + 11, $local);
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

    private static function registerGuard(
        Plugin $firewall,
        string $id,
        string $interface,
        string $ip,
        string $family,
        array $scope = [],
        int $priority = Policy::PRIORITY + 11,
        string $local = Policy::LOCAL_TABLE
    ): void {
        $suffix = $family === 'inet6' ? '_v6' : '';
        $rule = [
            'type' => 'block', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
            'from' => $ip, 'quick' => true
        ];
        $firewall->registerFilterRule($priority, [
            'to' => '<' . $local . '>', 'to_not' => true,
            'label' => Policy::marker('kill' . $suffix, $id), 'descr' => 'Blank VPN device internet guard'
        ] + $rule + $scope);
        $firewall->registerFilterRule(Policy::PRIORITY + 7, [
            'protocol' => 'tcp/udp', 'to_port' => '53', 'label' => Policy::marker('kill_dns' . $suffix, $id)
        ] + $rule);
    }

    private static function combinedInterfaces(array $assignments): array
    {
        $interfaces = [];
        foreach ($assignments as $row) {
            if (!Policy::assignmentPaused($row) && Policy::mode($row) === 'full_multi') {
                $interfaces[$row['interface']] = true;
            }
        }
        return $interfaces;
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
        $combinedInterfaces = self::combinedInterfaces($assignments);
        $combinedNetwork = ($settings['coverage'] ?? '') === 'network' && $settings['networkMode'] === 'full_multi';
        $routes = [];
        foreach ($services as $service) {
            $table = SmartRouting::table($service);
            $firewall->registerTable($table, true);
            $routes[] = [$service['id'], $table, self::selectProfile($firewall, $profiles[$service['profile']] ?? [], [], $health)];
        }
        foreach ($settings['smartInterfaces'] as $interface) {
            $strict = in_array($interface, $settings['strictInterfaces'], true);
            if (
                (!Policy::interfaceId($interface) && $interface !== Policy::TAILSCALE_DEVICE) ||
                empty($interfaces[$interface]['if']) || ($strict && !isset($combinedInterfaces[$interface]))
            ) {
                continue;
            }
            $tag = Policy::marker('smart', $interface);
            $assignedOnly = $strict || !empty($settings['smartAssignedOnly']) ||
                in_array($interface, $settings['deviceMultiInterfaces'] ?? [], true);
            $sources = [];
            $combinedSources = [];
            if (!$assignedOnly && !$combinedNetwork) {
                foreach (['inet', 'inet6'] as $family) {
                    self::redirectDns($firewall, $interface, 'any', SmartRouting::PORT, $interface, 64, true, $family);
                }
            }
            foreach ($assignments as $id => $row) {
                if ($row['interface'] !== $interface) {
                    continue;
                }
                $mode = Policy::assignmentPaused($row) ? 'disabled' : Policy::mode($row);
                $included = Policy::usesMultiPath($mode) && (!$strict || $mode === 'full_multi') &&
                    $row['ip'] !== '' && $diagnostics !== null &&
                    self::hasAssignmentIdentity($settings, $row, $diagnostics);
                $combined = $mode === 'full_multi';
                if (!$combined && ($assignedOnly ? !$included : ($included || $mode === 'default'))) {
                    continue;
                }
                foreach (['inet' => $row['ip'], 'inet6' => $row['ipv6'] ?? ''] as $family => $source) {
                    if (!filter_var($source, FILTER_VALIDATE_IP, $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6)) {
                        continue;
                    }
                    if ($combined) {
                        if ($included) {
                            $combinedSources[] = $source;
                        }
                        if (!$assignedOnly) {
                            // Keep these sources out of the ordinary Multi-Path destination exceptions.
                            $sources[] = $source;
                        }
                    } else {
                        $sources[] = $source;
                    }
                    if (!$combined && $assignedOnly && $mode === 'multi') {
                        self::redirectDns($firewall, $interface, $source, SmartRouting::PORT, $id, 64, false, $family);
                    } elseif (Policy::assignmentPaused($row) || ($row['ip'] === '' && $mode === 'disabled')) {
                        self::bypassSmartDns($firewall, $interface, $source, $family);
                    }
                }
            }
            if (!$combinedNetwork && (!$assignedOnly || $sources !== [])) {
                self::registerSmartScope($firewall, $interface, $tag, Policy::LOCAL_TABLE, $sources, !$assignedOnly);
            }
            if ($combinedNetwork || $combinedSources !== []) {
                self::registerSmartScope($firewall, $interface, $tag, Policy::COMBINED_LOCAL_TABLE, $combinedSources, false);
            }
            foreach ($routes as $index => [$id, $table, $profile]) {
                $id .= ':' . $interface;
                $table = '<' . $table . '>';
                $base = [
                    'direction' => 'in', 'interface' => $interface, 'to' => $table,
                    'tagged' => $tag, 'quick' => true, 'disablereplyto' => true
                ];
                $priority = Policy::PRIORITY + 30 + $index * 2;
                if ($profile !== null) {
                    $firewall->registerFilterRule($priority, [
                        'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => $profile['gateway'],
                        'skip_rules_gw_down' => true, 'statetype' => 'keep',
                        'label' => Policy::marker('service', $id)
                    ] + self::stateOptions($profile) + $base);
                    $source = $interface === Policy::TAILSCALE_DEVICE ? Policy::TAILSCALE_V4 : $interface;
                    self::registerClientNat($firewall, $profile, $source, $table, 61);
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

    private static function registerSmartScope(
        Plugin $firewall,
        string $interface,
        string $tag,
        string $local,
        array $sources,
        bool $exclude
    ): void {
        $combined = $local === Policy::COMBINED_LOCAL_TABLE;
        $scope = [];
        if ($sources !== []) {
            $table = self::registerSmartSources($firewall, $interface, $combined ? 'cs' : 'src', $sources);
            $scope = ['from' => '<' . $table . '>', 'from_not' => $exclude];
        }
        $firewall->registerFilterRule(Policy::PRIORITY + 12, [
            'type' => 'match', 'interface' => $interface, 'ipprotocol' => 'inet46', 'quick' => false,
            'to' => '<' . $local . '>', 'to_not' => true, 'tag' => $tag,
            'label' => Policy::marker($combined ? 'combined_scope' : 'smart_scope', $interface),
            'descr' => 'Blank VPN Multi-Path source and destination scope'
        ] + $scope);
    }

    private static function registerSmartSources(Plugin $firewall, string $interface, string $type, array $sources): string
    {
        // PF table names are limited to 31 characters.
        $table = substr(Policy::marker($type, $interface), 0, 31);
        $file = Policy::writeState($table, implode("\n", array_unique($sources)) . "\n");
        $firewall->registerTable($table, true, $file);
        return $table;
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

    private static function registerProfile(Plugin $firewall, array $profile, bool $includeDns): void
    {
        $address = explode('/', $profile['address'] ?? '')[0];
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return;
        }

        $ready = self::gatewayAvailable($firewall, $profile);
        $destinations = [
            ['to' => self::probeIp(), 'to_port' => '443', 'protocol' => 'tcp', 'kind' => 'probe']
        ];
        foreach ($includeDns ? ($profile['dns'] ?? []) : [] as $dns) {
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
        $settings = Policy::effectiveRouting($model);
        foreach ($settings['strictInterfaces'] as $interface) {
            $marker = Policy::marker('block', $interface);
            if ($settings['enabled'] !== (($loaded[$marker]['action'] ?? '') === 'block')) {
                throw new \RuntimeException('The loaded PF rules do not match the Blank VPN segment policy.');
            }
        }
        if (!$settings['enabled']) {
            return;
        }
        if ($settings['coverage'] === 'network' && $settings['networkMode'] === 'full_multi') {
            foreach ($settings['interfaces'] as $interface) {
                $id = 'network:' . $interface;
                if (($loaded[Policy::marker('kill', $id)]['action'] ?? '') !== 'block' ||
                    ($loaded[Policy::marker('kill_v6', $id)]['action'] ?? '') !== 'block') {
                    throw new \RuntimeException('A Whole-Network plus Multi-Path guard is missing.');
                }
            }
        }
        $assignments = $settings['coverage'] === 'device'
            ? Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()) : [];
        foreach ($assignments as $id => $row) {
            $mode = Policy::mode($row);
            $guard = $loaded[Policy::marker('kill', $id)] ?? [];
            $ipv6Guard = $loaded[Policy::marker('kill_v6', $id)] ?? [];
            $pass = $loaded[Policy::marker('device', $id)] ?? [];
            if (Policy::bindsMac($row) &&
                (($pass !== [] && ($pass['source'] ?? '') !== $row['ip']) ||
                    ($guard !== [] && ($guard['source'] ?? '') !== $row['ip']))) {
                throw new \RuntimeException('A MAC-bound rule still uses its previous IPv4 address.');
            }
            $failClosed = in_array($mode, ['blocked', 'full_multi'], true) ||
                ($mode === 'full' && $row['failure'] !== 'wan');
            $expectIpv6 = $failClosed || ($row['ip'] === '' && Policy::bindsMac($row) && Policy::killSwitch($row));
            if (($row['ip'] !== '' && $failClosed && ($guard['action'] ?? '') !== 'block') ||
                (!empty($row['ipv6']) && $expectIpv6 && ($ipv6Guard['action'] ?? '') !== 'block')) {
                throw new \RuntimeException('A per-IP fail-closed firewall guard is missing.');
            }
        }
        $services = SmartRouting::activeServices($settings, SmartRouting::services($model));
        if ($services !== [] && SmartRouting::usesBypass($settings)) {
            foreach ($settings['interfaces'] as $interface) {
                $id = 'network:' . $interface;
                if (($loaded[Policy::marker('device', $id)]['action'] ?? '') === 'pass' &&
                    ($loaded[Policy::marker('bypass', $id)]['action'] ?? '') !== 'match') {
                    throw new \RuntimeException('A Whole-Network bypass rule is missing.');
                }
            }
            return;
        }
        $combinedInterfaces = self::combinedInterfaces($assignments);
        foreach ($services as $id => $service) {
            foreach ($settings['smartInterfaces'] as $interface) {
                if (in_array($interface, $settings['strictInterfaces'], true) &&
                    !isset($combinedInterfaces[$interface])) {
                    continue;
                }
                $marker = Policy::marker('service_guard', $id . ':' . $interface);
                if (($loaded[$marker]['action'] ?? '') !== 'block') {
                    throw new \RuntimeException('A Multi-Path destination guard is missing.');
                }
            }
        }
    }
}
