<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Plugin;

final class Firewall
{
    // All 16 service-specific pass/block pairs precede the combined policy's default route.
    private const STATIC_DESTINATIONS = Policy::PRIORITY + 30;
    private const LEARNED_DESTINATIONS = self::STATIC_DESTINATIONS + SmartRouting::MAX_SERVICES * 2;
    private const COMBINED_BASE = self::LEARNED_DESTINATIONS + SmartRouting::MAX_SERVICES * 2 + 2;

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
        $lists = SmartRouting::services($model);
        $services = SmartRouting::forwardServices($settings, $lists);
        $bypass = SmartRouting::bypassServices($settings, $lists);
        $bypassDomains = $bypass !== [] && SmartRouting::hasDomains(array_merge(...array_column($bypass, 'domains')));
        $wan = WanEgress::gateways($firewall);
        $multiOutage = self::multiPathOutage($firewall, $services, $profiles, $health);
        $rows = Policy::assignments($model);
        $assignments = $settings['coverage'] === 'device' ? Policy::routingAssignments($rows, $diagnostics) : [];
        $deviceBypass = Policy::networkBypassSources($settings, $rows, $diagnostics);
        $combinedInterfaces = self::combinedInterfaces($assignments);
        if (($settings['coverage'] === 'network' && $settings['networkMode'] === 'full_multi') ||
            $combinedInterfaces !== [] || $bypass !== [] || $deviceBypass !== []) {
            $combined = Policy::localNetworks(array_replace($settings, ['localNetworks' => []]));
            $combinedFile = Policy::writeState('combined-local-networks', implode("\n", $combined) . "\n");
            $firewall->registerTable(Policy::COMBINED_LOCAL_TABLE, true, $combinedFile);
        }
        if ($bypassDomains || $deviceBypass !== [] ||
            ($settings['coverage'] === 'network' && Policy::usesBase($settings['networkMode']) &&
            !$settings['networkKillSwitch'])) {
            self::registerWanDns($firewall, $wan);
        }
        $wan = array_filter($wan, static fn (array $gateway, string $family): bool =>
            self::wanGatewayMapped($firewall, $gateway, $family), ARRAY_FILTER_USE_BOTH);
        self::registerDeviceBypass($firewall, $interfaces, $deviceBypass, $wan);
        if ($bypass !== []) {
            self::registerBypass($firewall, $settings, $interfaces, $bypass, $wan, $assignments, $diagnostics);
        }
        if ($settings['coverage'] === 'network') {
            self::registerNetworkPolicy(
                $firewall, $settings, $interfaces, $profiles, $health, $multiOutage, $wan, $bypassDomains
            );
        } else {
            self::registerAssignments(
                $firewall, $settings, $interfaces, $assignments, $profiles, $health, $diagnostics, $multiOutage, $bypassDomains
            );
        }

        if ($services !== [] || $bypassDomains) {
            self::registerSmartRoutes(
                $firewall, $settings, $interfaces, $services, $profiles, $health, $assignments, $diagnostics, $bypassDomains
            );
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
                'descr' => 'Blank VPN & Proxy prevents use of the default resolver'
            ]);
            $combined = isset($combinedInterfaces[$interface]);
            $priority = $combined ? self::COMBINED_BASE + 2 : Policy::PRIORITY + 22;
            $firewall->registerFilterRule($priority, [
                'type' => 'block', 'interface' => $interface, 'ipprotocol' => 'inet46',
                'to' => '<' . ($combined ? Policy::COMBINED_LOCAL_TABLE : Policy::LOCAL_TABLE) . '>',
                'to_not' => true, 'quick' => true,
                'label' => Policy::marker('block', $interface),
                'descr' => 'Blank VPN & Proxy managed segment default deny'
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
        array $wan = [],
        bool $bypassDomains = false
    ): void {
        $mode = $settings['networkMode'];
        $killSwitch = $settings['networkKillSwitch'] ?? Policy::usesBase($mode);
        if ($mode === 'disabled' || ($mode === 'multi' && (!$killSwitch || !$multiOutage))) {
            return;
        }
        $base = Policy::usesBase($mode) ? ($profiles[$settings['networkProfile']] ?? []) : [];
        $profile = self::selectProfile($firewall, $base, [], $health);
        foreach ($settings['interfaces'] as $interface) {
            if (!Policy::interfaceId($interface) || empty($interfaces[$interface]['if'])) {
                continue;
            }
            $id = 'network:' . $interface;
            $fallback = !$killSwitch && $profile === null ? $wan : [];
            if ($mode === 'full_multi') {
                self::registerCombinedPolicy($firewall, $id, $interface, 'any', 'any', $base, $profile, $fallback);
                continue;
            }
            if ($mode === 'multi') {
                self::registerOutageGuard($firewall, $id, $interface, 'any', 'any',
                    Policy::LOCAL_TABLE, $bypassDomains ? Resolver::BYPASS_PORT : 0);
                continue;
            }
            if ($profile !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                    'to' => '<' . Policy::LOCAL_TABLE . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true,
                    'statetype' => 'keep', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN & Proxy Whole-Network coverage'
                ] + self::stateOptions($profile));
                self::registerClientNat($firewall, $profile, $interface, 'any', 60);
            }
            $basePort = (int)(($profile ?? $base)['dnsPort'] ?? 0);
            foreach (['inet', 'inet6'] as $family) {
                if ($mode === 'full' && isset($fallback[$family])) {
                    self::registerWanFallback($firewall, $id, $interface, $family, $fallback[$family],
                        Policy::PRIORITY + 10, Policy::LOCAL_TABLE);
                }
                if (isset($fallback['inet'])) {
                    self::redirectDns($firewall, $interface, 'any', Resolver::FALLBACK_PORT, $id, 57, false, $family);
                } elseif (($profile !== null && $family === 'inet') || $bypassDomains) {
                    self::redirectDns($firewall, $interface, 'any', $basePort, $id, 58, false, $family);
                }
                self::registerGuard($firewall, $id, $interface, 'any', $family);
            }
        }
    }

    private static function registerDeviceBypass(
        Plugin $firewall,
        array $interfaces,
        array $scopes,
        array $wan
    ): void {
        foreach ($scopes as $id => $scope) {
            $interface = $scope['interface'];
            if (empty($interfaces[$interface]['if'])) {
                continue;
            }
            foreach ($scope['sources'] as $family => $source) {
                $key = $id . ':' . $family;
                self::redirectDns($firewall, $interface, $source, Resolver::DEVICE_BYPASS_PORT,
                    'network-bypass:' . $id, 54, false, $family);
                $rule = [
                    'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
                    'from' => $source, 'quick' => true, 'disablereplyto' => true
                ];
                $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                    'type' => 'block', 'protocol' => 'tcp/udp', 'to_port' => '53',
                    'label' => Policy::marker('device_bypass_dns_guard', $key)
                ] + $rule);
                $internet = ['to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true] + $rule;
                if (isset($wan[$family])) {
                    $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                        'type' => 'pass', 'gateway' => $wan[$family]['gateway'], 'skip_rules_gw_down' => true,
                        'statetype' => 'keep', 'label' => Policy::marker('device_bypass', $key)
                    ] + $internet);
                }
                $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                    'type' => 'block', 'label' => Policy::marker('device_bypass_guard', $key)
                ] + $internet);
            }
        }
    }

    private static function registerBypass(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $bypass,
        array $wan,
        array $assignments,
        Diagnostics $diagnostics
    ): void {
        $entries = array_merge(...array_column($bypass, 'domains'));
        $tables = [];
        if (SmartRouting::hasDomains($entries)) {
            $tables['learned'] = SmartRouting::bypassTable($bypass);
            $firewall->registerTable($tables['learned'], true);
        }
        $addresses = SmartRouting::addressEntries($entries);
        if ($addresses !== []) {
            $tables['static'] = SmartRouting::bypassAddressTable($bypass);
            self::registerAddressTable($firewall, $tables['static'], $addresses);
        }
        foreach (self::bypassScopes($settings, $assignments, $diagnostics) as $interface => $families) {
            if (empty($interfaces[$interface]['if'])) {
                continue;
            }
            foreach ($families as $family => $scope) {
                $id = $interface . ':' . $family;
                $tag = Policy::marker('bypass_source', $id);
                $match = [
                    'type' => 'match', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
                    'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true,
                    'quick' => false, 'tag' => $tag
                ];
                if ($scope['sources'] !== []) {
                    $sources = self::registerSmartSources($firewall, $id, 'bi', $scope['sources']);
                    $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                        'from' => '<' . $sources . '>', 'label' => Policy::marker('bypass_include', $id)
                    ] + $match);
                }
                if ($scope['all']) {
                    $exclude = [];
                    if ($scope['excluded'] !== []) {
                        $table = self::registerSmartSources($firewall, $id, 'be', $scope['excluded']);
                        $exclude = ['from' => '<' . $table . '>', 'from_not' => true];
                    }
                    $firewall->registerFilterRule(Policy::PRIORITY + 7,
                        ['label' => Policy::marker('bypass_default', $id)] + $exclude + $match);
                }
                foreach ($tables as $kind => $table) {
                    $destination = '<' . $table . '>';
                    $rule = [
                        'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
                        'to' => $destination, 'quick' => true, 'tagged' => $tag, 'disablereplyto' => true
                    ];
                    if (isset($wan[$family])) {
                        $firewall->registerFilterRule(Policy::PRIORITY + 8, [
                            'type' => 'pass', 'gateway' => $wan[$family]['gateway'], 'skip_rules_gw_down' => true,
                            'statetype' => 'keep', 'label' => Policy::marker('bypass', $id . ':' . $kind)
                        ] + $rule);
                        if ($family === 'inet' && self::isTailnetIngress($settings, $interface)) {
                            foreach (array_unique($scope['sources']) as $source) {
                                self::registerClientNat($firewall, $wan[$family], $source, $destination, 59);
                            }
                        }
                    }
                    $firewall->registerFilterRule(Policy::PRIORITY + 9, [
                        'type' => 'block', 'label' => Policy::marker('bypass_guard', $id . ':' . $kind)
                    ] + $rule);
                }
            }
        }
    }

    public static function bypassScopes(array $settings, array $assignments, Diagnostics $diagnostics): array
    {
        if (!SmartRouting::usesBypass($settings)) {
            return [];
        }
        $network = $settings['coverage'] === 'network';
        $scopes = [];
        foreach ($settings['interfaces'] as $interface) {
            if (!Policy::interfaceId($interface) && $interface !== Policy::TAILSCALE_DEVICE) {
                continue;
            }
            $strict = in_array($interface, $settings['strictInterfaces'], true);
            $all = $network || (!$strict && !self::isTailnetIngress($settings, $interface) &&
                empty($settings['smartAssignedOnly']) &&
                in_array($interface, $settings['smartInterfaces'], true) &&
                !in_array($interface, $settings['deviceMultiInterfaces'] ?? [], true));
            $families = [];
            foreach (['inet' => FILTER_FLAG_IPV4, 'inet6' => FILTER_FLAG_IPV6] as $family => $flag) {
                $sources = $excluded = [];
                foreach ($assignments as $row) {
                    if ($row['interface'] !== $interface) {
                        continue;
                    }
                    $source = $row[$family === 'inet' ? 'ip' : 'ipv6'] ?? '';
                    $mode = Policy::assignmentPaused($row) ? 'disabled' : Policy::mode($row);
                    if (!filter_var($source, FILTER_VALIDATE_IP, $flag) || $mode === 'default') {
                        continue;
                    }
                    $excluded[] = $source;
                    if (($mode !== 'multi' || !$strict) && in_array($mode, ['full', 'full_multi', 'multi'], true) &&
                        filter_var($row['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
                        self::hasAssignmentIdentity($settings, $row, $diagnostics)) {
                        $sources[] = $source;
                    }
                }
                if ($all || $sources !== []) {
                    $families[$family] = ['all' => $all, 'sources' => $sources, 'excluded' => $excluded];
                }
            }
            if ($families !== []) {
                $scopes[$interface] = $families;
            }
        }
        return $scopes;
    }

    private static function registerWanDns(Plugin $firewall, array $wan): void
    {
        if (!isset($wan['inet'])) {
            return;
        }
        $gateway = $wan['inet'];
        foreach (WanEgress::dnsServers($wan) as $ip) {
            $id = $ip . ':' . $gateway['address'];
            $rule = [
                'direction' => 'out', 'ipprotocol' => 'inet', 'protocol' => 'tcp/udp',
                'from' => $gateway['address'], 'to' => $ip, 'to_port' => '53',
                'quick' => true, 'disablereplyto' => true
            ];
            if (self::wanGatewayMapped($firewall, $gateway, 'inet')) {
                $firewall->registerFilterRule(Policy::PRIORITY - 2, [
                    'type' => 'pass', 'gateway' => $gateway['gateway'], 'skip_rules_gw_down' => true,
                    'statetype' => 'keep', 'label' => Policy::marker('wan_dns', $id)
                ] + $rule);
            }
            $firewall->registerFilterRule(Policy::PRIORITY - 1, [
                'type' => 'block', 'label' => Policy::marker('wan_dns_guard', $id)
            ] + $rule);
        }
    }

    private static function wanGatewayMapped(Plugin $firewall, array $gateway, string $family): bool
    {
        $mapped = @$firewall->getGateway($gateway['gateway']) ?? [];
        return ($mapped['interface'] ?? '') === $gateway['interface'] && ($mapped['proto'] ?? '') === $family &&
            !empty($mapped['logic']);
    }

    private static function registerWanFallback(
        Plugin $firewall,
        string $id,
        string $interface,
        string $family,
        array $gateway,
        int $priority,
        string $local
    ): void {
        $firewall->registerFilterRule($priority, [
            'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
            'to' => '<' . $local . '>', 'to_not' => true,
            'quick' => true, 'disablereplyto' => true, 'statetype' => 'keep',
            'gateway' => $gateway['gateway'], 'skip_rules_gw_down' => true,
            'label' => Policy::marker('wan_fallback', $id . ':' . $family)
        ]);
    }

    private static function isTailnetIngress(array $settings, string $interface): bool
    {
        return $interface === Policy::TAILSCALE_DEVICE || in_array($interface, $settings['tailscaleInterfaces'] ?? [], true);
    }

    private static function registerAssignments(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $assignments,
        array $profiles,
        array $health,
        Diagnostics $diagnostics,
        bool $multiOutage = false,
        bool $bypassDomains = false
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
                    self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6, Policy::LOCAL_TABLE,
                        $reserved && $bypassDomains ? Resolver::BYPASS_PORT : 0);
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
                'descr' => 'Blank VPN & Proxy device routing'
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
            $basePort = (int)(($selected ?? $primary)['dnsPort'] ?? 0);
            $bypassPort = $bypassDomains && $reserved ? $basePort : 0;
            if ($bypassPort && $ipv6 !== '' && ($selected !== null || !$killSwitch)) {
                self::redirectDns($firewall, $interface, $ipv6, $bypassPort, $id, 58, false, 'inet6');
            }
            if ($selected !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'gateway' => $selected['gateway'], 'skip_rules_gw_down' => true
                ] + self::stateOptions($selected) + $pass);
                self::registerClientNat($firewall, $selected, $ip, 'any', 60);
                self::redirectDns($firewall, $interface, $ip, (int)$selected['dnsPort'], $id, 58);
            } elseif ($reserved && $row['failure'] === 'wan' && $primary !== []) {
                if ($strict && !$bypassPort) {
                    self::allowNativeDns($firewall, $interface, $ip, $id);
                }
                if ($strict) {
                    $firewall->registerFilterRule(Policy::PRIORITY + 10, $pass);
                }
                if ($bypassPort) {
                    self::redirectDns($firewall, $interface, $ip, $bypassPort, $id, 58);
                } elseif (!$strict && in_array($interface, $settings['smartInterfaces'], true)) {
                    self::bypassSmartDns($firewall, $interface, $ip, 'inet');
                    if ($ipv6 !== '') {
                        self::bypassSmartDns($firewall, $interface, $ipv6, 'inet6');
                    }
                }
                continue;
            } elseif ($killSwitch) {
                self::registerOutageGuard($firewall, $id, $interface, $ip, $ipv6, Policy::LOCAL_TABLE, $bypassPort);
                continue;
            } else {
                self::redirectDns($firewall, $interface, $ip, $bypassPort ?: Resolver::LOCAL_PORT, $id, 58);
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
        ?array $profile,
        array $fallback = []
    ): void {
        if ($profile !== null) {
            $firewall->registerFilterRule(self::COMBINED_BASE, [
                'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                'from' => $ip, 'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true,
                'quick' => true, 'disablereplyto' => true, 'statetype' => 'keep',
                'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN & Proxy base tunnel with Multi-Path'
            ] + self::stateOptions($profile));
            self::registerClientNat($firewall, $profile, $ip === 'any' ? $interface : $ip, 'any', 60);
        }
        // Keep DNS classification available for healthy overrides even when the base tunnel is down.
        $port = Resolver::combinedPort($base);
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                if (isset($fallback[$family])) {
                    self::registerWanFallback($firewall, $id, $interface, $family, $fallback[$family],
                        self::COMBINED_BASE + 1, Policy::COMBINED_LOCAL_TABLE);
                }
                if (isset($fallback['inet'])) {
                    self::redirectDns($firewall, $interface, $source, Resolver::FALLBACK_PORT, $id, 57, false, $family);
                } elseif ($port === 0) {
                    self::bypassSmartDns($firewall, $interface, $source, $family);
                } else {
                    self::redirectDns($firewall, $interface, $source, $port, $id, 57, false, $family);
                }
                self::registerGuard(
                    $firewall, $id, $interface, $source, $family, [], self::COMBINED_BASE + 2, Policy::COMBINED_LOCAL_TABLE
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
        string $local = Policy::LOCAL_TABLE,
        int $dnsPort = 0
    ): void {
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                if ($dnsPort === 0) {
                    self::bypassSmartDns($firewall, $interface, $source, $family);
                } else {
                    self::redirectDns($firewall, $interface, $source, $dnsPort, $id, 58, false, $family);
                }
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
            'label' => Policy::marker('kill' . $suffix, $id), 'descr' => 'Blank VPN & Proxy device internet guard'
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
        ?Diagnostics $diagnostics = null,
        bool $bypassDomains = false
    ): void {
        $combinedInterfaces = self::combinedInterfaces($assignments);
        $combinedNetwork = ($settings['coverage'] ?? '') === 'network' && $settings['networkMode'] === 'full_multi';
        $routes = [];
        $hasDomains = $bypassDomains;
        foreach (array_values($services) as $index => $service) {
            $profile = self::selectProfile($firewall, $profiles[$service['profile']] ?? [], [], $health);
            $addresses = SmartRouting::addressEntries($service['domains']);
            if ($addresses !== []) {
                $table = SmartRouting::addressTable($service);
                self::registerAddressTable($firewall, $table, $addresses);
                $routes[] = [$service['id'], $table, $profile, self::STATIC_DESTINATIONS + $index * 2, 'service'];
            }
            if (SmartRouting::hasDomains($service['domains'])) {
                $hasDomains = true;
                $table = SmartRouting::table($service);
                $firewall->registerTable($table, true);
                $routes[] = [$service['id'], $table, $profile, self::LEARNED_DESTINATIONS + $index * 2,
                    $addresses === [] ? 'service' : 'service_dns'];
            }
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
            if ($hasDomains && !$assignedOnly && !$combinedNetwork) {
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
                    if ($hasDomains && !$combined && $assignedOnly && $mode === 'multi') {
                        self::redirectDns($firewall, $interface, $source, SmartRouting::PORT, $id, 64, false, $family);
                    } elseif (Policy::assignmentPaused($row) || ($row['ip'] === '' && $mode === 'disabled')) {
                        self::bypassSmartDns($firewall, $interface, $source, $family);
                    }
                }
            }
            if ($routes !== [] && !$combinedNetwork && (!$assignedOnly || $sources !== [])) {
                self::registerSmartScope($firewall, $interface, $tag, Policy::LOCAL_TABLE, $sources, !$assignedOnly);
            }
            if ($routes !== [] && ($combinedNetwork || $combinedSources !== [])) {
                self::registerSmartScope($firewall, $interface, $tag, Policy::COMBINED_LOCAL_TABLE, $combinedSources, false);
            }
            foreach ($routes as [$id, $table, $profile, $priority, $marker]) {
                $id .= ':' . $interface;
                $table = '<' . $table . '>';
                $base = [
                    'direction' => 'in', 'interface' => $interface, 'to' => $table,
                    'tagged' => $tag, 'quick' => true, 'disablereplyto' => true
                ];
                if ($profile !== null) {
                    $firewall->registerFilterRule($priority, [
                        'type' => 'pass', 'ipprotocol' => 'inet', 'gateway' => $profile['gateway'],
                        'skip_rules_gw_down' => true, 'statetype' => 'keep',
                        'label' => Policy::marker($marker, $id)
                    ] + self::stateOptions($profile) + $base);
                    $source = $interface === Policy::TAILSCALE_DEVICE ? Policy::TAILSCALE_V4 : $interface;
                    self::registerClientNat($firewall, $profile, $source, $table, 61);
                }
                // A learned destination never takes the native route when its selected tunnel is unavailable.
                // IPv6 for learned destinations is blocked until VPN egress supports it.
                $firewall->registerFilterRule($priority + 1, [
                    'type' => 'block', 'ipprotocol' => 'inet46',
                    'label' => Policy::marker($marker . '_guard', $id)
                ] + $base);
            }
        }
    }

    private static function registerAddressTable(Plugin $firewall, string $table, array $addresses): void
    {
        $file = Policy::writeState($table, implode("\n", array_unique($addresses)) . "\n");
        $firewall->registerTable($table, true, $file);
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
            'descr' => 'Blank VPN & Proxy Multi-Path source and destination scope'
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
            'descr' => 'Blank VPN & Proxy client source NAT'
        ]);
    }

    private static function bypassSmartDns(Plugin $firewall, string $interface, string $ip, string $family): void
    {
        if (self::dnsRedirectionAvailable()) {
            $firewall->registerDestinationNatRule(55, [
                'nordr' => true, 'interface' => $interface, 'ipprotocol' => $family,
                'from' => $ip, 'protocol' => 'tcp/udp', 'to_port' => '53', 'natreflection' => 'disable',
                'descr' => 'Blank VPN & Proxy uses regular DNS for this address'
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
            'tag' => $tag, 'natreflection' => 'disable', 'descr' => 'Blank VPN & Proxy DNS redirection'
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

    public static function parseLoadedRules(string $output): array
    {
        $rules = [];
        foreach (explode("\n", $output) as $line) {
            if (!preg_match('/\blabel "(blankvpn_[a-z0-9_]+)"/', $line, $match)) {
                continue;
            }
            preg_match('/\broute-to\s+[({\s]*([a-zA-Z][a-zA-Z0-9_.-]*)\b/', $line, $gateway);
            preg_match('/^(?:@\d+\s+)?(pass|block|match)\b/', ltrim($line), $action);
            preg_match('/\bfrom\s+([a-f0-9:.]+)(?:%[\w.-]+)?(?:\/(?:32|128))?\s/i', $line, $source);
            preg_match('/\bto\s+<([a-z0-9_]+)>/i', $line, $table);
            preg_match('/\b(?:port\s*=\s*)([0-9]+)\b/', $line, $port);
            preg_match('/\btagged\s+"?(blankvpn_[a-z0-9_]+)/', $line, $tagged);
            preg_match('/\btag\s+"?(blankvpn_[a-z0-9_]+)/', $line, $tag);
            $rules[$match[1]] = [
                'gateway' => $gateway[1] ?? null, 'action' => $action[1] ?? null, 'source' => $source[1] ?? null,
                'table' => $table[1] ?? null, 'port' => isset($port[1]) ? (int)$port[1] : null,
                'tagged' => $tagged[1] ?? null, 'tag' => $tag[1] ?? null
            ];
        }
        return $rules;
    }

    public static function dnsRedirectLoaded(array $loaded, string $nat, string $id, int $port, string $family): bool
    {
        $tag = Policy::marker('dns', $id . ':' . $family);
        $rule = $loaded[$tag] ?? [];
        return ($rule['action'] ?? '') === 'pass' && ($rule['port'] ?? null) === $port &&
            ($rule['tagged'] ?? '') === $tag &&
            preg_match('/^(?:@\d+\s+)?rdr\b[^\r\n]*\btag\s+"?' . $tag . '\b[^\r\n]*' .
                '(?:->|rdr-to)\s+' . ($family === 'inet6' ? '::1' : '127\.0\.0\.1') .
                '\s+port\s+' . $port . '\b/m', $nat) === 1;
    }

    public static function loadedNat(): string
    {
        return (new Backend())->configdRun('blankvpn loaded_nat', false, 15);
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
            throw new \RuntimeException('OPNsense could not load the Blank VPN & Proxy firewall policy.');
        }
        $loaded = self::loadedRules();
        if ($loaded === null) {
            throw new \RuntimeException('Blank VPN & Proxy could not verify the loaded PF rules.');
        }
        $settings = Policy::effectiveRouting($model);
        foreach ($settings['strictInterfaces'] as $interface) {
            $marker = Policy::marker('block', $interface);
            if ($settings['enabled'] !== (($loaded[$marker]['action'] ?? '') === 'block')) {
                throw new \RuntimeException('The loaded PF rules do not match the Blank VPN & Proxy segment policy.');
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
        $diagnostics = new Diagnostics();
        $rows = Policy::assignments($model, true);
        foreach (Policy::networkBypassSources($settings, $rows, $diagnostics) as $id => $scope) {
            foreach ($scope['sources'] as $family => $address) {
                $key = $id . ':' . $family;
                $guard = $loaded[Policy::marker('device_bypass_guard', $key)] ?? [];
                $dnsGuard = $loaded[Policy::marker('device_bypass_dns_guard', $key)] ?? [];
                $route = $loaded[Policy::marker('device_bypass', $key)] ?? [];
                if (($guard['source'] ?? '') !== $address || ($guard['action'] ?? '') !== 'block' ||
                    ($dnsGuard['source'] ?? '') !== $address || ($dnsGuard['action'] ?? '') !== 'block' ||
                    ($route !== [] && (($route['source'] ?? '') !== $address || empty($route['gateway'])))) {
                    throw new \RuntimeException('A device Bypass rule or its WAN guard does not match the confirmed device address.');
                }
            }
        }
        $assignments = $settings['coverage'] === 'device' ? Policy::routingAssignments($rows, $diagnostics) : [];
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
        $lists = SmartRouting::services($model);
        $bypass = SmartRouting::bypassServices($settings, $lists);
        if ($bypass !== []) {
            $entries = array_merge(...array_column($bypass, 'domains'));
            $tables = array_filter([
                'static' => SmartRouting::addressEntries($entries) !== [],
                'learned' => SmartRouting::hasDomains($entries)
            ]);
            foreach (self::bypassScopes($settings, $assignments, new Diagnostics()) as $interface => $families) {
                foreach ($families as $family => $scope) {
                    foreach (array_keys($tables) as $kind) {
                        $id = $interface . ':' . $family . ':' . $kind;
                        if (($loaded[Policy::marker('bypass_guard', $id)]['action'] ?? '') !== 'block') {
                            throw new \RuntimeException('A Bypass destination guard is missing.');
                        }
                    }
                }
            }
        }
        $services = SmartRouting::forwardServices($settings, $lists);
        if ($settings['coverage'] === 'network' && $settings['networkMode'] === 'full_multi' &&
            array_filter($services, static fn (array $service): bool => SmartRouting::hasDomains($service['domains'])) !== []) {
            $profiles = Policy::routes($model);
            $base = $profiles[$settings['networkProfile']] ?? [];
            $nat = self::loadedNat();
            foreach ($settings['interfaces'] as $interface) {
                $id = 'network:' . $interface;
                $port = ($loaded[Policy::marker('wan_fallback', $id . ':inet')]['action'] ?? '') === 'pass'
                    ? Resolver::FALLBACK_PORT : Resolver::combinedPort($base);
                if (!self::dnsRedirectLoaded($loaded, $nat, $id, $port, 'inet') ||
                    !self::dnsRedirectLoaded($loaded, $nat, $id, $port, 'inet6')) {
                    throw new \RuntimeException('The DNS redirect for Whole-Network + Multi-Path did not load on ' . $interface . '.');
                }
            }
        }

        $combinedInterfaces = self::combinedInterfaces($assignments);
        foreach ($services as $id => $service) {
            foreach ($settings['smartInterfaces'] as $interface) {
                if (in_array($interface, $settings['strictInterfaces'], true) &&
                    !isset($combinedInterfaces[$interface])) {
                    continue;
                }
                $rule = $id . ':' . $interface;
                $marker = Policy::marker('service_guard', $rule);
                $mixed = SmartRouting::hasDomains($service['domains']) &&
                    SmartRouting::addressEntries($service['domains']) !== [];
                $dnsGuard = Policy::marker('service_dns_guard', $rule);
                if (($loaded[$marker]['action'] ?? '') !== 'block' ||
                    ($mixed && ($loaded[$dnsGuard]['action'] ?? '') !== 'block')) {
                    throw new \RuntimeException('A Multi-Path destination guard is missing.');
                }
            }
        }
    }
}
