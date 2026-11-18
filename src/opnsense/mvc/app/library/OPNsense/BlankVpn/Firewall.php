<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Plugin;

final class Firewall
{
    // All 16 service-specific pass/block pairs precede the combined policy's default route.
    private const VPN_EGRESS_TAG = 'blankvpn_tunnel_only';
    private const TAILNET_TUNNEL_TAG = 'blankvpn_tailnet_tunnel';
    private const TAILNET_WAN_TAG = 'blankvpn_tailnet_wan';
    // Tailscale carries 1280-byte IP packets. Leave room for IPv4 and TCP headers.
    private const TAILNET_TCP_SCRUB = 'max-mss 1240';
    // OPNsense evaluates manual outbound NAT at priority 100 and automatic NAT at 200.
    private const PROBE_NO_NAT_PRIORITY = 40;
    // Run after the OPNsense user rules so explicit quick rules are respected.
    private const TAILNET_DEFAULT_PRIORITY = 490000;
    private const STATIC_DESTINATIONS = Policy::PRIORITY + 30;
    private const LEARNED_DESTINATIONS = self::STATIC_DESTINATIONS + SmartRouting::MAX_SERVICES * 2;
    private const COMBINED_BASE = self::LEARNED_DESTINATIONS + SmartRouting::MAX_SERVICES * 2 + 2;

    public static function installRules(Plugin $firewall): void
    {
        $model = new BlankVpn();
        $settings = Policy::effectiveRouting($model);
        $profiles = Policy::routes($model, false);
        $health = self::health();
        $interfaces = iterator_to_array($firewall->getInterfaceMapping());
        $nativeTailnet = Policy::nativeTailnetConfigured();
        if ((string)(Config::getInstance()->object()->OPNsense->tailscale->settings->enabled ?? '') === '1') {
            // Keep Tailscale's native NAT anchor after OPNsense and VPN source NAT rules.
            $firewall->registerAnchor('tailscale', 'nat');
            $firewall->registerAnchor('tailscale');
        }
        if ($nativeTailnet || in_array(Policy::TAILSCALE_DEVICE, $settings['interfaces'], true)) {
            $interface = Policy::TAILSCALE_DEVICE;
            $interfaces[$interface] ??= [
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
            self::registerProfile($firewall, $profile, $settings['enabled'], isset($settings['scopes']['tailscale']));
        }
        unset($profile);
        $profiles += RouteGroups::aliases($model, $profiles, $health, true);
        if (!$settings['enabled']) {
            if ($nativeTailnet) {
                // Disabling Blank VPN must leave the native Tailscale exit node on the ISP WAN.
                $connected = Policy::localNetworks(array_replace($settings, ['localNetworks' => []]));
                $file = Policy::writeState('combined-local-networks', implode("\n", $connected) . "\n");
                $firewall->registerTable(Policy::COMBINED_LOCAL_TABLE, true, $file);
                $wan = array_filter(WanEgress::gateways($firewall), static fn (array $gateway, string $family): bool =>
                    self::wanGatewayMapped($firewall, $gateway, $family), ARRAY_FILTER_USE_BOTH);
                self::registerDirectTailnetInternet($firewall, $wan);
            }
            return;
        }

        $localNetworks = Policy::localNetworks($settings);
        $localFile = Policy::writeState('local-networks', implode("\n", $localNetworks) . "\n");
        $firewall->registerTable(Policy::LOCAL_TABLE, true, $localFile);
        $firewall->setGatewayGroups($proxyGateways);
        $diagnostics = new Diagnostics();
        $lists = SmartRouting::services($model);
        $scopes = Policy::scopes($settings);
        $wan = WanEgress::gateways($firewall);
        $rows = Policy::assignments($model);
        $bound = Policy::routingAssignments($rows, $diagnostics);
        $connected = Policy::localNetworks(array_replace($settings, ['localNetworks' => []]));
        $connectedFile = Policy::writeState('combined-local-networks', implode("\n", $connected) . "\n");
        $firewall->registerTable(Policy::COMBINED_LOCAL_TABLE, true, $connectedFile);
        self::registerUplinkGuards($firewall, $interfaces, isset($scopes['tailscale']));
        $wantWanDns = false;
        foreach ($scopes as $scope) {
            $wantWanDns = $wantWanDns || SmartRouting::hasBypassDomains($scope, $lists) ||
                Policy::networkBypassAssignments($scope, $rows) !== [] || Resolver::usesWanFallback($scope);
        }
        if ($wantWanDns) {
            self::registerWanDns($firewall, $wan);
        }
        $wan = array_filter($wan, static fn (array $gateway, string $family): bool =>
            self::wanGatewayMapped($firewall, $gateway, $family), ARRAY_FILTER_USE_BOTH);
        if ($nativeTailnet && !isset($scopes['tailscale'])) {
            // Local Blank VPN policy does not replace ordinary Tailscale exit-node internet.
            self::registerDirectTailnetInternet($firewall, $wan);
        }
        if (isset($scopes['tailscale'])) {
            foreach ($wan as $family => $gateway) {
                self::registerTailnetOutput($firewall, $gateway, $family, self::TAILNET_WAN_TAG);
            }
        }
        $registered = [];
        foreach ($scopes as $scope) {
            $assignments = $scope['coverage'] === 'device' ? Policy::scopedAssignments($scope, $bound) : [];
            $services = SmartRouting::forwardServices($scope, $lists);
            $bypass = SmartRouting::bypassServices($scope, $lists);
            $bypassDomains = SmartRouting::hasBypassDomains($scope, $lists);
            self::registerSharedLanGuards($firewall, $interfaces, $scope, $assignments, $diagnostics);
            if (($scope['scope'] ?? '') === 'tailscale' &&
                ($scope['coverage'] === 'device' || $scope['networkMode'] === 'disabled')) {
                foreach ($scope['interfaces'] as $interface) {
                    if (!empty($interfaces[$interface]['if']) &&
                        ($interface !== Policy::TAILSCALE_DEVICE || Policy::nativeTailnetConfigured())) {
                        self::registerTailnetInternet($firewall, 'network:' . $interface, $interface, [
                            'inet' => Policy::TAILSCALE_V4, 'inet6' => Policy::TAILSCALE_V6
                        ], $wan);
                    }
                }
            }
            self::registerDeviceBypass($firewall, $interfaces, Policy::networkBypassSources($scope, $rows, $diagnostics), $wan);
            if ($bypass !== []) {
                self::registerBypass($firewall, $scope, $interfaces, $bypass, $wan, $assignments, $diagnostics, $registered);
            }
            if ($scope['coverage'] === 'network') {
                self::registerNetworkPolicy(
                    $firewall, $scope, $interfaces, $profiles, $health, $wan, $bypassDomains
                );
            } else {
                self::registerAssignments(
                    $firewall, $scope, $interfaces, $assignments, $profiles, $health, $diagnostics, $bypassDomains
                );
            }
            if ($services !== [] || $bypassDomains) {
                self::registerSmartRoutes(
                    $firewall, $scope, $interfaces, $services, $profiles, $health, $assignments, $diagnostics,
                    $bypassDomains, $registered
                );
            }
        }
        $combinedInterfaces = self::combinedInterfaces(Policy::deviceAssignments($settings, $bound));

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

    private static function registerUplinkGuards(Plugin $firewall, array $interfaces, bool $tailnet = false): void
    {
        $tags = [self::VPN_EGRESS_TAG => 'tunnel_only'];
        if ($tailnet) {
            $tags[self::TAILNET_TUNNEL_TAG] = 'tailnet_tunnel_only';
        }
        foreach (self::uplinks($interfaces) as $id) {
            foreach ($tags as $tag => $kind) {
                $firewall->registerFilterRule(Policy::PRIORITY - 3, [
                    'type' => 'block', 'direction' => 'out', 'interface' => $id, 'ipprotocol' => 'inet46',
                    'tagged' => $tag, 'quick' => true, 'label' => Policy::marker($kind, $id)
                ]);
            }
        }
    }

    private static function uplinks(array $interfaces): array
    {
        return array_keys(array_filter($interfaces, static function (array $row, string $id): bool {
            $device = $row['if'] ?? '';
            return $device !== '' && !NativeVpn::tunnelDevice($device) && $device !== Policy::TAILSCALE_DEVICE &&
                ($id === 'wan' || !empty($row['gateway']) || !empty($row['gatewayv6']) || !empty($row['gateway_interface']));
        }, ARRAY_FILTER_USE_BOTH));
    }

    private static function registerSharedLanGuards(
        Plugin $firewall,
        array $interfaces,
        array $settings,
        array $assignments,
        Diagnostics $diagnostics
    ): void {
        $unbound = Policy::unboundKillSwitchInterfaces($settings, $assignments, $diagnostics);
        foreach (Policy::killSwitchIpv6Interfaces($settings, $assignments) as $interface) {
            if (empty($interfaces[$interface]['if'])) {
                continue;
            }
            // IPv6 privacy addresses cannot be tied to a single DHCPv4 reservation.
            // Block all upstream IPv6 from the interface while keeping connected services available.
            $unboundIpv4 = in_array($interface, $unbound, true);
            $families = $unboundIpv4 ? ['inet6', 'inet'] : ['inet6'];
            foreach ($families as $family) {
                $kind = $family === 'inet6' ? 'kill_interface_v6' : 'kill_unbound_v4';
                // Keep generic Multi-Path DNS rules from forwarding unrecognized IPv6 clients to native DNS.
                self::redirectDns($firewall, $interface, 'any', Resolver::LOCAL_PORT, $kind . ':' . $interface,
                    $unboundIpv4 ? 53 : 63, false, $family);
                $rule = [
                    'type' => 'block', 'direction' => 'in', 'interface' => $interface,
                    'ipprotocol' => $family, 'quick' => true, 'from' => 'any'
                ];
                $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                    'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true,
                    'label' => Policy::marker($kind, $interface)
                ] + $rule);
                $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                    'protocol' => 'tcp/udp', 'to_port' => '53',
                    'label' => Policy::marker($kind . '_dns', $interface)
                ] + $rule);
            }
        }
    }

    private static function registerNetworkPolicy(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $profiles,
        array $health,
        array $wan = [],
        bool $bypassDomains = false
    ): void {
        $mode = $settings['networkMode'];
        $killSwitch = $settings['networkKillSwitch'] ?? Policy::usesBase($mode);
        if ($mode === 'disabled') {
            return;
        }
        $base = Policy::usesBase($mode) ? ($profiles[$settings['networkProfile']] ?? []) : [];
        $backup = Policy::usesBase($mode) ? ($profiles[$settings['networkBackupProfile'] ?? ''] ?? []) : [];
        $profile = self::selectProfile($firewall, $base, $backup, $health);
        foreach ($settings['interfaces'] as $interface) {
            if (empty($interfaces[$interface]['if'])) {
                continue;
            }
            $id = 'network:' . $interface;
            $tailnet = self::isTailnetIngress($settings, $interface);
            $sources = $tailnet ? ['inet' => Policy::TAILSCALE_V4, 'inet6' => Policy::TAILSCALE_V6] :
                ['inet' => 'any', 'inet6' => 'any'];
            $fallback = !$killSwitch && $profile === null ? $wan : [];
            if ($mode === 'full_multi') {
                self::registerCombinedPolicy($firewall, $id, $interface, $sources['inet'], $sources['inet6'],
                    $base, $profile, $fallback, $killSwitch, $tailnet);
                continue;
            }
            if ($mode === 'multi') {
                if ($killSwitch) {
                    self::registerProtectedPolicy($firewall, $id, $interface, $sources['inet'], $sources['inet6'],
                        false, Resolver::PROTECTED_MULTI_PORT);
                } elseif ($tailnet) {
                    self::registerTailnetInternet($firewall, $id, $interface, $sources, $wan);
                }
                continue;
            }
            if ($mode === 'full' && $killSwitch && $profile === null) {
                self::registerProtectedPolicy($firewall, $id, $interface, $sources['inet'], $sources['inet6'], true);
                continue;
            }
            $local = $killSwitch || $mode === 'blocked' || $tailnet ? Policy::COMBINED_LOCAL_TABLE : Policy::LOCAL_TABLE;
            if ($profile !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, self::stateOptions($profile, $tailnet) + [
                    'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                    'from' => $sources['inet'],
                    'to' => '<' . $local . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true,
                    'statetype' => 'keep', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN & Proxy Whole-Network coverage'
                ]);
                self::registerClientNat($firewall, $profile, $tailnet ? $sources['inet'] : $interface, 'any', 60);
            }
            $basePort = $killSwitch && $profile !== null
                ? Resolver::protectedPort($profile) : (int)(($profile ?? $base)['dnsPort'] ?? 0);
            foreach ($sources as $family => $source) {
                if ($mode === 'full' && isset($fallback[$family])) {
                    self::registerWanFallback($firewall, $id, $interface, $family, $fallback[$family],
                        Policy::PRIORITY + 10, $local, $source, $tailnet);
                }
                if (isset($fallback['inet'])) {
                    self::redirectDns($firewall, $interface, $source, Resolver::FALLBACK_PORT, $id, 57, false, $family);
                } elseif (($profile !== null && ($family === 'inet' || $killSwitch)) || (!$killSwitch && $bypassDomains)) {
                    self::redirectDns($firewall, $interface, $source, $basePort, $id, 58, false, $family);
                }
                self::registerGuard($firewall, $id, $interface, $source, $family, local: $local);
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
        Diagnostics $diagnostics,
        array &$registered = []
    ): void {
        $entries = array_merge(...array_column($bypass, 'domains'));
        $tables = [];
        if (SmartRouting::hasDomains($entries)) {
            $tables['learned'] = SmartRouting::bypassTable($bypass);
            self::registerDestinationTable($firewall, $tables['learned'], [], $registered);
        }
        $addresses = SmartRouting::addressEntries($entries);
        if ($addresses !== []) {
            $tables['static'] = SmartRouting::bypassAddressTable($bypass);
            self::registerDestinationTable($firewall, $tables['static'], $addresses, $registered);
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
                    $exclude = self::isTailnetIngress($settings, $interface) ?
                        ['from' => self::tailnetSource($family)] : [];
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
                        $tailnet = self::isTailnetIngress($settings, $interface);
                        $firewall->registerFilterRule(Policy::PRIORITY + 8, [
                            'type' => 'pass', 'gateway' => $wan[$family]['gateway'], 'skip_rules_gw_down' => true,
                            'statetype' => 'keep', 'label' => Policy::marker('bypass', $id . ':' . $kind)
                        ] + ($tailnet ? self::tailnetWanState() : []) + $rule);
                        if ($tailnet) {
                            foreach ($scope['all'] ? [self::tailnetSource($family)] : array_unique($scope['sources']) as $source) {
                                self::registerClientNat($firewall, $wan[$family], $source, $destination, 59, $family);
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
        if (!SmartRouting::usesBypass($settings) ||
            (($settings['coverage'] ?? '') === 'network' && !empty($settings['networkKillSwitch']))) {
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
                    if (!Policy::killSwitch($row) && ($mode !== 'multi' || !$strict) &&
                        in_array($mode, ['full', 'full_multi', 'multi'], true) &&
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
        string $local,
        string $source,
        bool $tailnet
    ): void {
        $firewall->registerFilterRule($priority, [
            'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
            'from' => $source, 'to' => '<' . $local . '>', 'to_not' => true,
            'quick' => true, 'disablereplyto' => true, 'statetype' => 'keep',
            'gateway' => $gateway['gateway'], 'skip_rules_gw_down' => true,
            'label' => Policy::marker('wan_fallback', $id . ':' . $family)
        ] + ($tailnet ? self::tailnetWanState() : []));
        if ($tailnet) {
            self::registerClientNat($firewall, $gateway, $source, 'any', 62, $family);
        }
    }

    private static function isTailnetIngress(array $settings, string $interface): bool
    {
        return $interface === Policy::TAILSCALE_DEVICE || in_array($interface, $settings['tailscaleInterfaces'] ?? [], true);
    }

    private static function tailnetSource(string $family): string
    {
        return $family === 'inet' ? Policy::TAILSCALE_V4 : Policy::TAILSCALE_V6;
    }

    private static function registerAssignments(
        Plugin $firewall,
        array $settings,
        array $interfaces,
        array $assignments,
        array $profiles,
        array $health,
        Diagnostics $diagnostics,
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
            $tailnet = self::isTailnetIngress($settings, $interface);
            $local = $killSwitch || $mode === 'blocked' || $tailnet ? Policy::COMBINED_LOCAL_TABLE : Policy::LOCAL_TABLE;
            $canFallback = !$killSwitch && $row['failure'] === 'wan';
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $blockIpv6 = $killSwitch || $mode === 'blocked' ||
                    ($mode === 'full' && $row['profile'] !== '' && $row['failure'] !== 'wan');
                if ((Policy::bindsMac($row) || $killSwitch) && $blockIpv6) {
                    self::registerProtectedPolicy($firewall, $id, $interface, '', $ipv6, true);
                }
                continue;
            }
            $reserved = self::hasAssignmentIdentity($settings, $row, $diagnostics);
            if ($mode === 'full_multi') {
                $base = $profiles[$row['profile']] ?? [];
                $selected = $reserved ? self::selectProfile($firewall, $base, [], $health) : null;
                if (!$reserved || $base === []) {
                    self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, true);
                    continue;
                }
                self::registerCombinedPolicy($firewall, $id, $interface, $ip, $ipv6, $base, $selected,
                    protected: true, tailnet: $tailnet);
                continue;
            }
            if ($mode === 'multi') {
                if ($killSwitch) {
                    $outage = !$reserved || !in_array($interface, $settings['smartInterfaces'], true);
                    self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, $outage,
                        Resolver::PROTECTED_MULTI_PORT);
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
                'to' => '<' . $local . '>', 'to_not' => true, 'quick' => true, 'disablereplyto' => true
            ];
            $pass = [
                'type' => 'pass', 'statetype' => 'keep', 'label' => Policy::marker('device', $id),
                'descr' => 'Blank VPN & Proxy device routing'
            ] + $rule;
            if ($mode === 'blocked') {
                self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, false);
                continue;
            }
            if ($mode === 'full' && $row['profile'] === '' && $killSwitch) {
                self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, true);
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
            $bypassPort = !$killSwitch && $bypassDomains && $reserved ? $basePort : 0;
            if ($bypassPort && $ipv6 !== '' && ($selected !== null || !$killSwitch)) {
                self::redirectDns($firewall, $interface, $ipv6, $bypassPort, $id, 58, false, 'inet6');
            }
            if ($selected !== null) {
                $firewall->registerFilterRule(Policy::PRIORITY + 10, [
                    'gateway' => $selected['gateway'], 'skip_rules_gw_down' => true
                ] + self::stateOptions($selected, $tailnet) + $pass);
                self::registerClientNat($firewall, $selected, $ip, 'any', 60);
                if ($killSwitch) {
                    self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, false,
                        Resolver::protectedPort($selected));
                    continue;
                }
                self::redirectDns($firewall, $interface, $ip, (int)$selected['dnsPort'], $id, 58);
            } elseif ($reserved && $canFallback && $primary !== []) {
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
                self::registerProtectedPolicy($firewall, $id, $interface, $ip, $ipv6, true);
                continue;
            } else {
                self::redirectDns($firewall, $interface, $ip, $bypassPort ?: Resolver::LOCAL_PORT, $id, 58);
            }

            if ($canFallback && $reserved) {
                continue;
            }
            self::registerGuard($firewall, $id, $interface, $ip, 'inet', local: $local);
            // The managed client tunnel is IPv4-only. A per-device WAN fallback
            // is an IPv4 outage policy and must not turn a healthy IPv4 VPN rule
            // into a parallel IPv6 path over the ISP.
            if ($ipv6 !== '') {
                self::registerGuard($firewall, $id, $interface, $ipv6, 'inet6', local: $local);
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
        array $fallback = [],
        bool $protected = false,
        bool $tailnet = false
    ): void {
        if ($profile !== null) {
            $firewall->registerFilterRule(self::COMBINED_BASE, self::stateOptions($profile, $tailnet) + [
                'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet',
                'from' => $ip, 'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>', 'to_not' => true,
                'quick' => true, 'disablereplyto' => true, 'statetype' => 'keep',
                'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                'label' => Policy::marker('device', $id), 'descr' => 'Blank VPN & Proxy base tunnel with Multi-Path'
            ]);
            self::registerClientNat($firewall, $profile, $ip === 'any' ? $interface : $ip, 'any', 60);
        }
        // Keep DNS classification available for healthy overrides even when the base tunnel is down.
        $port = $protected ? Resolver::protectedCombinedPort($base) : Resolver::combinedPort($base);
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source !== '') {
                if (isset($fallback[$family])) {
                    self::registerWanFallback($firewall, $id, $interface, $family, $fallback[$family],
                        self::COMBINED_BASE + 1, Policy::COMBINED_LOCAL_TABLE, $source, $tailnet);
                }
                if (isset($fallback['inet'])) {
                    self::redirectDns($firewall, $interface, $source, Resolver::COMBINED_FALLBACK_PORT, $id, 57, false, $family);
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

    private static function registerTailnetInternet(
        Plugin $firewall,
        string $id,
        string $interface,
        array $sources,
        array $wan
    ): void {
        foreach ($sources as $family => $source) {
            if ($source === '' || !isset($wan[$family])) {
                continue;
            }
            $firewall->registerFilterRule(self::TAILNET_DEFAULT_PRIORITY, [
                'type' => 'pass', 'direction' => 'in', 'interface' => $interface,
                'ipprotocol' => $family, 'from' => $source, 'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>',
                'to_not' => true, 'quick' => false, 'statetype' => 'keep', 'disablereplyto' => true,
                'label' => Policy::marker('tailnet_internet', $id . ':' . $family)
            ] + self::tailnetWanState());
            self::registerClientNat($firewall, $wan[$family], $source, 'any', 62, $family);
        }
    }

    private static function registerDirectTailnetInternet(Plugin $firewall, array $wan): void
    {
        foreach ($wan as $family => $gateway) {
            self::registerTailnetOutput($firewall, $gateway, $family, self::TAILNET_WAN_TAG);
        }
        self::registerTailnetInternet($firewall, 'network:' . Policy::TAILSCALE_DEVICE, Policy::TAILSCALE_DEVICE, [
            'inet' => Policy::TAILSCALE_V4, 'inet6' => Policy::TAILSCALE_V6
        ], $wan);
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

    private static function registerProtectedPolicy(
        Plugin $firewall,
        string $id,
        string $interface,
        string $ip,
        string $ipv6,
        bool $outage,
        int $dnsPort = Resolver::LOCAL_PORT
    ): void {
        foreach (['inet' => $ip, 'inet6' => $ipv6] as $family => $source) {
            if ($source === '') {
                continue;
            }
            $port = $outage || $dnsPort === 0 ? Resolver::LOCAL_PORT : $dnsPort;
            self::redirectDns($firewall, $interface, $source, $port, $id, 56, false, $family);
            self::registerGuard($firewall, $id, $interface, $source, $family,
                priority: self::COMBINED_BASE + 2, local: Policy::COMBINED_LOCAL_TABLE);
            if ($outage) {
                $firewall->registerFilterRule(Policy::PRIORITY + 7, [
                    'type' => 'block', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
                    'from' => $source, 'to' => '<' . Policy::COMBINED_LOCAL_TABLE . '>',
                    'to_not' => true, 'quick' => true, 'label' => Policy::marker('kill_outage', $id . ':' . $family)
                ]);
            }
        }
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
        bool $bypassDomains = false,
        array &$registered = []
    ): void {
        $combinedInterfaces = self::combinedInterfaces($assignments);
        $network = ($settings['coverage'] ?? '') === 'network';
        $protectedMultiNetwork = $network && $settings['networkMode'] === 'multi' && !empty($settings['networkKillSwitch']);
        $connectedOnlyNetwork = ($network && $settings['networkMode'] === 'full_multi') || $protectedMultiNetwork;
        $routes = [];
        $hasDomains = $bypassDomains;
        foreach (array_values($services) as $index => $service) {
            $profile = self::selectProfile($firewall, $profiles[$service['profile']] ?? [], [], $health);
            $addresses = SmartRouting::addressEntries($service['domains']);
            if ($addresses !== []) {
                $table = SmartRouting::addressTable($service);
                self::registerDestinationTable($firewall, $table, $addresses, $registered);
                $routes[] = [$service['id'], $table, $profile, self::STATIC_DESTINATIONS + $index * 2, 'service'];
            }
            if (SmartRouting::hasDomains($service['domains'])) {
                $hasDomains = true;
                $table = SmartRouting::table($service);
                self::registerDestinationTable($firewall, $table, [], $registered);
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
            $tailnet = self::isTailnetIngress($settings, $interface);
            $assignedOnly = $strict || !empty($settings['smartAssignedOnly']) ||
                in_array($interface, $settings['deviceMultiInterfaces'] ?? [], true);
            $sources = [];
            $connectedOnlySources = [];
            if ($hasDomains && !$assignedOnly && !$connectedOnlyNetwork) {
                foreach (['inet', 'inet6'] as $family) {
                    self::redirectDns($firewall, $interface, $tailnet ? self::tailnetSource($family) : 'any',
                        SmartRouting::PORT, $interface, 64, true, $family);
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
                $connectedOnly = $mode === 'full_multi' || ($mode === 'multi' && Policy::killSwitch($row));
                if (!$connectedOnly && ($assignedOnly ? !$included : ($included || $mode === 'default'))) {
                    continue;
                }
                foreach (['inet' => $row['ip'], 'inet6' => $row['ipv6'] ?? ''] as $family => $source) {
                    if (!filter_var($source, FILTER_VALIDATE_IP, $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6)) {
                        continue;
                    }
                    if ($connectedOnly) {
                        if ($included) {
                            $connectedOnlySources[] = $source;
                        }
                        if (!$assignedOnly) {
                            // Keep these sources out of the ordinary Multi-Path destination exceptions.
                            $sources[] = $source;
                        }
                    } else {
                        $sources[] = $source;
                    }
                    if ($hasDomains && !$connectedOnly && $assignedOnly && $mode === 'multi') {
                        self::redirectDns($firewall, $interface, $source, SmartRouting::PORT, $id, 64, false, $family);
                    } elseif (Policy::assignmentPaused($row) || ($row['ip'] === '' && $mode === 'disabled')) {
                        self::bypassSmartDns($firewall, $interface, $source, $family);
                    }
                }
            }
            if ($routes !== [] && !$connectedOnlyNetwork && (!$assignedOnly || $sources !== [])) {
                self::registerSmartScope($firewall, $interface, $tag,
                    $tailnet ? Policy::COMBINED_LOCAL_TABLE : Policy::LOCAL_TABLE,
                    $tailnet && $network ? [Policy::TAILSCALE_V4, Policy::TAILSCALE_V6] : $sources, !$assignedOnly && !$tailnet,
                    false);
            }
            if ($routes !== [] && ($connectedOnlyNetwork || $connectedOnlySources !== [])) {
                self::registerSmartScope($firewall, $interface, $tag, Policy::COMBINED_LOCAL_TABLE,
                    $tailnet && $network ? [Policy::TAILSCALE_V4, Policy::TAILSCALE_V6] : $connectedOnlySources, false, true);
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
                    ] + self::stateOptions($profile, $tailnet) + $base);
                    $source = $tailnet ? Policy::TAILSCALE_V4 : $interface;
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

    private static function registerDestinationTable(
        Plugin $firewall,
        string $table,
        array $addresses,
        array &$registered
    ): void {
        if (isset($registered[$table])) {
            return;
        }
        $file = $addresses === [] ? null : Policy::writeState($table, implode("\n", array_unique($addresses)) . "\n");
        $firewall->registerTable($table, true, $file);
        $registered[$table] = true;
    }

    private static function registerSmartScope(
        Plugin $firewall,
        string $interface,
        string $tag,
        string $local,
        array $sources,
        bool $exclude,
        bool $combined
    ): void {
        $scope = [];
        if ($sources !== []) {
            $table = self::registerSmartSources($firewall, $interface, $combined ? 'cs' : 'src', $sources);
            $scope = ['from' => '<' . $table . '>', 'from_not' => $exclude];
        }
        $firewall->registerFilterRule(Policy::PRIORITY + 12, [
            'type' => 'match', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => 'inet46', 'quick' => false,
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

    private static function stateOptions(array $profile, bool $tailnet): array
    {
        // A floating ingress state can match on output before PF evaluates tunnel source NAT.
        $scrub = $tailnet ? ['scrub' => self::TAILNET_TCP_SCRUB] : [];
        if (($profile['kind'] ?? '') === 'proxy') {
            return ['tag' => self::VPN_EGRESS_TAG, 'state-policy' => 'floating'] + $scrub;
        }
        return $tailnet ? ['tag' => self::TAILNET_TUNNEL_TAG, 'state-policy' => 'if-bound'] + $scrub :
            ['tag' => self::VPN_EGRESS_TAG];
    }

    private static function tailnetWanState(): array
    {
        return ['tag' => self::TAILNET_WAN_TAG, 'state-policy' => 'if-bound'];
    }

    private static function registerClientNat(
        Plugin $firewall,
        array $profile,
        string $source,
        string $destination,
        int $priority,
        string $family = 'inet'
    ): void {
        if (($profile['kind'] ?? '') === 'proxy') {
            return;
        }
        $firewall->registerSourceNatRule($priority, [
            'interface' => $profile['logicalInterface'], 'ipprotocol' => $family,
            'from' => $source, 'to' => $destination, 'target' => explode('/', $profile['address'])[0],
            'descr' => 'Blank VPN & Proxy client source NAT'
        ]);
    }

    private static function registerTailnetOutput(Plugin $firewall, array $profile, string $family, string $tag): void
    {
        // This state handles the translated reply across the egress and Tailscale interfaces.
        // The source match requires PF to have applied NAT on this interface.
        $firewall->registerFilterRule(self::TAILNET_DEFAULT_PRIORITY, [
            'type' => 'pass', 'direction' => 'out', 'interface' => $profile['logicalInterface'],
            'ipprotocol' => $family, 'from' => explode('/', $profile['address'])[0],
            'tagged' => $tag, 'quick' => false, 'disablereplyto' => true,
            'statetype' => 'keep', 'state-policy' => 'floating',
            'label' => self::tailnetOutputMarker($profile['logicalInterface'], $family, $tag)
        ] + ($tag === self::TAILNET_TUNNEL_TAG ? ['scrub' => self::TAILNET_TCP_SCRUB] : []));
    }

    private static function tailnetOutputMarker(string $interface, string $family, string $tag): string
    {
        return Policy::marker('tailnet_output', $interface . ':' . $family . ':' . $tag);
    }

    public static function forwardedReplyMarkers(array $loaded, array $markers, array $profile): array
    {
        foreach ($markers as $marker) {
            if (($loaded[$marker]['tag'] ?? '') === self::TAILNET_TUNNEL_TAG) {
                return [self::tailnetOutputMarker($profile['logicalInterface'], 'inet', self::TAILNET_TUNNEL_TAG)];
            }
        }
        return $markers;
    }

    public static function tailnetForwardingInstalled(array $profile, array $loaded, array $markers, string $nat, string $source): bool
    {
        if (($profile['kind'] ?? '') === 'proxy') {
            return true;
        }
        $marker = self::tailnetOutputMarker($profile['logicalInterface'], 'inet', self::TAILNET_TUNNEL_TAG);
        $output = $loaded[$marker] ?? [];
        $address = explode('/', $profile['address'], 2)[0];
        if (($output['action'] ?? '') !== 'pass' || ($output['source'] ?? '') !== $address ||
            ($output['tagged'] ?? '') !== self::TAILNET_TUNNEL_TAG) {
            return false;
        }
        return array_any($markers, static fn (string $path): bool =>
            ($loaded[$path]['tag'] ?? '') === self::TAILNET_TUNNEL_TAG &&
            ($loaded[$path]['source'] ?? '') === $source) &&
            self::sourceNatLoaded($nat, $profile['interface'], $source, $address);
    }

    private static function sourceNatLoaded(string $nat, string $interface, string $source, string $address): bool
    {
        $interface = preg_quote($interface, '/');
        $source = preg_quote($source, '/');
        $address = preg_quote($address, '/');
        return preg_match('/^(?:@\d+\s+)?nat\s+on\s+' . $interface . '\s+inet\s+from\s+' .
            $source . '(?:\/32)?\s+to\s+any\s+->\s+' . $address . '(?:\/32)?(?:\s|$)/m', $nat) === 1;
    }

    private static function bypassSmartDns(Plugin $firewall, string $interface, string $ip, string $family): void
    {
        if (self::dnsRedirectionAvailable()) {
            $firewall->registerDestinationNatRule(55, [
                'nordr' => true, 'interface' => $interface, 'ipprotocol' => $family,
                'from' => $ip, 'to' => 'any', 'protocol' => 'tcp/udp', 'to_port' => '53', 'natreflection' => 'disable',
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
        $tailnet = $interface === Policy::TAILSCALE_DEVICE ||
            in_array($interface, explode(',', (string)(
                Config::getInstance()->object()->OPNsense->BlankVpn->settings->tailscaleInterfaces ?? ''
            )), true);
        $port = Resolver::scopedPort($port, $tailnet);
        if (!self::dnsRedirectionAvailable() || !Resolver::allowedPort($port)) {
            return;
        }
        $tag = Policy::marker('dns', $id . ':' . $family);
        $target = $family === 'inet6' ? '::1' : '127.0.0.1';
        $firewall->registerDestinationNatRule($priority, [
            'interface' => $interface, 'ipprotocol' => $family, 'protocol' => 'tcp/udp',
            'from' => $ip, 'to' => 'any', 'to_port' => '53', 'target' => $target, 'local-port' => (string)$port,
            'tag' => $tag, 'natreflection' => 'disable', 'descr' => 'Blank VPN & Proxy DNS redirection'
        ]);
        $firewall->registerFilterRule(Policy::PRIORITY + ($default ? 6 : 5), [
            'type' => 'pass', 'direction' => 'in', 'interface' => $interface, 'ipprotocol' => $family,
            'from' => $ip, 'to' => $target, 'to_port' => (string)$port, 'protocol' => 'tcp/udp',
            'tagged' => $tag, 'quick' => true, 'statetype' => 'keep', 'disablereplyto' => true,
            'label' => $tag
        ] + ($tailnet ? ['state-policy' => 'floating'] : []));
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
        foreach ([$primary, $backup] as $profile) {
            if (!self::gatewayAvailable($firewall, $profile)) {
                continue;
            }
            $checked = $health[$profile['id']] ?? [];
            if (($checked['reachable'] ?? true) ||
                (($profile['kind'] ?? '') === 'native' && isset($checked['source']) &&
                    $checked['source'] !== ($profile['address'] ?? ''))) {
                return $profile;
            }
        }
        return null;
    }

    private static function registerProfile(Plugin $firewall, array $profile, bool $includeDns, bool $tailnet = false): void
    {
        $address = explode('/', $profile['address'] ?? '')[0];
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return;
        }

        $ready = self::gatewayAvailable($firewall, $profile);
        if ($ready && $tailnet) {
            self::registerTailnetOutput($firewall, $profile, 'inet', self::TAILNET_TUNNEL_TAG);
        }
        $destinations = [];
        foreach (array_keys(Policy::PROBE_TARGETS) as $target) {
            $destinations[] = ['to' => $target, 'to_port' => (string)Policy::PROBE_PORT, 'protocol' => 'tcp', 'kind' => 'probe'];
            // Outbound translation runs before the source-bound pass and fallback block.
            // Preserve the exact probe's source even if its initial route points at a WAN.
            $firewall->registerSourceNatRule(self::PROBE_NO_NAT_PRIORITY, [
                'nonat' => true, 'ipprotocol' => 'inet', 'protocol' => 'tcp',
                'from' => $address, 'to' => $target, 'dstport' => (string)Policy::PROBE_PORT,
                'descr' => 'Blank VPN & Proxy prevents source NAT on a tunnel probe'
            ]);
        }
        foreach ($includeDns ? ($profile['dns'] ?? []) : [] as $dns) {
            if (filter_var($dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $destinations[] = ['to' => $dns, 'to_port' => '53', 'protocol' => 'tcp/udp', 'kind' => 'dns_out'];
            }
        }
        foreach ($destinations as $destination) {
            $kind = $destination['kind'];
            unset($destination['kind']);
            if ($kind === 'dns_out') {
                // The kernel initially selects WAN for the provider resolver. PF
                // translates that source before the filter's route-to can use
                // WireGuard, so exclude this exact tunnel DNS flow from WAN NAT.
                $firewall->registerSourceNatRule(self::PROBE_NO_NAT_PRIORITY, [
                    'nonat' => true, 'ipprotocol' => 'inet', 'protocol' => 'tcp/udp',
                    'from' => $address, 'to' => $destination['to'], 'dstport' => '53',
                    'descr' => 'Blank VPN & Proxy preserves tunnel DNS source'
                ]);
            }
            $label = Policy::marker($kind, $profile['id'] . $destination['to']);
            $base = $destination + [
                'direction' => 'out', 'ipprotocol' => 'inet', 'from' => $address,
                'quick' => true, 'disablereplyto' => true
            ];
            $sourcePorts = isset($profile['peerKey']) ? ($kind === 'probe'
                ? Resolver::probeSourcePorts($profile) : Resolver::dnsSourcePorts($profile)) : null;
            if ($sourcePorts !== null) {
                $base['from_port'] = $sourcePorts[0] . ':' . $sourcePorts[1];
            }
            if ($ready) {
                $firewall->registerFilterRule(Policy::PRIORITY, [
                    'type' => 'pass', 'gateway' => $profile['gateway'], 'skip_rules_gw_down' => true,
                    'statetype' => 'keep', 'label' => $label, 'tag' => self::VPN_EGRESS_TAG
                ] + $base);
            }
            $firewall->registerFilterRule(Policy::PRIORITY + 1, [
                'type' => 'block', 'label' => $label . '_block'
            ] + $base);
        }
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

    public static function probePathsInstalled(array $profile, array $loaded, string $nat): array
    {
        $source = explode('/', $profile['address'] ?? '', 2)[0];
        if (!filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || empty($profile['interface'])) {
            return [];
        }
        $verified = [];
        $sourcePorts = isset($profile['peerKey']) ? Resolver::probeSourcePorts($profile) : null;
        foreach (array_keys(Policy::PROBE_TARGETS) as $target) {
            $marker = Policy::marker('probe', $profile['id'] . $target);
            $pass = $loaded[$marker] ?? [];
            $guard = $loaded[$marker . '_block'] ?? [];
            if (($pass['action'] ?? '') === 'pass' && ($pass['source'] ?? '') === $source &&
                ($pass['gateway'] ?? null) === $profile['interface'] && ($pass['probeTarget'] ?? '') === $target &&
                ($guard['action'] ?? '') === 'block' && ($guard['source'] ?? '') === $source &&
                ($guard['probeTarget'] ?? '') === $target &&
                ($sourcePorts === null ||
                    (($pass['sourcePortStart'] ?? null) === $sourcePorts[0] &&
                    ($pass['sourcePortEnd'] ?? null) === $sourcePorts[1] &&
                    ($guard['sourcePortStart'] ?? null) === $sourcePorts[0] &&
                    ($guard['sourcePortEnd'] ?? null) === $sourcePorts[1])) &&
                self::probeNoNatInstalled($nat, $source, $target)) {
                $verified[] = $target;
            }
        }
        return $verified;
    }

    private static function probeNoNatInstalled(string $nat, string $source, string $destination): bool
    {
        $source = preg_quote($source, '/');
        $destination = preg_quote($destination, '/');
        return preg_match('/^\h*(?:@\d+\h+)?no nat inet proto tcp from ' . $source . '(?:\/32)? to ' .
            $destination . '(?:\/32)? port\h*=\h*(?:443|https)\h*$/m', $nat) === 1;
    }

    public static function parseLoadedRules(string $output): array
    {
        $rules = [];
        foreach (explode("\n", $output) as $line) {
            if (!preg_match('/\blabel "(blankvpn_[a-z0-9_]+)"/', $line, $match)) {
                continue;
            }
            preg_match('/^(?:@\d+\s+)?(?:pass|block|match)\s+(?:(?:drop|return)\s+)?in\s+(?:log\s+)?(?:quick\s+)?on\s+([a-zA-Z][a-zA-Z0-9_.-]*)\b/',
                ltrim($line), $ingress);
            preg_match('/\broute-to\s+[({\s]*([a-zA-Z][a-zA-Z0-9_.-]*)\b/', $line, $gateway);
            preg_match('/^(?:@\d+\s+)?(pass|block|match)\b/', ltrim($line), $action);
            preg_match('/\bfrom\s+([a-f0-9:.]+)(?:%[\w.-]+)?(?:\/([0-9]+))?\s/i', $line, $source);
            preg_match('/\bfrom\s+\S+\s+port\s+(?:=\s*)?([0-9]+)(?:\s*(?::|><)\s*([0-9]+))?/i',
                $line, $sourcePort);
            $prefix = $source[2] ?? '';
            $address = isset($source[1]) && $prefix !== '' &&
                $prefix !== (str_contains($source[1], ':') ? '128' : '32')
                ? Policy::cidr($source[1] . '/' . $prefix, false) : ($source[1] ?? null);
            preg_match('/\bto\s+<([a-z0-9_]+)>/i', $line, $table);
            preg_match('/\b(?:port\s*=\s*)([0-9]+)\b/', $line, $port);
            preg_match('/\btagged\s+"?(blankvpn_[a-z0-9_]+)/', $line, $tagged);
            preg_match('/\btag\s+"?(blankvpn_[a-z0-9_]+)/', $line, $tag);
            $rules[$match[1]] = [
                'gateway' => $gateway[1] ?? null, 'action' => $action[1] ?? null, 'source' => $address,
                'table' => $table[1] ?? null, 'port' => isset($port[1]) ? (int)$port[1] : null,
                'sourcePortStart' => isset($sourcePort[1]) ? (int)$sourcePort[1] : null,
                'sourcePortEnd' => isset($sourcePort[2]) ? (int)$sourcePort[2] : null,
                'tagged' => $tagged[1] ?? null, 'tag' => $tag[1] ?? null,
                'quick' => preg_match('/^.+?\bquick\s+(?:on|inet|inet6|proto|from|all)\b/', $line) === 1
            ] + (isset($ingress[1]) ? ['ingress' => $ingress[1]] : []);
            if (str_starts_with($match[1], 'blankvpn_probe_') &&
                preg_match('/^(?:@\d+\s+)?(?:pass|block)(?:\s+(?:drop|return))?\s+out\s+quick\b.*' .
                    '\binet\s+proto\s+tcp\s+from\s+\S+(?:\s+port\s+\S+)?\s+to\s+([0-9.]+)(?:\/32)?\s+port\s*=\s*(?:443|https)\b/',
                    ltrim($line), $probe)) {
                $rules[$match[1]]['probeTarget'] = $probe[1];
            }
            if (preg_match('/\bmax-mss\s+([0-9]+)\b/', $line, $mss)) {
                $rules[$match[1]]['mss'] = (int)$mss[1];
            }
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

    private static function verifyInternetGuard(array $loaded, string $id, string $family, ?string $source = null): void
    {
        $suffix = $family === 'inet6' ? '_v6' : '';
        $rule = $loaded[Policy::marker('kill' . $suffix, $id)] ?? [];
        $dns = $loaded[Policy::marker('kill_dns' . $suffix, $id)] ?? [];
        if (($rule['action'] ?? '') !== 'block' || ($dns['action'] ?? '') !== 'block' ||
            ($rule['source'] ?? null) !== $source || ($dns['source'] ?? null) !== $source) {
            throw new \RuntimeException('An internet or DNS Kill Switch guard did not load for ' . $id . '.');
        }
    }

    private static function verifySharedLanGuard(array $loaded, string $kind, string $interface): void
    {
        if (($loaded[Policy::marker($kind, $interface)]['action'] ?? '') !== 'block' ||
            ($loaded[Policy::marker($kind . '_dns', $interface)]['action'] ?? '') !== 'block') {
            throw new \RuntimeException('An interface-wide Kill Switch guard did not load on ' . $interface . '.');
        }
    }

    private static function verifyTunnelPass(array $loaded, string $marker): void
    {
        $rule = $loaded[$marker] ?? [];
        if ($rule !== [] && (($rule['action'] ?? '') !== 'pass' ||
            !preg_match('/^(?:wg[0-9]+|ovpnc[0-9]+|tun20[0-7])$/D', $rule['gateway'] ?? '') ||
            !in_array($rule['tag'] ?? '', [self::VPN_EGRESS_TAG, self::TAILNET_TUNNEL_TAG], true))) {
            throw new \RuntimeException('A protected route is not pinned to a VPN or proxy interface.');
        }
    }

    private static function verifyServicePath(
        array $loaded,
        array $order,
        string $kind,
        string $route,
        string $scope,
        string $table
    ): void
    {
        $marker = Policy::marker($kind, $route);
        $guardMarker = Policy::marker($kind . '_guard', $route);
        $guard = $loaded[$guardMarker] ?? [];
        if (($guard['action'] ?? '') !== 'block' || empty($guard['quick']) ||
            ($guard['tagged'] ?? '') !== $scope || ($guard['table'] ?? '') !== $table) {
            throw new \RuntimeException('A Multi-Path destination guard is missing or has the wrong scope.');
        }
        self::verifyTunnelPass($loaded, $marker);
        $pass = $loaded[$marker] ?? [];
        if ($pass !== [] && (empty($pass['quick']) || ($pass['tagged'] ?? '') !== $scope ||
            ($pass['table'] ?? '') !== $table || $order[$marker] >= $order[$guardMarker])) {
            throw new \RuntimeException('A Multi-Path tunnel rule does not precede its destination guard.');
        }
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
        foreach (Policy::scopes($settings) as $scope) {
            self::verifyScope($model, $scope, $loaded);
        }
        if ((string)(Config::getInstance()->object()->interfaces->wan->if ?? '') !== '') {
            $tags = [self::VPN_EGRESS_TAG => 'tunnel_only'];
            if (isset($settings['scopes']['tailscale'])) {
                $tags[self::TAILNET_TUNNEL_TAG] = 'tailnet_tunnel_only';
            }
            foreach ($tags as $tag => $kind) {
                $guard = $loaded[Policy::marker($kind, 'wan')] ?? [];
                if (($guard['action'] ?? '') === 'block' && ($guard['tagged'] ?? '') === $tag) {
                    continue;
                }
                throw new \RuntimeException('The tagged WAN egress guard did not load.');
            }
        }
    }

    private static function verifyScope(BlankVpn $model, array $settings, array $loaded): void
    {
        $network = $settings['coverage'] === 'network';
        $networkMode = $settings['networkMode'];
        $networkProtected = $network && $settings['networkKillSwitch'] &&
            (Policy::usesBase($networkMode) || $networkMode === 'multi');
        if ($network && ($networkProtected || Policy::usesBase($networkMode) || $networkMode === 'blocked')) {
            foreach ($settings['interfaces'] as $interface) {
                $id = 'network:' . $interface;
                foreach (['inet', 'inet6'] as $family) {
                    $source = self::isTailnetIngress($settings, $interface) ? self::tailnetSource($family) : null;
                    self::verifyInternetGuard($loaded, $id, $family, $source);
                }
                if ($interface === Policy::TAILSCALE_DEVICE &&
                    ($loaded[Policy::marker('kill', $id)]['ingress'] ?? '') !== Policy::TAILSCALE_DEVICE) {
                    throw new \RuntimeException('The Tailscale policy did not load on the exit-node interface.');
                }
                if ($networkProtected) {
                    self::verifyTunnelPass($loaded, Policy::marker('device', $id));
                    foreach (['inet', 'inet6'] as $family) {
                        if (isset($loaded[Policy::marker('wan_fallback', $id . ':' . $family)])) {
                            throw new \RuntimeException('A WAN fallback rule is still active under the Kill Switch.');
                        }
                    }
                }
            }
        }
        $diagnostics = new Diagnostics();
        $rows = Policy::assignments($model, true);
        $exceptions = $networkProtected ? [] : Policy::networkBypassSources($settings, $rows, $diagnostics);
        foreach ($exceptions as $id => $scope) {
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
        $assignments = Policy::deviceAssignments($settings, Policy::routingAssignments($rows, $diagnostics));
        foreach ($assignments as $id => $row) {
            if (!in_array($row['interface'], $settings['interfaces'], true)) {
                continue;
            }
            $mode = Policy::mode($row);
            $protected = Policy::killSwitch($row);
            $guard = $loaded[Policy::marker('kill', $id)] ?? [];
            $ipv6Guard = $loaded[Policy::marker('kill_v6', $id)] ?? [];
            $pass = $loaded[Policy::marker('device', $id)] ?? [];
            if (Policy::bindsMac($row) &&
                (($pass !== [] && ($pass['source'] ?? '') !== $row['ip']) ||
                    ($guard !== [] && ($guard['source'] ?? '') !== $row['ip']))) {
                throw new \RuntimeException('A MAC-bound rule still uses its previous IPv4 address.');
            }
            if ($protected) {
                self::verifyTunnelPass($loaded, Policy::marker('device', $id));
                if ($row['ip'] !== '') {
                    self::verifyInternetGuard($loaded, $id, 'inet', $row['ip']);
                }
                if ($row['ipv6'] !== '') {
                    self::verifyInternetGuard($loaded, $id, 'inet6', $row['ipv6']);
                }
            }
            $failClosed = $protected || $mode === 'blocked' ||
                ($mode === 'full' && $row['failure'] !== 'wan');
            $expectIpv6 = $failClosed || ($row['ip'] === '' && $protected);
            if (($row['ip'] !== '' && $failClosed && ($guard['action'] ?? '') !== 'block') ||
                (!empty($row['ipv6']) && $expectIpv6 && ($ipv6Guard['action'] ?? '') !== 'block')) {
                throw new \RuntimeException('A per-IP fail-closed firewall guard is missing.');
            }
        }
        foreach (Policy::killSwitchIpv6Interfaces($settings, $assignments) as $interface) {
            self::verifySharedLanGuard($loaded, 'kill_interface_v6', $interface);
        }
        foreach (Policy::unboundKillSwitchInterfaces($settings, $assignments, $diagnostics) as $interface) {
            self::verifySharedLanGuard($loaded, 'kill_unbound_v4', $interface);
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
                $port = match (true) {
                    ($loaded[Policy::marker('wan_fallback', $id . ':inet')]['action'] ?? '') === 'pass' =>
                        Resolver::COMBINED_FALLBACK_PORT,
                    $networkProtected => Resolver::protectedCombinedPort($base),
                    default => Resolver::combinedPort($base)
                };
                $port = Resolver::scopedPort($port, self::isTailnetIngress($settings, $interface));
                if (!self::dnsRedirectLoaded($loaded, $nat, $id, $port, 'inet') ||
                    !self::dnsRedirectLoaded($loaded, $nat, $id, $port, 'inet6')) {
                    throw new \RuntimeException('The DNS redirect for Whole-Network + Multi-Path did not load on ' . $interface . '.');
                }
            }
        }

        $combinedInterfaces = self::combinedInterfaces($assignments);
        $loadedOrder = array_flip(array_keys($loaded));
        foreach ($services as $id => $service) {
            $hasDomains = SmartRouting::hasDomains($service['domains']);
            $hasAddresses = SmartRouting::addressEntries($service['domains']) !== [];
            foreach ($settings['smartInterfaces'] as $interface) {
                if (in_array($interface, $settings['strictInterfaces'], true) &&
                    !isset($combinedInterfaces[$interface])) {
                    continue;
                }
                $rule = $id . ':' . $interface;
                $scope = Policy::marker('smart', $interface);
                $paths = [];
                if ($hasAddresses) {
                    $paths['service'] = SmartRouting::addressTable($service);
                }
                if ($hasDomains) {
                    $paths[$hasAddresses ? 'service_dns' : 'service'] = SmartRouting::table($service);
                }
                foreach ($paths as $kind => $table) {
                    self::verifyServicePath($loaded, $loadedOrder, $kind, $rule, $scope, $table);
                    if ($networkMode === 'full_multi' && $network) {
                        $guard = $loadedOrder[Policy::marker($kind . '_guard', $rule)];
                        $scopePosition = $loadedOrder[Policy::marker('combined_scope', $interface)] ?? PHP_INT_MAX;
                        $basePosition = $loadedOrder[Policy::marker('device', 'network:' . $interface)] ??
                            $loadedOrder[Policy::marker('wan_fallback', 'network:' . $interface . ':inet')] ??
                            $loadedOrder[Policy::marker('kill', 'network:' . $interface)];
                        if ($scopePosition >= $guard || $guard >= $basePosition) {
                            throw new \RuntimeException('The loaded Multi-Path policy does not precede its base route.');
                        }
                    }
                }
            }
        }
    }
}
