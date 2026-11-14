<?php

declare(strict_types=1);

namespace OPNsense\Core {
    final class Backend
    {
        public static array $interfaces = [];

        public function configdRun(string $action, bool $async, int $timeout): string
        {
            if ($action !== 'interface list ifconfig') {
                throw new \RuntimeException('Unexpected interface query.');
            }
            return json_encode(self::$interfaces, JSON_THROW_ON_ERROR);
        }
    }

    final class Config
    {
        public static ?\SimpleXMLElement $fixture = null;

        public static function getInstance(): self
        {
            return new self();
        }

        public function object(): object
        {
            return self::$fixture ?? (object)['system' => (object)[]];
        }
    }
}

namespace OPNsense\BlankVpn {
    final class Diagnostics
    {
        public bool $reserved = true;

        public function hasReservation(string $interface, string $ip, string $mac): bool
        {
            return $this->reserved;
        }
    }
}

namespace OPNsense\Firewall {
    final class Plugin
    {
        public array $rules = [];
        public array $nat = [];
        public array $dns = [];
        public array $tables = [];

        public function registerFilterRule(int $priority, array $rule): void
        {
            $this->rules[$rule['label'] ?? 'match'] = $rule + ['priority' => $priority];
        }

        public function registerSourceNatRule(int $priority, array $rule): void
        {
            $this->nat[] = $rule + ['priority' => $priority];
        }

        public function registerDestinationNatRule(int $priority, array $rule): void
        {
            $this->dns[] = $rule + ['priority' => $priority];
        }

        public function registerTable(string $table, bool $persist): void
        {
            $this->tables[$table] = $persist;
        }

        public function getGateway(string $name): array
        {
            return match ($name) {
                'VPN' => ['interface' => 'wg0', 'proto' => 'inet', 'logic' => 'route-to wg0'],
                'NORD' => ['interface' => 'ovpnc1', 'proto' => 'inet', 'logic' => 'route-to ovpnc1'],
                default => []
            };
        }
    }
}

namespace {
    use OPNsense\BlankVpn\Diagnostics;
    use OPNsense\BlankVpn\Firewall;
    use OPNsense\BlankVpn\NativeVpn;
    use OPNsense\BlankVpn\Policy;
    use OPNsense\BlankVpn\SmartRouting;
    use OPNsense\Firewall\Plugin;

    foreach (['Policy', 'NativeVpn', 'Resolver', 'SmartRouting', 'ProxyRuntime', 'Firewall'] as $file) {
        require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $file . '.php';
    }

    function checkRouting(bool $value, string $message): void
    {
        if (!$value) {
            throw new RuntimeException($message);
        }
    }

    function rejectRouting(callable $operation): void
    {
        try {
            $operation();
        } catch (DomainException) {
            return;
        }
        throw new RuntimeException('Expected invalid domain input to be rejected.');
    }

    \OPNsense\Core\Config::$fixture = new SimpleXMLElement(<<<'XML'
        <opnsense><interfaces>
          <lan><enable>1</enable><if>igc1</if><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet><ipaddrv6>track6</ipaddrv6></lan>
          <opt1><enable>1</enable><if>vlan1</if><ipaddr>10.12.0.1</ipaddr><subnet>24</subnet><ipaddrv6>2001:db8:99::1</ipaddrv6><subnetv6>64</subnetv6></opt1>
          <opt2><enable>1</enable><if>igc2</if><ipaddr>dhcp</ipaddr><ipaddrv6>none</ipaddrv6></opt2>
          <wan><enable>1</enable><if>igc0</if><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>
        </interfaces></opnsense>
        XML);
    \OPNsense\Core\Backend::$interfaces = [
        'igc1' => ['ipv6' => [
            ['ipaddr' => 'fe80::1%igc1', 'subnetbits' => 64],
            ['ipaddr' => '2001:db8:12::1', 'subnetbits' => 64],
            ['ipaddr' => '2001:db8:12::2', 'subnetbits' => 64]
        ]],
        'igc0' => ['ipv6' => [['ipaddr' => '2001:db8:ffff::1', 'subnetbits' => 64]]]
    ];
    checkRouting(Policy::segmentNetworks(['lan', 'opt1']) === [
        '192.168.2.0/24', '2001:db8:12::/64', '10.12.0.0/24', '2001:db8:99::/64'
    ], 'Session resets must include the current tracked IPv6 prefix and static prefixes.');
    $local = Policy::localNetworks(['localNetworks' => []]);
    checkRouting(in_array('2001:db8:12::/64', $local, true) &&
        !in_array('2001:db8:ffff::/64', $local, true), 'Keep the tracked LAN prefix local and exclude WAN IPv6.');
    rejectRouting(fn () => Policy::segmentNetworks(['opt2']));
    \OPNsense\Core\Config::$fixture->interfaces->lan->ipaddrv6 = 'idassoc6';
    \OPNsense\Core\Backend::$interfaces['igc1']['ipv6'] = [];
    checkRouting(Policy::segmentNetworks(['lan']) === ['192.168.2.0/24'],
        'A tracked LAN without a delegated prefix must still be usable for IPv4.');
    unset(\OPNsense\Core\Backend::$interfaces['igc1']);
    rejectRouting(fn () => Policy::segmentNetworks(['lan']));
    \OPNsense\Core\Config::$fixture = null;

    $domains = SmartRouting::domains("NETFLIX.com, *.netflix.com.\n*.nflxvideo.net");
    checkRouting($domains === ['netflix.com', 'nflxvideo.net'], 'Normalize suffixes and deduplicate the apex.');
    $fileDomains = SmartRouting::domains("\xEF\xBB\xBF# Domains\r\n*.netflix.com, Nflxvideo.net # streaming\r\n");
    checkRouting($fileDomains === $domains, 'Plain text and CSV imports must accept BOM, comments and wildcards.');
    $largeList = array_map(static fn (int $n): string => "service{$n}.example.com", range(1, 1000));
    checkRouting(SmartRouting::domains(implode("\n", $largeList)) === $largeList, 'Accept a 1,000-domain list.');
    rejectRouting(fn () => SmartRouting::domains(implode("\n", [...$largeList, 'extra.example.com'])));
    checkRouting(SmartRouting::matches('a.b.netflix.com', 'netflix.com'), 'Match multiple subdomain levels.');
    checkRouting(!SmartRouting::matches('fakenetflix.com', 'netflix.com'), 'Require a DNS label boundary.');
    $china = SmartRouting::domains(".CN, *.cn.\n.cn");
    checkRouting($china === ['.cn'] && SmartRouting::domains(implode("\n", $china)) === $china,
        'Top-level suffixes must deduplicate and survive saving and reloading.');
    checkRouting(SmartRouting::matches('sub.example.cn', '.cn') &&
        !SmartRouting::matches('example.cn.com', '.cn') && !SmartRouting::matches('examplecn', '.cn'),
        'Match only the final DNS label for a top-level suffix.');
    foreach (['com', '.arpa', '*.local', '*.localhost', '*.*.cn', 'http://netflix.com', '*foo.netflix.com', '127.0.0.1', 'opnsense.home.arpa', 'x.local'] as $invalid) {
        rejectRouting(fn () => SmartRouting::domains($invalid));
    }
    $service = ['id' => 'streaming', 'name' => 'Netflix', 'profile' => 'jp', 'domains' => $domains];
    $services = ['streaming' => $service];
    rejectRouting(fn () => SmartRouting::checkOverlap($services, '', ['a.netflix.com']));
    SmartRouting::checkOverlap($services, 'streaming', ['a.netflix.com']);
    SmartRouting::checkOverlap($services, '', ['fakenetflix.com']);
    rejectRouting(fn () => SmartRouting::checkOverlap(
        ['child' => array_replace($service, ['domains' => ['a.netflix.com']])], '', ['netflix.com']
    ));

    $chinaService = ['china' => array_replace($service, ['id' => 'china', 'domains' => $china])];
    rejectRouting(fn () => SmartRouting::checkOverlap($chinaService, '', ['example.cn']));
    rejectRouting(fn () => SmartRouting::checkOverlap(
        ['child' => array_replace($service, ['domains' => ['example.cn']])], '', $china
    ));
    SmartRouting::checkOverlap($chinaService, '', ['example.cn.com']);

    $table = SmartRouting::table($service);
    checkRouting(strlen($table) <= 31, 'PF table name must fit the native limit.');
    checkRouting($table === SmartRouting::table(array_replace($service, ['domains' => array_reverse($domains)])), 'Table identity is independent of domain order.');
    checkRouting($table !== SmartRouting::table(array_replace($service, ['profile' => 'ca'])), 'Changing exits invalidates an old destination table.');
    $profiles = ['jp' => [
        'id' => 'jp', 'address' => '10.64.0.9/32', 'dns' => ['10.64.0.1', 'fd00::1'],
        'owned' => true, 'gateway' => 'VPN', 'interface' => 'wg0', 'logicalInterface' => 'opt1',
        'dnsPort' => 46651
    ]];
    $probe = Policy::marker('probe', 'jp' . Policy::PROBE_IP);
    $probeOnly = new Plugin();
    (new ReflectionMethod(Firewall::class, 'registerProfile'))->invoke(null, $probeOnly, $profiles['jp'], false);
    checkRouting(array_keys($probeOnly->rules) === [$probe, $probe . '_block'] &&
        $probeOnly->rules[$probe]['from'] === '10.64.0.9' && $probeOnly->rules[$probe]['direction'] === 'out',
        'A VPN test while routing is off installs only a source-bound router probe and its guard.');
    $loaded = [$probe => ['action' => 'pass', 'source' => '10.64.0.9', 'gateway' => 'wg0']];
    checkRouting(!Firewall::probePathInstalled($profiles['jp'], $loaded), 'A manual exit test requires a fallback guard.');
    $loaded[$probe . '_block'] = ['action' => 'block', 'source' => '10.64.0.9'];
    checkRouting(Firewall::probePathInstalled($profiles['jp'], $loaded), 'A protected source may test its configured exit.');
    checkRouting(SmartRouting::dnsDirectives($chinaService, $profiles) === [
        'ipset=/cn/' . SmartRouting::table($chinaService['china']), 'server=/cn/10.64.0.1@10.64.0.9'
    ], 'Compile a top-level suffix to label-boundary DNS learning and tunnel forwarding.');
    $directives = SmartRouting::dnsDirectives($services, $profiles);
    checkRouting(in_array('ipset=/netflix.com/' . $table, $directives, true), 'Learn from apex and wildcard DNS.');
    checkRouting(in_array('server=/nflxvideo.net/10.64.0.1@10.64.0.9', $directives, true), 'Send matched DNS through the chosen tunnel source.');
    checkRouting(in_array('local=/netflix.com/', SmartRouting::dnsDirectives($services, []), true), 'A missing profile must not send matched DNS to native upstream.');

    $settings = ['enabled' => true, 'interfaces' => ['lan'], 'smartInterfaces' => ['lan'], 'strictInterfaces' => []];
    $drafts = ['draft' => array_replace($service, ['profile' => ''])];
    checkRouting(SmartRouting::boundServices($drafts) === [] &&
        !SmartRouting::active($settings, $drafts) && SmartRouting::dnsDirectives($drafts, $profiles) === [],
        'A saved list without an exit must not generate DNS routes or activate routing.');
    $interfaces = ['lan' => ['if' => 'igb0']];
    $compileSmart = new ReflectionMethod(Firewall::class, 'registerSmartRoutes');
    $good = new Plugin();
    $compileSmart->invoke(null, $good, $settings, $interfaces, $services, $profiles, []);
    $pass = $good->rules[Policy::marker('service', 'streaming:lan')];
    $block = $good->rules[Policy::marker('service_guard', 'streaming:lan')];
    checkRouting($pass['gateway'] === 'VPN' && $pass['skip_rules_gw_down'], 'Matched IPv4 must use a usable WireGuard gateway.');
    checkRouting($block['priority'] > $pass['priority'] && $block['ipprotocol'] === 'inet46', 'Install a destination block after the VPN-only pass.');
    checkRouting($good->rules['match']['quick'] === false && $good->rules['match']['to_not'], 'Local exceptions must not short-circuit the service rules.');
    checkRouting($good->nat[0]['to'] === '<' . $table . '>' && $good->nat[0]['from'] === 'lan', 'Scope Multi-Path NAT by destination and source network.');
    checkRouting(count($good->dns) === 2, 'Capture regular DNS over IPv4 and IPv6 on the selected interface.');
    $down = new Plugin();
    $compileSmart->invoke(null, $down, $settings, $interfaces, $services, $profiles, ['jp' => ['reachable' => false]]);
    checkRouting(!isset($down->rules[Policy::marker('service', 'streaming:lan')]) &&
        isset($down->rules[Policy::marker('service_guard', 'streaming:lan')]), 'Keep the block when the service exit is down.');

    $networkSettings = $settings + [
        'coverage' => 'network', 'networkMode' => 'full', 'networkProfile' => 'jp', 'tailscaleInterfaces' => []
    ];
    $network = new ReflectionMethod(Firewall::class, 'registerNetworkPolicy');
    $whole = new Plugin();
    $network->invoke(null, $whole, $networkSettings, $interfaces, $profiles, []);
    $networkPass = $whole->rules[Policy::marker('device', 'network:lan')];
    $networkBlock = $whole->rules[Policy::marker('kill', 'network:lan')];
    checkRouting($networkPass['gateway'] === 'VPN' && $networkPass['priority'] < $networkBlock['priority'] &&
        $networkBlock['from'] === 'any' && $networkBlock['to_not'] && $whole->nat[0]['from'] === 'lan',
        'Whole-Network coverage needs a gateway pass, LAN-scoped NAT and an internet guard.');
    $wholeDown = new Plugin();
    $network->invoke(null, $wholeDown, $networkSettings, $interfaces, $profiles, ['jp' => ['reachable' => false]]);
    checkRouting(!isset($wholeDown->rules[Policy::marker('device', 'network:lan')]) &&
        isset($wholeDown->rules[Policy::marker('kill', 'network:lan')],
            $wholeDown->rules[Policy::marker('kill_v6', 'network:lan')]) && $wholeDown->nat === [],
        'A VPN outage under Whole-Network coverage blocks both address families without WAN fallback.');
    $bypassList = ['china' => array_replace($chinaService['china'], ['profile' => SmartRouting::BYPASS])];
    $bypassTable = SmartRouting::bypassTable($bypassList);
    checkRouting(SmartRouting::activeServices($networkSettings, $bypassList + $services) === $bypassList &&
        SmartRouting::activeServices($settings, $bypassList + $services) === $services,
        'Only bypass lists are active under one-server network coverage.');
    checkRouting(SmartRouting::dnsDirectives($bypassList, $profiles) === [
        'ipset=/cn/' . $bypassTable, 'server=/cn/127.0.0.1#53'
    ], 'Learn bypass destinations from the native resolver.');
    $withBypass = new Plugin();
    $network->invoke(null, $withBypass, $networkSettings, $interfaces, $profiles, [], false, $bypassTable);
    $tag = $withBypass->rules[Policy::marker('bypass', 'network:lan')];
    $vpn = $withBypass->rules[Policy::marker('device', 'network:lan')];
    $guard = $withBypass->rules[Policy::marker('kill', 'network:lan')];
    checkRouting($tag['type'] === 'match' && !$tag['quick'] && $tag['priority'] < $vpn['priority'] &&
        $tag['to'] === '<' . $bypassTable . '>' && $tag['to_not'] && $tag['tag'] === $vpn['tagged'] &&
        $tag['tag'] === $guard['tagged'] && count($withBypass->dns) === 2 &&
        $withBypass->dns[0]['local-port'] === (string)SmartRouting::PORT,
        'Bypass traffic follows native policy and both DNS families use the split resolver.');
    $withBypassDown = new Plugin();
    $network->invoke(null, $withBypassDown, $networkSettings, $interfaces, $profiles,
        ['jp' => ['reachable' => false]], false, $bypassTable);
    checkRouting(!isset($withBypassDown->rules[Policy::marker('bypass', 'network:lan')]) &&
        !isset($withBypassDown->rules[Policy::marker('kill', 'network:lan')]['tagged']) &&
        $withBypassDown->dns === [], 'An outage installs a kill switch that covers previously bypassed destinations.');
    $wholeFallback = new Plugin();
    $network->invoke(null, $wholeFallback, $networkSettings + ['networkKillSwitch' => false],
        $interfaces, $profiles, ['jp' => ['reachable' => false]]);
    checkRouting($wholeFallback->rules === [] && $wholeFallback->nat === [],
        'Disabling the network kill switch allows regular routing when the one exit is down.');

    $outage = new ReflectionMethod(Firewall::class, 'multiPathOutage');
    $liveHealth = ['jp' => ['probeSucceeded' => true, 'checkedAt' => time(), 'reachable' => true]];
    checkRouting(!$outage->invoke(null, $good, $services, $profiles, $liveHealth) &&
        $outage->invoke(null, $good, $services, $profiles, []) &&
        $outage->invoke(null, $good, $services, $profiles, ['jp' => [
            'probeSucceeded' => true, 'checkedAt' => time() - 181
        ]]) && $outage->invoke(null, $good, $services, $profiles, ['jp' => [
            'probeSucceeded' => false, 'checkedAt' => time(), 'reachable' => true
        ]]) && $outage->invoke(null, $good, [], $profiles, $liveHealth),
        'Require a recent successful probe for every exit and close when no list has an exit.');
    $wholeMulti = array_replace($networkSettings, ['networkMode' => 'multi', 'networkKillSwitch' => true]);
    $wholeMultiDown = new Plugin();
    $network->invoke(null, $wholeMultiDown, $wholeMulti, $interfaces, $profiles, [], true);
    $networkKill = $wholeMultiDown->rules[Policy::marker('kill', 'network:lan')];
    checkRouting($networkKill['interface'] === 'lan' && $networkKill['from'] === 'any' && $networkKill['to_not'] &&
        $networkKill['priority'] < $pass['priority'] &&
        isset($wholeMultiDown->rules[Policy::marker('kill_v6', 'network:lan')]) &&
        $wholeMultiDown->dns[0]['nordr'] && $wholeMultiDown->dns[0]['priority'] < $good->dns[0]['priority'],
        'A checked network Multi-Path outage blocks both families ahead of service routing and DNS forwarding.');
    $wholeMultiUp = new Plugin();
    $network->invoke(null, $wholeMultiUp, $wholeMulti, $interfaces, $profiles, $liveHealth, false);
    $network->invoke(null, $wholeMultiUp, array_replace($wholeMulti, ['networkKillSwitch' => false]),
        $interfaces, $profiles, [], true);
    checkRouting($wholeMultiUp->rules === [], 'Only a checked Multi-Path outage adds a network-wide guard.');
    $multiNetwork = Policy::routingSettings(array_replace($networkSettings, [
        'networkMode' => 'multi', 'interfaces' => ['lan', 'opt2'], 'tailscaleInterfaces' => ['opt2'],
        'strictInterfaces' => ['lan'], 'smartAssignedOnly' => true
    ]));
    checkRouting($multiNetwork['smartInterfaces'] === ['lan'] && $multiNetwork['strictInterfaces'] === [] &&
        !$multiNetwork['smartAssignedOnly'], 'Multi-Path under Whole-Network coverage uses selected LANs without per-IP assignment.');

    $assignment = ['interface' => 'lan', 'ip' => '192.0.2.23', 'mac' => '02:00:00:00:00:23',
        'profile' => 'jp', 'backup' => '', 'failure' => 'block'];
    $compileDevice = new ReflectionMethod(Firewall::class, 'registerAssignments');
    $diag = new Diagnostics();
    $good = new Plugin();
    $compileDevice->invoke(null, $good, $settings, $interfaces, ['device-a' => $assignment], $profiles, [], $diag);
    $device = $good->rules[Policy::marker('device', 'device-a')];
    $kill = $good->rules[Policy::marker('kill', 'device-a')];
    checkRouting($device['from'] === '192.0.2.23' && $kill['from'] === $device['from'], 'A shared-LAN guard applies to only the assigned IPv4.');
    checkRouting($device['priority'] < $kill['priority'] && $kill['to_not'], 'Protect the assigned address without blocking approved local destinations.');
    $down = new Plugin();
    $compileDevice->invoke(null, $down, $settings, $interfaces, ['device-a' => $assignment], $profiles, ['jp' => ['reachable' => false]], $diag);
    checkRouting(isset($down->rules[Policy::marker('kill', 'device-a')]) &&
        !isset($down->rules[Policy::marker('device', 'device-a')]), 'Down exit must remove the pass and preserve the IPv4 guard.');
    \OPNsense\Core\Config::$fixture = new SimpleXMLElement('<opnsense/>');
    $native = \OPNsense\Core\Config::$fixture->addChild('OPNsense')->addChild('tailscale')->addChild('settings');
    $native->addChild('enabled', '1');
    $native->addChild('advertiseExitNode', '1');
    $native->addChild('disableSNAT', '1');
    $tailnet = array_replace($assignment, [
        'kind' => 'tailnet', 'interface' => Policy::TAILSCALE_DEVICE, 'ip' => '100.101.102.103',
        'ipv6' => 'fd7a:115c:a1e0::103', 'mac' => ''
    ]);
    checkRouting(!Policy::assignmentPaused($tailnet) && Policy::assignmentPaused($tailnet + ['paused' => '1']) &&
        !Policy::assignmentPaused($assignment + ['paused' => '1']), 'Saved LAN and legacy Tailscale rules stay enabled.');
    $tailnetSettings = array_replace($settings, ['interfaces' => [Policy::TAILSCALE_DEVICE], 'tailscaleInterfaces' => []]);
    $tailnetInterfaces = [Policy::TAILSCALE_DEVICE => ['if' => Policy::TAILSCALE_DEVICE]];
    $nativePeer = new Plugin();
    $compileDevice->invoke(null, $nativePeer, $tailnetSettings, $tailnetInterfaces,
        ['native-peer' => $tailnet], $profiles, [], $diag);
    $tailnetPass = $nativePeer->rules[Policy::marker('device', 'native-peer')];
    checkRouting($tailnetPass['interface'] === Policy::TAILSCALE_DEVICE && $tailnetPass['from'] === $tailnet['ip'] &&
        $tailnetPass['gateway'] === 'VPN' && $nativePeer->nat[0]['from'] === $tailnet['ip'] &&
        $nativePeer->rules[Policy::marker('kill_v6', 'native-peer')]['from'] === $tailnet['ipv6'],
        'A native peer routes through its VPN and blocks IPv6 with a kill switch.');
    $pausedPeer = new Plugin();
    $compileDevice->invoke(null, $pausedPeer, $tailnetSettings, $tailnetInterfaces,
        ['native-peer' => $tailnet + ['paused' => '1']], $profiles, [], $diag);
    checkRouting($pausedPeer->rules === [] && $pausedPeer->nat === [] && $pausedPeer->dns === [],
        'A paused Tailscale rule must produce no route, DNS redirect, or kill switch.');
    $native->disableSNAT = '0';
    $userspace = new Plugin();
    $compileDevice->invoke(null, $userspace, $tailnetSettings, $tailnetInterfaces,
        ['native-peer' => $tailnet], $profiles, [], $diag);
    checkRouting(!isset($userspace->rules[Policy::marker('device', 'native-peer')]) &&
        isset($userspace->rules[Policy::marker('kill', 'native-peer')]),
        'Userspace mode cannot install the native per-peer VPN pass.');
    \OPNsense\Core\Config::$fixture = null;
    $multiAssignment = array_replace($assignment, [
        'mode' => 'multi', 'profile' => '', 'killSwitch' => '1', 'ipv6' => '2001:db8::23'
    ]);
    $deviceMulti = new Plugin();
    $compileDevice->invoke(null, $deviceMulti, $settings, $interfaces, [
        'protected' => $multiAssignment,
        'unprotected' => array_replace($multiAssignment, ['ip' => '192.0.2.24', 'killSwitch' => '0', 'ipv6' => ''])
    ], $profiles, [], $diag, true);
    checkRouting($deviceMulti->rules[Policy::marker('kill', 'protected')]['from'] === '192.0.2.23' &&
        $deviceMulti->rules[Policy::marker('kill_v6', 'protected')]['from'] === '2001:db8::23' &&
        !isset($deviceMulti->rules[Policy::marker('kill', 'unprotected')]) &&
        $deviceMulti->dns[0]['nordr'], 'A device Multi-Path outage closes only the opted-in addresses.');
    $deviceMultiUp = new Plugin();
    $compileDevice->invoke(null, $deviceMultiUp, $settings, $interfaces,
        ['protected' => $multiAssignment], $profiles, $liveHealth, $diag, false);
    checkRouting($deviceMultiUp->rules === [], 'Healthy Multi-Path does not block regular internet.');
    checkRouting(Policy::killSwitch($assignment) && !Policy::killSwitch(array_replace($assignment, ['mode' => 'multi'])) &&
        !Policy::killSwitch(array_replace($assignment, ['failure' => 'backup'])),
        'Existing one-exit, backup and Multi-Path policies keep their settings during an upgrade.');
    $unbound = new Plugin();
    $compileDevice->invoke(null, $unbound, $settings, $interfaces, [
        'unbound' => array_replace($assignment, [
            'ip' => '', 'ipv6' => '2001:db8::23', 'bindMac' => '1', 'failure' => 'backup'
        ])
    ], $profiles, [], $diag);
    checkRouting(!isset($unbound->rules[Policy::marker('kill', 'unbound')]) &&
        !isset($unbound->rules[Policy::marker('device', 'unbound')]) &&
        $unbound->rules[Policy::marker('kill_v6', 'unbound')]['from'] === '2001:db8::23' &&
        $unbound->nat === [], 'An unresolved MAC binding drops its IPv4 match and retains its stable IPv6 guard.');
    $native = array_replace($profiles['jp'], [
        'kind' => 'native', 'interface' => 'ovpnc1', 'gateway' => 'NORD', 'address' => '198.51.100.20'
    ]);
    $vpn = new Plugin();
    $compileDevice->invoke(null, $vpn, $settings, $interfaces, ['device-a' => $assignment], ['jp' => $native], [], $diag);
    checkRouting($vpn->rules[Policy::marker('device', 'device-a')]['gateway'] === 'NORD' &&
        $vpn->nat[0]['target'] === '198.51.100.20', 'An attached OpenVPN gateway gets a scoped policy and NAT.');
    $vpnDown = new Plugin();
    $compileDevice->invoke(null, $vpnDown, $settings, $interfaces, ['device-a' => $assignment],
        ['jp' => array_replace($native, ['owned' => false, 'address' => ''])], [], $diag);
    checkRouting(isset($vpnDown->rules[Policy::marker('kill', 'device-a')]) &&
        !isset($vpnDown->rules[Policy::marker('device', 'device-a')]) && $vpnDown->nat === [],
        'Loss of the native tunnel address keeps the per-IP guard without a route or NAT.');
    $address = ['up' => true, 'unicast' => [['address' => '198.51.100.20']]];
    checkRouting(NativeVpn::sourceAddress('ovpnc1', ['ovpnc1' => $address]) === '198.51.100.20',
        'A native exit needs an active source address.');
    checkRouting(NativeVpn::sourceAddress('ovpnc1', ['ovpnc1' => $address, 'wg3' => $address]) === '',
        'Reject a native exit when its source IP is also bound to a different interface.');
    checkRouting(\OPNsense\BlankVpn\Resolver::freePort(array_map(
        static fn (int $port): array => ['dnsPort' => $port], range(46651, 46655)
    )) === 46680, 'Additional native profiles use ports outside the service and proxy ranges.');
    $blocked = new Plugin();
    $compileDevice->invoke(null, $blocked, $settings, $interfaces, ['device-a' => array_replace($assignment,
        ['mode' => 'blocked', 'profile' => '', 'ipv6' => '2001:db8::23'])], $profiles, [], $diag);
    checkRouting(!isset($blocked->rules[Policy::marker('device', 'device-a')]) &&
        $blocked->rules[Policy::marker('kill', 'device-a')]['from'] === '192.0.2.23' &&
        $blocked->rules[Policy::marker('kill_v6', 'device-a')]['from'] === '2001:db8::23',
        'Blocked mode protects both assigned addresses without an exit.');
    $scoped = new Plugin();
    $compileSmart->invoke(null, $scoped, $settings + ['smartAssignedOnly' => true], $interfaces, $services, $profiles, []);
    checkRouting(!isset($scoped->rules['match']) && $scoped->dns === [],
        'Per-device Multi-Path does not classify or redirect unassigned devices.');
    checkRouting(Policy::tailnetAddress('100.101.102.103') && Policy::tailnetAddress('fd7a:115c:a1e0::23', true) &&
        !Policy::tailnetAddress('192.0.2.23'), 'Validate both Tailscale peer address families.');
    checkRouting(\OPNsense\BlankVpn\Resolver::validHostname('blankvpn.local') &&
        !\OPNsense\BlankVpn\Resolver::validHostname('other.local'), 'Permit the scoped mDNS name.');
    $magic = ['BackendState' => 'Running', 'Self' => ['DNSName' => 'opnsense.tailnet.ts.net.'],
        'CurrentTailnet' => ['MagicDNSEnabled' => true]];
    checkRouting(\OPNsense\BlankVpn\Resolver::magicDnsFromStatus($magic) === 'opnsense.tailnet.ts.net' &&
        \OPNsense\BlankVpn\Resolver::magicDnsFromStatus(array_replace($magic, ['BackendState' => 'Stopped'])) === '',
        'Use the connected node’s MagicDNS hostname.');
    $webGui = new SimpleXMLElement('<opnsense><system><webgui><althostnames>router.home.arpa</althostnames></webgui></system></opnsense>');
    checkRouting(\OPNsense\BlankVpn\Resolver::allowDashboardHostname($webGui, 'opnsense.tailnet.ts.net') &&
        !\OPNsense\BlankVpn\Resolver::allowDashboardHostname($webGui, 'opnsense.tailnet.ts.net') &&
        (string)$webGui->system->webgui->althostnames === 'router.home.arpa opnsense.tailnet.ts.net',
        'Allow the new dashboard hostname without overwriting aliases.');
    $diag->reserved = false;
    $moved = new Plugin();
    $compileDevice->invoke(null, $moved, $settings, $interfaces, ['device-a' => $assignment], $profiles, [], $diag);
    checkRouting(isset($moved->rules[Policy::marker('kill', 'device-a')]) &&
        !isset($moved->rules[Policy::marker('device', 'device-a')]), 'A missing reservation must not fall through to WAN.');
    echo "Multi-Path and per-IP policy fixtures passed.\n";
}
