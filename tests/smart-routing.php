<?php

declare(strict_types=1);

namespace OPNsense\Core {
    final class Config
    {
        public static function getInstance(): self
        {
            return new self();
        }

        public function object(): object
        {
            return (object)['system' => (object)[]];
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

    $domains = SmartRouting::domains("NETFLIX.com, *.netflix.com.\n*.nflxvideo.net");
    checkRouting($domains === ['netflix.com', 'nflxvideo.net'], 'Normalize suffixes and deduplicate the apex.');
    $fileDomains = SmartRouting::domains("\xEF\xBB\xBF# Domains\r\n*.netflix.com, Nflxvideo.net # streaming\r\n");
    checkRouting($fileDomains === $domains, 'Plain text and CSV imports must accept BOM, comments and wildcards.');
    $largeList = array_map(static fn (int $n): string => "service{$n}.example.com", range(1, 1000));
    checkRouting(SmartRouting::domains(implode("\n", $largeList)) === $largeList, 'Accept a 1,000-domain list.');
    rejectRouting(fn () => SmartRouting::domains(implode("\n", [...$largeList, 'extra.example.com'])));
    checkRouting(SmartRouting::matches('a.b.netflix.com', 'netflix.com'), 'Match multiple subdomain levels.');
    checkRouting(!SmartRouting::matches('fakenetflix.com', 'netflix.com'), 'Require a DNS label boundary.');
    foreach (['com', 'http://netflix.com', '*foo.netflix.com', '127.0.0.1', 'opnsense.home.arpa', 'x.local'] as $invalid) {
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

    $table = SmartRouting::table($service);
    checkRouting(strlen($table) <= 31, 'PF table name must fit the native limit.');
    checkRouting($table === SmartRouting::table(array_replace($service, ['domains' => array_reverse($domains)])), 'Table identity is independent of domain order.');
    checkRouting($table !== SmartRouting::table(array_replace($service, ['profile' => 'ca'])), 'Changing exits invalidates an old destination table.');
    $profiles = ['jp' => [
        'id' => 'jp', 'address' => '10.64.0.9/32', 'dns' => ['10.64.0.1', 'fd00::1'],
        'owned' => true, 'gateway' => 'VPN', 'interface' => 'wg0', 'logicalInterface' => 'opt1',
        'dnsPort' => 46651
    ]];
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
    checkRouting($good->nat[0]['to'] === '<' . $table . '>' && $good->nat[0]['from'] === 'lan', 'Scope Smart Routing NAT by destination and source network.');
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
        'Whole-network routing needs a gateway pass, LAN-scoped NAT and an internet guard.');
    $wholeDown = new Plugin();
    $network->invoke(null, $wholeDown, $networkSettings, $interfaces, $profiles, ['jp' => ['reachable' => false]]);
    checkRouting(!isset($wholeDown->rules[Policy::marker('device', 'network:lan')]) &&
        isset($wholeDown->rules[Policy::marker('kill', 'network:lan')],
            $wholeDown->rules[Policy::marker('kill_v6', 'network:lan')]) && $wholeDown->nat === [],
        'A whole-network VPN outage blocks both address families without WAN fallback.');
    $multiNetwork = Policy::routingSettings(array_replace($networkSettings, [
        'networkMode' => 'multi', 'interfaces' => ['lan', 'opt2'], 'tailscaleInterfaces' => ['opt2'],
        'strictInterfaces' => ['lan'], 'smartAssignedOnly' => true
    ]));
    checkRouting($multiNetwork['smartInterfaces'] === ['lan'] && $multiNetwork['strictInterfaces'] === [] &&
        !$multiNetwork['smartAssignedOnly'], 'Whole-network Multi-Path covers selected LANs without per-IP assignment.');

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
    $diag->reserved = false;
    $moved = new Plugin();
    $compileDevice->invoke(null, $moved, $settings, $interfaces, ['device-a' => $assignment], $profiles, [], $diag);
    checkRouting(isset($moved->rules[Policy::marker('kill', 'device-a')]) &&
        !isset($moved->rules[Policy::marker('device', 'device-a')]), 'A missing reservation must not fall through to WAN.');
    echo "Smart Routing and per-IP policy fixtures passed.\n";
}
