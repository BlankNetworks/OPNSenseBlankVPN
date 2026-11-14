<?php

declare(strict_types=1);

namespace OPNsense\Core {
    final class Config
    {
        public static bool $reflection = false;

        public static function getInstance(): self
        {
            return new self();
        }

        public function object(): object
        {
            return (object)['system' => (object)['enablenatreflectionhelper' => self::$reflection]];
        }
    }
}

namespace OPNsense\Firewall {
    final class Plugin
    {
        public array $rules = [];
        public array $dns = [];

        public function registerFilterRule(int $priority, array $rule): void
        {
            $this->rules[$rule['label']] = $rule + ['priority' => $priority];
        }

        public function registerDestinationNatRule(int $priority, array $rule): void
        {
            $this->dns[] = $rule + ['priority' => $priority];
        }
    }
}

namespace OPNsense\BlankVpn {
    final class Diagnostics
    {
        public array $rows = [];

        public function reservations(): array
        {
            return $this->rows;
        }
    }

    function file_get_contents(string $path): string|false
    {
        return $path === Policy::STATE_DIR . '/mac-claims.json'
            ? json_encode($GLOBALS['fixtureMacState'], JSON_THROW_ON_ERROR)
            : \file_get_contents($path);
    }
}

namespace {
    use OPNsense\BlankVpn\Diagnostics;
    use OPNsense\BlankVpn\Firewall;
    use OPNsense\BlankVpn\Policy;
    use OPNsense\BlankVpn\Resolver;
    use OPNsense\Core\Config;
    use OPNsense\Firewall\Plugin;

    foreach (['Policy', 'DeviceIdentity', 'Firewall', 'Resolver', 'ProxyRuntime', 'SmartRouting'] as $class) {
        require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $class . '.php';
    }

    function checkBypass(bool $ok, string $message): void
    {
        if (!$ok) {
            throw new RuntimeException($message);
        }
    }

    $settings = [
        'enabled' => true, 'coverage' => 'network', 'networkMode' => 'full_multi',
        'interfaces' => ['lan', 'opt1'], 'tailscaleInterfaces' => ['opt1']
    ];
    $device = [
        'kind' => 'lan', 'mode' => 'blocked', 'interface' => 'lan', 'networkBypass' => '1',
        'bindMac' => '0', 'ip' => '10.0.0.20', 'mac' => '02:00:00:00:00:20',
        'ipv6' => '2001:db8:1::20', 'networkBypassIpv6' => '2001:db8:1::20'
    ];
    $rows = [
        'device' => $device,
        'unselected' => array_replace($device, ['interface' => 'opt2']),
        'transit' => array_replace($device, ['interface' => 'opt1']),
        'tunnel' => array_replace($device, ['kind' => 'tailnet']),
        'disabled' => array_replace($device, ['networkBypass' => '0'])
    ];
    foreach (['full', 'full_multi', 'multi', 'blocked', 'disabled'] as $mode) {
        $applicable = Policy::networkBypassAssignments(array_replace($settings, ['networkMode' => $mode]), $rows);
        checkBypass(array_keys($applicable) === (in_array($mode, ['full', 'full_multi', 'multi'], true)
            ? ['device'] : []), 'Only selected LAN devices in an active whole-network routing mode may bypass it.');
    }
    checkBypass(Policy::networkBypassAssignments(array_replace($settings, ['coverage' => 'device']), $rows) === [] &&
        Policy::networkBypassAssignments(array_replace($settings, ['enabled' => false]), $rows) === [],
        'A saved whole-network exception does not affect device-specific or disabled routing.');

    $diagnostics = new Diagnostics();
    $diagnostics->rows = [['interface' => 'lan', 'mac' => $device['mac'], 'ip' => '10.0.0.21']];
    $GLOBALS['fixtureMacState'] = ['confirmed' => ['device' => $device['ip']]];
    checkBypass(Policy::networkBypassSources($settings, $rows, $diagnostics) === [],
        'Do not grant the old IP or the newly reserved one before checking the moved reservation.');
    $GLOBALS['fixtureMacState'] = [
        'confirmed' => ['device' => '10.0.0.21'], 'networkBypassIpv6' => ['device' => '2001:db8:1::20'],
        'observations' => ['arp' => ['lan/10.0.0.21' => ['02:00:00:00:00:21']]]
    ];
    checkBypass(Policy::networkBypassSources($settings, $rows, $diagnostics) === [],
        'A contradictory MAC observation prevents either family from getting an exception.');
    unset($GLOBALS['fixtureMacState']['observations']);
    $scopes = Policy::networkBypassSources($settings, $rows, $diagnostics);
    checkBypass($scopes === [
        'device' => ['interface' => 'lan', 'sources' => ['inet' => '10.0.0.21', 'inet6' => '2001:db8:1::20']]
    ], 'The exception follows the confirmed DHCP reservation and verifies an explicitly selected IPv6 address.');
    $edited = $rows;
    $edited['device']['ipv6'] = '2001:db8:1::21';
    checkBypass(Policy::networkBypassSources($settings, $edited, $diagnostics)['device']['sources'] === [
        'inet' => '10.0.0.21'
    ], 'An edited IPv6 address invalidates the prior owner confirmation and never adds an unknown IPv6 source.');

    $interfaces = ['lan' => ['if' => 'igc1']];
    $wan = ['inet' => ['gateway' => 'WAN_DHCP']];
    $compile = new ReflectionMethod(Firewall::class, 'registerDeviceBypass');
    $firewall = new Plugin();
    $compile->invoke(null, $firewall, $interfaces, $scopes, $wan);
    $direct = $firewall->rules[Policy::marker('device_bypass', 'device:inet')];
    $guard = $firewall->rules[Policy::marker('device_bypass_guard', 'device:inet')];
    $ipv6Guard = $firewall->rules[Policy::marker('device_bypass_guard', 'device:inet6')];
    checkBypass($direct['type'] === 'pass' && $direct['direction'] === 'in' && $direct['quick'] &&
        $direct['from'] === '10.0.0.21' && $direct['gateway'] === 'WAN_DHCP' && $direct['skip_rules_gw_down'] &&
        $direct['to'] === '<' . Policy::COMBINED_LOCAL_TABLE . '>' && $direct['to_not'] &&
        $direct['priority'] < Policy::PRIORITY + 8 &&
        $guard['type'] === 'block' && $guard['priority'] === $direct['priority'] &&
        $ipv6Guard['type'] === 'block' && $ipv6Guard['from'] === '2001:db8:1::20' &&
        !isset($firewall->rules[Policy::marker('device_bypass', 'device:inet6')]),
        'The isolated WAN pass and guard precede domain and network policy, and an unavailable WAN family blocks.');
    foreach (['inet' => '10.0.0.21', 'inet6' => '2001:db8:1::20'] as $family => $ip) {
        $dnsGuard = $firewall->rules[Policy::marker('device_bypass_dns_guard', 'device:' . $family)];
        $dnsPass = $firewall->rules[Policy::marker('dns', 'network-bypass:device:' . $family)];
        checkBypass($dnsGuard['from'] === $ip && $dnsGuard['to_port'] === '53' && $dnsGuard['protocol'] === 'tcp/udp' &&
            $dnsPass['priority'] < $dnsGuard['priority'], 'Allow the dedicated redirect then block unredirected DNS.');
    }
    checkBypass(array_column($firewall->dns, 'from') === ['10.0.0.21', '2001:db8:1::20'] &&
        array_column($firewall->dns, 'local-port') === array_fill(0, 2, (string)Resolver::DEVICE_BYPASS_PORT) &&
        max(array_column($firewall->dns, 'priority')) < 55,
        'Redirect only verified source addresses to a dedicated WAN-only listener before network-level DNS.');
    Config::$reflection = true;
    $firewall = new Plugin();
    $compile->invoke(null, $firewall, $interfaces, $scopes, []);
    checkBypass($firewall->dns === [] &&
        ($firewall->rules[Policy::marker('device_bypass_dns_guard', 'device:inet')]['type'] ?? '') === 'block' &&
        ($firewall->rules[Policy::marker('device_bypass_guard', 'device:inet')]['type'] ?? '') === 'block',
        'A missing DNS redirect or WAN gateway keeps the device exception closed.');

    echo "Whole-Network device Bypass fixture checks passed.\n";
}
