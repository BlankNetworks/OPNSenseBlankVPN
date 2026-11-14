<?php

declare(strict_types=1);

use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\WanEgress;

foreach (['Policy', 'Firewall', 'WanEgress'] as $class) {
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $class . '.php';
}

function checkWan(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$carrier = ['name' => 'ISP_DHCP', 'interface' => 'wan', 'if' => 'igc0',
    'ipprotocol' => 'inet', 'gateway' => '192.0.2.1'];
$carrier6 = ['name' => 'ISP_DHCP6', 'interface' => 'wan', 'if' => 'igc0',
    'ipprotocol' => 'inet6', 'gateway' => 'fe80::1%igc0'];
$interfaces = [
    'igc0' => ['up' => true, 'unicast' => [['address' => 'fe80::2%igc0'], ['address' => '192.0.2.2']]],
    'wg0' => ['up' => true, 'unicast' => [['address' => '198.51.100.2']]],
    'igc1' => ['up' => false, 'unicast' => [['address' => '192.0.2.3']]]
];
$vpn = array_replace($carrier, ['name' => 'WG_GATEWAY', 'if' => 'wg0']);
$alternate = array_replace($carrier, ['name' => 'OPT_GATEWAY', 'interface' => 'opt1']);
$forcedDown = array_replace($carrier, ['name' => 'DISABLED_WAN', 'force_down' => true]);
$offline = array_replace($carrier, ['name' => 'OFFLINE_WAN', 'if' => 'igc1']);
$wan = WanEgress::select([$vpn, $alternate, $forcedDown, $offline, $carrier, $carrier6], $interfaces);
checkWan(array_column($wan, 'gateway') === ['ISP_DHCP', 'ISP_DHCP6'] &&
    $wan['inet']['address'] === '192.0.2.2', 'Only a usable primary ISP interface can be selected.');
checkWan(WanEgress::select([$vpn, $alternate, $forcedDown, $offline], $interfaces) === [],
    'Missing primary WAN must leave direct routing unavailable.');

$id = '9.9.9.9:192.0.2.2';
$pass = Policy::marker('wan_dns', $id);
$guard = Policy::marker('wan_dns_guard', $id);
$rules = "pass out quick inet proto udp from 192.0.2.2 to 9.9.9.9 port = domain "
    . "route-to (igc0 192.0.2.1) label \"{$pass}\"\n"
    . "block drop out quick inet proto udp from 192.0.2.2 to 9.9.9.9 port = domain label \"{$guard}\"\n";
checkWan(WanEgress::dnsUpstreams($wan, Firewall::parseLoadedRules($rules)) === ['9.9.9.9@192.0.2.2'],
    'DNS uses only a carrier-bound source, with a verified direct route and a guard.');
checkWan(WanEgress::dnsUpstreams($wan, Firewall::parseLoadedRules(str_replace('(igc0 ', '(wg0 ', $rules))) === [],
    'DNS must stay unconfigured when the direct rule is missing or a VPN interface is loaded.');
checkWan(WanEgress::dnsUpstreams($wan, Firewall::parseLoadedRules(strtok($rules, "\n"))) === [],
    'DNS must stay unconfigured when the guard is missing.');

echo "Direct WAN gateway and DNS fixture checks passed.\n";
