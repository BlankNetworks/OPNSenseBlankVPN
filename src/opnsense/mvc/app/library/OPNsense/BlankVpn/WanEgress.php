<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use OPNsense\Firewall\Plugin;
use OPNsense\Routing\Gateways;

final class WanEgress
{
    public static function gateways(?Plugin $firewall = null): array
    {
        $gateways = $firewall?->getGateways() ?? new Gateways();
        return self::select($gateways->gatewaysIndexedByName(), net_get_interfaces() ?: []);
    }

    public static function select(array $gateways, array $interfaces): array
    {
        $result = [];
        foreach ($gateways as $gateway) {
            $family = $gateway['ipprotocol'] ?? '';
            $interface = $gateway['if'] ?? '';
            $name = $gateway['name'] ?? '';
            $status = $interfaces[$interface] ?? [];
            if (!in_array($family, ['inet', 'inet6'], true) || isset($result[$family]) ||
                ($gateway['interface'] ?? '') !== 'wan' || empty($status['up']) ||
                $name === '' || !preg_match('/^[a-zA-Z][a-zA-Z0-9_.-]*$/D', $interface) ||
                preg_match('/^(?:wg|ovpn|tun|tap|tailscale|ipsec|gre|gif|lo|bvproxy)/i', $interface) ||
                !empty($gateway['disabled']) || !empty($gateway['defunct']) || !empty($gateway['force_down'])) {
                continue;
            }
            $flag = $family === 'inet' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
            if (empty($gateway['gateway_interface']) &&
                !filter_var(explode('%', $gateway['gateway'] ?? '', 2)[0], FILTER_VALIDATE_IP, $flag)) {
                continue;
            }
            foreach ($status['unicast'] ?? [] as $entry) {
                $address = explode('%', $entry['address'] ?? '', 2)[0];
                if (!filter_var($address, FILTER_VALIDATE_IP, $flag)) {
                    continue;
                }
                $result[$family] = ['gateway' => $name, 'interface' => $interface,
                    'address' => $address, 'logicalInterface' => 'wan'];
                break;
            }
        }
        return $result;
    }

    public static function dnsServers(array $wan): array
    {
        return isset($wan['inet']) ? ['9.9.9.9', '149.112.112.112'] : [];
    }

    public static function dnsUpstreams(array $wan, array $rules): array
    {
        $upstreams = [];
        foreach (self::dnsServers($wan) as $server) {
            $source = $wan['inet']['address'];
            $id = $server . ':' . $source;
            $pass = $rules[Policy::marker('wan_dns', $id)] ?? [];
            $guard = $rules[Policy::marker('wan_dns_guard', $id)] ?? [];
            if (($pass['action'] ?? '') === 'pass' && ($pass['gateway'] ?? '') === $wan['inet']['interface'] &&
                ($guard['action'] ?? '') === 'block' && ($pass['source'] ?? '') === $source &&
                ($guard['source'] ?? '') === $source) {
                $upstreams[] = $server . '@' . $source;
            }
        }
        return $upstreams;
    }
}
