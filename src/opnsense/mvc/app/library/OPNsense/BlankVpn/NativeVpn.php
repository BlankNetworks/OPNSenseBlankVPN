<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;
use OPNsense\Routing\Gateways;

final class NativeVpn
{
    public static function gateways(): array
    {
        $config = Config::getInstance()->object()->interfaces;
        $gateways = [];
        foreach ((new Gateways())->gateway_item->iterateItems() as $id => $node) {
            $gateway = Policy::fields($node);
            $logical = $gateway['interface'] ?? '';
            if (!Policy::interfaceId($logical) || ($gateway['ipprotocol'] ?? '') !== 'inet' ||
                ($gateway['disabled'] ?? '0') === '1' || ($gateway['defaultgw'] ?? '0') === '1' ||
                ($gateway['force_down'] ?? '0') === '1' ||
                !preg_match('/^[a-zA-Z0-9_-]{1,32}$/D', $gateway['name'] ?? '')) {
                continue;
            }
            $interface = $config->{$logical};
            $device = (string)$interface->if;
            if (!isset($interface->enable) || !self::tunnelDevice($device)) {
                continue;
            }
            if (str_starts_with($gateway['name'], 'BVPN_')) {
                continue;
            }
            $gateways[$id] = [
                'id' => $id, 'gateway' => $gateway['name'], 'interface' => $device,
                'logicalInterface' => $logical, 'protocol' => str_starts_with($device, 'wg') ? 'WireGuard' : 'OpenVPN'
            ];
        }
        return $gateways;
    }

    public static function tunnelDevice(string $device): bool
    {
        return preg_match('/^(?:wg|ovpnc)[0-9]+$/D', $device) === 1;
    }

    public static function routes(BlankVpn $model): array
    {
        $rows = $model->nativeRoutes->route->iterateItems();
        $routes = [];
        $gateways = null;
        $interfaces = null;
        foreach ($rows as $id => $node) {
            $row = Policy::fields($node);
            $gateways ??= self::gateways();
            $interfaces ??= net_get_interfaces() ?: [];
            $gateway = $gateways[$row['gatewayId']] ?? [];
            $configured = ($gateway['interface'] ?? '') === $row['device'] &&
                ($gateway['gateway'] ?? '') === $row['gatewayName'] &&
                ($gateway['logicalInterface'] ?? '') === $row['logicalInterface'];
            $address = $configured ? self::sourceAddress($row['device'], $interfaces) : '';
            $routes[$id] = [
                'id' => $id, 'kind' => 'native', 'name' => $row['name'], 'protocol' => $row['protocol'],
                'provider' => $row['provider'] ?? '', 'gateway' => $row['gatewayName'], 'interface' => $row['device'],
                'logicalInterface' => $row['logicalInterface'], 'configured' => $configured,
                'address' => $address, 'dnsPort' => (int)$row['dnsPort'],
                'dns' => [$row['dns']]
            ];
        }
        return $routes;
    }

    public static function sourceAddress(string $device, array $interfaces): string
    {
        if (!self::tunnelDevice($device) || empty($interfaces[$device]['up'])) {
            return '';
        }
        $addresses = [];
        foreach ($interfaces as $name => $interface) {
            foreach ($interface['unicast'] ?? [] as $entry) {
                $ip = $entry['address'] ?? '';
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $addresses[$ip][$name] = true;
                }
            }
        }
        $matches = array_filter($addresses, static fn (array $owners): bool => isset($owners[$device]));
        if (count($matches) !== 1 || count(reset($matches)) !== 1) {
            return '';
        }
        return array_key_first($matches);
    }
}
