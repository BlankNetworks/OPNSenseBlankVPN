<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;

final class Policy
{
    public const PRIORITY = 9000;
    public const LOCAL_TABLE = 'blankvpn_local';
    public const STATE_DIR = '/var/db/blank-vpn';
    public const PROBE_IP = '1.1.1.1';
    private const FAILURE = ['block', 'backup', 'wan'];

    public static function fields($node): array
    {
        return array_map('strval', $node->getNodeContent());
    }

    public static function settings(BlankVpn $model): array
    {
        $stored = self::fields($model->settings);
        $result = ['enabled' => ($stored['enabled'] ?? '0') === '1'];
        foreach (['interfaces', 'strictInterfaces', 'smartInterfaces', 'localNetworks'] as $key) {
            $result[$key] = array_values(array_filter(explode(',', $stored[$key] ?? ''), 'strlen'));
        }
        $result['hostname'] = $stored['hostname'] ?? 'opnsense.home.arpa';
        return $result;
    }

    public static function profiles(BlankVpn $model): array
    {
        $profiles = [];
        foreach ($model->profiles->profile->iterateItems() as $id => $node) {
            $row = self::fields($node);
            $ownership = json_decode($row['ownership'], true);
            if (is_array($ownership)) {
                $profiles[$id] = ['id' => $id, 'name' => $row['name'], 'relay' => $row['relay']] + $ownership;
            }
        }
        return $profiles;
    }

    public static function assignments(BlankVpn $model): array
    {
        $assignments = [];
        foreach ($model->assignments->assignment->iterateItems() as $id => $node) {
            $assignments[$id] = ['id' => $id] + self::fields($node);
        }
        return $assignments;
    }

    public static function availableInterfaces(): array
    {
        $interfaces = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $id => $node) {
            $device = (string)$node->if;
            if (
                !self::interfaceId($id) || !isset($node->enable) ||
                !empty((string)$node->gateway) || !empty((string)$node->gatewayv6) ||
                !empty((string)$node->gateway_interface) || !preg_match('/^[a-z][a-z0-9_.:-]{0,31}$/iD', $device) ||
                preg_match('/^(wg|ovpn|ipsec|enc|tun|tap|ppp|lo)[0-9]/i', $device)
            ) {
                continue;
            }
            $interfaces[$id] = ['id' => $id, 'device' => $device, 'name' => (string)$node->descr ?: strtoupper($id)];
        }
        return $interfaces;
    }

    public static function interfaceId(string $interface): bool
    {
        return preg_match('/^(?:lan|opt[1-9][0-9]*)$/D', $interface) === 1;
    }

    public static function cidr(string $value, bool $localOnly = true): ?string
    {
        if (strlen($value) > 50) {
            return null;
        }
        $parts = explode('/', $value);
        $bytes = @inet_pton($parts[0]);
        if ($bytes === false || count($parts) !== 2 || !ctype_digit($parts[1])) {
            return null;
        }
        $length = strlen($bytes) * 8;
        $prefix = (int)$parts[1];
        if ($prefix < ($localOnly ? ($length === 32 ? 8 : 32) : 1) || $prefix > $length) {
            return null;
        }
        for ($i = 0; $i < strlen($bytes); $i++) {
            $bits = min(8, max(0, $prefix - $i * 8));
            $bytes[$i] = chr(ord($bytes[$i]) & ((0xff << (8 - $bits)) & 0xff));
        }
        return inet_ntop($bytes) . '/' . $prefix;
    }

    public static function contains(string $cidr, string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !str_contains($cidr, '/')) {
            return false;
        }
        [, $prefix] = explode('/', $cidr, 2);
        return self::cidr($ip . '/' . $prefix, false) === $cidr;
    }

    public static function segmentNetworks(array $interfaces): array
    {
        $networks = [];
        $config = Config::getInstance()->object();
        foreach ($interfaces as $interface) {
            $node = $config->interfaces->{$interface};
            $ipv4 = self::cidr((string)$node->ipaddr . '/' . (string)$node->subnet);
            $ipv6 = (string)$node->ipaddrv6;
            if ($ipv4 === null || str_contains($ipv4, ':') ||
                !in_array($ipv6, ['', 'none'], true) && !filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                throw new \DomainException('A managed segment needs static IPv4 and either static IPv6 or no IPv6.');
            }
            $networks[] = $ipv4;
            if (!in_array($ipv6, ['', 'none'], true)) {
                $network = self::cidr($ipv6 . '/' . (string)$node->subnetv6);
                if ($network === null) {
                    throw new \DomainException('The managed segment has an invalid static IPv6 network.');
                }
                $networks[] = $network;
            }
        }
        return array_values(array_unique($networks));
    }

    public static function localNetworks(array $settings): array
    {
        $networks = ['127.0.0.0/8', '::1/128', 'fe80::/10', 'ff02::/16', '255.255.255.255/32'];
        foreach ($settings['localNetworks'] as $network) {
            if (self::cidr($network) === $network) {
                $networks[] = $network;
            }
        }
        foreach (Config::getInstance()->object()->interfaces->children() as $node) {
            if (!isset($node->enable)) {
                continue;
            }
            foreach ([['ipaddr', 'subnet', 32], ['ipaddrv6', 'subnetv6', 128]] as [$address, $prefix, $max]) {
                $ip = (string)$node->{$address};
                if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                    continue;
                }
                $networks[] = $ip . '/' . $max;
                if (
                    empty((string)$node->gateway) && empty((string)$node->gatewayv6) &&
                    empty((string)$node->gateway_interface) && self::interfaceId($node->getName())
                ) {
                    $subnet = self::cidr($ip . '/' . (string)$node->{$prefix});
                    if ($subnet !== null) {
                        $networks[] = $subnet;
                    }
                }
            }
        }
        return array_values(array_unique($networks));
    }

    public static function stateDirectory(): string
    {
        if (!is_dir(self::STATE_DIR) && !@mkdir(self::STATE_DIR, 0700) && !is_dir(self::STATE_DIR)) {
            throw new \RuntimeException('The Blank VPN state directory is unavailable.');
        }
        if (is_link(self::STATE_DIR) || (fileperms(self::STATE_DIR) & 0077) !== 0) {
            throw new \RuntimeException('The Blank VPN state directory permissions are unsafe.');
        }
        return self::STATE_DIR;
    }

    public static function writeState(string $name, string $contents): string
    {
        $path = self::stateDirectory() . '/' . $name;
        $temporary = tempnam(self::STATE_DIR, '.blankvpn-');
        if ($temporary === false) {
            throw new \RuntimeException('Blank VPN could not create its state file.');
        }
        try {
            chmod($temporary, 0600);
            if (file_put_contents($temporary, $contents) !== strlen($contents) || !rename($temporary, $path)) {
                throw new \RuntimeException('Blank VPN could not write its state file.');
            }
        } finally {
            if (is_file($temporary)) {
                unlink($temporary);
            }
        }
        return $path;
    }

    public static function failure(string $value): bool
    {
        return in_array($value, self::FAILURE, true);
    }

    public static function validMac(string $mac): bool
    {
        return preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D', $mac) === 1;
    }

    public static function marker(string $type, string $id): string
    {
        return 'blankvpn_' . $type . '_' . substr(hash('sha256', $id), 0, 20);
    }
}
