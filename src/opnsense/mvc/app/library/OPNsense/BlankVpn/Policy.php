<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

final class Policy
{
    public const PRIORITY = 9000;
    public const LOCAL_TABLE = 'blankvpn_local';
    public const STATE_DIR = '/var/db/blank-vpn';
    public const PROBE_IP = '1.1.1.1';
    private const FAILURE = ['block', 'backup', 'wan'];
    private const LIVE_IPV6 = ['track6', 'idassoc6', 'dhcp6', 'slaac', 'linklocal'];

    public static function fields($node): array
    {
        return array_map('strval', $node->getNodeContent());
    }

    public static function settings(BlankVpn $model): array
    {
        $stored = self::fields($model->settings);
        $result = ['enabled' => ($stored['enabled'] ?? '0') === '1'];
        foreach (['interfaces', 'strictInterfaces', 'smartInterfaces', 'tailscaleInterfaces', 'localNetworks'] as $key) {
            $result[$key] = array_values(array_filter(explode(',', $stored[$key] ?? ''), 'strlen'));
        }
        $result['smartAssignedOnly'] = ($stored['smartAssignedOnly'] ?? '0') === '1';
        $result['coverage'] = ($stored['coverage'] ?? '') === 'network' ? 'network' : 'device';
        $result['networkMode'] = in_array($stored['networkMode'] ?? '', ['full', 'multi', 'blocked', 'disabled'], true)
            ? $stored['networkMode'] : 'disabled';
        $result['networkProfile'] = $stored['networkProfile'] ?? '';
        $killSwitch = $stored['networkKillSwitch'] ?? '';
        $result['networkKillSwitch'] = $killSwitch === '1' || ($killSwitch === '' && $result['networkMode'] !== 'multi');
        $result['dashboardBind'] = ($stored['dashboardBind'] ?? '') === 'tailnet' ? 'tailnet' : 'lan';
        $result['hostname'] = $stored['hostname'] ?? 'blankvpn.home.arpa';
        return $result;
    }

    public static function routingSettings(array $settings): array
    {
        if (($settings['coverage'] ?? '') === 'network') {
            $settings['interfaces'] = array_values(array_diff($settings['interfaces'], $settings['tailscaleInterfaces']));
            $settings['smartInterfaces'] = $settings['networkMode'] === 'multi' ? $settings['interfaces'] : [];
            $settings['strictInterfaces'] = [];
            $settings['smartAssignedOnly'] = false;
        }
        return $settings;
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

    public static function routes(BlankVpn $model): array
    {
        return self::profiles($model) + NativeVpn::routes($model) + ProxyRuntime::routes($model);
    }

    public static function assignments(BlankVpn $model): array
    {
        $assignments = [];
        foreach ($model->assignments->assignment->iterateItems() as $id => $node) {
            $assignments[$id] = ['id' => $id] + self::fields($node);
        }
        return $assignments;
    }

    public static function mode(array $assignment): string
    {
        return ($assignment['mode'] ?? '') ?: (($assignment['profile'] ?? '') !== '' ? 'full' : 'default');
    }

    public static function killSwitch(array $assignment): bool
    {
        $mode = self::mode($assignment);
        if (!in_array($mode, ['full', 'multi'], true)) {
            return false;
        }
        return match ($assignment['killSwitch'] ?? '') {
            '1' => true,
            '0' => false,
            default => $mode === 'full' && ($assignment['failure'] ?? 'block') === 'block'
        };
    }

    public static function tailnetAddress(string $address, bool $ipv6 = false): bool
    {
        return self::contains($ipv6 ? 'fd7a:115c:a1e0::/48' : '100.64.0.0/10', $address);
    }

    public static function tailnetInterface(string $interface): bool
    {
        $candidate = self::availableInterfaces()[$interface] ?? [];
        return str_starts_with($interface, 'opt') && isset($candidate['device']) &&
            !preg_match('/^tailscale[0-9]*$/D', $candidate['device']);
    }

    public static function ipv6Address(string $value): string
    {
        if ($value === '') {
            return '';
        }
        if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ||
            self::contains('fe80::/10', $value) || self::contains('ff00::/8', $value) ||
            in_array($value, ['::', '::1'], true)) {
            throw new \DomainException('Enter a stable IPv6 unicast address for this device.');
        }
        return inet_ntop(inet_pton($value));
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
                preg_match('/^(wg|ovpn[cs]?|ipsec|enc|tun|tap|ppp|lo|tailscale)[0-9]/i', $device)
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
        $runtime = null;
        foreach ($interfaces as $interface) {
            $node = $config->interfaces->{$interface};
            $name = (string)$node->descr ?: strtoupper($interface);
            $ipv4 = self::cidr((string)$node->ipaddr . '/' . (string)$node->subnet);
            if ($ipv4 === null || str_contains($ipv4, ':')) {
                throw new \DomainException($name . ' needs a Static IPv4 address on the router. Check Interfaces → Assignments.');
            }
            $networks[] = $ipv4;
            $ipv6 = (string)$node->ipaddrv6;
            if ($ipv6 === '' || $ipv6 === 'none') {
                continue;
            }
            if (in_array($ipv6, self::LIVE_IPV6, true)) {
                $runtime ??= self::runtimeInterfaces();
                $rows = $runtime[(string)$node->if]['ipv6'] ?? null;
                if (!is_array($rows)) {
                    throw new \DomainException('Blank VPN could not read the current IPv6 addresses on ' . $name . '. Check that the interface is active and try again.');
                }
                array_push($networks, ...self::interfaceIpv6Networks($rows));
                continue;
            }
            $network = self::cidr($ipv6 . '/' . (string)$node->subnetv6);
            if ($network === null || !str_contains($network, ':')) {
                throw new \DomainException($name . ' has an unsupported IPv6 mode or invalid IPv6 prefix. Check Interfaces → Assignments.');
            }
            $networks[] = $network;
        }
        return array_values(array_unique($networks));
    }

    private static function runtimeInterfaces(): array
    {
        $output = (new Backend())->configdRun('interface list ifconfig', false, 5);
        $interfaces = json_decode((string)$output, true);
        return is_array($interfaces) ? $interfaces : [];
    }

    private static function interfaceIpv6Networks(array $rows): array
    {
        $networks = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $ip = explode('%', (string)($row['ipaddr'] ?? ''), 2)[0];
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ||
                self::contains('fe80::/10', $ip) || self::contains('ff00::/8', $ip) ||
                in_array($ip, ['::', '::1'], true)) {
                continue;
            }
            $network = self::cidr($ip . '/' . (string)($row['subnetbits'] ?? ''));
            if ($network !== null) {
                $networks[] = $network;
            }
        }
        return $networks;
    }

    public static function localNetworks(array $settings): array
    {
        $networks = ['127.0.0.0/8', '::1/128', 'fe80::/10', 'ff02::/16', '224.0.0.251/32', '255.255.255.255/32'];
        foreach ($settings['localNetworks'] as $network) {
            if (self::cidr($network) === $network) {
                $networks[] = $network;
            }
        }
        $runtime = null;
        foreach (Config::getInstance()->object()->interfaces->children() as $id => $node) {
            if (!isset($node->enable)) {
                continue;
            }
            $local = self::interfaceId($id) && empty((string)$node->gateway) &&
                empty((string)$node->gatewayv6) && empty((string)$node->gateway_interface);
            if ($local && in_array((string)$node->ipaddrv6, self::LIVE_IPV6, true)) {
                $runtime ??= self::runtimeInterfaces();
                $rows = $runtime[(string)$node->if]['ipv6'] ?? [];
                if (is_array($rows)) {
                    array_push($networks, ...self::interfaceIpv6Networks($rows));
                }
            }
            foreach ([['ipaddr', 'subnet', 32], ['ipaddrv6', 'subnetv6', 128]] as [$address, $prefix, $max]) {
                $ip = (string)$node->{$address};
                if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                    continue;
                }
                $networks[] = $ip . '/' . $max;
                if ($local) {
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
