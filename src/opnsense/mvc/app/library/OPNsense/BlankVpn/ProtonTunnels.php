<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;

final class ProtonTunnels
{
    /**
     * Proton documents 10.N.0.2/32 with DNS 10.N.0.1 for additional manual tunnels.
     * Each tunnel still needs its own client credential issued by Proton.
     */
    public static function allocate(
        array $config,
        array $wireGuardNetworks,
        array $localNetworks,
        bool $dnsOverride = false,
        bool $ipv4Only = false,
        string $previousAddress = ''
    ): array {
        $reserved = array_unique([...$wireGuardNetworks, ...$localNetworks]);
        if ($ipv4Only) {
            $config['address6'] = '';
            $ipv4Dns = array_values(array_filter($config['dns'], static fn (string $ip): bool =>
                filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false));
            if ($config['dns'] !== [] && $ipv4Dns === []) {
                throw new DomainException('Enter an IPv4 DNS resolver for this IPv4-only Proton tunnel.');
            }
            $config['dns'] = $ipv4Dns;
        } elseif (!empty($config['address6']) && self::reserved(explode('/', $config['address6'])[0], $reserved)) {
            throw new DomainException('The Proton IPv6 address overlaps a WireGuard or local network. Choose IPv4 only for this tunnel or use a configuration with a different IPv6 address.');
        }

        if ($config['address'] !== '10.2.0.2/32') {
            if ($previousAddress !== '' && $config['address'] !== $previousAddress) {
                throw new DomainException('The replacement Proton configuration specifies a different tunnel IPv4 address. Keep the current address and matching DNS, or use a fresh Proton configuration with its default address.');
            }
            if (self::reserved(explode('/', $config['address'])[0], $reserved)) {
                throw new DomainException('The IPv4 address in this Proton configuration overlaps a WireGuard or local network. Choose an unused Proton tunnel address and its matching DNS.');
            }
            return $config;
        }

        if ($previousAddress !== '') {
            if (!preg_match('~^10\.(\d{1,3})\.0\.2/32$~D', $previousAddress, $match) ||
                (int)$match[1] < 2 || (int)$match[1] > 255) {
                throw new DomainException('The current Proton tunnel uses a custom IPv4 address. Keep that address and its DNS in the replacement configuration.');
            }
            $slots = [(int)$match[1]];
        } else {
            $slots = range(2, 255);
        }
        $useProtonDns = !$dnsOverride && in_array('10.2.0.1', $config['dns'], true);
        foreach ($slots as $slot) {
            $ip = "10.$slot.0.2";
            $dns = "10.$slot.0.1";
            if (self::reserved($ip, $reserved) || ($useProtonDns && self::reserved($dns, $reserved))) {
                continue;
            }
            $config['address'] = $ip . '/32';
            if ($useProtonDns && $slot !== 2) {
                $config['dns'] = array_values(array_unique(array_map(static fn (string $server): string =>
                    $server === '10.2.0.1' ? $dns : $server, $config['dns'])));
            }
            return $config;
        }
        throw new DomainException($previousAddress !== ''
            ? 'The current Proton tunnel IPv4 address or DNS conflicts with another WireGuard or local network. Resolve the conflict before replacing the credential.'
            : 'No unused Proton tunnel IPv4 address is available. Check your WireGuard and local network ranges.');
    }

    private static function reserved(string $ip, array $networks): bool
    {
        foreach ($networks as $network) {
            if (Policy::contains($network, $ip)) {
                return true;
            }
        }
        return false;
    }
}
