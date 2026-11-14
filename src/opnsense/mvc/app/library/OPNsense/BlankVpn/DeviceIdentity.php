<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

final class DeviceIdentity
{
    /**
     * Index configured DHCP reservations. A reservation is a configuration binding.
     * Runtime PF rules still match IP addresses, and cannot authenticate an Ethernet sender.
     */
    public static function index(array $reservations): array
    {
        $addresses = [];
        $owners = [];
        foreach ($reservations as $row) {
            $interface = (string)($row['interface'] ?? '');
            $mac = self::mac((string)($row['mac'] ?? ''));
            $ip = (string)($row['ip'] ?? '');
            if ($mac === null || !Policy::interfaceId($interface) || !self::ipv4($ip)) {
                continue;
            }
            $owner = $interface . '/' . $mac;
            $addresses[$owner][$ip] = true;
            $owners[$ip][$owner] = true;
        }

        $index = [];
        foreach ($addresses as $owner => $candidates) {
            $ip = array_key_first($candidates);
            if (count($candidates) === 1 && count($owners[$ip]) === 1) {
                $index[$owner] = $ip;
            }
        }
        return $index;
    }

    public static function reservation(string $interface, string $mac, array $reservations): ?string
    {
        return self::effective(['interface' => $interface, 'mac' => $mac], self::index($reservations));
    }

    /**
     * Suppress bindings contradicted by a live DHCP observation, indexed by interface/IP.
     * An absent claim cannot prove ownership, but preserves the configured reservation.
     */
    public static function filterReservations(array $reservations, array $leaseClaims): array
    {
        if ($leaseClaims === []) {
            return $reservations;
        }

        // Resolve configuration ambiguity first. Removing one conflicting row must not
        // make the other row an eligible reservation.
        $index = self::index($reservations);
        $filtered = [];
        foreach ($reservations as $row) {
            $interface = (string)($row['interface'] ?? '');
            $address = self::effective($row, $index);
            if ($address === null || $address !== ($row['ip'] ?? '')) {
                continue;
            }

            $key = $interface . '/' . $address;
            if (array_key_exists($key, $leaseClaims)) {
                $claims = $leaseClaims[$key];
                if (!is_array($claims) || !array_is_list($claims)) {
                    continue;
                }
                $mac = self::mac((string)$row['mac']);
                foreach ($claims as $claim) {
                    if (!is_string($claim) || self::mac($claim) !== $mac) {
                        continue 2;
                    }
                }
            }
            $filtered[] = $row;
        }
        return $filtered;
    }

    /** Combine independent checks without letting a match override evidence of a conflict. */
    public static function combineClaims(array $observations): array
    {
        $claims = [];
        foreach ($observations as $rows) {
            foreach ($rows as $address => $owners) {
                $claims[$address] = array_values(array_unique([...($claims[$address] ?? []), ...$owners]));
            }
        }
        return $claims;
    }

    /** The originally saved address is descriptive and never a fallback for a missing binding. */
    public static function effective(array $assignment, array $index): ?string
    {
        if (!self::isLan($assignment)) {
            return null;
        }
        $interface = (string)($assignment['interface'] ?? '');
        $mac = self::mac((string)($assignment['mac'] ?? ''));
        if ($mac === null || !Policy::interfaceId($interface)) {
            return null;
        }
        return $index[$interface . '/' . $mac] ?? null;
    }

    /** Return LAN assignment IDs with their current IPv4, including null for unresolved rows. */
    public static function lanBindings(array $assignments, array $index): array
    {
        $bindings = [];
        $owners = [];
        foreach ($assignments as $id => $assignment) {
            if (!self::isLan($assignment)) {
                continue;
            }
            $ip = self::effective($assignment, $index);
            $bindings[$id] = $ip;
            if ($ip !== null) {
                $owners[$ip][] = $id;
            }
        }
        foreach ($owners as $ids) {
            if (count($ids) > 1) {
                foreach ($ids as $id) {
                    $bindings[$id] = null;
                }
            }
        }
        return $bindings;
    }

    private static function isLan(array $assignment): bool
    {
        return in_array($assignment['kind'] ?? '', ['', 'lan'], true);
    }

    private static function ipv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false &&
            !in_array($ip, ['0.0.0.0', '255.255.255.255'], true) &&
            !Policy::contains('127.0.0.0/8', $ip) && !Policy::contains('224.0.0.0/4', $ip);
    }

    private static function mac(string $mac): ?string
    {
        $mac = strtolower($mac);
        if (!Policy::validMac($mac) || $mac === '00:00:00:00:00:00' || (hexdec(substr($mac, 0, 2)) & 1)) {
            return null;
        }
        return $mac;
    }
}
