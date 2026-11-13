<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use InvalidArgumentException;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use RuntimeException;
use SimpleXMLElement;

final class Diagnostics
{
    private const DEVICE_LIMIT = 512;
    private const SOURCE_LIMIT = 4096;
    private const STATE_LIMIT = 100;
    private const MAX_BACKEND_RESPONSE = 8 * 1024 * 1024;
    private const FRESH_NEIGHBOR_SECONDS = 300;
    private const RECENT_HANDSHAKE_SECONDS = 180;

    private Backend $backend;
    private SimpleXMLElement $config;

    public function __construct(?Backend $backend = null, ?SimpleXMLElement $config = null)
    {
        $this->backend = $backend ?? new Backend();
        $this->config = $config ?? Config::getInstance()->object();
    }

    public function devices(): array
    {
        $warnings = [];
        $truncated = false;
        $interfaces = $this->localInterfaces($warnings);
        $observations = [];
        $now = time();
        $leases = [];

        $append = function (array $record) use (&$observations, $interfaces): void {
            $ip = self::ip((string)($record['ip'] ?? ''));
            $mac = self::mac((string)($record['mac'] ?? ''));
            $device = (string)($record['device'] ?? '');
            if ($ip === null || $mac === null || !isset($interfaces[$device])) {
                return;
            }
            if (in_array($ip, $interfaces[$device]['ownAddresses'], true) ||
                (!str_contains($ip, ':') && self::interfaceForIp($ip, [$device => $interfaces[$device]], []) === null)) {
                return;
            }
            $record['ip'] = $ip;
            $record['mac'] = $mac;
            $observations[] = $record;
        };

        foreach (['arp' => 'ARP', 'ndp' => 'NDP'] as $action => $label) {
            $rows = $this->read('interface list ' . $action, ['json']);
            if ($rows === null || !array_is_list($rows)) {
                $warnings[] = $label . ' table is unavailable.';
                continue;
            }
            foreach ($this->bounded($rows, $truncated) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $append([
                    'device' => $row['intf'] ?? '', 'mac' => $row['mac'] ?? '', 'ip' => $row['ip'] ?? '',
                    'name' => $row['hostname'] ?? '', 'source' => $label,
                    'current' => empty($row['expired']) && empty($row['permanent']) &&
                        !in_array($row['type'] ?? '', ['published', 'proxy'], true),
                ]);
            }
        }

        $hostwatch = $this->read('hostwatch dump_full');
        if (($hostwatch['source'] ?? null) === 'discovery' && is_array($hostwatch['rows'] ?? null)) {
            foreach ($this->bounded($hostwatch['rows'], $truncated) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $seen = self::timestamp($row[5] ?? null, $now);
                $append([
                    'device' => $row[0] ?? '', 'mac' => $row[1] ?? '', 'ip' => $row[2] ?? '',
                    'source' => 'Hostwatch', 'seen' => $seen,
                    'current' => $seen !== null && $now - $seen <= self::FRESH_NEIGHBOR_SECONDS,
                ]);
            }
        } elseif ($hostwatch === null) {
            $warnings[] = 'Hostwatch history is unavailable.';
        }

        $kea4 = $this->config->OPNsense->Kea->dhcp4 ?? null;
        $kea6 = $this->config->OPNsense->Kea->dhcp6 ?? null;
        $dnsmasq = $this->config->dnsmasq ?? null;
        $leaseSources = [];
        if ((string)($kea4->general->enabled ?? '') === '1') {
            $leaseSources['kea list leases4'] = 'Kea DHCPv4';
        }
        if ((string)($kea6->general->enabled ?? '') === '1') {
            $leaseSources['kea list leases6'] = 'Kea DHCPv6';
        }
        if ((string)($dnsmasq->enable ?? '') === '1') {
            $leaseSources['dnsmasq list leases'] = 'Dnsmasq DHCP';
        }
        foreach ($leaseSources as $action => $source) {
            $leaseData = $this->read($action);
            if (!is_array($leaseData['records'] ?? null)) {
                // The native Kea action has no output when it has no leases.
                if ($source === 'Dnsmasq DHCP') {
                    $warnings[] = 'Dnsmasq DHCP lease data is unavailable.';
                }
                continue;
            }
            foreach ($this->bounded($leaseData['records'], $truncated) as $lease) {
                if (!is_array($lease) || (int)($lease['state'] ?? 0) !== 0) {
                    continue;
                }
                $expiry = (int)($lease['expire'] ?? 0);
                if ($expiry > 0 && $expiry <= $now) {
                    continue;
                }
                // Prefix-delegation leases describe routed networks rather than host addresses.
                if (($lease['type'] ?? '') === 'IA_PD' || (int)($lease['type'] ?? -1) === 2) {
                    continue;
                }
                $address = self::ip((string)($lease['address'] ?? ''));
                $hardware = self::mac((string)($lease['hwaddr'] ?? ''));
                $port = $interfaces[(string)($lease['if'] ?? '')]['id'] ?? null;
                if ($port !== null && $address !== null && !str_contains($address, ':') && $hardware !== null) {
                    $leases[$port . '/' . $address][$source . '/' . $hardware] = ['source' => $source, 'mac' => $hardware];
                }
                $append([
                    'device' => $lease['if'] ?? '', 'mac' => $lease['hwaddr'] ?? '',
                    'ip' => $lease['address'] ?? '', 'name' => $lease['hostname'] ?? '',
                    'source' => $source, 'current' => true,
                ]);
            }
        }

        foreach ($this->bounded($this->readReservations($interfaces), $truncated) as $reservation) {
            $append($reservation + ['source' => 'DHCP reservation']);
        }

        $snapshot = $this->combine($observations, $interfaces, $this->reservations(), $warnings, $truncated, $now);
        foreach ($snapshot['devices'] as &$device) {
            $claims = $leases[$device['interface'] . '/' . $device['ipv4']] ?? [];
            $lease = count($claims) === 1 ? reset($claims) : null;
            $device['leaseProvider'] = !$snapshot['truncated'] && !$device['addressConflict'] &&
                ($lease['mac'] ?? null) === $device['mac'] ? $lease['source'] : '';
        }
        unset($device);
        return $snapshot;
    }

    public function tailnetDevices(): array
    {
        $output = Resolver::command(['/usr/bin/timeout', '2', '/usr/local/bin/tailscale', 'status', '--json'], false);
        $status = json_decode($output, true);
        return is_array($status) ? self::tailnetPeers($status) : [];
    }

    public static function tailnetPeers(array $status): array
    {
        if (($status['BackendState'] ?? '') !== 'Running' || !is_array($status['Peer'] ?? null)) {
            return [];
        }
        $peers = [];
        foreach (array_slice($status['Peer'], 0, self::DEVICE_LIMIT) as $peer) {
            if (!is_array($peer) || !is_array($peer['TailscaleIPs'] ?? null)) {
                continue;
            }
            $addresses = array_values(array_filter(array_map(
                static fn ($ip) => is_string($ip) ? self::ip($ip) : null, $peer['TailscaleIPs']
            )));
            $v4 = current(array_filter($addresses, static fn ($ip) => Policy::tailnetAddress($ip))) ?: '';
            $v6 = current(array_filter($addresses, static fn ($ip) => Policy::tailnetAddress($ip, true))) ?: '';
            if ($v4 === '' && $v6 === '') {
                continue;
            }
            $host = self::label($peer['HostName'] ?? '');
            $dnsName = self::label(explode('.', (string)($peer['DNSName'] ?? ''), 2)[0]);
            $name = $host === null || strtolower($host) === 'localhost' ? ($dnsName ?? $host) : $host;
            $peers[] = ['kind' => 'tailnet', 'name' => $name, 'ipv4' => $v4, 'ipv6' => $v6 === '' ? [] : [$v6],
                'online' => ($peer['Online'] ?? false) === true];
        }
        usort($peers, static fn ($a, $b) => [!$a['online'], $a['name'] ?? '', $a['ipv4']] <=>
            [!$b['online'], $b['name'] ?? '', $b['ipv4']]);
        return $peers;
    }

    public function probeLanNeighbors(array $selected): array
    {
        $warnings = [];
        $commands = [];
        $ports = array_intersect_key(Policy::availableInterfaces(), array_fill_keys($selected, true));
        $targetsByInterface = [];
        foreach ($this->localInterfaces($warnings, false) as $interface) {
            if (!isset($ports[$interface['id']])) {
                continue;
            }
            foreach ($interface['prefixes'] as $ip => $bits) {
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $bits < 24 || $bits > 30) {
                    continue;
                }
                $source = ip2long($ip);
                $size = 1 << (32 - $bits);
                $first = $source & (-$size);
                for ($address = $first + 1; $address < $first + $size - 1; $address++) {
                    if (!in_array(long2ip($address), $interface['ownAddresses'], true)) {
                        $targetsByInterface[$interface['id']][] = ['/sbin/ping', '-n', '-r', '-c', '1', '-t', '1', '-S', $ip, long2ip($address)];
                    }
                }
            }
        }
        for ($index = 0; $index < 254 && count($commands) < 256; $index++) {
            foreach ($targetsByInterface as $targets) {
                if (isset($targets[$index])) {
                    $commands[] = $targets[$index];
                    if (count($commands) === 256) {
                        break;
                    }
                }
            }
        }
        $descriptors = array_fill(0, 3, ['file', '/dev/null', 'w']);
        $descriptors[0][2] = 'r';
        $probed = 0;
        foreach (array_chunk($commands, 24) as $batch) {
            $processes = [];
            foreach ($batch as $command) {
                $process = @proc_open($command, $descriptors, $pipes);
                if (is_resource($process)) {
                    $processes[] = $process;
                }
            }
            foreach ($processes as $process) {
                proc_close($process);
                $probed++;
            }
        }
        return ['probed' => $probed];
    }

    public function reservations(): array
    {
        // The firewall renderer may call this while configd is applying a reload.
        $warnings = [];
        $interfaces = $this->localInterfaces($warnings, false);
        $claims = [];
        $addresses = [];
        foreach ($this->readReservations($interfaces) as $record) {
            $mac = self::mac($record['mac']);
            $ip = $record['ip'];
            $interface = $interfaces[$record['device']]['id'];
            if ($mac === null || in_array($ip, $interfaces[$record['device']]['ownAddresses'], true)) {
                continue;
            }
            $owner = $interface . '/' . $mac;
            $claims[$ip][$owner] = ['interface' => $interface, 'ip' => $ip, 'mac' => $mac];
            $addresses[$owner][$ip] = true;
        }

        $result = [];
        foreach ($claims as $owners) {
            if (count($owners) !== 1) {
                continue;
            }
            $owner = array_key_first($owners);
            if (count($addresses[$owner]) === 1) {
                $result[] = $owners[$owner];
            }
        }
        return $result;
    }

    public function reservationProvider(string $interface, string $ip, string $mac): string
    {
        foreach ($this->devices()['devices'] as $device) {
            if ($device['interface'] === $interface && $device['ipv4'] === $ip && $device['mac'] === $mac) {
                return $device['leaseProvider'];
            }
        }
        return '';
    }

    public function reserveDevice(string $provider, string $interface, string $ip, string $mac): void
    {
        $warnings = [];
        $interfaces = $this->localInterfaces($warnings, false);
        $device = self::interfaceForIp($ip, $interfaces, [$interface]);
        if ($device === null || in_array($ip, $interfaces[$device]['ownAddresses'], true)) {
            throw new \DomainException('This address is outside the selected LAN.');
        }
        foreach ($this->readReservations($interfaces) as $entry) {
            if ($entry['ip'] === $ip || ($entry['device'] === $device && self::mac($entry['mac']) === $mac)) {
                throw new \DomainException('An existing DHCP reservation conflicts with this device. Review it in OPNsense.');
            }
        }

        if ($provider === 'Dnsmasq DHCP') {
            $model = new \OPNsense\Dnsmasq\Dnsmasq();
            foreach ($this->config->dnsmasq->hosts as $entry) {
                if (in_array($ip, self::csv((string)$entry->ip), true) ||
                    in_array($mac, self::csv(strtolower((string)$entry->hwaddr)), true)) {
                    throw new \DomainException('An existing Dnsmasq host entry matches this device. Review it before reserving its IP.');
                }
            }
            $node = $model->hosts->add();
            $node->ip = $ip;
            $node->hwaddr = $mac;
            $node->descr = 'Blank VPN device rule';
        } elseif ($provider === 'Kea DHCPv4') {
            $model = new \OPNsense\Kea\KeaDhcpv4();
            $subnets = [];
            foreach ($this->config->OPNsense->Kea->dhcp4->subnets->subnet4 as $subnet) {
                $network = Policy::cidr((string)$subnet->subnet);
                if ($network !== null && Policy::contains($network, $ip)) {
                    $subnets[] = (string)$subnet['uuid'];
                }
            }
            if (count($subnets) !== 1 || (string)$model->general->manual_config === '1' ||
                !in_array($interface, self::csv((string)$model->general->interfaces), true)) {
                throw new \DomainException('Create a reservation in Kea for the device’s LAN subnet, then save the rule.');
            }
            $node = $model->reservations->reservation->add();
            $node->subnet = $subnets[0];
            $node->ip_address = $ip;
            $node->hw_address = $mac;
        } else {
            throw new \DomainException('Create a DHCP reservation for this device in OPNsense, then save the rule.');
        }
        if (count($model->performValidation()) !== 0) {
            throw new \DomainException('OPNsense rejected this DHCP reservation. Review the address and MAC in DHCP settings.');
        }
        $model->serializeToConfig();
        if (!(new self())->hasReservation($interface, $ip, $mac)) {
            throw new \DomainException('OPNsense could not confirm the reservation on this LAN.');
        }
    }

    public function hasReservation(string $interface, string $ip, string $mac): bool
    {
        $ip = self::ip($ip);
        $mac = self::mac($mac);
        if ($ip === null || $mac === null) {
            return false;
        }
        return in_array(['interface' => $interface, 'ip' => $ip, 'mac' => $mac], $this->reservations(), true);
    }

    public function connections(string $ip): array
    {
        $ip = self::ip($ip);
        if ($ip === null || self::within($ip, 'fe80::', 10)) {
            throw new InvalidArgumentException('Choose an IPv4 or non-link-local IPv6 address.');
        }

        $states = $this->read('filter list states', [$ip, (string)self::STATE_LIMIT, '0', '', '']);
        if (!is_array($states['details'] ?? null)) {
            throw new RuntimeException('Firewall sessions are unavailable. Try again.');
        }
        $connections = [];
        foreach (array_slice($states['details'], 0, self::STATE_LIMIT) as $state) {
            if (!is_array($state)) {
                continue;
            }
            $source = self::ip((string)($state['src_addr'] ?? ''));
            $destination = self::ip((string)($state['dst_addr'] ?? ''));
            if ($ip !== $source && $ip !== $destination) {
                continue;
            }
            $stateKey = (string)($state['id'] ?? '');
            $validKey = preg_match('/\A([0-9a-f]{16})\/([0-9a-f]{8})\z/i', $stateKey, $parts);
            $connections[] = [
                'id' => $validKey ? $stateKey : null,
                'stateId' => $validKey ? $parts[1] : null,
                'creatorId' => $validKey ? $parts[2] : null,
                'source' => $source,
                'sourcePort' => self::port($state['src_port'] ?? null),
                'destination' => $destination,
                'destinationPort' => self::port($state['dst_port'] ?? null),
                'protocol' => self::label($state['proto'] ?? ''),
                'state' => self::label($state['state'] ?? ''),
                'age' => self::label($state['age'] ?? ''),
                'bytes' => self::counterPair($state['bytes'] ?? null),
                'packets' => self::counterPair($state['pkts'] ?? null),
                'interface' => self::label($state['iface'] ?? ''),
                'direction' => self::label($state['direction'] ?? ''),
                'natAddress' => self::ip((string)($state['nat_addr'] ?? '')),
                'routeTo' => self::ip((string)($state['route-to'] ?? '')),
            ];
        }

        return [
            'connections' => $connections,
            'total' => count($connections),
            'truncated' => (int)($states['total_entries'] ?? 0) > self::STATE_LIMIT,
            'asOf' => gmdate('c'),
        ];
    }

    public function tunnels(): array
    {
        $snapshot = $this->read('wireguard show');
        if (($snapshot['status'] ?? null) !== 'ok' || !is_array($snapshot['records'] ?? null)) {
            throw new RuntimeException('WireGuard runtime status is unavailable.');
        }

        $tunnels = [];
        $now = time();
        foreach ($snapshot['records'] as $record) {
            if (!is_array($record) || ($record['type'] ?? null) !== 'interface') {
                continue;
            }
            $interface = (string)($record['if'] ?? '');
            if (!preg_match('/\Awg[0-9]+\z/', $interface)) {
                continue;
            }
            $tunnels[$interface] = [
                'interface' => $interface,
                'status' => ($record['status'] ?? null) === 'up' ? 'up' : 'down',
                'latestHandshake' => null,
                'handshakeRecent' => false,
                'receivedBytes' => 0,
                'sentBytes' => 0,
                'peerCount' => 0,
                'reachability' => 'unverified',
            ];
        }
        foreach ($snapshot['records'] as $record) {
            if (!is_array($record) || ($record['type'] ?? null) !== 'peer') {
                continue;
            }
            $interface = (string)($record['if'] ?? '');
            if (!isset($tunnels[$interface])) {
                continue;
            }
            $status = &$tunnels[$interface];
            $status['peerCount']++;
            $status['receivedBytes'] += max(0, (int)($record['transfer-rx'] ?? 0));
            $status['sentBytes'] += max(0, (int)($record['transfer-tx'] ?? 0));
            $handshake = (int)($record['latest-handshake'] ?? 0);
            if ($handshake > ($status['latestHandshake'] ?? 0) && $handshake <= $now) {
                $status['latestHandshake'] = $handshake;
                $status['handshakeRecent'] = $status['status'] === 'up'
                    && $now - $handshake <= self::RECENT_HANDSHAKE_SECONDS;
            }
            unset($status);
        }

        return $tunnels;
    }

    private function localInterfaces(array &$warnings, bool $useRuntime = true): array
    {
        $runtime = $useRuntime ? $this->read('interface list ifconfig') : [];
        if ($runtime === null) {
            $warnings[] = 'Runtime interface addresses are unavailable. Static interface configuration was used.';
            $runtime = [];
        }
        $uplinks = ['wan' => true];
        foreach ([$this->config->OPNsense->Gateways ?? null, $this->config->gateways ?? null] as $gateways) {
            foreach (($gateways->gateway_item ?? []) as $gateway) {
                if ((string)$gateway->disabled !== '1' && (string)$gateway->defaultgw === '1') {
                    $uplinks[(string)$gateway->interface] = true;
                }
            }
        }

        $interfaces = [];
        foreach (($this->config->interfaces?->children() ?? []) as $id => $node) {
            $device = (string)$node->if;
            if (
                (string)$node->enable !== '1' || isset($uplinks[$id])
                || !preg_match('/\A(?:lan|opt[0-9]+)\z/', $id)
                || !preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,30}\z/', $device)
                || preg_match('/\A(?:wg|ovpn[cs]|pppoe|tun|tap|lo)[0-9]+\z/', $device)
                || in_array((string)$node->ipaddr, ['dhcp', 'pppoe', 'pptp', 'l2tp'], true)
                || (string)$node->gateway !== ''
                || (string)$node->gatewayv6 !== ''
            ) {
                continue;
            }
            $addresses = [];
            foreach (['ipv4' => ['ipaddr', 'subnet'], 'ipv6' => ['ipaddrv6', 'subnetv6']] as $family => [$ip, $bits]) {
                $rows = $runtime[$device][$family] ?? [];
                $rows[] = ['ipaddr' => (string)$node->{$ip}, 'subnetbits' => (string)$node->{$bits}];
                foreach ($rows as $row) {
                    $address = self::ip((string)($row['ipaddr'] ?? ''));
                    $prefix = filter_var($row['subnetbits'] ?? null, FILTER_VALIDATE_INT);
                    if ($address !== null && $prefix !== false && $prefix > 0 && $prefix <= ($family === 'ipv4' ? 32 : 128)) {
                        $addresses[$address] = $prefix;
                    }
                }
            }
            $interfaces[$device] = [
                'id' => $id,
                'name' => self::label((string)$node->descr) ?: strtoupper($id),
                'prefixes' => $addresses,
                'ownAddresses' => array_keys($addresses),
            ];
        }

        return $interfaces;
    }

    private function readReservations(array $interfaces): array
    {
        $records = [];
        $kea = $this->config->OPNsense->Kea->dhcp4 ?? null;
        if ((string)($kea->general->enabled ?? '') === '1' && (string)($kea->general->manual_config ?? '') !== '1') {
            $listening = self::csv((string)($kea->general->interfaces ?? ''));
            $subnets = [];
            foreach (($kea->subnets->subnet4 ?? []) as $subnet) {
                $subnets[(string)$subnet['uuid']] = explode('/', (string)$subnet->subnet, 2);
            }
            foreach (($kea->reservations->reservation ?? []) as $entry) {
                $ip = self::ip((string)$entry->ip_address);
                $network = $subnets[(string)$entry->subnet] ?? [];
                if ($ip === null || str_contains($ip, ':') || count($network) !== 2
                    || !self::within($ip, $network[0], (int)$network[1])) {
                    continue;
                }
                $device = self::interfaceForIp($ip, $interfaces, $listening);
                if ($device !== null) {
                    $records[] = ['ip' => $ip, 'mac' => (string)$entry->hw_address, 'device' => $device,
                        'name' => (string)$entry->hostname, 'reserved' => true];
                }
            }
        }

        $dnsmasq = $this->config->dnsmasq ?? null;
        if ((string)($dnsmasq->enable ?? '') === '1') {
            $excluded = self::csv((string)($dnsmasq->dhcp->no_interface ?? ''));
            $ranges = [];
            foreach ($dnsmasq->dhcp_ranges as $range) {
                $start = self::ip((string)$range->start_addr);
                if ($start === null || str_contains($start, ':')) {
                    continue;
                }
                $listener = (string)$range->interface;
                if ($listener === '') {
                    $detected = self::interfaceForIp($start, $interfaces, []);
                    $listener = $detected !== null ? $interfaces[$detected]['id'] : '';
                }
                if ($listener !== '') {
                    $ranges[] = $listener;
                }
            }
            $listening = array_values(array_diff($ranges, $excluded));
            foreach ($dnsmasq->hosts as $entry) {
                $macs = self::csv((string)$entry->hwaddr);
                if (count($macs) !== 1 || !$listening || (string)$entry->ignore === '1') {
                    continue;
                }
                foreach (self::csv((string)$entry->ip) as $ip) {
                    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        continue;
                    }
                    $device = self::interfaceForIp($ip, $interfaces, $listening);
                    if ($device !== null) {
                        $records[] = ['ip' => $ip, 'mac' => $macs[0], 'device' => $device,
                            'name' => (string)$entry->host, 'reserved' => true];
                    }
                }
            }
        }

        foreach ($interfaces as $device => $interface) {
            $dhcpd = $this->config->dhcpd->{$interface['id']} ?? null;
            if (!isset($dhcpd->enable) || (string)$dhcpd->enable === '0') {
                continue;
            }
            foreach ($dhcpd->staticmap as $entry) {
                $ip = self::ip((string)$entry->ipaddr);
                if ($ip !== null && !str_contains($ip, ':')
                    && self::interfaceForIp($ip, $interfaces, [$interface['id']]) === $device) {
                    $records[] = ['ip' => $ip, 'mac' => (string)$entry->mac, 'device' => $device,
                        'name' => (string)$entry->hostname, 'reserved' => true];
                }
            }
        }

        return $records;
    }

    private function combine(
        array $observations,
        array $interfaces,
        array $reservations,
        array $warnings,
        bool $truncated,
        int $now
    ): array {
        $devices = [];
        $claims = [];
        $configuredOwners = [];
        foreach ($reservations as $reservation) {
            $configuredOwners[$reservation['ip']] = $reservation['interface'] . '/' . $reservation['mac'];
        }
        foreach ($observations as $record) {
            $interface = $interfaces[$record['device']];
            $id = $interface['id'] . '-' . str_replace(':', '', $record['mac']);
            $devices[$id] ??= [
                'id' => $id,
                'mac' => $record['mac'],
                'interface' => $interface['id'],
                'interfaceDevice' => $record['device'],
                'interfaceName' => $interface['name'],
                'name' => null,
                'lastSeen' => null,
                'sources' => [],
                'records' => [],
            ];
            $device = &$devices[$id];
            $device['records'][] = $record;
            $device['sources'][$record['source']] = true;
            $device['lastSeen'] = max($device['lastSeen'] ?? 0, $record['seen'] ?? 0) ?: null;
            $name = self::label($record['name'] ?? '');
            if ($name !== null && ($device['name'] === null || !empty($record['reserved']))) {
                $device['name'] = $name;
            }
            if (!empty($record['current']) || !empty($record['reserved'])) {
                $claims[$record['ip']][$id] = true;
            }
            unset($device);
        }

        foreach ($devices as $id => &$device) {
            $ipv4 = [];
            $ipv6 = [];
            $reserved = [];
            $liveIpv4 = [];
            foreach ($device['records'] as $record) {
                $ip = $record['ip'];
                $current = !empty($record['current']);
                if (str_contains($ip, ':')) {
                    if ($current) {
                        $ipv6[$ip] = true;
                    }
                } elseif (!empty($record['reserved'])) {
                    $reserved[$ip] = true;
                } elseif ($current) {
                    $ipv4[$ip] = true;
                    if ($record['source'] === 'ARP') {
                        $liveIpv4[$ip] = true;
                    }
                }
            }
            if ($liveIpv4 === []) {
                unset($devices[$id]);
                continue;
            }
            $reservedIp = count($reserved) === 1 ? array_key_first($reserved) : null;
            $ip = array_key_first($liveIpv4);
            $conflict = count($reserved) > 1 || ($ip !== null && count($claims[$ip] ?? []) > 1)
                || ($reservedIp !== null && $ipv4 && (count($ipv4) > 1 || !isset($ipv4[$reservedIp])));
            $device['ipv4'] = $ip;
            $device['ipv4Addresses'] = array_keys($liveIpv4);
            $device['ipv6'] = array_keys($ipv6);
            $device['reservationIpv4'] = $reservedIp;
            $device['addressConflict'] = $conflict;
            $device['stable'] = $reservedIp !== null && !$conflict && !$truncated
                && ($configuredOwners[$reservedIp] ?? '') === $device['interface'] . '/' . $device['mac'];
            $device['sources'] = array_keys($device['sources']);
            $device['lastSeen'] = $device['lastSeen'] === null ? null : gmdate('c', $device['lastSeen']);
            unset($device['records']);
        }
        unset($device);

        $devices = array_values($devices);
        usort($devices, static fn ($a, $b) => [$a['interface'], ip2long($a['ipv4'])]
            <=> [$b['interface'], ip2long($b['ipv4'])]);

        return [
            'devices' => array_slice($devices, 0, self::DEVICE_LIMIT),
            'warnings' => $warnings,
            'truncated' => $truncated || count($devices) > self::DEVICE_LIMIT,
            'asOf' => gmdate('c', $now),
        ];
    }

    private function read(string $action, array $arguments = []): ?array
    {
        $stream = $this->backend->configdpStream($action, $arguments, 1, false, 4, 1);
        if (!is_resource($stream)) {
            return null;
        }
        $response = '';
        $deadline = microtime(true) + 4;
        $terminator = "\0\0\0";
        try {
            while (microtime(true) < $deadline && strlen($response) <= self::MAX_BACKEND_RESPONSE) {
                $previousLength = strlen($response);
                $chunk = fread($stream, 65536);
                if ($chunk === false || ($chunk === '' && feof($stream))) {
                    return null;
                }
                $response .= $chunk;
                $end = strpos($response, $terminator, max(0, $previousLength - 2));
                if ($end !== false && $end <= self::MAX_BACKEND_RESPONSE) {
                    $decoded = json_decode(substr($response, 0, $end), true, 64);
                    return is_array($decoded) ? $decoded : null;
                }
            }
        } finally {
            fclose($stream);
        }
        return null;
    }

    private function bounded(array $rows, bool &$truncated): array
    {
        if (count($rows) > self::SOURCE_LIMIT) {
            $truncated = true;
            return array_slice($rows, 0, self::SOURCE_LIMIT);
        }
        return $rows;
    }

    private static function interfaceForIp(string $ip, array $interfaces, array $allowed): ?string
    {
        $matches = [];
        foreach ($interfaces as $device => $interface) {
            if ($allowed && !in_array($interface['id'], $allowed, true)) {
                continue;
            }
            foreach ($interface['prefixes'] as $address => $bits) {
                if (self::within($ip, $address, $bits)) {
                    $matches[$device] = max($matches[$device] ?? 0, $bits);
                }
            }
        }
        if (!$matches) {
            return null;
        }
        $best = array_keys($matches, max($matches), true);
        return count($best) === 1 ? $best[0] : null;
    }

    private static function within(string $ip, string $address, int $bits): bool
    {
        $candidate = @inet_pton($ip);
        $network = @inet_pton($address);
        if ($candidate === false || $network === false || strlen($candidate) !== strlen($network)
            || $bits < 0 || $bits > strlen($network) * 8) {
            return false;
        }
        $whole = intdiv($bits, 8);
        $remaining = $bits % 8;
        if (substr($candidate, 0, $whole) !== substr($network, 0, $whole)) {
            return false;
        }
        return $remaining === 0 || ((ord($candidate[$whole]) ^ ord($network[$whole])) >> (8 - $remaining)) === 0;
    }

    private static function ip(string $ip): ?string
    {
        if (str_contains($ip, ':')) {
            $ip = explode('%', $ip, 2)[0];
        }
        $packed = @inet_pton($ip);
        if ($packed === false || $ip === '0.0.0.0' || self::within($ip, '224.0.0.0', 4)
            || self::within($ip, 'ff00::', 8) || $packed === str_repeat("\0", 16)) {
            return null;
        }
        return inet_ntop($packed) ?: null;
    }

    private static function mac(string $mac): ?string
    {
        $mac = strtolower($mac);
        if (!preg_match('/\A[0-9a-f]{2}(?::[0-9a-f]{2}){5}\z/', $mac)
            || (hexdec(substr($mac, 0, 2)) & 1) || $mac === '00:00:00:00:00:00') {
            return null;
        }
        return $mac;
    }

    private static function label(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $value = trim(preg_replace('/\p{C}+/u', '', $value) ?? '');
        if (in_array($value, ['', '?', '*'], true)) {
            return null;
        }
        return preg_match('/\A.{1,120}/us', $value, $match) ? $match[0] : null;
    }

    private static function timestamp(mixed $value, int $now): ?int
    {
        if (!is_string($value) || !preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\z/', $value)) {
            return null;
        }
        $timestamp = strtotime($value);
        return $timestamp !== false && $timestamp > 0 && $timestamp <= $now ? $timestamp : null;
    }

    private static function port(mixed $value): ?int
    {
        $port = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        return $port === false ? null : $port;
    }

    private static function counterPair(mixed $value): ?array
    {
        if (!is_array($value) || !array_is_list($value) || count($value) !== 2) {
            return null;
        }
        if (!is_int($value[0]) || !is_int($value[1]) || $value[0] < 0 || $value[1] < 0) {
            return null;
        }
        return $value;
    }

    private static function csv(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn ($item) => $item !== ''));
    }
}
