<?php

declare(strict_types=1);

namespace OPNsense\Core {
    final class Backend
    {
        public array $calls = [];

        public function __construct(private array $fixtures)
        {
        }

        public function configdpStream(string $action, array $arguments, mixed ...$unused)
        {
            $this->calls[] = [$action, $arguments];
            if (!array_key_exists($action, $this->fixtures)) {
                throw new \RuntimeException('Unexpected action ' . $action);
            }
            if ($this->fixtures[$action] === null) {
                return null;
            }
            if ($this->fixtures[$action] instanceof \Closure) {
                return ($this->fixtures[$action])();
            }
            $stream = fopen('php://temp', 'w+');
            fwrite($stream, json_encode($this->fixtures[$action], JSON_THROW_ON_ERROR) . "\0\0\0");
            rewind($stream);
            return $stream;
        }
    }
}

namespace {
    use OPNsense\BlankVpn\Diagnostics;
    use OPNsense\Core\Backend;

    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Diagnostics.php';
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Policy.php';

    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        if ((error_reporting() & $severity) !== 0) {
            throw new ErrorException($message, 0, $severity, $file, $line);
        }
        return true;
    });

    function check(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    $peers = Diagnostics::tailnetPeers(['BackendState' => 'Running', 'Peer' => [
        ['HostName' => 'Travel iPad', 'Online' => true, 'TailscaleIPs' => ['100.100.1.2', 'fd7a:115c:a1e0::2', '192.168.2.1']],
        ['HostName' => 'localhost', 'DNSName' => 'laptop.example.ts.net.', 'Online' => false, 'TailscaleIPs' => ['100.100.1.3']],
        ['HostName' => 'Unrelated', 'TailscaleIPs' => ['198.51.100.2']],
    ]]);
    check(count($peers) === 2 && $peers[0]['ipv4'] === '100.100.1.2' && $peers[0]['ipv6'] === ['fd7a:115c:a1e0::2'] &&
        $peers[1]['name'] === 'laptop', 'Display only known peers and their actual Tailscale addresses.');

    $node = ['Name' => 'travel-ipad.example.ts.net.', 'Addresses' => [
        '100.100.1.4/32', 'fd7a:115c:a1e0::4/128', '100.100.0.0/16'
    ]];
    $manualPeer = Diagnostics::tailnetPeerFromWhois('100.100.1.4', $node);
    check($manualPeer !== null && $manualPeer['name'] === 'travel-ipad' &&
        $manualPeer['ipv6'] === ['fd7a:115c:a1e0::4'] &&
        Diagnostics::tailnetPeerFromWhois('100.100.1.5', $node) === null,
        'Only verify the requested Tailscale address and its matching peer.');
    $tailnetConfig = new SimpleXMLElement('<opnsense><OPNsense><tailscale><settings><enabled>1</enabled>'
        . '<advertiseExitNode>1</advertiseExitNode><disableSNAT>0</disableSNAT></settings></tailscale></OPNsense></opnsense>');
    $tailnetDiagnostics = new Diagnostics(new Backend([]), $tailnetConfig);
    $status = ['BackendState' => 'Running', 'Version' => '1.104.5', 'TUN' => false];
    $unchecked = $tailnetDiagnostics->nativeTailnetSetup($status);
    check(!$unchecked['ready'] && !$unchecked['disableSnat'] && str_contains($unchecked['reason'], 'Check Disable SNAT'),
        'The setup message must identify the unchecked SNAT option.');
    $tailnetConfig->OPNsense->tailscale->settings->disableSNAT = '1';
    $checked = $tailnetDiagnostics->nativeTailnetSetup($status);
    check(!$checked['ready'] && $checked['disableSnat'] && str_contains($checked['reason'], 'kernel interface'),
        'Saved SNAT setting must be separate from the live kernel status.');

    $config = new SimpleXMLElement(<<<'XML'
        <opnsense>
          <interfaces>
            <lan><if>igc0</if><enable>1</enable><ipaddr>192.168.10.1</ipaddr><subnet>24</subnet></lan>
            <wan><if>igc1</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>
            <opt1><if>vlan0.40</if><enable>1</enable><descr>Guest</descr><ipaddr>192.168.40.1</ipaddr><subnet>24</subnet></opt1>
          </interfaces>
          <OPNsense><Kea><dhcp4>
            <general><enabled>1</enabled><interfaces>lan</interfaces></general>
            <subnets><subnet4 uuid="lan-subnet"><subnet>192.168.10.0/24</subnet></subnet4></subnets>
            <reservations>
              <reservation><subnet>lan-subnet</subnet><ip_address>192.168.10.5</ip_address><hw_address>02:00:00:00:00:01</hw_address><hostname>reserved-host</hostname></reservation>
              <reservation><subnet>lan-subnet</subnet><ip_address>192.168.10.7</ip_address><hw_address>02:00:00:00:00:02</hw_address></reservation>
            </reservations>
          </dhcp4></Kea></OPNsense>
          <dnsmasq>
            <enable>1</enable>
            <dhcp_ranges><interface>opt1</interface><start_addr>192.168.40.10</start_addr><end_addr>192.168.40.40</end_addr></dhcp_ranges>
            <hosts><host>guest-host</host><ip>192.168.40.15</ip><hwaddr>02:00:00:00:00:03</hwaddr></hosts>
          </dnsmasq>
        </opnsense>
        XML);

    $now = time();
    $backend = new Backend([
        'interface list ifconfig' => [
            'igc0' => ['ipv6' => [['ipaddr' => 'fe80::1%igc0', 'subnetbits' => 64]]],
        ],
        'interface list arp' => [
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:01', 'ip' => '192.168.10.5'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:09', 'ip' => '192.168.10.7'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:06', 'ip' => '192.168.10.16'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:06', 'ip' => '192.168.10.18'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:16', 'ip' => '192.168.10.20'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:24', 'ip' => '192.168.10.30'],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:13', 'ip' => '192.168.10.19', 'expired' => true],
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:10', 'ip' => '192.168.10.1'],
            ['intf' => 'igc1', 'mac' => '02:00:00:00:00:11', 'ip' => '203.0.113.1'],
        ],
        'interface list ndp' => [
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:01', 'ip' => 'fe80::5%igc0'],
        ],
        'hostwatch dump_full' => ['source' => 'discovery', 'rows' => [
            ['igc0', '02:00:00:00:00:01', '192.168.10.5', '', '', gmdate('Y-m-d\TH:i:s\Z', $now - 10)],
            ['igc0', '02:00:00:00:00:12', '192.168.10.25', '', '', gmdate('Y-m-d\TH:i:s\Z', $now - 4000)],
        ]],
        'kea list leases4' => ['records' => [
            ['if' => null, 'hwaddr' => '02:00:00:00:00:04', 'address' => '192.168.10.8', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:14', 'address' => '192.168.10.20', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:21', 'address' => '192.168.10.21', 'state' => 1, 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:22', 'address' => '192.168.10.22', 'expire' => 0],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:23', 'address' => '192.168.10.23'],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:24', 'address' => '192.168.10.31', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:25', 'address' => '192.168.10.32', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:25', 'address' => '192.168.10.33', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:06', 'address' => '192.168.10.18', 'expire' => $now + 4000, 'hostname' => 'pitv'],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:05', 'address' => '192.168.10.9', 'expire' => $now - 20],
        ]],
        'dnsmasq list leases' => ['records' => [
            ['if' => 'vlan0.40', 'hwaddr' => '02:00:00:00:00:15', 'address' => '192.168.40.16', 'expire' => 0],
            ['if' => 'igc1', 'hwaddr' => '02:00:00:00:00:17', 'address' => '192.168.40.17', 'expire' => $now + 4000],
            ['if' => 'igc0', 'hwaddr' => '02:00:00:00:00:18', 'address' => '192.168.40.18', 'expire' => $now + 4000],
        ]],
        'filter list states' => ['total_entries' => 102, 'details' => [
            ['id' => '0000000012345678/abcdef01', 'src_addr' => '192.168.10.5', 'src_port' => '10000',
                'dst_addr' => '198.51.100.2', 'dst_port' => '443', 'proto' => 'tcp', 'iface' => 'igc0',
                'direction' => 'out', 'state' => 'ESTABLISHED:ESTABLISHED', 'age' => '00:04:05',
                'bytes' => [321, 4321], 'pkts' => [4, 5], 'route-to' => '10.10.0.2', 'label' => 'blankvpn_device_fixture'],
            ['id' => '0000000012345679/abcdef01', 'src_addr' => '192.168.10.6', 'dst_addr' => '198.51.100.4',
                'nat_addr' => '192.168.10.5'],
        ]],
        'wireguard show' => ['status' => 'ok', 'records' => [
            ['type' => 'interface', 'if' => 'wg4', 'status' => 'up', 'public-key' => 'do-not-return'],
            ['type' => 'peer', 'if' => 'wg4', 'latest-handshake' => $now - 20, 'transfer-rx' => 30, 'transfer-tx' => 50],
            ['type' => 'peer', 'if' => 'wg4', 'latest-handshake' => $now - 400, 'transfer-rx' => 5, 'transfer-tx' => 10],
        ]],
    ]);
    $diagnostics = new Diagnostics($backend, $config);

    check($diagnostics->hasReservation('lan', '192.168.10.5', '02:00:00:00:00:01'), 'Kea reservation');
    check($diagnostics->hasReservation('opt1', '192.168.40.15', '02:00:00:00:00:03'), 'Dnsmasq reservation');
    check(!$diagnostics->hasReservation('wan', '192.168.10.5', '02:00:00:00:00:01'), 'Reservation scope');
    check($backend->calls === [], 'Firewall generation never calls configd for reservations');

    $snapshot = $diagnostics->devices();
    check($snapshot['warnings'] === [] && !$snapshot['truncated'], 'Healthy discovery result');
    $devices = array_column($snapshot['devices'], null, 'id');
    $desktop = $devices['lan-020000000001'];
    check($desktop['online'] && $desktop['stable'] && $desktop['ipv4'] === '192.168.10.5', 'Stable online device');
    check($desktop['ipv6'] === ['fe80::5'] && $desktop['lastSeen'] !== null, 'NDP and Hostwatch');
    check($desktop['name'] === 'reserved-host', 'Reservation hostname');
    check($devices['lan-020000000009']['addressConflict'] && !$devices['lan-020000000009']['stable'],
        'A live IP conflicting with another MAC’s reservation cannot be assigned automatically.');
    check(!isset($devices['lan-020000000002']) && !isset($devices['lan-020000000012']) && !isset($devices['lan-020000000013']),
        'Hide reservation-only, historical and expired neighbors.');
    check($devices['lan-020000000004']['ipv4'] === '192.168.10.8' && !$devices['lan-020000000004']['arpConfirmed'] &&
        !$devices['lan-020000000004']['stable'] && !$devices['opt1-020000000015']['arpConfirmed'] &&
        $devices['opt1-020000000015']['leaseProvider'] === 'Dnsmasq DHCP',
        'Discover a valid Kea lease without an interface and a Dnsmasq lease without ARP.');
    check(!$devices['lan-020000000004']['online'] && !$devices['opt1-020000000015']['online'],
        'A DHCP lease by itself does not indicate recent device activity.');
    check($devices['lan-020000000014']['addressConflict'] && $devices['lan-020000000014']['leaseProvider'] === '' &&
        $devices['lan-020000000016']['addressConflict'] && $devices['lan-020000000025']['addressConflict'],
        'Conflicting DHCP or ARP claims and ambiguous leases are visible but cannot be auto-reserved.');
    check($devices['lan-020000000024']['ipv4'] === '192.168.10.31' &&
        $devices['lan-020000000024']['ipv4Addresses'] === ['192.168.10.31', '192.168.10.30'] &&
        !$devices['lan-020000000024']['arpConfirmed'] && $devices['lan-020000000024']['online'] &&
        $devices['lan-020000000024']['leaseProvider'] === 'Kea DHCPv4',
        'Prefer the current unique DHCP lease over an older ARP address for the same device.');
    foreach (['lan-020000000021', 'lan-020000000022', 'lan-020000000023', 'opt1-020000000017', 'lan-020000000018'] as $key) {
        check(!isset($devices[$key]), 'Reject invalid lease identity or status for ' . $key);
    }
    check($diagnostics->devices(['opt1'])['devices'][0]['interface'] === 'opt1',
        'Prefer selected interfaces when showing network discovery results.');
    check(!isset($devices['lan-020000000005']) && !isset($devices['lan-020000000010'])
        && !isset($devices['wan-020000000011']), 'Expired and non-client devices excluded');
    check($devices['lan-020000000006']['name'] === 'pitv' && $devices['lan-020000000006']['arpConfirmed'] &&
        $devices['lan-020000000006']['ipv4'] === '192.168.10.18' && !$devices['lan-020000000006']['stable'] &&
        $diagnostics->reservationProvider('lan', '192.168.10.18', '02:00:00:00:00:06') === 'Kea DHCPv4',
        'Match a live client to its exact DHCP lease for in-place reservation.');
    check($diagnostics->reservationProvider('lan', '192.168.10.8', '02:00:00:00:00:04') === 'Kea DHCPv4' &&
        $diagnostics->reservationProvider('lan', '192.168.10.18', '02:00:00:00:00:99') === '',
        'Accept an unambiguous native DHCP lease and reject an incorrect MAC.');

    $offlineBackend = new Backend(['interface list ifconfig' => null]);
    $offline = (new Diagnostics($offlineBackend, $config))->devices();
    check(count($offlineBackend->calls) === 1 && $offline['devices'] === [] &&
        in_array('ARP table is unavailable.', $offline['warnings'], true) &&
        in_array('Dnsmasq DHCP lease data is unavailable.', $offline['warnings'], true),
        'When configd is unavailable, avoid reconnecting for each source and retain discovery warnings.');

    [$slowRead, $slowWrite] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    stream_set_timeout($slowRead, 0, 1000);
    $concurrentBackend = new Backend([
        'interface list ifconfig' => static fn () => $slowRead,
        'interface list arp' => [
            ['intf' => 'igc0', 'mac' => '02:00:00:00:00:01', 'ip' => '192.168.10.5'],
        ],
        // Configd can return valid JSON with the wrong shape for a single source.
        'interface list ndp' => ['error' => 'unavailable'],
        'hostwatch dump_full' => static function () use ($slowWrite) {
            fwrite($slowWrite, "[]\0\0\0");
            fclose($slowWrite);
            $response = fopen('php://temp', 'w+');
            fwrite($response, "[]\0\0\0");
            rewind($response);
            return $response;
        },
        'kea list leases4' => ['records' => []],
        'dnsmasq list leases' => ['records' => []],
    ]);
    $concurrent = (new Diagnostics($concurrentBackend, $config))->devices();
    check($concurrent['warnings'] === ['NDP table is unavailable.'] &&
        $concurrent['devices'][0]['ipv4'] === '192.168.10.5' && !is_resource($slowRead),
        'Launch independent reads before waiting on the first source, and preserve partial data and warnings.');

    $sessions = $diagnostics->connections('192.168.10.5');
    check($sessions['truncated'] && $sessions['total'] === 1, 'Bounded, exact endpoint matching');
    check($sessions['connections'][0]['bytes'] === [321, 4321], 'Directional firewall counters');
    check($sessions['connections'][0]['stateId'] === '0000000012345678'
        && $sessions['connections'][0]['creatorId'] === 'abcdef01', 'Native PF state identifiers');

    check($diagnostics->hasRoutedTraffic('192.168.10.5', 'blankvpn_device_fixture') &&
        !$diagnostics->hasRoutedTraffic('192.168.10.5', 'blankvpn_other_rule') &&
        !$diagnostics->hasRoutedTraffic('192.168.10.6', 'blankvpn_device_fixture'),
        'A device probe requires both the saved address and the policy rule label.');

    $tunnels = $diagnostics->tunnels();
    check($tunnels['wg4']['handshakeRecent'] && $tunnels['wg4']['reachability'] === 'unverified', 'Handshake and path status');
    check($tunnels['wg4']['receivedBytes'] === 35 && $tunnels['wg4']['sentBytes'] === 60, 'WireGuard transfer totals');
    check(!str_contains(json_encode($tunnels, JSON_THROW_ON_ERROR), 'do-not-return'), 'Keys absent from diagnostics');

    echo "Diagnostics fixture checks passed.\n";
}
