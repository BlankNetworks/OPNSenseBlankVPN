<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use ReflectionMethod;
use RuntimeException;

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Policy.php';
require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/WireGuard.php';

function checkWireGuard(bool $condition, string $name): void
{
    if (!$condition) {
        throw new RuntimeException($name);
    }
}

final class RouteFixture
{
    public static string $default = 'igc0';
    public static array $lookups = [];
    public static array $routes = [];
}

function proc_open(array $command, array $descriptors, ?array &$pipes)
{
    $destination = $command[4] ?? '';
    if (array_slice($command, 0, 4) !== ['/sbin/route', '-n', 'get', '-inet']) {
        throw new RuntimeException('Unexpected command in WireGuard fixture.');
    }
    RouteFixture::$lookups[] = $destination;
    $output = fopen('php://temp', 'w+');
    fwrite($output, '    interface: ' . (RouteFixture::$routes[$destination] ?? RouteFixture::$default) . "\n");
    rewind($output);
    $pipes = [1 => $output];
    return fopen('php://temp', 'w+');
}

function proc_close($process): int
{
    fclose($process);
    return 0;
}

final class WireGuardBackendFixture
{
    public static array $records = [];
    public static array $applies = [];

    public function configdpRun(string $action, array $arguments): string
    {
        if (!in_array([$action, $arguments], [['template reload', ['OPNsense/Wireguard']], ['wireguard configure', []]], true)) {
            throw new RuntimeException('Unexpected WireGuard apply operation.');
        }
        self::$applies[] = [$action, $arguments];
        return 'OK';
    }

    public function configdRun(string $action, bool $raiseOnFailure, int $timeout): string
    {
        if ($action !== 'wireguard show') {
            throw new RuntimeException('Unexpected configd action in WireGuard fixture.');
        }
        return json_encode(['records' => self::$records], JSON_THROW_ON_ERROR);
    }
}

class_alias(WireGuardBackendFixture::class, 'OPNsense\Core\Backend');

$profile = ['interface' => 'wg7', 'identityKey' => 'local-key', 'peerKey' => 'peer-key', 'address' => '10.130.65.41/32'];
$now = time();
$records = [
    ['if' => 'wg9', 'type' => 'interface', 'public-key' => 'local-key', 'status' => 'up'],
    ['if' => 'wg7', 'type' => 'interface', 'public-key' => 'local-key', 'status' => 'up'],
    ['if' => 'wg7', 'type' => 'peer', 'public-key' => 'other-key', 'latest-handshake' => $now],
    ['if' => 'wg7', 'type' => 'peer', 'public-key' => 'peer-key', 'latest-handshake' => $now - 10,
        'transfer-rx' => 4096, 'transfer-tx' => 8192, 'endpoint' => '198.51.100.9:51820'],
];

$status = WireGuard::status($profile, $records);
checkWireGuard($status['available'] && $status['peerPresent'], 'Find the exact native interface and peer');
checkWireGuard($status['handshake'] === $now - 10 && $status['status'] === 'recent handshake', 'Read the owned peer handshake');
checkWireGuard($status['received'] === 4096 && $status['sent'] === 8192, 'Preserve the actual tunnel counters');

$records[3]['latest-handshake'] = $now - 360;
checkWireGuard(WireGuard::status($profile, $records)['status'] === 'stale handshake', 'Distinguish a stale handshake');
$records[3]['latest-handshake'] = $now + 360;
checkWireGuard(WireGuard::status($profile, $records)['status'] === 'stale handshake', 'Reject a future handshake');
$records[3]['latest-handshake'] = 0;
checkWireGuard(WireGuard::status($profile, $records)['status'] === 'awaiting handshake', 'Distinguish a missing handshake');

$records[1]['public-key'] = 'foreign-local-key';
checkWireGuard(WireGuard::status($profile, $records)['status'] === 'unavailable', 'A reused device name is insufficient');
checkWireGuard(WireGuard::probe($profile)['reachable'] === null, 'An unreadable runtime remains unverified.');

$records[1]['public-key'] = 'local-key';
$records[3]['latest-handshake'] = $now;
WireGuardBackendFixture::$records = $records;
checkWireGuard(WireGuard::probe($profile)['reachable'] === null, 'Avoid an internet probe without a verified local route.');
WireGuardBackendFixture::$records[3]['latest-handshake'] = 0;
$failed = WireGuard::probe($profile + ['port' => 53]);
checkWireGuard($failed['reachable'] === false && str_contains($failed['detail'], 'no recent WireGuard handshake on UDP 53'),
    'A readable owned peer without a handshake invalidates a positive health reading even with no safe probe route.');

$probeState = new ReflectionMethod(WireGuard::class, 'probeStateConfirmed');
$marker = Policy::marker('probe', 'fixture' . Policy::PROBE_IP);
$flow = [
    'label' => $marker, 'direction' => 'out', 'proto' => 'tcp', 'src_addr' => '10.130.65.41',
    'src_port' => '41443', 'dst_addr' => Policy::PROBE_IP, 'dst_port' => '443',
    'route-to' => '0.0.0.0@wg7', 'nat_addr' => null, 'pkts' => [5, 4],
];
$confirmed = static fn (array $state): bool =>
    $probeState->invoke(null, [$state], '10.130.65.41', 41443, Policy::PROBE_IP, 'wg7', $marker);
checkWireGuard($confirmed($flow), 'A bidirectional exact probe flow through the intended tunnel proves reachability.');
checkWireGuard(!$confirmed(array_replace($flow, ['src_addr' => '192.0.2.10', 'nat_addr' => '10.130.65.41'])),
    'A source-bound probe that succeeds only via WAN NAT is never green.');
foreach ([
    ['label' => 'native_default'],
    ['route-to' => '0.0.0.0@wg70'],
    ['route-to' => '192.0.2.1@igc0'],
    ['src_port' => '41444'],
    ['dst_addr' => '8.8.8.8'],
    ['dst_port' => '853'],
    ['pkts' => [5, 0]],
] as $invalid) {
    checkWireGuard(!$confirmed(array_replace($flow, $invalid)),
        'Missing or different flow evidence must fail: ' . json_encode($invalid, JSON_THROW_ON_ERROR));
}

$routeLookup = new ReflectionMethod(WireGuard::class, 'routeLookup');
$underlay = new ReflectionMethod(WireGuard::class, 'checkUnderlay');
RouteFixture::$routes = ['default' => 'igc2', '198.51.100.77' => 'igc2', '10.141.89.206' => 'lo0'];
$underlay->invoke(null, '198.51.100.77');
checkWireGuard(RouteFixture::$lookups === ['default', '198.51.100.77'] &&
    RouteFixture::$routes['10.141.89.206'] === 'lo0',
    'A relay endpoint on the active WAN is accepted even when the reused tunnel address is already local on lo0.');
RouteFixture::$lookups = [];
RouteFixture::$routes = [];
$first = $routeLookup->invoke(null);
for ($index = 1; $index <= 32; $index++) {
    $underlay->invoke(null, '192.0.2.' . $index, $first);
}
$underlay->invoke(null, '192.0.2.1', $first);
checkWireGuard(count(RouteFixture::$lookups) === 33 && $first('default') === 'igc0',
    'One dashboard batch must look up the default once and each distinct endpoint once.');
RouteFixture::$default = 'igc1';
$second = $routeLookup->invoke(null);
$underlay->invoke(null, '192.0.2.1', $second);
checkWireGuard(count(RouteFixture::$lookups) === 35 && $second('default') === 'igc1',
    'The next dashboard batch must see a new WAN route.');

WireGuardBackendFixture::$records = [['type' => 'interface', 'if' => 'wg99']];
WireGuard::applyRemovals([['interface' => 'wg1'], ['interface' => 'wg2']]);
checkWireGuard(count(WireGuardBackendFixture::$applies) === 2,
    'A batch of retired tunnels must render and configure WireGuard once, retaining unrelated devices.');
WireGuardBackendFixture::$records[] = ['type' => 'interface', 'if' => 'wg2'];
try {
    WireGuard::applyRemovals([['interface' => 'wg1'], ['interface' => 'wg2']]);
    throw new RuntimeException('The second retired interface was not checked.');
} catch (RuntimeException $error) {
    checkWireGuard(str_contains($error->getMessage(), 'still present'),
        'A failed retirement anywhere in the batch must fail apply so the transaction can roll back.');
}

fwrite(STDOUT, "WireGuard diagnostics tests passed.\n");
