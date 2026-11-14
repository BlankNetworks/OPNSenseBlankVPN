<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use ReflectionMethod;
use RuntimeException;

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
}

function proc_open(array $command, array $descriptors, ?array &$pipes)
{
    $destination = $command[4] ?? '';
    if (array_slice($command, 0, 4) !== ['/sbin/route', '-n', 'get', '-inet']) {
        throw new RuntimeException('Unexpected command in WireGuard fixture.');
    }
    RouteFixture::$lookups[] = $destination;
    $output = fopen('php://temp', 'w+');
    fwrite($output, '    interface: ' . RouteFixture::$default . "\n");
    rewind($output);
    $pipes = [1 => $output];
    return fopen('php://temp', 'w+');
}

function proc_close($process): int
{
    fclose($process);
    return 0;
}

$profile = ['interface' => 'wg7', 'identityKey' => 'local-key', 'peerKey' => 'peer-key'];
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
checkWireGuard(WireGuard::probe($profile)['reachable'] === null, 'Avoid an internet probe without a verified local route');

$routeLookup = new ReflectionMethod(WireGuard::class, 'routeLookup');
$underlay = new ReflectionMethod(WireGuard::class, 'checkUnderlay');
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

fwrite(STDOUT, "WireGuard diagnostics tests passed.\n");
