<?php

declare(strict_types=1);

use OPNsense\BlankVpn\WireGuard;

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/WireGuard.php';

function checkWireGuard(bool $condition, string $name): void
{
    if (!$condition) {
        throw new RuntimeException($name);
    }
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

fwrite(STDOUT, "WireGuard diagnostics tests passed.\n");
