<?php

declare(strict_types=1);

use OPNsense\BlankVpn\DeviceIdentity;

foreach (['Policy', 'DeviceIdentity'] as $class) {
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $class . '.php';
}

function assertDeviceIdentity(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$original = ['interface' => 'lan', 'mac' => '02:00:00:00:00:01', 'ip' => '192.168.20.10'];
$moved = array_replace($original, ['ip' => '192.168.20.11']);
$newOwner = array_replace($original, ['mac' => '02:00:00:00:00:02']);
$otherLan = array_replace($moved, ['interface' => 'opt1', 'ip' => '192.168.30.11']);
$tailnet = ['kind' => 'tailnet', 'interface' => 'opt1', 'ip' => '100.100.1.1'];
$index = DeviceIdentity::index([$moved, $newOwner, $otherLan, $moved]);

assertDeviceIdentity(DeviceIdentity::effective($original, $index) === '192.168.20.11',
    'Follow the current reservation, not the original IP even after another device acquired it.');
assertDeviceIdentity(DeviceIdentity::effective($newOwner, $index) === '192.168.20.10',
    'A policy for the new occupant has its own identity binding.');
assertDeviceIdentity(DeviceIdentity::effective($otherLan, $index) === '192.168.30.11',
    'A reservation follows the selected LAN or VLAN only.');
assertDeviceIdentity(DeviceIdentity::effective($original, DeviceIdentity::index([$newOwner, $otherLan])) === null,
    'An unreserved original identity must never reuse its former IP or match on another LAN.');
assertDeviceIdentity(DeviceIdentity::effective($tailnet, $index) === null,
    'Leave Tailscale identities to their native verifier.');

$contested = array_replace($newOwner, ['ip' => $moved['ip']]);
assertDeviceIdentity(DeviceIdentity::reservation('lan', $original['mac'], [$moved, $contested]) === null,
    'Different MACs claiming a single IPv4 invalidate the binding.');
assertDeviceIdentity(DeviceIdentity::reservation('lan', $original['mac'], [$moved, $original]) === null,
    'Multiple configured addresses for the same interface and MAC invalidate the binding.');
assertDeviceIdentity(DeviceIdentity::reservation('lan', '02:00:00:00:AA:01', [
    array_replace($moved, ['mac' => '02:00:00:00:aa:01']),
]) === '192.168.20.11', 'MAC matching is case-insensitive.');
assertDeviceIdentity(DeviceIdentity::index([
    array_replace($original, ['ip' => '2001:db8::1']),
    array_replace($original, ['mac' => 'ff:ff:ff:ff:ff:ff']),
    array_replace($original, ['mac' => '00:00:00:00:00:00']),
    array_replace($original, ['interface' => 'wan']),
]) === [], 'Reject non-IPv4 bindings, invalid MACs and non-LAN interfaces.');

$bindings = DeviceIdentity::lanBindings(['old' => $original, 'new' => $newOwner, 'tailnet' => $tailnet], $index);
assertDeviceIdentity($bindings === ['old' => '192.168.20.11', 'new' => '192.168.20.10'],
    'Batch rendering keeps identities separate when the old address is reassigned.');
assertDeviceIdentity(DeviceIdentity::lanBindings(['one' => $original, 'two' => $moved], $index) ===
    ['one' => null, 'two' => null], 'Duplicate saved policy rows must not race to claim a current address.');

$leaseKey = 'lan/' . $moved['ip'];
$reservations = [$moved, $newOwner, $otherLan];
foreach ([[$newOwner['mac']], [$moved['mac'], $newOwner['mac']], [null], ['malformed MAC'], false,
    ['owner' => $moved['mac']], null] as $claim) {
    assertDeviceIdentity(DeviceIdentity::filterReservations($reservations, [$leaseKey => $claim]) === [$newOwner, $otherLan],
        'A contradictory or malformed lease claim suppresses only the contested reservation.');
}
foreach ([[$moved['mac']], []] as $claim) {
    assertDeviceIdentity(DeviceIdentity::filterReservations($reservations, [$leaseKey => $claim]) === $reservations,
        'A matching or empty lease claim keeps the configured binding.');
}
assertDeviceIdentity(DeviceIdentity::filterReservations($reservations, ['opt1/' . $moved['ip'] => false]) === $reservations,
    'A claim on another interface does not alter this LAN binding.');
assertDeviceIdentity(DeviceIdentity::filterReservations([$moved, $contested], [$leaseKey => [$moved['mac']]]) === [],
    'Filtering must not make a duplicate configured address eligible.');
assertDeviceIdentity(DeviceIdentity::filterReservations([$moved, $original], [
    'lan/' . $original['ip'] => [$newOwner['mac']],
]) === [], 'A lease conflict cannot turn an ambiguous static MAC reservation into a unique binding.');

$observed = DeviceIdentity::combineClaims([
    'arp' => [$leaseKey => [$moved['mac']]], 'kea list leases4' => [$leaseKey => [$newOwner['mac']]],
]);
assertDeviceIdentity(DeviceIdentity::filterReservations($reservations, $observed) === [$newOwner, $otherLan],
    'A matching ARP neighbor does not override a conflicting lease.');
fwrite(STDOUT, "Device identity fixture checks passed.\n");
