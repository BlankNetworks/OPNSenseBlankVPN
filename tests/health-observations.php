<?php

declare(strict_types=1);

use OPNsense\BlankVpn\Operations;

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Operations.php';

function expectHealth(bool $ok, string $message): void
{
    if (!$ok) {
        throw new RuntimeException($message);
    }
}

$native = ['kind' => 'native', 'address' => '192.0.2.10'];
$known = ['source' => $native['address'], 'reachable' => true, 'probeSucceeded' => true, 'checkedAt' => 100];

$missing = Operations::probeObservation($known, $native, null, true, 200);
expectHealth($missing === ['health' => $known, 'reload' => false, 'failed' => false],
    'A missing probe pin is unverified and cannot turn a healthy tunnel into an outage.');

$down = Operations::probeObservation($known, $native, false, true, 201);
expectHealth($down['health']['reachable'] === false && $down['reload'] && $down['failed'],
    'A verified failure immediately closes the selected protected path.');
$stillDown = Operations::probeObservation($down['health'], $native, false, true, 202);
expectHealth(!$stillDown['health']['reachable'] && !$stillDown['reload'] && !$stillDown['failed'],
    'Continued failure does not trigger repeated firewall reloads and session resets.');
$newSource = Operations::probeObservation($down['health'], ['kind' => 'native', 'address' => '192.0.2.11'], null, true, 203);
expectHealth($newSource === ['health' => ['source' => '192.0.2.11'], 'reload' => true, 'failed' => false],
    'A new source rebuilds the probe pin without carrying forward obsolete health.');

$recovered = Operations::probeObservation($down['health'], $native, true, true, 204);
expectHealth($recovered['health']['reachable'] && $recovered['reload'] && !$recovered['failed'],
    'A verified positive probe reopens the selected tunnel.');

$legacyHealth = ['old-native' => $known, 'old-proxy' => $known, 'verified-native' => $recovered['health'],
    'failed-native' => $down['health']];
expectHealth(($recovered['health']['tunnelVerified'] ?? false) &&
    Operations::discardUnverifiedTunnelProbes($legacyHealth, array_fill_keys(
        ['old-native', 'verified-native', 'failed-native'], true
    )) === array_diff_key($legacyHealth, ['old-native' => true]),
    'Upgrades invalidate old positive tunnel probes without resetting verified results, failures or proxy health.');

$proxy = ['kind' => 'proxy'];
$retry = Operations::probeObservation([], $proxy, false, false, 201);
expectHealth($retry['health']['reachable'] && !$retry['reload'] &&
    !Operations::probeObservation($retry['health'], $proxy, false, false, 202)['health']['reachable'],
    'Unchecked exits tolerate one failed probe.');

$runtimeState = new ReflectionMethod(Operations::class, 'wireGuardRuntimeState');
$managed = ['interface' => 'wg2', 'identityKey' => 'local-key', 'peerKey' => 'expected-peer'];
$runtime = [
    'keys' => ['wg2' => 'local-key'], 'peers' => ['wg2' => ['expected-peer' => '25']],
    'allowed' => ['wg2' => ['expected-peer' => '0.0.0.0/0']]
];
$interfaces = ['wg2' => ['up' => true]];
expectHealth($runtimeState->invoke(null, $managed, $runtime, $interfaces) === 'ready',
    'The expected interface and sole peer are usable.');
expectHealth($runtimeState->invoke(null, $managed, ['keys' => [], 'peers' => []], []) === 'missing',
    'Only a unit absent from both inventories can be recreated safely.');
expectHealth($runtimeState->invoke(null, $managed, ['keys' => [], 'peers' => []], $interfaces) === 'conflict',
    'An existing interface with an unknown identity must not be overwritten.');
expectHealth($runtimeState->invoke(null, $managed, ['keys' => ['wg2' => 'other-key'], 'peers' => []], $interfaces) === 'conflict',
    'A changed identity must not be overwritten.');
expectHealth($runtimeState->invoke(null, $managed, ['keys' => ['wg9' => 'local-key'], 'peers' => []], []) === 'conflict',
    'An identity already live on a different unit must not be duplicated.');
expectHealth($runtimeState->invoke(null, $managed, ['keys' => $runtime['keys'], 'peers' => []], $interfaces) === 'missing',
    'A managed interface that lost its sole peer can be restored.');
$unexpectedPeer = ['keys' => $runtime['keys'], 'peers' => ['wg2' => ['unexpected-peer' => '25']]];
expectHealth($runtimeState->invoke(null, $managed, $unexpectedPeer, $interfaces) === 'conflict',
    'A changed peer must not be overwritten.');
expectHealth($runtimeState->invoke(null, $managed, $runtime, ['wg2' => ['up' => false]]) === 'missing',
    'The owned instance can be reapplied when the kernel interface is down.');

$missingDefault = array_replace($runtime, ['allowed' => ['wg2' => ['expected-peer' => '(none)']]]);
expectHealth($runtimeState->invoke(null, $managed, $missingDefault, $interfaces) === 'missing',
    'The correct peer without the IPv4 default needs its owned configuration restored.');
$dualStack = $managed + ['address6' => 'fd00::2/128'];
expectHealth($runtimeState->invoke(null, $dualStack, $runtime, $interfaces) === 'missing',
    'A dual stack managed peer also requires an IPv6 default.');
$bothDefaults = array_replace($runtime, ['allowed' => ['wg2' => ['expected-peer' => '::/0 0.0.0.0/0']]]);
expectHealth($runtimeState->invoke(null, $dualStack, $bothDefaults, $interfaces) === 'ready',
    'Both defaults are accepted regardless of their reported order.');
expectHealth($runtimeState->invoke(null, $managed, array_replace($runtime, ['allowed' => []]), $interfaces) === 'conflict',
    'Disagreeing kernel peer inventories are not safe to overwrite.');

echo "Tunnel health observation fixtures passed.\n";
