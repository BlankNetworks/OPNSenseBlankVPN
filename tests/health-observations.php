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

$proxy = ['kind' => 'proxy'];
$retry = Operations::probeObservation([], $proxy, false, false, 201);
expectHealth($retry['health']['reachable'] && !$retry['reload'] &&
    !Operations::probeObservation($retry['health'], $proxy, false, false, 202)['health']['reachable'],
    'Unchecked exits tolerate one failed probe.');

echo "Tunnel health observation fixtures passed.\n";
