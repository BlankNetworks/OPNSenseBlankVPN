<?php

declare(strict_types=1);

use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\RoutingBackup;
use OPNsense\BlankVpn\SmartRouting;

$source = __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/';
require $source . 'Policy.php';
require $source . 'SmartRouting.php';
require $source . 'RoutingBackup.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectFail(callable $work, string $expected): void
{
    try {
        $work();
    } catch (DomainException $error) {
        check(str_contains($error->getMessage(), $expected), 'Unexpected validation failure: ' . $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected validation failure: ' . $expected);
}

$key = str_repeat('a', 64);
$exit = '169d069e-d9c0-4224-9c62-45b789ad7fa1';
$assignment = 'f2804e4a-588f-45ae-844d-2833498069ce';
$service = '9511230c-1e2e-4fc5-8a44-6053d61a3a1f';
$policy = [
    'settings' => [
        'enabled' => '1', 'interfaces' => 'lan,opt2', 'coverage' => 'device',
        'networkMode' => 'disabled', 'networkProfile' => '', 'networkKillSwitch' => '',
        'strictInterfaces' => 'opt2', 'smartInterfaces' => 'lan', 'smartAssignedOnly' => '0',
        'tailscaleInterfaces' => '', 'localNetworks' => '192.168.2.0/24',
    ],
    'mullvadCatalog' => ['worldwide' => '0', 'countries' => 'CA', 'cities' => 'ca-yyz'],
    'interfaces' => ['lan' => str_repeat('b', 64), 'opt2' => str_repeat('c', 64)],
    'assignments' => [[
        'id' => $assignment, 'ip' => '192.168.2.100', 'interface' => 'lan', 'mac' => '02:00:00:00:00:11',
        'ipv6' => '', 'paused' => '0', 'kind' => 'lan', 'mode' => 'full', 'label' => 'Office iPad',
        'profile' => $exit, 'backup' => '', 'killSwitch' => '', 'failure' => 'block',
        'onDemand' => '0', 'bindMac' => '1',
    ]],
    'services' => [['id' => $service, 'name' => 'Country suffix', 'domains' => ['.cn'], 'profile' => $exit]],
    'routes' => [$exit => str_repeat('d', 64)],
];

$backup = RoutingBackup::envelope($policy, $key);
$json = json_encode($backup, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
check(RoutingBackup::decode($json, $key) === $policy, 'Routing settings must round-trip across JSON.');
check($backup['assignments'][0]['onDemand'] === '0' && $backup['assignments'][0]['bindMac'] === '1',
    'New policy controls must retain their original values.');
check(!str_contains($json, $key) && !isset($backup['ownership']), 'The backup must not expose local authentication material.');
expectFail(fn () => RoutingBackup::decode($json, str_repeat('e', 64)), 'original Blank VPN installation');
expectFail(fn () => RoutingBackup::decode(substr($json, 0, -1), $key), 'not valid');
expectFail(fn () => RoutingBackup::decode(str_repeat('x', RoutingBackup::MAX_BYTES + 1), $key), 'up to 2 MiB');
expectFail(fn () => RoutingBackup::decode(str_replace('Office iPad', 'Different device', $json), $key), 'has changed');

$corrupt = $policy;
$corrupt['settings']['hostname'] = 'unapproved.home.arpa';
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'unsupported fields');
$corrupt = $policy;
$corrupt['assignments'][0]['privateKey'] = 'unapproved';
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'unsupported fields');
$corrupt = $policy;
$corrupt['assignments'][] = ['id' => '9cc929a4-8905-414f-94c3-68f5d49cdef1'] + $policy['assignments'][0];
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'duplicate devices');
$corrupt = $policy;
$corrupt['routes'] = [];
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'valid references');
$corrupt = $policy;
$corrupt['interfaces'] = ['opt2' => str_repeat('c', 64)];
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'valid references');
$corrupt = $policy;
$corrupt['services'][0]['domains'] = ['192.168.2.1'];
expectFail(fn () => RoutingBackup::envelope($corrupt, $key), 'DNS domain');

$legacy = $policy;
unset($legacy['assignments'][0]['onDemand'], $legacy['assignments'][0]['bindMac']);
$result = RoutingBackup::envelope($legacy, $key)['assignments'][0];
check($result['onDemand'] === '1' && $result['bindMac'] === '0', 'Legacy policies must receive the model defaults.');
check(Policy::mode($result) === 'full' && SmartRouting::domains(implode(',', ['.cn'])) === ['.cn'],
    'Backup validation must match native route and domain normalization.');

echo "Routing backup fixtures passed.\n";
