<?php

declare(strict_types=1);

use OPNsense\BlankVpn\DeviceBindings;
use OPNsense\BlankVpn\OnDemand;

foreach (['Policy', 'OnDemand', 'DeviceBindings'] as $class) {
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $class . '.php';
}

function check(bool $ok, string $message): void
{
    if (!$ok) {
        throw new RuntimeException($message);
    }
}

$settings = ['enabled' => true, 'coverage' => 'device', 'interfaces' => ['lan', 'tailscale0']];
$base = ['mode' => 'full', 'interface' => 'lan', 'profile' => 'tunnel', 'failure' => 'block'];
$onDemand = fn (array $overrides = [], array $services = []) => OnDemand::selectExits($settings, $overrides ?: [$base], $services);
check($onDemand() === ['tunnel' => true], 'Legacy or omitted On Demand defaults to enabled for eligible scopes.');
check($onDemand([$base + ['onDemand' => '0']]) === [], 'Explicit warm policy retains health checks.');
check($onDemand([$base, $base + ['onDemand' => '0']]) === [], 'Shared always-on consumers keep the exit warm.');
check($onDemand([$base, array_replace($base, ['profile' => 'primary', 'failure' => 'backup', 'backup' => 'tunnel'])]) === [],
    'A backup consumer keeps an otherwise on-demand exit warm.');
check($onDemand([$base], [['profile' => 'tunnel']]) === [], 'Multi-Path consumer keeps the exit warm.');
check($onDemand([array_replace($base, ['failure' => 'wan'])]) === [], 'Explicit WAN fallback retains health checks.');
check($onDemand([array_replace($base, ['interface' => 'opt9'])]) === [], 'Unmanaged interfaces do not determine On Demand.');
check($onDemand([array_replace($base, ['interface' => 'tailscale0'])]) === ['tunnel' => true], 'Eligible tailnet traffic can wake an exit.');
check(OnDemand::selectExits(array_replace($settings, ['coverage' => 'network']), [$base], []) === [],
    'Whole-network modes retain health checks.');

$old = ['a' => '192.168.10.2', 'b' => '192.168.10.3', 'c' => '192.168.10.4'];
$new = ['a' => '192.168.10.6', 'b' => '192.168.10.3', 'd' => '192.168.10.4'];
check(DeviceBindings::changedAddresses($old, $new) === ['192.168.10.2', '192.168.10.6', '192.168.10.4'],
    'A move resets old and new IPv4 states without touching unchanged bindings or duplicate reset addresses.');
check(DeviceBindings::changedAddresses($new, $new) === [], 'Unchanged assignments do not reset states.');
check(DeviceBindings::changedAddresses([], ['a' => 'fd00::2']) === [], 'IPv6 addresses are independent.');
check(DeviceBindings::changedAddresses(['a' => '192.168.10.2'], []) === ['192.168.10.2'],
    'A missing reservation resets the previous IPv4 states.');

echo "On Demand and device binding fixture checks passed.\n";
