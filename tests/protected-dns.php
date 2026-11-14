<?php

declare(strict_types=1);

use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\ProxyRuntime;
use OPNsense\BlankVpn\Resolver;
use OPNsense\BlankVpn\SmartRouting;

foreach (['Policy', 'ProxyRuntime', 'Resolver', 'SmartRouting'] as $class) {
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $class . '.php';
}

function checkDnsPlan(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$plan = new ReflectionMethod(Resolver::class, 'listenerPlan');
$settings = [
    'enabled' => true, 'coverage' => 'network', 'networkMode' => 'full_multi',
    'networkKillSwitch' => true, 'networkProfile' => 'base', 'interfaces' => ['lan'],
    'smartInterfaces' => ['lan'], 'deviceMultiInterfaces' => [], 'strictInterfaces' => [],
    'smartAssignedOnly' => false,
];
$base = ['dnsPort' => 46651, 'address' => '10.64.0.9/32', 'dns' => ['10.64.0.1']];
$proxy = ProxyRuntime::route('video', 0, str_repeat('a', 64), 'Video', 'mihomo', 'socks5');
$profiles = ['base' => $base, 'video' => $proxy];
$routed = ['id' => 'video', 'profile' => 'video', 'domains' => ['video.example.net']];
$bypass = ['id' => 'direct', 'profile' => SmartRouting::BYPASS, 'domains' => ['example.net']];
$lists = ['video' => $routed, 'direct' => $bypass];
$wan = ['9.9.9.9@192.0.2.9'];
$makePlan = static fn (array $settings, array $assignments = [], bool $fallback = false): array =>
    $plan->invoke(null, $settings, 'blankvpn.home.arpa', '192.0.2.1', $assignments, $profiles, $lists, $wan, $fallback, false);

$combinedPort = Resolver::protectedCombinedPort($base);
$protectedPort = Resolver::protectedPort($base);
$protectedMulti = Resolver::PROTECTED_MULTI_PORT;
$ports = [$base['dnsPort'], Resolver::combinedPort($base), $combinedPort, $protectedPort, $protectedMulti, $proxy['proxyDns']];
checkDnsPlan(count(array_unique($ports)) === count($ports) &&
    Resolver::allowedPort($combinedPort) && Resolver::allowedPort($protectedPort) && Resolver::allowedPort($protectedMulti) &&
    Resolver::protectedPort([]) === 0 && Resolver::protectedCombinedPort([]) === 0,
    'Protected DNS listeners must use distinct valid ports.');

$wholeCombined = $makePlan($settings);
checkDnsPlan(!isset($wholeCombined[Resolver::FALLBACK_PORT]) && !isset($wholeCombined[Resolver::SERVICE_PORT]) &&
    str_contains($wholeCombined[$combinedPort], "\nserver=10.64.0.1@10.64.0.9\n") &&
    str_contains($wholeCombined[$combinedPort], "\nserver=/video.example.net/127.0.0.1#{$protectedMulti}\n") &&
    !str_contains(implode('', $wholeCombined), '9.9.9.9') &&
    !str_contains(implode('', $wholeCombined), '127.0.0.1#53'),
    'Protected combined coverage only resolves over the base tunnel or service listener.');
checkDnsPlan(str_contains($wholeCombined[$protectedMulti],
    "\nipset=/video.example.net/" . SmartRouting::table($routed) . "\n") &&
    str_contains($wholeCombined[$protectedMulti], "\nserver=/video.example.net/127.0.0.1#{$proxy['proxyDns']}\n") &&
    !preg_match('/^server=[^\/]/m', $wholeCombined[$protectedMulti]),
    'Protected Multi-Path learns the routed suffix and has no general resolver.');
checkDnsPlan(str_contains($wholeCombined[Resolver::LOCAL_PORT], "\nlisten-address=127.0.0.1,::1\n") &&
    str_contains($wholeCombined[Resolver::LOCAL_PORT], "\nlog-async=16\n") &&
    !str_contains($wholeCombined[Resolver::LOCAL_PORT], "\nserver="),
    'During an outage the local-only resolver accepts both address families with no upstream.');

$wholeMulti = $makePlan(array_replace($settings, ['networkMode' => 'multi']));
checkDnsPlan(isset($wholeMulti[$protectedMulti]) && !isset($wholeMulti[SmartRouting::PORT]) &&
    !str_contains(implode('', $wholeMulti), '9.9.9.9'),
    'Protected Whole-Network Multi-Path cannot use general WAN DNS.');

$wholeFull = $makePlan(array_replace($settings, ['networkMode' => 'full']));
checkDnsPlan(str_contains($wholeFull[$protectedPort], "\nlisten-address=127.0.0.1,::1\n") &&
    str_contains($wholeFull[$protectedPort], "\nserver=10.64.0.1@10.64.0.9\n") &&
    !str_contains(implode('', $wholeFull), '9.9.9.9'),
    'Protected single-tunnel DNS never receives Bypass upstreams.');
$wholeProxy = $makePlan(array_replace($settings, ['networkMode' => 'full', 'networkProfile' => 'video']));
checkDnsPlan(str_contains($wholeProxy[Resolver::protectedPort($proxy)],
    "\nserver=127.0.0.1#{$proxy['proxyDns']}\n") &&
    !str_contains(implode('', $wholeProxy), '9.9.9.9'),
    'A protected proxy base uses only that proxy’s DNS listener.');

$verifyProfiles = new ReflectionMethod(Resolver::class, 'verifiedDnsProfiles');
$dnsMarker = Policy::marker('dns_out', 'base10.64.0.1');
$dnsRules = [
    $dnsMarker => ['action' => 'pass', 'gateway' => 'wg3', 'source' => '10.64.0.9'],
    $dnsMarker . '_block' => ['action' => 'block', 'source' => '10.64.0.9'],
];
$dnsProfiles = ['base' => $base + ['interface' => 'wg3']] + $profiles;
checkDnsPlan($verifyProfiles->invoke(null, $dnsProfiles, $dnsRules)['base']['dns'] === ['10.64.0.1'],
    'A native DNS server requires the installed tunnel route and source-specific guard.');
$wrongRoute = $dnsRules;
$wrongRoute[$dnsMarker]['gateway'] = 'igc0';
checkDnsPlan($verifyProfiles->invoke(null, $dnsProfiles, $wrongRoute)['base']['dns'] === [] &&
    $verifyProfiles->invoke(null, $dnsProfiles, [$dnsMarker => $dnsRules[$dnsMarker]])['base']['dns'] === [],
    'A native DNS server is suppressed if its guard is missing or the egress interface changed.');
$dnsProfiles['base']['disabled'] = true;
checkDnsPlan($verifyProfiles->invoke(null, $dnsProfiles, $dnsRules)['base']['dns'] === [],
    'A disabled tunnel never contributes DNS upstreams, even if old rules remain.');
$disabledProxy = $verifyProfiles->invoke(null, ['video' => $proxy + ['disabled' => true]], [])['video'];
$profileUpstreams = new ReflectionMethod(Resolver::class, 'profileUpstreams');
checkDnsPlan($profileUpstreams->invoke(null, $disabledProxy) === [],
    'A disabled proxy renders no malformed loopback upstream.');

$deviceSettings = array_replace($settings, ['coverage' => 'device']);
$assignments = [
    ['interface' => 'lan', 'profile' => 'base', 'mode' => 'full', 'killSwitch' => '1', 'failure' => 'block'],
    ['interface' => 'lan', 'profile' => 'base', 'mode' => 'full', 'killSwitch' => '0', 'failure' => 'wan'],
    ['interface' => 'lan', 'profile' => 'base', 'mode' => 'full_multi', 'failure' => 'block'],
    ['interface' => 'lan', 'profile' => '', 'mode' => 'multi', 'killSwitch' => '1', 'failure' => 'block'],
];
$devices = $makePlan($deviceSettings, $assignments);
checkDnsPlan(str_contains($devices[$base['dnsPort']], 'server=/example.net/9.9.9.9@192.0.2.9') &&
    str_contains($devices[SmartRouting::PORT], "\nserver=127.0.0.1#53\n") &&
    !str_contains($devices[$protectedPort] . $devices[$combinedPort] . $devices[$protectedMulti], '9.9.9.9') &&
    str_contains($devices[$protectedMulti], 'server=/video.example.net/'),
    'Protected and unprotected devices on the same profile keep separate DNS paths, including overlapping lists.');

$unchecked = $makePlan(array_replace($settings, ['networkKillSwitch' => false]), fallback: true);
checkDnsPlan(str_contains($unchecked[Resolver::FALLBACK_PORT], "\nserver=9.9.9.9@192.0.2.9\n") &&
    !isset($unchecked[$combinedPort]), 'Unchecked Whole-Network coverage can retain explicit WAN DNS fallback.');

$table = SmartRouting::table($routed);
$other = 'bvs_' . str_repeat('a', 24);
$anchor = 'bvs_' . str_repeat('b', 24);
$bypassTable = SmartRouting::bypassTable([$bypass]);
$parseStats = new ReflectionMethod(SmartRouting::class, 'parseLearnedTableStats');
$stats = $parseStats->invoke(null, "-pa-r--\t{$table}\n\tAddresses:   34285\n" .
    "-pa----\t{$other}\n\tAddresses:   45\n" .
    "-pa----\t{$anchor}\ttest-anchor\n\tAddresses:   9\n" .
    "-pa--h-\t{$bypassTable}\n\tAddresses:   0\n" .
    "-pa----\tcustom_table\n\tAddresses:   17\n");
checkDnsPlan($stats === [
    $table => ['count' => 34285, 'referenced' => true],
    $other => ['count' => 45, 'referenced' => false],
    $bypassTable => ['count' => 0, 'referenced' => true],
], 'Read counts without dumping addresses, excluding tables under PF anchors and non-plugin tables.');
$orphans = new ReflectionMethod(SmartRouting::class, 'orphanLearnedTables');
checkDnsPlan($orphans->invoke(null, $stats, []) === [$other => true] &&
    $orphans->invoke(null, $stats, [$other => true]) === [],
    'Cleanup only considers unreferenced learned tables absent from the current DNS plan.');

foreach (['192.0.2.1,-f', '192.0.2.1,::1', str_repeat('192.0.2.1,', 128) . '192.0.2.1'] as $badInput) {
    try {
        SmartRouting::testLearnedAddresses($table, $badInput);
        throw new RuntimeException('Untrusted PF membership input was accepted.');
    } catch (InvalidArgumentException) {
    }
}

echo "Protected routing DNS fixtures passed.\n";
