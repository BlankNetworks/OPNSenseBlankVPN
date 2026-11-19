<?php

declare(strict_types=1);

use OPNsense\BlankVpn\ChinaRules;

require_once dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/BlankVpn/Policy.php';
require_once dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/BlankVpn/ChinaRules.php';

$method = new ReflectionMethod(ChinaRules::class, 'validateSnapshotData');
$method->setAccessible(true);
$data = [
    'domains' => ['example.cn'],
    'networks' => ['1.0.0.0/24', '2001:4860::/32'],
    'unsupportedGeoRules' => ['full:example.cn'],
];
$manifest = ['domains' => 1, 'ipv4' => 1, 'ipv6' => 1, 'unsupportedGeoRules' => 1];
$method->invoke(null, $data, $manifest);

$invalid = $data;
$invalid['networks'][0] = '1.0.0.1/24';
try {
    $method->invoke(null, $invalid, $manifest);
    throw new RuntimeException('Invalid noncanonical network was accepted.');
} catch (ReflectionException $error) {
    throw $error;
} catch (Throwable $error) {
    if ($error instanceof RuntimeException && $error->getMessage() === 'Invalid noncanonical network was accepted.') {
        throw $error;
    }
}

$invalid = $data;
$invalid['domains'][0] = '*.example.cn';
try {
    $method->invoke(null, $invalid, $manifest);
    throw new RuntimeException('Invalid wildcard domain was accepted.');
} catch (ReflectionException $error) {
    throw $error;
} catch (Throwable $error) {
    if ($error instanceof RuntimeException && $error->getMessage() === 'Invalid wildcard domain was accepted.') {
        throw $error;
    }
}

echo "China Rules snapshot validation passed.\n";
