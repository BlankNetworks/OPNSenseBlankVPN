<?php
declare(strict_types=1);
require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/VpnProviders.php';
use OPNsense\BlankVpn\VpnProviders;
$p = new VpnProviders();
foreach (['free', 'plus'] as $tier) {
    $servers = $p->protonServers($tier);
    $countries = [];
    foreach ($servers as $server) {
        if (isset($countries[$server['country']])) {
            continue;
        }
        try {
            $p->protonRelay($server);
            $countries[$server['country']] = true;
        } catch (RuntimeException $e) {
            continue;
        }
        if (count($countries) >= 3) {
            break;
        }
    }
    echo 'Live Proton ', $tier, ' gateways: ', count($servers), '; catalog and public DNS confirmed for ', implode(', ', array_keys($countries)), PHP_EOL;
    if (count($countries) < 3) {
        throw new RuntimeException('Could not confirm three Proton countries');
    }
}
