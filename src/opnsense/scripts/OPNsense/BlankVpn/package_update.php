#!/usr/local/bin/php
<?php

declare(strict_types=1);

use OPNsense\BlankVpn\PackageUpdate;
use OPNsense\BlankVpn\Policy;

require_once '/usr/local/opnsense/mvc/app/library/OPNsense/BlankVpn/Policy.php';
require_once '/usr/local/opnsense/mvc/app/library/OPNsense/BlankVpn/PackageUpdate.php';

if (!PackageUpdate::runningAsRoot()) {
    exit(77);
}
umask(0077);

$action = $argv[1] ?? '';
$background = in_array($action, ['dispatch', 'install'], true);
try {
    $value = match ($action) {
        'enable' => PackageUpdate::enable(),
        'check' => PackageUpdate::check(),
        'apply' => PackageUpdate::enqueue($argv[2] ?? null),
        'dispatch' => PackageUpdate::dispatch($argv[2] ?? ''),
        'install' => PackageUpdate::install($argv[2] ?? ''),
        default => throw new DomainException('Unknown package update operation.'),
    };
    if (!$background) {
        echo json_encode(['ok' => true] + $value, JSON_THROW_ON_ERROR) . PHP_EOL;
    }
} catch (DomainException | RuntimeException $error) {
    if ($background) {
        syslog(LOG_ERR, 'Blank VPN package update: ' . $error->getMessage());
        exit(1);
    }
    echo json_encode(['ok' => false, 'error' => $error->getMessage()], JSON_THROW_ON_ERROR) . PHP_EOL;
} catch (Throwable $error) {
    syslog(LOG_ERR, 'Blank VPN package update failed: ' . $error::class);
    if ($background) {
        exit(1);
    }
    echo json_encode(['ok' => false, 'error' => 'The package update operation could not be completed.'], JSON_THROW_ON_ERROR) . PHP_EOL;
}
