<?php

use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\ProxyCores;

require_once('/usr/local/etc/inc/config.inc');

if (PHP_SAPI !== 'cli' || !function_exists('posix_geteuid') || posix_geteuid() !== 0) {
    exit(77);
}

try {
    $result = Operations::exclusive(function () use ($argv) {
        switch ($argv[1] ?? '') {
            case 'check':
                ProxyCores::refresh();
                break;
            case 'install':
                ProxyCores::install($argv[2] ?? '', $argv[3] ?? null);
                break;
            case 'install-local':
                ProxyCores::installLocal($argv[2] ?? '', $argv[3] ?? '', $argv[4] ?? '', $argv[5] ?? '');
                break;
            case 'rollback':
                ProxyCores::rollback($argv[2] ?? '');
                break;
            case 'status':
                break;
            default:
                throw new DomainException('Use status, check, install CORE [APPROVED_ARCHIVE], install-local CORE VERSION FILE SHA256, or rollback CORE.');
        }
        return ProxyCores::status();
    });
    echo json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT), "\n";
} catch (DomainException $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
} catch (Throwable) {
    fwrite(STDERR, "Blank VPN could not complete the core operation. Check the router log and current core status.\n");
    exit(1);
}
