<?php

declare(strict_types=1);

use OPNsense\BlankVpn\ChinaRules;
use OPNsense\BlankVpn\Policy;

require_once dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/BlankVpn/Policy.php';
require_once dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/BlankVpn/ChinaRules.php';

$repository = dirname(__DIR__);
$output = $repository . '/data/china-rules';
$temporary = sys_get_temp_dir() . '/blankvpn-china-rules-' . bin2hex(random_bytes(8));

function writeAtomic(string $path, string $contents): void
{
    $directory = dirname($path);
    $temporary = tempnam($directory, '.china-rules-publish-');
    if ($temporary === false) {
        throw new RuntimeException('Could not create a temporary China Rules publish file.');
    }
    try {
        if (file_put_contents($temporary, $contents) !== strlen($contents) || !rename($temporary, $path)) {
            throw new RuntimeException('Could not write the China Rules publish file.');
        }
    } finally {
        if (is_file($temporary)) {
            @unlink($temporary);
        }
    }
}

try {
    if (!mkdir($temporary, 0700, true)) {
        throw new RuntimeException('Could not create the temporary China Rules build directory.');
    }
    $status = ChinaRules::buildSnapshot(
        null,
        static fn (string $url): string => ChinaRules::fetchSource($url),
        $temporary
    );
    $snapshotPath = $temporary . '/' . $status['file'];
    $snapshot = file_get_contents($snapshotPath);
    if (!is_string($snapshot) || strlen($snapshot) !== $status['bytes'] ||
        !hash_equals($status['artifactSha256'], hash('sha256', $snapshot))) {
        throw new RuntimeException('The generated China Rules snapshot failed its checksum check.');
    }
    unset($status['file']);
    $manifest = ['format' => 1] + $status;
    $manifestJson = json_encode($manifest, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    writeAtomic($output . '/current.json.gz', $snapshot);
    writeAtomic($output . '/manifest.json', $manifestJson);
    fwrite(STDOUT, sprintf(
        "Published snapshot: %s domains, %s IPv4, %s IPv6; next scheduled refresh %s UTC\n",
        number_format($status['domains']), number_format($status['ipv4']), number_format($status['ipv6']),
        gmdate('Y-m-d H:i', $status['nextUpdateAt'])
    ));
} catch (Throwable $error) {
    fwrite(STDERR, 'China Rules snapshot was not published: ' . $error->getMessage() . "\n");
    exit(1);
} finally {
    foreach (glob($temporary . '/*') ?: [] as $path) {
        if (is_file($path) && !is_link($path)) {
            @unlink($path);
        }
    }
    if (is_dir($temporary) && !is_link($temporary)) {
        @rmdir($temporary);
    }
}
