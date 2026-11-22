<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class ProxyCores
{
    public const BASE = [
        'mihomo' => '1.19.34', 'tun2socks' => '2.7.0', 'xray' => '26.11.9', 'sing-box' => '1.14.4'
    ];
    private const REPO = 'BlankNetworks/OPNSenseBlankVPN';
    private const RESERVE = 64 * 1024 * 1024;
    private const MAX_CATALOG = 32768;
    private const MODE_FILE = '/usr/local/share/blankvpn/core-mode';
    private const SYSTEM_PACKAGES = [
        'mihomo' => 'mihomo', 'tun2socks' => 'tun2socks', 'xray' => 'xray-core', 'sing-box' => 'sing-box'
    ];

    public static function distributionMode(?string $path = null): string
    {
        $path ??= self::MODE_FILE;
        if (!is_file($path) || is_link($path)) {
            return 'blank-release';
        }
        $mode = @file_get_contents($path, false, null, 0, 64);
        return is_string($mode) && trim($mode) === 'opnsense-packages' ? 'opnsense-packages' : 'blank-release';
    }

    public static function usesSystemPackages(): bool
    {
        return self::distributionMode() === 'opnsense-packages';
    }

    private static function requireBlankReleaseMode(): void
    {
        if (self::usesSystemPackages()) {
            throw new DomainException('Install and update proxy cores from the OPNsense Firmware package catalog.');
        }
    }

    private static function version(string $version): bool
    {
        return preg_match('/^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$/D', $version) === 1;
    }

    private static function digest(string $value): bool
    {
        return preg_match('/^[0-9a-f]{64}$/D', $value) === 1;
    }

    public static function architecture(): string
    {
        return match (php_uname('m')) {
            'amd64', 'x86_64' => 'amd64',
            'aarch64', 'arm64' => 'aarch64',
            default => throw new DomainException('The proxy cores require FreeBSD amd64 or aarch64.')
        };
    }

    private static function architectureSuffix(): string
    {
        return self::architecture() === 'aarch64' ? '-aarch64' : '';
    }

    private static function directory(): string
    {
        return Policy::STATE_DIR . '/cores' . self::architectureSuffix();
    }

    private static function stateFile(): string
    {
        return 'core-versions' . self::architectureSuffix() . '.json';
    }

    private static function catalogFile(): string
    {
        return 'core-catalog' . self::architectureSuffix() . '.json';
    }

    public static function releaseUrl(string $core, array $row, ?string $arch = null): string
    {
        $arch ??= self::architecture();
        if (!in_array($arch, ['amd64', 'aarch64'], true)) {
            throw new DomainException('The core catalog architecture is unsupported.');
        }
        $arm = $arch === 'aarch64';
        $version = $row['version'] ?? '';
        $sha = $row['sha256'] ?? '';
        if (!isset(self::BASE[$core]) || !is_string($version) || !self::version($version) ||
            !is_string($sha) || !self::digest($sha)) {
            throw new DomainException('The core catalog contains invalid release metadata.');
        }
        if (($row['source'] ?? '') === 'blanknetworks') {
            $repository = self::REPO;
            $tag = "cores-{$core}-v{$version}" . ($arm ? "-aarch64" : "");
            $extension = in_array($core, ['tun2socks', 'xray'], true) ? 'zip' : 'gz';
            $asset = "{$core}-{$version}-freebsd-{$arch}.{$extension}";
        } else {
            throw new DomainException('Core downloads must use a Blank Networks release.');
        }
        if (($row['tag'] ?? null) !== $tag || ($row['asset'] ?? null) !== $asset) {
            throw new DomainException('The core catalog specifies an unexpected asset.');
        }
        return "https://github.com/{$repository}/releases/download/{$tag}/{$asset}";
    }

    public static function parseCatalog(string $content, ?string $arch = null): array
    {
        $data = strlen($content) <= self::MAX_CATALOG ? json_decode($content, true, 8) : null;
        if (($data['schema'] ?? null) !== 1 || !is_array($data['cores'] ?? null) || $data['cores'] === []) {
            throw new DomainException('The core catalog is invalid.');
        }
        $cores = [];
        foreach ($data['cores'] as $core => $row) {
            if (!is_string($core) || !is_array($row)) {
                throw new DomainException('The core catalog is invalid.');
            }
            self::releaseUrl($core, $row, $arch);
            $cores[$core] = array_intersect_key($row, array_flip(['version', 'source', 'tag', 'asset', 'sha256']));
        }
        return $cores;
    }

    private static function catalog(): array
    {
        $filename = self::catalogFile();
        $cache = Policy::STATE_DIR . '/' . $filename;
        $bundled = (string)file_get_contents('/usr/local/share/blankvpn/' . $filename, false, null, 0, self::MAX_CATALOG + 1);
        $bundledCatalog = self::parseCatalog($bundled);
        if (!is_file($cache)) {
            return $bundledCatalog;
        }
        try {
            $cached = (string)file_get_contents($cache, false, null, 0, self::MAX_CATALOG + 1);
            $cachedCatalog = self::parseCatalog($cached);
            foreach ($cachedCatalog as $row) {
                if (($row['source'] ?? '') !== 'blanknetworks') {
                    Policy::writeState($filename, $bundled);
                    return $bundledCatalog;
                }
            }
            return $cachedCatalog;
        } catch (DomainException) {
            Policy::writeState($filename, $bundled);
            return $bundledCatalog;
        }
    }

    public static function refresh(): void
    {
        self::requireBlankReleaseMode();
        $url = 'https://raw.githubusercontent.com/' . self::REPO . '/main/src/share/blankvpn/' . self::catalogFile();
        $curl = curl_init($url);
        $body = '';
        curl_setopt_array($curl, [
            CURLOPT_PROTOCOLS_STR => 'HTTPS', CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROXY => '',
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_TIMEOUT => 10, CURLOPT_USERAGENT => 'BlankVPN core updates',
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_CATALOG) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            }
        ]);
        if (curl_exec($curl) !== true || curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) {
            throw new DomainException('The approved core catalog could not be downloaded.');
        }
        self::parseCatalog($body);
        Policy::writeState(self::catalogFile(), $body);
    }

    private static function state(): array
    {
        $path = Policy::STATE_DIR . '/' . self::stateFile();
        if (!is_file($path)) {
            return ['cores' => []];
        }
        $data = json_decode((string)file_get_contents($path, false, null, 0, 8193), true, 12);
        if (!is_array($data['cores'] ?? null)) {
            throw new RuntimeException('The proxy core state could not be read.');
        }
        return $data;
    }

    private static function save(array $state): void
    {
        Policy::writeState(self::stateFile(), json_encode($state, JSON_THROW_ON_ERROR));
    }

    public static function isManagedPath(string $core, string $path): bool
    {
        return isset(self::BASE[$core]) && preg_match(
            '/^' . preg_quote(self::directory() . '/' . $core . '-', '/') . '[0-9a-f]{64}$/D',
            $path
        ) === 1;
    }

    public static function override(string $core): ?string
    {
        if (self::usesSystemPackages()) {
            return null;
        }
        $digest = self::state()['cores'][$core]['active']['sha256'] ?? '';
        if (!isset(self::BASE[$core]) || !is_string($digest) || !self::digest($digest)) {
            return null;
        }
        return self::directory() . '/' . $core . '-' . $digest;
    }

    public static function uses(array $route, string $core): bool
    {
        return in_array($core, ['mihomo', 'tun2socks', $route['core']], true);
    }

    public static function pausedCore(): ?string
    {
        try {
            $pending = self::state()['pending'] ?? [];
            return !empty($pending['paused']) ? $pending['core'] : null;
        } catch (RuntimeException) {
            syslog(LOG_ERR, 'Blank VPN proxy routes paused because the core state could not be read.');
            return 'mihomo';
        }
    }

    private static function systemSingBoxVersion(): ?string
    {
        try {
            $output = Resolver::command(['/usr/bin/timeout', '3', '/usr/local/bin/sing-box', 'version'], false);
        } catch (\Throwable) {
            return null;
        }
        return self::reportedSingBoxVersion($output);
    }

    private static function reportedSingBoxVersion(string $output): ?string
    {
        return preg_match('/^sing-box version ([0-9]+\.[0-9]+\.[0-9]+)/mi', $output, $matches) === 1
            ? $matches[1] : null;
    }

    private static function packageVersion(string $package, bool $installed): ?string
    {
        $pkg = '/usr/local/sbin/pkg';
        if (!is_executable($pkg)) {
            return null;
        }
        try {
            $command = $installed ? 'query' : 'rquery';
            $output = Resolver::command(['/usr/bin/timeout', '5', $pkg, $command, '%v', $package], false);
            $version = trim($output);
            return preg_match('/^[A-Za-z0-9][A-Za-z0-9._+,-]{0,63}$/D', $version) === 1 ? $version : null;
        } catch (\Throwable) {
            return null;
        }
    }

    public static function status(): array
    {
        $state = self::state();
        $packageMode = self::usesSystemPackages();
        $catalog = $packageMode ? [] : self::catalog();
        $capabilities = ProxyRuntime::capabilities();
        $cores = [];
        foreach (self::BASE as $core => $base) {
            $selection = $state['cores'][$core] ?? [];
            $active = $selection['active'] ?? null;
            $system = $packageMode || ($core === 'sing-box' && ProxyRuntime::usesSystemSingBox());
            $packageVersion = $packageMode ? self::packageVersion(self::SYSTEM_PACKAGES[$core], true) : null;
            $packageLatestVersion = $packageMode ? self::packageVersion(self::SYSTEM_PACKAGES[$core], false) : null;
            $version = $packageMode ? $packageVersion : ($active['version'] ?? ($system ? self::systemSingBoxVersion() :
                (!$capabilities[$core] ? null : $base)));
            $previous = $packageMode ? null : ($selection['previous']['version'] ??
                ($active !== null && !$system && ProxyRuntime::hasBase($core) ? $base : null));
            $available = $packageMode ? null : ($catalog[$core] ?? null);
            $cores[] = [
                'id' => $core, 'package' => self::SYSTEM_PACKAGES[$core], 'version' => $version,
                'installed' => $capabilities[$core],
                'packageVersion' => $packageVersion, 'packageLatestVersion' => $packageLatestVersion,
                'catalogAvailable' => $packageMode ? $packageLatestVersion !== null : null,
                'packageUpdate' => $packageMode && $packageVersion !== null && $packageLatestVersion !== null &&
                    version_compare($packageLatestVersion, $packageVersion, '>'),
                'source' => $packageMode ? 'OPNsense package' : ($active === null ?
                    ($system ? 'System package' : 'Bundled') :
                    ($active['source'] === 'local' ? 'Local upload' : 'Approved update')),
                'previous' => $previous,
                'rollback' => !$packageMode && (isset($selection['previous']) ||
                    ($active !== null && ProxyRuntime::hasBase($core))),
                'available' => $available,
                'update' => !$packageMode && $available !== null &&
                    ($version === null || version_compare($available['version'], $version, '>')),
            ];
        }
        $used = 0;
        foreach (glob(self::directory() . '/*') ?: [] as $path) {
            if (is_file($path)) {
                $used += filesize($path);
            }
        }
        return [
            'cores' => $cores, 'architecture' => self::architecture(), 'pending' => isset($state['pending']),
            'mode' => $packageMode ? 'opnsense-packages' : 'blank-release',
            'storage' => [
                'freeBytes' => disk_free_space(Policy::STATE_DIR) ?: 0, 'coreBytes' => $used,
                'catalogBytes' => @filesize(Policy::STATE_DIR . '/proxy-catalog.json') ?: 0,
                'reserveBytes' => self::RESERVE
            ]
        ];
    }

    public static function install(string $core, ?string $upload = null, ?string $expected = null): void
    {
        self::requireBlankReleaseMode();
        $release = self::catalog()[$core] ?? null;
        if ($release === null || ($expected !== null && !hash_equals($release['sha256'], $expected))) {
            throw new DomainException('Refresh the approved catalog and select the core again.');
        }
        self::stage($core, $release, $upload ?? self::releaseUrl($core, $release));
    }

    public static function installLocal(string $core, string $version, string $archive, string $sha256): void
    {
        self::requireBlankReleaseMode();
        if (!isset(self::BASE[$core]) || !self::version($version) || !self::digest($sha256) || !is_file($archive)) {
            throw new DomainException('Provide a supported core, numeric version, local file and its SHA-256.');
        }
        self::stage($core, ['version' => $version, 'sha256' => $sha256, 'source' => 'local'], $archive);
    }

    private static function stage(string $core, array $release, string $source): void
    {
        $state = self::state();
        if (isset($state['pending'])) {
            throw new DomainException('A core change is awaiting recovery. Retry after router maintenance.');
        }
        $entry = array_intersect_key($release, array_flip(['version', 'sha256', 'source']));
        $original = $state['cores'][$core]['active'] ?? null;
        if (($original['sha256'] ?? '') === $entry['sha256']) {
            return;
        }
        Policy::stateDirectory();
        $directory = self::directory();
        if ((!is_dir($directory) && !mkdir($directory, 0700)) ||
            is_link($directory) || fileowner($directory) !== 0 || (fileperms($directory) & 0077) !== 0) {
            throw new RuntimeException('The core storage directory is unavailable.');
        }
        if (disk_free_space($directory) <= self::RESERVE) {
            throw new DomainException('Free space on the OPNsense state filesystem before updating cores.');
        }
        self::clearStaging();
        $temporary = tempnam($directory, '.stage-');
        if ($temporary === false) {
            throw new RuntimeException('The core could not be staged.');
        }
        $destination = $directory . '/' . $core . '-' . $entry['sha256'];
        try {
            $script = '/usr/local/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py';
            try {
                Resolver::command(['/usr/bin/timeout', '40', '/usr/local/bin/python3.13', $script,
                    '--stage', $core, $entry['sha256'], $temporary, $source, (string)self::RESERVE]);
            } catch (RuntimeException) {
                throw new DomainException('The core archive could not be downloaded or verified as FreeBSD ' . self::architecture() . '.');
            }
            if (disk_free_space($directory) <= self::RESERVE) {
                throw new DomainException('The core would leave too little space for Blank VPN & Proxy settings and router state.');
            }
            self::validate($core, $entry['version'], $temporary);
            if (!rename($temporary, $destination)) {
                throw new RuntimeException('The core could not be saved.');
            }
            self::activate($core, $entry, $original, $state);
        } finally {
            if (is_file($temporary)) {
                unlink($temporary);
            }
            self::prune($core, self::state());
        }
    }

    private static function validate(string $core, string $version, string $path): void
    {
        $command = ['/usr/bin/timeout', '12', $path];
        $versionArg = in_array($core, ['xray', 'sing-box'], true) ? 'version' : ($core === 'mihomo' ? '-v' : '--version');
        try {
            $output = Resolver::command([...$command, $versionArg]);
            if (stripos($output, $core) === false || !preg_match(
                '/(?<![0-9.])' . preg_quote($version, '/') . '(?![0-9.])/D', $output
            )) {
                throw new RuntimeException('Unexpected core version.');
            }
            if ($core === 'tun2socks') {
                return;
            }
            $model = new BlankVpn();
            $routes = array_filter(ProxyRuntime::routes($model), static fn (array $route): bool => self::uses($route, $core));
            $nodes = $routes === [] ? [] : ProxyCatalog::read()['nodes'];
            foreach ($routes as $route) {
                if (!isset($nodes[$route['node']])) {
                    throw new RuntimeException('Missing proxy node.');
                }
                $config = ProxyRuntime::configuration($route, $nodes[$route['node']]);
                $file = Policy::writeState('core-validation.json', json_encode(
                    $core === 'mihomo' ? $config['mihomo'] : $config['adapter'],
                    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
                ));
                try {
                    $arguments = match ($core) {
                        'mihomo' => ['-t', '-d', self::directory(), '-f', $file],
                        'xray' => ['run', '-test', '-config', $file],
                        'sing-box' => ['check', '-c', $file]
                    };
                    Resolver::command([...$command, ...$arguments]);
                } finally {
                    unlink($file);
                }
            }
        } catch (RuntimeException) {
            throw new DomainException('The core did not report the expected version or rejected a saved proxy exit.');
        }
    }

    public static function rollback(string $core): void
    {
        self::requireBlankReleaseMode();
        $state = self::state();
        $selection = $state['cores'][$core] ?? [];
        if (isset($state['pending']) || (!isset($selection['active']) && !isset($selection['previous']))) {
            throw new DomainException('No core rollback is available.');
        }
        $target = $selection['previous'] ?? null;
        if ($target !== null) {
            $path = self::directory() . '/' . $core . '-' . $target['sha256'];
            self::validate($core, $target['version'], $path);
        } elseif (!ProxyRuntime::hasBase($core)) {
            throw new DomainException('Install the bundled core before rolling back to it.');
        }
        self::activate($core, $target, $selection['active'] ?? null, $state);
    }

    private static function activate(string $core, ?array $target, ?array $prior, array $state): void
    {
        $model = new BlankVpn();
        $affected = array_filter(ProxyRuntime::assignedRoutes($model), static fn (array $route): bool => self::uses($route, $core));
        $live = Policy::anyEnabled(Policy::settings($model)) && $affected !== [];
        $state['pending'] = ['core' => $core, 'restore' => $state['cores'][$core] ?? [], 'paused' => true];
        self::save($state);
        try {
            if ($live) {
                self::reloadPaths($model);
            }
            $state['cores'][$core] = ['active' => $target, 'previous' => $prior];
            self::save($state);
            if ($live) {
                $status = ProxyRuntime::reconcile($model);
                if (array_diff(array_keys($affected), $status['active']) !== []) {
                    throw new RuntimeException('An affected proxy exit failed to start.');
                }
            }
            self::finish($state, $model, $live);
        } catch (\Throwable) {
            self::recover($model);
            throw new DomainException('The new core could not be activated. The previous selection was restored.');
        }
    }

    private static function finish(array $state, BlankVpn $model, bool $reload): void
    {
        $state['pending']['paused'] = false;
        self::save($state);
        if ($reload) {
            self::reloadPaths($model);
        }
        unset($state['pending']);
        self::save($state);
    }

    public static function recover(BlankVpn $model): void
    {
        $state = self::state();
        self::clearStaging();
        if (!isset($state['pending'])) {
            return;
        }
        $core = $state['pending']['core'];
        $state['pending']['paused'] = true;
        $state['cores'][$core] = $state['pending']['restore'];
        self::save($state);
        $live = Policy::anyEnabled(Policy::settings($model));
        if ($live) {
            self::reloadPaths($model);
            ProxyRuntime::reconcile($model);
        }
        self::finish($state, $model, $live);
        self::prune($core, $state);
    }

    private static function reloadPaths(BlankVpn $model): void
    {
        $settings = Policy::effectiveRouting($model);
        $assignments = Policy::deviceAssignments($settings,
            Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics()));
        Operations::reloadRoutingPaths($model, $settings, $assignments, Firewall::loadedRules() ?? []);
    }

    private static function clearStaging(): void
    {
        foreach (glob(self::directory() . '/.stage-*') ?: [] as $path) {
            if (is_file($path) && !is_link($path)) {
                unlink($path);
            }
        }
    }

    private static function prune(string $core, array $state): void
    {
        $keep = array_filter(array_column($state['cores'][$core] ?? [], 'sha256'));
        $keep = array_merge($keep, array_filter(array_column($state['pending']['restore'] ?? [], 'sha256')));
        foreach (glob(self::directory() . '/' . $core . '-*') ?: [] as $path) {
            if (self::isManagedPath($core, $path) && !in_array(substr($path, -64), $keep, true)) {
                unlink($path);
            }
        }
    }
}
