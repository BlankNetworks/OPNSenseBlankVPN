<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class PackageUpdate
{
    private const PACKAGE = 'os-blank-vpn';
    private const ORIGIN = 'opnsense/os-blank-vpn';
    private const SERIES = '26.7';
    private const PKG = '/usr/local/sbin/pkg';
    private const VERSION_FILE = '/usr/local/opnsense/version/core';
    private const REPO = 'BlankNetworks';
    private const REPO_DIR = '/usr/local/etc/pkg/repos';
    private const KEY = '/usr/local/share/blankvpn/repo.pub';
    private const KEY_HASH = 'dad2499cd97e6c44f590daa89a62ef6a05527c328c6324d3908c3d6045dc1e88';
    private const URL = 'https://blanknetworks.github.io/OPNSenseBlankVPN/pkg/26.7/${ABI}';
    private const STATE = 'package-update.json';
    private const DEPENDENCIES = [
        'opnsense' => 'opnsense/opnsense', 'dnsmasq' => 'opnsense/dnsmasq',
        'php85-curl' => 'ftp/php85-curl', 'python313' => 'lang/python313',
    ];
    public const LAUNCHER = '/usr/local/opnsense/scripts/firmware/launcher.sh';
    public const WORKER = '/usr/local/opnsense/scripts/OPNsense/BlankVpn/package_update.php';

    public static function runningAsRoot(): bool
    {
        if (function_exists('posix_geteuid')) {
            return posix_geteuid() === 0;
        }
        try {
            return trim(self::command(['/usr/bin/id', '-u'], 2, 'Cannot determine the updater privileges.')) === '0';
        } catch (RuntimeException) {
            return false;
        }
    }

    public static function status(): array
    {
        $abi = self::supportedAbi();
        $supported = $abi !== null;
        $state = self::readState();
        $phase = $state['phase'] ?? 'idle';
        $running = in_array($phase, ['queued', 'running'], true);
        $enabled = $supported && self::repoEnabled();
        $installed = $running ? ($state['installed'] ?? null) : self::installed($abi);
        $checkedVersion = $enabled ? ($state['available'] ?? null) : null;
        if (!self::validVersion($installed)) {
            $installed = null;
        }
        $available = self::validVersion($checkedVersion) && $installed !== null && self::newer($checkedVersion, $installed)
            ? $checkedVersion : null;

        $message = $state['message'] ?? 'Check for a Blank VPN update.';
        if (!$supported) {
            $message = 'Updates require OPNsense Community Edition 26.7 on FreeBSD 15 amd64 or aarch64.';
        } elseif ($running && self::interrupted($state)) {
            $phase = 'failed';
            $running = false;
            $installed = self::installed($abi);
            if ($installed === ($state['available'] ?? null)) {
                $available = null;
            }
            $message = 'The update worker stopped. Check the installed package before trying again.';
        } elseif (!$running && $available === null && self::validVersion($checkedVersion) && $installed !== null) {
            $phase = 'idle';
            $message = 'Blank VPN is up to date.';
        }

        return [
            'installed' => $installed, 'available' => $available, 'enabled' => $enabled,
            'supported' => $supported, 'running' => $running, 'phase' => $phase,
            'message' => $message, 'checkedAt' => $state['checkedAt'] ?? null,
        ];
    }

    public static function enable(): array
    {
        return self::withQueueLock(static fn (): array => self::enableLocked());
    }

    private static function enableLocked(): array
    {
        self::requireSupported();
        self::assertKey();
        self::assertIdle();
        self::enableRepository();
        return self::status();
    }

    private static function enableRepository(): void
    {
        if (self::repoEnabled()) {
            return;
        }
        if (!is_dir(self::REPO_DIR) || is_link(self::REPO_DIR)) {
            throw new DomainException('The native package repository directory is unavailable.');
        }
        $target = self::repoPath();
        if (file_exists($target) || is_link($target)) {
            throw new DomainException('An existing Blank Networks repository definition conflicts with the signed settings.');
        }
        $temporary = tempnam(self::REPO_DIR, '.blankvpn-repo-');
        if ($temporary === false) {
            throw new RuntimeException('The signed repository configuration could not be staged.');
        }
        try {
            $configuration = self::repoConfiguration();
            if (file_put_contents($temporary, $configuration) !== strlen($configuration) ||
                !chmod($temporary, 0644) || !@link($temporary, $target)) {
                throw new RuntimeException('The signed repository configuration could not be enabled.');
            }
        } finally {
            unlink($temporary);
        }
    }

    public static function check(): array
    {
        return self::withQueueLock(static fn (): array => self::checkLocked());
    }

    private static function checkLocked(): array
    {
        $abi = self::requireSupported();
        self::assertKey();
        self::assertIdle();
        $work = self::workDirectory();
        try {
            $installed = self::requireInstalled($abi);
            $available = self::refreshCatalog($work, $abi);
            // Make the same signed source available to OPNsense Firmware after a successful check.
            self::enableRepository();
            $update = self::newer($available, $installed);
            self::writeState([
                'phase' => 'idle', 'checkedAt' => time(), 'available' => $update ? $available : null,
                'message' => $update ? 'An update is ready to install.' : 'Blank VPN is up to date.',
            ]);
        } catch (DomainException | RuntimeException $error) {
            self::writeState(['phase' => 'failed', 'message' => $error->getMessage()]);
        } finally {
            self::removeWork($work);
        }
        return self::status();
    }

    public static function enqueue(mixed $version): array
    {
        if (!self::validVersion($version)) {
            throw new DomainException('Choose an available Blank VPN version.');
        }
        $abi = self::requireEnabled();
        return self::withQueueLock(static function () use ($version, $abi): array {
            self::assertIdle();
            $state = self::readState();
            $installed = self::requireInstalled($abi);
            if (($state['available'] ?? null) !== $version || !self::newer($version, $installed)) {
                throw new DomainException('Check for an update before installing this version.');
            }

            $job = bin2hex(random_bytes(16));
            $state = array_replace($state, [
                'phase' => 'queued', 'job' => $job, 'installed' => $installed, 'started' => time(),
                'pid' => null, 'message' => 'Starting update. The WebGUI and VPN connections may briefly reconnect.',
            ]);
            self::writeState($state);
            try {
                self::startWorker($job);
            } catch (RuntimeException $error) {
                self::writeState(array_replace($state, ['phase' => 'failed', 'message' => $error->getMessage()]));
            }
            return self::status();
        });
    }

    public static function dispatch(string $job): void
    {
        if (!self::job($job) || !self::isQueued($job)) {
            return;
        }
        try {
            self::command([self::LAUNCHER, '-s', self::WORKER, 'install', $job], 0,
                'The firmware service is busy or the Blank VPN update worker stopped.');
        } catch (RuntimeException $error) {
            self::withQueueLock(static function () use ($job, $error): void {
                $state = self::readState();
                if (($state['job'] ?? '') === $job && in_array($state['phase'] ?? '', ['queued', 'running'], true)) {
                    self::writeState(array_replace($state, ['phase' => 'failed', 'message' => $error->getMessage()]));
                }
            });
        }
    }

    public static function install(string $job): void
    {
        if (!self::job($job)) {
            return;
        }
        $state = self::withQueueLock(static function () use ($job): array {
            if (!self::isQueued($job)) {
                return [];
            }
            $state = array_replace(self::readState(), [
                'phase' => 'running', 'pid' => getmypid(), 'message' => 'Verifying and installing the signed Blank VPN package.',
            ]);
            self::writeState($state);
            return $state;
        });
        if ($state === []) {
            return;
        }

        $work = null;
        try {
            $abi = self::requireEnabled();
            $installed = self::requireInstalled($abi);
            $version = $state['available'] ?? null;
            if (!self::validVersion($version) || !self::newer($version, $installed)) {
                throw new DomainException('This update is no longer newer than the installed package.');
            }
            $work = self::workDirectory();
            if (self::refreshCatalog($work, $abi) !== $version) {
                throw new DomainException('A different version is available. Check for an update again.');
            }

            $package = self::fetchPackage($work, $abi, $version);
            self::verifyTransaction($package, $abi, $installed, $version);
            $arguments = ['-R', $work . '/repos', '-o', 'PKG_ENABLE_PLUGINS=false',
                '-o', 'PKG_CACHEDIR=' . $work . '/cache', '-o', 'ASSUME_ALWAYS_YES=false',
                '-o', 'DEFAULT_ALWAYS_YES=false', '-o', 'PERMISSIVE=false', 'install'];
            $plan = self::pkg([...$arguments, '-lUny', $package], 25, 'The Blank VPN package upgrade could not be planned.');
            if (!self::singleUpgrade($plan, $installed, $version)) {
                throw new DomainException('The update would affect other packages or requires package changes in OPNsense Firmware first.');
            }
            self::runInstaller([...$arguments, '-lU', $package], $installed, $version);
            if (self::installed($abi) !== $version) {
                throw new RuntimeException('The package manager did not confirm the requested Blank VPN version.');
            }
            self::writeState(array_replace($state, ['installed' => $version, 'available' => null, 'phase' => 'succeeded',
                'message' => 'Blank VPN ' . $version . ' installed. Reload the WebGUI to use the updated dashboard.']));
        } catch (DomainException | RuntimeException $error) {
            self::writeState(array_replace($state, ['phase' => 'failed', 'message' => $error->getMessage()]));
        } finally {
            if ($work !== null) {
                self::removeWork($work);
            }
        }
    }

    private static function repoConfiguration(): string
    {
        return self::REPO . ': { url: "' . self::URL . '", enabled: true, signature_type: "pubkey", pubkey: "' .
            self::KEY . '", priority: 0 }' . "\n";
    }

    private static function repoPath(): string
    {
        return self::REPO_DIR . '/' . self::REPO . '.conf';
    }

    private static function repoEnabled(): bool
    {
        $path = self::repoPath();
        return self::trustedFile($path) && self::trustedFile(self::KEY) &&
            @file_get_contents($path, false, null, 0, 1024) === self::repoConfiguration() &&
            @hash_file('sha256', self::KEY) === self::KEY_HASH;
    }

    private static function trustedFile(string $path): bool
    {
        clearstatcache(true, $path);
        return !is_link($path) && is_file($path) && @fileowner($path) === 0 &&
            ((@fileperms($path) ?: 0) & 0022) === 0;
    }

    private static function assertKey(): void
    {
        if (!self::trustedFile(self::KEY) || @hash_file('sha256', self::KEY) !== self::KEY_HASH) {
            throw new DomainException('The installed repository public key did not match the expected signing key.');
        }
    }

    private static function supportedAbi(): ?string
    {
        $data = @file_get_contents(self::VERSION_FILE, false, null, 0, 8192);
        $product = is_string($data) ? json_decode($data, true) : null;
        $arch = $product['product_arch'] ?? null;
        $actualArch = str_replace(['x86_64', 'arm64'], ['amd64', 'aarch64'], php_uname('m'));
        if (PHP_OS !== 'FreeBSD' || !is_executable(self::PKG) || !is_executable(self::LAUNCHER) ||
            !in_array($arch, ['amd64', 'aarch64'], true) || $arch !== $actualArch ||
            ($product['product_id'] ?? null) !== 'opnsense' || ($product['product_abi'] ?? null) !== self::SERIES ||
            !str_starts_with(php_uname('r'), '15.')) {
            return null;
        }
        return 'FreeBSD:15:' . $arch;
    }

    private static function requireSupported(): string
    {
        $abi = self::supportedAbi();
        if ($abi === null || trim(self::pkg(['config', 'ABI'], 4, 'The native package ABI could not be verified.')) !== $abi) {
            throw new DomainException('The signed updates require OPNsense Community Edition 26.7 and its native FreeBSD 15 package ABI.');
        }
        return $abi;
    }

    private static function requireEnabled(): string
    {
        $abi = self::requireSupported();
        if (!self::repoEnabled()) {
            throw new DomainException('Check for an update before installing.');
        }
        return $abi;
    }

    private static function installed(?string $abi): ?string
    {
        if ($abi === null) {
            return null;
        }
        try {
            return self::versionFromQuery(self::pkg(['query', '%n %v %o %q', self::PACKAGE], 4,
                'The installed Blank VPN package could not be queried.'), $abi);
        } catch (RuntimeException) {
            return null;
        }
    }

    private static function requireInstalled(string $abi): string
    {
        return self::installed($abi) ?? throw new DomainException('A compatible Blank VPN package must already be installed.');
    }

    private static function versionFromQuery(string $output, string $abi): ?string
    {
        $fields = preg_split('/[ \t]+/', trim($output));
        if (count($fields) !== 4 || $fields[0] !== self::PACKAGE || !self::validVersion($fields[1]) ||
            $fields[2] !== self::ORIGIN || $fields[3] !== $abi) {
            return null;
        }
        return $fields[1];
    }

    public static function validVersion(mixed $version): bool
    {
        return is_string($version) && preg_match('/^(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}$/D', $version) === 1;
    }

    private static function newer(string $candidate, string $installed): bool
    {
        return version_compare($candidate, $installed, '>');
    }

    private static function remoteArguments(string $work): array
    {
        return [
            '-R', $work . '/repos', '-o', 'PKG_DBDIR=' . $work . '/db',
            '-o', 'PKG_CACHEDIR=' . $work . '/cache', '-o', 'PKG_ENABLE_PLUGINS=false',
            '-o', 'FETCH_RETRY=1', '-o', 'FETCH_TIMEOUT=12',
        ];
    }

    private static function refreshCatalog(string $work, string $abi): string
    {
        $options = self::remoteArguments($work);
        self::pkg([...$options, 'update', '-f', '-r', self::REPO], 23,
            'The signed Blank Networks package catalog could not be refreshed.');
        // An empty isolated DB prevents reuse of a previously cached catalog after a signature failure.
        $output = self::pkg([...$options, 'rquery', '-U', '-r', self::REPO, '-a', '%n %v %o %q'], 4,
            'No verified package catalog is available for this router.');
        return self::versionFromQuery($output, $abi) ??
            throw new DomainException('The signed repository did not contain exactly one compatible Blank VPN package.');
    }

    private static function fetchPackage(string $work, string $abi, string $version): string
    {
        self::pkg([...self::remoteArguments($work), 'fetch', '-Uy', '-r', self::REPO,
            '-o', $work . '/fetched', self::PACKAGE . '-' . $version], 65,
            'The verified Blank VPN package could not be downloaded.');

        $package = $work . '/fetched/All/' . self::PACKAGE . '-' . $version . '.pkg';
        if (!is_file($package) || is_link($package) ||
            self::versionFromQuery(self::pkg(['query', '-F', $package, '%n %v %o %q'], 8,
                'The downloaded package manifest could not be read.'), $abi) !== $version) {
            throw new DomainException('The downloaded package did not match the requested Blank VPN release and ABI.');
        }
        return $package;
    }

    private static function singleUpgrade(string $output, string $installed, string $version): bool
    {
        preg_match_all('/^Number of (packages|groups) to be (\w+):\s*([0-9]+)$/m', $output, $counts, PREG_SET_ORDER);
        if (count($counts) !== 1 || $counts[0][1] !== 'packages' || $counts[0][3] !== '1') {
            return false;
        }
        // FreeBSD pkg 2.8.4 reports a local package archive replacement as an install.
        $heading = match ($counts[0][2]) {
            'upgraded' => 'Installed packages to be UPGRADED:',
            'installed' => 'New packages to be INSTALLED:',
            default => null,
        };
        if ($heading === null) {
            return false;
        }
        $transition = $counts[0][2] === 'upgraded' ? $installed . ' -> ' . $version : $version;
        $row = preg_quote(self::PACKAGE . ': ' . $transition, '/');
        return preg_match('/^' . preg_quote($heading, '/') . '\r?\n[ \t]+' . $row .
            '(?: \[[^\]\r\n]+\])?\r?$/m', $output) === 1;
    }

    private static function verifyTransaction(string $package, string $abi, string $installed, string $version): void
    {
        $manifest = self::pkg(['info', '-R', '--raw-format', 'json-compact', '-F', $package], 8,
            'The signed package manifest could not be verified.', 2097152);
        $metadata = json_decode($manifest, true, 16);
        $deps = $metadata['deps'] ?? null;
        if (!is_array($deps) || array_diff_key($deps, self::DEPENDENCIES) !== [] ||
            array_diff_key(self::DEPENDENCIES, $deps) !== [] || !empty($metadata['conflicts']) ||
            !empty($metadata['shlibs_required']) || !is_array($metadata['files'] ?? null)) {
            throw new DomainException('This release requires a dependency or package change outside Blank VPN. Use OPNsense Firmware.');
        }
        foreach (self::DEPENDENCIES as $name => $origin) {
            $minimum = $deps[$name]['version'] ?? '';
            $row = self::pkg(['query', '%n %v %o %q', $name], 3,
                'Install the required OPNsense dependencies before updating Blank VPN.');
            $fields = preg_split('/[ \t]+/', trim($row));
            if (($deps[$name]['origin'] ?? null) !== $origin || !is_string($minimum) ||
                preg_match('/^[A-Za-z0-9.,_+-]{1,48}$/D', $minimum) !== 1 || count($fields) !== 4 ||
                $fields[0] !== $name || $fields[2] !== $origin || $fields[3] !== $abi ||
                trim(self::pkg(['version', '-t', $fields[1], $minimum], 3, 'Could not compare package dependency versions.')) === '<') {
                throw new DomainException('Install the required OPNsense dependencies before updating Blank VPN.');
            }
        }

        $locked = self::pkg(['query', '%k', self::PACKAGE], 3, 'Could not read the installed package lock.');
        if (trim($locked) !== '0' || self::installed($abi) !== $installed || !self::newer($version, $installed)) {
            throw new DomainException('Blank VPN is locked or its installed version changed. Check OPNsense Firmware first.');
        }

        $files = $metadata['files'];
        if ($files === [] || count($files) > 4096) {
            throw new DomainException('The signed Blank VPN archive contains an unexpected file list.');
        }
        foreach ($files as $path => $value) {
            if (!is_string($path) || preg_match('#^/usr/local/(?:etc|libexec|opnsense|sbin|share)/[A-Za-z0-9/_.-]+$#D', $path) !== 1 ||
                preg_match('#(?:^|/)\.{1,2}(?:/|$)#', $path) === 1) {
                throw new DomainException('The signed Blank VPN archive contains an unexpected file path.');
            }
        }
        $ownership = self::pkg(['query', '-a', '%n %Fp'], 20, 'Could not verify package file ownership.', 16777216);
        foreach (explode("\n", $ownership) as $row) {
            [$owner, $path] = array_pad(explode(' ', $row, 2), 2, '');
            if ($owner !== self::PACKAGE && isset($files[$path])) {
                throw new DomainException('A different installed package owns a file in this Blank VPN release.');
            }
        }
    }

    private static function interrupted(array $state): bool
    {
        $age = time() - (int)($state['started'] ?? 0);
        $pid = (int)($state['pid'] ?? 0);
        return ($state['phase'] === 'queued' && $age > 35) ||
            ($state['phase'] === 'running' && $age > 15 && !self::workerAlive($pid));
    }

    private static function workerAlive(int $pid): bool
    {
        if ($pid < 2) {
            return false;
        }
        try {
            $command = self::command(['/bin/ps', '-ww', '-p', (string)$pid, '-o', 'command='], 2,
                'The update worker is no longer active.');
            return str_contains($command, self::WORKER . ' install ');
        } catch (RuntimeException) {
            return false;
        }
    }

    private static function assertIdle(): void
    {
        $state = self::readState();
        if (in_array($state['phase'] ?? '', ['queued', 'running'], true) && !self::interrupted($state)) {
            throw new DomainException('A Blank VPN package update is already running.');
        }
    }

    private static function job(string $job): bool
    {
        return preg_match('/^[a-f0-9]{32}$/D', $job) === 1;
    }

    private static function runInstaller(array $arguments, string $installed, string $version): void
    {
        $process = @proc_open([self::PKG, ...$arguments],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, '/',
            self::commandEnvironment());
        if (!is_resource($process)) {
            throw new RuntimeException('The Blank VPN package installer could not be started.');
        }

        $plan = '';
        $prompt = "\nProceed with this action? [y/N]: ";
        $deadline = microtime(true) + 30;
        stream_set_blocking($pipes[1], false);
        while (!feof($pipes[1]) && strlen($plan) < 65536 && microtime(true) < $deadline) {
            $ready = [$pipes[1]];
            $write = $except = null;
            if (@stream_select($ready, $write, $except, 1) > 0) {
                $chunk = fread($pipes[1], 4096);
                if ($chunk === false) {
                    break;
                }
                $plan .= $chunk;
                if (str_contains($plan, $prompt)) {
                    break;
                }
            }
        }

        $approved = strlen($plan) < 65536 && str_ends_with($plan, $prompt) && self::singleUpgrade($plan, $installed, $version);
        if ($approved) {
            $approved = @fwrite($pipes[0], "y\n") === 2;
        }
        // A later solver prompt gets an EOF and its default answer is no.
        fclose($pipes[0]);
        if (!$approved) {
            @proc_terminate($process);
        }
        stream_set_blocking($pipes[1], true);
        while (!feof($pipes[1])) {
            if (fread($pipes[1], 8192) === false) {
                break;
            }
        }
        fclose($pipes[1]);
        $status = proc_close($process);
        if (!$approved || $status !== 0) {
            throw new RuntimeException('The package manager did not complete the isolated Blank VPN upgrade.');
        }
    }

    private static function isQueued(string $job): bool
    {
        $state = self::readState();
        return ($state['job'] ?? '') === $job && ($state['phase'] ?? '') === 'queued' && !self::interrupted($state);
    }

    private static function readState(): array
    {
        $path = Policy::STATE_DIR . '/' . self::STATE;
        if (!is_file($path) && !is_link($path)) {
            return [];
        }
        if (!self::trustedFile($path) || ((@fileperms($path) ?: 0) & 0077) !== 0) {
            throw new RuntimeException('The private Blank VPN update status file is unsafe.');
        }
        $data = @file_get_contents($path, false, null, 0, 8192);
        $state = is_string($data) ? json_decode($data, true) : null;
        if (!is_array($state)) {
            throw new RuntimeException('The private Blank VPN update status file is invalid.');
        }
        return $state;
    }

    private static function writeState(array $state): void
    {
        Policy::writeState(self::STATE, json_encode($state, JSON_THROW_ON_ERROR));
    }

    private static function withQueueLock(callable $callback): mixed
    {
        $path = Policy::stateDirectory() . '/package-update.lock';
        if (is_link($path)) {
            throw new RuntimeException('The private Blank VPN update lock is unsafe.');
        }
        $file = @fopen($path, 'ce');
        if ($file === false) {
            throw new RuntimeException('The Blank VPN update lock could not be opened.');
        }
        try {
            chmod($path, 0600);
            if (!flock($file, LOCK_EX | LOCK_NB)) {
                throw new DomainException('A Blank VPN package operation is starting. Try again shortly.');
            }
            return $callback();
        } finally {
            fclose($file);
        }
    }

    private static function workDirectory(): string
    {
        $path = Policy::stateDirectory() . '/pkg-work-' . bin2hex(random_bytes(16));
        if (!mkdir($path, 0700)) {
            throw new RuntimeException('The private package work directory could not be created.');
        }
        try {
            foreach (['repos', 'db', 'cache', 'fetched'] as $directory) {
                if (!mkdir($path . '/' . $directory, 0700)) {
                    throw new RuntimeException('The private package work directory could not be prepared.');
                }
            }
            $contents = self::repoConfiguration();
            if (file_put_contents($path . '/repos/' . self::REPO . '.conf', $contents) !== strlen($contents)) {
                throw new RuntimeException('The isolated signed repository could not be configured.');
            }
            return $path;
        } catch (RuntimeException $error) {
            self::removeWork($path);
            throw $error;
        }
    }

    private static function removeWork(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST) as $entry) {
            if ($entry->isDir() && !$entry->isLink()) {
                @rmdir($entry->getPathname());
            } else {
                @unlink($entry->getPathname());
            }
        }
        @rmdir($path);
    }

    private static function pkg(array $arguments, int $timeout, string $error, int $outputLimit = 65536): string
    {
        return self::command([self::PKG, ...$arguments], $timeout, $error, $outputLimit);
    }

    private static function startWorker(string $job): void
    {
        $stdio = [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
        $process = @proc_open(['/usr/sbin/daemon', '-f', self::WORKER, 'dispatch', $job], $stdio, $pipes, '/', self::commandEnvironment());
        if (!is_resource($process) || proc_close($process) !== 0) {
            throw new RuntimeException('The Blank VPN update worker could not be started.');
        }
    }

    private static function command(array $arguments, int $timeout, string $error, int $outputLimit = 65536): string
    {
        if ($timeout !== 0) {
            $timeoutCommand = is_executable('/usr/bin/timeout') ? '/usr/bin/timeout' : '/bin/timeout';
            $arguments = [$timeoutCommand, '-k', '5', (string)$timeout, ...$arguments];
        }
        $process = @proc_open($arguments,
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, '/',
            self::commandEnvironment());
        if (!is_resource($process)) {
            throw new RuntimeException($error);
        }
        $output = stream_get_contents($pipes[1], $outputLimit + 1);
        if (is_string($output) && strlen($output) > $outputLimit && $timeout === 0) {
            while (!feof($pipes[1])) {
                if (fread($pipes[1], 8192) === false) {
                    break;
                }
            }
        }
        fclose($pipes[1]);
        if (proc_close($process) !== 0 || !is_string($output) || strlen($output) > $outputLimit) {
            throw new RuntimeException($error);
        }
        return $output;
    }

    private static function commandEnvironment(): array
    {
        return ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin', 'LC_ALL' => 'C'];
    }
}
