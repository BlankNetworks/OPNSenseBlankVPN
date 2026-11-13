<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

class Ivpn
{
    private const API = 'https://api.ivpn.net';
    private const MAX_RESPONSE = 2097152;
    private const STATUS_TTL = 300;
    private const DNS = ['172.16.0.1'];
    private const CHALLENGES = [70001 => 'captcha', 70002 => 'captcha', 70011 => 'totp', 70012 => 'totp'];
    private readonly string $path;

    public function __construct(string $user, private readonly string $directory = '/var/db/blank-vpn')
    {
        if ($user === '' || strlen($user) > 128 || preg_match('/[\x00-\x1f\x7f]/', $user)) {
            throw new DomainException('IVPN sign-in requires an authenticated OPNsense user.');
        }
        $this->path = $directory . '/ivpn-' . hash('sha256', $user);
    }

    public function authStatus(bool $refresh = false): array
    {
        $state = $this->readState();
        if (!isset($state['token']) || !$refresh) {
            if (($state['status'] ?? null) === 'authenticated' && ($state['activeUntil'] ?? PHP_INT_MAX) <= $this->now()) {
                $state['status'] = 'expired';
                $state['message'] = 'The last verified IVPN subscription period ended. Refresh the session status.';
            } elseif (($state['status'] ?? null) === 'authenticated'
                && ($state['checkedAt'] ?? 0) + self::STATUS_TTL <= $this->now()) {
                $state['status'] = 'stale';
                $state['message'] = 'IVPN sign-in was saved. Refresh the session status to verify it.';
            }
            return self::status($state);
        }
        return $this->locked(fn (array $state): array => self::status($this->checkSession($state)));
    }

    public function login(string $accountId, string $confirmation = ''): array
    {
        $accountId = trim($accountId);
        if (!preg_match('/\A(?:i-(?:[A-Za-z0-9]{4}-){2}[A-Za-z0-9]{4}|ivpn[A-Za-z0-9]{8})\z/i', $accountId)) {
            throw new DomainException('Enter an IVPN Account ID in the format i-XXXX-XXXX-XXXX.');
        }
        if ($confirmation !== '' && !preg_match('/\A[0-9]{6}\z/', $confirmation)) {
            throw new DomainException('Enter the six-digit code from your IVPN authenticator.');
        }

        return $this->locked(function (array $state) use ($accountId, $confirmation): array {
            $account = hash('sha256', $accountId);
            if (isset($state['token'])) {
                if (!hash_equals($state['account'], $account)) {
                    throw new DomainException('Sign out of the saved IVPN account before changing accounts.');
                }
                $state = $this->checkSession($state);
                if (isset($state['token'])) {
                    return self::status($state);
                }
            }

            if (!isset($state['privateKey']) || !hash_equals($state['account'], $account)) {
                $state = ['account' => $account, 'privateKey' => $this->generateKey()];
            }
            if (!self::validKey($state['privateKey'])) {
                throw new RuntimeException('The router could not generate a WireGuard key for IVPN.');
            }
            $publicKey = $this->publicKey($state['privateKey']);
            if (!self::validKey($publicKey)) {
                throw new RuntimeException('The router could not derive a WireGuard public key for IVPN.');
            }
            unset($state['challenge'], $state['message'], $state['status']);
            $this->writeState($state);

            $body = ['username' => $accountId, 'force' => false, 'wg_public_key' => $publicKey];
            if ($confirmation !== '') {
                $body['confirmation'] = $confirmation;
            }
            try {
                $response = $this->request('/v4/session/new', $body);
            } catch (RuntimeException $error) {
                if (in_array($error->getCode(), [401, 403, 429], true)) {
                    throw $error;
                }
                throw new RuntimeException('IVPN did not confirm registration. Retrying uses the same key. If IVPN reports a device limit, check the account device list.');
            }
            $code = self::code($response);
            if (isset(self::CHALLENGES[$code])) {
                $state['challenge'] = self::CHALLENGES[$code];
                $state['status'] = 'pending';
                $state['message'] = match ($code) {
                    70011 => 'Enter the six-digit code from your IVPN authenticator.',
                    70012 => 'IVPN rejected that code. Enter a new code from your authenticator.',
                    default => 'IVPN requires a CAPTCHA. Generate a WireGuard configuration in the IVPN Account Area and import it here.',
                };
                $this->writeState($state);
                return self::status($state);
            }
            if ($code !== 200) {
                throw new DomainException(match ($code) {
                    401 => 'IVPN rejected the Account ID.',
                    602 => 'IVPN has reached the device limit. Review devices in the IVPN Account Area.',
                    702 => 'The IVPN subscription is inactive.',
                    default => 'IVPN could not register this router. Try again or import a WireGuard configuration.',
                });
            }

            $token = $response['token'] ?? null;
            if (!is_string($token) || !preg_match('/\A[\x21-\x7e]{8,2048}\z/', $token)) {
                throw new RuntimeException('IVPN returned an unreadable session token.');
            }
            $state['token'] = $token;
            $state['publicKey'] = $publicKey;
            // Preserve the owned session even if its WireGuard allocation was incomplete.
            $allocation = $response['wireguard'] ?? [];
            $state['address'] = self::tunnelAddress($allocation['ip_address'] ?? null);
            return self::status($this->saveStatus($state, $response));
        });
    }

    public function logout(): void
    {
        $this->locked(function (array $state): void {
            if (isset($state['token'])) {
                try {
                    $response = $this->request('/v4/session/delete', ['session_token' => $state['token']]);
                } catch (RuntimeException $error) {
                    if ($error->getCode() !== 401) {
                        throw $error;
                    }
                    $response = ['status' => 401];
                }
                if (!in_array(self::code($response), [200, 401, 601], true)) {
                    throw new RuntimeException('IVPN could not release this router’s session. Try again.');
                }
            }
            $file = $this->path . '.json';
            if (is_file($file) && !@unlink($file)) {
                throw new RuntimeException('Blank VPN could not remove the saved IVPN sign-in.');
            }
        });
    }

    public function servers(string $country = ''): array
    {
        $country = strtoupper($country);
        if ($country !== '' && !preg_match('/\A[A-Z]{2}\z/', $country)) {
            throw new DomainException('Enter a two-letter country code.');
        }
        $servers = self::normalizeServers($this->request('/v5/servers.json'), $country);
        if ($servers === []) {
            throw new DomainException('IVPN returned no compatible WireGuard servers for this location.');
        }
        return $servers;
    }

    public function configuration(string $serverId, string $country = ''): array
    {
        $state = $this->locked(fn (array $state): array => $this->checkSession($state));
        if (($state['status'] ?? '') !== 'authenticated') {
            throw new DomainException($state['message'] ?? 'Sign in to IVPN before creating a profile.');
        }
        $server = $this->servers($country)[$serverId] ?? null;
        if ($server === null) {
            throw new DomainException('Choose a WireGuard server from the IVPN list.');
        }
        $identity = [
            'privateKey' => $state['privateKey'], 'publicKey' => $state['publicKey'],
            'address' => $state['address'], 'address6' => '', 'dns' => self::DNS,
        ];
        return [$identity, $server];
    }

    private static function normalizeServers(array $catalog, string $country): array
    {
        $servers = [];
        $ports = [];
        foreach ((array)($catalog['config']['ports']['wireguard'] ?? []) as $row) {
            if (is_array($row) && strcasecmp((string)($row['type'] ?? ''), 'udp') === 0 && is_int($row['port'] ?? null)
                && $row['port'] >= 1 && $row['port'] <= 65535) {
                $ports[] = $row['port'];
            }
        }
        $port = in_array(2049, $ports, true) ? 2049 : ($ports[0] ?? null);
        if ($port === null) {
            return [];
        }
        foreach ((array)($catalog['wireguard'] ?? []) as $location) {
            $code = $location['country_code'] ?? '';
            if (!is_string($code) || !preg_match('/\A[A-Z]{2}\z/i', $code)
                || ($country !== '' && $country !== strtoupper($code))) {
                continue;
            }
            foreach ((array)($location['hosts'] ?? []) as $row) {
                $id = $row['hostname'] ?? '';
                $ip = $row['host'] ?? '';
                if (!is_string($id) || !preg_match('/\A[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,3}\.ivpn\.net\z/i', $id)
                    || !is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE)
                    || !self::validKey($row['public_key'] ?? null)) {
                    continue;
                }
                $id = strtolower($id);
                $label = implode(' · ', array_filter([$location['city'] ?? '', $location['country'] ?? '', $id],
                    static fn (mixed $part): bool => is_string($part) && $part !== ''));
                $servers[$id] = [
                    'name' => preg_match('/\A[^\p{C}<>]{1,64}\z/u', $label) ? $label : $id,
                    'ipv4' => $ip, 'publicKey' => $row['public_key'], 'port' => $port,
                    'dns' => self::DNS, 'countryCode' => strtoupper($code),
                ];
            }
        }
        uasort($servers, static fn (array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));
        return $servers;
    }

    private function checkSession(array $state): array
    {
        if (!isset($state['token'])) {
            return $state;
        }
        try {
            $response = $this->request('/v4/session/status', ['session_token' => $state['token']]);
        } catch (RuntimeException $error) {
            if ($error->getCode() === 401) {
                return $this->saveStatus($state, ['status' => 401]);
            }
            return $this->saveStatus($state, ['status' => 0]);
        }
        return $this->saveStatus($state, $response);
    }

    private function saveStatus(array $state, array $response): array
    {
        $code = self::code($response);
        $account = is_array($response['service_status'] ?? null) ? $response['service_status'] : [];
        if (is_int($account['active_until'] ?? null) && $account['active_until'] > 0) {
            $state['activeUntil'] = $account['active_until'];
        }
        $state['checkedAt'] = $this->now();
        [$state['status'], $state['message']] = match (true) {
            $code === 401 || $code === 601 => ['expired', 'The saved IVPN session ended. Sign in again.'],
            $code === 702 || ($account['is_active'] ?? null) === false
                || ($state['activeUntil'] ?? PHP_INT_MAX) <= $this->now() => ['expired', 'The IVPN subscription is inactive.'],
            $code !== 200 || !is_bool($account['is_active'] ?? null) => ['stale', 'Blank VPN could not confirm the IVPN session. Try again.'],
            !isset($state['address']) => ['stale', 'IVPN did not allocate a compatible WireGuard address. Sign out and try again or import a configuration.'],
            default => ['authenticated', null],
        };
        if ($code === 401 || $code === 601) {
            unset($state['token'], $state['publicKey'], $state['address']);
        }
        $this->writeState($state);
        return $state;
    }

    private static function status(array $state): array
    {
        $status = $state['status'] ?? 'signed_out';
        return [
            'authenticated' => $status === 'authenticated', 'saved' => isset($state['token']),
            'status' => $status, 'activeUntil' => $state['activeUntil'] ?? null,
            'challenge' => $state['challenge'] ?? null, 'message' => $state['message'] ?? null,
        ];
    }

    private static function code(array $response): int
    {
        return is_int($response['status'] ?? null) ? $response['status'] : 0;
    }

    private static function tunnelAddress(mixed $input): ?string
    {
        $ip = is_string($input) ? explode('/', $input, 2)[0] : '';
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && preg_match('/\A172\.(?:1[6-9]|2[0-9]|3[01])\./', $ip) ? $ip . '/32' : null;
    }

    private static function validKey(mixed $key): bool
    {
        $raw = is_string($key) && strlen($key) === 44 ? base64_decode($key, true) : false;
        return $raw !== false && strlen($raw) === 32 && $raw !== str_repeat("\0", 32) && base64_encode($raw) === $key;
    }

    protected function request(string $path, ?array $body = null): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP curl extension is required for IVPN sign-in.');
        }
        $handle = curl_init(self::API . $path);
        $headers = ['Accept: application/json'];
        $response = '';
        $options = [
            CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROXY => '',
            CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_TIMEOUT => 12, CURLOPT_ENCODING => '',
            CURLOPT_USERAGENT => 'Blank VPN (OPNsense)',
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response): int {
                if (strlen($response) + strlen($chunk) > self::MAX_RESPONSE) {
                    return 0;
                }
                $response .= $chunk;
                return strlen($chunk);
            },
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $options[CURLOPT_POSTFIELDS] = json_encode($body, JSON_THROW_ON_ERROR);
        }
        $options[CURLOPT_HTTPHEADER] = $headers;
        if ($handle === false || !curl_setopt_array($handle, $options) || curl_exec($handle) === false) {
            throw new RuntimeException('Could not reach IVPN. Check router DNS, connectivity and time.');
        }
        $http = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $data = json_decode($response, true, 24);
        $code = is_array($data) ? self::code($data) : 0;
        if (is_array($data) && (($http >= 200 && $http < 300)
            || ($http >= 400 && $http < 500 && $http !== 429 && $code > 0 && $code !== 200))) {
            return $data;
        }
        throw new RuntimeException(match ($http) {
            401, 403 => 'IVPN rejected account authorization.',
            429 => 'IVPN is rate limiting requests. Try again shortly.',
            default => 'IVPN returned an unexpected response.',
        }, $http);
    }

    private function locked(callable $operation): mixed
    {
        $this->ensureDirectory();
        $path = $this->path . '.lock';
        $handle = is_link($path) ? false : @fopen($path, 'c');
        if ($handle === false) {
            throw new RuntimeException('Blank VPN could not open the IVPN state lock.');
        }
        try {
            if (!@chmod($path, 0600) || !flock($handle, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('Another IVPN operation is in progress. Try again shortly.');
            }
            return $operation($this->readState());
        } finally {
            fclose($handle);
        }
    }

    private function ensureDirectory(): void
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700) && !is_dir($this->directory)) {
            throw new RuntimeException('The Blank VPN state directory is unavailable.');
        }
        $mode = @fileperms($this->directory);
        if ($mode === false || ($mode & 0077) !== 0 || is_link($this->directory)) {
            throw new RuntimeException('The Blank VPN state directory permissions are unsafe.');
        }
    }

    private function readState(): array
    {
        $path = $this->path . '.json';
        if (!file_exists($path) && !is_link($path)) {
            return [];
        }
        $this->ensureDirectory();
        $mode = @fileperms($path);
        if ($mode === false || ($mode & 0077) !== 0 || is_link($path) || !is_file($path)) {
            throw new RuntimeException('The saved IVPN state has unsafe permissions.');
        }
        $raw = @file_get_contents($path, false, null, 0, 8193);
        $state = $raw === false || strlen($raw) > 8192 ? null : json_decode($raw, true, 12);
        if (!is_array($state) || ($state['version'] ?? null) !== 1 || !is_string($state['account'] ?? null)
            || !self::validKey($state['privateKey'] ?? null)) {
            throw new RuntimeException('Blank VPN could not read the saved IVPN state.');
        }
        return $state;
    }

    private function writeState(array $state): void
    {
        $json = json_encode($state + ['version' => 1], JSON_THROW_ON_ERROR);
        $temp = @tempnam($this->directory, '.ivpn-');
        if ($temp === false) {
            throw new RuntimeException('Blank VPN could not create the IVPN state file.');
        }
        try {
            if (realpath(dirname($temp)) !== realpath($this->directory) || !@chmod($temp, 0600)
                || @file_put_contents($temp, $json) !== strlen($json) || !@rename($temp, $this->path . '.json')) {
                throw new RuntimeException('Blank VPN could not save IVPN state.');
            }
        } finally {
            if (file_exists($temp)) {
                @unlink($temp);
            }
        }
    }

    protected function now(): int
    {
        return time();
    }

    protected function generateKey(): string
    {
        return trim(Resolver::command(['/usr/bin/wg', 'genkey']));
    }

    protected function publicKey(string $privateKey): string
    {
        return (new Mullvad())->derivePublicKey($privateKey);
    }
}
