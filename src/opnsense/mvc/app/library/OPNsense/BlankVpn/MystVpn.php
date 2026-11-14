<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

class MystVpn
{
    private const API = 'https://api.mysteriumvpn.com/api/v1';
    private const APPROVAL = 'https://app.mysteriumvpn.com/oauth/authorize';
    private const ACTIVATION = '/auth/activation';
    private const TOKEN = '/oauth/token';
    private const CLIENT = 'cli';
    private const ACTIVATION_TTL = 300;
    private const POLL_INTERVAL = 10;
    private const CATALOG_TTL = 900;
    private const PROVISION_TTL = 300;
    private const MAX_RESPONSE = 1048576;
    private readonly string $path;

    public function __construct(string $user, private readonly string $dataDirectory = '/var/db/blank-vpn')
    {
        if ($user === '' || strlen($user) > 128 || preg_match('/[\x00-\x1f\x7f]/', $user)) {
            throw new DomainException('Mysterium sign-in requires an authenticated OPNsense user.');
        }
        $this->path = $dataDirectory . '/mysterium-' . hash('sha256', $user);
    }

    public function authStatus(): array
    {
        return $this->status($this->readState());
    }

    public function beginAuth(): array
    {
        return $this->locked(function (array $state): array {
            if ($this->status($state)['pending']) {
                return $this->status($state);
            }
            $id = self::uuid();
            $this->request('POST', self::ACTIVATION, null, ['id' => $id], [200, 204], false);
            $state['activation'] = ['id' => $id, 'expiresAt' => $this->now() + self::ACTIVATION_TTL, 'lastPoll' => 0];
            $this->writeState($state);
            return $this->status($state);
        });
    }

    public function pollAuth(): array
    {
        return $this->locked(function (array $state): array {
            $status = $this->status($state);
            if (!$status['pending']) {
                return $status;
            }
            $activation = $state['activation'];
            if ($activation['lastPoll'] + self::POLL_INTERVAL > $this->now()) {
                return $status;
            }
            $state['activation']['lastPoll'] = $this->now();
            $this->writeState($state);
            try {
                $result = $this->request('GET', self::ACTIVATION . '/' . $activation['id']);
            } catch (RuntimeException $error) {
                if (!in_array($error->getCode(), [404, 410], true)) {
                    throw $error;
                }
                return $this->expireActivation($state);
            }
            if (($result['id'] ?? null) !== $activation['id'] || !is_bool($result['valid'] ?? null)) {
                throw new RuntimeException('Mysterium returned an unexpected browser approval response.');
            }
            if (!$result['valid'] || $activation['expiresAt'] <= $this->now()) {
                return $this->expireActivation($state);
            }
            if (($result['token'] ?? null) === null) {
                return $status;
            }
            $newTokens = $this->tokens($result['token']);
            $oldUser = $state['tokens']['userId'] ?? null;
            if ($oldUser === null || $oldUser !== $newTokens['userId']) {
                $state = [];
            }
            unset($state['activation']);
            $state['tokens'] = $newTokens;
            $this->writeState($state);
            return $this->status($state);
        });
    }

    public function logout(): void
    {
        $this->locked(function (): void {
            $file = $this->path . '.json';
            if (is_file($file) && !@unlink($file)) {
                throw new RuntimeException('Blank VPN & Proxy could not remove the saved Mysterium credentials.');
            }
        });
    }

    public function locations(string $ipType = 'hosting', bool $refresh = false): array
    {
        $ipType = self::ipType($ipType);
        return $this->locked(fn (array $state): array => $this->catalog($state, $ipType, $refresh));
    }

    public function provision(string $country, string $ipType = 'hosting', string $region = '', string $dnsOverride = ''): array
    {
        $country = self::country($country);
        $ipType = self::ipType($ipType);
        if ($region !== '' && self::region($region) === '') {
            throw new DomainException('Choose a valid Mysterium city or state.');
        }
        if ($dnsOverride !== '' && !self::usableDns($dnsOverride)) {
            throw new DomainException('Enter an IPv4 DNS resolver reachable through the Mysterium tunnel.');
        }
        return $this->locked(function (array $state) use ($country, $ipType, $region, $dnsOverride): array {
            $this->requireTokens($state);
            $target = self::locationId($country, $ipType, $region);
            $attempt = $state['attempt'] ?? [];
            if (($attempt['target'] ?? '') === $target && ($attempt['expiresAt'] ?? 0) > $this->now()) {
                return $this->provisioned($state['privateKey'], $attempt, $dnsOverride);
            }

            $catalog = $this->catalog($state, $ipType, false);
            if ($catalog['stale'] || !in_array($target, array_column($catalog['locations'], 'id'), true)) {
                throw new DomainException('Refresh the Mysterium location list and choose an available location.');
            }
            $previous = $state['target'] ?? null;
            $privateKey = $state['privateKey'] ?? $this->generateKey();
            $publicKey = $this->publicKey($privateKey);
            $reset = $previous !== null && $previous !== $target && isset($state['privateKey']);
            $state['target'] = $target;
            $state['privateKey'] = $privateKey;
            unset($state['attempt']);
            $this->writeState($state);

            $body = [
                'public_key' => $publicKey,
                'country' => $country,
                'ip_type' => $ipType,
                'os_type' => 'linux-cli',
                'cli_version' => 'dev',
                'os_version' => 'OPNsense/' . php_uname('r'),
                // Only replace an explicitly changed target for our saved key.
                'reset_connection' => $reset,
            ];
            if ($region !== '') {
                $body['city'] = $region;
            }
            $response = $this->authorized($state, 'POST', '/connection/connect', $body);
            if (($response['limit_exceeded'] ?? false) === true) {
                throw new DomainException('Mysterium reports a connection limit for this account.');
            }
            $sessionId = $response['id'] ?? null;
            $template = $response['wg_config'] ?? null;
            if (
                !is_string($sessionId) || !preg_match('/^[A-Za-z0-9_-]{1,128}$/D', $sessionId)
                || !is_string($template) || strlen($template) > 16384
            ) {
                throw new RuntimeException('Mysterium returned an unexpected WireGuard session response.');
            }
            if (
                (isset($response['country']) && (!is_string($response['country']) || strcasecmp($response['country'], $country) !== 0))
                || (isset($response['ip_type']) && $response['ip_type'] !== $ipType)
                || ($region !== '' && isset($response['city']) && $response['city'] !== $region)
            ) {
                throw new RuntimeException('Mysterium returned a WireGuard session for a different location.');
            }
            $attempt = [
                'target' => $target, 'sessionId' => $sessionId, 'template' => $template,
                'country' => $country, 'region' => $region, 'ipType' => $ipType,
                'exitIp' => self::exitIp($response['exit_ip'] ?? null),
                'expiresAt' => $this->now() + self::PROVISION_TTL,
                'receipt' => bin2hex(random_bytes(24)),
            ];
            // Keep a validated response for a retried native profile transaction.
            $config = $this->provisioned($privateKey, $attempt, $dnsOverride);
            $state['attempt'] = $attempt;
            $this->writeState($state);
            return $config;
        });
    }

    public function completeProvision(string $receipt): void
    {
        if (!preg_match('/^[a-f0-9]{48}$/D', $receipt)) {
            throw new DomainException('Invalid Mysterium provisioning receipt.');
        }
        $this->locked(function (array $state) use ($receipt): void {
            if (hash_equals($state['attempt']['receipt'] ?? '', $receipt)) {
                unset($state['attempt']);
                $this->writeState($state);
            }
        });
    }

    private function provisioned(string $privateKey, array $attempt, string $dnsOverride): array
    {
        $template = $attempt['template'];
        if (
            strlen($template) > 16384 || substr_count($template, '%private_key%') !== 1
            || preg_match('/^\h*PrivateKey\h*=\h*%private_key%\h*(?:#.*)?\r?$/mi', $template) !== 1
        ) {
            throw new RuntimeException('Mysterium did not return a compatible WireGuard configuration template.');
        }
        try {
            $config = (new Mullvad())->parseConfig(str_replace('%private_key%', $privateKey, $template), $dnsOverride);
        } catch (\InvalidArgumentException) {
            throw new RuntimeException('The Mysterium WireGuard template is incompatible with the router.');
        }
        $host = $config['host'];
        $ip = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $host : $this->resolveIpv4($host);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE)) {
            throw new RuntimeException('Mysterium did not return a public IPv4 WireGuard endpoint.');
        }
        $config['dns'] = array_values(array_filter($config['dns'], self::usableDns(...)));
        return $config + [
            'ipv4' => $ip,
            'identityPublicKey' => $this->publicKey($privateKey),
            'country' => $attempt['country'],
            'region' => $attempt['region'],
            'ipType' => $attempt['ipType'],
            'sessionId' => $attempt['sessionId'],
            'exitIp' => $attempt['exitIp'],
            'provisionReceipt' => $attempt['receipt'],
        ];
    }

    private function catalog(array &$state, string $ipType, bool $refresh): array
    {
        $this->requireTokens($state);
        $cached = $state['catalog'][$ipType] ?? ['locations' => [], 'fetchedAt' => null];
        if (!$refresh && $cached['fetchedAt'] !== null && $cached['fetchedAt'] + self::CATALOG_TTL > $this->now()) {
            return $cached + ['stale' => false, 'error' => null];
        }
        try {
            $response = $this->authorized($state, 'GET', '/connection/config/locations?ip_type=' . $ipType);
            $entry = ['locations' => self::normalizeLocations($response, $ipType), 'fetchedAt' => $this->now()];
            $state['catalog'][$ipType] = $entry;
            $this->writeState($state);
            return $entry + ['stale' => false, 'error' => null];
        } catch (RuntimeException $error) {
            if (in_array($error->getCode(), [401, 403], true)) {
                throw $error;
            }
            return $cached + ['stale' => true, 'error' => $error->getMessage()];
        }
    }

    private static function normalizeLocations(array $response, string $ipType): array
    {
        if (!array_is_list($response)) {
            throw new RuntimeException('Mysterium returned an unexpected location catalog.');
        }
        $locations = [];
        foreach ($response as $entry) {
            if (!is_array($entry) || !is_string($entry['country'] ?? null) || !preg_match('/^[a-z]{2}$/iD', $entry['country'])) {
                throw new RuntimeException('Mysterium returned an invalid country record.');
            }
            if (($entry['is_available'] ?? true) !== true) {
                continue;
            }
            $country = strtoupper($entry['country']);
            $label = self::region($entry['translations']['en'] ?? '') ?: $country;
            $cities = $entry['cities'] ?? [];
            if (!is_array($cities) || !array_is_list($cities)) {
                throw new RuntimeException('Mysterium returned an invalid city and state list.');
            }
            $regions = [''];
            foreach ($cities as $city) {
                if (is_array($city) && ($city['is_available'] ?? true) === true) {
                    $region = self::region($city['city'] ?? '');
                    if ($region !== '') {
                        $regions[] = $region;
                    }
                }
            }
            foreach ($regions as $region) {
                $id = self::locationId($country, $ipType, $region);
                $name = $region === '' ? $label : $label . ' · ' . $region;
                $locations[$id] = [
                    'id' => $id, 'name' => strlen($name) <= 64 ? $name : $country . ' · ' . $region,
                    'countryCode' => $country, 'country' => $label, 'city' => $region, 'region' => $region, 'ipType' => $ipType,
                ];
            }
        }
        uasort($locations, static fn (array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));
        return array_values($locations);
    }

    private function authorized(array &$state, string $method, string $path, ?array $body = null): array
    {
        $tokens = $this->requireTokens($state);
        if ($tokens['expiresAt'] <= $this->now()) {
            $tokens = $this->refreshTokens($state, $tokens);
            return $this->request($method, $path, $tokens['accessToken'], $body);
        }
        try {
            return $this->request($method, $path, $tokens['accessToken'], $body);
        } catch (RuntimeException $error) {
            if ($error->getCode() !== 401) {
                throw $error;
            }
        }
        $tokens = $this->refreshTokens($state, $tokens);
        return $this->request($method, $path, $tokens['accessToken'], $body);
    }

    private function refreshTokens(array &$state, array $previous): array
    {
        try {
            $result = $this->request('POST', self::TOKEN, null, [
                'grant_type' => 'refresh_token', 'client_id' => self::CLIENT, 'refresh_token' => $previous['refreshToken'],
            ]);
        } catch (RuntimeException $error) {
            if (in_array($error->getCode(), [400, 401, 403], true)) {
                $state = array_intersect_key($state, ['activation' => true]);
                $this->writeState($state);
                throw new RuntimeException('Mysterium sign-in has expired. Approve a new sign-in in your browser.', 401);
            }
            throw $error;
        }
        $tokens = $this->tokens($result);
        if ($tokens['userId'] !== null && $previous['userId'] !== null && $tokens['userId'] !== $previous['userId']) {
            throw new RuntimeException('Mysterium returned a token for an unexpected account.');
        }
        $tokens['userId'] ??= $previous['userId'];
        $state['tokens'] = $tokens;
        $this->writeState($state);
        return $tokens;
    }

    private function requireTokens(array $state): array
    {
        if (!isset($state['tokens'])) {
            throw new DomainException('Sign in to Mysterium in your browser first.');
        }
        return $state['tokens'];
    }

    private function tokens(mixed $payload): array
    {
        $access = is_array($payload) ? ($payload['access_token'] ?? null) : null;
        $refresh = is_array($payload) ? ($payload['refresh_token'] ?? null) : null;
        $type = is_array($payload) ? ($payload['token_type'] ?? null) : null;
        $expires = is_array($payload) ? ($payload['expires_in'] ?? null) : null;
        if (
            !is_string($access) || !preg_match('/^[A-Za-z0-9._~+\/=-]{1,8192}$/D', $access)
            || !is_string($refresh) || !preg_match('/^[A-Za-z0-9._~+\/=-]{1,8192}$/D', $refresh)
            || !is_string($type) || strcasecmp($type, 'Bearer') !== 0
            || !is_int($expires) || $expires < 1 || $expires > 31536000
        ) {
            throw new RuntimeException('Mysterium returned an unexpected sign-in token response.');
        }
        $user = $payload['user_id'] ?? null;
        return [
            'accessToken' => $access, 'refreshToken' => $refresh, 'expiresAt' => $this->now() + $expires,
            'userId' => is_string($user) && preg_match('/^[A-Za-z0-9_.@-]{1,128}$/D', $user) ? $user : null,
        ];
    }

    private function expireActivation(array $state): array
    {
        $state['activation']['expiresAt'] = 0;
        $this->writeState($state);
        return $this->status($state);
    }

    private function status(array $state): array
    {
        $activation = $state['activation'] ?? null;
        $pending = $activation !== null && $activation['expiresAt'] > $this->now();
        $authenticated = isset($state['tokens']);
        $status = $pending ? 'pending' : ($authenticated ? 'authenticated' : ($activation === null ? 'signed_out' : 'expired'));
        return [
            'status' => $status,
            'authenticated' => $authenticated,
            'pending' => $pending,
            'approvalUrl' => $pending ? self::APPROVAL . '?' . http_build_query([
                'response_type' => 'activation_none', 'client_id' => self::CLIENT, 'request_id' => $activation['id'],
            ], '', '&', PHP_QUERY_RFC3986) : null,
            'expiresAt' => $pending ? $activation['expiresAt'] : null,
        ];
    }

    protected function request(
        string $method,
        string $path,
        ?string $token = null,
        ?array $body = null,
        array $accepted = [200],
        bool $decode = true
    ): array {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP curl extension is required for Mysterium sign-in.');
        }
        $handle = curl_init(self::API . $path);
        $headers = ['Accept: application/json'];
        if ($token !== null) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        $output = '';
        $options = [
            CURLOPT_PROTOCOLS_STR => 'https',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROXY => '',
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_ENCODING => '',
            CURLOPT_USERAGENT => 'Blank VPN (OPNsense)',
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$output): int {
                if (strlen($output) + strlen($chunk) > self::MAX_RESPONSE) {
                    return 0;
                }
                $output .= $chunk;
                return strlen($chunk);
            },
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $options[CURLOPT_POSTFIELDS] = json_encode($body, JSON_THROW_ON_ERROR);
        }
        $options[CURLOPT_HTTPHEADER] = $headers;
        if ($handle === false || !curl_setopt_array($handle, $options) || curl_exec($handle) === false) {
            throw new RuntimeException('Could not reach Mysterium. Check the router’s WAN, DNS and clock.');
        }
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        if (!in_array($status, $accepted, true)) {
            $message = match ($status) {
                401 => 'Mysterium rejected account authorization.',
                403 => 'Mysterium denied access. Check the account and subscription.',
                429 => 'Mysterium is rate limiting requests. Try again shortly.',
                default => 'Mysterium returned HTTP ' . $status . '.',
            };
            throw new RuntimeException($message, $status);
        }
        if (!$decode) {
            return [];
        }
        $data = json_decode($output, true, 24);
        if (!is_array($data)) {
            throw new RuntimeException('Mysterium returned an unreadable API response.');
        }
        return $data;
    }

    private function locked(callable $operation): mixed
    {
        $this->stateDirectory();
        $path = $this->path . '.lock';
        if (is_link($path)) {
            throw new RuntimeException('The Mysterium state lock is invalid.');
        }
        $lock = @fopen($path, 'c');
        if ($lock === false) {
            throw new RuntimeException('Could not open the Mysterium state lock.');
        }
        try {
            if (!@chmod($path, 0600) || !flock($lock, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('Another Mysterium operation is in progress. Try again shortly.');
            }
            return $operation($this->readState());
        } finally {
            fclose($lock);
        }
    }

    private function stateDirectory(): void
    {
        if (!is_dir($this->dataDirectory) && !@mkdir($this->dataDirectory, 0700) && !is_dir($this->dataDirectory)) {
            throw new RuntimeException('The Blank VPN & Proxy state directory is unavailable.');
        }
        $mode = @fileperms($this->dataDirectory);
        if ($mode === false || ($mode & 0077) !== 0 || is_link($this->dataDirectory)) {
            throw new RuntimeException('The Blank VPN & Proxy state directory permissions are unsafe.');
        }
    }

    private function readState(): array
    {
        $path = $this->path . '.json';
        if (!file_exists($path) && !is_link($path)) {
            return [];
        }
        $this->stateDirectory();
        $mode = @fileperms($path);
        if ($mode === false || ($mode & 0077) !== 0 || is_link($path) || !is_file($path)) {
            throw new RuntimeException('The saved Mysterium state has unsafe permissions.');
        }
        $raw = @file_get_contents($path, false, null, 0, self::MAX_RESPONSE + 1);
        $state = $raw === false || strlen($raw) > self::MAX_RESPONSE ? null : json_decode($raw, true, 24);
        if (!is_array($state) || ($state['version'] ?? null) !== 1) {
            throw new RuntimeException('Blank VPN & Proxy could not read the saved Mysterium state.');
        }
        return $state;
    }

    private function writeState(array $state): void
    {
        $state['version'] = 1;
        $json = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (strlen($json) > self::MAX_RESPONSE) {
            throw new RuntimeException('The Mysterium state exceeds the supported size.');
        }
        $temp = @tempnam($this->dataDirectory, '.mysterium-');
        if ($temp === false) {
            throw new RuntimeException('Blank VPN & Proxy could not create the Mysterium state file.');
        }
        try {
            if (
                realpath(dirname($temp)) !== realpath($this->dataDirectory) || !@chmod($temp, 0600)
                || @file_put_contents($temp, $json) !== strlen($json) || !@rename($temp, $this->path . '.json')
            ) {
                throw new RuntimeException('Blank VPN & Proxy could not save Mysterium state.');
            }
        } finally {
            if (file_exists($temp)) {
                @unlink($temp);
            }
        }
    }

    protected function generateKey(): string
    {
        $key = trim(Resolver::command(['/usr/bin/wg', 'genkey']));
        if (!preg_match('/^[A-Za-z0-9+\/]{43}=$/D', $key)) {
            throw new RuntimeException('The router could not generate a WireGuard key.');
        }
        return $key;
    }

    protected function publicKey(string $key): string
    {
        return (new Mullvad())->derivePublicKey($key);
    }

    protected function resolveIpv4(string $host): string
    {
        return str_contains($host, ':') ? '' : gethostbyname($host);
    }

    protected function now(): int
    {
        return time();
    }

    private static function country(string $country): string
    {
        if (!preg_match('/^[a-z]{2}$/iD', $country)) {
            throw new DomainException('Choose a two-letter Mysterium country code.');
        }
        return strtoupper($country);
    }

    private static function region(mixed $value): string
    {
        return is_string($value) && strlen($value) <= 56 && preg_match('/^[\p{L}\p{M}\p{N} ._\x{27}\x{2019}-]+$/uD', $value)
            && trim($value) === $value ? $value : '';
    }

    private static function ipType(string $ipType): string
    {
        if (!in_array($ipType, ['hosting', 'residential'], true)) {
            throw new DomainException('Choose a Mysterium hosting or residential IP.');
        }
        return $ipType;
    }

    private static function locationId(string $country, string $ipType, string $region): string
    {
        $id = $ipType . '-' . strtolower($country);
        return $region === '' ? $id : $id . '-' . substr(hash('sha256', $region), 0, 24);
    }

    private static function exitIp(mixed $value): string
    {
        return is_string($value) && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false ? $value : '';
    }

    private static function usableDns(string $address): bool
    {
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $first = (int)strtok($address, '.');
        return $first !== 0 && $first !== 127 && $first < 224;
    }

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
