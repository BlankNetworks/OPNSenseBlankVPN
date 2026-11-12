<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use InvalidArgumentException;
use JsonException;
use RuntimeException;

class Mullvad
{
    private const API = 'https://api.mullvad.net';
    private const TOKEN = '/auth/v1/token';
    private const DEVICE_LIMIT = 5;
    private const ACCOUNT = '/accounts/v1/accounts/me';
    private const DEVICES = '/accounts/v1/devices';
    private const RELAYS = '/www/relays/all';
    private const CACHE_TTL = 21600;
    private const REFRESH_RETRY = 300;
    private const MAX_RESPONSE = 4194304;
    private const DNS = ['10.64.0.1', 'fc00:bbbb:bbbb:bb01::1'];

    public function __construct(private readonly string $dataDirectory = '/var/db/blank-vpn')
    {
    }

    public function relays(bool $refresh = false): array
    {
        $path = $this->dataDirectory . '/mullvad-relays.json';
        $cache = $this->relayCache($path);
        $now = time();
        if (!$refresh && !$this->shouldRefresh($cache, $now)) {
            return $this->catalogStatus($cache, $now);
        }

        try {
            $lock = $this->lock('mullvad-relays');
        } catch (RuntimeException $error) {
            return $this->catalogStatus($cache, $now, $error->getMessage());
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return $this->catalogStatus($cache, $now, 'A Mullvad catalog refresh is in progress.');
            }

            $cache = $this->relayCache($path);
            if (!$refresh && !$this->shouldRefresh($cache, $now)) {
                return $this->catalogStatus($cache, $now);
            }
            try {
                $relays = $this->normalizeRelays($this->request(self::RELAYS));
                $cache = ['relays' => $relays, 'fetchedAt' => time(), 'attemptedAt' => $now, 'error' => null];
                $this->writeJson($path, $cache);
            } catch (RuntimeException $error) {
                $cache['attemptedAt'] = $now;
                $cache['error'] = $error->getMessage();
                try {
                    $this->writeJson($path, $cache);
                } catch (RuntimeException) {
                    // A read-only or full filesystem can still serve the in-memory catalog.
                }
            }
            return $this->catalogStatus($cache, time());
        } finally {
            fclose($lock);
        }
    }

    public function account(string $account): array
    {
        return $this->authenticate($account)['account'];
    }

    public function authenticate(string $account): array
    {
        $auth = $this->authorization($account);
        $details = $this->accountDetails($auth['token']);
        unset($details['id']);
        $devices = $this->devices($auth['token']);
        $details['devices'] = array_map(static fn (array $device): array =>
            array_intersect_key($device, array_flip(['name', 'created'])), $devices);
        $details['availableSlots'] = max(0, $details['maxDevices'] - count($devices));
        $details['canAddDevices'] = $details['canAddDevices'] && $details['availableSlots'] > 0 && !$details['expired'];
        return $auth + ['account' => $details];
    }

    public function verifyBinding(string $account, string $binding): void
    {
        $this->verifyBindingWithToken($this->token($account), $binding);
    }

    public function verifyBindingWithToken(string $token, string $binding): void
    {
        $details = $this->accountDetails($token);
        if (!hash_equals($binding, $this->binding($details['id']))) {
            throw new RuntimeException('That exit is linked to a different Mullvad account.');
        }
        if ($details['expired']) {
            throw new RuntimeException('The Mullvad account has expired. Add time before reusing the exit.');
        }
    }

    private function binding(string $id): string
    {
        $path = $this->dataDirectory . '/mullvad-account-binding.json';
        $lock = $this->lock('mullvad-account-binding');
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('Another Mullvad account operation is running.');
            }
            if (!file_exists($path) && !is_link($path)) {
                $this->writeJson($path, ['key' => bin2hex(random_bytes(32))]);
            }
            $mode = @fileperms($path);
            $key = !is_link($path) && $mode !== false && ($mode & 0077) === 0
                ? ($this->readJson($path)['key'] ?? '') : '';
            if (!is_string($key) || !preg_match('/^[a-f0-9]{64}$/D', $key)) {
                throw new RuntimeException('Blank VPN could not read its account binding key.');
            }
            return hash_hmac('sha256', $id, hex2bin($key));
        } finally {
            fclose($lock);
        }
    }

    public function register(string $account, string $registrationId = ''): array
    {
        return $this->registerWithToken($this->token($account), $registrationId);
    }

    public function registerWithToken(string $token, string $registrationId = ''): array
    {
        if (strlen($registrationId) > 256) {
            throw new InvalidArgumentException('Invalid WireGuard registration identifier.');
        }
        $details = $this->accountDetails($token);
        $binding = $this->binding($details['id']);
        $scope = hash('sha256', $details['id'] . "\0" . $registrationId);
        $name = 'mullvad-registration-' . $scope;
        $path = $this->dataDirectory . '/' . $name . '.json';
        $lock = $this->lock($name);
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('A WireGuard registration for this profile is in progress.');
            }
            $devices = $this->devices($token);
            $privateKey = $this->pendingKey($path);
            if ($privateKey !== null) {
                $publicKey = $this->derivePublicKey($privateKey);
                $registered = $this->findDevice($devices, $publicKey);
                if ($registered !== null) {
                    return $this->identity($token, $scope, $privateKey, $registered) + ['accountBinding' => $binding];
                }
            }
            if ($details['expired']) {
                throw new RuntimeException('The Mullvad account has expired. Add time before registering a device.');
            }
            if (count($devices) >= $details['maxDevices'] || !$details['canAddDevices']) {
                throw new RuntimeException('The Mullvad account cannot add a device. Check the available device slots.');
            }
            if ($privateKey === null) {
                $privateKey = $this->wireGuardKey('genkey');
                $publicKey = $this->derivePublicKey($privateKey);
                $this->writeJson($path, ['privateKey' => $privateKey]);
            }

            try {
                $response = $this->request(self::DEVICES, $token, ['pubkey' => $publicKey, 'hijack_dns' => false]);
                $registered = $this->normalizeDevice($response);
                if (!hash_equals($publicKey, $registered['publicKey'])) {
                    throw new RuntimeException('Mullvad returned an unexpected device key.');
                }
            } catch (RuntimeException $error) {
                // A timeout may arrive after Mullvad accepted the key. Preserve it and reconcile on retry.
                throw new RuntimeException(
                    $error->getMessage() . ' The local key is available for retrying this registration.',
                    (int)$error->getCode()
                );
            }
            return $this->identity($token, $scope, $privateKey, $registered) + ['accountBinding' => $binding];
        } finally {
            fclose($lock);
        }
    }

    public function completeRegistration(string $receipt): void
    {
        if (!preg_match('/^([a-f0-9]{64})\.([a-f0-9]{64})$/D', $receipt, $matches)) {
            throw new InvalidArgumentException('Invalid WireGuard registration receipt.');
        }
        $name = 'mullvad-registration-' . $matches[1];
        $path = $this->dataDirectory . '/' . $name . '.json';
        $lock = $this->lock($name);
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('A WireGuard registration for this profile is in progress.');
            }
            $privateKey = $this->pendingKey($path);
            if (
                $privateKey !== null
                && hash_equals($matches[2], hash('sha256', $this->derivePublicKey($privateKey)))
                && !@unlink($path)
            ) {
                throw new RuntimeException('Could not remove the completed local WireGuard registration record.');
            }
        } finally {
            fclose($lock);
        }
    }

    public function parseConfig(string $text, string $dnsOverride = ''): array
    {
        if (strlen($text) > 16384 || str_contains($text, "\0")) {
            throw new InvalidArgumentException('Invalid WireGuard configuration size or format.');
        }
        $text = preg_replace('/^\xEF\xBB\xBF/', '', $text);
        $fields = [
            'interface' => ['privatekey', 'address', 'dns', 'mtu'],
            'peer' => ['publickey', 'presharedkey', 'allowedips', 'endpoint', 'persistentkeepalive'],
        ];
        $config = [];
        $section = '';
        foreach (preg_split('/\r\n|\n|\r/', $text) as $line) {
            $line = trim(explode('#', $line, 2)[0]);
            if ($line === '' || str_starts_with($line, ';')) {
                continue;
            }
            if (preg_match('/^\[(Interface|Peer)\]$/iD', $line, $match)) {
                $section = strtolower($match[1]);
                if (isset($config[$section])) {
                    throw new InvalidArgumentException('Import requires one WireGuard interface and one peer.');
                }
                $config[$section] = [];
                continue;
            }
            if ($section === '' || !preg_match('/^([a-z]+)\s*=\s*(.+)$/iD', $line, $match)) {
                throw new InvalidArgumentException('Invalid WireGuard configuration line or section.');
            }
            $key = strtolower($match[1]);
            if (!in_array($key, $fields[$section], true) || isset($config[$section][$key])) {
                throw new InvalidArgumentException('The WireGuard configuration includes an unsupported or duplicate directive.');
            }
            $config[$section][$key] = trim($match[2]);
        }

        $interface = $config['interface'] ?? [];
        $peer = $config['peer'] ?? [];
        $privateKey = $interface['privatekey'] ?? '';
        $publicKey = $peer['publickey'] ?? '';
        $presharedKey = $peer['presharedkey'] ?? '';
        if (($presharedKey !== '' && !$this->validKey($presharedKey)) || !$this->validKey($privateKey) || !$this->validKey($publicKey)) {
            throw new InvalidArgumentException('Import requires a valid WireGuard private key and peer public key.');
        }
        $addresses = [4 => '', 6 => ''];
        foreach ($this->commaList($interface['address'] ?? '') as $item) {
            $version = str_contains($item, ':') ? 6 : 4;
            $cidr = $this->cidr($item, $version);
            if ($cidr === '' || $addresses[$version] !== '') {
                throw new InvalidArgumentException('Import supports one tunnel address per IP family in CIDR format.');
            }
            $addresses[$version] = explode('/', $cidr, 2)[0] . ($version === 4 ? '/32' : '/128');
        }
        $allowed = array_unique($this->commaList($peer['allowedips'] ?? ''));
        sort($allowed);
        $v4 = ['0.0.0.0/0'];
        $dual = ['0.0.0.0/0', '::/0'];
        if ($addresses[4] === '' || ($allowed !== $dual && ($allowed !== $v4 || $addresses[6] !== ''))) {
            throw new InvalidArgumentException('Import requires an IPv4 tunnel address and full-tunnel AllowedIPs for each configured family.');
        }

        [$host, $port] = $this->endpoint($peer['endpoint'] ?? '');
        $dns = $this->commaList($dnsOverride !== '' ? $dnsOverride : ($interface['dns'] ?? ''));
        foreach ($dns as $server) {
            if (filter_var($server, FILTER_VALIDATE_IP, $dnsOverride !== '' ? FILTER_FLAG_IPV4 : 0) === false) {
                throw new InvalidArgumentException($dnsOverride !== ''
                    ? 'Enter an IPv4 DNS resolver reachable through this tunnel.'
                    : 'WireGuard DNS entries must be IP addresses.');
            }
        }
        return [
            'privateKey' => $privateKey,
            'publicKey' => $publicKey,
            'address' => $addresses[4],
            'address6' => $addresses[6],
            'host' => $host,
            'port' => $port,
            'presharedKey' => $presharedKey,
            'dns' => array_values(array_unique($dns)),
            'keepalive' => strtolower($peer['persistentkeepalive'] ?? '') === 'off'
                ? 0 : $this->integer($peer['persistentkeepalive'] ?? '0', 0, 65535, 'keepalive'),
            'mtu' => isset($interface['mtu']) ? $this->integer($interface['mtu'], 1280, 9000, 'MTU') : null,
        ];
    }

    private function token(string $account): string
    {
        return $this->authorization($account)['token'];
    }

    private function authorization(string $account): array
    {
        $account = preg_replace('/[ \t\r\n-]+/', '', $account);
        if (!preg_match('/^[0-9]{16}$/D', $account)) {
            throw new InvalidArgumentException('Enter the 16-digit Mullvad account number.');
        }
        $response = $this->request(self::TOKEN, null, ['account_number' => $account]);
        $token = $response['access_token'] ?? null;
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9._~+\/=\-]{10,2048}$/D', $token)) {
            throw new RuntimeException('Mullvad returned an unexpected authorization response.');
        }
        $expiry = is_string($response['expiry'] ?? null) ? strtotime($response['expiry']) : false;
        if ($expiry === false || $expiry <= time()) {
            throw new RuntimeException('Mullvad returned an expired or invalid authorization token.');
        }
        return ['token' => $token, 'expires' => $expiry];
    }

    private function accountDetails(string $token): array
    {
        $data = $this->request(self::ACCOUNT, $token);
        $expiresAt = $data['expiry'] ?? null;
        $expires = is_string($expiresAt) ? strtotime($expiresAt) : false;
        $maxDevices = $data['max_devices'] ?? self::DEVICE_LIMIT;
        $canAdd = $data['can_add_devices'] ?? true;
        $id = $data['id'] ?? '';
        if (!is_string($id) || !preg_match('/^[a-zA-Z0-9_-]{1,128}$/D', $id) || $expires === false || !is_int($maxDevices) || $maxDevices < 1 || !is_bool($canAdd)) {
            throw new RuntimeException('Mullvad returned an unexpected account status.');
        }
        return [
            'id' => $id,
            'expired' => $expires <= time(),
            'expiresAt' => gmdate(DATE_ATOM, $expires),
            'maxDevices' => $maxDevices,
            'canAddDevices' => $canAdd,
        ];
    }

    private function devices(string $token): array
    {
        $devices = $this->request(self::DEVICES, $token);
        if (!array_is_list($devices)) {
            throw new RuntimeException('Mullvad returned an unexpected device list.');
        }
        return array_map($this->normalizeDevice(...), $devices);
    }

    private function normalizeDevice(mixed $device): array
    {
        if (!is_array($device)) {
            throw new RuntimeException('Mullvad returned an unexpected device record.');
        }
        $id = $device['id'] ?? '';
        $publicKey = $device['pubkey'] ?? '';
        if (!is_string($id) || !$this->uuid($id) || !$this->validKey($publicKey)) {
            throw new RuntimeException('Mullvad returned an unexpected device record.');
        }
        return [
            'id' => $id,
            'name' => $this->label($device['name'] ?? null) ?: 'Unnamed device',
            'publicKey' => $publicKey,
            'address' => $this->cidr($device['ipv4_address'] ?? '', 4),
            'address6' => $this->cidr($device['ipv6_address'] ?? '', 6),
            'created' => $this->label($device['created'] ?? null),
        ];
    }

    private function findDevice(array $devices, string $key): ?array
    {
        foreach ($devices as $device) {
            if (hash_equals($key, $device['publicKey'])) {
                return $device;
            }
        }
        return null;
    }

    private function identity(string $token, string $scope, string $privateKey, array $device): array
    {
        if ($device['address'] === '' || $device['address6'] === '') {
            $current = $this->normalizeDevice($this->request(self::DEVICES . '/' . $device['id'], $token));
            if (!hash_equals($device['publicKey'], $current['publicKey']) || $current['address'] === '' || $current['address6'] === '') {
                throw new RuntimeException('Mullvad did not provide the assigned WireGuard addresses. Retry this registration.');
            }
            $device = $current;
        }
        return $device + [
            'privateKey' => $privateKey,
            'dns' => self::DNS,
            'registrationReceipt' => $scope . '.' . hash('sha256', $device['publicKey']),
        ];
    }

    public function derivePublicKey(string $privateKey): string
    {
        if (!$this->validKey($privateKey)) {
            throw new InvalidArgumentException('Invalid WireGuard private key.');
        }
        return $this->wireGuardKey('pubkey', $privateKey);
    }

    protected function wireGuardKey(string $command, string $privateKey = ''): string
    {
        $process = @proc_open(
            ['/usr/bin/wg', $command],
            [['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($process)) {
            throw new RuntimeException('Could not run the native WireGuard key utility.');
        }
        $input = $privateKey === '' ? '' : $privateKey . "\n";
        $written = $input === '' ? 0 : @fwrite($pipes[0], $input);
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1], 128);
        fclose($pipes[1]);
        $result = proc_close($process);
        $key = is_string($output) ? trim($output) : '';
        if ($result !== 0 || $written !== strlen($input) || !$this->validKey($key)) {
            throw new RuntimeException('The native WireGuard key utility could not generate the requested key.');
        }
        return $key;
    }

    private function normalizeRelays(array $data): array
    {
        if (!array_is_list($data)) {
            throw new RuntimeException('Mullvad returned an unexpected relay catalog.');
        }
        $relays = [];
        foreach ($data as $relay) {
            if (!is_array($relay) || !is_string($relay['type'] ?? null)) {
                throw new RuntimeException('Mullvad returned an unexpected relay record.');
            }
            if ($relay['type'] !== 'wireguard') {
                continue;
            }
            $hostname = $relay['hostname'] ?? null;
            $publicKey = $relay['pubkey'] ?? null;
            $ipv4 = $relay['ipv4_addr_in'] ?? null;
            $ipv6 = $relay['ipv6_addr_in'] ?? '';
            $ipv6 = is_string($ipv6) ? trim($ipv6, '[]') : '';
            $active = $relay['active'] ?? null;
            if (
                !is_string($hostname) || !preg_match('/^[a-z0-9][a-z0-9-]{0,62}$/D', $hostname)
                || isset($relays[$hostname]) || !$this->validKey($publicKey) || !is_bool($active)
                || !is_string($ipv4) || filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE) === false
                || ($ipv6 !== '' && filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_GLOBAL_RANGE) === false)
            ) {
                throw new RuntimeException('Mullvad returned an invalid WireGuard relay record.');
            }
            $countryCode = $this->label($relay['country_code'] ?? null);
            $cityCode = $this->label($relay['city_code'] ?? null);
            $relays[$hostname] = [
                'id' => $hostname,
                'hostname' => $hostname,
                'country' => $this->label($relay['country_name'] ?? null) ?: $countryCode,
                'countryCode' => $countryCode,
                'city' => $this->label($relay['city_name'] ?? null) ?: $cityCode,
                'cityCode' => $cityCode,
                'ipv4' => $ipv4,
                'ipv6' => $ipv6,
                'publicKey' => $publicKey,
                'port' => 51820,
                'active' => $active,
            ];
        }
        if ($relays === []) {
            throw new RuntimeException('Mullvad returned no WireGuard relays.');
        }
        ksort($relays, SORT_STRING);
        return array_values($relays);
    }

    protected function request(string $path, ?string $token = null, ?array $body = null): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP curl extension is required for Mullvad API requests.');
        }
        $curl = curl_init(self::API . $path);
        $headers = ['Accept: application/json'];
        if ($token !== null) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        $response = '';
        $options = [
            CURLOPT_PROTOCOLS_STR => 'https',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_PROXY => '',
            CURLOPT_ENCODING => '',
            CURLOPT_USERAGENT => 'Blank VPN (OPNsense)',
            CURLOPT_WRITEFUNCTION => static function ($handle, string $data) use (&$response): int {
                if (strlen($response) + strlen($data) > self::MAX_RESPONSE) {
                    return 0;
                }
                $response .= $data;
                return strlen($data);
            },
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = json_encode($body, JSON_THROW_ON_ERROR);
        }
        $options[CURLOPT_HTTPHEADER] = $headers;
        if ($curl === false || !curl_setopt_array($curl, $options) || curl_exec($curl) === false) {
            throw new RuntimeException('Could not reach Mullvad. Check the router’s DNS, WAN connectivity, and clock.');
        }
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if ($path === self::RELAYS && $token === null && $body === null && in_array($status, [301, 302, 307, 308], true)) {
            return $this->request(self::RELAYS . '/');
        }
        $data = json_decode($response, true, 32);
        if ($status < 200 || $status >= 300) {
            $code = $data['code'] ?? $data['type'] ?? '';
            $code = is_string($code) ? strtoupper(str_replace('-', '_', basename($code))) : '';
            $message = match ($code) {
                'INVALID_ACCOUNT' => 'Mullvad rejected the account number.',
                'ACCOUNT_EXPIRED' => 'The Mullvad account has expired.',
                'MAX_DEVICES_REACHED' => 'The Mullvad account has no available device slots.',
                'PUBKEY_IN_USE' => 'Mullvad reports that the WireGuard public key is in use.',
                default => match ($status) {
                    401, 403 => 'Mullvad rejected account authorization.',
                    429 => 'Mullvad is rate limiting requests. Try again shortly.',
                    default => 'Mullvad returned HTTP ' . $status . '.',
                },
            };
            throw new RuntimeException($message, $status);
        }
        if (!is_array($data)) {
            throw new RuntimeException('Mullvad returned an unreadable API response.');
        }
        return $data;
    }

    private function relayCache(string $path): array
    {
        $data = $this->readJson($path);
        if (
            $data === null || !is_array($data['relays'] ?? null) || !is_int($data['attemptedAt'] ?? null)
            || !array_key_exists('fetchedAt', $data) || ($data['fetchedAt'] !== null && !is_int($data['fetchedAt']))
            || !array_key_exists('error', $data) || ($data['error'] !== null && !is_string($data['error']))
        ) {
            return ['relays' => [], 'fetchedAt' => null, 'attemptedAt' => 0, 'error' => null];
        }
        return $data;
    }

    private function shouldRefresh(array $cache, int $now): bool
    {
        if ($cache['error'] !== null && $cache['attemptedAt'] + self::REFRESH_RETRY > $now) {
            return false;
        }
        return $cache['fetchedAt'] === null || $cache['fetchedAt'] + self::CACHE_TTL <= $now;
    }

    private function catalogStatus(array $cache, int $now, ?string $error = null): array
    {
        $error ??= $cache['error'];
        return [
            'relays' => $cache['relays'],
            'fetchedAt' => $cache['fetchedAt'],
            'stale' => $error !== null || $cache['fetchedAt'] === null || $cache['fetchedAt'] + self::CACHE_TTL <= $now,
            'error' => $error,
        ];
    }

    private function lock(string $name)
    {
        if (!is_dir($this->dataDirectory) && !@mkdir($this->dataDirectory, 0700, true) && !is_dir($this->dataDirectory)) {
            throw new RuntimeException('Could not create the Blank VPN data directory.');
        }
        $permissions = @fileperms($this->dataDirectory);
        if ($permissions === false || ($permissions & 0077) !== 0 || is_link($this->dataDirectory)) {
            throw new RuntimeException('The Blank VPN data directory must be private.');
        }
        $path = $this->dataDirectory . '/' . $name . '.lock';
        $lock = is_link($path) ? false : @fopen($path, 'c');
        if ($lock === false || !@chmod($path, 0600)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new RuntimeException('Could not open the Blank VPN data lock.');
        }
        return $lock;
    }

    private function pendingKey(string $path): ?string
    {
        if (!file_exists($path) && !is_link($path)) {
            return null;
        }
        $permissions = @fileperms($path);
        $key = !is_link($path) && $permissions !== false && ($permissions & 0077) === 0
            ? $this->readJson($path)['privateKey'] ?? null : null;
        if (!$this->validKey($key)) {
            throw new RuntimeException('The pending WireGuard key could not be read. Check the Blank VPN data directory.');
        }
        return $key;
    }

    private function readJson(string $path): ?array
    {
        $bytes = @file_get_contents($path, false, null, 0, self::MAX_RESPONSE + 1);
        if ($bytes === false || strlen($bytes) > self::MAX_RESPONSE) {
            return null;
        }
        $data = json_decode($bytes, true, 32);
        return is_array($data) ? $data : null;
    }

    private function writeJson(string $path, array $data): void
    {
        try {
            $bytes = json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (JsonException) {
            throw new RuntimeException('Could not encode Blank VPN data.');
        }
        $temporary = @tempnam($this->dataDirectory, '.mullvad-');
        if ($temporary === false) {
            throw new RuntimeException('Could not create the Blank VPN data file.');
        }
        try {
            if (
                realpath(dirname($temporary)) !== realpath($this->dataDirectory) || !@chmod($temporary, 0600)
                || @file_put_contents($temporary, $bytes) !== strlen($bytes) || !@rename($temporary, $path)
            ) {
                throw new RuntimeException('Could not save Blank VPN data.');
            }
        } finally {
            if (file_exists($temporary)) {
                @unlink($temporary);
            }
        }
    }

    private function validKey(mixed $key): bool
    {
        if (!is_string($key) || strlen($key) !== 44) {
            return false;
        }
        $raw = base64_decode($key, true);
        return $raw !== false && strlen($raw) === 32 && base64_encode($raw) === $key && $raw !== str_repeat("\0", 32);
    }

    private function cidr(mixed $value, int $version): string
    {
        if (!is_string($value) || !preg_match('/^([^\/]+)\/([0-9]{1,3})$/D', $value, $parts)) {
            return '';
        }
        $maximum = $version === 4 ? 32 : 128;
        $flag = $version === 4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
        $prefix = (int)$parts[2];
        if ($prefix < 1 || $prefix > $maximum || filter_var($parts[1], FILTER_VALIDATE_IP, $flag) === false) {
            return '';
        }
        return inet_ntop(inet_pton($parts[1])) . '/' . $prefix;
    }

    private function endpoint(string $value): array
    {
        if (!preg_match('/^(.+):([0-9]{1,5})$/D', $value, $parts)) {
            throw new InvalidArgumentException('The WireGuard peer needs an endpoint host and UDP port.');
        }
        $host = strtolower($parts[1]);
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw new InvalidArgumentException('Invalid WireGuard IPv6 endpoint.');
            }
        }
        if (
            filter_var($host, FILTER_VALIDATE_IP) === false
            && (!str_contains($host, '.') || preg_match('/^[0-9.]+$/D', $host)
                || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
        ) {
            throw new InvalidArgumentException('Invalid WireGuard endpoint host.');
        }
        return [$host, $this->integer($parts[2], 1, 65535, 'UDP port')];
    }

    private function integer(string $value, int $minimum, int $maximum, string $label): int
    {
        if (!preg_match('/^[0-9]{1,5}$/D', $value) || (int)$value < $minimum || (int)$value > $maximum) {
            throw new InvalidArgumentException('Invalid WireGuard ' . $label . '.');
        }
        return (int)$value;
    }

    private function commaList(string $value): array
    {
        return $value === '' ? [] : array_map('trim', explode(',', $value));
    }

    private function uuid(string $value): bool
    {
        return preg_match('/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/iD', $value) === 1;
    }

    private function label(mixed $value): string
    {
        return is_string($value) && strlen($value) <= 128 && !preg_match('/[\x00-\x1F\x7F]/', $value)
            ? $value
            : '';
    }
}
