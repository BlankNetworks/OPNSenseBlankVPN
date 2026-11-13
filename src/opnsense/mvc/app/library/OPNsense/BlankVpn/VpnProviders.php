<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

class VpnProviders
{
    public const CATALOG = [
        'airvpn' => ['name' => 'AirVPN', 'guide' => 'https://airvpn.org/generator/'],
        'azire' => ['name' => 'AzireVPN', 'login' => 'token', 'guide' => 'https://www.azirevpn.com/docs/api/authentication'],
        'express' => ['name' => 'ExpressVPN', 'guide' => 'https://www.expressvpn.com/support/manage-account/find-manual-configuration-credentials/'],
        'hide' => ['name' => 'hide.me', 'guide' => 'https://hide.me/en/help/how-to-connect-via-wireguard-configuration-file/'],
        'ivpn' => ['name' => 'IVPN', 'guide' => 'https://www.ivpn.net/setup/router/opnsense-wireguard/'],
        'mullvad' => ['name' => 'Mullvad', 'login' => 'mullvad', 'guide' => 'https://mullvad.net/en/account/wireguard-config'],
        'nord' => ['name' => 'NordVPN', 'login' => 'token', 'guide' => 'https://support.nordvpn.com/hc/en-us/articles/45535038276753-How-to-generate-a-NordVPN-login-token-to-connect-to-a-VPN-server-on-a-router'],
        'ovpn' => ['name' => 'OVPN', 'guide' => 'https://www.ovpn.com/en/guides/wireguard/opnsense'],
        'pia' => ['name' => 'Private Internet Access', 'login' => 'password', 'guide' => 'https://github.com/pia-foss/manual-connections'],
        'proton' => ['name' => 'Proton VPN', 'guide' => 'https://protonvpn.com/support/wireguard-configurations'],
        'vypr' => ['name' => 'VyprVPN', 'guide' => 'https://support.vyprvpn.com/hc/en-us/articles/43750934530317-VyprVPN-WireGuard-Go-Client-Setup'],
        'windscribe' => ['name' => 'Windscribe', 'guide' => 'https://windscribe.com/myaccount/config-generator#wireguard'],
        'other' => ['name' => 'Other VPN']
    ];
    public const LOGIN_PROVIDERS = ['azire', 'nord', 'pia'];
    private const AZIRE = 'https://api.azirevpn.com/v3';
    private const NORD = 'https://api.nordvpn.com/v1';
    private const PIA_CA = '/usr/local/share/blankvpn/pia-ca.rsa.4096.crt';

    public static function validate(string $provider, bool $login = false): string
    {
        if (!isset(self::CATALOG[$provider]) || ($login && !in_array($provider, self::LOGIN_PROVIDERS, true))) {
            throw new DomainException('Choose a supported VPN service.');
        }
        return $provider;
    }

    private static function file(string $provider, string $user): string
    {
        return 'vpn-login-' . self::validate($provider, true) . '-' . hash('sha256', $user) . '.json';
    }

    public function hasSaved(string $provider, string $user): bool
    {
        $path = Policy::STATE_DIR . '/' . self::file($provider, $user);
        return is_file($path) && !is_link($path);
    }

    public function saved(string $provider, string $user): ?array
    {
        $path = Policy::STATE_DIR . '/' . self::file($provider, $user);
        if (!file_exists($path) && !is_link($path)) {
            return null;
        }
        return self::privateRecord($path);
    }

    private static function privateRecord(string $path): array
    {
        Policy::stateDirectory();
        $mode = @fileperms($path);
        if (is_link($path) || !is_file($path) || $mode === false || ($mode & 0077) !== 0) {
            throw new RuntimeException('The saved VPN data has unsafe permissions.');
        }
        $data = json_decode((string)file_get_contents($path, false, null, 0, 16384), true);
        if (!is_array($data)) {
            throw new RuntimeException('The saved VPN data could not be read.');
        }
        return $data;
    }

    public function save(string $provider, string $user, ?array $credentials): void
    {
        $name = self::file($provider, $user);
        if ($credentials !== null) {
            Policy::writeState($name, json_encode($credentials, JSON_THROW_ON_ERROR));
        } else {
            $path = Policy::STATE_DIR . '/' . $name;
            if ((file_exists($path) || is_link($path)) && !unlink($path)) {
                throw new RuntimeException('The saved VPN login could not be removed.');
            }
        }
    }

    public function authenticate(string $provider, array $credentials): array
    {
        $secret = $credentials['secret'] ?? '';
        if (!is_string($secret) || $secret === '' || strlen($secret) > 512 || preg_match('/[\x00-\x1f\x7f]/', $secret) ||
            ($provider !== 'pia' && !preg_match('/^[A-Za-z0-9._~+\/=-]{12,512}$/D', $secret))) {
            throw new DomainException('Enter the VPN service credentials.');
        }
        return match (self::validate($provider, true)) {
            'azire' => $this->azireLogin($secret),
            'nord' => $this->nordLogin($secret),
            'pia' => $this->piaLogin((string)($credentials['username'] ?? ''), $secret),
        };
    }

    private function azireLogin(string $token): array
    {
        $result = $this->request(self::AZIRE . '/users/me', ['Authorization: Bearer ' . $token]);
        $user = $result['data'] ?? $result['user'] ?? $result;
        if (!is_string($user['username'] ?? null) || ($user['is_active'] ?? true) === false) {
            throw new DomainException('AzireVPN did not confirm an active account.');
        }
        return ['token' => $token, 'account' => $user['username']];
    }

    private function nordLogin(string $token): array
    {
        $result = $this->request(self::NORD . '/users/services/credentials', [], [
            CURLOPT_USERPWD => 'token:' . $token, CURLOPT_HTTPAUTH => CURLAUTH_BASIC
        ]);
        if (!self::wireGuardKey($result['nordlynx_private_key'] ?? null)) {
            throw new DomainException('NordVPN did not return a NordLynx key for this token.');
        }
        return ['privateKey' => $result['nordlynx_private_key']];
    }

    private function piaLogin(string $username, string $password): array
    {
        if (!preg_match('/^p[0-9]{4,20}$/iD', $username)) {
            throw new DomainException('Enter your PIA username beginning with p.');
        }
        $result = $this->request('https://www.privateinternetaccess.com/api/client/v2/token', [], [
            CURLOPT_POSTFIELDS => ['username' => $username, 'password' => $password]
        ]);
        $token = $result['token'] ?? null;
        if (!is_string($token) || $token === '' || strlen($token) > 2048) {
            throw new DomainException('PIA did not accept these credentials.');
        }
        return ['token' => $token];
    }

    public function servers(string $provider, array $auth, string $country = ''): array
    {
        if ($country !== '' && !preg_match('/^[a-z]{2}$/iD', $country)) {
            throw new DomainException('Enter a two-letter country code.');
        }
        $servers = match (self::validate($provider, true)) {
            'azire' => self::azireServers($this->request(self::AZIRE . '/locations', ['Authorization: Bearer ' . $auth['token']])),
            'nord' => self::nordServers($this->request(self::NORD . '/servers/recommendations?' . http_build_query([
                'limit' => 100,
                'filters' => ['servers_technologies' => 35] + ($country === '' ? [] : [
                    'country_id' => $this->nordCountryId($country)
                ])
            ], '', '&', PHP_QUERY_RFC3986))),
            'pia' => self::piaServers($this->request('https://serverlist.piaservers.net/vpninfo/servers/v6', [], [], true)),
        };
        if ($servers === []) {
            throw new RuntimeException('The provider returned no compatible WireGuard servers.');
        }
        uasort($servers, static fn (array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));
        return $servers;
    }

    private function nordCountryId(string $code): int
    {
        foreach ($this->request(self::NORD . '/servers/countries') as $country) {
            if (strcasecmp((string)($country['code'] ?? ''), $code) === 0 && (int)($country['id'] ?? 0) > 0) {
                return (int)$country['id'];
            }
        }
        throw new DomainException('NordVPN did not list that country.');
    }

    public static function azireServers(array $data): array
    {
        $servers = [];
        foreach ((array)($data['locations'] ?? $data['data'] ?? []) as $location) {
            $id = $location['name'] ?? '';
            $host = $location['pool'] ?? '';
            $key = $location['pubkey'] ?? null;
            if (!is_string($id) || !preg_match('/^[a-z0-9-]{1,64}$/D', $id) || !is_string($host) ||
                !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) ||
                !preg_match('/\.(?:azirevpn\.net|azirevpn\.com)$/iD', $host) ||
                !self::wireGuardKey($key)) {
                continue;
            }
            $servers[$id] = ['name' => self::label($location['city'] ?? '', $location['country'] ?? '', $id),
                'host' => $host, 'publicKey' => $key, 'port' => 51820];
        }
        return $servers;
    }

    public static function nordServers(array $data): array
    {
        $servers = [];
        foreach ($data as $server) {
            $host = $server['hostname'] ?? '';
            $ip = $server['station'] ?? '';
            if (!is_string($host) || !preg_match('/^[a-z0-9-]+\.nordvpn\.com$/D', $host) ||
                !self::publicIpv4($ip) || ($server['status'] ?? 'online') !== 'online') {
                continue;
            }
            foreach ((array)($server['technologies'] ?? []) as $tech) {
                if ((int)($tech['id'] ?? 0) !== 35 || ($tech['pivot']['status'] ?? 'online') !== 'online') {
                    continue;
                }
                foreach ((array)($tech['metadata'] ?? []) as $meta) {
                    if (($meta['name'] ?? '') !== 'public_key' || !self::wireGuardKey($meta['value'] ?? null)) {
                        continue;
                    }
                    $country = $server['locations'][0]['country'] ?? [];
                    $servers[$host] = ['name' => self::label($country['name'] ?? '', $server['name'] ?? '', $host),
                        'ipv4' => $ip, 'publicKey' => $meta['value'], 'port' => 51820];
                }
            }
        }
        return $servers;
    }

    public static function piaServers(array $data): array
    {
        $servers = [];
        foreach ((array)($data['regions'] ?? []) as $region) {
            $id = $region['id'] ?? '';
            if (!is_string($id) || !preg_match('/^[a-z0-9_-]{1,64}$/D', $id)) {
                continue;
            }
            foreach ((array)($region['servers']['wg'] ?? []) as $server) {
                $cn = $server['cn'] ?? '';
                $ip = $server['ip'] ?? '';
                if (is_string($cn) && preg_match('/^[a-z0-9-]{1,63}$/D', $cn) && self::publicIpv4($ip)) {
                    $servers[$id] = ['name' => self::label($region['country'] ?? '', $region['name'] ?? '', $id),
                        'cn' => $cn, 'ipv4' => $ip];
                    break;
                }
            }
        }
        return $servers;
    }

    public function configuration(string $provider, array $auth, string $id, array $server): array
    {
        $wireGuard = new Mullvad();
        if ($provider === 'nord') {
            $identity = ['privateKey' => $auth['privateKey'], 'address' => '10.5.0.2/32',
                'dns' => ['103.86.96.100', '103.86.99.100']];
        } elseif ($provider === 'pia') {
            $private = $this->generateKey();
            $key = $wireGuard->derivePublicKey($private);
            $host = $server['cn'];
            $ip = $server['ipv4'];
            $response = $this->request('https://' . $host . ':1337/addKey?' . http_build_query(
                ['pt' => $auth['token'], 'pubkey' => $key], '', '&', PHP_QUERY_RFC3986
            ), [], [CURLOPT_CAINFO => self::PIA_CA, CURLOPT_RESOLVE => [$host . ':1337:' . $ip]]);
            if (($response['status'] ?? '') !== 'OK' || !self::wireGuardKey($response['server_key'] ?? null)) {
                throw new RuntimeException('PIA did not accept the WireGuard registration.');
            }
            $identity = ['privateKey' => $private, 'publicKey' => $key,
                'address' => self::hostAddress($response['peer_ip'] ?? ''), 'dns' => self::ipv4Dns($response['dns_servers'] ?? [])];
            $server['publicKey'] = $response['server_key'];
            $server['port'] = $response['server_port'] ?? 0;
        } else {
            $endpoint = gethostbyname($server['host']);
            if (!self::publicIpv4($endpoint)) {
                throw new RuntimeException('The AzireVPN server did not resolve to a public IPv4 address.');
            }
            WireGuard::preflight($endpoint);
            $server['ipv4'] = $endpoint;
            $identity = $this->azireIdentity($auth, $id);
        }
        $identity['publicKey'] ??= $wireGuard->derivePublicKey($identity['privateKey']);
        return [$identity, $server];
    }

    private function azireIdentity(array $auth, string $location): array
    {
        $file = 'azire-registration-' . hash('sha256', $auth['account'] . '/' . $location) . '.json';
        $path = Policy::STATE_DIR . '/' . $file;
        $pending = is_file($path) || is_link($path);
        $private = $pending ? (self::privateRecord($path)['key'] ?? '') : $this->generateKey();
        $key = (new Mullvad())->derivePublicKey($private);
        if (!$pending) {
            Policy::writeState($file, json_encode(['key' => $private], JSON_THROW_ON_ERROR));
        }
        $headers = ['Authorization: Bearer ' . $auth['token']];
        $allocation = null;
        if ($pending) {
            $response = $this->request(self::AZIRE . '/ips', $headers);
            foreach ((array)($response['data'] ?? $response['ips'] ?? []) as $ip) {
                if (is_array($ip['keys'] ?? null) && in_array($key, array_column($ip['keys'], 'key'), true)) {
                    $allocation = $ip;
                    break;
                }
            }
        }
        if ($allocation === null) {
            $response = $this->request(self::AZIRE . '/ips', [...$headers, 'Content-Type: application/json'], [
                CURLOPT_POSTFIELDS => json_encode(['key' => $key], JSON_THROW_ON_ERROR)
            ]);
            $allocation = $response['data'] ?? $response;
        }
        return ['privateKey' => $private, 'publicKey' => $key,
            'address' => self::hostAddress($allocation['ipv4_address'] ?? ''),
            'dns' => self::ipv4Dns($allocation['dns'] ?? [])];
    }

    private function generateKey(): string
    {
        $key = trim(Resolver::command(['/usr/bin/wg', 'genkey']));
        if (!self::wireGuardKey($key)) {
            throw new RuntimeException('The router could not generate a WireGuard key.');
        }
        return $key;
    }

    private static function hostAddress(mixed $value): string
    {
        $ip = is_string($value) ? explode('/', $value, 2)[0] : '';
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new RuntimeException('The provider returned no usable IPv4 tunnel address.');
        }
        return $ip . '/32';
    }

    private static function ipv4Dns(mixed $dns): array
    {
        $addresses = array_values(array_filter(is_array($dns) ? $dns : [], static fn ($ip): bool =>
            is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false));
        if ($addresses === []) {
            throw new RuntimeException('The provider returned no IPv4 DNS resolver for the tunnel.');
        }
        return $addresses;
    }

    private static function wireGuardKey(mixed $value): bool
    {
        $bytes = is_string($value) && strlen($value) === 44 ? base64_decode($value, true) : false;
        return $bytes !== false && strlen($bytes) === 32 && $bytes !== str_repeat("\0", 32) && base64_encode($bytes) === $value;
    }

    private static function publicIpv4(mixed $ip): bool
    {
        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE) !== false;
    }

    private static function label(mixed $first, mixed $second, string $fallback): string
    {
        $label = trim(implode(' · ', array_filter([$first, $second], static fn ($value): bool => is_string($value) && $value !== '')));
        return preg_match('/^[^\p{C}<>]{1,64}$/uD', $label) ? $label : $fallback;
    }

    protected function request(string $url, array $headers = [], array $extra = [], bool $firstLine = false): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP curl extension is required for VPN provider sign-in.');
        }
        $response = '';
        $curl = curl_init($url);
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
            CURLOPT_HTTPHEADER => ['Accept: application/json', ...$headers],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response): int {
                if (strlen($response) + strlen($chunk) > 4 * 1024 * 1024) {
                    return 0;
                }
                $response .= $chunk;
                return strlen($chunk);
            }
        ];
        if ($curl === false || !curl_setopt_array($curl, $options + $extra) || curl_exec($curl) === false) {
            throw new RuntimeException('Could not reach the VPN provider. Check router DNS, connectivity and time.');
        }
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException(match ($status) {
                401, 403 => 'The VPN provider rejected authorization. Check the account, token and subscription.',
                429 => 'The VPN provider is rate limiting requests. Try again shortly.',
                default => 'The VPN provider returned HTTP ' . $status . '.'
            });
        }
        $data = json_decode($firstLine ? explode("\n", $response, 2)[0] : $response, true, 32);
        if (!is_array($data)) {
            throw new RuntimeException('The VPN provider returned unreadable configuration data.');
        }
        return $data;
    }
}
