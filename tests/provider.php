<?php

declare(strict_types=1);

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Mullvad.php';
require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/VpnProviders.php';

use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\VpnProviders;

final class FixtureMullvad extends Mullvad
{
    public array $deviceRecords = [];
    public int $relayCalls = 0;
    public int $creates = 0;
    public bool $catalogOffline = false;
    public bool $expireAccount = false;
    public bool $responseLost = false;

    protected function request(string $path, ?string $token = null, ?array $body = null): array
    {
        if ($path === '/www/relays/all') {
            $this->relayCalls++;
            check($token === null && $body === null, 'The public catalog request must be anonymous.');
            if ($this->catalogOffline) {
                throw new RuntimeException('Provider unreachable.');
            }
            return [
                ['type' => 'other'],
                [
                    'type' => 'wireguard',
                    'hostname' => 'ca-yyz-wg-001',
                    'ipv4_addr_in' => '8.8.4.4',
                    'ipv6_addr_in' => '[2606:4700:4700::1001]',
                    'pubkey' => base64_encode(str_repeat('r', 32)),
                    'active' => true,
                    'country_name' => 'Canada',
                    'country_code' => 'ca',
                    'city_name' => 'Toronto',
                    'city_code' => 'yyz',
                ],
            ];
        }
        if ($path === '/auth/v1/token') {
            check($token === null && $body === ['account_number' => '0000000000000000'], 'Unexpected login payload.');
            return ['access_token' => 'test-bearer-token', 'expiry' => gmdate(DATE_ATOM, time() + 3600)];
        }
        check($token === 'test-bearer-token', 'Expected the backend bearer token.');
        if ($path === '/accounts/v1/accounts/me') {
            return [
                'id' => '00000000-0000-4000-8000-000000000000',
                'expiry' => gmdate(DATE_ATOM, time() + ($this->expireAccount ? -3600 : 3600)),
                'can_add_devices' => true,
                'max_devices' => 1,
            ];
        }
        check($path === '/accounts/v1/devices', 'Unexpected account API endpoint.');
        if ($body === null) {
            return $this->deviceRecords;
        }
        check(array_keys($body) === ['pubkey', 'hijack_dns'] && $body['hijack_dns'] === false, 'Only the public key and DNS option should leave the router.');
        $this->creates++;
        $device = [
            'id' => '00000000-0000-4000-8000-000000000001',
            'name' => 'Fixture Key',
            'pubkey' => $body['pubkey'],
            'ipv4_address' => '10.64.0.9/32',
            'ipv6_address' => 'fc00:bbbb:bbbb:bb01::9/128',
        ];
        $this->deviceRecords[] = $device;
        if ($this->responseLost) {
            throw new RuntimeException('Registration response was lost.');
        }
        return $device;
    }

    protected function wireGuardKey(string $command, string $privateKey = ''): string
    {
        if (is_executable('/usr/bin/wg')) {
            return parent::wireGuardKey($command, $privateKey);
        }
        // Exercise the registration protocol on development machines without WireGuard.
        return $command === 'genkey' ? base64_encode(str_repeat('p', 32)) : base64_encode(hash('sha256', $privateKey, true));
    }
}

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectFailure(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (DomainException | InvalidArgumentException | RuntimeException $error) {
        check(str_contains($error->getMessage(), $message), $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected error: ' . $message);
}

$fixtureKey = base64_encode(str_repeat('k', 32));
$azire = VpnProviders::azireServers(['locations' => [
    ['name' => 'se-sto', 'pool' => 'se-sto.azirevpn.net', 'city' => 'Stockholm', 'country' => 'Sweden', 'pubkey' => $fixtureKey],
    ['name' => 'malformed', 'pool' => 'azirevpn.net.invalid', 'pubkey' => $fixtureKey]
]]);
check(array_keys($azire) === ['se-sto'] && $azire['se-sto']['port'] === 51820, 'AzireVPN locations must use provider endpoints.');
$nord = VpnProviders::nordServers([
    ['hostname' => 'jp100.nordvpn.com', 'station' => '8.8.4.4', 'status' => 'online', 'name' => 'Japan #100',
        'technologies' => [['id' => 35, 'metadata' => [['name' => 'public_key', 'value' => $fixtureKey]]]]],
    ['hostname' => 'jp101.nordvpn.com', 'station' => '10.0.0.1', 'status' => 'online']
]);
check(array_keys($nord) === ['jp100.nordvpn.com'] && $nord['jp100.nordvpn.com']['publicKey'] === $fixtureKey,
    'NordLynx recommendations must include a usable WireGuard public key and public endpoint.');
$pia = VpnProviders::piaServers(['regions' => [
    ['id' => 'us_chicago', 'name' => 'Chicago', 'country' => 'US', 'servers' => [
        'wg' => [['cn' => 'invalid.example', 'ip' => '8.8.8.8'], ['cn' => 'chicago001', 'ip' => '8.8.4.4']]
    ]]
]]);
check(array_keys($pia) === ['us_chicago'] && $pia['us_chicago']['cn'] === 'chicago001',
    'PIA regions must use the certificate name of a listed WireGuard endpoint.');
expectFailure(fn () => VpnProviders::validate('express', true), 'supported VPN service');

$directory = sys_get_temp_dir() . '/blank-vpn-test-' . bin2hex(random_bytes(8));
$provider = new FixtureMullvad($directory);

try {
    $catalog = $provider->relays();
    check(!$catalog['stale'] && count($catalog['relays']) === 1, 'The real catalog schema should produce a current WireGuard list.');
    $relay = $catalog['relays'][0];
    check($relay['id'] === 'ca-yyz-wg-001' && $relay['ipv6'] === '2606:4700:4700::1001' && $relay['port'] === 51820, 'Relay normalization failed.');
    check($provider->relays() === $catalog && $provider->relayCalls === 1, 'Fresh cache should avoid additional requests.');
    $provider->catalogOffline = true;
    $offline = $provider->relays(true);
    check($offline['stale'] && $offline['error'] === 'Provider unreachable.' && $offline['relays'] === $catalog['relays'], 'The last good catalog should survive an outage.');
    check($provider->relays() === $offline && $provider->relayCalls === 2, 'An outage must limit background retries.');

    $account = '0000 0000 0000 0000';
    expectFailure(fn () => $provider->account('invalid'), '16-digit');
    $provider->saveAccount('operator', $account);
    $stored = glob($directory . '/mullvad-login-*.json');
    check(count($stored) === 1 && (fileperms($stored[0]) & 0777) === 0600, 'The saved login must use a private file.');
    check($provider->hasSavedAccount('operator') && $provider->savedAccount('operator') === '0000000000000000' &&
        $provider->savedAccount('other-operator') === null, 'Saved accounts must be scoped to their WebGUI user.');
    $provider->saveAccount('operator', null);
    check(!$provider->hasSavedAccount('operator'), 'Forgetting the login must remove the saved account.');
    check($provider->account($account)['availableSlots'] === 1, 'Account slot count is wrong.');
    $provider->expireAccount = true;
    check($provider->account($account)['expired'], 'Expired account should be visible.');
    expectFailure(fn () => $provider->register($account, 'profile-1'), 'expired');
    $provider->expireAccount = false;
    $provider->responseLost = true;
    expectFailure(fn () => $provider->register($account, 'profile-1'), 'available for retrying');
    check($provider->creates === 1, 'The first registration should have created a provider device.');
    $pending = glob($directory . '/mullvad-registration-*.json');
    check(count($pending) === 1 && (fileperms($pending[0]) & 0777) === 0600, 'The retry key must be stored with restrictive permissions.');
    $identity = $provider->register($account, 'profile-1');
    check($provider->creates === 1 && $identity['address'] === '10.64.0.9/32', 'Retry should recover the previously registered identity.');
    check(!str_contains(file_get_contents($pending[0]), 'test-bearer-token') && !str_contains(file_get_contents($pending[0]), '0000000000000000'), 'Credential leaked into retry state.');
    $provider->verifyBinding($account, $identity['accountBinding']);
    expectFailure(fn () => $provider->verifyBinding($account, str_repeat('a', 64)), 'different Mullvad account');
    $provider->completeRegistration($identity['registrationReceipt']);
    $provider->completeRegistration($identity['registrationReceipt']);
    check(glob($directory . '/mullvad-registration-*.json') === [], 'Completion should remove the retry key.');
    expectFailure(fn () => $provider->register($account, 'profile-2'), '1 of 1 device slots');

    $token = $provider->authenticate($account)['token'];
    $profile = [
        'relay' => 'ca-yyz-wg-001', 'identityKey' => $identity['publicKey'],
        'identity' => $identity['id'], 'accountBinding' => $identity['accountBinding']
    ];
    check($provider->routerProfiles($token, ['legacy' => $profile])['legacy']['registered'],
        'An upgrade must recognize the existing Mullvad device.');
    check($provider->routerProfiles($token, ['unbound' => array_diff_key($profile, ['accountBinding' => true])])
        ['unbound']['accountBinding'] === $identity['accountBinding'], 'Recognize older tunnels by their registered public key.');
    $provider->rememberRouterKey($identity['accountBinding'], $identity['privateKey']);
    $restarted = new FixtureMullvad($directory);
    $restarted->deviceRecords = $provider->deviceRecords;
    foreach (['ca-yyz-wg-001', 'jp-tyo-wg-001'] as $relayId) {
        $reused = $restarted->registerRouterWithToken($token, $relayId);
        check($reused['id'] === $identity['id'] && $reused['publicKey'] === $identity['publicKey'] &&
            $restarted->creates === 0, 'Changing servers and reloading the package must preserve the registered identity.');
    }

    $privateKey = base64_encode(str_repeat('p', 32));
    $publicKey = base64_encode(str_repeat('r', 32));
    $config = <<<WG
        [Interface]
        #device = fixture
        PrivateKey = $privateKey
        Address = 10.64.0.9/32, fc00:bbbb:bbbb:bb01::9/128
        DNS = 10.64.0.1, fc00:bbbb:bbbb:bb01::1
        MTU = 1380
        [Peer]
        PublicKey = $publicKey
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = [2001:db8::91]:51820
        PersistentKeepalive = 25
        WG;
    $parsed = $provider->parseConfig(str_replace("\n", "\r\n", $config));
    check($parsed['host'] === '2001:db8::91' && $parsed['port'] === 51820 && $parsed['address6'] === 'fc00:bbbb:bbbb:bb01::9/128', 'Import lost tunnel address or endpoint information.');
    check($parsed['mtu'] === 1380 && $parsed['keepalive'] === 25 && count($parsed['dns']) === 2, 'Import lost tunnel settings.');
    $namedDns = str_replace('DNS = 10.64.0.1, fc00:bbbb:bbbb:bb01::1', 'DNS = vpn.example', $config);
    expectFailure(fn () => $provider->parseConfig($namedDns), 'DNS entries must be IP addresses');
    check($provider->parseConfig($namedDns, '10.64.0.1')['dns'] === ['10.64.0.1'], 'The explicit IPv4 resolver should replace the profile DNS.');
    expectFailure(fn () => $provider->parseConfig($config, '::1'), 'IPv4 DNS resolver');
    $withPsk = $provider->parseConfig(str_replace('[Peer]', "[Peer]\nPresharedKey = " . base64_encode(str_repeat('P', 32)), $config));
    if ($withPsk['presharedKey'] !== base64_encode(str_repeat('P', 32))) {
        throw new RuntimeException('Imported WireGuard configuration lost its preshared key.');
    }
    expectFailure(fn () => $provider->parseConfig(str_replace('MTU = 1380', 'PostUp = invalid', $config)), 'unsupported');
    expectFailure(fn () => $provider->parseConfig(str_replace('0.0.0.0/0, ::/0', '0.0.0.0/0', $config)), 'AllowedIPs');
    expectFailure(fn () => $provider->parseConfig(str_replace('[2001:db8::91]:51820', 'vpn.example:70000', $config)), 'UDP port');
    expectFailure(fn () => $provider->parseConfig($config . "\n[Peer]\n"), 'one WireGuard interface');
    echo "Mullvad provider fixtures passed.\n";
} finally {
    if (is_dir($directory)) {
        foreach (glob($directory . '/*') as $path) {
            unlink($path);
        }
        rmdir($directory);
    }
}
