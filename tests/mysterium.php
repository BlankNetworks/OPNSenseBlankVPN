<?php

declare(strict_types=1);

use OPNsense\BlankVpn\MystVpn;

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Mullvad.php';
require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/MystVpn.php';

final class MystFixture extends MystVpn
{
    public int $clock = 2000000000;
    public string $activation = '';
    public bool $approved = false;
    public bool $rejected = false;
    public bool $unauthorized = true;
    public bool $refreshDenied = false;
    public bool $catalogOffline = false;
    public bool $responseLost = false;
    public bool $limitExceeded = false;
    public string $endpoint = '1.1.1.1';
    public string $templateOptions = '';
    public string $allowedIps = '0.0.0.0/0';
    public string $targetCity = 'Berlin';
    public bool $expectReset = false;
    public int $polls = 0;
    public int $refreshes = 0;
    public int $provisions = 0;
    public int $keys = 0;
    public array $publishedKeys = [];

    protected function now(): int
    {
        return $this->clock;
    }

    protected function generateKey(): string
    {
        ++$this->keys;
        return base64_encode(str_repeat('k', 32));
    }

    protected function publicKey(string $key): string
    {
        return base64_encode(hash('sha256', $key, true));
    }

    protected function request(
        string $method,
        string $path,
        ?string $token = null,
        ?array $body = null,
        array $accepted = [200],
        bool $decode = true
    ): array {
        if ($path === '/auth/activation') {
            check($method === 'POST' && $accepted === [200, 204] && !$decode, 'Activation should accept a bodyless 204.');
            check($token === null && array_keys($body) === ['id'], 'Activation must only send the random ID.');
            check(preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $body['id']) === 1, 'Expected a valid UUIDv4.');
            $this->activation = $body['id'];
            return [];
        }
        if ($path === '/auth/activation/' . $this->activation) {
            check($method === 'GET' && $token === null, 'Unexpected activation poll.');
            ++$this->polls;
            return ['id' => $this->activation, 'valid' => !$this->rejected, 'token' => $this->approved ? $this->fixtureTokens('first') : null];
        }
        if ($path === '/oauth/token') {
            check($method === 'POST' && $token === null && $body === [
                'grant_type' => 'refresh_token', 'client_id' => 'cli',
                'refresh_token' => $this->refreshes === 0 ? 'first-refresh' : 'next-refresh',
            ], 'Unexpected OAuth token refresh.');
            ++$this->refreshes;
            if ($this->refreshDenied) {
                throw new RuntimeException('Refresh rejected.', 401);
            }
            return $this->fixtureTokens('next');
        }
        if ($this->unauthorized) {
            $this->unauthorized = false;
            check($token === 'first-access', 'Expected initial OAuth access token.');
            throw new RuntimeException('Unauthorized.', 401);
        }
        check($token === 'next-access', 'Expected the refreshed access token.');
        if (str_starts_with($path, '/connection/config/locations?ip_type=')) {
            check($method === 'GET' && $body === null, 'Unexpected location catalog request.');
            if ($this->catalogOffline) {
                throw new RuntimeException('Catalog offline.');
            }
            return [
                ['country' => 'DE', 'translations' => ['en' => 'Germany'], 'cities' => [
                    ['city' => 'Berlin'],
                    ['city' => 'Hamburg'],
                    ['city' => 'Unavailable', 'is_available' => false],
                ]],
                ['country' => 'US', 'is_available' => false],
            ];
        }
        check($method === 'POST' && $path === '/connection/connect', 'Unexpected provisioning request.');
        check($body === [
            'public_key' => $this->publicKey(base64_encode(str_repeat('k', 32))),
            'country' => 'DE', 'ip_type' => 'hosting', 'os_type' => 'linux-cli',
            'cli_version' => 'dev', 'os_version' => 'OPNsense/' . php_uname('r'),
            'reset_connection' => $this->expectReset, 'city' => $this->targetCity,
        ], 'Unexpected WireGuard provisioning fields or local private key leaked.');
        ++$this->provisions;
        $this->publishedKeys[] = $body['public_key'];
        if ($this->responseLost) {
            throw new RuntimeException('Connection response lost.');
        }
        $peer = base64_encode(str_repeat('p', 32));
        return [
            'id' => 'fixture-session',
            'wg_config' => "[Interface]\nPrivateKey = %private_key%\nAddress = 10.10.0.2/24\n"
                . $this->templateOptions . "\n[Peer]\nPublicKey = " . $peer
                . "\nAllowedIPs = " . $this->allowedIps . "\nEndpoint = " . $this->endpoint . ":51820\n",
            'exit_ip' => '8.8.4.4',
            'limit_exceeded' => $this->limitExceeded,
            'country' => 'DE',
            'city' => $this->targetCity,
            'ip_type' => 'hosting',
        ];
    }

    private function fixtureTokens(string $name): array
    {
        return ['access_token' => $name . '-access', 'refresh_token' => $name . '-refresh',
            'expires_in' => 3600, 'token_type' => 'Bearer', 'user_id' => 'example-account'];
    }
}

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function expectError(callable $action, string $message): void
{
    try {
        $action();
    } catch (RuntimeException | DomainException $error) {
        check(str_contains($error->getMessage(), $message), $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected error: ' . $message);
}

$directory = sys_get_temp_dir() . '/blank-vpn-myst-' . bin2hex(random_bytes(8));
$client = new MystFixture('root', $directory);
$other = new MystFixture('operator', $directory);

try {
    check($client->authStatus()['status'] === 'signed_out', 'Fresh user should be signed out.');
    expectError(fn () => $client->locations(), 'Sign in');
    $pending = $client->beginAuth();
    parse_str(parse_url($pending['approvalUrl'], PHP_URL_QUERY), $query);
    check(parse_url($pending['approvalUrl'], PHP_URL_HOST) === 'app.mysteriumvpn.com' && $query === [
        'response_type' => 'activation_none', 'client_id' => 'cli', 'request_id' => $client->activation,
    ], 'Expected the official approval URL.');
    check($pending['pending'] && $pending['expiresAt'] === $client->clock + 300, 'Activation must expire after five minutes.');
    check($client->beginAuth() === $pending, 'An existing approval should be reused.');
    check($client->pollAuth()['pending'], 'Browser approval should remain pending.');
    $client->approved = true;
    check($client->pollAuth()['pending'] && $client->polls === 1, 'Provider approval polling should be throttled.');
    $client->clock += 10;
    $approved = $client->pollAuth();
    check($approved['authenticated'] && $approved['approvalUrl'] === null, 'The browser approval should sign in.');
    check(!str_contains(json_encode($approved), 'first-access') && !$other->authStatus()['authenticated'], 'Authorization should be scoped and secret.');
    $other->beginAuth();
    $other->rejected = true;
    check($other->pollAuth()['status'] === 'expired', 'Rejected approval must be closed.');
    $other->beginAuth();
    $other->clock += 300;
    check($other->pollAuth()['status'] === 'expired' && $other->polls === 1, 'Expired approvals should not poll upstream.');

    $catalog = $client->locations('hosting');
    check(count($catalog['locations']) === 3 && !$catalog['stale'] && $client->refreshes === 1, 'Location retrieval should refresh a rejected token once.');
    check($catalog['locations'][1]['countryCode'] === 'DE' && $catalog['locations'][1]['region'] === 'Berlin', 'Expected an exact city/state identifier.');
    $client->catalogOffline = true;
    $offline = $client->locations('hosting', true);
    check($offline['stale'] && $offline['locations'] === $catalog['locations'], 'An outage should preserve the last catalog.');
    $client->catalogOffline = false;
    expectError(fn () => $client->provision('DE', 'hosting', 'Unavailable'), 'available location');

    $client->responseLost = true;
    expectError(fn () => $client->provision('DE', 'hosting', 'Berlin'), 'Connection response lost');
    $client->responseLost = false;
    $config = $client->provision('DE', 'hosting', 'Berlin', '9.9.9.9');
    check($client->keys === 1 && count(array_unique($client->publishedKeys)) === 1, 'Provision retry should reuse the local identity.');
    check($config['address'] === '10.10.0.2/32' && $config['address6'] === '' && $config['ipv4'] === '1.1.1.1'
        && $config['dns'] === ['9.9.9.9'] && $config['exitIp'] === '8.8.4.4', 'Unexpected native WireGuard configuration.');
    $retry = $client->provision('DE', 'hosting', 'Berlin', '9.9.9.9');
    check($retry === $config && $client->provisions === 2, 'Interrupted local commit should reuse the provider session.');
    $client->completeProvision($config['provisionReceipt']);
    $client->completeProvision($config['provisionReceipt']);
    $client->endpoint = '192.168.1.2';
    expectError(fn () => $client->provision('DE', 'hosting', 'Berlin'), 'public IPv4');
    $client->endpoint = '1.1.1.1';
    $client->templateOptions = "PostUp = bad\n";
    expectError(fn () => $client->provision('DE', 'hosting', 'Berlin'), 'incompatible');
    $client->templateOptions = '';
    $client->allowedIps = '10.0.0.0/8';
    expectError(fn () => $client->provision('DE', 'hosting', 'Berlin'), 'incompatible');
    $client->limitExceeded = true;
    expectError(fn () => $client->provision('DE', 'hosting', 'Berlin'), 'connection limit');
    $client->limitExceeded = false;
    $client->targetCity = 'Hamburg';
    $client->expectReset = true;
    $moved = $client->provision('DE', 'hosting', 'Hamburg');
    check($moved['region'] === 'Hamburg' && $client->keys === 1, 'An explicit target change should reset only the existing local identity.');
    $client->clock += 3600;
    $client->refreshDenied = true;
    expectError(fn () => $client->locations('hosting', true), 'sign-in has expired');
    check(!$client->authStatus()['authenticated'], 'A rejected refresh token must clear the saved account.');

    $files = glob($directory . '/mysterium-*.json');
    check(count($files) === 2, 'Expected one state record per WebGUI user.');
    foreach ($files as $file) {
        check((fileperms($file) & 0777) === 0600, 'Provider state must have mode 0600.');
    }
    $client->logout();
    check(!$client->authStatus()['authenticated'] && count(glob($directory . '/mysterium-*.json')) === 1, 'Local logout must only remove the current account.');
    echo "Mysterium provider fixtures passed.\n";
} finally {
    if (is_dir($directory)) {
        foreach (glob($directory . '/*') as $file) {
            unlink($file);
        }
        rmdir($directory);
    }
}
