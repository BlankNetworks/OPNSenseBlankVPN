<?php

declare(strict_types=1);

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Ivpn.php';

use OPNsense\BlankVpn\Ivpn;

final class FixtureIvpn extends Ivpn
{
    public array $calls = [];
    public array $loginReplies = [];
    public int $generated = 0;
    public int $clock = 1600000000;
    public int $statusCode = 200;
    public bool $offline = false;

    protected function request(string $path, ?array $body = null): array
    {
        $this->calls[] = [$path, $body];
        if ($path === '/v4/session/new') {
            $reply = array_shift($this->loginReplies);
            if ($reply instanceof RuntimeException) {
                throw $reply;
            }
            return $reply;
        }
        if ($path === '/v4/session/status') {
            if ($this->offline) {
                throw new RuntimeException('Provider unreachable.');
            }
            return ['status' => $this->statusCode, 'service_status' => ['is_active' => true, 'active_until' => 1900000000]];
        }
        if ($path === '/v4/session/delete') {
            return ['status' => 200];
        }
        check($path === '/v5/servers.json' && $body === null, 'The catalog request is public.');
        $key = base64_encode(str_repeat('k', 32));
        return [
            'config' => ['ports' => ['wireguard' => [['type' => 'TCP', 'port' => 80],
                ['type' => 'UDP', 'port' => 443], ['type' => 'UDP', 'port' => 2049]]]],
            'wireguard' => [
                ['country' => 'Canada', 'country_code' => 'CA', 'city' => 'Toronto', 'hosts' => [
                    ['hostname' => 'ca1.wg.ivpn.net', 'host' => '8.8.8.8', 'public_key' => $key],
                    ['hostname' => 'ca2.wg.ivpn.net', 'host' => '192.168.1.1', 'public_key' => $key],
                    ['hostname' => 'ca3.wg.ivpn.net.invalid', 'host' => '8.8.8.9', 'public_key' => $key],
                    ['hostname' => 'ca4.wg.ivpn.net', 'host' => '8.8.8.9', 'public_key' => 'not-a-key'],
                ]],
                ['country' => 'United States', 'country_code' => 'US', 'city' => 'Chicago', 'hosts' => [
                    ['hostname' => 'us1.wg.ivpn.net', 'host' => '8.8.4.4', 'public_key' => $key],
                ]],
            ],
        ];
    }

    protected function now(): int
    {
        return $this->clock;
    }

    protected function generateKey(): string
    {
        $this->generated++;
        return base64_encode(str_repeat('a', 32));
    }

    protected function publicKey(string $privateKey): string
    {
        return base64_encode(hash('sha256', $privateKey, true));
    }
}

function check(bool $ok, string $message): void
{
    if (!$ok) {
        throw new RuntimeException($message);
    }
}

function expectFailure(callable $call, string $expected): void
{
    try {
        $call();
    } catch (DomainException | RuntimeException $error) {
        check(str_contains($error->getMessage(), $expected), $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected failure containing ' . $expected);
}

$dir = sys_get_temp_dir() . '/blank-vpn-ivpn-' . bin2hex(random_bytes(8));
$ivpn = new FixtureIvpn('admin', $dir);
$accountId = 'i-A1B2-C3D4-E5F6';
$token = 'mock_session_token';
$success = [
    'status' => 200, 'token' => $token, 'service_status' => ['is_active' => true, 'active_until' => 1900000000],
    'wireguard' => ['status' => 200, 'ip_address' => '172.16.3.19'],
];
try {
    check($ivpn->authStatus()['status'] === 'signed_out', 'Initial session state');
    expectFailure(fn () => $ivpn->login('bad-account'), 'Account ID');
    expectFailure(fn () => $ivpn->login($accountId, '12'), 'six-digit');
    $ivpn->loginReplies = [new RuntimeException('Simulated lost response'), ['status' => 70011],
        ['status' => 70012], $success];
    expectFailure(fn () => $ivpn->login($accountId), 'same key');
    check($ivpn->login($accountId)['challenge'] === 'totp', 'IVPN asks for the authenticator challenge');
    check($ivpn->login($accountId, '123456')['challenge'] === 'totp', 'IVPN rejects an invalid authenticator code');
    $status = $ivpn->login($accountId, '654321');
    check($status['authenticated'] && $status['challenge'] === null && $status['saved'], 'Valid login saved');
    check($ivpn->generated === 1, 'WireGuard key reused through interrupted login and challenges');
    $lastLogin = $ivpn->calls[3][1];
    check($lastLogin === ['username' => $accountId, 'force' => false, 'wg_public_key' => $ivpn->calls[0][1]['wg_public_key'],
        'confirmation' => '654321'], 'Only public key and required credentials sent, no force login');
    check(!str_contains(json_encode($status, JSON_THROW_ON_ERROR), $token), 'API status omits token');
    $path = $dir . '/ivpn-' . hash('sha256', 'admin') . '.json';
    $disk = file_get_contents($path);
    check(($disk !== false) && !str_contains($disk, $accountId) && !str_contains($disk, '654321'), 'Account ID and OTP never saved');
    check((fileperms($path) & 0777) === 0600 && (fileperms($dir) & 0777) === 0700, 'Session storage is owner-only');
    check(!(new FixtureIvpn('operator', $dir))->authStatus()['saved'], 'No credentials shared across WebGUI users');
    expectFailure(fn () => $ivpn->login('i-FFFF-FFFF-FFFF'), 'Sign out');

    $servers = $ivpn->servers('ca');
    check(array_keys($servers) === ['ca1.wg.ivpn.net'] && $servers['ca1.wg.ivpn.net']['port'] === 2049,
        'Catalog filter, public IPv4 address and documented UDP preference');
    [$identity, $relay] = $ivpn->configuration('ca1.wg.ivpn.net', 'CA');
    check($identity['address'] === '172.16.3.19/32' && $identity['dns'] === ['172.16.0.1']
        && $relay['publicKey'] === base64_encode(str_repeat('k', 32)), 'Native routing receives provider allocation and peer data');
    expectFailure(fn () => $ivpn->configuration('us1.wg.ivpn.net', 'CA'), 'Choose a WireGuard server');

    $ivpn->clock += 301;
    $calls = count($ivpn->calls);
    check($ivpn->authStatus()['status'] === 'stale' && count($ivpn->calls) === $calls, 'Dashboard status stays local');
    $ivpn->offline = true;
    $stale = $ivpn->authStatus(true);
    check($stale['status'] === 'stale' && $stale['saved'] && !$stale['authenticated'], 'Offline session status is stale');
    $ivpn->offline = false;
    check($ivpn->authStatus(true)['authenticated'], 'Active session refreshes');
    $ivpn->statusCode = 601;
    $expired = $ivpn->authStatus(true);
    check($expired['status'] === 'expired' && !$expired['saved'], 'Revoked provider session is expired');
    $ivpn->loginReplies = [['status' => 70001], ['status' => 602], $success];
    check($ivpn->login($accountId)['challenge'] === 'captcha', 'CAPTCHA fallback is explicit');
    expectFailure(fn () => $ivpn->login($accountId), 'device limit');
    check($ivpn->login($accountId)['authenticated'] && $ivpn->generated === 1, 'Fresh session can reuse the prior router key');
    $ivpn->logout();
    check(end($ivpn->calls) === ['/v4/session/delete', ['session_token' => $token]] && !file_exists($path),
        'Only the owned provider session is deleted');
} finally {
    foreach (glob($dir . '/*') ?: [] as $path) {
        unlink($path);
    }
    if (is_dir($dir)) {
        rmdir($dir);
    }
}

echo "IVPN adapter fixture checks passed.\n";
