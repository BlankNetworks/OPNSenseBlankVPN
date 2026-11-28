<?php

declare(strict_types=1);

require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/VpnProviders.php';

use OPNsense\BlankVpn\VpnProviders;

final class ProtonDirectoryFixture extends VpnProviders
{
    public array $response = [];
    public int $calls = 0;

    protected function request(string $url, array $headers = [], array $extra = [], bool $firstLine = false): array
    {
        check($url === 'https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json'
            && !$headers && !$extra, 'Directory request must be anonymous and use a fixed URL.');
        ++$this->calls;
        return $this->response;
    }
}

function check(bool $value, string $message): void
{
    if (!$value) {
        throw new RuntimeException($message);
    }
}

function rejected(callable $call, string $message): void
{
    try {
        $call();
    } catch (RuntimeException | DomainException $e) {
        if (str_contains($e->getMessage(), $message)) {
            return;
        }
        throw $e;
    }
    throw new RuntimeException('Expected rejection: ' . $message);
}

$fixture = new ProtonDirectoryFixture();
$key = base64_encode(str_repeat('r', 32));
$host = 'node-ca-71.protonvpn.net';
$free = ['vpn' => 'wireguard', 'free' => true, 'country' => 'Canada', 'city' => 'Montreal',
    'server_name' => 'CA-FREE#25', 'hostname' => $host, 'wgpubkey' => $key, 'ips' => ['8.8.8.8', '10.1.1.1', '::1']];
$paid = array_replace($free, ['hostname' => 'ca-02.protonvpn.net', 'server_name' => 'CA#31']);
unset($paid['free']);
$fixture->response = ['version' => 4, 'servers' => [$free, $paid]];
foreach ([
    ['vpn' => 'openvpn'], ['hostname' => 'node-ca-71.protonvpn.net.example.org'], ['hostname' => 'ca.example.org'],
    ['hostname' => 'sub.node.protonvpn.net'], ['ips' => ['10.0.0.1']], ['wgpubkey' => ''], ['tor' => true],
    ['secure_core' => true], ['city' => '<img>'], ['wgpubkey' => base64_encode(str_repeat("\0", 32))],
] as $bad) {
    $fixture->response['servers'][] = array_replace($free, ['hostname' => 'bad-peer.protonvpn.net'], $bad);
}
$fixture->response['servers'][] = ['hostname' => $host];
$freeGateways = $fixture->protonServers('free');
check(array_keys($freeGateways) === [$host], 'Expose only standard Free WireGuard gateways with complete metadata.');
check(array_keys($fixture->protonServers('plus')) === [$paid['hostname']], 'Plus must use the paid gateway list.');
$gateway = $freeGateways[$host];
check($gateway['name'] === 'node-ca-71' && $gateway['country'] === 'Canada' && $gateway['city'] === 'Montreal'
    && $gateway['ips'] === ['8.8.8.8'], 'List the physical gateway, country, city and public IPv4 addresses.');
$relay = VpnProviders::protonRelay($gateway, static function (string $fqdn) use ($host): array {
    check($fqdn === $host . '.', 'Resolve the absolute Proton-owned hostname.');
    return ['10.0.0.1', '1.1.1.1', '8.8.8.8'];
});
check($relay['ipv4'] === '8.8.8.8' && $relay['publicKey'] === $key && $relay['port'] === 51820,
    'Pin the DNS-confirmed address and expected WireGuard public key.');
rejected(fn () => VpnProviders::protonRelay($gateway, fn () => ['1.1.1.1']), 'could not be confirmed');
rejected(fn () => VpnProviders::protonRelay($gateway, fn () => false), 'could not be confirmed');
rejected(fn () => $fixture->protonServers('unknown'), 'Choose Proton Free or Plus');
check($fixture->calls === 2, 'Invalid plans must be rejected before fetching the catalog.');
$fixture->response['version'] = 999;
rejected(fn () => $fixture->protonServers('free'), 'format has changed');
$fixture->response = ['version' => 4, 'servers' => []];
rejected(fn () => $fixture->protonServers('free'), 'no compatible gateways');
echo "Proton server directory fixtures passed.\n";
