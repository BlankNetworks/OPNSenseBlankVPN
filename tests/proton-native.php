<?php

declare(strict_types=1);

namespace OPNsense\Base {
    class BaseModel
    {
        public function performValidation(): array { return []; }
        public function serializeToConfig(): void {}
    }
}
namespace OPNsense\Core {
    class Config
    {
        public static object $xml;
        public static function getInstance(): self { return new self(); }
        public function object(): object { return self::$xml; }
    }
}
namespace OPNsense\BlankVpn {
    class Field
    {
        public function __construct(private string $value) {}
        public function __toString(): string { return $this->value; }
        public function getValues(): array { return array_filter(explode(',', $this->value), 'strlen'); }
        public function isEmpty(): bool { return $this->value === ''; }
    }
    class Row
    {
        public function __construct(private array $fields) {}
        public function __get(string $field): Field { return new Field($this->fields[$field] ?? ''); }
        public function __set(string $field, mixed $value): void { $this->fields[$field] = (string)$value; }
    }
    class Rows
    {
        public function __construct(public array $items) {}
        public function iterateItems(): \Generator { yield from $this->items; }
    }
    class Mullvad
    {
        public function derivePublicKey(string $private): string { return base64_encode(hash('sha256', $private, true)); }
    }
    function proc_open(array $cmd, array $spec, ?array &$pipes)
    {
        if (array_slice($cmd, 0, 4) !== ['/sbin/route', '-n', 'get', '-inet']) {
            throw new \RuntimeException('Unexpected native command.');
        }
        $output = fopen('php://temp', 'w+');
        fwrite($output, "interface: igc0\n");
        rewind($output);
        $pipes = [1 => $output];
        return fopen('php://temp', 'w+');
    }
    function proc_close($process): int { fclose($process); return 0; }
}
namespace OPNsense\Wireguard {
    use OPNsense\Base\BaseModel;
    use OPNsense\BlankVpn\{Rows, Row};
    class General { public string $enabled = '1'; }
    class Server extends BaseModel
    {
        public static Rows $rows;
        public object $servers;
        public function __construct() { $this->servers = (object)['server' => self::$rows]; }
        public function getNodeByReference(string $path): ?Row { return self::$rows->items[substr($path, 15)] ?? null; }
    }
    class Client extends BaseModel
    {
        public static Rows $rows;
        public object $clients;
        public function __construct() { $this->clients = (object)['client' => self::$rows]; }
        public function getNodeByReference(string $path): ?Row { return self::$rows->items[substr($path, 15)] ?? null; }
    }
}
namespace OPNsense\Routing {
    use OPNsense\BlankVpn\{Rows, Row};
    class Gateways
    {
        public static Rows $rows;
        public Rows $gateway_item;
        public function __construct() { $this->gateway_item = self::$rows; }
        public function getNodeByReference(string $path): ?Row { return self::$rows->items[substr($path, 13)] ?? null; }
        public function getDefaultGW(mixed $group, string $family): array
        { return ['name' => 'WAN', 'if' => 'igc0', 'gateway' => '192.0.2.254']; }
    }
}
namespace {
    use OPNsense\BlankVpn\{WireGuard, Mullvad, Row, Rows};
    use OPNsense\Core\Config;
    use OPNsense\Routing\Gateways;
    use OPNsense\Wireguard\{Client, Server};

    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/WireGuard.php';
    function verify(bool $ok, string $message): void
    {
        if (!$ok) { throw new RuntimeException($message); }
    }
    function mustReject(callable $action, string $fragment): void
    {
        try { $action(); } catch (RuntimeException|DomainException $e) {
            verify(str_contains($e->getMessage(), $fragment), $e->getMessage());
            return;
        }
        throw new RuntimeException('Expected rejection: ' . $fragment);
    }
    $id = 'aaaaaaaa-1111-4111-8111-111111111111';
    $instanceId = 'bbbbbbbb-1111-4111-8111-111111111111';
    $peerId = 'cccccccc-1111-4111-8111-111111111111';
    $gatewayId = 'dddddddd-1111-4111-8111-111111111111';
    $owner = 'bvpn_' . substr(hash('sha256', $id), 0, 20);
    $gateway = strtoupper($owner) . '_4';
    $private = base64_encode(str_repeat('a', 32));
    $identityKey = (new Mullvad())->derivePublicKey($private);
    $serverKey = base64_encode(str_repeat('b', 32));
    $profile = ['id' => $id, 'owner' => $owner, 'name' => 'Existing', 'provider' => 'proton', 'relay' => '',
        'instance' => $instanceId, 'peer' => $peerId, 'gatewayId' => $gatewayId, 'gateway' => $gateway,
        'logicalInterface' => 'opt1', 'interface' => 'wg4', 'address' => '10.3.0.2/32', 'address6' => '',
        'privateFingerprint' => hash('sha256', $private), 'peerKey' => $serverKey, 'identityKey' => $identityKey,
        'port' => 51820, 'endpoint' => '192.0.2.1', 'keepalive' => 25, 'mtu' => 1420, 'pskFingerprint' => '',
        'dns' => ['10.3.0.1'], 'disabled' => true];
    Config::$xml = (object)['interfaces' => (object)['opt1' => (object)['if' => 'wg4', 'descr' => $owner,
        'enable' => '1', 'gateway_interface' => '1', 'ipaddr' => '', 'ipaddrv6' => '']]];
    $server = new Row(['name' => $owner, 'instance' => '4', 'enabled' => '0', 'disableroutes' => '1',
        'mtu' => '1420', 'peers' => $peerId, 'pubkey' => $identityKey, 'privkey' => $private, 'tunneladdress' => $profile['address']]);
    $peer = new Row(['name' => $owner, 'enabled' => '1', 'pubkey' => $serverKey, 'serveraddress' => '192.0.2.1',
        'serverport' => '51820', 'keepalive' => '25', 'tunneladdress' => '0.0.0.0/0']);
    Server::$rows = new Rows([$instanceId => $server]);
    Client::$rows = new Rows([$peerId => $peer]);
    Gateways::$rows = new Rows([$gatewayId => new Row(['name' => $gateway, 'interface' => 'opt1', 'ipprotocol' => 'inet',
        'monitor_disable' => '1', 'priority' => '255'])]);
    $replacement = ['privateKey' => base64_encode(str_repeat('c', 32)), 'address' => '10.3.0.2/32', 'address6' => '',
        'dns' => ['10.3.0.1'], 'keepalive' => 0, 'mtu' => 1350];
    $newRelay = ['host' => '192.0.2.2', 'port' => 443, 'publicKey' => base64_encode(str_repeat('d', 32))];
    $replace = static fn () => WireGuard::replaceProton($profile, $replacement, $newRelay);
    $peer->serverport = '53';
    mustReject($replace, 'changed outside');
    $peer->serverport = '51820';
    $other = new Row(['name' => 'independent', 'peers' => $peerId]);
    Server::$rows->items['other'] = $other;
    mustReject($replace, 'Another WireGuard instance references');
    $other->peers = '';
    $other->privkey = $replacement['privateKey'];
    mustReject($replace, 'already belongs to another tunnel');
    unset(Server::$rows->items['other']);
    Client::$rows->items['other'] = new Row(['name' => 'other', 'serveraddress' => '192.0.2.2',
        'port' => '443', 'serverport' => '443', 'pubkey' => $newRelay['publicKey']]);
    mustReject($replace, 'already has a WireGuard peer');
    unset(Client::$rows->items['other']);
    mustReject(static fn () => WireGuard::replaceProton($profile,
        array_replace($replacement, ['address6' => 'fd00::2/128']), $newRelay), 'IPv4-only');
    verify((string)$server->privkey === $private && (string)$peer->pubkey === $serverKey, 'Rejected changes cannot stage a partial replacement.');
    $new = $replace();
    verify($new['disabled'] && (string)$server->enabled === '0' && $new['id'] === $id && $new['gatewayId'] === $gatewayId &&
        $new['interface'] === 'wg4' && $new['address'] === '10.3.0.2/32' && $new['dns'] === ['10.3.0.1'],
        'Update credentials in place and keep disabled state, address slot, gateway, and policy references.');
    verify($new['privateFingerprint'] === hash('sha256', $replacement['privateKey']) &&
        (string)$server->privkey === $replacement['privateKey'] && (string)$peer->pubkey === $newRelay['publicKey'] &&
        (string)$server->mtu === '1350' && (string)$peer->keepalive === '' && $new['port'] === 443 &&
        !str_contains(json_encode($new), $replacement['privateKey']), 'Only the native instance stores the replacement private key.');
    verify(WireGuard::replaceProton($new, $replacement, $newRelay) === $new, 'The updated ownership record validates on retry.');
    echo "Proton native credential replacement fixtures passed.\n";
}
