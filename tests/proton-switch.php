<?php

declare(strict_types=1);

namespace OPNsense\Base {
    class ApiControllerBase
    {
        protected object $request;
        protected object $response;

        public function __construct(array $fields, bool $post = true, string $scheme = 'https')
        {
            $this->request = new class ($fields, $post, $scheme) {
                public function __construct(private array $fields, private bool $post, private string $scheme) {}
                public function isPost(): bool { return $this->post; }
                public function getScheme(): string { return $this->scheme; }
                public function getPost(string $key, mixed $filter = null, mixed $default = null): mixed
                { return $this->fields[$key] ?? $default; }
            };
            $this->response = new class {
                public function setHeader(string $key, string $value): void {}
            };
        }
    }
}

namespace OPNsense\Core {
    final class Config
    {
        public static function getInstance(): self { return new self(); }
        public function object(): object { return (object)[]; }
    }
}

namespace OPNsense\BlankVpn {
    final class BlankVpn
    {
        public object $profiles;
        public object $node;
        public function __construct()
        {
            $this->node = new \stdClass();
            $this->profiles = (object)['profile' => new class ($this->node) {
                public function __construct(private object $node) {}
                public function getChild(string $id): object
                {
                    if ($id !== Policy::$profile['id']) { throw new \RuntimeException('Unknown profile'); }
                    return $this->node;
                }
            }];
        }
    }
    final class Policy
    {
        public static array $profile;
        public static function settings(BlankVpn $model): array { return []; }
        public static function localNetworks(array $settings): array { return []; }
        public static function profiles(BlankVpn $model): array { return [self::$profile['id'] => self::$profile]; }
        public static function writeState(string $name, string $data): void
        {
            if ($name !== 'health.json') { throw new \RuntimeException('Unexpected state change'); }
            Firewall::$health = json_decode($data, true, flags: JSON_THROW_ON_ERROR);
        }
    }
    final class Firewall
    {
        public static array $health = [];
        public static function health(): array { return self::$health; }
    }
    final class Operations
    {
        public static array $lastChange = [];
        public static bool $applyFails = false;
        private static bool $locked = false;
        public static function exclusive(callable $work): mixed
        {
            self::$locked = true;
            try { return $work(); } finally { self::$locked = false; }
        }
        public static function change(callable $edit): array
        {
            if (!self::$locked) { throw new \RuntimeException('Unlocked change'); }
            $model = new BlankVpn();
            self::$lastChange = $edit($model);
            if (isset(self::$lastChange['added']) && self::$applyFails) {
                throw new \RuntimeException('Native apply failed and was rolled back.');
            }
            $fields = array_intersect_key(Policy::$profile, array_flip(['id', 'name', 'relay']));
            Policy::$profile = $fields + json_decode($model->node->ownership, true, flags: JSON_THROW_ON_ERROR);
            return self::$lastChange;
        }
    }
    final class VpnProviders
    {
        public static bool $available = true;
        public static int $reads = 0;
        public function protonServers(string $tier): array
        {
            self::$reads++;
            if (!self::$available || $tier !== 'free') { throw new \RuntimeException('Unavailable catalog'); }
            return [
                'jp' => ['name' => 'JP-FREE#1', 'country' => 'Japan', 'city' => 'Tokyo', 'publicKey' => 'jp-key',
                    'ipv4' => '192.0.2.2', 'port' => 51820],
                'nl' => ['name' => 'NL-FREE#2', 'country' => 'Netherlands', 'city' => 'Amsterdam', 'publicKey' => 'nl-key',
                    'ipv4' => '192.0.2.3', 'port' => 51820],
            ];
        }
        public static function protonRelay(array $server): array { return $server; }
    }
    final class WireGuard
    {
        public static bool $owned = true;
        public static function tunnelNetworks(string $except): array
        {
            if ($except !== 'instance-id') { throw new \RuntimeException('Allocation must exclude the tunnel being replaced.'); }
            return [];
        }
        public static function replaceProton(array $profile, array $config, array $relay): array
        {
            return self::retarget($profile, $relay) + ['fixtureKeyHash' => hash('sha256', $config['privateKey'])];
        }
        public static function retarget(array $profile, array $relay): array
        {
            if (!self::$owned) { throw new \RuntimeException('The peer no longer belongs to this profile.'); }
            return array_replace($profile, ['endpoint' => $relay['ipv4'] ?? $relay['host'], 'port' => $relay['port'], 'peerKey' => $relay['publicKey']]);
        }
    }
}

namespace {
    use OPNsense\BlankVpn\Api\ServiceController;
    use OPNsense\BlankVpn\{Firewall, Operations, Policy, VpnProviders, WireGuard};

    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Mullvad.php';
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/ProtonTunnels.php';
    require __DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/BlankVpn/Api/ServiceController.php';

    function verify(bool $passed, string $message): void
    {
        if (!$passed) { throw new RuntimeException($message); }
    }
    function choose(string $server, string $id = 'existing'): array
    {
        return (new ServiceController(['profile' => $id, 'server' => $server, 'ipv4' => '127.0.0.1']))->switchProtonServerAction();
    }
    $initial = Policy::$profile = ['id' => 'existing', 'name' => 'My Proton exit', 'relay' => '', 'provider' => 'proton',
        'peerKey' => 'import-key', 'port' => 443, 'endpoint' => '192.0.2.1', 'dns' => ['10.2.0.1'], 'address' => '10.2.0.2/32',
        'interface' => 'wg3', 'instance' => 'instance-id', 'privateFingerprint' => 'existing-identity-fingerprint', 'pskFingerprint' => ''];
    $original = ['ipv4' => '192.0.2.1', 'port' => 443, 'publicKey' => 'import-key'];

    verify(!(new ServiceController([], false))->switchProtonServerAction()['ok'] &&
        !(new ServiceController([], true, 'http'))->switchProtonServerAction()['ok'] && VpnProviders::$reads === 0,
        'An HTTPS POST is required before looking up or changing any server.');
    $menu = (new ServiceController([]))->protonServersAction();
    verify($menu['ok'] && $menu['servers'][0] === ['id' => 'jp', 'name' => 'JP-FREE#1', 'country' => 'Japan', 'city' => 'Tokyo'],
        'The Free menu exposes only the ID and display fields.');
    verify(!choose('127.0.0.1')['ok'] && !choose('jp', 'native-gateway')['ok'], 'Accept only catalog IDs and imported profiles.');
    foreach ([['provider' => 'mullvad'], ['relay' => 'us-test-wg-001'], ['pskFingerprint' => 'custom-psk']] as $change) {
        Policy::$profile = array_replace($initial, $change);
        verify(!choose('jp')['ok'] && Policy::$profile === array_replace($initial, $change), 'Reject ineligible profiles.');
    }

    Policy::$profile = $initial;
    WireGuard::$owned = false;
    verify(!choose('jp')['ok'] && Policy::$profile === $initial, 'Verify native WireGuard ownership before updating metadata.');
    WireGuard::$owned = true;
    Firewall::$health = ['existing' => ['reachable' => true, 'probeSucceeded' => true]];
    Operations::$applyFails = true;
    verify(!choose('jp')['ok'] && Policy::$profile === $initial && isset(Firewall::$health['existing']),
        'Failed native apply keeps the previous peer and its health record.');
    Operations::$applyFails = false;
    $result = choose('jp');
    verify($result['ok'] && $result['profile'] === 'existing' && count($result) === 3 &&
        Policy::$profile === array_replace($initial, ['peerKey' => 'jp-key', 'port' => 51820, 'endpoint' => '192.0.2.2',
            'protonOriginalPeer' => $original, 'providerLocation' => 'jp', 'providerServer' => 'JP-FREE#1']) &&
        Operations::$lastChange['reload'] && empty(Firewall::$health), 'Replace just the public peer and keep the imported route and identity.');
    verify(choose('jp')['ok'] && empty(Operations::$lastChange['added']), 'Retrying the same switch never reapplies a native peer.');
    Policy::$profile['disabled'] = true;
    Firewall::$health = ['existing' => ['reachable' => false, 'checkedAt' => 1234]];
    verify(choose('nl')['ok'] && empty(Operations::$lastChange['added']) && empty(Operations::$lastChange['reload']) &&
        Policy::$profile['disabled'] && Policy::$profile['protonOriginalPeer'] === $original &&
        Firewall::$health['existing'] === ['reachable' => false, 'failures' => 2],
        'A disabled tunnel stays disabled, retains its original server, and keeps an outage pending a new test.');

    $reads = VpnProviders::$reads;
    VpnProviders::$available = false;
    verify(choose('original')['ok'] && Policy::$profile === $initial + ['disabled' => true] &&
        empty(Operations::$lastChange['added']), 'Restore the original endpoint, key and port without enabling the tunnel.');
    verify(choose('original')['ok'] && empty(Operations::$lastChange['added']) && VpnProviders::$reads === $reads,
        'Restore and its retries work while the directory is offline.');
    $private = base64_encode(str_repeat('c', 32));
    $peer = base64_encode(str_repeat('p', 32));
    $text = "[Interface]\nPrivateKey = $private\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n" .
        "[Peer]\nPublicKey = $peer\nEndpoint = 192.0.2.40:51820\nAllowedIPs = 0.0.0.0/0\n";
    $fields = ['profile' => 'existing', 'config' => $text];
    $replace = new ServiceController($fields);
    verify(!(new ServiceController($fields, true, 'http'))->replaceProtonProfileAction()['ok'] &&
        !(new ServiceController($fields, false))->replaceProtonProfileAction()['ok'],
        'Credential replacement accepts only HTTPS POST.');
    verify(!(new ServiceController(array_replace($fields, ['profile' => 'foreign'])))->replaceProtonProfileAction()['ok'],
        'Credential replacement cannot modify a native gateway.');
    VpnProviders::$available = true;
    verify(choose('jp')['ok'], 'Stage a switched profile before changing account.');
    $before = Policy::$profile;
    WireGuard::$owned = false;
    verify(!$replace->replaceProtonProfileAction()['ok'] && Policy::$profile === $before,
        'Changes to native ownership abort an account replacement.');
    WireGuard::$owned = true;
    unset(Policy::$profile['disabled']);
    $before = Policy::$profile;
    Operations::$applyFails = true;
    verify(!$replace->replaceProtonProfileAction()['ok'] && Policy::$profile === $before, 'Failed apply keeps the preceding credentials.');
    Operations::$applyFails = false;
    $response = $replace->replaceProtonProfileAction();
    verify($response['ok'] && $response['profile'] === 'existing' && !str_contains(json_encode($response), $private) &&
        !isset(Policy::$profile['protonOriginalPeer']) && !isset(Policy::$profile['providerLocation']) &&
        Policy::$profile['endpoint'] === '192.0.2.40' && Policy::$profile['name'] === $initial['name'] &&
        Operations::$lastChange['reload'], 'Rebinding a tunnel keeps its route and clears previous-account restoration.');
    $otherGateway = (new ServiceController($fields + ['server' => 'nl']))->replaceProtonProfileAction();
    verify($otherGateway['ok'] && Policy::$profile['endpoint'] === '192.0.2.3' &&
        Policy::$profile['protonOriginalPeer'] === ['publicKey' => $peer, 'host' => '192.0.2.40', 'port' => 51820] &&
        choose('original')['ok'] && Policy::$profile['endpoint'] === '192.0.2.40',
        'Choosing a different gateway during replacement restores only the new account’s imported peer.');
    echo "Proton VPN switch, replacement and restore controller fixtures passed.\n";
}
