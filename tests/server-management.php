<?php

declare(strict_types=1);

namespace {
    define('SERVER_MANAGEMENT_STATE', sys_get_temp_dir() . '/blankvpn-server-management-' . getmypid());
    mkdir(SERVER_MANAGEMENT_STATE, 0700);
    register_shutdown_function(static function (): void {
        foreach (glob(SERVER_MANAGEMENT_STATE . '/*') as $path) {
            unlink($path);
        }
        rmdir(SERVER_MANAGEMENT_STATE);
    });
}

namespace OPNsense\Base {
    class ApiControllerBase
    {
        protected object $request;
        protected object $response;
        public function __construct(array $fields, bool $post = true)
        {
            $this->request = new class ($fields, $post) {
                public function __construct(private array $fields, private bool $post) {}
                public function isPost(): bool { return $this->post; }
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
    final class Policy
    {
        public const STATE_DIR = \SERVER_MANAGEMENT_STATE;
        public static array $routes = [];
        public static array $assignments = [];
        public static array $settings = ['networkProfile' => '', 'tailnetNetworkProfile' => ''];
        public static int $catalogWrites = 0;
        public static function routes(BlankVpn $model): array { return self::$routes; }
        public static function assignments(BlankVpn $model): array { return self::$assignments; }
        public static function settings(BlankVpn $model): array { return self::$settings; }
        public static function anyEnabled(array $settings): bool { return true; }
        public static function writeState(string $file, string $bytes): void
        {
            file_put_contents(self::STATE_DIR . '/pending', $bytes);
            chmod(self::STATE_DIR . '/pending', 0600);
            rename(self::STATE_DIR . '/pending', self::STATE_DIR . '/' . $file);
            self::$catalogWrites += $file === 'proxy-catalog.json' ? 1 : 0;
        }
    }
    final class BlankVpn
    {
        public object $profiles;
        public object $proxyRoutes;
        public object $nativeRoutes;
        public function __construct()
        {
            $collection = new class {
                public function del(string $id): void { unset(Policy::$routes[$id]); }
            };
            $this->profiles = (object)['profile' => $collection];
            $this->proxyRoutes = $this->nativeRoutes = (object)['route' => $collection];
        }
    }
    final class SmartRouting
    {
        public static array $services = [];
        public static function services(BlankVpn $model): array { return self::$services; }
    }
    final class ProxyRuntime
    {
        public static function routes(BlankVpn $model): array
        { return array_filter(Policy::$routes, static fn (array $row): bool => ($row['kind'] ?? '') === 'proxy'); }
    }
    final class WireGuard
    {
        public static array $validated = [];
        public static array $removed = [];
        public static ?string $reject = null;
        public static function validateRemoval(array $profile): void
        {
            self::$validated[] = $profile['id'];
            if ($profile['id'] === self::$reject) {
                throw new \RuntimeException('Another native gateway uses this interface.');
            }
        }
        public static function remove(array $profile): void { self::$removed[] = $profile['id']; }
    }
    final class Operations
    {
        public static array $changes = [];
        public static function exclusive(callable $work): mixed { return $work(); }
        public static function change(callable $edit): array
        {
            $result = $edit(new BlankVpn());
            self::$changes[] = $result;
            if (isset($result['catalogRemoval'])) {
                ProxyCatalog::applyRemoval($result['catalogRemoval']);
            }
            return $result;
        }
    }
}

namespace {
    use OPNsense\BlankVpn\Api\ServiceController;
    use OPNsense\BlankVpn\Operations;
    use OPNsense\BlankVpn\Policy;
    use OPNsense\BlankVpn\ProxyCatalog;
    use OPNsense\BlankVpn\ProxyImport;
    use OPNsense\BlankVpn\SmartRouting;
    use OPNsense\BlankVpn\WireGuard;

    foreach (['ProxyCatalog', 'ProxyImport', 'VpnProviders', 'RouteGroups'] as $library) {
        require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $library . '.php';
    }
    require __DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/BlankVpn/Api/ServiceController.php';

    function verifyServers(bool $condition, string $message): void
    {
        if (!$condition) { throw new RuntimeException($message); }
    }
    function expectServerRejection(callable $work, string $message): void
    {
        try { $work(); } catch (DomainException) { return; }
        throw new RuntimeException($message);
    }
    function removeVpn(array $profiles, array $nodes = []): array
    {
        return (new ServiceController(['selection' => json_encode(compact('profiles', 'nodes'))]))->removeProfilesAction();
    }
    function seedServers(array $data): void
    {
        Policy::writeState('proxy-catalog.json', json_encode($data, JSON_THROW_ON_ERROR));
        Policy::$catalogWrites = 0;
    }

    $node = array_values(ProxyImport::parse('trojan://fixture-secret@192.0.2.1:443?sni=example.com#Original%20server')['nodes'])[0];
    $id = $node['id'];
    $node['sources'] = ['manual', 'feed'];
    $node['disabled'] = true;
    $data = ['nodes' => [$id => $node], 'feeds' => ['feed' => ['name' => 'Subscription', 'count' => 1, 'auto' => false]]];
    seedServers($data);
    $renamed = (new ServiceController(['id' => $id, 'name' => 'My alias']))->renameProxyNodeAction();
    $saved = ProxyCatalog::read()['nodes'][$id];
    verifyServers($renamed === ['ok' => true] && $saved === array_replace($node, ['name' => 'My alias', 'customName' => true]),
        'Renaming must preserve every connection field, identity, original label, source and disabled state.');
    $public = ProxyCatalog::publicView()['nodes'][0];
    verifyServers($public['name'] === 'My alias' && $public['serverName'] === 'Original server' &&
        !isset($public['config']) && !str_contains(json_encode($public), 'fixture-secret'),
        'Expose a separate original server name without credentials.');
    $refresh = new ReflectionMethod(ProxyCatalog::class, 'replaceNodes');
    $refreshed = ProxyCatalog::read();
    $newLabel = array_replace($node, ['name' => 'Updated server', 'serverName' => 'Updated server']);
    $refresh->invokeArgs(null, [&$refreshed, 'feed', [$id => $newLabel], []]);
    verifyServers($refreshed['nodes'][$id]['name'] === 'My alias' && $refreshed['nodes'][$id]['serverName'] === 'Updated server' &&
        $refreshed['nodes'][$id]['config'] === $node['config'], 'Subscription refresh updates the server label while retaining the alias.');
    seedServers(['nodes' => [$id => array_diff_key($saved, ['serverName' => true])], 'feeds' => []]);
    verifyServers(ProxyCatalog::publicView()['nodes'][0]['serverName'] === $node['host'],
        'An older custom alias must use the endpoint when the original server label cannot be recovered.');
    ProxyCatalog::import('socks5://192.0.2.2:1080#Imported%20label', 'Custom import alias');
    $custom = array_values(array_filter(ProxyCatalog::read()['nodes'], static fn (array $entry): bool => $entry['host'] === '192.0.2.2'))[0];
    verifyServers($custom['name'] === 'Custom import alias' && $custom['serverName'] === 'Imported label',
        'A custom import name must not overwrite the upstream label.');

    $nodes = [];
    for ($i = 0; $i < 1201; $i++) {
        $key = hash('sha256', (string)$i);
        $nodes[$key] = array_replace($node, ['id' => $key]);
    }
    seedServers(['nodes' => $nodes, 'feeds' => $data['feeds']]);
    $ids = array_keys($nodes);
    $before = file_get_contents(Policy::STATE_DIR . '/proxy-catalog.json');
    expectServerRejection(fn () => ProxyCatalog::prepareRemoval($ids, [$ids[1000]]), 'An in-use node must block the full batch.');
    expectServerRejection(fn () => ProxyCatalog::prepareRemoval([$ids[0], str_repeat('f', 64)], []), 'A stale node must block the full batch.');
    verifyServers(file_get_contents(Policy::STATE_DIR . '/proxy-catalog.json') === $before && Policy::$catalogWrites === 0,
        'Rejected batches must not partially remove servers.');
    $removed = (new ServiceController(['selection' => json_encode($ids)]))->removeProxyNodesAction();
    verifyServers($removed === ['ok' => true, 'removed' => 1201] && ProxyCatalog::read()['nodes'] === [] &&
        ProxyCatalog::read()['feeds']['feed']['count'] === 0 && Policy::$catalogWrites === 1,
        'A selection above PHP max_input_vars removes every node in one catalog write and updates subscription counts.');
    seedServers($data);
    $plan = ProxyCatalog::prepareRemoval([$id], []);
    ProxyCatalog::renameNode($id, 'Concurrent name');
    expectServerRejection(fn () => ProxyCatalog::applyRemoval($plan), 'A stale catalog snapshot must not overwrite a later edit.');
    verifyServers(ProxyCatalog::read()['nodes'][$id]['name'] === 'Concurrent name', 'A rejected plan preserves the newer data.');
    foreach (['[]', 'null', '{}', '[1]', '[["x"]]', '["invalid"]', '{"nodes":[]}'] as $invalid) {
        verifyServers(!(new ServiceController(['selection' => $invalid]))->removeProxyNodesAction()['ok'],
            'Malformed selections must fail without changing the catalog.');
    }
    verifyServers(!(new ServiceController(['selection' => json_encode([$id])], false))->removeProxyNodesAction()['ok'],
        'Removal requires POST.');

    $first = '11111111-1111-4111-8111-111111111111';
    $second = '22222222-2222-4222-8222-222222222222';
    $third = '33333333-3333-4333-8333-333333333333';
    $profiles = [
        $first => ['id' => $first, 'relay' => '', 'interface' => 'wg1'],
        $second => ['id' => $second, 'relay' => '', 'interface' => 'wg2'],
        $third => ['id' => $third, 'kind' => 'native'],
    ];
    Policy::$routes = $profiles;
    foreach (['device', 'backup', 'networkProfile', 'tailnetNetworkProfile', 'service', 'native'] as $guard) {
        Policy::$assignments = in_array($guard, ['device', 'backup'])
            ? [['profile' => $guard === 'device' ? $second : '', 'backup' => $guard === 'backup' ? $second : '']] : [];
        Policy::$settings = ['networkProfile' => '', 'tailnetNetworkProfile' => ''];
        if (in_array($guard, ['networkProfile', 'tailnetNetworkProfile'])) { Policy::$settings[$guard] = $second; }
        SmartRouting::$services = $guard === 'service' ? [['profile' => $second]] : [];
        WireGuard::$reject = $guard === 'native' ? $second : null;
        $response = removeVpn([$first, $second, $third]);
        verifyServers(!$response['ok'] && Policy::$routes === $profiles && WireGuard::$removed === [] && Operations::$changes === [],
            'The entire VPN batch must remain unchanged when any routing or native reference blocks removal: ' . $guard);
    }
    Policy::$assignments = [];
    Policy::$settings = ['networkProfile' => '', 'tailnetNetworkProfile' => ''];
    SmartRouting::$services = [];
    WireGuard::$reject = null;
    $response = removeVpn([$first, $second, $third, $first]);
    verifyServers($response === ['ok' => true, 'removed' => 3] && Policy::$routes === [] && count(Operations::$changes) === 1 &&
        count(Operations::$changes[0]['removedProfiles']) === 2 && Operations::$changes[0]['reload'] === true,
        'Deduplicate VPN selections and retire all owned tunnels in one configuration transaction.');
    verifyServers(WireGuard::$removed === [$first, $second], 'Native references must not delete externally managed tunnels.');

    $nord = array_replace($node, ['provider' => 'nord', 'providerLocation' => 'us123.nordvpn.com', 'sources' => ['managed-nord']]);
    seedServers(['nodes' => [$id => $nord], 'feeds' => []]);
    Policy::$routes = [$first => ['id' => $first, 'kind' => 'proxy', 'node' => $id]];
    verifyServers(!(new ServiceController(['selection' => json_encode([$id])]))->removeProxyNodesAction()['ok'],
        'The generic proxy list cannot delete a managed VPN or a node with an existing proxy exit.');
    $response = removeVpn([], [$id]);
    verifyServers($response === ['ok' => true, 'removed' => 1] && Policy::$routes === [] && ProxyCatalog::read()['nodes'] === [],
        'Managed Nord VPN removal deletes its unused route and private node in one transaction without exposing the catalog.');
    echo "Server management fixtures passed.\n";
}
