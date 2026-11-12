<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class ProxyRuntime
{
    public const SLOTS = 8;
    public const FIRST_DNS_PORT = 46660;
    private const BIN = [
        'mihomo' => '/usr/local/libexec/blankvpn/mihomo',
        'tun2socks' => '/usr/local/libexec/blankvpn/tun2socks',
        'xray' => '/usr/local/libexec/blankvpn/xray',
        'sing-box' => '/usr/local/libexec/blankvpn/sing-box'
    ];

    private const SYSTEM_SING_BOX = '/usr/local/bin/sing-box';

    public static function routes(BlankVpn $model): array
    {
        $routes = [];
        $slots = [];
        foreach ($model->proxyRoutes->route->iterateItems() as $id => $node) {
            $values = Policy::fields($node);
            $slot = (int)$values['slot'];
            if (!in_array($values['core'] ?? '', ['mihomo', 'xray', 'sing-box'], true) || $slot < 0 || $slot >= self::SLOTS || isset($slots[$slot]) ||
                !preg_match('/^[a-f0-9]{64}$/D', $values['node'])) {
                continue;
            }
            $slots[$slot] = true;
            $routes[$id] = self::route($id, $slot, $values['node'], $values['name'], $values['core'], $values['protocol']);
        }
        return $routes;
    }

    public static function route(string $id, int $slot, string $node, string $name, string $core, string $protocol): array
    {
        return [
            'id' => $id, 'slot' => $slot, 'node' => $node, 'name' => $name, 'core' => $core, 'protocol' => $protocol,
            'kind' => 'proxy', 'relay' => '', 'interface' => 'tun' . (200 + $slot),
            'gateway' => 'BVPNP_' . substr(hash('sha256', $id), 0, 20),
            'address' => '198.19.254.' . (4 * $slot + 1) . '/30',
            'peer' => '198.19.254.' . (4 * $slot + 2),
            'dnsPort' => self::FIRST_DNS_PORT + $slot,
            'proxyDns' => 47200 + $slot, 'socksPort' => 47220 + $slot, 'adapterPort' => 47240 + $slot
        ];
    }

    public static function preflight(string $core): void
    {
        if (!in_array($core, ['mihomo', 'xray', 'sing-box'], true)) {
            throw new DomainException('Select a supported proxy core.');
        }
        foreach (array_unique(['mihomo', 'tun2socks', $core]) as $tool) {
            if (!self::available($tool)) {
                throw new DomainException('Install the verified ' . $tool . ' executable before enabling this proxy exit.');
            }
        }
    }

    public static function capabilities(): array
    {
        $result = [];
        foreach (array_keys(self::BIN) as $tool) {
            $result[$tool] = self::available($tool);
        }
        return $result;
    }

    private static function available(string $tool): bool
    {
        return isset(self::BIN[$tool]) && self::safeBinary(self::binary($tool));
    }

    private static function binary(string $tool): string
    {
        return ProxyCores::override($tool) ?? self::base($tool);
    }

    private static function base(string $tool): string
    {
        return $tool === 'sing-box' && self::usesSystemSingBox() ? self::SYSTEM_SING_BOX : self::BIN[$tool];
    }

    public static function usesSystemSingBox(): bool
    {
        return !self::safeBinary(self::BIN['sing-box']) && self::safeBinary(self::SYSTEM_SING_BOX);
    }

    public static function hasBase(string $tool): bool
    {
        return isset(self::BIN[$tool]) && self::safeBinary(self::base($tool));
    }

    private static function binaries(string $core): array
    {
        $paths = ['bridge' => self::binary('tun2socks'), 'mihomo' => self::binary('mihomo')];
        if ($core !== 'mihomo') {
            $paths['adapter'] = self::binary($core);
        }
        return $paths;
    }

    private static function safeBinary(string $path): bool
    {
        return !is_link($path) && is_file($path) && is_executable($path) &&
            @fileowner($path) === 0 && (fileperms($path) & 0022) === 0;
    }

    public static function configuration(array $route, array $node): array
    {
        $core = $node['core'];
        $adapter = null;
        $target = $node['config'];
        if ($core === 'xray') {
            $target['tag'] = 'selected';
            $adapter = [
                'log' => ['loglevel' => 'none'],
                'inbounds' => [[
                    'listen' => '127.0.0.1', 'port' => $route['adapterPort'], 'protocol' => 'socks',
                    'settings' => ['auth' => 'noauth', 'udp' => true, 'ip' => '127.0.0.1']
                ]],
                'outbounds' => [$target]
            ];
        } elseif ($core === 'sing-box') {
            $target['tag'] = 'selected';
            $adapter = [
                'log' => ['disabled' => true],
                'inbounds' => [[
                    'type' => 'socks', 'listen' => '127.0.0.1', 'listen_port' => $route['adapterPort']
                ]],
                'outbounds' => [$target],
                'route' => ['final' => 'selected', 'default_domain_resolver' => 'native'],
                'dns' => ['servers' => [['type' => 'local', 'tag' => 'native']], 'final' => 'native']
            ];
        }
        if ($adapter !== null) {
            $target = ['type' => 'socks5', 'server' => '127.0.0.1', 'port' => $route['adapterPort'], 'udp' => true];
        }
        $target['name'] = 'blankvpn-upstream';
        return [
            'adapter' => $adapter,
            'mihomo' => [
                'allow-lan' => false, 'bind-address' => '127.0.0.1', 'socks-port' => $route['socksPort'],
                'mode' => 'rule', 'log-level' => 'silent', 'ipv6' => true,
                'geo-auto-update' => false, 'tun' => ['enable' => false],
                'proxies' => [$target], 'rules' => ['MATCH,blankvpn-upstream'],
                'dns' => [
                    'enable' => true, 'listen' => '127.0.0.1:' . $route['proxyDns'],
                    'ipv6' => true, 'enhanced-mode' => 'redir-host',
                    'default-nameserver' => ['127.0.0.1'],
                    'proxy-server-nameserver' => ['127.0.0.1'],
                    'nameserver' => ['https://1.1.1.1/dns-query#blankvpn-upstream']
                ]
            ]
        ];
    }

    public static function ready(array $route): bool
    {
        $slot = $route['slot'];
        $state = self::marker($slot);
        $paths = self::binaries($route['core']);
        $recorded = $state['binaries'] ?? array_filter([
            'bridge' => self::BIN['tun2socks'], 'mihomo' => self::BIN['mihomo'],
            'adapter' => $route['core'] === 'mihomo' ? null : self::base($route['core'])
        ]);
        if ($recorded !== $paths || ($state['node'] ?? null) !== $route['node'] || ($state['id'] ?? null) !== $route['id'] ||
            self::pid($slot, 'bridge') === null || self::pid($slot, 'mihomo') === null ||
            ($route['core'] !== 'mihomo' && self::pid($slot, 'adapter') === null)) {
            return false;
        }
        $interface = self::ifconfig($route['interface']);
        return self::ownedInterface($route, $interface) &&
            preg_match('/^\s*inet\s+' . preg_quote(explode('/', $route['address'])[0], '/') . '\s/m', $interface) === 1;
    }

    public static function reconcile(BlankVpn $model): array
    {
        $desired = Policy::settings($model)['enabled'] ? array_column(self::routes($model), null, 'slot') : [];
        $catalog = $desired === [] ? [] : ProxyCatalog::read()['nodes'];
        $errors = [];
        $active = [];
        for ($slot = 0; $slot < self::SLOTS; $slot++) {
            $route = $desired[$slot] ?? null;
            if ($route !== null && self::ready($route)) {
                $active[] = $route['id'];
                continue;
            }
            try {
                self::stop($slot);
                if ($route !== null) {
                    $node = $catalog[$route['node']] ?? null;
                    if (!is_array($node)) {
                        throw new DomainException('Restore the proxy catalog entry for this exit.');
                    }
                    self::start($route, $node);
                    $active[] = $route['id'];
                }
            } catch (DomainException | RuntimeException $error) {
                if ($route !== null) {
                    $errors[$route['id']] = $error->getMessage();
                }
            }
        }
        $result = ['active' => $active, 'errors' => $errors];
        if ($desired !== [] || is_file(Policy::STATE_DIR . '/proxy-status.json')) {
            Policy::writeState('proxy-status.json', json_encode($result, JSON_THROW_ON_ERROR));
        }
        return $result;
    }

    public static function lastStatus(): array
    {
        $path = Policy::STATE_DIR . '/proxy-status.json';
        $data = is_file($path) ? json_decode((string)file_get_contents($path), true, 8) : null;
        return is_array($data) ? $data : ['active' => [], 'errors' => []];
    }

    public static function probe(array $route): array
    {
        if (!self::ready($route)) {
            return ['reachable' => false];
        }
        $curl = curl_init('https://cloudflare-dns.com/dns-query?name=example.com&type=A');
        if ($curl === false) {
            return ['reachable' => false];
        }
        curl_setopt_array($curl, [
            CURLOPT_PROXY => 'socks5h://127.0.0.1:' . $route['socksPort'],
            CURLOPT_NOPROXY => '', CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
            CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 4,
            CURLOPT_WRITEFUNCTION => static fn ($handle, string $body) => strlen($body)
        ]);
        return ['reachable' => curl_exec($curl) !== false && curl_getinfo($curl, CURLINFO_RESPONSE_CODE) === 200];
    }

    private static function start(array $route, array $node): void
    {
        self::preflight($node['core']);
        $slot = $route['slot'];
        $interface = $route['interface'];
        if (!file_exists('/dev/tun')) {
            throw new DomainException('The FreeBSD if_tun driver must be available to enable a proxy exit.');
        }
        if (self::ifconfig($interface) !== '') {
            throw new DomainException('A non-Blank VPN interface is using this proxy slot.');
        }
        foreach (Policy::localNetworks(['localNetworks' => []]) as $network) {
            if (Policy::contains($network, $route['peer'])) {
                throw new DomainException('The proxy tunnel address overlaps a local network.');
            }
        }
        $paths = self::path($slot);
        if (!is_dir($paths) && !mkdir($paths, 0700)) {
            throw new RuntimeException('Could not create the proxy runtime directory.');
        }
        if (is_link($paths) || (fileperms($paths) & 0077) !== 0) {
            throw new RuntimeException('The proxy runtime directory is not private.');
        }
        $configuration = self::configuration($route, $node);
        $binaries = self::binaries($node['core']);
        self::save($paths . '/owner.json', [
            'id' => $route['id'], 'node' => $route['node'], 'core' => $node['core'], 'binaries' => $binaries
        ]);
        try {
            if ($configuration['adapter'] !== null) {
                $adapter = $paths . '/adapter.json';
                self::save($adapter, $configuration['adapter']);
                $args = $node['core'] === 'xray' ? ['run', '-config', $adapter] : ['run', '-c', $adapter];
                self::launch($slot, 'adapter', [$binaries['adapter'], ...$args]);
                self::waitForSocket($route['adapterPort'], $slot, 'adapter');
            }
            $mihomo = $paths . '/mihomo.json';
            self::save($mihomo, $configuration['mihomo']);
            self::launch($slot, 'mihomo', [$binaries['mihomo'], '-d', $paths, '-f', $mihomo]);
            self::waitForSocket($route['socksPort'], $slot, 'mihomo');
            self::waitForSocket($route['proxyDns'], $slot, 'mihomo', 'udp4');
            self::launch($slot, 'bridge', [
                $binaries['bridge'], '--device', 'tun://' . $interface,
                '--proxy', 'socks5://127.0.0.1:' . $route['socksPort'], '--loglevel', 'error', '--mtu', '1400'
            ]);
            for ($attempt = 0; $attempt < 20; $attempt++) {
                if (self::ifconfig($interface) !== '' && self::pid($slot, 'bridge') !== null) {
                    break;
                }
                usleep(100000);
            }
            if (self::ifconfig($interface) === '' || self::pid($slot, 'bridge') === null) {
                throw new RuntimeException('The FreeBSD proxy tunnel did not start.');
            }
            Resolver::command([
                '/sbin/ifconfig', $interface, 'inet', $route['address'], 'description', 'BlankVPN-' . $route['id'], 'up'
            ]);
            if (!self::ready($route)) {
                throw new RuntimeException('The proxy tunnel started without a usable interface.');
            }
        } catch (\Throwable $error) {
            self::stop($slot);
            throw $error;
        }
    }

    private static function waitForSocket(int $port, int $slot, string $name, string $protocol = 'tcp4'): void
    {
        for ($attempt = 0; $attempt < 25; $attempt++) {
            $pid = self::pid($slot, $name);
            if ($pid !== null) {
                $rows = Resolver::command(['/usr/bin/sockstat', '-4', '-l', '-p', (string)$port], false);
                foreach (preg_split('/\R/', $rows) as $row) {
                    $fields = preg_split('/\s+/', trim($row));
                    if (($fields[2] ?? '') === (string)$pid && ($fields[4] ?? '') === $protocol &&
                        ($fields[5] ?? '') === '127.0.0.1:' . $port) {
                        return;
                    }
                }
            }
            usleep(100000);
        }
        throw new RuntimeException('A proxy core rejected the configuration or could not bind its local port.');
    }

    private static function path(int $slot): string
    {
        return Policy::STATE_DIR . '/proxy-slot-' . $slot;
    }

    private static function marker(int $slot): array
    {
        $path = self::path($slot) . '/owner.json';
        $data = is_file($path) ? json_decode((string)file_get_contents($path), true, 8) : null;
        return is_array($data) ? $data : [];
    }

    private static function save(string $path, array $config): void
    {
        $file = fopen($path, 'wb');
        if ($file === false) {
            throw new RuntimeException('Could not write a private proxy runtime file.');
        }
        try {
            chmod($path, 0600);
            $bytes = json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (fwrite($file, $bytes) !== strlen($bytes)) {
                throw new RuntimeException('Could not write the complete proxy runtime file.');
            }
        } finally {
            fclose($file);
        }
    }

    private static function launch(int $slot, string $name, array $command): void
    {
        Resolver::command([
            '/usr/sbin/daemon', '-f', '-p', self::path($slot) . '/' . $name . '.pid', '--', ...$command
        ]);
    }

    private static function pid(int $slot, string $name): ?int
    {
        $paths = self::path($slot);
        $file = $paths . '/' . $name . '.pid';
        $value = is_file($file) ? trim((string)file_get_contents($file)) : '';
        if (!ctype_digit($value) || (int)$value < 2) {
            return null;
        }
        $args = trim(Resolver::command(['/bin/ps', '-ww', '-p', $value, '-o', 'command='], false));
        $marker = self::marker($slot);
        $tool = match ($name) {
            'bridge' => 'tun2socks',
            'mihomo' => 'mihomo',
            'adapter' => $marker['core'] ?? '',
            default => ''
        };
        $recorded = $marker['binaries'][$name] ?? null;
        if (is_string($recorded) && isset(self::BIN[$tool])) {
            $known = $recorded === self::BIN[$tool] || ($tool === 'sing-box' && $recorded === self::SYSTEM_SING_BOX) ||
                ProxyCores::isManagedPath($tool, $recorded);
            $matches = $known && str_starts_with($args, $recorded . ' ');
        } else {
            $matches = isset(self::BIN[$tool]) && (str_starts_with($args, self::BIN[$tool] . ' ') ||
                ($tool === 'sing-box' && str_starts_with($args, self::SYSTEM_SING_BOX . ' ')));
        }
        if (!$matches) {
            return null;
        }
        $valid = match ($name) {
            'bridge' => str_contains($args, 'tun://tun' . (200 + $slot) . ' ') &&
                str_contains($args, 'socks5://127.0.0.1:' . (47220 + $slot) . ' '),
            'mihomo' => str_ends_with($args, $paths . '/mihomo.json'),
            'adapter' => str_ends_with($args, $paths . '/adapter.json'),
            default => false
        };
        return $valid ? (int)$value : null;
    }

    private static function ifconfig(string $device): string
    {
        return Resolver::command(['/sbin/ifconfig', $device], false);
    }

    private static function ownedInterface(array $route, string $state): bool
    {
        return preg_match('/^\s*description:\s+BlankVPN-' . preg_quote($route['id'], '/') . '\s*$/m', $state) === 1;
    }

    private static function stop(int $slot): void
    {
        $paths = self::path($slot);
        if (!is_dir($paths)) {
            return;
        }
        $owner = self::marker($slot);
        foreach (['bridge', 'mihomo', 'adapter'] as $name) {
            $pid = self::pid($slot, $name);
            if ($pid === null) {
                continue;
            }
            Resolver::command(['/bin/kill', '-TERM', (string)$pid], false);
            for ($attempt = 0; $attempt < 15 && self::pid($slot, $name) !== null; $attempt++) {
                usleep(100000);
            }
            if (self::pid($slot, $name) !== null) {
                throw new RuntimeException('A proxy core is still stopping. Retry after it exits.');
            }
        }
        if (is_string($owner['id'] ?? null)) {
            $device = 'tun' . (200 + $slot);
            if (self::ownedInterface(['id' => $owner['id']], self::ifconfig($device))) {
                Resolver::command(['/sbin/ifconfig', $device, 'destroy']);
            }
        }
        foreach (['owner.json', 'adapter.json', 'mihomo.json', 'bridge.pid', 'mihomo.pid', 'adapter.pid'] as $file) {
            if (is_file($paths . '/' . $file)) {
                unlink($paths . '/' . $file);
            }
        }
    }
}
