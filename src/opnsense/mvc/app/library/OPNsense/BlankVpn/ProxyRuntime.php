<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class ProxyRuntime
{
    public const SLOTS = 8;
    public const FIRST_DNS_PORT = 46660;
    private const TEST_SLOTS = [self::SLOTS, self::SLOTS + 1];
    private const CONFIG_VERSION = 4;
    private const RETRY_LIMIT = 900;
    private const STATUS_FILE = 'proxy-status.json';
    private const PROBE_TARGETS = [
        'https://1.1.1.1/dns-query?name=example.com&type=A' => [200, 3000],
        'https://223.5.5.5/resolve?name=example.com&type=A' => [200, 3000],
        'https://www.gstatic.com/generate_204' => [204, 2000]
    ];
    private const BIN = [
        'mihomo' => '/usr/local/libexec/blankvpn/mihomo',
        'tun2socks' => '/usr/local/libexec/blankvpn/tun2socks',
        'xray' => '/usr/local/libexec/blankvpn/xray',
        'sing-box' => '/usr/local/libexec/blankvpn/sing-box'
    ];
    private const SYSTEM_BIN = [
        'mihomo' => '/usr/local/bin/mihomo', 'tun2socks' => '/usr/local/bin/tun2socks',
        'xray' => '/usr/local/bin/xray', 'sing-box' => '/usr/local/bin/sing-box'
    ];

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

    public static function assignedRoutes(BlankVpn $model): array
    {
        $settings = Policy::effectiveRouting($model);
        $services = SmartRouting::forwardServices($settings, SmartRouting::services($model));
        $selected = array_column($services, 'profile');
        $assignments = Policy::deviceAssignments($settings, Policy::assignments($model, true));
        foreach ($assignments as $row) {
            if (Policy::usesBase(Policy::mode($row))) {
                $selected[] = $row['profile'];
                if (($row['failure'] ?? '') === 'backup') {
                    $selected[] = $row['backup'];
                }
            }
        }
        foreach (Policy::scopes($settings) as $scope) {
            if ($scope['coverage'] === 'network' && Policy::usesBase($scope['networkMode'])) {
                $selected[] = $scope['networkProfile'];
                if (($scope['networkBackupProfile'] ?? '') !== '') {
                    $selected[] = $scope['networkBackupProfile'];
                }
            }
        }
        $routes = self::routes($model);
        $aliases = RouteGroups::aliases($model, Policy::routes($model, false), Firewall::health());
        foreach ($selected as $choice) {
            if (isset($aliases[$choice])) {
                $selected[] = $aliases[$choice]['id'];
            }
        }
        return array_intersect_key($routes, array_fill_keys($selected, true));
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
                if (ProxyCores::usesSystemPackages()) {
                    $package = ['mihomo' => 'mihomo', 'tun2socks' => 'tun2socks',
                        'xray' => 'xray-core', 'sing-box' => 'sing-box'][$tool] ?? $tool;
                    throw new DomainException('Install the ' . $package .
                        ' package from the OPNsense Firmware package catalog before enabling this proxy exit.');
                }
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
        if (ProxyCores::usesSystemPackages()) {
            return self::SYSTEM_BIN[$tool] ?? self::BIN[$tool];
        }
        return $tool === 'sing-box' && self::usesSystemSingBox() ? self::SYSTEM_BIN['sing-box'] : self::BIN[$tool];
    }

    public static function usesSystemSingBox(): bool
    {
        return !self::safeBinary(self::BIN['sing-box']) && self::safeBinary(self::SYSTEM_BIN['sing-box']);
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
            $target['streamSettings'] ??= [];
            $target['streamSettings']['sockopt'] ??= [];
            // Route the endpoint lookup through Xray's encrypted local DoH
            // module rather than leaving domain resolution to the host.
            $target['streamSettings']['sockopt']['domainStrategy'] = 'UseIP';
            $adapter = [
                'log' => ['loglevel' => 'none'],
                // Xray otherwise uses the host resolver when its DNS module is absent.
                // Local DoH breaks the bootstrap loop while keeping queries encrypted.
                'dns' => [
                    'servers' => [
                        'https+local://1.1.1.1/dns-query',
                        'https+local://9.9.9.9/dns-query'
                    ],
                    'queryStrategy' => 'UseIP'
                ],
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
                // Resolve the upstream proxy hostname with validated DoT to IP-literal
                // servers; a local resolver would use the router's system DNS.
                'route' => ['final' => 'selected', 'default_domain_resolver' => 'bootstrap'],
                'dns' => [
                    'servers' => [
                        [
                            'type' => 'tls', 'tag' => 'bootstrap',
                            'server' => '1.1.1.1', 'server_port' => 853,
                            'tls' => ['enabled' => true, 'server_name' => 'cloudflare-dns.com']
                        ],
                        [
                            'type' => 'tls', 'tag' => 'bootstrap-fallback',
                            'server' => '9.9.9.9', 'server_port' => 853,
                            'tls' => ['enabled' => true, 'server_name' => 'dns.quad9.net']
                        ]
                    ],
                    'final' => 'bootstrap'
                ]
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
                'profile' => ['store-selected' => false, 'store-fake-ip' => false],
                'proxies' => [$target], 'rules' => ['MATCH,blankvpn-upstream'],
                'dns' => [
                    'enable' => true, 'listen' => '127.0.0.1:' . $route['proxyDns'],
                    'ipv6' => false, 'enhanced-mode' => 'redir-host',
                    'default-nameserver' => ['tls://1.1.1.1', 'tls://9.9.9.9'],
                    'proxy-server-nameserver' => ['tls://1.1.1.1', 'tls://9.9.9.9'],
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
            'bridge' => self::binary('tun2socks'), 'mihomo' => self::binary('mihomo'),
            'adapter' => $route['core'] === 'mihomo' ? null : self::base($route['core'])
        ]);
        if (($state['configVersion'] ?? 0) !== self::CONFIG_VERSION || $recorded !== $paths ||
            ($state['node'] ?? null) !== $route['node'] || ($state['id'] ?? null) !== $route['id'] ||
            self::pid($slot, 'bridge', $state) === null) {
            return false;
        }
        $interface = self::ifconfig($route['interface']);
        if (!self::ownedInterface($route, $interface) ||
            preg_match('/^' . preg_quote($route['interface'], '/') . ': flags=[0-9a-f]+<(?:[^>]+,)?UP(?:,[^>]+)?>/im', $interface) !== 1 ||
            preg_match('/^\s*inet\s+' . preg_quote(explode('/', $route['address'])[0], '/') . '\s/m', $interface) !== 1) {
            return false;
        }
        $mihomo = self::pid($slot, 'mihomo', $state);
        if ($mihomo === null) {
            return false;
        }
        $listeners = [$route['socksPort'] => [$mihomo, 'tcp4'], $route['proxyDns'] => [$mihomo, 'udp4']];
        if ($route['core'] !== 'mihomo') {
            $adapter = self::pid($slot, 'adapter', $state);
            if ($adapter === null) {
                return false;
            }
            $listeners[$route['adapterPort']] = [$adapter, 'tcp4'];
        }
        return self::boundListeners($listeners);
    }

    public static function reconcile(BlankVpn $model, bool $background = false): array
    {
        // Do not interrupt a live ping running in one of the bounded test slots.
        foreach (self::TEST_SLOTS as $slot) {
            try {
                self::stopUnusedTestSlot($slot);
            } catch (RuntimeException $error) {
                syslog(LOG_WARNING, 'Blank VPN proxy test cleanup: ' . $error->getMessage());
            }
        }
        $desired = Policy::anyEnabled(Policy::settings($model)) ? array_column(self::assignedRoutes($model), null, 'slot') : [];
        $previous = self::statusRecord();
        $catalog = null;
        $catalogError = null;
        $errors = [];
        $active = [];
        $retries = [];
        for ($slot = 0; $slot < self::SLOTS; $slot++) {
            $route = $desired[$slot] ?? null;
            if ($route !== null && self::ready($route)) {
                $active[] = $route['id'];
                continue;
            }
            $key = $route === null ? '' : hash('sha256', $route['id'] . ':' . $route['node'] . ':' . $route['core']);
            $retry = $previous['retries'][$slot] ?? [];
            $retry = is_array($retry) ? $retry : [];
            $now = time();
            if ($route !== null && $background && self::waitingToRetry($retry, $key, $now)) {
                $retries[$slot] = $retry;
                $errors[$route['id']] = $previous['errors'][$route['id']] ?? 'The proxy tunnel is waiting to restart.';
                continue;
            }
            try {
                self::stop($slot);
                if ($route !== null) {
                    if ($catalog === null && $catalogError === null) {
                        try {
                            $catalog = ProxyCatalog::read()['nodes'];
                        } catch (RuntimeException $error) {
                            $catalogError = $error;
                        }
                    }
                    if ($catalogError !== null) {
                        throw $catalogError;
                    }
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
                    $retries[$slot] = self::nextRetry($retry, $key, time());
                }
            }
        }
        $state = ['active' => $active, 'errors' => $errors, 'retries' => $retries];
        if ($state !== $previous) {
            Policy::writeState(self::STATUS_FILE, json_encode($state, JSON_THROW_ON_ERROR));
        }
        return ['active' => $active, 'errors' => $errors];
    }

    public static function lastStatus(): array
    {
        $state = self::statusRecord();
        return ['active' => $state['active'], 'errors' => $state['errors']];
    }

    private static function statusRecord(): array
    {
        $path = Policy::STATE_DIR . '/' . self::STATUS_FILE;
        $raw = is_file($path) ? file_get_contents($path, false, null, 0, 32769) : false;
        $data = is_string($raw) && strlen($raw) <= 32768 ? json_decode($raw, true, 8) : null;
        return [
            'active' => is_array($data['active'] ?? null) ? $data['active'] : [],
            'errors' => is_array($data['errors'] ?? null) ? $data['errors'] : [],
            'retries' => is_array($data['retries'] ?? null) ? $data['retries'] : []
        ];
    }

    private static function waitingToRetry(array $previous, string $key, int $now): bool
    {
        $retryAt = $previous['retryAt'] ?? 0;
        return ($previous['key'] ?? null) === $key && is_int($retryAt) &&
            $retryAt > $now && $retryAt <= $now + self::RETRY_LIMIT;
    }

    private static function nextRetry(array $previous, string $key, int $now): array
    {
        $failures = ($previous['key'] ?? null) === $key && is_int($previous['failures'] ?? null)
            ? min(5, max(1, $previous['failures']) + 1) : 1;
        $delay = min(self::RETRY_LIMIT, 60 * (2 ** ($failures - 1)));
        return ['key' => $key, 'failures' => $failures, 'retryAt' => $now + $delay];
    }

    public static function testNode(string $id, ?array $route = null): array
    {
        $node = ProxyCatalog::read()['nodes'][$id] ?? null;
        if (!is_array($node)) {
            throw new DomainException('The saved proxy server is missing. Import it again before testing.');
        }
        if ($route !== null && self::ready($route)) {
            $result = self::testSocks($route['socksPort'], $node);
            if (!$result['reachable']) {
                syslog(LOG_NOTICE, 'Blank VPN proxy test (' . $node['core'] . '): ' . $result['detail']);
            }
            return $result;
        }

        // Use loopback listeners only, on a locked port set reserved for tests.
        // No tunnel interface, gateway, or client firewall rule is created.
        [$slot, $slotLock] = self::acquireTestSlot();
        $test = self::route('proxy-test', $slot, $id, $node['name'], $node['core'], $node['protocol']);
        try {
            self::stop($slot);
            self::start($test, $node, true);
            $result = self::testSocks($test['socksPort'], $node);
            if (!$result['reachable']) {
                syslog(LOG_NOTICE, 'Blank VPN proxy test (' . $node['core'] . '): ' . $result['detail']);
            }
            return $result;
        } catch (DomainException | RuntimeException $error) {
            syslog(LOG_WARNING, 'Blank VPN proxy test (' . $node['core'] . '): ' . $error->getMessage());
            throw $error;
        } finally {
            try {
                self::stop($slot);
            } finally {
                flock($slotLock, LOCK_UN);
                fclose($slotLock);
            }
        }
    }

    /** @return array{0:int,1:resource} */
    private static function acquireTestSlot(): array
    {
        foreach (self::TEST_SLOTS as $slot) {
            $path = Policy::stateDirectory() . '/proxy-test-' . $slot . '.lock';
            $lock = @fopen($path, 'c');
            if ($lock === false) {
                continue;
            }
            @chmod($path, 0600);
            if (flock($lock, LOCK_EX | LOCK_NB)) {
                return [$slot, $lock];
            }
            fclose($lock);
        }
        throw new RuntimeException('Both proxy test slots are busy. Wait for a test to finish and retry.');
    }

    private static function stopUnusedTestSlot(int $slot): void
    {
        $path = Policy::stateDirectory() . '/proxy-test-' . $slot . '.lock';
        $lock = @fopen($path, 'c');
        if ($lock === false) {
            throw new RuntimeException('Could not open a proxy test slot lock.');
        }
        @chmod($path, 0600);
        try {
            if (flock($lock, LOCK_EX | LOCK_NB)) {
                self::stop($slot);
                flock($lock, LOCK_UN);
            }
        } finally {
            fclose($lock);
        }
    }

    public static function probe(array $route): array
    {
        if (!self::ready($route)) {
            return ['reachable' => false, 'detail' => 'The proxy tunnel is not running.'];
        }
        return self::probeSocks($route['socksPort']);
    }

    private static function testSocks(int $port, array $node): array
    {
        $result = self::probeSocks($port, true);
        if (!$result['reachable'] && $node['core'] === 'mihomo' && $node['protocol'] === 'socks5' &&
            empty($node['config']['fingerprint'])) {
            $result['detail'] = self::upstreamSocksStatus($node['config']) . ' ' . $result['detail'];
        }
        return $result;
    }

    private static function upstreamSocksStatus(array $config): string
    {
        $server = $config['server'];
        $address = str_contains($server, ':') ? '[' . $server . ']' : $server;
        $context = stream_context_create(['ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $config['name-cert-verify'] ?? $server
        ]]);
        $socket = @stream_socket_client('tcp://' . $address . ':' . $config['port'],
            $error, $message, 3, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) {
            return 'OPNsense could not open a TCP connection to the SOCKS5 server.';
        }
        try {
            stream_set_timeout($socket, 2);
            if (!empty($config['tls']) && @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT) !== true) {
                return 'The SOCKS5 server’s TLS connection or certificate check failed.';
            }
            return self::socksGreeting($socket, (string)($config['username'] ?? ''), (string)($config['password'] ?? ''));
        } finally {
            fclose($socket);
        }
    }

    private static function socksGreeting($socket, string $user, string $password): string
    {
        $authenticated = $user !== '';
        $greeting = $authenticated ? "\x05\x01\x02" : "\x05\x01\x00";
        $reply = @fwrite($socket, $greeting) === strlen($greeting) ? @stream_get_contents($socket, 2) : false;
        if ($reply === "\x05\x02" && $authenticated) {
            if (strlen($user) > 255 || strlen($password) > 255) {
                return 'The SOCKS5 username or password exceeds the protocol limit.';
            }
            $request = "\x01" . chr(strlen($user)) . $user . chr(strlen($password)) . $password;
            $reply = @fwrite($socket, $request) === strlen($request) ? @stream_get_contents($socket, 2) : false;
            if ($reply === "\x01\x00") {
                return 'The SOCKS5 server accepted the username and password.';
            }
            if (is_string($reply) && strlen($reply) === 2 && $reply[0] === "\x01") {
                return 'The SOCKS5 server rejected the username or password.';
            }
            return 'The SOCKS5 server did not finish authentication.';
        }
        return match ($reply) {
            "\x05\x00" => 'The SOCKS5 server accepted a connection without authentication.',
            "\x05\xff" => 'The SOCKS5 server refused the configured authentication method.',
            default => 'TCP connected, but the server did not return a valid SOCKS5 greeting.'
        };
    }

    private static function probeSocks(int $port, bool $manual = false): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The OPNsense PHP cURL extension is unavailable.');
        }
        // Race independent HTTPS destinations through the same SOCKS listener so a
        // slow provider does not delay a healthy proxy. The test slot remains singular.
        $detail = 'The proxy did not complete the HTTPS test.';
        $multi = curl_multi_init();
        if ($multi === false) {
            throw new RuntimeException('OPNsense could not initialize the parallel proxy test.');
        }
        $handles = [];
        $expectedStatuses = [];
        try {
            foreach (self::PROBE_TARGETS as $url => [$expectedStatus, $backgroundTimeout]) {
                $timeout = $manual ? 3500 : $backgroundTimeout;
                $curl = curl_init($url);
                if ($curl === false) {
                    throw new RuntimeException('OPNsense could not configure the proxy connection test.');
                }
                if (!curl_setopt_array($curl, [
                    CURLOPT_PROXY => 'socks5h://127.0.0.1:' . $port,
                    CURLOPT_NOPROXY => '', CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
                    CURLOPT_CONNECTTIMEOUT_MS => $manual ? 2500 : $timeout, CURLOPT_TIMEOUT_MS => $timeout,
                    CURLOPT_WRITEFUNCTION => static fn ($handle, string $body) => strlen($body)
                ])) {
                    curl_close($curl);
                    throw new RuntimeException('OPNsense could not configure the proxy connection test.');
                }
                $key = spl_object_id($curl);
                $handles[$key] = $curl;
                $expectedStatuses[$key] = $expectedStatus;
                if (curl_multi_add_handle($multi, $curl) !== CURLM_OK) {
                    throw new RuntimeException('OPNsense could not schedule a proxy connection test.');
                }
            }

            $running = 0;
            do {
                do {
                    $multiStatus = curl_multi_exec($multi, $running);
                } while (defined('CURLM_CALL_MULTI_PERFORM') && $multiStatus === CURLM_CALL_MULTI_PERFORM);
                if ($multiStatus !== CURLM_OK) {
                    throw new RuntimeException('OPNsense could not run the parallel proxy test.');
                }
                while (($done = curl_multi_info_read($multi)) !== false) {
                    $curl = $done['handle'];
                    $key = spl_object_id($curl);
                    $expectedStatus = $expectedStatuses[$key] ?? 0;
                    $transport = $done['result'] === CURLE_OK;
                    $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
                    if ($transport && $status === $expectedStatus) {
                        $milliseconds = round(curl_getinfo($curl, CURLINFO_TOTAL_TIME) * 1000, 1);
                        curl_multi_remove_handle($multi, $curl);
                        curl_close($curl);
                        unset($handles[$key], $expectedStatuses[$key]);
                        return ['reachable' => true, 'detail' => null, 'milliseconds' => $milliseconds];
                    }
                    $error = (int)$done['result'];
                    $detail = self::probeFailure($error, $status,
                        (float)curl_getinfo($curl, CURLINFO_CONNECT_TIME),
                        (float)curl_getinfo($curl, CURLINFO_APPCONNECT_TIME),
                        $error === CURLE_PROXY ? (int)curl_getinfo($curl, CURLINFO_PROXY_ERROR) : 0);
                    curl_multi_remove_handle($multi, $curl);
                    curl_close($curl);
                    unset($handles[$key], $expectedStatuses[$key]);
                }
                if ($running > 0 && curl_multi_select($multi, 0.1) === -1) {
                    usleep(10000);
                }
            } while ($running > 0);
        } finally {
            foreach ($handles as $curl) {
                curl_multi_remove_handle($multi, $curl);
                curl_close($curl);
            }
            curl_multi_close($multi);
        }
        return ['reachable' => false, 'detail' => $detail, 'milliseconds' => null];
    }

    private static function probeFailure(
        int $error,
        int $status,
        float $connected = 0,
        float $tls = 0,
        int $proxyError = 0
    ): string
    {
        return match ($error) {
            CURLE_OPERATION_TIMEDOUT => $tls > 0 ? 'TLS connected through the proxy. The HTTPS response timed out.'
                : ($connected > 0 ? 'The local SOCKS listener connected. The upstream connection or TLS handshake timed out.'
                    : 'The connection to the local SOCKS listener timed out.'),
            CURLE_SSL_CACERT => 'The HTTPS test certificate could not be verified.',
            CURLE_COULDNT_CONNECT => 'The local SOCKS listener could not be reached.',
            CURLE_PROXY => 'The local SOCKS listener rejected the upstream connection'
                . ($proxyError > 0 ? ' (SOCKS code ' . $proxyError . ')' : '') . '.',
            default => $status > 0 ? 'The HTTPS test returned HTTP ' . $status . '.'
                : 'The HTTPS connection ended before a response (cURL ' . $error . ').'
        };
    }

    public static function prepareTunnelDriver(): void
    {
        if (!file_exists('/dev/tun')) {
            Resolver::command(['/sbin/kldload', '-n', 'if_tuntap'], false);
        }
        if (!file_exists('/dev/tun')) {
            throw new DomainException('The FreeBSD TUN device is unavailable. Check if_tuntap and net.link.tun.devfs_cloning.');
        }
    }

    private static function start(array $route, array $node, bool $testOnly = false): void
    {
        self::preflight($node['core']);
        $slot = $route['slot'];
        $interface = $route['interface'];
        if (!$testOnly) {
            self::prepareTunnelDriver();
            if (self::ifconfig($interface) !== '') {
                throw new DomainException('A non-Blank VPN & Proxy interface is using this proxy slot.');
            }
            foreach (Policy::localNetworks(['localNetworks' => []]) as $network) {
                if (Policy::contains($network, $route['peer'])) {
                    throw new DomainException('The proxy tunnel address overlaps a local network.');
                }
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
            'id' => $route['id'], 'node' => $route['node'], 'core' => $node['core'], 'binaries' => $binaries,
            'configVersion' => self::CONFIG_VERSION
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
            if ($testOnly) {
                return;
            }
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
            if (!$testOnly) {
                self::stop($slot);
            }
            throw $error;
        }
    }

    private static function waitForSocket(int $port, int $slot, string $name, string $protocol = 'tcp4'): void
    {
        for ($attempt = 0; $attempt < 25; $attempt++) {
            $pid = self::pid($slot, $name);
            if ($pid !== null && self::boundListeners([$port => [$pid, $protocol]])) {
                return;
            }
            usleep(100000);
        }
        throw new RuntimeException('A proxy core rejected the configuration or could not bind its local port.');
    }

    private static function boundListeners(array $listeners): bool
    {
        $ports = implode(',', array_keys($listeners));
        $rows = Resolver::command(['/usr/bin/sockstat', '-4', '-l', '-p', $ports], false);
        return self::hasListeners($rows, $listeners);
    }

    private static function hasListeners(string $rows, array $listeners): bool
    {
        $expected = [];
        $found = [];
        foreach ($listeners as $port => [$pid, $protocol]) {
            $expected[$protocol . ' 127.0.0.1:' . $port] = (string)$pid;
        }
        foreach (preg_split('/\R/', $rows) as $row) {
            $fields = preg_split('/\s+/', trim($row));
            $listener = ($fields[4] ?? '') . ' ' . ($fields[5] ?? '');
            if (isset($expected[$listener])) {
                if ($expected[$listener] !== $fields[2]) {
                    return false;
                }
                $found[$listener] = true;
            }
        }
        return count($found) === count($expected);
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

    private static function pid(int $slot, string $name, ?array $marker = null): ?int
    {
        $paths = self::path($slot);
        $file = $paths . '/' . $name . '.pid';
        $value = is_file($file) ? trim((string)file_get_contents($file, false, null, 0, 32)) : '';
        if (!ctype_digit($value) || (int)$value < 2) {
            return null;
        }
        $args = trim(Resolver::command(['/bin/ps', '-ww', '-p', $value, '-o', 'command='], false));
        $marker ??= self::marker($slot);
        $tool = match ($name) {
            'bridge' => 'tun2socks',
            'mihomo' => 'mihomo',
            'adapter' => $marker['core'] ?? '',
            default => ''
        };
        $recorded = $marker['binaries'][$name] ?? null;
        if (is_string($recorded) && isset(self::BIN[$tool])) {
            $known = $recorded === self::BIN[$tool] || $recorded === self::SYSTEM_BIN[$tool] ||
                ProxyCores::isManagedPath($tool, $recorded);
            $matches = $known && str_starts_with($args, $recorded . ' ');
        } else {
            $matches = isset(self::BIN[$tool]) && (str_starts_with($args, self::BIN[$tool] . ' ') ||
                str_starts_with($args, self::SYSTEM_BIN[$tool] . ' '));
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
        if (is_link($paths) || (fileperms($paths) & 0077) !== 0) {
            throw new RuntimeException('The proxy runtime directory is not private.');
        }
        $owner = self::marker($slot);
        foreach (['bridge', 'mihomo', 'adapter'] as $name) {
            $pid = self::pid($slot, $name, $owner);
            if ($pid === null) {
                continue;
            }
            Resolver::command(['/bin/kill', '-TERM', (string)$pid], false);
            if (self::waitForExit($slot, $name, $owner, $pid)) {
                continue;
            }
            // Validate the child again immediately before escalating. Its PID may have been reused.
            if (self::pid($slot, $name, $owner) === $pid) {
                Resolver::command(['/bin/kill', '-KILL', (string)$pid], false);
            }
            if (!self::waitForExit($slot, $name, $owner, $pid)) {
                throw new RuntimeException('A proxy core is still stopping. Retry after it exits.');
            }
        }
        if ($slot < self::SLOTS && is_string($owner['id'] ?? null)) {
            $device = 'tun' . (200 + $slot);
            if (self::ownedInterface(['id' => $owner['id']], self::ifconfig($device))) {
                Resolver::command(['/sbin/ifconfig', $device, 'destroy']);
            }
        }
        foreach (['owner.json', 'adapter.json', 'mihomo.json', 'bridge.pid', 'mihomo.pid', 'adapter.pid', 'cache.db'] as $file) {
            if (is_file($paths . '/' . $file)) {
                unlink($paths . '/' . $file);
            }
        }
    }

    private static function waitForExit(int $slot, string $name, array $owner, int $pid): bool
    {
        for ($attempt = 0; $attempt < 10; $attempt++) {
            if (self::pid($slot, $name, $owner) !== $pid) {
                return true;
            }
            usleep(100000);
        }
        return self::pid($slot, $name, $owner) !== $pid;
    }
}
