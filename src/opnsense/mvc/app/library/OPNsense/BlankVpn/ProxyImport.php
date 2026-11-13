<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;

final class ProxyImport
{
    public const MAX_BYTES = 2097152;
    public const MAX_NODES = 256;
    private const MIHOMO = [
        'http', 'socks5', 'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic',
        'anytls', 'snell', 'ssh', 'wireguard', 'mieru', 'masque', 'sudoku', 'shadowquic', 'gost-relay', 'trusttunnel'
    ];
    private const XRAY = ['http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria'];
    private const SING = [
        'http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2',
        'tuic', 'anytls', 'ssh', 'naive', 'shadowtls'
    ];

    public static function parse(string $body): array
    {
        if (strlen($body) > self::MAX_BYTES || str_contains($body, "\0")) {
            throw new DomainException('The subscription exceeds the proxy import limit or contains binary data.');
        }
        $body = trim(preg_replace('/^\xEF\xBB\xBF/', '', $body));
        if ($body === '') {
            throw new DomainException('The proxy list is empty.');
        }
        if (preg_match('/^[A-Za-z0-9+\/=_\s-]+$/D', $body)) {
            $decoded = self::decode(preg_replace('/\s+/', '', $body), false);
            if ($decoded !== null && preg_match('/[a-z][a-z0-9+.-]*:\/\//i', $decoded)) {
                $body = trim($decoded);
            }
        }
        $document = json_decode($body, true, 32);
        if ($document === null && preg_match('/^\s*(?:---\s*\R\s*)?proxies\s*:/mi', $body)) {
            $document = self::yaml($body);
        }
        if (is_array($document)) {
            return self::structured($document);
        }

        $nodes = [];
        $skipped = 0;
        $seen = 0;
        foreach (preg_split('/\R/', $body) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (++$seen > self::MAX_NODES) {
                throw new DomainException('This import has more than 256 server entries.');
            }
            try {
                $node = self::link($line);
                $nodes[$node['id']] = $node;
            } catch (DomainException | \TypeError | \ValueError | \JsonException) {
                $skipped++;
            }
        }
        return self::result($nodes, $skipped);
    }

    public static function manual(
        string $name,
        string $protocol,
        string $host,
        string $port,
        string $username,
        string $secret,
        string $cipher,
        string $parameters
    ): array {
        $host = self::host($host);
        $port = self::port($port);
        $endpoint = (str_contains($host, ':') ? '[' . $host . ']' : $host) . ':' . $port;
        $query = self::query(ltrim($parameters, '?'));
        foreach ([$username, $secret, $cipher] as $credential) {
            if (preg_match('/[\x00-\x1f\x7f]/', $credential)) {
                throw new DomainException('Proxy credentials must use a single line.');
            }
        }
        if ($protocol === 'ss') {
            if ($cipher === '' || $secret === '') {
                throw new DomainException('Enter a Shadowsocks cipher and password.');
            }
            $authentication = rawurlencode($cipher . ':' . $secret);
        } elseif (in_array($protocol, ['vless', 'vmess', 'tuic'], true)) {
            if (!preg_match('/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iD', $username) ||
                ($protocol === 'tuic' && $secret === '')) {
                throw new DomainException('Enter a valid UUID and, for TUIC, its password.');
            }
            $authentication = rawurlencode($username) . ($protocol === 'tuic' ? ':' . rawurlencode($secret) : '');
        } elseif (in_array($protocol, ['trojan', 'hysteria', 'hysteria2', 'anytls', 'snell'], true)) {
            if ($secret === '') {
                throw new DomainException('Enter the proxy password, authentication string or key.');
            }
            $authentication = rawurlencode($secret);
        } elseif (in_array($protocol, ['http', 'https', 'socks5'], true)) {
            if ($secret !== '' && $username === '') {
                throw new DomainException('Enter the username for this proxy password.');
            }
            $authentication = $username === '' ? '' : rawurlencode($username) . ':' . rawurlencode($secret);
        } else {
            throw new DomainException('Choose a supported proxy protocol.');
        }
        $link = $protocol . '://' . ($authentication === '' ? '' : $authentication . '@') . $endpoint;
        if ($query !== []) {
            $link .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
        return self::link($link . '#' . rawurlencode($name));
    }

    private static function structured(array $document): array
    {
        if (isset($document['proxies']) && is_array($document['proxies'])) {
            $engine = 'mihomo';
            $items = $document['proxies'];
        } elseif (isset($document['outbounds']) && is_array($document['outbounds'])) {
            $items = $document['outbounds'];
            $engine = null;
        } else {
            $items = array_is_list($document) ? $document : [$document];
            $engine = null;
        }
        if (!array_is_list($items) || count($items) > self::MAX_NODES) {
            throw new DomainException('The document must provide a list of up to 256 individual proxy entries.');
        }
        $nodes = [];
        $skipped = 0;
        foreach ($items as $entry) {
            try {
                if (!is_array($entry)) {
                    throw new DomainException('Invalid server entry.');
                }
                $core = $engine ?? (isset($entry['protocol']) ? 'xray' : (isset($entry['name']) ? 'mihomo' : 'sing-box'));
                $label = $entry['name'] ?? $entry['tag'] ?? '';
                unset($entry['tag'], $entry['name']);
                $node = self::node($core, $entry, is_string($label) ? $label : '');
                $nodes[$node['id']] = $node;
            } catch (DomainException | \TypeError | \ValueError | \JsonException) {
                $skipped++;
            }
        }
        return self::result($nodes, $skipped);
    }

    private static function result(array $nodes, int $skipped): array
    {
        if ($nodes === []) {
            throw new DomainException('No supported proxy nodes were found. For a single link, check its protocol, options and TLS settings.');
        }
        return ['nodes' => $nodes, 'skipped' => $skipped];
    }

    private static function link(string $line): array
    {
        if (strlen($line) > 32768 || !preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iD', $line, $m)) {
            throw new DomainException('Invalid proxy link.');
        }
        $scheme = strtolower($m[1]);
        if ($scheme === 'vmess' && !str_contains($m[2], '@')) {
            return self::vmess($m[2]);
        }
        if ($scheme === 'ssr') {
            return self::ssr($m[2]);
        }
        if ($scheme === 'ss') {
            return self::shadowsocks($m[2]);
        }

        $url = parse_url($line);
        if ($url === false || empty($url['host'])) {
            throw new DomainException('Invalid proxy endpoint.');
        }
        $label = rawurldecode($url['fragment'] ?? '');
        $query = self::query($url['query'] ?? '');
        $server = self::host($url['host']);
        $port = self::port($url['port'] ?? match ($scheme) {
            'http' => 80, 'https' => 443, 'socks', 'socks5', 'socks5h' => 1080, default => 443
        });
        $user = rawurldecode($url['user'] ?? '');
        $pass = rawurldecode($url['pass'] ?? '');
        $base = ['server' => $server, 'port' => $port];
        if (in_array($scheme, ['socks', 'socks5', 'socks5h', 'http', 'https'], true)) {
            $socks = str_starts_with($scheme, 'socks');
            if (array_diff(array_keys($query), $socks ? ['tls', 'sni', 'udp'] : []) !== [] ||
                !in_array($url['path'] ?? '', ['', '/'], true)) {
                throw new DomainException('Use a structured entry for additional HTTP or SOCKS options.');
            }
            if (($pass !== '' && $user === '') || preg_match('/[\x00-\x1f\x7f]/', $user . $pass) ||
                ($socks && (strlen($user) > 255 || strlen($pass) > 255))) {
                throw new DomainException('Invalid proxy username or password.');
            }
            $auth = $user === '' ? [] : ['username' => $user, 'password' => $pass];
            $tls = $scheme === 'https';
            $options = [];
            foreach (['tls', 'udp'] as $flag) {
                if (isset($query[$flag])) {
                    $options[$flag] = match (strtolower($query[$flag])) {
                        '1', 'true' => true,
                        '0', 'false' => false,
                        default => throw new DomainException('Use true or false for the SOCKS5 ' . $flag . ' option.')
                    };
                }
            }
            $tls = $options['tls'] ?? $tls;
            if (isset($query['sni'])) {
                if (!$tls) {
                    throw new DomainException('Enable TLS to set a SOCKS5 certificate hostname.');
                }
                $options['name-cert-verify'] = self::host($query['sni']);
            }
            return self::node('mihomo', ['type' => $socks ? 'socks5' : 'http', 'tls' => $tls] + $base + $auth + $options, $label);
        }
        $query['password'] = $pass;
        if ($scheme === 'vless' &&
            (in_array($query['type'] ?? '', ['xhttp', 'splithttp', 'kcp'], true) ||
                !in_array($query['encryption'] ?? 'none', ['', 'none'], true))) {
            return self::xrayVless($base, $user, $query, $label);
        }
        $type = match ($scheme) {
            'hy2', 'hysteria2' => 'hysteria2',
            'hysteria', 'tuic', 'anytls', 'vless', 'trojan', 'vmess', 'snell' => $scheme,
            default => throw new DomainException('Unsupported share-link scheme.')
        };
        $options = ['type' => $type] + $base;
        if (in_array($type, ['vless', 'vmess', 'tuic'], true)) {
            $options['uuid'] = $user;
        }
        if (in_array($type, ['trojan', 'hysteria2', 'anytls', 'tuic'], true)) {
            $options['password'] = $type === 'tuic' ? $pass : ($pass === '' ? $user : $user . ':' . $pass);
        }
        if ($type === 'hysteria') {
            $options['auth-str'] = $query['auth'] ?? $user;
        }
        if ($type === 'snell') {
            $options['psk'] = $user;
            $options['version'] = (int)($query['version'] ?? 3);
        }
        if ($type === 'vmess') {
            $options['alterId'] = (int)($query['aid'] ?? 0);
            $options['cipher'] = $query['scy'] ?? 'auto';
        }
        $options += self::tlsAndTransport($query, in_array($type, ['trojan', 'tuic', 'anytls', 'hysteria', 'hysteria2'], true));
        foreach ([
            'flow' => 'flow', 'upmbps' => 'up', 'downmbps' => 'down', 'auth' => 'auth-str',
            'obfs' => 'obfs', 'obfs-password' => 'obfs-password', 'congestion_control' => 'congestion-controller',
            'udp_relay_mode' => 'udp-relay-mode', 'packetEncoding' => 'packet-encoding'
        ] as $key => $field) {
            if (isset($query[$key]) && $query[$key] !== '') {
                $options[$field] = $query[$key];
            }
        }
        if ($type === 'hysteria') {
            $options['protocol'] = $query['protocol'] ?? 'udp';
            if (isset($query['obfsParam'])) {
                $options['obfs'] = $query['obfsParam'];
            }
        }
        $options['udp'] = true;
        return self::node('mihomo', $options, $label);
    }

    private static function tlsAndTransport(array $query, bool $requiredTls): array
    {
        self::tlsPolicy($query);
        $security = $query['security'] ?? ($requiredTls ? 'tls' : 'none');
        if (!in_array($security, ['', 'none', 'tls', 'reality'], true)) {
            throw new DomainException('Use a structured entry for this TLS mode.');
        }
        $out = [];
        if ($requiredTls || in_array($security, ['tls', 'reality'], true)) {
            $out['tls'] = true;
        }
        if (($sni = $query['sni'] ?? $query['peer'] ?? '') !== '') {
            $out['servername'] = self::host($sni);
            $out['sni'] = $out['servername'];
        }
        if (!empty($query['fp'])) {
            $out['client-fingerprint'] = $query['fp'];
        }
        if (!empty($query['alpn'])) {
            $out['alpn'] = explode(',', $query['alpn']);
        }
        if ($security === 'reality') {
            if (empty($query['pbk'])) {
                throw new DomainException('REALITY requires a server public key.');
            }
            $out['reality-opts'] = ['public-key' => $query['pbk'], 'short-id' => $query['sid'] ?? ''];
        }
        $network = $query['type'] ?? $query['net'] ?? 'tcp';
        $out += match ($network) {
            '', 'tcp', 'raw' => ($query['headerType'] ?? 'none') === 'none' ? [] :
                throw new DomainException('Use structured configuration for a custom TCP header.'),
            'ws', 'websocket' => ['network' => 'ws', 'ws-opts' => [
                'path' => $query['path'] ?? '/', 'headers' => empty($query['host']) ? null : ['Host' => $query['host']]
            ]],
            'grpc' => ['network' => 'grpc', 'grpc-opts' => ['grpc-service-name' => $query['serviceName'] ?? $query['path'] ?? '']],
            'httpupgrade' => ['network' => 'ws', 'ws-opts' => [
                'path' => $query['path'] ?? '/', 'v2ray-http-upgrade' => true,
                'headers' => empty($query['host']) ? null : ['Host' => $query['host']]
            ]],
            'h2', 'http' => ['network' => 'h2', 'h2-opts' => [
                'host' => empty($query['host']) ? [] : explode(',', $query['host']), 'path' => $query['path'] ?? '/'
            ]],
            default => throw new DomainException('Use a structured entry for this transport.')
        };
        return $out;
    }

    private static function xrayVless(array $base, string $uuid, array $q, string $label): array
    {
        self::tlsPolicy($q);
        $net = $q['type'] ?? 'raw';
        $net = match ($net) {'tcp' => 'raw', 'splithttp' => 'xhttp', default => $net};
        $stream = ['network' => $net, 'security' => $q['security'] ?? 'none'];
        $stream += match ($net) {
            'raw' => [],
            'xhttp' => ['xhttpSettings' => ['host' => $q['host'] ?? '', 'path' => $q['path'] ?? '/', 'mode' => $q['mode'] ?? 'auto']],
            'ws' => ['wsSettings' => ['host' => $q['host'] ?? '', 'path' => $q['path'] ?? '/']],
            'grpc' => ['grpcSettings' => ['serviceName' => $q['serviceName'] ?? '']],
            'httpupgrade' => ['httpupgradeSettings' => ['host' => $q['host'] ?? '', 'path' => $q['path'] ?? '/']],
            'kcp' => ['kcpSettings' => ['header' => ['type' => $q['headerType'] ?? 'none'], 'seed' => $q['seed'] ?? '']],
            default => throw new DomainException('Use structured Xray JSON for this transport.')
        };
        if (!empty($q['extra'])) {
            $extra = json_decode($q['extra'], true, 16);
            if ($net !== 'xhttp' || !is_array($extra)) {
                throw new DomainException('Invalid XHTTP extra parameters.');
            }
            $stream['xhttpSettings']['extra'] = $extra;
        }
        if ($stream['security'] === 'reality') {
            $stream['realitySettings'] = [
                'serverName' => $q['sni'] ?? $base['server'], 'fingerprint' => $q['fp'] ?? 'chrome',
                'password' => $q['pbk'] ?? '', 'shortId' => $q['sid'] ?? '', 'spiderX' => $q['spx'] ?? ''
            ];
        } elseif ($stream['security'] === 'tls') {
            $stream['tlsSettings'] = ['serverName' => $q['sni'] ?? $base['server'], 'fingerprint' => $q['fp'] ?? 'chrome'];
        }
        return self::node('xray', [
            'protocol' => 'vless', 'settings' => ['vnext' => [[
                'address' => $base['server'], 'port' => $base['port'],
                'users' => [['id' => $uuid, 'encryption' => $q['encryption'] ?? 'none', 'flow' => $q['flow'] ?? '']]
            ]]], 'streamSettings' => $stream
        ], $label);
    }

    private static function vmess(string $raw): array
    {
        $config = json_decode(self::decode($raw), true, 16);
        if (!is_array($config)) {
            throw new DomainException('Invalid VMess configuration.');
        }
        $q = [
            'type' => $config['net'] ?? 'tcp', 'headerType' => $config['type'] ?? 'none',
            'security' => $config['tls'] ?? 'none', 'path' => $config['path'] ?? '/',
            'host' => $config['host'] ?? '', 'sni' => $config['sni'] ?? '', 'fp' => $config['fp'] ?? '',
            'alpn' => $config['alpn'] ?? ''
        ];
        return self::node('mihomo', [
            'type' => 'vmess', 'server' => $config['add'] ?? '', 'port' => $config['port'] ?? '',
            'uuid' => $config['id'] ?? '', 'alterId' => (int)($config['aid'] ?? 0),
            'cipher' => $config['scy'] ?? 'auto', 'udp' => true
        ] + self::tlsAndTransport($q, false), (string)($config['ps'] ?? ''));
    }

    private static function shadowsocks(string $raw): array
    {
        [$raw, $label] = array_pad(explode('#', $raw, 2), 2, '');
        [$raw, $query] = array_pad(explode('?', $raw, 2), 2, '');
        if (!str_contains($raw, '@')) {
            $raw = self::decode(rtrim($raw, '/'));
        }
        $at = strrpos($raw, '@');
        if ($at === false) {
            throw new DomainException('Invalid Shadowsocks endpoint.');
        }
        $secret = rawurldecode(substr($raw, 0, $at));
        if (!str_contains($secret, ':')) {
            $secret = self::decode($secret);
        }
        [$cipher, $password] = array_pad(explode(':', $secret, 2), 2, '');
        $endpoint = parse_url('ss://' . rtrim(substr($raw, $at + 1), '/'));
        $config = ['type' => 'ss', 'server' => $endpoint['host'] ?? '', 'port' => $endpoint['port'] ?? 0,
            'cipher' => $cipher, 'password' => $password, 'udp' => true];
        $options = self::query($query);
        if (!empty($options['plugin'])) {
            [$plugin, $parameters] = array_pad(explode(';', $options['plugin'], 2), 2, '');
            $settings = [];
            foreach (explode(';', $parameters) as $item) {
                if ($item === '') {
                    continue;
                }
                [$key, $value] = array_pad(explode('=', $item, 2), 2, true);
                $settings[$key] = $value;
            }
            $config['plugin'] = match ($plugin) {
                'obfs-local', 'simple-obfs' => 'obfs', 'v2ray-plugin' => 'v2ray-plugin',
                'shadow-tls', 'shadow-tls-client' => 'shadow-tls',
                default => throw new DomainException('Unsupported SIP003 plugin.')
            };
            $config['plugin-opts'] = $config['plugin'] === 'obfs'
                ? ['mode' => $settings['obfs'] ?? 'http', 'host' => $settings['obfs-host'] ?? $config['server']]
                : $settings;
        }
        return self::node('mihomo', $config, rawurldecode($label));
    }

    private static function ssr(string $raw): array
    {
        [$body, $query] = array_pad(explode('/?', self::decode($raw), 2), 2, '');
        $parts = explode(':', $body);
        if (count($parts) < 6) {
            throw new DomainException('Invalid ShadowsocksR configuration.');
        }
        [$port, $protocol, $cipher, $obfs, $password] = array_splice($parts, -5);
        $q = self::query($query);
        return self::node('mihomo', [
            'type' => 'ssr', 'server' => implode(':', $parts), 'port' => $port, 'protocol' => $protocol,
            'cipher' => $cipher, 'obfs' => $obfs, 'password' => self::decode($password), 'udp' => true,
            'obfs-param' => isset($q['obfsparam']) ? self::decode($q['obfsparam']) : '',
            'protocol-param' => isset($q['protoparam']) ? self::decode($q['protoparam']) : ''
        ], isset($q['remarks']) ? self::decode($q['remarks']) : '');
    }

    private static function node(string $core, array $config, string $label): array
    {
        self::reviewFields($config);
        $protocol = $config[$core === 'xray' ? 'protocol' : 'type'] ?? '';
        $allowed = match ($core) {'mihomo' => self::MIHOMO, 'xray' => self::XRAY, 'sing-box' => self::SING};
        if (!is_string($protocol) || !in_array($protocol, $allowed, true)) {
            throw new DomainException('Unsupported core or outbound protocol.');
        }
        if ($core === 'xray') {
            $sets = $config['settings']['vnext'] ?? $config['settings']['servers'] ?? [];
            if (!is_array($sets) || count($sets) !== 1 || !is_array($sets[0] ?? null)) {
                throw new DomainException('An Xray proxy route requires exactly one upstream server.');
            }
            $server = self::host($sets[0]['address'] ?? '');
            $port = self::port($sets[0]['port'] ?? 0);
            $config = array_intersect_key($config, array_flip(['protocol', 'settings', 'streamSettings', 'mux']));
        } else {
            $server = self::host($config['server'] ?? '');
            $portField = $core === 'mihomo' ? 'port' : 'server_port';
            $port = self::port($config[$portField] ?? 0);
            $config['server'] = $server;
            $config[$portField] = $port;
            if ($core === 'mihomo' && isset($config['plugin']) &&
                !in_array($config['plugin'], ['obfs', 'v2ray-plugin', 'shadow-tls', 'restls'], true)) {
                throw new DomainException('The SIP003 plugin is unavailable in this core adapter.');
            }
        }
        if (($config['password'] ?? null) === '' && in_array($protocol, ['ss', 'ssr', 'trojan', 'tuic', 'anytls', 'hysteria2'], true)) {
            throw new DomainException('A proxy credential is missing.');
        }
        $label = preg_replace('/[\x00-\x1f\x7f]/', '', $label);
        if (!preg_match('//u', $label)) {
            $label = '';
        }
        preg_match('/^.{0,80}/us', $label, $shortLabel);
        $canonical = self::canonical($config);
        $id = hash('sha256', $core . "\0" . json_encode($canonical, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
        $cipher = $config['cipher'] ?? $config['method'] ?? '';
        return [
            'id' => $id, 'name' => trim($shortLabel[0] ?? '') ?: $server . ':' . $port,
            'core' => $core, 'protocol' => $protocol, 'host' => $server, 'port' => $port, 'config' => $config,
            'legacy' => $protocol === 'ssr' || ($protocol === 'vmess' && (int)($config['alterId'] ?? 0) !== 0) ||
                (is_string($cipher) && preg_match('/(?:^none$|rc4|cfb|ctr|chacha20$|salsa20)/i', $cipher) === 1) ||
                (in_array($protocol, ['http', 'socks', 'socks5'], true) && empty($config['tls']))
        ];
    }

    private static function reviewFields(array $data, int $depth = 0): void
    {
        if ($depth > 16 || count($data) > 100) {
            throw new DomainException('The proxy configuration is too deeply nested or too large.');
        }
        foreach ($data as $key => $value) {
            if (is_string($key)) {
                $normalized = strtolower(preg_replace('/[-_]/', '', $key));
                if (in_array($normalized, [
                    'dialerproxy', 'detour', 'proxysettings', 'sockopt', 'sendthrough', 'routingmark', 'bindinterface',
                    'interfacename', 'inet4bindaddress', 'inet6bindaddress', 'downloadurl',
                    'certificatepath', 'keypath', 'privatekeypath', 'certificatefile', 'keyfile', 'sshkeyfile',
                    'privatekeyfile', 'cafile', 'hostkeypath', 'clientcertificatepath', 'clientkeypath',
                    'externalcontroller', 'script', 'usersfile', 'logfile', 'configfile', 'keylog'
                ], true)) {
                    throw new DomainException('The proxy entry requests router-local files, chaining or privileged routing options.');
                }
                if (preg_match('/(?:file|filepaths|filepath)$/D', $normalized) ||
                    ($normalized === 'privatekey' && is_string($value) &&
                        !preg_match('/^[a-z0-9+\/_=-]{40,128}$/iD', trim($value)) &&
                        !preg_match('/^-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----\R/', trim($value)))) {
                    throw new DomainException('The proxy entry references a router-local file.');
                }
                if (in_array($normalized, ['allowinsecure', 'skipcertverify', 'insecure'], true) &&
                    !in_array($value, [false, 0, '0', 'false', ''], true)) {
                    throw new DomainException('TLS certificate verification must remain enabled.');
                }
            }
            if (is_array($value)) {
                self::reviewFields($value, $depth + 1);
            } elseif (is_string($value) && (strlen($value) > 16384 || str_contains($value, "\0"))) {
                throw new DomainException('A proxy setting is too large or invalid.');
            }
        }
    }

    private static function canonical(array $data): array
    {
        if (!array_is_list($data)) {
            ksort($data, SORT_STRING);
        }
        return array_map(static fn ($value) => is_array($value) ? self::canonical($value) : $value, $data);
    }

    public static function host(mixed $host): string
    {
        if (!is_string($host)) {
            throw new DomainException('Invalid proxy hostname.');
        }
        $host = strtolower(rtrim(trim($host, '[]'), '.'));
        if (filter_var($host, FILTER_VALIDATE_IP) ||
            (strlen($host) <= 253 && str_contains($host, '.') && !preg_match('/^[0-9.]+$/D', $host) &&
                filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME))) {
            return $host;
        }
        throw new DomainException('Invalid proxy hostname.');
    }

    public static function port(mixed $port): int
    {
        if ((!is_int($port) && (!is_string($port) || !ctype_digit($port))) || (int)$port < 1 || (int)$port > 65535) {
            throw new DomainException('Invalid proxy port.');
        }
        return (int)$port;
    }

    private static function query(string $raw): array
    {
        $result = [];
        foreach (explode('&', $raw) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $key = rawurldecode($key);
            if (array_key_exists($key, $result)) {
                throw new DomainException('Duplicate proxy link option.');
            }
            $result[$key] = rawurldecode($value);
        }
        return $result;
    }

    private static function tlsPolicy(array $q): void
    {
        foreach (['insecure', 'allowInsecure', 'skip-cert-verify'] as $key) {
            if (isset($q[$key]) && !in_array(strtolower($q[$key]), ['', '0', 'false'], true)) {
                throw new DomainException('TLS certificate verification must remain enabled.');
            }
        }
    }

    private static function decode(string $raw, bool $required = true): ?string
    {
        $raw = strtr($raw, '-_', '+/');
        $decoded = base64_decode($raw, true);
        if ($decoded === false) {
            if ($required) {
                throw new DomainException('Invalid base64 proxy data.');
            }
            return null;
        }
        return $decoded;
    }

    private static function yaml(string $body): array
    {
        $process = proc_open(
            ['/usr/local/bin/python3.13', '/usr/local/opnsense/scripts/OPNsense/BlankVpn/proxy_yaml.py'],
            [['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($process)) {
            throw new DomainException('The router could not start the Clash YAML parser.');
        }
        $written = fwrite($pipes[0], $body);
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1], self::MAX_BYTES + 1);
        fclose($pipes[1]);
        $status = proc_close($process);
        if ($status === 2) {
            throw new DomainException('The Clash YAML parser is missing. Install the full Blank VPN release package.');
        }
        $config = is_string($output) ? json_decode($output, true, 32) : null;
        if ($status !== 0 || $written !== strlen($body) || !is_array($config)) {
            throw new DomainException('Invalid or oversized Clash YAML subscription.');
        }
        return $config;
    }
}
