<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class ProxyCatalog
{
    public const MAX_URL_BYTES = 8192;
    private const FILE = 'proxy-catalog.json';
    private const REFRESH_STATE = 'proxy-refresh.json';
    private const MANAGED_NORD = 'managed-nord';
    private const MAX_FEEDS = 12;
    private const MAX_CATALOG_BYTES = 25165824;
    private const REFRESH_INTERVAL = 21600;
    private const RETRY_INTERVAL = 900;

    public static function read(): array
    {
        $path = Policy::STATE_DIR . '/' . self::FILE;
        if (!file_exists($path) && !is_link($path)) {
            return ['nodes' => [], 'feeds' => []];
        }
        $mode = @fileperms($path);
        if ($mode === false || is_link($path) || ($mode & 0077) !== 0) {
            throw new RuntimeException('The private proxy catalog has unsafe permissions.');
        }
        $bytes = file_get_contents($path, false, null, 0, self::MAX_CATALOG_BYTES + 1);
        $data = is_string($bytes) && strlen($bytes) <= self::MAX_CATALOG_BYTES ? json_decode($bytes, true, 32) : null;
        if (!is_array($data['nodes'] ?? null) || !is_array($data['feeds'] ?? null)) {
            throw new RuntimeException('The private proxy catalog could not be read.');
        }
        return $data;
    }

    private static function save(array $data): void
    {
        $bytes = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (strlen($bytes) > self::MAX_CATALOG_BYTES) {
            throw new DomainException('Remove unused proxy subscriptions or nodes to make room in the catalog.');
        }
        Policy::writeState(self::FILE, $bytes);
        self::scheduleRefresh($data['feeds']);
    }

    public static function publicView(): array
    {
        $data = self::read();
        return [
            'nodes' => array_values(array_map(self::publicNode(...), $data['nodes'])),
            'feeds' => array_values(array_map(static fn (array $feed): array =>
                array_intersect_key($feed, array_flip(['id', 'name', 'auto', 'updated', 'error', 'skipped', 'count', 'usage'])),
                $data['feeds']))
        ];
    }

    private static function publicNode(array $node): array
    {
        $public = array_intersect_key($node, array_flip([
            'id', 'name', 'core', 'protocol', 'host', 'port', 'legacy', 'sources', 'disabled',
        ]));
        $public['serverName'] = self::originalServerName($node);
        if (self::isManagedNord($node)) {
            $public += array_intersect_key($node, array_flip(['provider', 'providerLocation', 'providerServer']));
        }
        return $public;
    }

    public static function managedNord(?string $location = null): array
    {
        return self::managedNordNodes(self::read(), $location);
    }

    public static function dashboardNodes(array $nodeIds): array
    {
        $data = self::read();
        $names = [];
        foreach ($nodeIds as $id) {
            if (isset($data['nodes'][$id]['name'])) {
                $names[$id] = $data['nodes'][$id]['name'];
            }
        }
        return [
            'names' => $names,
            'managedNord' => self::managedNordNodes($data, null),
        ];
    }

    private static function managedNordNodes(array $data, ?string $location): array
    {
        $nodes = array_filter($data['nodes'], static fn (array $node): bool =>
            self::isManagedNord($node) && ($location === null || $node['providerLocation'] === $location));
        return array_map(self::publicNode(...), $nodes);
    }

    public static function saveManagedNord(array $node): array
    {
        $id = $node['id'] ?? '';
        $location = $node['providerLocation'] ?? null;
        if (($node['provider'] ?? '') !== 'nord' || ($node['core'] ?? '') !== 'mihomo' ||
            ($node['protocol'] ?? '') !== 'wireguard' || !VpnProviders::nordServerId($location) ||
            !is_string($id) || preg_match('/^[a-f0-9]{64}$/D', $id) !== 1) {
            throw new DomainException('The NordVPN server configuration is invalid.');
        }

        $data = self::read();
        $saved = self::managedNordNodes($data, $location);
        if ($saved !== []) {
            $savedId = array_key_first($saved);
            if (!empty($data['nodes'][$savedId]['disabled'])) {
                unset($data['nodes'][$savedId]['disabled']);
                self::save($data);
            }
            return self::publicNode($data['nodes'][$savedId]);
        }
        if (self::isManagedNord($data['nodes'][$id] ?? [])) {
            throw new DomainException('An equivalent NordVPN exit is already saved under a different server name.');
        }

        $node['providerServer'] = self::serverName((string)($node['providerServer'] ?? $location));
        self::replaceNodes($data, self::MANAGED_NORD, [$id => $node], []);
        unset($data['nodes'][$id]['disabled']);
        self::save($data);
        return self::publicNode($data['nodes'][$id]);
    }

    public static function removeManagedNord(string $id): void
    {
        $data = self::read();
        self::dropManagedNord($data, $id);
        self::save($data);
    }

    private static function dropManagedNord(array &$data, string $id): void
    {
        $node = $data['nodes'][$id] ?? [];
        if (!self::isManagedNord($node)) {
            throw new DomainException('This NordVPN server is no longer saved.');
        }
        $node['sources'] = array_values(array_diff($node['sources'], [self::MANAGED_NORD]));
        if ($node['sources'] === []) {
            unset($data['nodes'][$id]);
            return;
        }
        unset($node['provider'], $node['providerLocation'], $node['providerServer']);
        $data['nodes'][$id] = $node;
    }

    private static function isManagedNord(array $node): bool
    {
        return ($node['provider'] ?? '') === 'nord' &&
            in_array(self::MANAGED_NORD, $node['sources'] ?? [], true) &&
            VpnProviders::nordServerId($node['providerLocation'] ?? null);
    }

    public static function import(string $body, string $name = ''): array
    {
        $parsed = ProxyImport::parse($body);
        if (trim($name) !== '') {
            if (count($parsed['nodes']) !== 1 || $parsed['skipped'] !== 0) {
                throw new DomainException('A server name applies to a single proxy. Clear it to import a list.');
            }
            $id = array_key_first($parsed['nodes']);
            $parsed['nodes'][$id]['name'] = self::serverName($name);
            $parsed['nodes'][$id]['customName'] = true;
        }
        self::saveManual($parsed['nodes']);
        return ['imported' => count($parsed['nodes']), 'skipped' => $parsed['skipped']];
    }

    public static function saveManual(array $nodes): void
    {
        $data = self::read();
        self::replaceNodes($data, 'manual', $nodes, []);
        self::save($data);
    }

    public static function serverName(string $name): string
    {
        $name = trim($name);
        if (!preg_match('/^[^\p{C}<>]{1,64}$/uD', $name)) {
            throw new DomainException('Enter a server name between 1 and 64 characters.');
        }
        return $name;
    }

    public static function renameNode(string $id, string $name): void
    {
        $data = self::read();
        if (!isset($data['nodes'][$id])) {
            throw new DomainException('This proxy server is no longer saved.');
        }
        $data['nodes'][$id]['serverName'] = self::originalServerName($data['nodes'][$id]);
        $data['nodes'][$id]['name'] = self::serverName($name);
        $data['nodes'][$id]['customName'] = true;
        self::save($data);
    }

    private static function originalServerName(array $node): string
    {
        // Older custom aliases did not retain the upstream label. Do not present
        // the edited name as though it were the original server name.
        return (string)($node['serverName'] ?? $node['providerServer'] ??
            $node['config']['name'] ?? $node['config']['tag'] ??
            (empty($node['customName']) ? ($node['name'] ?? $node['host'] ?? '') : ($node['host'] ?? '')));
    }

    /** Build the entire edit before writing anything; callers hold Operations::exclusive. */
    public static function prepareRemoval(array $ids, array $pinned, bool $managedNord = false): array
    {
        $before = self::read();
        $after = $before;
        foreach ($ids as $id) {
            if (!is_string($id) || !isset($before['nodes'][$id])) {
                throw new DomainException('A selected server is no longer saved. Refresh the list and try again.');
            }
            if (in_array($id, $pinned, true)) {
                throw new DomainException('Remove the selected servers from their proxy exits before deleting them.');
            }
            if ($managedNord) {
                self::dropManagedNord($after, $id);
            } else {
                if (self::isManagedNord($before['nodes'][$id])) {
                    throw new DomainException('Remove managed VPN servers from the VPN server list.');
                }
                unset($after['nodes'][$id]);
            }
        }
        foreach ($after['feeds'] as $feedId => &$feed) {
            $feed['count'] = count(array_filter($after['nodes'], static fn (array $node): bool =>
                in_array($feedId, $node['sources'] ?? [], true)));
        }
        unset($feed);
        return compact('before', 'after');
    }

    public static function applyRemoval(array $plan): void
    {
        if (self::read() !== $plan['before']) {
            throw new DomainException('The server list changed. Refresh the list and try again.');
        }
        // writeState replaces the private catalog atomically. No fallible work
        // follows this write in the configuration transaction.
        self::save($plan['after']);
    }

    public static function addFeed(string $name, string $url, bool $auto, array $pinned): array
    {
        $name = trim($name);
        if ($name === '' || strlen($name) > 96 || preg_match('/[\x00-\x1f\x7f<>]/', $name)) {
            throw new DomainException('Enter a short name for the subscription.');
        }
        $url = trim($url);
        self::endpoint($url);
        $data = self::read();
        $id = hash('sha256', $url);
        if (isset($data['feeds'][$id])) {
            throw new DomainException('That subscription is already saved. Refresh its existing entry.');
        }
        if (count($data['feeds']) >= self::MAX_FEEDS) {
            throw new DomainException('Remove an existing subscription before adding another.');
        }
        $feed = ['id' => $id, 'name' => $name, 'url' => $url, 'auto' => $auto];
        $result = self::refresh($data, $feed, $pinned);
        self::save($data);
        return $result;
    }

    public static function setAutoRefresh(string $id, bool $enabled): void
    {
        $data = self::read();
        if (!isset($data['feeds'][$id])) {
            throw new DomainException('The proxy subscription was removed.');
        }
        $data['feeds'][$id]['auto'] = $enabled;
        self::save($data);
    }

    public static function refreshFeed(string $id, array $pinned): array
    {
        $data = self::read();
        $feed = $data['feeds'][$id] ?? null;
        if (!is_array($feed)) {
            throw new DomainException('The proxy subscription was removed.');
        }
        return self::refreshSavedFeed($data, $feed, $pinned);
    }

    private static function refreshSavedFeed(array $data, array $feed, array $pinned): array
    {
        try {
            $candidate = $data;
            $result = self::refresh($candidate, $feed, $pinned);
            self::save($candidate);
            return $result;
        } catch (DomainException | RuntimeException $error) {
            $id = $feed['id'];
            $data['feeds'][$id]['error'] = $error->getMessage();
            $data['feeds'][$id]['attempted'] = time();
            try {
                self::save($data);
            } catch (DomainException | RuntimeException) {
                self::scheduleRefresh($data['feeds'], time() + self::RETRY_INTERVAL);
            }
            throw $error;
        }
    }

    public static function refreshDue(array $pinned): void
    {
        $now = time();
        $fingerprint = self::catalogFingerprint();
        if ($fingerprint === null) {
            return;
        }
        $path = Policy::STATE_DIR . '/' . self::REFRESH_STATE;
        $raw = @file_get_contents($path, false, null, 0, 512);
        $schedule = is_string($raw) ? json_decode($raw, true, 4) : null;
        if (($schedule['catalog'] ?? null) === $fingerprint &&
            is_int($schedule['next'] ?? null) && ($schedule['next'] === 0 || $schedule['next'] > $now)) {
            return;
        }
        try {
            $data = self::read();
        } catch (RuntimeException $error) {
            self::scheduleRefresh([], $now + self::RETRY_INTERVAL);
            throw $error;
        }
        foreach ($data['feeds'] as $feed) {
            $next = self::nextRefresh($feed);
            if ($next !== null && $next <= $now) {
                try {
                    self::refreshSavedFeed($data, $feed, $pinned);
                } catch (DomainException | RuntimeException) {
                    // The previous usable list remains available, with an error shown in the dashboard.
                }
                return;
            }
        }
        self::scheduleRefresh($data['feeds']);
    }

    private static function nextRefresh(array $feed): ?int
    {
        return empty($feed['auto']) ? null : max(
            (int)($feed['updated'] ?? 0) + self::REFRESH_INTERVAL,
            (int)($feed['attempted'] ?? 0) + self::RETRY_INTERVAL
        );
    }

    private static function catalogFingerprint(): ?array
    {
        $path = Policy::STATE_DIR . '/' . self::FILE;
        clearstatcache(true, $path);
        $status = @lstat($path);
        return $status === false ? null : array_values(array_intersect_key($status, array_flip([
            'dev', 'ino', 'mode', 'size', 'mtime', 'ctime'
        ])));
    }

    private static function scheduleRefresh(array $feeds, int $notBefore = 0): void
    {
        $catalog = self::catalogFingerprint();
        $dates = array_filter(array_map(self::nextRefresh(...), $feeds), 'is_int');
        $next = max($notBefore, $dates === [] ? 0 : min($dates));
        try {
            Policy::writeState(self::REFRESH_STATE, json_encode(compact('catalog', 'next'), JSON_THROW_ON_ERROR));
        } catch (RuntimeException) {
            // The catalog is authoritative if the optional schedule cannot be saved.
        }
    }

    private static function refresh(array &$data, array $feed, array $pinned): array
    {
        $download = self::fetch($feed['url']);
        if (preg_match('/^\s*<(?:!doctype\s+html|html|head|body)(?:[\s>])/i', $download['body'])) {
            throw new DomainException('The provider returned a web page. Copy the direct Clash or Mihomo subscription URL from your provider.');
        }
        $result = ProxyImport::parse($download['body']);
        self::replaceNodes($data, $feed['id'], $result['nodes'], $pinned);
        $data['feeds'][$feed['id']] = [
            'updated' => time(), 'attempted' => time(), 'error' => null,
            'count' => count($result['nodes']), 'skipped' => $result['skipped'], 'usage' => $download['usage']
        ] + $feed;
        return ['imported' => count($result['nodes']), 'skipped' => $result['skipped']];
    }

    public static function removeFeed(string $id, array $pinned): void
    {
        $data = self::read();
        if (!isset($data['feeds'][$id])) {
            throw new DomainException('The proxy subscription was removed.');
        }
        unset($data['feeds'][$id]);
        self::replaceNodes($data, $id, [], $pinned);
        self::save($data);
    }

    public static function setEnabled(string $id, bool $enabled): void
    {
        $data = self::read();
        if (!isset($data['nodes'][$id])) {
            throw new DomainException('This proxy server is no longer saved.');
        }
        $data['nodes'][$id]['disabled'] = !$enabled;
        self::save($data);
    }

    public static function removeNode(string $id, array $pinned): void
    {
        if (in_array($id, $pinned, true)) {
            throw new DomainException('Remove this server’s proxy exit before deleting the saved node.');
        }
        $data = self::read();
        unset($data['nodes'][$id]);
        self::save($data);
    }

    private static function replaceNodes(array &$data, string $source, array $nodes, array $pinned): void
    {
        foreach ($data['nodes'] as $id => &$entry) {
            if (!in_array($source, ['manual', self::MANAGED_NORD], true) && !isset($nodes[$id])) {
                $entry['sources'] = array_values(array_diff($entry['sources'], [$source]));
                if ($entry['sources'] === [] && !in_array($id, $pinned, true)) {
                    unset($data['nodes'][$id]);
                }
            }
        }
        unset($entry);
        foreach ($nodes as $id => $node) {
            $existing = $data['nodes'][$id] ?? [];
            $node['serverName'] = self::originalServerName($node);
            if ($source !== self::MANAGED_NORD) {
                if (self::isManagedNord($existing)) {
                    // A generic import of the same endpoint cannot replace the managed exit.
                    continue;
                }
                unset($node['provider'], $node['providerLocation'], $node['providerServer']);
            }
            if (empty($node['customName']) && !empty($existing['customName'])) {
                $node['name'] = $existing['name'];
                $node['customName'] = true;
            }
            if (!empty($existing['disabled'])) {
                $node['disabled'] = true;
            }
            $node['sources'] = array_values(array_unique([...($existing['sources'] ?? []), $source]));
            $data['nodes'][$id] = $node;
        }
    }

    private static function endpoint(string $url): array
    {
        $parts = strlen($url) <= self::MAX_URL_BYTES && !preg_match('/[\x00-\x20\x7f\\\\]/', $url) ? parse_url($url) : false;
        if (!$parts || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new DomainException('Use an HTTPS subscription URL without embedded login credentials or a fragment.');
        }
        $host = ProxyImport::host($parts['host']);
        $literal = filter_var($host, FILTER_VALIDATE_IP);
        $expectedHost = $literal && str_contains($host, ':') ? '[' . $host . ']' : $host;
        if (strcasecmp($parts['host'], $expectedHost) !== 0 ||
            (!$literal && !preg_match('/\.[a-z][a-z0-9-]*$/D', $host))) {
            throw new DomainException('Use a conventional public subscription hostname.');
        }
        $port = ProxyImport::port($parts['port'] ?? 443);
        return [$host, $port, $parts['host']];
    }

    public static function subscriptionUsage(string $header): array
    {
        $usage = [];
        $seen = [];
        if (strlen($header) > 1024) {
            return $usage;
        }
        foreach (explode(';', $header) as $field) {
            if (!preg_match('/^\s*(upload|download|total|expire)\s*=\s*([0-9]{1,19})\s*$/iD', $field, $match)) {
                continue;
            }
            $key = strtolower($match[1]);
            if (isset($seen[$key])) {
                unset($usage[$key]);
                continue;
            }
            $seen[$key] = true;
            $digits = ltrim($match[2], '0') ?: '0';
            $limit = $key === 'expire' ? '253402300799' : (string)PHP_INT_MAX;
            if (strlen($digits) < strlen($limit) || (strlen($digits) === strlen($limit) && strcmp($digits, $limit) <= 0)) {
                $usage[$key] = (int)$digits;
            }
        }
        return $usage;
    }

    private static function publicAddresses(string $host): array
    {
        $addresses = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : (gethostbynamel($host) ?: []);
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                if (isset($record['ipv6'])) {
                    $addresses[] = $record['ipv6'];
                }
            }
        }
        if ($addresses === []) {
            throw new DomainException('The router could not resolve the subscription hostname.');
        }
        foreach ($addresses as $address) {
            $ipv6 = str_contains($address, ':');
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) ||
                Policy::contains('224.0.0.0/4', $address) || ($ipv6 &&
                    (!Policy::contains('2000::/3', $address) || Policy::contains('2002::/16', $address)))) {
                throw new DomainException('The subscription hostname must resolve only to public unicast addresses.');
            }
        }
        return array_values(array_unique($addresses));
    }

    private static function fetch(string $url): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The OPNsense PHP cURL extension is unavailable.');
        }
        $deadline = microtime(true) + 25;
        for ($redirects = 0; $redirects <= 4; $redirects++) {
            [$host, $port, $urlHost] = self::endpoint($url);
            $addresses = self::publicAddresses($host);
            $remaining = (int)(($deadline - microtime(true)) * 1000);
            if ($remaining <= 0) {
                throw new RuntimeException('The subscription download timed out.');
            }
            $reply = self::download($url, $urlHost, $port, $addresses, $remaining);
            if ($reply['status'] === 200) {
                return $reply;
            }
            if (!in_array($reply['status'], [301, 302, 303, 307, 308], true) || $reply['redirect'] === '') {
                throw new RuntimeException('The subscription provider returned HTTP ' . $reply['status'] . '.');
            }
            // Resolve and validate each redirect independently. Never let cURL follow it automatically.
            $url = $reply['redirect'];
        }
        throw new RuntimeException('The subscription provider redirected the download too many times.');
    }

    private static function download(string $url, string $host, int $port, array $addresses, int $remaining): array
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new RuntimeException('The router could not initialize the subscription download.');
        }
        $resolve = filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) ? [] : [
            $host . ':' . $port . ':' . implode(',', array_map(static fn (string $ip): string =>
                str_contains($ip, ':') ? '[' . $ip . ']' : $ip, $addresses))
        ];
        $body = '';
        $usage = [];
        $oversized = false;
        $options = [
            CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false, CURLOPT_RESOLVE => $resolve,
            CURLOPT_PROXY => '', CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2, CURLOPT_CONNECTTIMEOUT_MS => min(5000, $remaining),
            CURLOPT_TIMEOUT_MS => $remaining, CURLOPT_ENCODING => '', CURLOPT_USERAGENT => 'Clash.Meta/1.19.34 BlankVPN',
            CURLOPT_HEADERFUNCTION => static function ($handle, string $header) use (&$usage): int {
                if (str_starts_with($header, 'HTTP/')) {
                    $usage = [];
                } elseif (stripos($header, 'subscription-userinfo:') === 0) {
                    $usage = self::subscriptionUsage(substr($header, strlen('subscription-userinfo:')));
                }
                return strlen($header);
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$oversized): int {
                if (strlen($body) + strlen($chunk) > ProxyImport::MAX_BYTES) {
                    $oversized = true;
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            }
        ];
        if (!curl_setopt_array($curl, $options)) {
            throw new RuntimeException('The router could not configure a verified HTTPS subscription download.');
        }
        if (curl_exec($curl) === false) {
            throw new RuntimeException($oversized ? 'The subscription response exceeds the 4 MiB download limit.' :
                match (curl_errno($curl)) {
                    CURLE_OPERATION_TIMEDOUT => 'The subscription download timed out.',
                    CURLE_SSL_CACERT => 'The subscription server’s TLS certificate could not be verified.',
                    CURLE_SSL_CONNECT_ERROR => 'The subscription server could not establish a TLS connection.',
                    CURLE_COULDNT_CONNECT => 'The router could not connect to the subscription server over HTTPS.',
                    default => 'The HTTPS subscription download failed (cURL code ' . curl_errno($curl) . ').'
                });
        }
        return ['body' => $body, 'usage' => $usage, 'status' => curl_getinfo($curl, CURLINFO_RESPONSE_CODE),
            'redirect' => (string)curl_getinfo($curl, CURLINFO_REDIRECT_URL)];
    }
}
