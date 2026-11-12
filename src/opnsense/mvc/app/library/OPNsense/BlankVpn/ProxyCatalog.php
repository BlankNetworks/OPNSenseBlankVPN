<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

final class ProxyCatalog
{
    private const FILE = 'proxy-catalog.json';
    private const MAX_FEEDS = 12;
    private const MAX_CATALOG_BYTES = 16777216;
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
    }

    public static function publicView(): array
    {
        $data = self::read();
        return [
            'nodes' => array_values(array_map(static fn (array $node): array =>
                array_intersect_key($node, array_flip(['id', 'name', 'core', 'protocol', 'host', 'port', 'legacy', 'sources'])),
                $data['nodes'])),
            'feeds' => array_values(array_map(static fn (array $feed): array =>
                array_intersect_key($feed, array_flip(['id', 'name', 'auto', 'updated', 'error', 'skipped', 'count'])),
                $data['feeds']))
        ];
    }

    public static function import(string $body): array
    {
        $data = self::read();
        $parsed = ProxyImport::parse($body);
        self::replaceNodes($data, 'manual', $parsed['nodes'], []);
        self::save($data);
        return ['imported' => count($parsed['nodes']), 'skipped' => $parsed['skipped']];
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

    public static function refreshFeed(string $id, array $pinned): array
    {
        $data = self::read();
        $feed = $data['feeds'][$id] ?? null;
        if (!is_array($feed)) {
            throw new DomainException('The proxy subscription was removed.');
        }
        try {
            return self::refresh($data, $feed, $pinned);
        } catch (DomainException | RuntimeException $error) {
            $data['feeds'][$id]['error'] = $error->getMessage();
            $data['feeds'][$id]['attempted'] = time();
            throw $error;
        } finally {
            self::save($data);
        }
    }

    public static function refreshDue(array $pinned): void
    {
        foreach (self::read()['feeds'] as $feed) {
            $now = time();
            if (!empty($feed['auto']) && $now - ($feed['updated'] ?? 0) >= self::REFRESH_INTERVAL &&
                $now - ($feed['attempted'] ?? 0) >= self::RETRY_INTERVAL) {
                try {
                    self::refreshFeed($feed['id'], $pinned);
                } catch (DomainException | RuntimeException) {
                    // The previous usable list remains available, with an error shown in the dashboard.
                }
                return;
            }
        }
    }

    private static function refresh(array &$data, array $feed, array $pinned): array
    {
        $result = ProxyImport::parse(self::fetch($feed['url']));
        self::replaceNodes($data, $feed['id'], $result['nodes'], $pinned);
        $data['feeds'][$feed['id']] = [
            'updated' => time(), 'attempted' => time(), 'error' => null,
            'count' => count($result['nodes']), 'skipped' => $result['skipped']
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
            if ($source !== 'manual' && !isset($nodes[$id])) {
                $entry['sources'] = array_values(array_diff($entry['sources'], [$source]));
                if ($entry['sources'] === [] && !in_array($id, $pinned, true)) {
                    unset($data['nodes'][$id]);
                }
            }
        }
        unset($entry);
        foreach ($nodes as $id => $node) {
            $node['sources'] = array_values(array_unique([...($data['nodes'][$id]['sources'] ?? []), $source]));
            $data['nodes'][$id] = $node;
        }
    }

    private static function endpoint(string $url): array
    {
        $parts = strlen($url) <= 2048 && !preg_match('/[\x00-\x20\x7f\\\\]/', $url) ? parse_url($url) : false;
        if (!$parts || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new DomainException('Use an HTTPS subscription URL without embedded login credentials or a fragment.');
        }
        $host = ProxyImport::host($parts['host']);
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/\.[a-z][a-z0-9-]*$/D', $host)) {
            throw new DomainException('Use a conventional public subscription hostname.');
        }
        $port = ProxyImport::port($parts['port'] ?? 443);
        return [$host, $port];
    }

    private static function fetch(string $url): string
    {
        [$host, $port] = self::endpoint($url);
        $addresses = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : (gethostbynamel($host) ?: []);
        if ($addresses === [] || array_filter($addresses, static fn ($ip) =>
            !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE))) {
            throw new DomainException('The subscription hostname must resolve only to public addresses.');
        }
        $ip = $addresses[0];
        $resolve = !filter_var($host, FILTER_VALIDATE_IP) ? [sprintf('%s:%d:%s', $host, $port, $ip)] : [];
        $curl = curl_init($url);
        $body = '';
        $options = [
            CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false, CURLOPT_RESOLVE => $resolve,
            CURLOPT_PROXY => '', CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_TIMEOUT => 10,
            CURLOPT_ENCODING => '', CURLOPT_USERAGENT => 'Blank VPN/0.3 (OPNsense; Clash-compatible)',
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > ProxyImport::MAX_BYTES) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            }
        ];
        if ($curl === false || !curl_setopt_array($curl, $options) || curl_exec($curl) === false ||
            (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) {
            throw new RuntimeException('The subscription could not be downloaded. Check the HTTPS URL and provider response.');
        }
        return $body;
    }
}
