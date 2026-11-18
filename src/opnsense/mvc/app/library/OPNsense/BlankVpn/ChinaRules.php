<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use RuntimeException;

/** Large China destination data stored outside config.xml. */
final class ChinaRules
{
    public const ID = '030a8fd7-4a18-4a2b-9b82-a4e67c397102';
    public const MARKER = '@passwall-china';
    private const DATA_PREFIX = 'china-rules-';
    private const STATUS_FILE = 'china-rules-status.json';
    private const MATCHER_MODE_FILE = 'china-matcher-mode.json';
    private const MAX_RESPONSE_BYTES = 33_554_432;
    private const MAX_DOMAINS = 250_000;
    private const MAX_NETWORKS = 100_000;
    private const MAX_SPECIAL_RULES = 1024;
    private const FEEDS = [
        'domains' => [
            'https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf',
            'https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf',
        ],
        'ipv4' => [
            'https://ispip.clang.cn/all_cn.txt',
            'https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china.txt',
        ],
        'ipv6' => [
            'https://ispip.clang.cn/all_cn_ipv6.txt',
            'https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt',
        ],
        'geosite' => ['https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'],
        'geoip' => ['https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'],
    ];

    public static function status(): array
    {
        $path = Policy::STATE_DIR . '/' . self::STATUS_FILE;
        $raw = @file_get_contents($path, false, null, 0, 8192);
        $status = is_string($raw) ? json_decode($raw, true, 8) : null;
        $file = is_array($status) ? (string)($status['file'] ?? '') : '';
        $dataPath = preg_match('/^china-rules-[a-f0-9]{24}\.json\.gz$/D', $file) === 1
            ? Policy::STATE_DIR . '/' . $file : '';
        if (!is_array($status) || $dataPath === '' || !is_file($dataPath)) {
            return [
                'available' => false, 'updated' => null, 'domains' => 0, 'ipv4' => 0, 'ipv6' => 0,
                'geoDomains' => 0, 'geoNetworks' => 0, 'unsupportedGeoRules' => 0,
                'exactGeoDomains' => 0, 'regexSuffixDomains' => 0,
                'bytes' => 0, 'error' => $status['error'] ?? null, 'matcherMode' => self::matcherMode(),
            ];
        }
        return ['available' => true, 'matcherMode' => self::matcherMode()] + array_intersect_key($status, array_flip([
            'file', 'updated', 'domains', 'ipv4', 'ipv6', 'geoDomains', 'geoNetworks', 'unsupportedGeoRules',
            'exactGeoDomains', 'regexSuffixDomains', 'bytes', 'sha256', 'sources', 'error'
        ]));
    }

    public static function destinations(): array
    {
        $data = self::readData();
        return [...($data['domains'] ?? []), ...($data['networks'] ?? [])];
    }

    public static function specialRules(): array
    {
        $data = self::readData();
        $rules = [];
        foreach ($data['unsupportedGeoRules'] ?? [] as $entry) {
            if (!is_string($entry) || strlen($entry) > 1024 || !str_contains($entry, ':')) {
                continue;
            }
            [$type, $pattern] = explode(':', $entry, 2);
            $kind = match ($type) {
                'full' => 'full', 'plain', 'type0' => 'keyword', 'regex', 'type1' => 'regex', default => null
            };
            if ($kind === null || $pattern === '' || strlen($pattern) > 512) {
                continue;
            }
            if ($kind === 'regex' && @preg_match('~' . str_replace('~', '\\~', $pattern) . '~i', '') === false) {
                continue;
            }
            $rules[] = ['type' => $kind, 'pattern' => $pattern];
        }
        return $rules;
    }

    public static function matcherMode(): string
    {
        $path = Policy::STATE_DIR . '/' . self::MATCHER_MODE_FILE;
        $raw = @file_get_contents($path, false, null, 0, 128);
        $data = is_string($raw) ? json_decode($raw, true, 4) : null;
        return is_array($data) && ($data['mode'] ?? '') === 'route' ? 'route' : 'shadow';
    }

    public static function setMatcherMode(string $mode): void
    {
        if (!in_array($mode, ['shadow', 'route'], true)) {
            throw new DomainException('Choose shadow or active DNS matching.');
        }
        Policy::writeState(self::MATCHER_MODE_FILE, json_encode(['mode' => $mode], JSON_THROW_ON_ERROR));
    }

    private static function readData(): array
    {
        $status = self::status();
        $file = (string)($status['file'] ?? '');
        if (preg_match('/^china-rules-[a-f0-9]{24}\.json\.gz$/D', $file) !== 1) {
            return [];
        }
        $path = Policy::STATE_DIR . '/' . $file;
        if (!is_file($path) || is_link($path)) {
            return [];
        }
        $mode = @fileperms($path);
        if ($mode === false || ($mode & 0077) !== 0 || ($mode & 0170000) !== 0100000) {
            throw new RuntimeException('The private China routing data has unsafe permissions.');
        }
        $compressed = file_get_contents($path, false, null, 0, 33_554_433);
        $json = is_string($compressed) && strlen($compressed) <= 33_554_432 ? gzdecode($compressed, 128_000_000) : false;
        if (!is_string($json) || !hash_equals((string)($status['sha256'] ?? ''), hash('sha256', $json))) {
            throw new RuntimeException('The private China routing data failed its integrity check. Refresh the China rules.');
        }
        $data = json_decode($json, true, 4);
        if (!is_array($data) || !is_array($data['domains'] ?? null) || !is_array($data['networks'] ?? null) ||
            !is_array($data['unsupportedGeoRules'] ?? null) || count($data['domains']) > self::MAX_DOMAINS ||
            count($data['networks']) > self::MAX_NETWORKS) {
            throw new RuntimeException('The private China routing data could not be read. Refresh the China rules.');
        }
        return $data;
    }

    public static function service(array $row): array
    {
        $status = self::status();
        return [
            'id' => self::ID, 'name' => 'China', 'profile' => $row['profile'] ?? '',
            'domains' => !empty($status['available']) && ($row['profile'] ?? '') !== '' ? self::destinations() : [],
            'scope' => in_array($row['scope'] ?? '', ['local', 'tailscale', 'both'], true) ? $row['scope'] : 'both',
            'managed' => true, 'entryCount' => (int)($status['domains'] ?? 0) + (int)($status['ipv4'] ?? 0) + (int)($status['ipv6'] ?? 0),
        ];
    }

    public static function ensureList(BlankVpn $model): bool
    {
        $node = $model->services->service->getChild(self::ID);
        if ($node !== null) {
            $row = Policy::fields($node);
            if (($row['domains'] ?? '') === self::MARKER) {
                return false;
            }
            throw new DomainException('A saved Multi-Path list uses the reserved China rule identifier. Rename or remove it first.');
        }
        $node = $model->services->service->add(self::ID);
        $node->name = 'China';
        $node->domains = self::MARKER;
        $node->profile = '';
        $node->scope = 'both';
        return true;
    }

    public static function digest(): string
    {
        return (string)(self::status()['sha256'] ?? 'unavailable');
    }

    public static function update(?callable $validate = null): array
    {
        $domains = [];
        $networks = [];
        $unsupportedGeoRules = [];
        $exactGeoDomains = 0;
        $regexSuffixDomains = 0;
        $geoDomainCount = 0;
        $geoNetworkCount = 0;
        $sources = [];
        $newPath = '';
        $previousStatus = self::status();
        try {
            foreach (self::FEEDS as $kind => $urls) {
                if (in_array($kind, ['ipv4', 'ipv6'], true)) {
                    // These are alternate providers. Do not make an
                    // otherwise healthy update depend on both mirrors being online.
                    $errors = [];
                    $succeeded = false;
                    foreach ($urls as $url) {
                        try {
                            $candidate = [];
                            $count = self::parseNetworks(self::fetch($url), $candidate, $kind);
                            $minimum = $kind === 'ipv4' ? 1_000 : 500;
                            if ($count < $minimum) {
                                throw new DomainException('The China ' . strtoupper($kind) . ' source was unexpectedly small.');
                            }
                            $networks += $candidate;
                            $sources[] = ['url' => $url, 'entries' => $count];
                            $succeeded = true;
                            break;
                        } catch (\Throwable $error) {
                            $errors[] = $error->getMessage();
                        }
                    }
                    if (!$succeeded) {
                        throw new RuntimeException('All China ' . strtoupper($kind) . ' sources failed: ' . implode(' ', $errors));
                    }
                    unset($count);
                    continue;
                }
                foreach ($urls as $url) {
                    $body = self::fetch($url);
                    $count = $kind === 'domains'
                        ? self::parseDomains($body, $domains)
                        : ($kind === 'geosite'
                            ? self::parseGeoSite($body, $domains, $unsupportedGeoRules, $exactGeoDomains, $regexSuffixDomains)
                            : self::parseGeoIp($body, $networks));
                    if ($kind === 'geosite') {
                        $geoDomainCount = $count;
                    } elseif ($kind === 'geoip') {
                        $geoNetworkCount = $count;
                    }
                    $sources[] = ['url' => $url, 'entries' => $count];
                }
            }
            $ipv4Count = count(array_filter(array_keys($networks), static fn (string $ip): bool => !str_contains($ip, ':')));
            $ipv6Count = count($networks) - $ipv4Count;
            if (count($domains) < 10_000 || $ipv4Count < 1_000 || $ipv6Count < 500 ||
                $geoDomainCount < 50_000 || $geoNetworkCount < 1_000) {
                throw new DomainException('A China rule source was unexpectedly small. Existing rules were kept.');
            }
            ksort($domains, SORT_STRING);
            ksort($networks, SORT_STRING);
            $unsupportedGeoRules = array_values(array_unique($unsupportedGeoRules));
            sort($unsupportedGeoRules, SORT_STRING);
            if (count($unsupportedGeoRules) > self::MAX_SPECIAL_RULES) {
                throw new DomainException('The China geographic list exceeds the safe hostname matcher capacity. Existing rules were kept.');
            }
            if ($validate !== null) {
                $validate([...array_keys($domains), ...array_keys($networks)]);
            }
            $json = json_encode([
                'domains' => array_keys($domains), 'networks' => array_keys($networks),
                'unsupportedGeoRules' => $unsupportedGeoRules,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $compressed = gzencode($json, 6, ZLIB_ENCODING_GZIP);
            if (!is_string($compressed) || strlen($compressed) > 33_554_432) {
                throw new DomainException('The combined China rules exceed the safe storage limit. Existing rules were kept.');
            }
            // Hash the canonical, sorted rules so identical refreshes reuse the same PF table IDs.
            $digest = hash('sha256', $json);
            $file = self::DATA_PREFIX . substr($digest, 0, 24) . '.json.gz';
            $newPath = Policy::writeState($file, $compressed);
            $status = [
                'updated' => time(), 'domains' => count($domains),
                'ipv4' => $ipv4Count, 'ipv6' => $ipv6Count,
                'geoDomains' => $geoDomainCount, 'geoNetworks' => $geoNetworkCount,
                'unsupportedGeoRules' => count($unsupportedGeoRules), 'exactGeoDomains' => $exactGeoDomains,
                'regexSuffixDomains' => $regexSuffixDomains,
                'file' => $file, 'bytes' => strlen($compressed), 'sha256' => $digest, 'sources' => $sources,
                'error' => null,
            ];
            Policy::writeState(self::STATUS_FILE, json_encode($status, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            return ['available' => true, 'matcherMode' => self::matcherMode()] + $status;
        } catch (\Throwable $error) {
            $old = $previousStatus;
            if ($newPath !== '' && ($old['file'] ?? '') !== basename($newPath)) {
                @unlink($newPath);
            }
            $old['error'] = $error->getMessage();
            try {
                Policy::writeState(self::STATUS_FILE, json_encode($old, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            } catch (\Throwable) {
                // Keep the original download failure if the optional status file is unwritable.
            }
            throw $error;
        }
    }

    public static function restore(array $status): void
    {
        $file = (string)($status['file'] ?? '');
        if (preg_match('/^china-rules-[a-f0-9]{24}\.json\.gz$/D', $file) === 1 &&
            is_file(Policy::STATE_DIR . '/' . $file)) {
            Policy::writeState(self::STATUS_FILE, json_encode($status, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        } else {
            @unlink(Policy::STATE_DIR . '/' . self::STATUS_FILE);
        }
        self::prune();
    }

    public static function prune(): void
    {
        $active = (string)(self::status()['file'] ?? '');
        foreach (glob(Policy::STATE_DIR . '/' . self::DATA_PREFIX . '*.json.gz', GLOB_NOSORT) ?: [] as $path) {
            if (basename($path) !== $active && !is_link($path) && is_file($path)) {
                @unlink($path);
            }
        }
    }

    private static function parseDomains(string $body, array &$domains): int
    {
        $before = count($domains);
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') ||
                !preg_match('~^server=/([^/]+)/[^/\s]+$~D', $line, $match)) {
                continue;
            }
            $name = strtolower(rtrim($match[1], '.'));
            if (strlen($name) > 253 || !str_contains($name, '.') ||
                preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $name) !== 1) {
                continue;
            }
            $domains[$name] = true;
            if (count($domains) > self::MAX_DOMAINS) {
                throw new DomainException('A China rule source returned more than ' . self::MAX_DOMAINS . ' domains. Existing rules were kept.');
            }
        }
        return count($domains) - $before;
    }

    private static function parseNetworks(string $body, array &$networks, string $family): int
    {
        $before = count($networks);
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $line = trim(preg_replace('/\s+#.*$/', '', $line));
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $prefix = Policy::cidr($line, false);
            if ($prefix === null || (($family === 'ipv6') !== str_contains($prefix, ':'))) {
                continue;
            }
            $networks[$prefix] = true;
            if (count($networks) > self::MAX_NETWORKS) {
                throw new DomainException('A China rule source returned more than ' . self::MAX_NETWORKS . ' IP ranges. Existing rules were kept.');
            }
        }
        return count($networks) - $before;
    }

    private static function parseGeoSite(
        string $body,
        array &$domains,
        array &$unsupported,
        int &$exactCount,
        int &$regexSuffixCount
    ): int
    {
        $rules = 0;
        foreach (self::protobufFields($body) as [$field, $wire, $record]) {
            if ($field !== 1 || $wire !== 2) {
                continue;
            }
            $country = '';
            foreach (self::protobufFields($record) as [$siteField, $siteWire, $value]) {
                if ($siteField === 1 && $siteWire === 2) {
                    $country = strtoupper($value);
                    break;
                }
            }
            if ($country !== 'CN') {
                continue;
            }
            foreach (self::protobufFields($record) as [$siteField, $siteWire, $entry]) {
                if ($siteField !== 2 || $siteWire !== 2) {
                    continue;
                }
                // Protobuf's default enum value is PLAIN (0), including omitted fields.
                $type = 0;
                $name = '';
                foreach (self::protobufFields($entry) as [$domainField, $domainWire, $value]) {
                    if ($domainField === 1 && $domainWire === 0) {
                        $type = $value;
                    } elseif ($domainField === 2 && $domainWire === 2) {
                        $name = strtolower(rtrim($value, '.'));
                    }
                }
                $rules++;
                if ($type === 2) {
                    self::addGeoDomain($name, $domains);
                } elseif ($type === 3) {
                    // dnsmasq's suffix match would also capture every subdomain.
                    // Keep exact-name records out of the route set rather than
                    // widening their policy silently.
                    $exactCount++;
                    $unsupported[] = 'full:' . $name;
                } elseif ($type === 1 && ($suffix = self::regexSuffixDomain($name)) !== null) {
                    self::addGeoDomain($suffix, $domains);
                    $regexSuffixCount++;
                } elseif ($type >= 0) {
                    // Plain, non-equivalent regex, and future matcher types are unsupported.
                    $unsupported[] = 'type' . $type . ':' . $name;
                }
            }
        }
        return $rules;
    }

    /** Convert only anchored regex forms with exact DNS-suffix semantics. */
    private static function regexSuffixDomain(string $pattern): ?string
    {
        foreach (['^(.+\\.)*', '^([^.]+\\.)*'] as $prefix) {
            if (str_starts_with($pattern, $prefix) && str_ends_with($pattern, '$')) {
                $escapedDomain = substr($pattern, strlen($prefix), -1);
                $domain = str_replace('\\.', '.', $escapedDomain);
                if (strlen($domain) <= 253 && preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $domain) === 1) {
                    return $domain;
                }
            }
        }
        return null;
    }

    private static function parseGeoIp(string $body, array &$networks): int
    {
        $rules = 0;
        foreach (self::protobufFields($body) as [$field, $wire, $record]) {
            if ($field !== 1 || $wire !== 2) {
                continue;
            }
            $country = '';
            foreach (self::protobufFields($record) as [$ipField, $ipWire, $value]) {
                if ($ipField === 1 && $ipWire === 2) {
                    $country = strtoupper($value);
                    break;
                }
            }
            if ($country !== 'CN') {
                continue;
            }
            foreach (self::protobufFields($record) as [$ipField, $ipWire, $entry]) {
                if ($ipField !== 2 || $ipWire !== 2) {
                    continue;
                }
                $address = '';
                $prefixLength = -1;
                foreach (self::protobufFields($entry) as [$cidrField, $cidrWire, $value]) {
                    if ($cidrField === 1 && $cidrWire === 2) {
                        $address = inet_ntop($value) ?: '';
                    } elseif ($cidrField === 2 && $cidrWire === 0) {
                        $prefixLength = $value;
                    }
                }
                if ($address !== '' && $prefixLength >= 0) {
                    $prefix = Policy::cidr($address . '/' . $prefixLength, false);
                    if ($prefix !== null) {
                        $networks[$prefix] = true;
                        $rules++;
                        if (count($networks) > self::MAX_NETWORKS) {
                throw new DomainException('A China rule source returned more than ' . self::MAX_NETWORKS . ' IP ranges. Existing rules were kept.');
                        }
                    }
                }
            }
        }
        return $rules;
    }

    private static function addGeoDomain(string $name, array &$domains): void
    {
        if (strlen($name) <= 253 && str_contains($name, '.') &&
            preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $name) === 1) {
            $domains[$name] = true;
            if (count($domains) > self::MAX_DOMAINS) {
                throw new DomainException('A China rule source returned more than ' . self::MAX_DOMAINS . ' domains. Existing rules were kept.');
            }
        }
    }

    private static function protobufFields(string $bytes): \Generator
    {
        $offset = 0;
        $length = strlen($bytes);
        while ($offset < $length) {
            $tag = self::protobufVarint($bytes, $offset);
            $field = $tag >> 3;
            $wire = $tag & 7;
            if ($field < 1) {
                throw new RuntimeException('The China geographic rules are malformed.');
            }
            if ($wire === 0) {
                $value = self::protobufVarint($bytes, $offset);
            } elseif ($wire === 2) {
                $size = self::protobufVarint($bytes, $offset);
                if ($size < 0 || $size > $length - $offset) {
                    throw new RuntimeException('A China geographic rule is truncated.');
                }
                $value = substr($bytes, $offset, $size);
                $offset += $size;
            } elseif ($wire === 1 || $wire === 5) {
                $size = $wire === 1 ? 8 : 4;
                if ($size > $length - $offset) {
                    throw new RuntimeException('A China geographic rule is truncated.');
                }
                $value = substr($bytes, $offset, $size);
                $offset += $size;
            } else {
                throw new RuntimeException('The China geographic rules use an unsupported encoding.');
            }
            yield [$field, $wire, $value];
        }
    }

    private static function protobufVarint(string $bytes, int &$offset): int
    {
        $value = 0;
        $shift = 0;
        $length = strlen($bytes);
        while ($offset < $length && $shift < 64) {
            $byte = ord($bytes[$offset++]);
            $value |= ($byte & 0x7f) << $shift;
            if (($byte & 0x80) === 0) {
                return $value;
            }
            $shift += 7;
        }
        throw new RuntimeException('The China geographic rules contain a malformed field.');
    }

    private static function fetch(string $url): string
    {
        $parts = parse_url($url);
        $host = strtolower((string)($parts['host'] ?? ''));
        if (($parts['scheme'] ?? '') !== 'https' || !in_array($host, ['ispip.clang.cn', 'cdn.jsdelivr.net'], true) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) ||
            (isset($parts['port']) && (int)$parts['port'] !== 443) || !function_exists('curl_init')) {
            throw new RuntimeException('A China rules source is invalid or HTTPS downloading is unavailable.');
        }
        $body = '';
        $curl = curl_init($url);
        if ($curl === false) {
            throw new RuntimeException('The router could not initialize a China rules download.');
        }
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_PROTOCOLS_STR => 'https', CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROXY => '', CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_TIMEOUT => 15, CURLOPT_ENCODING => '',
            CURLOPT_USERAGENT => 'Blank VPN OPNsense China rules',
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_RESPONSE_BYTES) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_error($curl);
        curl_close($curl);
        if ($ok !== true || $status !== 200 || $body === '') {
            throw new RuntimeException('A China rules download failed (HTTP ' . $status . '). ' . $error);
        }
        if (preg_match('/^\s*(?:<!doctype\s+html|<html|<head|<body)/i', $body)) {
            throw new RuntimeException('A China rules source returned an HTML page instead of its rule list.');
        }
        return $body;
    }
}
