<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use OPNsense\Core\Backend;

final class SmartRouting
{
    public const BYPASS = 'bypass';
    public const PORT = Resolver::LOCAL_PORT + 6;
    public const MAX_SERVICES = 16;
    public const MAX_DOMAINS = 1000;
    public const MAX_DOMAIN_BYTES = 131072;
    public const TABLE_MAX_AGE = 86400;
    public const PRESETS = [
        'Netflix' => ['netflix.com', 'netflix.net', 'nflxext.com', 'nflximg.com', 'nflximg.net',
            'nflxsearch.net', 'nflxso.net', 'nflxvideo.net'],
        'Hulu' => ['hulu.com', 'hulustream.com', 'huluim.com'],
        'WeChat' => ['wechat.com', 'weixin.qq.com'],
        'YouTube' => ['youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com', 'ytimg.com',
            'youtubei.googleapis.com', 'youtube.googleapis.com', 'yt3.ggpht.com']
    ];

    public static function services(BlankVpn $model): array
    {
        $services = [];
        foreach ($model->services->service->iterateItems() as $id => $node) {
            $row = Policy::fields($node);
            $services[$id] = [
                'id' => $id, 'name' => $row['name'], 'profile' => $row['profile'] ?? '',
                'domains' => self::destinations($row['domains'])
            ];
        }
        return $services;
    }

    public static function boundServices(array $services): array
    {
        return array_filter($services, static fn (array $service): bool => ($service['profile'] ?? '') !== '');
    }

    public static function usesBypass(array $settings): bool
    {
        return !empty($settings['enabled']) && !empty($settings['interfaces']) &&
            (($settings['coverage'] ?? '') !== 'network' ||
            in_array($settings['networkMode'] ?? '', ['full', 'full_multi', 'multi'], true));
    }

    public static function activeServices(array $settings, array $services): array
    {
        return self::forwardServices($settings, $services) + self::bypassServices($settings, $services);
    }

    public static function forwardServices(array $settings, array $services): array
    {
        if (empty($settings['enabled']) || empty($settings['smartInterfaces']) ||
            (($settings['coverage'] ?? '') === 'network' && !Policy::usesMultiPath($settings['networkMode'] ?? ''))) {
            return [];
        }
        return array_filter(self::boundServices($services), static fn (array $service): bool =>
            $service['profile'] !== self::BYPASS);
    }

    public static function bypassServices(array $settings, array $services): array
    {
        if (!self::usesBypass($settings)) {
            return [];
        }
        return array_filter(self::boundServices($services), static fn (array $service): bool =>
            $service['profile'] === self::BYPASS);
    }

    public static function bypassTable(array $services): string
    {
        $domains = self::domainEntries(array_merge(...array_column($services, 'domains')));
        return self::tableName('bvb_', $domains);
    }

    public static function domains(string $input): array
    {
        return self::parseList($input, false);
    }

    public static function destinations(string $input): array
    {
        return self::parseList($input, true);
    }

    private static function parseList(string $input, bool $allowAddresses): array
    {
        if (strlen($input) > self::MAX_DOMAIN_BYTES) {
            throw new DomainException('The Multi-Path destination list is too long.');
        }
        $input = preg_replace('/^\xEF\xBB\xBF/', '', $input);
        $input = preg_replace('/#[^\r\n]*/', '', $input);
        $destinations = [];
        foreach (preg_split('/[\s,]+/', trim($input), -1, PREG_SPLIT_NO_EMPTY) as $item) {
            if ($allowAddresses && (str_contains($item, '/') || filter_var($item, FILTER_VALIDATE_IP))) {
                if (!str_contains($item, '/')) {
                    $item .= str_contains($item, ':') ? '/128' : '/32';
                }
                $prefix = Policy::cidr($item, false);
                if ($prefix === null) {
                    throw new DomainException('Enter a valid IP address or CIDR between /1 and /32 for IPv4, or /1 and /128 for IPv6.');
                }
                $destinations[$prefix] = true;
                continue;
            }
            $domain = strtolower($item);
            $explicitSuffix = str_starts_with($domain, '*.') || str_starts_with($domain, '.');
            $domain = rtrim(substr($domain, str_starts_with($domain, '*.') ? 2 : (int)$explicitSuffix), '.');
            $topLevel = !str_contains($domain, '.');
            if (
                strlen($domain) > 253 ||
                !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $domain) ||
                ($topLevel && (!$explicitSuffix || in_array($domain, [
                    'arpa', 'example', 'internal', 'invalid', 'local', 'localhost', 'onion', 'test'
                ], true))) ||
                self::matches($domain, 'home.arpa') || self::matches($domain, 'local')
            ) {
                throw new DomainException($allowAddresses
                    ? 'Enter a DNS domain such as netflix.com or *.cn, an IP address, or a CIDR. Local domains are excluded.'
                    : 'Enter a DNS domain such as netflix.com or a suffix such as *.cn. Local domains and IPs are excluded.');
            }
            $destinations[$topLevel ? '.' . $domain : $domain] = true;
        }
        if (count($destinations) < 1 || count($destinations) > self::MAX_DOMAINS) {
            throw new DomainException('Add between one and ' . self::MAX_DOMAINS . ' unique destinations per list.');
        }
        return array_keys($destinations);
    }

    public static function matches(string $name, string $suffix): bool
    {
        $suffix = ltrim($suffix, '.');
        return $name === $suffix || str_ends_with($name, '.' . $suffix);
    }

    public static function checkOverlap(array $services, string $editedId, array $destinations): void
    {
        $existing = [];
        $parents = [];
        $addresses = [];
        foreach ($services as $id => $service) {
            if ($id === $editedId) {
                continue;
            }
            foreach (self::domainEntries($service['domains']) as $domain) {
                $domain = ltrim($domain, '.');
                $existing[$domain] = true;
                foreach (self::parentDomains($domain) as $parent) {
                    $parents[$parent] = true;
                }
            }
            $addresses += array_fill_keys(self::addressEntries($service['domains']), true);
        }
        foreach (self::domainEntries($destinations) as $domain) {
            $domain = ltrim($domain, '.');
            if (isset($existing[$domain]) || isset($parents[$domain])) {
                throw new DomainException('A domain overlaps another routed list.');
            }
            foreach (self::parentDomains($domain) as $parent) {
                if (isset($existing[$parent])) {
                    throw new DomainException('A domain overlaps another routed list.');
                }
            }
        }
        $pending = self::addressEntries($destinations);
        if ($pending !== [] && $addresses !== []) {
            self::checkAddressOverlap(array_keys($addresses), $pending);
        }
    }

    private static function checkAddressOverlap(array $existing, array $pending): void
    {
        $ranges = [];
        foreach ([$existing, $pending] as $current => $prefixes) {
            foreach ($prefixes as $network) {
                [$ip, $prefix] = explode('/', $network);
                $start = inet_pton($ip);
                $width = strlen($start);
                $end = $start;
                for ($byte = 0; $byte < $width; $byte++) {
                    $hostBits = min(8, max(0, $byte * 8 + 8 - (int)$prefix));
                    $end[$byte] = chr(ord($start[$byte]) | ((1 << $hostBits) - 1));
                }
                $ranges[$width][] = [$start, $end, $current];
            }
        }
        foreach ($ranges as $family) {
            usort($family, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));
            $farthest = ['', ''];
            foreach ($family as [$start, $end, $current]) {
                if (strcmp($start, $farthest[1 - $current]) <= 0) {
                    throw new DomainException('An IP address or CIDR overlaps another routed list.');
                }
                if (strcmp($end, $farthest[$current]) > 0) {
                    $farthest[$current] = $end;
                }
            }
        }
    }

    private static function parentDomains(string $domain): \Generator
    {
        while (($dot = strpos($domain, '.')) !== false) {
            $domain = substr($domain, $dot + 1);
            yield $domain;
        }
    }

    private static function domainEntries(array $destinations): array
    {
        return array_filter($destinations, static fn (string $entry): bool => !str_contains($entry, '/'));
    }

    public static function hasDomains(array $destinations): bool
    {
        return self::domainEntries($destinations) !== [];
    }

    public static function addressEntries(array $destinations): array
    {
        return array_values(array_filter($destinations, static fn (string $entry): bool => str_contains($entry, '/')));
    }

    public static function table(array $service): string
    {
        return self::tableName('bvs_', self::domainEntries($service['domains']), [$service['id'], $service['profile']]);
    }

    public static function addressTable(array $service): string
    {
        return self::tableName('bvi_', self::addressEntries($service['domains']), [$service['id'], $service['profile']]);
    }

    public static function bypassAddressTable(array $services): string
    {
        return self::tableName('bvx_', self::addressEntries(array_merge(...array_column($services, 'domains'))));
    }

    private static function tableName(string $prefix, array $entries, array $identity = []): string
    {
        $entries = array_unique($entries);
        sort($entries, SORT_STRING);
        return $prefix . substr(hash('sha256', implode(',', [...$identity, ...$entries])), 0, 24);
    }

    public static function profileDns(array $profile): array
    {
        return array_values(array_filter(
            $profile['dns'] ?? [],
            static fn ($ip) => is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        ));
    }

    public static function canResolve(array $profile): bool
    {
        return isset($profile['proxyDns']) || self::profileDns($profile) !== [];
    }

    public static function dnsDirectives(array $services, array $profiles, array $bypassUpstreams = []): array
    {
        $lines = [];
        $bypassLists = array_filter($services, static fn (array $service): bool =>
            ($service['profile'] ?? '') === self::BYPASS);
        $bypassTable = $bypassLists === [] ? '' : self::bypassTable($bypassLists);
        $bypassSuffixes = [];
        foreach ($bypassLists as $service) {
            foreach (self::domainEntries($service['domains']) as $domain) {
                $bypassSuffixes[ltrim($domain, '.')] = true;
            }
        }
        foreach (self::boundServices($services) as $service) {
            $profile = $profiles[$service['profile']] ?? [];
            $source = explode('/', $profile['address'] ?? '')[0];
            $servers = self::profileDns($profile);
            $bypass = $service['profile'] === self::BYPASS;
            $table = $bypass ? $bypassTable : self::table($service);
            foreach (self::domainEntries($service['domains']) as $domain) {
                $domain = ltrim($domain, '.');
                if ($bypass) {
                    $lines[] = "ipset=/{$domain}/{$table}";
                    if ($bypassUpstreams === []) {
                        $lines[] = "local=/{$domain}/";
                    }
                    foreach ($bypassUpstreams as $upstream) {
                        $lines[] = "server=/{$domain}/{$upstream}";
                    }
                    continue;
                }
                // An explicit bypass applies to all names below its suffix, even with a more specific VPN list.
                foreach (self::parentDomains($domain) as $parent) {
                    if (isset($bypassSuffixes[$parent])) {
                        continue 2;
                    }
                }
                if (isset($bypassSuffixes[$domain])) {
                    continue;
                }
                $lines[] = "ipset=/{$domain}/{$table}";
                if (isset($profile['proxyDns'])) {
                    $lines[] = "server=/{$domain}/127.0.0.1#{$profile['proxyDns']}";
                    continue;
                }
                if (!filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $servers === []) {
                    $lines[] = "local=/{$domain}/";
                    continue;
                }
                foreach ($servers as $server) {
                    $lines[] = "server=/{$domain}/{$server}@{$source}";
                }
            }
        }
        return $lines;
    }

    public static function active(array $settings, array $services): bool
    {
        return self::activeServices($settings, $services) !== [];
    }

    public static function status(): array
    {
        $raw = (new Backend())->configdRun('blankvpn smart_status', false, 10);
        $result = json_decode($raw, true);
        return is_array($result) ? $result : [];
    }

    private static function learnedTables(array $settings, array $services): array
    {
        $hasDomains = static fn (array $service): bool => self::hasDomains($service['domains']);
        $forward = array_filter(self::forwardServices($settings, $services), $hasDomains);
        $bypass = array_filter(self::bypassServices($settings, $services), $hasDomains);
        $tables = array_map(self::table(...), $forward);
        return $bypass === [] ? $tables : $tables + array_fill_keys(array_keys($bypass), self::bypassTable($bypass));
    }

    public static function countLearned(array $settings, array $services): array
    {
        $counts = [];
        $tableCounts = [];
        foreach (self::learnedTables($settings, $services) as $id => $table) {
            if (!array_key_exists($table, $tableCounts)) {
                try {
                    $output = Resolver::command(['/sbin/pfctl', '-t', $table, '-T', 'show']);
                    $lines = preg_split('/\R/', trim($output), -1, PREG_SPLIT_NO_EMPTY);
                    $tableCounts[$table] = count($lines);
                } catch (\RuntimeException) {
                    $tableCounts[$table] = null;
                }
            }
            $counts[$id] = $tableCounts[$table];
        }
        return $counts;
    }

    public static function expire(array $settings, array $services): void
    {
        foreach (array_unique(self::learnedTables($settings, $services)) as $table) {
            Resolver::command(
                ['/sbin/pfctl', '-t', $table, '-T', 'expire', (string)self::TABLE_MAX_AGE],
                false
            );
        }
    }
}
