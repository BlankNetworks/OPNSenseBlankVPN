<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;
use OPNsense\Core\Backend;

final class SmartRouting
{
    public const PORT = Resolver::LOCAL_PORT + 6;
    public const MAX_SERVICES = 16;
    public const MAX_DOMAINS = 24;
    public const TABLE_MAX_AGE = 86400;
    public const PRESETS = [
        'Netflix' => ['netflix.com', 'netflix.net', 'nflxext.com', 'nflximg.com', 'nflximg.net',
            'nflxsearch.net', 'nflxso.net', 'nflxvideo.net'],
        'Hulu' => ['hulu.com', 'hulustream.com', 'huluim.com'],
        'WeChat' => ['wechat.com', 'weixin.qq.com']
    ];

    public static function services(BlankVpn $model): array
    {
        $services = [];
        foreach ($model->services->service->iterateItems() as $id => $node) {
            $row = Policy::fields($node);
            $services[$id] = [
                'id' => $id, 'name' => $row['name'], 'profile' => $row['profile'],
                'domains' => self::domains($row['domains'])
            ];
        }
        return $services;
    }

    public static function domains(string $input): array
    {
        if (strlen($input) > 2048) {
            throw new DomainException('The Smart Routing domain list is too long.');
        }
        $domains = [];
        foreach (preg_split('/[\s,]+/', trim($input), -1, PREG_SPLIT_NO_EMPTY) as $item) {
            $domain = strtolower($item);
            if (str_starts_with($domain, '*.')) {
                $domain = substr($domain, 2);
            }
            $domain = rtrim($domain, '.');
            if (
                strlen($domain) > 253 || !str_contains($domain, '.') ||
                !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $domain) ||
                self::matches($domain, 'home.arpa') || self::matches($domain, 'local')
            ) {
                throw new DomainException('Use a DNS domain such as netflix.com or *.netflix.com. Local domains and IPs are excluded.');
            }
            $domains[$domain] = true;
        }
        if (count($domains) < 1 || count($domains) > self::MAX_DOMAINS) {
            throw new DomainException('Add between one and 24 domain suffixes per service.');
        }
        return array_keys($domains);
    }

    public static function matches(string $name, string $suffix): bool
    {
        return $name === $suffix || str_ends_with($name, '.' . $suffix);
    }

    public static function checkOverlap(array $services, string $editedId, array $domains): void
    {
        foreach ($services as $id => $service) {
            if ($id === $editedId) {
                continue;
            }
            foreach ($service['domains'] as $existing) {
                foreach ($domains as $domain) {
                    if (self::matches($domain, $existing) || self::matches($existing, $domain)) {
                        throw new DomainException('A domain suffix overlaps another Smart Routing service.');
                    }
                }
            }
        }
    }

    public static function table(array $service): string
    {
        $domains = $service['domains'];
        sort($domains, SORT_STRING);
        return 'bvs_' . substr(hash('sha256', implode(',', [$service['id'], $service['profile'], ...$domains])), 0, 24);
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

    public static function dnsDirectives(array $services, array $profiles): array
    {
        $lines = [];
        foreach ($services as $service) {
            $profile = $profiles[$service['profile']] ?? [];
            $source = explode('/', $profile['address'] ?? '')[0];
            $servers = self::profileDns($profile);
            $table = self::table($service);
            foreach ($service['domains'] as $domain) {
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
        return $settings['enabled'] && $settings['smartInterfaces'] !== [] && $services !== [];
    }

    public static function status(): array
    {
        $raw = (new Backend())->configdRun('blankvpn smart_status', false, 10);
        $result = json_decode($raw, true);
        return is_array($result) ? $result : [];
    }

    public static function countLearned(array $services): array
    {
        $counts = [];
        foreach ($services as $id => $service) {
            try {
                $output = Resolver::command(['/sbin/pfctl', '-t', self::table($service), '-T', 'show']);
                $lines = preg_split('/\R/', trim($output), -1, PREG_SPLIT_NO_EMPTY);
                $counts[$id] = count($lines);
            } catch (\RuntimeException) {
                $counts[$id] = null;
            }
        }
        return $counts;
    }

    public static function expire(array $services): void
    {
        foreach ($services as $service) {
            Resolver::command(
                ['/sbin/pfctl', '-t', self::table($service), '-T', 'expire', (string)self::TABLE_MAX_AGE],
                false
            );
        }
    }
}
