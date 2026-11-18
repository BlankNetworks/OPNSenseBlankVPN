<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;

final class Resolver
{
    public const LOCAL_PORT = 46650;
    public const FALLBACK_PORT = 46657;
    public const BYPASS_PORT = 46658;
    public const DEVICE_BYPASS_PORT = 46659;
    public const SERVICE_PORT = 46668;
    public const PROTECTED_MULTI_PORT = 46669;
    public const COMBINED_FALLBACK_PORT = 46670;
    private const MATCHER_PORT_START = 49100;
    private const MATCHER_PORT_LIMIT = 200;
    private const MATCHER_SCRIPT = '/usr/local/opnsense/scripts/OPNsense/BlankVpn/dns_matcher.py';
    private const MATCHER_CONFIG = 'dns-matcher.json';
    private const MATCHER_PID = 'dns-matcher.pid';
    private const TAILNET_PORT_OFFSET = 2000;
    private const COMBINED_PORT_OFFSET = 200;
    private const PROTECTED_PORT_OFFSET = 400;
    private const PROTECTED_COMBINED_PORT_OFFSET = 800;
    private const DNS_SOURCE_PORT_START = 20000;
    private const DNS_SOURCE_PORTS_PER_LISTENER = 128;
    private const PROBE_SOURCE_PORT_START = 53000;
    private const PROBE_SOURCE_PORTS_PER_PROFILE = 8;

    private static function vpnPorts(): array
    {
        return [...range(self::LOCAL_PORT + 1, self::LOCAL_PORT + 5), ...range(46680, 46706)];
    }

    /** Dedicated source-port ranges keep shared-key tunnels distinct in PF. */
    public static function dnsSourcePorts(array $profile): ?array
    {
        $slot = array_search((int)($profile['dnsPort'] ?? 0), self::vpnPorts(), true);
        if ($slot === false) {
            return null;
        }
        $start = self::DNS_SOURCE_PORT_START + $slot * 8 * self::DNS_SOURCE_PORTS_PER_LISTENER;
        return [$start, $start + 8 * self::DNS_SOURCE_PORTS_PER_LISTENER - 1];
    }

    public static function probeSourcePorts(array $profile): ?array
    {
        $slot = array_search((int)($profile['dnsPort'] ?? 0), self::vpnPorts(), true);
        if ($slot === false) {
            return null;
        }
        $start = self::PROBE_SOURCE_PORT_START + $slot * self::PROBE_SOURCE_PORTS_PER_PROFILE;
        return [$start, $start + self::PROBE_SOURCE_PORTS_PER_PROFILE - 1];
    }

    private static function listenerSourcePorts(int $port): ?array
    {
        foreach (self::vpnPorts() as $slot => $base) {
            foreach ([0, self::COMBINED_PORT_OFFSET, self::PROTECTED_PORT_OFFSET,
                self::PROTECTED_COMBINED_PORT_OFFSET] as $variant => $offset) {
                foreach ([0, self::TAILNET_PORT_OFFSET] as $tailnet) {
                    if ($port === $base + $offset + $tailnet) {
                        $index = $variant + ($tailnet === 0 ? 0 : 4);
                        $start = self::DNS_SOURCE_PORT_START +
                            ($slot * 8 + $index) * self::DNS_SOURCE_PORTS_PER_LISTENER;
                        return [$start, $start + self::DNS_SOURCE_PORTS_PER_LISTENER - 1];
                    }
                }
            }
        }
        return null;
    }

    private static function profilePorts(): array
    {
        return [...self::vpnPorts(),
            ...range(ProxyRuntime::FIRST_DNS_PORT, ProxyRuntime::FIRST_DNS_PORT + ProxyRuntime::SLOTS - 1)];
    }

    public static function combinedPort(array $profile): int
    {
        return self::profilePort($profile, self::COMBINED_PORT_OFFSET);
    }

    public static function protectedPort(array $profile): int
    {
        return self::profilePort($profile, self::PROTECTED_PORT_OFFSET);
    }

    public static function protectedCombinedPort(array $profile): int
    {
        return self::profilePort($profile, self::PROTECTED_COMBINED_PORT_OFFSET);
    }

    private static function profilePort(array $profile, int $offset): int
    {
        $base = (int)($profile['dnsPort'] ?? 0);
        return in_array($base, self::profilePorts(), true) ? $base + $offset : 0;
    }

    public static function allowedPort(int $port): bool
    {
        if ($port >= self::LOCAL_PORT + self::TAILNET_PORT_OFFSET) {
            $port -= self::TAILNET_PORT_OFFSET;
        }
        $profilePorts = self::profilePorts();
        return in_array($port, [
            self::LOCAL_PORT, self::FALLBACK_PORT, self::BYPASS_PORT, self::DEVICE_BYPASS_PORT,
            self::SERVICE_PORT, self::PROTECTED_MULTI_PORT, self::COMBINED_FALLBACK_PORT, SmartRouting::PORT
        ], true) ||
            in_array($port, $profilePorts, true) ||
            in_array($port - self::PROTECTED_PORT_OFFSET, $profilePorts, true) ||
            in_array($port - self::PROTECTED_COMBINED_PORT_OFFSET, $profilePorts, true) ||
            in_array($port - self::COMBINED_PORT_OFFSET, $profilePorts, true);
    }

    public static function scopedPort(int $port, bool $tailscale): int
    {
        return $port === 0 || !$tailscale ? $port : $port + self::TAILNET_PORT_OFFSET;
    }

    public static function freePort(array $profiles): int
    {
        $ports = array_column($profiles, 'dnsPort');
        foreach (self::vpnPorts() as $port) {
            if (!in_array($port, $ports, true)) {
                return $port;
            }
        }
        throw new \DomainException('All 32 Blank VPN & Proxy profile slots are in use.');
    }

    public static function reconcile(BlankVpn $model): void
    {
        $settings = Policy::effectiveRouting($model);
        $wanted = [];
        $matcherConfig = ['version' => 1, 'mode' => ChinaRules::matcherMode(), 'listeners' => []];
        if ($settings['enabled']) {
            $hostname = $settings['hostname'];
            $bind = $hostname === 'blankvpn.local' ? 'lan' : $settings['dashboardBind'];
            $host = self::dashboardAddresses()[$bind];
            if (!self::validHostname($hostname)) {
                throw new \DomainException('Set a valid local dashboard hostname.');
            }
            $profiles = Policy::routes($model);
            $assignments = Policy::assignments($model, true);
            $services = SmartRouting::services($model);
            $wan = SmartRouting::hasBypassDomains($settings, $services) ? WanEgress::gateways() : [];
            foreach (Policy::scopes($settings) as $scope) {
                if (self::usesWanFallback($scope) || Policy::networkBypassAssignments($scope, $assignments) !== []) {
                    $wan = $wan ?: WanEgress::gateways();
                    break;
                }
            }
            $loaded = $profiles !== [] || isset($wan['inet'])
                ? Firewall::parseLoadedRules(self::command(['/sbin/pfctl', '-sr'], false)) : [];
            $profiles = self::verifiedDnsProfiles($profiles, $loaded);
            $wanUpstreams = WanEgress::dnsUpstreams($wan, $loaded);
            $plan = self::scopedListenerPlan($settings, $hostname, $host, $assignments, $profiles, $services,
                $wanUpstreams, $loaded, Firewall::health());
            $wanted = $plan['listeners'];
            $matcherConfig['listeners'] = $plan['matcher'];
        }

        if ($matcherConfig['listeners'] !== []) {
            self::reconcileMatcher($matcherConfig);
        }

        $ipsetChecked = false;
        foreach (self::listenerPorts($wanted) as $port) {
            $name = "dns-{$port}.conf";
            $config = Policy::STATE_DIR . '/' . $name;
            $pid = self::running($port);
            $next = $wanted[$port] ?? null;
            if ($next !== null && $pid !== null && is_file($config) && file_get_contents($config) === $next) {
                continue;
            }
            if ($pid !== null) {
                self::stop($pid, $port);
            }
            if ($next === null) {
                if (is_file($config)) {
                    unlink($config);
                }
                $pidFile = Policy::STATE_DIR . "/dns-{$port}.pid";
                if (is_file($pidFile)) {
                    unlink($pidFile);
                }
                continue;
            }
            if (!$ipsetChecked && str_contains($next, "\nipset=")) {
                $version = self::command(['/usr/local/sbin/dnsmasq', '--version']);
                if (!preg_match('/(?:^|\s)ipset(?:\s|$)/i', $version)) {
                    throw new \RuntimeException('Multi-Path requires the OPNsense Dnsmasq build with PF ipset support.');
                }
                $ipsetChecked = true;
            }
            if ($port === SmartRouting::PORT) {
                self::checkNativeDns($hostname);
            }
            Policy::writeState($name, $next);
            self::command(['/usr/local/sbin/dnsmasq', '--test', '--conf-file=' . $config]);
            self::command(['/usr/local/sbin/dnsmasq', '--conf-file=' . $config]);
            if (self::running($port) === null) {
                throw new \RuntimeException('The Blank VPN & Proxy DNS listener did not start.');
            }
        }
        if ($matcherConfig['listeners'] === []) {
            self::stopMatcher();
        }
    }

    private static function verifiedDnsProfiles(array $profiles, array $loaded): array
    {
        foreach ($profiles as $id => &$profile) {
            if (!empty($profile['disabled'])) {
                $profile['dns'] = [];
                unset($profile['proxyDns']);
                continue;
            }
            if (($profile['kind'] ?? '') === 'proxy') {
                continue;
            }
            $source = explode('/', $profile['address'] ?? '', 2)[0];
            $interface = $profile['interface'] ?? '';
            $ports = isset($profile['peerKey']) ? self::dnsSourcePorts($profile) : null;
            $profile['dns'] = array_values(array_filter(SmartRouting::profileDns($profile),
                static function (string $server) use ($id, $loaded, $source, $interface, $ports): bool {
                    $marker = Policy::marker('dns_out', $id . $server);
                    $route = $loaded[$marker] ?? [];
                    $guard = $loaded[$marker . '_block'] ?? [];
                    return $source !== '' && $interface !== '' &&
                        ($route['action'] ?? '') === 'pass' && ($route['gateway'] ?? '') === $interface &&
                        ($route['source'] ?? '') === $source &&
                        ($guard['action'] ?? '') === 'block' && ($guard['source'] ?? '') === $source &&
                        ($ports === null ||
                            (($route['sourcePortStart'] ?? null) === $ports[0] &&
                            ($route['sourcePortEnd'] ?? null) === $ports[1] &&
                            ($guard['sourcePortStart'] ?? null) === $ports[0] &&
                            ($guard['sourcePortEnd'] ?? null) === $ports[1]));
                }));
        }
        unset($profile);
        return $profiles;
    }

    public static function usesWanFallback(array $settings): bool
    {
        return $settings['coverage'] === 'network' && Policy::usesBase($settings['networkMode']) &&
            !$settings['networkKillSwitch'] && $settings['interfaces'] !== [];
    }

    private static function scopedListenerPlan(
        array $settings,
        string $hostname,
        string $host,
        array $assignments,
        array $profiles,
        array $services,
        array $wanUpstreams,
        array $loaded,
        array $health
    ): array {
        $baseDns = [];
        foreach ($profiles as $id => $profile) {
            $observation = $health[$id] ?? [];
            if (($observation['reachable'] ?? true) ||
                (($profile['kind'] ?? '') === 'native' && isset($observation['source']) &&
                    $observation['source'] !== ($profile['address'] ?? ''))) {
                $baseDns[$id] = $profile;
            }
        }
        $wanted = [];
        $matchers = [];
        foreach (Policy::scopes($settings) as $scope) {
            $devices = $scope['coverage'] === 'device' ? Policy::scopedAssignments($scope, $assignments) : [];
            $scopePlan = self::listenerPlan($scope, $hostname, $host, $devices, $profiles, $services, $wanUpstreams,
                self::usesWanFallback($scope), Policy::networkBypassAssignments($scope, $assignments) !== [],
                $loaded, $baseDns, $matchers);
            $wanted += $scopePlan['listeners'];
            $matchers += $scopePlan['matcher'];
        }
        return ['listeners' => $wanted, 'matcher' => array_values($matchers)];
    }

    private static function listenerPlan(
        array $settings,
        string $hostname,
        string $host,
        array $assignments,
        array $profiles,
        array $services,
        array $wanUpstreams,
        bool $fallback,
        bool $deviceBypass,
        array $loaded,
        ?array $baseDns = null,
        array &$matchers = []
    ): array {
        $protectedNetwork = $settings['coverage'] === 'network' && !empty($settings['networkKillSwitch']);
        $routed = SmartRouting::forwardServices($settings, $services);
        $bypass = SmartRouting::bypassServices($settings, $services);
        $tailscale = ($settings['scope'] ?? '') === 'tailscale';
        $portFor = static fn (int $port): int => self::scopedPort($port, $tailscale);
        $publicLists = $routed + $bypass;
        $bypassDirectives = SmartRouting::dnsDirectives($bypass, $profiles, $wanUpstreams);
        $directives = SmartRouting::dnsDirectives($publicLists, $profiles, $wanUpstreams, $portFor(self::SERVICE_PORT));
        $localPort = $portFor(self::LOCAL_PORT);
        $protectedMultiPort = $portFor(self::PROTECTED_MULTI_PORT);
        $servicePort = $portFor(self::SERVICE_PORT);
        $wanted = [$localPort => self::configuration($localPort, $hostname, $host, [], true, true)];

        // HTTPS and SVCB address hints do not enter PF's learned-IP tables.
        $available = self::liveDnsServices($settings, $routed, $profiles, $loaded);
        $matcherRules = self::specialRouteRules($publicLists, $profiles, $available, $portFor, $wanUpstreams, $hostname, $host, $wanted);
        $forward = SmartRouting::dnsDirectives($publicLists, $profiles, forwardOnly: true, availableServices: $available);
        if ($forward !== [] && !$protectedNetwork) {
            $wanted[$servicePort] = self::configuration($servicePort, $hostname, $host,
                ['filter-rr=64,65', ...$forward], true, true);
        }
        $protectedMulti = $protectedNetwork && Policy::usesMultiPath($settings['networkMode']);
        foreach ($assignments as $row) {
            if (Policy::usesMultiPath(Policy::mode($row)) && Policy::killSwitch($row)) {
                $protectedMulti = true;
                break;
            }
        }
        $protectedDirectives = [];
        if ($protectedMulti) {
            $protectedDirectives = SmartRouting::dnsDirectives($routed, $profiles,
                forwardPort: $protectedMultiPort, availableServices: $available);
            $protectedForward = SmartRouting::dnsDirectives($routed, $profiles, forwardOnly: true,
                availableServices: $available);
            $wanted[$protectedMultiPort] = self::configuration($protectedMultiPort, $hostname, $host,
                ['filter-rr=64,65', ...$protectedForward], true, true);
        }
        if ($deviceBypass) {
            $directUpstreams = array_map(static fn (string $server): string => 'server=' . $server, $wanUpstreams);
            $wanted[self::DEVICE_BYPASS_PORT] = self::configuration(self::DEVICE_BYPASS_PORT, $hostname, $host,
                $directUpstreams, true, true);
        }
        foreach (self::defaultDnsProfiles($settings, $assignments) as [$id, $protected]) {
            $profile = $profiles[$id] ?? [];
            $port = $protected ? self::protectedPort($profile) : self::profilePort($profile, 0);
            if ($port === 0) {
                continue;
            }
            $upstreams = self::profileUpstreams($profile);
            $extra = $protected ? [] : $bypassDirectives;
            $port = $portFor($port);
            $wanted[$port] = self::configuration($port, $hostname, $host,
                [...$upstreams, ...$extra], $extra !== [], true, $protected);
        }
        if (($directives !== [] || $matcherRules !== []) && self::usesSharedDns($settings, $assignments)) {
            $port = $portFor(SmartRouting::PORT);
            $config = self::configuration($port, $hostname, $host,
                ['server=127.0.0.1#53', ...$directives], true);
            $wanted[$port] = $matcherRules === [] ? $config
                : self::withMatcher($config, $port, 53, $matcherRules, $matchers);
        }
        foreach (array_keys(Policy::combinedProfiles($settings, $assignments)) as $id) {
            $profile = $profiles[$id] ?? [];
            // Per-device combined coverage always uses the Kill Switch.
            $protected = $settings['coverage'] === 'device' || $protectedNetwork;
            $port = $protected ? self::protectedCombinedPort($profile) : self::combinedPort($profile);
            if ($port !== 0) {
                $port = $portFor($port);
                $baseProfile = ($baseDns ?? $profiles)[$id] ?? [];
                $baseDnsPort = $portFor((int)($baseProfile['dnsPort'] ?? 0));
                if ($matcherRules !== [] && $baseDnsPort > 0) {
                    $wanted[$baseDnsPort] = self::configuration($baseDnsPort, $hostname, $host,
                        self::profileUpstreams($baseProfile), true, true, $protected);
                }
                $config = self::configuration($port, $hostname, $host,
                    [...self::profileUpstreams($baseProfile), ...($protected ? $protectedDirectives : $directives)], true, true);
                $wanted[$port] = $matcherRules === [] || $baseDnsPort === 0 ? $config
                    : self::withMatcher($config, $port, $baseDnsPort, $matcherRules, $matchers);
            }
        }
        if ($fallback) {
            $upstreams = array_map(static fn (string $server): string => 'server=' . $server, $wanUpstreams);
            $combined = $settings['networkMode'] === 'full_multi';
            $port = $portFor($combined ? self::COMBINED_FALLBACK_PORT : self::FALLBACK_PORT);
            $config = self::configuration($port, $hostname, $host,
                [...$upstreams, ...($combined ? $directives : $bypassDirectives)], true, true);
            if ($matcherRules !== [] && $combined && $wanUpstreams !== []) {
                $bypassPort = $portFor(self::BYPASS_PORT);
                $wanted[$bypassPort] = self::configuration($bypassPort, $hostname, $host, $upstreams, true, true);
                $wanted[$port] = self::withMatcher($config, $port, $bypassPort, $matcherRules, $matchers);
            } else {
                $wanted[$port] = $config;
            }
        }
        return ['listeners' => $wanted, 'matcher' => $matchers];
    }

    private static function specialRouteRules(
        array $services,
        array $profiles,
        array $available,
        callable $portFor,
        array $wanUpstreams,
        string $hostname,
        string $host,
        array &$wanted
    ): array {
        $rules = [];
        foreach ($services as $service) {
            if (($service['id'] ?? '') !== ChinaRules::ID || empty($service['managed']) ||
                ($service['profile'] ?? '') === '') {
                continue;
            }
            $special = ChinaRules::specialRules();
            if ($special === []) {
                continue;
            }
            if ($service['profile'] === SmartRouting::BYPASS) {
                if ($wanUpstreams === []) {
                    $upstreamPort = null;
                } else {
                    $upstreamPort = $portFor(self::BYPASS_PORT);
                    $direct = array_map(static fn (string $server): string => 'server=' . $server, $wanUpstreams);
                    $wanted[$upstreamPort] = self::configuration($upstreamPort, $hostname, $host, $direct, true, true);
                }
                $table = SmartRouting::bypassTable([$service]);
            } else {
                $profile = $profiles[$service['profile']] ?? [];
                $dnsPort = (int)($profile['dnsPort'] ?? 0);
                $upstreams = self::profileUpstreams($profile);
                if ($dnsPort < 1 || $upstreams === [] || empty($available[$service['id']])) {
                    $upstreamPort = null;
                } else {
                    $upstreamPort = $portFor($dnsPort);
                    $wanted[$upstreamPort] ??= self::configuration($upstreamPort, $hostname, $host,
                        $upstreams, true, true);
                }
                $table = SmartRouting::table($service);
            }
            foreach ($special as $rule) {
                $rules[] = [
                    'type' => $rule['type'], 'pattern' => $rule['pattern'],
                    'upstreamPort' => $upstreamPort, 'table' => $table,
                ];
            }
        }
        return $rules;
    }

    private static function withMatcher(
        string $config,
        int $dnsPort,
        int $defaultPort,
        array $rules,
        array &$matchers
    ): string {
        if (isset($matchers[$dnsPort])) {
            return $config . 'server=/#/127.0.0.1#' . $matchers[$dnsPort]['port'] . "\n";
        }
        $index = count($matchers);
        if ($index >= self::MATCHER_PORT_LIMIT) {
            throw new \RuntimeException('The active DNS matching rules need more local matcher listeners than Blank can safely start.');
        }
        $matcherPort = self::MATCHER_PORT_START + $index;
        $matchers[$dnsPort] = [
            'port' => $matcherPort, 'defaultPort' => $defaultPort, 'rules' => array_values($rules),
        ];
        $rows = array_values(array_filter(explode("\n", rtrim($config, "\n")),
            static fn (string $line): bool => !str_starts_with($line, 'server=') || str_starts_with($line, 'server=/')));
        $rows[] = 'server=/#/127.0.0.1#' . $matcherPort;
        return implode("\n", $rows) . "\n";
    }

    private static function reconcileMatcher(array $config): void
    {
        $path = Policy::STATE_DIR . '/' . self::MATCHER_CONFIG;
        $pidPath = Policy::STATE_DIR . '/' . self::MATCHER_PID;
        $serialized = json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $pid = self::matcherPid();
        if ($pid !== null && is_file($path) && hash_equals(hash('sha256', $serialized), hash_file('sha256', $path) ?: '')) {
            return;
        }
        if ($pid !== null) {
            self::stopMatcher();
        } elseif (is_file($pidPath) && !is_link($pidPath)) {
            @unlink($pidPath);
        }
        Policy::writeState(self::MATCHER_CONFIG, $serialized);
        self::command([
            '/usr/sbin/daemon', '-f', '-p', $pidPath, '--', '/usr/local/bin/python3.13',
            self::MATCHER_SCRIPT, '--config', $path,
        ]);
        foreach ($config['listeners'] as $listener) {
            $ready = false;
            for ($attempt = 0; $attempt < 20; $attempt++) {
                $socket = @stream_socket_client('tcp://127.0.0.1:' . (int)$listener['port'], $errno, $error, 0.1);
                if (is_resource($socket)) {
                    fclose($socket);
                    $ready = true;
                    break;
                }
                usleep(50_000);
            }
            if (!$ready) {
                self::stopMatcher();
                throw new \RuntimeException('The Blank DNS matcher did not start its local listener.');
            }
        }
    }

    private static function matcherPid(): ?int
    {
        $path = Policy::STATE_DIR . '/' . self::MATCHER_PID;
        $value = is_file($path) ? trim((string)file_get_contents($path, false, null, 0, 32)) : '';
        if (!ctype_digit($value) || (int)$value < 2) {
            return null;
        }
        $command = trim(self::command(['/bin/ps', '-ww', '-p', $value, '-o', 'command='], false));
        return str_contains($command, self::MATCHER_SCRIPT) && str_contains($command, self::MATCHER_CONFIG)
            ? (int)$value : null;
    }

    private static function stopMatcher(): void
    {
        $pid = self::matcherPid();
        if ($pid !== null) {
            self::command(['/bin/kill', '-TERM', (string)$pid], false);
            for ($attempt = 0; $attempt < 20; $attempt++) {
                if (self::matcherPid() === null) {
                    break;
                }
                usleep(50_000);
            }
        }
        foreach ([self::MATCHER_PID, self::MATCHER_CONFIG] as $file) {
            $path = Policy::STATE_DIR . '/' . $file;
            if (is_file($path) && !is_link($path)) {
                @unlink($path);
            }
        }
    }

    private static function liveDnsServices(array $settings, array $services, array $profiles, array $loaded): array
    {
        $available = [];
        foreach ($services as $service) {
            $profile = $profiles[$service['profile']] ?? [];
            if (!SmartRouting::hasDomains($service['domains']) || self::profileUpstreams($profile) === []) {
                continue;
            }
            $table = SmartRouting::table($service);
            $marker = SmartRouting::addressEntries($service['domains']) === [] ? 'service' : 'service_dns';
            foreach ($settings['smartInterfaces'] as $interface) {
                $id = $service['id'] . ':' . $interface;
                $tag = Policy::marker('smart', $interface);
                $scope = $loaded[Policy::marker('combined_scope', $interface)] ??
                    $loaded[Policy::marker('smart_scope', $interface)] ?? [];
                $route = $loaded[Policy::marker($marker, $id)] ?? [];
                $guard = $loaded[Policy::marker($marker . '_guard', $id)] ?? [];
                if (($scope['tag'] ?? '') === $tag &&
                    ($route['action'] ?? '') === 'pass' && ($route['table'] ?? '') === $table &&
                    ($route['tagged'] ?? '') === $tag &&
                    ($route['gateway'] ?? '') === ($profile['interface'] ?? '') &&
                    ($guard['action'] ?? '') === 'block' && ($guard['table'] ?? '') === $table &&
                    ($guard['tagged'] ?? '') === $tag) {
                    $available[$service['id']] = true;
                    break;
                }
            }
        }
        return $available;
    }

    private static function profileUpstreams(array $profile): array
    {
        if (($profile['kind'] ?? '') === 'proxy') {
            return isset($profile['proxyDns']) ? ['server=127.0.0.1#' . $profile['proxyDns']] : [];
        }
        $source = explode('/', $profile['address'] ?? '', 2)[0];
        if (!in_array((int)($profile['dnsPort'] ?? 0), self::vpnPorts(), true) ||
            !filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return [];
        }
        return array_map(static fn (string $ip): string => "server={$ip}@{$source}", $profile['dns'] ?? []);
    }

    private static function defaultDnsProfiles(array $settings, array $assignments): array
    {
        if ($settings['coverage'] === 'network') {
            return $settings['networkMode'] === 'full'
                ? [[$settings['networkProfile'], !empty($settings['networkKillSwitch'])]] : [];
        }
        $profiles = [];
        foreach ($assignments as $row) {
            if (Policy::mode($row) !== 'full' || !in_array($row['interface'], $settings['interfaces'], true)) {
                continue;
            }
            $protected = Policy::killSwitch($row);
            $profiles[$row['profile'] . ':' . (int)$protected] = [$row['profile'], $protected];
            if ($row['failure'] === 'backup') {
                $profiles[$row['backup'] . ':' . (int)$protected] = [$row['backup'], $protected];
            }
        }
        return $profiles;
    }

    private static function usesSharedDns(array $settings, array $assignments): bool
    {
        if ($settings['coverage'] === 'network') {
            return $settings['networkMode'] === 'multi' && empty($settings['networkKillSwitch']);
        }
        if (empty($settings['smartAssignedOnly']) &&
            array_diff($settings['smartInterfaces'], $settings['deviceMultiInterfaces'], $settings['strictInterfaces']) !== []) {
            return true;
        }
        foreach ($assignments as $row) {
            if (Policy::mode($row) === 'multi' && !Policy::killSwitch($row) &&
                in_array($row['interface'], $settings['smartInterfaces'], true) &&
                !in_array($row['interface'], $settings['strictInterfaces'], true)) {
                return true;
            }
        }
        return false;
    }

    private static function listenerPorts(array $wanted): array
    {
        $ports = $wanted;
        foreach (glob(Policy::STATE_DIR . '/dns-*.{conf,pid}', GLOB_BRACE | GLOB_NOSORT) ?: [] as $file) {
            if (preg_match('/^dns-([0-9]{1,5})\.(?:conf|pid)$/D', basename($file), $match) &&
                self::allowedPort((int)$match[1])) {
                $ports[(int)$match[1]] ??= '';
            }
        }
        return array_keys($ports);
    }

    public static function testAddresses(int $port, string $name): array
    {
        if (!self::allowedPort($port) || SmartRouting::domains($name) !== [$name]) {
            throw new \InvalidArgumentException('Choose a valid Multi-Path DNS test.');
        }
        $drill = is_executable('/usr/bin/drill') ? '/usr/bin/drill' : '/usr/local/bin/drill';
        if (!is_executable($drill)) {
            throw new \RuntimeException('The router does not have the DNS diagnostic command.');
        }
        $reply = self::command(['/bin/timeout', '5', $drill, '-p', (string)$port, $name, '@127.0.0.1', 'A'], false);
        return self::answerAddresses($reply);
    }

    public static function answerAddresses(string $reply): array
    {
        if (!preg_match('/^;; ANSWER SECTION:\R(.*?)(?:^;;|\z)/ms', $reply, $section)) {
            return [];
        }
        preg_match_all('/^[^\s]+\s+\d+\s+IN\s+A\s+([0-9.]+)\s*$/m', $section[1], $matches);
        return array_values(array_unique(array_filter($matches[1], static fn (string $address): bool =>
            filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false)));
    }

    public static function dashboardAddresses(): array
    {
        $config = Config::getInstance()->object();
        $lan = (string)$config->interfaces->lan->ipaddr;
        $tailnet = '';
        foreach (net_get_interfaces() ?: [] as $name => $interface) {
            if (!preg_match('/^tailscale[0-9]+$/D', $name) || empty($interface['up'])) {
                continue;
            }
            foreach ($interface['unicast'] ?? [] as $entry) {
                $address = $entry['address'] ?? '';
                if (is_string($address) && Policy::tailnetAddress($address)) {
                    $tailnet = $address;
                    break 2;
                }
            }
        }
        return ['lan' => filter_var($lan, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ?: '', 'tailnet' => $tailnet];
    }

    public static function magicDnsName(): string
    {
        if (!is_executable('/usr/local/bin/tailscale')) {
            return '';
        }
        $output = self::command(['/usr/bin/timeout', '2', '/usr/local/bin/tailscale', 'status', '--json', '--peers=false'], false);
        $status = json_decode($output, true);
        return is_array($status) ? self::magicDnsFromStatus($status) : '';
    }

    public static function magicDnsFromStatus(array $status): string
    {
        if (($status['BackendState'] ?? '') !== 'Running' || ($status['CurrentTailnet']['MagicDNSEnabled'] ?? false) !== true) {
            return '';
        }
        $name = strtolower(rtrim((string)($status['Self']['DNSName'] ?? ''), '.'));
        return preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}ts\.net$/D', $name) &&
            strlen($name) <= 253 ? $name : '';
    }

    public static function allowDashboardHostname(\SimpleXMLElement $config, string $hostname): bool
    {
        if ($hostname === '') {
            return false;
        }
        $webgui = $config->system->webgui;
        $current = trim((string)$webgui->althostnames);
        $names = preg_split('/\s+/', strtolower($current), -1, PREG_SPLIT_NO_EMPTY);
        if (in_array(strtolower($hostname), $names, true)) {
            return false;
        }
        $webgui->althostnames = trim($current . ' ' . $hostname);
        return true;
    }

    public static function validHostname(string $host): bool
    {
        return $host === 'blankvpn.local' || (strlen($host) <= 120 && preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+home\.arpa$/D', $host) === 1);
    }

    private static function checkNativeDns(string $hostname): void
    {
        $socket = @stream_socket_client('udp://127.0.0.1:53', $errno, $error, 1);
        if ($socket === false) {
            throw new \RuntimeException('Multi-Path needs a working native DNS resolver on 127.0.0.1 port 53.');
        }
        try {
            stream_set_timeout($socket, 2);
            $id = random_bytes(2);
            $question = '';
            foreach (explode('.', $hostname) as $part) {
                $question .= chr(strlen($part)) . $part;
            }
            $query = $id . pack('n5', 0x0100, 1, 0, 0, 0) . $question . "\0" . pack('n2', 1, 1);
            $response = @fwrite($socket, $query) === strlen($query) ? @fread($socket, 512) : false;
            if (!is_string($response) || strlen($response) < 12 || substr($response, 0, 2) !== $id ||
                !(ord($response[2]) & 0x80) || !in_array(ord($response[3]) & 0x0f, [0, 3], true)) {
                throw new \RuntimeException('The native DNS resolver on 127.0.0.1 did not answer the Multi-Path readiness check.');
            }
        } finally {
            fclose($socket);
        }
    }

    private static function configuration(
        int $port,
        string $hostname,
        string $host,
        array $upstreams,
        bool $smart = false,
        bool $vpnOnly = false,
        bool $ipv6 = false
    ): string {
        $rows = [
            'port=' . $port, $smart || $ipv6 ? 'listen-address=127.0.0.1,::1' : 'listen-address=127.0.0.1', 'bind-interfaces',
            'no-resolv', 'no-hosts', 'no-poll', 'dns-forward-max=64', 'log-async=16',
            $smart ? 'cache-size=0' : 'cache-size=256',
            'pid-file=' . Policy::STATE_DIR . "/dns-{$port}.pid",
        ];
        $sourcePorts = self::listenerSourcePorts($port);
        if ($sourcePorts !== null && array_filter($upstreams,
            static fn (string $upstream): bool => str_starts_with($upstream, 'server=') &&
                str_contains($upstream, '@')) !== []) {
            $rows[] = 'min-port=' . $sourcePorts[0];
            $rows[] = 'max-port=' . $sourcePorts[1];
        }
        $rows[] = 'local=/' . $hostname . '/';
        if ($host !== '') {
            $rows[] = 'host-record=' . $hostname . ',' . $host;
        }
        if ($smart) {
            // Relearn destinations on every upstream answer and bound ordinary client DNS caching.
            $rows[] = 'max-ttl=60';
        }
        if (!$smart || $vpnOnly) {
            $rows[] = 'local=/home.arpa/';
        }
        return implode("\n", [...$rows, ...$upstreams]) . "\n";
    }

    private static function running(int $port): ?int
    {
        $path = Policy::STATE_DIR . "/dns-{$port}.pid";
        $value = is_file($path) ? trim((string)file_get_contents($path)) : '';
        if (!ctype_digit($value) || (int)$value < 2) {
            return null;
        }
        $process = self::command(['/bin/ps', '-ww', '-p', $value, '-o', 'command='], false);
        $expected = '/usr/local/sbin/dnsmasq --conf-file=' . Policy::STATE_DIR . "/dns-{$port}.conf";
        return trim($process) === $expected ? (int)$value : null;
    }

    private static function stop(int $pid, int $port): void
    {
        self::command(['/bin/kill', '-TERM', (string)$pid]);
        for ($attempt = 0; $attempt < 20; $attempt++) {
            if (self::running($port) === null) {
                return;
            }
            usleep(50_000);
        }
        throw new \RuntimeException('A Blank VPN & Proxy DNS listener could not be stopped.');
    }

    public static function command(array $command, bool $required = true, array $successStatuses = [0]): string
    {
        $process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($process)) {
            if ($required) {
                throw new \RuntimeException('A required OPNsense command could not start.');
            }
            return '';
        }
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $status = proc_close($process);
        if ($required && !in_array($status, $successStatuses, true)) {
            throw new \RuntimeException('A required OPNsense command failed.');
        }
        return (string)$output;
    }
}
