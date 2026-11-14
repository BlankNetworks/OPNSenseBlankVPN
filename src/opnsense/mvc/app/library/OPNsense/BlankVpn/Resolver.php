<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;

final class Resolver
{
    public const LOCAL_PORT = 46650;
    public const FALLBACK_PORT = 46657;
    public const BYPASS_PORT = 46658;
    private const COMBINED_PORT_OFFSET = 200;

    private static function vpnPorts(): array
    {
        return [...range(self::LOCAL_PORT + 1, self::LOCAL_PORT + 5), ...range(46680, 46706)];
    }

    private static function profilePorts(): array
    {
        return [...self::vpnPorts(),
            ...range(ProxyRuntime::FIRST_DNS_PORT, ProxyRuntime::FIRST_DNS_PORT + ProxyRuntime::SLOTS - 1)];
    }

    public static function combinedPort(array $profile): int
    {
        $base = (int)($profile['dnsPort'] ?? 0);
        return in_array($base, self::profilePorts(), true) ? $base + self::COMBINED_PORT_OFFSET : 0;
    }

    public static function allowedPort(int $port): bool
    {
        $profilePorts = self::profilePorts();
        return in_array($port, [self::LOCAL_PORT, self::FALLBACK_PORT, self::BYPASS_PORT, SmartRouting::PORT], true) ||
            in_array($port, $profilePorts, true) ||
            in_array($port - self::COMBINED_PORT_OFFSET, $profilePorts, true);
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
        $ipsetPorts = [];
        if ($settings['enabled']) {
            $hostname = $settings['hostname'];
            $bind = $hostname === 'blankvpn.local' ? 'lan' : $settings['dashboardBind'];
            $host = self::dashboardAddresses()[$bind];
            if (!self::validHostname($hostname)) {
                throw new \DomainException('Set a valid local dashboard hostname.');
            }
            $profiles = Policy::routes($model);
            $wanted[self::LOCAL_PORT] = self::configuration(self::LOCAL_PORT, $hostname, $host, []);
            $assignments = $settings['coverage'] === 'device' ? Policy::assignments($model, true) : [];
            $services = SmartRouting::activeServices($settings, SmartRouting::services($model));
            $bypass = SmartRouting::bypassServices($settings, $services);
            $fallback = $settings['coverage'] === 'network' && Policy::usesBase($settings['networkMode']) &&
                !$settings['networkKillSwitch'] && $settings['interfaces'] !== [];
            $wan = ($fallback || array_filter($bypass, static fn (array $list) =>
                SmartRouting::hasDomains($list['domains'])) !== []) ? WanEgress::gateways() : [];
            $wanUpstreams = isset($wan['inet'])
                ? WanEgress::dnsUpstreams($wan, Firewall::parseLoadedRules(self::command(['/sbin/pfctl', '-sr'], false)))
                : [];
            $bypassDirectives = SmartRouting::dnsDirectives($bypass, $profiles, $wanUpstreams);
            $directives = SmartRouting::dnsDirectives($services, $profiles, $wanUpstreams);
            if ($bypassDirectives !== [] && Operations::watchMultiPathOutages($settings, $assignments)) {
                $wanted[self::BYPASS_PORT] = self::configuration(self::BYPASS_PORT, $hostname, $host,
                    $bypassDirectives, true, true);
                $ipsetPorts[self::BYPASS_PORT] = true;
            }
            foreach (array_intersect_key($profiles, self::defaultDnsProfiles($settings, $assignments)) as $profile) {
                $port = (int)($profile['dnsPort'] ?? 0);
                $upstreams = self::profileUpstreams($profile);
                if ($upstreams === []) {
                    continue;
                }
                $wanted[$port] = self::configuration($port, $hostname, $host, [...$upstreams, ...$bypassDirectives],
                    $bypassDirectives !== [], true);
                $ipsetPorts[$port] = $bypassDirectives !== [];
            }
            if ($directives !== [] && self::usesSharedDns($settings, $assignments)) {
                $wanted[SmartRouting::PORT] = self::configuration(SmartRouting::PORT, $hostname, $host,
                    ['server=127.0.0.1#53', ...$directives], true);
                $ipsetPorts[SmartRouting::PORT] = true;
            }
            foreach (array_keys(Policy::combinedProfiles($settings, $assignments)) as $id) {
                $profile = $profiles[$id] ?? [];
                $port = self::combinedPort($profile);
                if ($port !== 0) {
                    $wanted[$port] = self::configuration($port, $hostname, $host,
                        [...self::profileUpstreams($profile), ...$directives], true, true);
                    $ipsetPorts[$port] = $directives !== [];
                }
            }
            if ($fallback) {
                $upstreams = array_map(static fn (string $server): string => 'server=' . $server, $wanUpstreams);
                $wanted[self::FALLBACK_PORT] = self::configuration(self::FALLBACK_PORT, $hostname, $host,
                    [...$upstreams, ...$directives], true, true);
                $ipsetPorts[self::FALLBACK_PORT] = $directives !== [];
            }
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
            if (!$ipsetChecked && ($ipsetPorts[$port] ?? false)) {
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
    }

    private static function profileUpstreams(array $profile): array
    {
        if (($profile['kind'] ?? '') === 'proxy') {
            return ['server=127.0.0.1#' . $profile['proxyDns']];
        }
        $source = explode('/', $profile['address'] ?? '', 2)[0];
        if (!in_array((int)($profile['dnsPort'] ?? 0), self::vpnPorts(), true) ||
            !filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return [];
        }
        return array_map(static fn (string $ip): string => "server={$ip}@{$source}", SmartRouting::profileDns($profile));
    }

    private static function defaultDnsProfiles(array $settings, array $assignments): array
    {
        if ($settings['coverage'] === 'network') {
            return Policy::usesBase($settings['networkMode']) ? [$settings['networkProfile'] => true] : [];
        }
        $profiles = [];
        foreach ($assignments as $row) {
            if (Policy::usesBase(Policy::mode($row)) && in_array($row['interface'], $settings['interfaces'], true)) {
                $profiles[$row['profile']] = true;
                if ($row['failure'] === 'backup') {
                    $profiles[$row['backup']] = true;
                }
            }
        }
        return $profiles;
    }

    private static function usesSharedDns(array $settings, array $assignments): bool
    {
        if ($settings['coverage'] === 'network') {
            return $settings['networkMode'] === 'multi';
        }
        if (empty($settings['smartAssignedOnly']) &&
            array_diff($settings['smartInterfaces'], $settings['deviceMultiInterfaces'], $settings['strictInterfaces']) !== []) {
            return true;
        }
        foreach ($assignments as $row) {
            if (Policy::mode($row) === 'multi' && in_array($row['interface'], $settings['smartInterfaces'], true) &&
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
        bool $vpnOnly = false
    ): string {
        $rows = [
            'port=' . $port, $smart ? 'listen-address=127.0.0.1,::1' : 'listen-address=127.0.0.1', 'bind-interfaces',
            'no-resolv', 'no-hosts', 'no-poll', 'dns-forward-max=64',
            $smart ? 'cache-size=0' : 'cache-size=256',
            'pid-file=' . Policy::STATE_DIR . "/dns-{$port}.pid",
        ];
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

    public static function command(array $command, bool $required = true): string
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
        if ($required && $status !== 0) {
            throw new \RuntimeException('A required OPNsense command failed.');
        }
        return (string)$output;
    }
}
