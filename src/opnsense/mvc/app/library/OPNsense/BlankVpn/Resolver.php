<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;

final class Resolver
{
    public const LOCAL_PORT = 46650;

    public static function freePort(array $profiles): int
    {
        $ports = array_column($profiles, 'dnsPort');
        for ($port = self::LOCAL_PORT + 1; $port <= self::LOCAL_PORT + 5; $port++) {
            if (!in_array($port, $ports, true)) {
                return $port;
            }
        }
        throw new \DomainException('All five Blank VPN profile slots are in use.');
    }

    public static function reconcile(BlankVpn $model): void
    {
        $settings = Policy::settings($model);
        $services = SmartRouting::services($model);
        $smart = SmartRouting::active($settings, $services);
        $wanted = [];
        if ($settings['enabled']) {
            $hostname = $settings['hostname'];
            $host = (string)Config::getInstance()->object()->interfaces->lan->ipaddr;
            if (!self::validHostname($hostname) || !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                throw new \DomainException('Set a local dashboard hostname and a static IPv4 address on LAN.');
            }
            $profiles = Policy::profiles($model);
            $wanted[self::LOCAL_PORT] = self::configuration(self::LOCAL_PORT, $hostname, $host, []);
            foreach ($profiles as $profile) {
                $port = (int)($profile['dnsPort'] ?? 0);
                $source = explode('/', $profile['address'] ?? '')[0];
                if ($port <= self::LOCAL_PORT || $port > self::LOCAL_PORT + 5 ||
                    !filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    continue;
                }
                $upstreams = array_map(static fn ($ip) => "server={$ip}@{$source}", SmartRouting::profileDns($profile));
                $wanted[$port] = self::configuration($port, $hostname, $host, $upstreams);
            }
            if ($smart) {
                $upstreams = ['server=127.0.0.1#53', ...SmartRouting::dnsDirectives($services, $profiles)];
                $wanted[SmartRouting::PORT] = self::configuration(SmartRouting::PORT, $hostname, $host, $upstreams, true);
            }
        }

        for ($port = self::LOCAL_PORT; $port <= SmartRouting::PORT; $port++) {
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
                continue;
            }
            if ($port === SmartRouting::PORT) {
                $version = self::command(['/usr/local/sbin/dnsmasq', '--version']);
                if (!preg_match('/(?:^|\s)ipset(?:\s|$)/i', $version)) {
                    throw new \RuntimeException('Smart Routing requires the OPNsense Dnsmasq build with PF ipset support.');
                }
                self::checkNativeDns($hostname);
            }
            Policy::writeState($name, $next);
            self::command(['/usr/local/sbin/dnsmasq', '--test', '--conf-file=' . $config]);
            self::command(['/usr/local/sbin/dnsmasq', '--conf-file=' . $config]);
            if (self::running($port) === null) {
                throw new \RuntimeException('The Blank VPN DNS listener did not start.');
            }
        }
    }

    public static function validHostname(string $host): bool
    {
        return strlen($host) <= 120 && preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+home\.arpa$/D', $host) === 1;
    }

    private static function checkNativeDns(string $hostname): void
    {
        $socket = @stream_socket_client('udp://127.0.0.1:53', $errno, $error, 1);
        if ($socket === false) {
            throw new \RuntimeException('Smart Routing needs a working native DNS resolver on 127.0.0.1 port 53.');
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
                throw new \RuntimeException('The native DNS resolver on 127.0.0.1 did not answer the Smart Routing readiness check.');
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
        bool $smart = false
    ): string {
        $rows = [
            'port=' . $port, $smart ? 'listen-address=127.0.0.1,::1' : 'listen-address=127.0.0.1', 'bind-interfaces',
            'no-resolv', 'no-hosts', 'no-poll', 'dns-forward-max=64',
            $smart ? 'cache-size=0' : 'cache-size=256',
            'pid-file=' . Policy::STATE_DIR . "/dns-{$port}.pid",
            'host-record=' . $hostname . ',' . $host
        ];
        if ($smart) {
            // Relearn destinations on every upstream answer and bound ordinary client DNS caching.
            $rows[] = 'max-ttl=60';
        } else {
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
        throw new \RuntimeException('A Blank VPN DNS listener could not be stopped.');
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
