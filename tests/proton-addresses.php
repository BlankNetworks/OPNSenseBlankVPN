<?php

declare(strict_types=1);

namespace OPNsense\Wireguard {
    final class Server
    {
        public object $servers;
        public function __construct()
        {
            $this->servers = (object)['server' => new class {
                public function iterateItems(): iterable
                {
                    foreach (['previous' => ['10.6.0.2/32'], 'disabled' => ['10.3.0.9/24', 'fd00:01::2/64'],
                        'host' => ['10.2.0.2']] as $uuid => $addresses) {
                        yield $uuid => (object)['enabled' => $uuid !== 'disabled', 'tunneladdress' => new class ($addresses) {
                            public function __construct(private array $addresses) {}
                            public function getValues(): array { return $this->addresses; }
                        }];
                    }
                }
            }];
        }
    }
}

namespace {
    use OPNsense\BlankVpn\{Policy, ProtonTunnels, WireGuard};

    $library = __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/';
    require $library . 'Policy.php';
    require $library . 'ProtonTunnels.php';
    require $library . 'WireGuard.php';

    function check(bool $ok, string $message): void
    {
        if (!$ok) { throw new RuntimeException($message); }
    }

    function shouldReject(callable $operation, string $message): void
    {
        try { $operation(); } catch (DomainException $error) {
            check(str_contains($error->getMessage(), $message), $error->getMessage());
            return;
        }
        throw new RuntimeException('Expected error mentioning ' . $message);
    }

    $networks = WireGuard::tunnelNetworks('previous');
    check($networks === ['10.3.0.0/24', 'fd00:1::/64', '10.2.0.2/32'],
        'Native reservations include disabled or unmanaged instances and omit only the updated instance.');
    $input = ['address' => '10.2.0.2/32', 'address6' => 'fd00:7::2/128', 'dns' => ['1.1.1.1', '10.2.0.1', 'fd00:7::1'],
        'privateKey' => 'example', 'protonOriginalPeer' => ['name' => 'original']];
    check(ProtonTunnels::allocate($input, [], []) === $input, 'A free default address and its DNS are preserved.');
    $result = ProtonTunnels::allocate($input, $networks, ['10.4.0.1/32']);
    check($result === array_replace($input, ['address' => '10.5.0.2/32', 'dns' => ['1.1.1.1', '10.5.0.1', 'fd00:7::1']]),
        'Skip occupied native host addresses, routed subnets, and conflicting Proton DNS addresses.');
    $result = ProtonTunnels::allocate($input, [], ['10.2.0.0/16'], true);
    check($result['address'] === '10.3.0.2/32' && $result['dns'] === $input['dns'],
        'Do not rewrite even a default-looking DNS address when supplied as a manual override.');
    $result = ProtonTunnels::allocate($input, $networks, [], false, false, '10.6.0.2/32');
    check($result['address'] === '10.6.0.2/32' && $result['dns'][1] === '10.6.0.1',
        'Renewal preserves the previously allocated and still available Proton address.');
    $custom = array_replace($input, ['address' => '10.21.0.2/32', 'dns' => ['10.21.0.1']]);
    check(ProtonTunnels::allocate($custom, [], []) === $custom, 'A custom tunnel address and resolver stay intact.');
    check(ProtonTunnels::allocate($custom, [], [], false, false, $custom['address']) === $custom,
        'A replacement using the same custom address and resolver keeps both.');
    shouldReject(fn () => ProtonTunnels::allocate($custom, [], [], false, false, '10.6.0.2/32'), 'different tunnel IPv4');
    shouldReject(fn () => ProtonTunnels::allocate($input, ['10.6.0.2/32'], [], false, false, '10.6.0.2/32'), 'conflicts');
    shouldReject(fn () => ProtonTunnels::allocate($input, [], [], false, false, '192.168.2.9/32'), 'custom IPv4 address');
    shouldReject(fn () => ProtonTunnels::allocate($custom, [], ['10.21.0.0/16']), 'IPv4 address');
    shouldReject(fn () => ProtonTunnels::allocate($input, [], ['10.0.0.0/8']), 'No unused');
    shouldReject(fn () => ProtonTunnels::allocate($input, ['fd00:7::/48'], []), 'IPv6 address');
    $result = ProtonTunnels::allocate($input, ['fd00:7::/48'], [], false, true);
    check($result === array_replace($input, ['address6' => '', 'dns' => ['1.1.1.1', '10.2.0.1']]),
        'Only an explicit IPv4-only choice drops IPv6 and IPv6 DNS.');
    shouldReject(fn () => ProtonTunnels::allocate(array_replace($input, ['dns' => ['fd00:7::1']]), [], [], false, true), 'IPv4 DNS');
    echo "Proton tunnel address and DNS fixtures passed.\n";
}
