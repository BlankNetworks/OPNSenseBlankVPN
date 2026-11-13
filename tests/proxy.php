<?php

declare(strict_types=1);

use OPNsense\BlankVpn\ProxyCatalog;
use OPNsense\BlankVpn\ProxyCores;
use OPNsense\BlankVpn\ProxyImport;
use OPNsense\BlankVpn\ProxyRuntime;

foreach (['Policy', 'ProxyCatalog', 'ProxyCores', 'ProxyImport', 'ProxyRuntime'] as $file) {
    require __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/' . $file . '.php';
}

function assertProxy(bool $valid, string $reason): void
{
    if (!$valid) {
        throw new RuntimeException($reason);
    }
}

function proxyNode(string $body): array
{
    return array_values(ProxyImport::parse($body)['nodes'])[0];
}

function rejectProxy(string $body): void
{
    try {
        ProxyImport::parse($body);
    } catch (DomainException) {
        return;
    }
    throw new RuntimeException('An unsafe or invalid proxy configuration was accepted.');
}

$plainSocks = proxyNode('socks5://192.0.2.8:1080');
assertProxy($plainSocks['id'] === proxyNode('socks5h://192.0.2.8:1080')['id'],
    'Remote DNS SOCKS links must keep the existing node identity.');
$tlsSocks = proxyNode('socks5://test%40account:secret%3Apass@192.0.2.8:443?tls=true&sni=example.com&udp=1');
assertProxy($tlsSocks['config']['username'] === 'test@account' &&
    $tlsSocks['config']['password'] === 'secret:pass' && $tlsSocks['config']['tls'] === true &&
    $tlsSocks['config']['name-cert-verify'] === 'example.com' && $tlsSocks['config']['udp'] === true,
    'SOCKS5 links should preserve decoded credentials and TLS and UDP settings.');
assertProxy($tlsSocks['id'] === ProxyImport::manual('TLS SOCKS', 'socks5', '192.0.2.8', '443',
    'test@account', 'secret:pass', '', 'tls=true&sni=example.com&udp=true')['id'], 'Manual SOCKS5 settings must match link import.');
rejectProxy('socks5://192.0.2.8:1080?sni=example.com');
rejectProxy('socks5://192.0.2.8:1080?tls=invalid');
rejectProxy('socks5://192.0.2.8:1080?skip-cert-verify=true');

$greet = new ReflectionMethod(ProxyRuntime::class, 'socksGreeting');
foreach ([
    ["\x05\x00", '', '', 'without authentication'],
    ["\x05\xff", 'user', 'pass', 'refused'],
    ["\x05\x02\x01\x00", 'user', 'pass', 'accepted the username'],
    ["\x05\x02\x01\x01", 'user', 'pass', 'rejected the username'],
    ['HT', '', '', 'valid SOCKS5 greeting']
] as [$reply, $username, $password, $detail]) {
    [$client, $server] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    fwrite($server, $reply);
    assertProxy(str_contains($greet->invoke(null, $client, $username, $password), $detail),
        'SOCKS5 diagnostics must report the upstream greeting or authentication stage.');
    fclose($client);
    fclose($server);
}

$uuid = 'e823f0a1-0f99-4ed1-aa0d-f5b05ae75e19';
$ss = 'ss://' . rtrim(strtr(base64_encode('aes-256-gcm:fixture-pass'), '+/', '-_'), '=') . '@192.0.2.2:1234#Example';
$legacy = 'ssr://' . rtrim(strtr(base64_encode('192.0.2.3:443:origin:aes-256-cfb:plain:' .
    rtrim(base64_encode('fixture-pass'), '=')), '+/', '-_'), '=');
$vless = "vless://{$uuid}@192.0.2.4:443?type=xhttp&security=tls&sni=example.com&path=%2Fproxy#XHTTP";
$vmess = 'vmess://' . base64_encode(json_encode(['v' => '2', 'add' => '192.0.2.5', 'port' => '443',
    'id' => $uuid, 'aid' => '0', 'net' => 'ws', 'type' => 'none', 'host' => 'example.com', 'path' => '/ws']));
$ss2022 = 'ss://' . rawurlencode('2022-blake3-aes-128-gcm:' . base64_encode(str_repeat('x', 16))) . '@192.0.2.8:443';
$list = base64_encode(implode("\n", [$ss, $legacy, $vless, $vmess, 'https://user:pass@192.0.2.6:8443', 'unknown://host']));
$result = ProxyImport::parse($list);
assertProxy(count($result['nodes']) === 5 && $result['skipped'] === 1, 'Recognize each supported subscription node independently.');
assertProxy(proxyNode($ss)['id'] === proxyNode(str_replace('#Example', '#Changed', $ss))['id'], 'An alias change must preserve node identity.');
assertProxy(proxyNode($ss)['id'] !== proxyNode($ss2022)['id'], 'Different upstream configuration needs a different identity.');
assertProxy(proxyNode($legacy)['legacy'], 'Identify SSR as legacy.');
assertProxy(proxyNode($vless)['core'] === 'xray', 'XHTTP uses Xray.');
assertProxy(proxyNode($vmess)['config']['network'] === 'ws', 'VMess subscription carries WebSocket settings.');
assertProxy(proxyNode($ss2022)['config']['cipher'] === '2022-blake3-aes-128-gcm', 'Preserve Shadowsocks 2022 method.');
assertProxy(proxyNode('hysteria2://fixture-pass@192.0.2.7:443?sni=example.com')['protocol'] === 'hysteria2', 'Hysteria2 link');
assertProxy(proxyNode("tuic://{$uuid}:fixture-pass@192.0.2.9:443?sni=example.com")['protocol'] === 'tuic', 'TUIC link');
rejectProxy("trojan://secret@192.0.2.8:443?allowInsecure=1");
rejectProxy('{"proxies":[{"name":"bad","type":"socks5","server":"192.0.2.2","port":1080,"dialer-proxy":"DIRECT"}]}');
rejectProxy('{"outbounds":[{"type":"ssh","server":"192.0.2.2","server_port":22,"private_key_path":"/etc/key"}]}');
rejectProxy('{"outbounds":[{"type":"ssh","server":"192.0.2.2","server_port":22,"private_key":"../../secret"}]}');
rejectProxy('{"outbounds":[{"protocol":"freedom","settings":{}}]}');

$manual = ProxyImport::manual('Manual', 'hysteria2', '2001:db8::1', '443', '', 'fixture:@ secret', '', 'sni=example.com');
assertProxy($manual['host'] === '2001:db8::1' && $manual['config']['password'] === 'fixture:@ secret',
    'Manual proxy entry preserves IPv6 endpoints and credentials.');
$manualReality = ProxyImport::manual('REALITY', 'vless', '192.0.2.2', '443', $uuid, '', '',
    'security=reality&sni=example.com&pbk=fixture&sid=0123&fp=chrome');
assertProxy($manualReality['config']['reality-opts']['short-id'] === '0123', 'Manual REALITY parameters are preserved.');
assertProxy(ProxyCatalog::subscriptionUsage('Upload=12; download=34; total=100; expire=1798761600') ===
    ['upload' => 12, 'download' => 34, 'total' => 100, 'expire' => 1798761600], 'Read quota and expiry headers.');
assertProxy(ProxyCatalog::subscriptionUsage('upload=1; upload=2; total=9223372036854775808; expire=-1; download=0') ===
    ['download' => 0], 'Ignore duplicate, overflowed and negative metadata.');

$savedNode = proxyNode($ss);
$id = $savedNode['id'];
$catalogData = ['nodes' => [$id => ['name' => 'My server', 'customName' => true, 'sources' => ['manual']] + $savedNode]];
$replaceNodes = new ReflectionMethod(ProxyCatalog::class, 'replaceNodes');
$replaceNodes->invokeArgs(null, [&$catalogData, 'feed', [$id => $savedNode], []]);
assertProxy($catalogData['nodes'][$id]['name'] === 'My server' && $catalogData['nodes'][$id]['config'] === $savedNode['config'] &&
    $catalogData['nodes'][$id]['sources'] === ['manual', 'feed'], 'Subscription refresh must preserve custom names and identity.');
assertProxy(ProxyCatalog::serverName('  My SOCKS5 server  ') === 'My SOCKS5 server', 'Trim a custom server name.');

$subscriptionEndpoint = new ReflectionMethod(ProxyCatalog::class, 'endpoint');
$subscriptionAddresses = new ReflectionMethod(ProxyCatalog::class, 'publicAddresses');
assertProxy($subscriptionEndpoint->invoke(null, 'https://Example.com:8443/feed?token=private') ===
    ['example.com', 8443, 'Example.com'], 'Read a normal HTTPS subscription endpoint.');
assertProxy($subscriptionAddresses->invoke(null, '1.1.1.1') === ['1.1.1.1'] &&
    $subscriptionAddresses->invoke(null, '2606:4700:4700::1111') === ['2606:4700:4700::1111'],
    'Pin public IPv4 and IPv6 addresses.');
foreach (['127.0.0.1', '10.0.0.1', '224.0.0.1', '::ffff:127.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::1', 'ff02::1'] as $address) {
    try {
        $subscriptionAddresses->invoke(null, $address);
        throw new RuntimeException('Subscription fetch accepted a non-public or translated destination.');
    } catch (DomainException) {
    }
}
foreach (['http://example.com/list', 'https://name:secret@example.com/list', 'https://example.com./list'] as $url) {
    try {
        $subscriptionEndpoint->invoke(null, $url);
        throw new RuntimeException('Subscription fetch accepted an invalid redirect target.');
    } catch (DomainException) {
    }
}

$catalog = ProxyCores::parseCatalog((string)file_get_contents(__DIR__ . '/../src/share/blankvpn/core-catalog.json'), 'amd64');
assertProxy(str_starts_with(ProxyCores::releaseUrl('mihomo', $catalog['mihomo'], 'amd64'), 'https://github.com/MetaCubeX/mihomo/'),
    'Derive downloads from the approved source.');
try {
    ProxyCores::releaseUrl('mihomo', array_replace($catalog['mihomo'], ['asset' => '../../unexpected']), 'amd64');
    throw new RuntimeException('An unexpected asset path was accepted.');
} catch (DomainException) {
}
$armCatalog = ProxyCores::parseCatalog((string)file_get_contents(
    __DIR__ . '/../src/share/blankvpn/core-catalog-aarch64.json'
), 'aarch64');
assertProxy(str_ends_with(ProxyCores::releaseUrl('xray', $armCatalog['xray'], 'aarch64'), 'Xray-freebsd-arm64-v8a.zip'),
    'ARM uses the FreeBSD arm64 asset.');
try {
    ProxyCores::releaseUrl('mihomo', $catalog['mihomo'], 'aarch64');
    throw new RuntimeException('An amd64 asset was accepted on aarch64.');
} catch (DomainException) {
}
assertProxy(ProxyCores::uses(['core' => 'xray'], 'mihomo') && !ProxyCores::uses(['core' => 'xray'], 'sing-box'),
    'A core update must only affect the exits that use it.');

$route = ProxyRuntime::route('proxy-exit', 0, proxyNode($ss)['id'], 'test', 'mihomo', 'ss');
$ssConfig = ProxyRuntime::configuration($route, proxyNode($ss));
assertProxy($ssConfig['mihomo']['rules'] === ['MATCH,blankvpn-upstream'], 'Single exit without direct fallback.');
assertProxy($ssConfig['mihomo']['allow-lan'] === false && !$ssConfig['mihomo']['tun']['enable'], 'No core-managed routing or exposed SOCKS port.');
assertProxy($ssConfig['mihomo']['dns']['proxy-server-nameserver'] === ['system'],
    'Resolve upstream hostnames using router DNS without requiring localhost port 53.');
assertProxy($ssConfig['mihomo']['dns']['nameserver'] === ['https://1.1.1.1/dns-query#blankvpn-upstream'], 'Use the same exit for service DNS.');
$xray = ProxyRuntime::configuration($route, proxyNode($vless));
assertProxy($xray['adapter']['inbounds'][0]['listen'] === '127.0.0.1' && $xray['adapter']['outbounds'][0]['protocol'] === 'vless', 'Xray runs behind a private SOCKS listener.');
$reality = proxyNode('vless://' . $uuid .
    '@192.0.2.11:23576?type=tcp&encryption=none&flow=xtls-rprx-vision&sni=example.com&fp=chrome&security=reality&pbk=' .
    rtrim(strtr(base64_encode(str_repeat('k', 32)), '+/', '-_'), '=') . '&sid=01#Fixture');
$realityConfig = ProxyRuntime::configuration($route, $reality)['mihomo'];
assertProxy($realityConfig['proxies'][0]['flow'] === 'xtls-rprx-vision' &&
    $realityConfig['proxies'][0]['reality-opts']['short-id'] === '01' &&
    $realityConfig['proxies'][0]['servername'] === 'example.com', 'Preserve REALITY and XTLS Vision settings.');

$probeFailure = new ReflectionMethod(ProxyRuntime::class, 'probeFailure');
assertProxy(str_contains($probeFailure->invoke(null, CURLE_SSL_CACERT, 0), 'certificate') &&
    str_contains($probeFailure->invoke(null, CURLE_RECV_ERROR, 0), 'ended') &&
    str_contains($probeFailure->invoke(null, CURLE_OK, 403), 'HTTP 403') &&
    str_contains($probeFailure->invoke(null, CURLE_OPERATION_TIMEDOUT, 0, 0.001), 'upstream') &&
    str_contains($probeFailure->invoke(null, CURLE_OPERATION_TIMEDOUT, 0, 0.001, 0.2), 'response timed out'),
    'Report PHP cURL failures without throwing an undefined-constant error.');
$singNode = proxyNode('{"outbounds":[{"tag":"example","type":"anytls","server":"192.0.2.2","server_port":443,"password":"fixture-pass","tls":{"enabled":true,"server_name":"example.com"}}]}');
$sing = ProxyRuntime::configuration($route, $singNode);
assertProxy($sing['adapter']['route']['final'] === 'selected', 'sing-box has exactly one selected outbound.');

if (isset($argv[1])) {
    $dir = $argv[1];
    foreach (['ss' => $ssConfig['mihomo'], 'ssr' => ProxyRuntime::configuration($route, proxyNode($legacy))['mihomo'],
        'vmess' => ProxyRuntime::configuration($route, proxyNode($vmess))['mihomo'],
        'ss2022' => ProxyRuntime::configuration($route, proxyNode($ss2022))['mihomo'], 'reality' => $realityConfig,
        'adapter-bridge' => $xray['mihomo'], 'xray' => $xray['adapter'], 'sing-box' => $sing['adapter']] as $name => $config) {
        file_put_contents($dir . '/' . $name . '.json', json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
echo "Proxy import, identity, and core configuration fixtures passed.\n";
