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

$catalog = ProxyCores::parseCatalog((string)file_get_contents(__DIR__ . '/../src/share/blankvpn/core-catalog.json'));
assertProxy(str_starts_with(ProxyCores::releaseUrl('mihomo', $catalog['mihomo']), 'https://github.com/MetaCubeX/mihomo/'),
    'Derive downloads from the approved source.');
try {
    ProxyCores::releaseUrl('mihomo', array_replace($catalog['mihomo'], ['asset' => '../../unexpected']));
    throw new RuntimeException('An unexpected asset path was accepted.');
} catch (DomainException) {
}
assertProxy(ProxyCores::uses(['core' => 'xray'], 'mihomo') && !ProxyCores::uses(['core' => 'xray'], 'sing-box'),
    'A core update must only affect the exits that use it.');

$route = ProxyRuntime::route('proxy-exit', 0, proxyNode($ss)['id'], 'test', 'mihomo', 'ss');
$ssConfig = ProxyRuntime::configuration($route, proxyNode($ss));
assertProxy($ssConfig['mihomo']['rules'] === ['MATCH,blankvpn-upstream'], 'Single exit without direct fallback.');
assertProxy($ssConfig['mihomo']['allow-lan'] === false && !$ssConfig['mihomo']['tun']['enable'], 'No core-managed routing or exposed SOCKS port.');
assertProxy($ssConfig['mihomo']['dns']['nameserver'] === ['https://1.1.1.1/dns-query#blankvpn-upstream'], 'Use the same exit for service DNS.');
$xray = ProxyRuntime::configuration($route, proxyNode($vless));
assertProxy($xray['adapter']['inbounds'][0]['listen'] === '127.0.0.1' && $xray['adapter']['outbounds'][0]['protocol'] === 'vless', 'Xray runs behind a private SOCKS listener.');
$singNode = proxyNode('{"outbounds":[{"tag":"example","type":"anytls","server":"192.0.2.2","server_port":443,"password":"fixture-pass","tls":{"enabled":true,"server_name":"example.com"}}]}');
$sing = ProxyRuntime::configuration($route, $singNode);
assertProxy($sing['adapter']['route']['final'] === 'selected', 'sing-box has exactly one selected outbound.');

if (isset($argv[1])) {
    $dir = $argv[1];
    foreach (['ss' => $ssConfig['mihomo'], 'ssr' => ProxyRuntime::configuration($route, proxyNode($legacy))['mihomo'],
        'vmess' => ProxyRuntime::configuration($route, proxyNode($vmess))['mihomo'],
        'ss2022' => ProxyRuntime::configuration($route, proxyNode($ss2022))['mihomo'],
        'adapter-bridge' => $xray['mihomo'], 'xray' => $xray['adapter'], 'sing-box' => $sing['adapter']] as $name => $config) {
        file_put_contents($dir . '/' . $name . '.json', json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
echo "Proxy import, identity, and core configuration fixtures passed.\n";
