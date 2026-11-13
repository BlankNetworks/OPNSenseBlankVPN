<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use OPNsense\Base\BaseModel;
use OPNsense\Base\FieldTypes\InterfaceField;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Interfaces\NetworkInterface;
use OPNsense\Routing\Gateways;
use OPNsense\Wireguard\Client;
use OPNsense\Wireguard\General;
use OPNsense\Wireguard\Server;
use RuntimeException;

final class WireGuard
{
    public const PROBE_ADDRESS = '1.1.1.1';
    public const PROBE_PORT = 443;

    private const PROBE_HOST = 'cloudflare-dns.com';
    private const HANDSHAKE_WINDOW = 300;

    /** Stage objects under the caller's configuration lock. The caller commits and applies them. */
    public static function create(string $id, array $identity, array $relay): array
    {
        if (!self::uuid($id)) {
            throw new RuntimeException('The profile identifier is invalid.');
        }

        [$endpoint, $port, $peerKey, $psk] = self::relaySettings($relay);
        self::preflight($endpoint);

        $privateKey = self::key((string)($identity['privateKey'] ?? ''));
        $identityKey = self::key((string)($identity['publicKey'] ?? ''));
        if (
            $identityKey === $peerKey ||
            !hash_equals($identityKey, (new Mullvad())->derivePublicKey($privateKey))
        ) {
            throw new RuntimeException('The WireGuard identity and peer keys are inconsistent.');
        }
        $mtu = self::integer($relay['mtu'] ?? 1420, 1280, 9000, 'MTU');
        $keepalive = self::integer($relay['keepalive'] ?? 25, 0, 65535, 'keepalive');
        $address = self::hostAddress((string)($identity['address'] ?? ''), false);
        $address6 = empty($identity['address6']) ? '' : self::hostAddress((string)$identity['address6'], true);
        $addresses = $address6 === '' ? [$address] : [$address, $address6];
        self::checkUnderlay(explode('/', $address, 2)[0]);
        $previousIpv6 = (new Gateways())->getDefaultGW(null, 'inet6');
        $owner = self::owner($id);
        $nativeServers = new Server();
        $nativeClients = new Client();

        $usedUnits = [];
        foreach ($nativeServers->servers->server->iterateItems() as $current) {
            if ((string)$current->name === $owner) {
                throw new RuntimeException('This Blank VPN profile already owns a WireGuard instance.');
            }
            if ((string)$current->pubkey === $identityKey || (string)$current->privkey === $privateKey) {
                throw new RuntimeException('This WireGuard identity is already used by another instance.');
            }
            $currentAddresses = array_map(
                static fn ($value) => inet_pton(explode('/', $value, 2)[0]),
                $current->tunneladdress->getValues()
            );
            foreach ($addresses as $candidate) {
                if (in_array(inet_pton(explode('/', $candidate, 2)[0]), $currentAddresses, true)) {
                    throw new RuntimeException('A WireGuard tunnel address is already used by another instance.');
                }
            }
            $usedUnits['wg' . $current->instance] = true;
        }

        self::ensureUniquePeer($nativeClients, $owner, $peerKey, $endpoint, $port);

        $config = Config::getInstance()->object();
        if (!isset($config->interfaces)) {
            throw new RuntimeException('OPNsense has no interface configuration.');
        }
        foreach ($config->interfaces->children() as $interface) {
            if (strcasecmp((string)$interface->descr, $owner) === 0) {
                throw new RuntimeException('A native interface already uses this Blank VPN profile name.');
            }
            $usedUnits[(string)$interface->if] = true;
        }

        $runtime = self::runtimeRecords();
        foreach ($runtime as $record) {
            if (($record['type'] ?? '') === 'interface') {
                $usedUnits[$record['if']] = true;
            }
        }

        $peer = $nativeClients->clients->client->add();
        $peerId = (string)$peer->getAttribute('uuid');
        $peer->name = $owner;
        $peer->pubkey = $peerKey;
        $peer->psk = $psk;
        $peer->serveraddress = $endpoint;
        $peer->serverport = (string)$port;
        $peer->tunneladdress = self::allowedAddresses($address6);
        $peer->keepalive = $keepalive === 0 ? '' : (string)$keepalive;
        self::serialize($nativeClients, 'WireGuard peer');

        $instance = $nativeServers->servers->server->add();
        $instanceId = (string)$instance->getAttribute('uuid');
        $unit = 0;
        while (isset($usedUnits['wg' . $unit])) {
            ++$unit;
        }
        $device = 'wg' . $unit;
        $instance->instance = (string)$unit;
        $instance->name = $owner;
        $instance->pubkey = $identityKey;
        $instance->privkey = $privateKey;
        $instance->tunneladdress = implode(',', $addresses);
        $instance->disableroutes = '1';
        $instance->mtu = (string)$mtu;
        // Native relation choices were loaded before the peer was staged. Refresh this
        // new instance's peer choices from the current in-memory config and keep ownership scoped.
        $instance->peers->setDisableCache('Y');
        $instance->peers->setModel(['template' => [
            'source' => 'OPNsense.Wireguard.Client',
            'items' => 'clients.client',
            'display' => 'name',
            'filters' => ['name' => '/^' . $owner . '$/D'],
        ]]);
        $instance->peers->eventPostLoading();
        $instance->peers = $peerId;
        self::serialize($nativeServers, 'WireGuard instance');
        $general = new General();
        if ((string)$general->enabled !== '1') {
            $general->enabled = '1';
            self::serialize($general, 'WireGuard service');
        }

        $logical = self::createInterface($device, $owner);
        $gateway = strtoupper($owner) . '_4';
        $gateway6 = $address6 !== '' ? strtoupper($owner) . '_6' : '';
        $gatewayModel = new Gateways();
        $gatewayId = self::addGateway($gatewayModel, $gateway, $logical, 'inet');
        $gateway6Id = $gateway6 === '' ? '' : self::addGateway($gatewayModel, $gateway6, $logical, 'inet6');
        self::serialize($gatewayModel, 'WireGuard gateways');
        self::validateDefaultGateway($gateway);
        $nextIpv6 = (new Gateways())->getDefaultGW(null, 'inet6');
        if (!empty($previousIpv6['gateway']) && $previousIpv6['name'] !== ($nextIpv6['name'] ?? '')) {
            throw new RuntimeException('The existing IPv6 default gateway must take precedence over Blank VPN gateways.');
        }

        return [
            'instance' => $instanceId,
            'peer' => $peerId,
            'interface' => $device,
            'logicalInterface' => $logical,
            'gateway' => $gateway,
            'gatewayId' => $gatewayId,
            'gateway6' => $gateway6,
            'gateway6Id' => $gateway6Id,
            'owner' => $owner,
            'address' => $address,
            'address6' => $address6,
            'endpoint' => $endpoint,
            'port' => $port,
            'mtu' => $mtu,
            'keepalive' => $keepalive,
            'peerKey' => $peerKey,
            'identityKey' => $identityKey,
            'privateFingerprint' => hash('sha256', $privateKey),
            'pskFingerprint' => $psk === '' ? '' : hash('sha256', $psk),
            'identity' => (string)($identity['id'] ?? substr(hash('sha256', $identityKey), 0, 16)),
        ];
    }

    /** Change a peer in place after the caller verifies no device uses this profile. */
    public static function retarget(array $profile, array $relay): array
    {
        [, $peers] = self::ownedObjects($profile);
        [$endpoint, $port, $peerKey, $psk] = self::relaySettings($relay);
        self::preflight($endpoint);
        if ($peerKey === $profile['identityKey']) {
            throw new RuntimeException('The WireGuard identity and peer keys are inconsistent.');
        }
        self::ensureUniquePeer($peers, $profile['owner'], $peerKey, $endpoint, $port, $profile['peer']);

        $peer = $peers->getNodeByReference('clients.client.' . $profile['peer']);
        $peer->pubkey = $peerKey;
        $peer->psk = $psk;
        $peer->serveraddress = $endpoint;
        $peer->serverport = (string)$port;
        self::serialize($peers, 'WireGuard peer');

        return array_replace($profile, [
            'endpoint' => $endpoint,
            'port' => $port,
            'peerKey' => $peerKey,
            'pskFingerprint' => $psk === '' ? '' : hash('sha256', $psk),
        ]);
    }

    public static function preflight(?string $endpoint = null): void
    {
        if ((string)(new General())->enabled !== '1') {
            foreach ((new Server())->servers->server->iterateItems() as $instance) {
                if ((string)$instance->enabled === '1') {
                    throw new RuntimeException('Review and enable the existing OPNsense WireGuard service before adding a Blank VPN exit.');
                }
            }
        }

        $model = new Gateways();
        $config = Config::getInstance()->object();
        if (
            count(iterator_to_array($model->gateway_item->iterateItems())) === 0 &&
            !empty($config->gateways->gateway_item)
        ) {
            throw new RuntimeException('The router is using legacy gateway entries. Review native gateway migration before adding an exit.');
        }

        self::checkUnderlay($endpoint);
        self::validateDefaultGateway('');
    }

    public static function check(array $profile): array
    {
        try {
            self::ownedObjects($profile);
            if ((string)(new General())->enabled !== '1') {
                throw new RuntimeException('The OPNsense WireGuard service is disabled.');
            }
            self::checkUnderlay((string)$profile['endpoint']);
            return ['ok' => true];
        } catch (RuntimeException $exception) {
            return ['ok' => false, 'error' => $exception->getMessage()];
        }
    }

    /** Stage removal of the owned objects. Native apply then removes the retired runtime instance. */
    public static function remove(array $profile): void
    {
        [$servers, $peers, $gateways] = self::ownedObjects($profile);
        $config = Config::getInstance()->object();
        $logical = $profile['logicalInterface'];
        $gatewayNames = array_filter([$profile['gateway'], $profile['gateway6'] ?? '']);
        foreach ($servers->servers->server->iterateItems() as $uuid => $server) {
            if ($uuid !== $profile['instance'] && in_array($profile['peer'], $server->peers->getValues(), true)) {
                throw new RuntimeException('Another WireGuard instance references this peer. Remove that reference first.');
            }
        }
        foreach ($gateways->gatewayIterator() as $gateway) {
            if ($gateway['interface'] === $logical && !in_array($gateway['name'], $gatewayNames, true)) {
                throw new RuntimeException('Another native gateway uses this interface. Remove that reference first.');
            }
        }
        self::checkRemovalReferences($config, $logical, $gatewayNames);
        if (isset((new NetworkInterface())->get_if_todo()[$logical])) {
            throw new RuntimeException('Apply or discard the pending native interface change before removing this profile.');
        }

        $servers->servers->server->del($profile['instance']);
        self::serialize($servers, 'WireGuard instances');
        $peers->clients->client->del($profile['peer']);
        self::serialize($peers, 'WireGuard peers');
        $gateways->gateway_item->del($profile['gatewayId']);
        if (!empty($profile['gateway6Id'])) {
            $gateways->gateway_item->del($profile['gateway6Id']);
        }
        self::serialize($gateways, 'WireGuard gateways');
        unset($config->interfaces->$logical);
        (new InterfaceField())->resetStaticOptions();
    }

    public static function apply(?array $profile = null): void
    {
        $backend = new Backend();
        if (trim($backend->configdpRun('template reload', ['OPNsense/Wireguard'])) !== 'OK') {
            throw new RuntimeException('OPNsense could not render the native WireGuard configuration.');
        }

        $arguments = [];
        if ($profile !== null) {
            $arguments[] = self::instanceId($profile);
        }
        if (trim($backend->configdpRun('wireguard configure', $arguments)) !== 'OK') {
            throw new RuntimeException('OPNsense could not apply the WireGuard configuration.');
        }
        if ($profile !== null) {
            $status = self::status($profile);
            if (
                !$status['available'] || !$status['peerPresent'] ||
                $status['endpoint'] !== $profile['endpoint'] . ':' . $profile['port']
            ) {
                throw new RuntimeException('The configured WireGuard interface and peer did not appear in the kernel.');
            }
        }
    }

    public static function applyRemoval(array $profile): void
    {
        self::apply();
        foreach (self::runtimeRecords() as $record) {
            if (($record['type'] ?? '') === 'interface' && ($record['if'] ?? '') === $profile['interface']) {
                throw new RuntimeException('The retired WireGuard device is still present in the kernel.');
            }
        }
    }

    public static function status(array $profile, ?array $records = null): array
    {
        $available = false;
        $peerPresent = false;
        $handshake = null;
        $endpoint = null;
        $received = null;
        $sent = null;

        foreach ($records ?? self::runtimeRecords() as $record) {
            if (($record['if'] ?? '') !== ($profile['interface'] ?? '')) {
                continue;
            }
            if (
                ($record['type'] ?? '') === 'interface' &&
                ($record['public-key'] ?? '') === ($profile['identityKey'] ?? '')
            ) {
                $available = ($record['status'] ?? '') === 'up';
            } elseif (
                ($record['type'] ?? '') === 'peer' &&
                ($record['public-key'] ?? '') === ($profile['peerKey'] ?? '')
            ) {
                $peerPresent = true;
                $handshake = (int)($record['latest-handshake'] ?? 0) ?: null;
                $endpoint = $record['endpoint'] ?? null;
                $received = $record['transfer-rx'] ?? null;
                $sent = $record['transfer-tx'] ?? null;
            }
        }

        $status = !$available || !$peerPresent ? 'unavailable' : 'awaiting handshake';
        if ($available && $peerPresent && $handshake !== null) {
            $age = time() - $handshake;
            $status = $age >= 0 && $age <= self::HANDSHAKE_WINDOW ? 'recent handshake' : 'stale handshake';
        }
        return [
            'available' => $available,
            'peerPresent' => $peerPresent,
            'handshake' => $handshake,
            'endpoint' => $endpoint,
            'received' => $received,
            'sent' => $sent,
            'status' => $status,
        ];
    }

    public static function runtimeRecords(): array
    {
        $data = json_decode((new Backend())->configdRun('wireguard show', false, 8), true);
        return is_array($data['records'] ?? null) ? $data['records'] : [];
    }

    public static function pingRelay(string $address): array
    {
        // The API obtains the address from Mullvad’s normalized catalog.
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE)) {
            throw new \DomainException('The relay has no public IPv4 endpoint.');
        }
        if (!is_executable('/sbin/ping')) {
            throw new RuntimeException('The FreeBSD ping utility is unavailable.');
        }
        $output = Resolver::command(['/sbin/ping', '-n', '-c', '1', '-W', '1500', '-t', '3', $address], false);
        $replied = preg_match('/\btime[=<]([0-9]+(?:[.,][0-9]+)?) ms\b/', $output, $matches) === 1;
        if (!$replied && !preg_match('/\b[0-9]+ packets? transmitted\b/', $output)) {
            throw new RuntimeException('OPNsense could not send a ping to the relay. Check the router’s IPv4 WAN route.');
        }
        return ['replied' => $replied, 'milliseconds' => $replied ? (float)str_replace(',', '.', $matches[1]) : null];
    }

    /**
     * Caller verifies the source-bound output route and fallback block in the running filter
     * before requesting this probe. Its result is router tunnel reachability.
     */
    public static function probe(array $profile, bool $routeInstalled = false): array
    {
        if (!$routeInstalled) {
            return ['reachable' => null, 'checkedAt' => null, 'status' => 'unverified',
                'detail' => 'The protected tunnel test route is unavailable.'];
        }
        $status = self::status($profile);
        if (!$status['available'] || !$status['peerPresent']) {
            return ['reachable' => null, 'checkedAt' => null, 'status' => 'unverified',
                'detail' => 'The WireGuard interface or peer is missing from the kernel.'];
        }

        $result = self::probeSource(explode('/', $profile['address'], 2)[0]);
        if ($result['reachable'] === false && (self::status($profile)['handshake'] ?? 0) < time() - self::HANDSHAKE_WINDOW) {
            $result['detail'] = 'The server has no recent WireGuard handshake. Check whether outbound UDP reaches the relay.';
        }
        return $result;
    }

    public static function probeSource(string $address): array
    {
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['reachable' => null, 'checkedAt' => null, 'status' => 'unverified',
                'detail' => 'The tunnel has no usable IPv4 source address.'];
        }
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The OPNsense PHP cURL extension is unavailable.');
        }
        $curl = curl_init('https://' . self::PROBE_HOST . '/dns-query?name=cloudflare.com&type=A');
        if ($curl === false) {
            throw new RuntimeException('OPNsense could not initialize the HTTPS tunnel test.');
        }
        $body = '';
        curl_setopt_array($curl, [
            CURLOPT_INTERFACE => $address,
            CURLOPT_RESOLVE => [self::PROBE_HOST . ':' . self::PROBE_PORT . ':' . self::PROBE_ADDRESS],
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
            CURLOPT_PROXY => '',
            CURLOPT_PROTOCOLS_STR => 'HTTPS',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_WRITEFUNCTION => static function ($handle, $chunk) use (&$body) {
                if (strlen($body) + strlen($chunk) > 8192) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $transport = curl_exec($curl) === true;
        $info = curl_getinfo($curl);
        $answer = json_decode($body, true);
        $reachable = $transport &&
            ($info['http_code'] ?? 0) === 200 &&
            ($info['local_ip'] ?? '') === $address &&
            ($info['primary_ip'] ?? '') === self::PROBE_ADDRESS &&
            ($answer['Status'] ?? null) === 0;
        return ['reachable' => $reachable, 'checkedAt' => time(), 'status' => $reachable ? 'reachable' : 'probe failed',
            'milliseconds' => $reachable ? round($info['total_time'] * 1000, 1) : null,
            'detail' => $reachable ? null : 'The HTTPS probe did not complete through the tunnel.'];
    }

    private static function createInterface(string $device, string $owner): string
    {
        $config = Config::getInstance()->object();
        $interfaces = new NetworkInterface();
        $pending = $interfaces->get_if_todo();
        $number = 1;
        do {
            $logical = 'opt' . $number++;
        } while (isset($config->interfaces->$logical) || isset($pending[$logical]));

        foreach ($pending as $change) {
            if (($change['pending']['if'] ?? '') === $device) {
                throw new RuntimeException('A pending OPNsense interface change uses this WireGuard device.');
            }
        }

        // Use the native model's compatibility mapping without applying unrelated pending GUI edits.
        $entry = $interfaces->interface->add($logical);
        $entry->if = $device;
        $entry->descr = $owner;
        $entry->enable = '1';
        $entry->lock = '1';
        $entry->gateway_interface = '1';

        $new = $config->interfaces->addChild($logical);
        foreach ($entry->toLegacy() as $name => $value) {
            $new->$name = $value;
        }
        (new InterfaceField())->resetStaticOptions();

        return $logical;
    }

    private static function addGateway(Gateways $model, string $name, string $logical, string $family): string
    {
        $gateway = $model->gateway_item->add();
        $gateway->name = $name;
        $gateway->descr = 'Blank VPN ' . $name;
        $gateway->interface = $logical;
        $gateway->ipprotocol = $family;
        $gateway->monitor_disable = '1';
        $gateway->monitor_noroute = '1';
        $gateway->priority = '255';
        return (string)$gateway->getAttribute('uuid');
    }

    private static function ownedObjects(array $profile): array
    {
        $id = (string)($profile['id'] ?? '');
        $owner = (string)($profile['owner'] ?? '');
        $logical = (string)($profile['logicalInterface'] ?? '');
        $device = (string)($profile['interface'] ?? '');
        if (
            ($id !== '' && (!self::uuid($id) || self::owner($id) !== $owner)) ||
            !preg_match('/^bvpn_[a-f0-9]{20}$/D', $owner) ||
            !preg_match('/^opt[1-9][0-9]*$/D', $logical) ||
            !preg_match('/^wg[0-9]+$/D', $device) ||
            !self::uuid((string)($profile['peer'] ?? ''))
        ) {
            throw new RuntimeException('The WireGuard ownership record is invalid.');
        }
        $servers = new Server();
        $peers = new Client();
        $gateways = new Gateways();
        $instance = $servers->getNodeByReference('servers.server.' . self::instanceId($profile));
        $peer = $peers->getNodeByReference('clients.client.' . $profile['peer']);
        $config = Config::getInstance()->object();
        $interface = $config->interfaces->$logical ?? null;
        $expectedAddresses = array_filter([(string)($profile['address'] ?? ''), (string)($profile['address6'] ?? '')]);

        if (
            $instance === null || $peer === null || $interface === null ||
            (string)$instance->name !== $owner || (string)$peer->name !== $owner ||
            'wg' . $instance->instance !== $device || (string)$interface->if !== $device ||
            (string)$interface->descr !== $owner || (string)$interface->enable !== '1' ||
            (string)$interface->gateway_interface !== '1' ||
            !empty((string)$interface->ipaddr) || !empty((string)$interface->ipaddrv6) ||
            (string)$instance->enabled !== '1' || (string)$peer->enabled !== '1' ||
            (string)$instance->disableroutes !== '1' || !$instance->gateway->isEmpty() ||
            !$instance->carp_depend_on->isEmpty() || (int)(string)$instance->mtu !== (int)($profile['mtu'] ?? 1420) ||
            (string)$instance->peers !== $profile['peer'] ||
            (string)$instance->pubkey !== ($profile['identityKey'] ?? '') ||
            hash('sha256', (string)$instance->privkey) !== ($profile['privateFingerprint'] ?? '') ||
            $instance->tunneladdress->getValues() !== array_values($expectedAddresses) ||
            (string)$peer->pubkey !== ($profile['peerKey'] ?? '') ||
            (!$peer->psk->isEmpty() ? hash('sha256', (string)$peer->psk) : '') !== ($profile['pskFingerprint'] ?? '') ||
            (string)$peer->serveraddress !== ($profile['endpoint'] ?? '') ||
            (int)(string)$peer->serverport !== (int)($profile['port'] ?? 0) ||
            (int)(string)$peer->keepalive !== (int)($profile['keepalive'] ?? 25) ||
            (string)$peer->tunneladdress !== self::allowedAddresses((string)($profile['address6'] ?? ''))
        ) {
            throw new RuntimeException('The native WireGuard configuration changed outside Blank VPN. Review its owned objects.');
        }

        foreach (['inet' => '', 'inet6' => '6'] as $family => $suffix) {
            $name = (string)($profile['gateway' . $suffix] ?? '');
            $uuid = (string)($profile['gateway' . $suffix . 'Id'] ?? '');
            if ($suffix === '6' && $name === '' && $uuid === '' && empty($profile['address6'])) {
                continue;
            }
            $gateway = self::uuid($uuid) ? $gateways->getNodeByReference('gateway_item.' . $uuid) : null;
            $expectedName = strtoupper($owner) . ($suffix === '' ? '_4' : '_6');
            if (
                $gateway === null || $name !== $expectedName || (string)$gateway->name !== $name ||
                (string)$gateway->interface !== $logical || (string)$gateway->ipprotocol !== $family ||
                !$gateway->gateway->isEmpty() || !$gateway->disabled->isEmpty() ||
                !$gateway->force_down->isEmpty() || !$gateway->defaultgw->isEmpty() ||
                (string)$gateway->monitor_disable !== '1' || (string)$gateway->priority !== '255'
            ) {
                throw new RuntimeException('The Blank VPN gateway changed outside Blank VPN. Review its native settings.');
            }
        }

        return [$servers, $peers, $gateways];
    }

    private static function checkRemovalReferences(\SimpleXMLElement $config, string $logical, array $gatewayNames): void
    {
        $paths = [
            '/opnsense/filter/rule', '/opnsense/nat/rule', '/opnsense/nat/outbound/rule',
            '/opnsense/staticroutes/route', '/opnsense/ifgroups/ifgroupentry', '/opnsense/bridges/bridged',
            '/opnsense/OPNsense/Firewall/Filter/rules/rule', '/opnsense/OPNsense/Firewall/Filter/snatrules/rule',
            '/opnsense/OPNsense/Firewall/Filter/npt', '/opnsense/OPNsense/Firewall/Filter/onetoone',
            '/opnsense/gateways/gateway_group/item', '/opnsense/gateways/gateway_group/item2',
            '/opnsense/gateways/gateway_group/item3', '/opnsense/gateways/gateway_group/item4',
            '/opnsense/gateways/gateway_group/item5',
        ];
        foreach ($paths as $path) {
            foreach ($config->xpath($path) ?: [] as $node) {
                $interfaces = explode(',', (string)$node->interface . ',' . (string)$node->members . ',' . (string)$node->if);
                $targets = explode(',', (string)$node->gateway . ',' . (string)$node);
                foreach ($targets as &$target) {
                    $target = explode('|', $target, 2)[0];
                }
                unset($target);
                if (in_array($logical, $interfaces, true) || array_intersect($gatewayNames, $targets)) {
                    throw new RuntimeException('A native rule, route, or group still references this Blank VPN gateway or interface.');
                }
            }
        }
    }

    private static function serialize(BaseModel $model, string $name): void
    {
        // Native serializeToConfig can include field values in validation logs. Catch errors first.
        if (count($model->performValidation()) !== 0) {
            throw new RuntimeException("OPNsense rejected the {$name} model. Review conflicts in the native configuration.");
        }
        $model->serializeToConfig();
    }

    private static function relaySettings(array $relay): array
    {
        return [
            self::endpoint((string)($relay['ipv4'] ?? $relay['host'] ?? '')),
            self::integer($relay['port'] ?? 51820, 1, 65535, 'endpoint port'),
            self::key((string)($relay['publicKey'] ?? '')),
            !empty($relay['presharedKey']) ? self::key((string)$relay['presharedKey']) : '',
        ];
    }

    private static function ensureUniquePeer(
        Client $clients,
        string $owner,
        string $peerKey,
        string $endpoint,
        int $port,
        string $skip = ''
    ): void {
        foreach ($clients->clients->client->iterateItems() as $uuid => $current) {
            if ($uuid === $skip) {
                continue;
            }
            if (
                (string)$current->name === $owner ||
                ((string)$current->pubkey === $peerKey && (string)$current->serveraddress === $endpoint &&
                    ((int)(string)$current->serverport ?: 51820) === $port)
            ) {
                throw new RuntimeException('This relay already has a WireGuard peer. Reuse its existing tunnel.');
            }
        }
    }

    private static function integer(mixed $value, int $minimum, int $maximum, string $field): int
    {
        $number = filter_var($value, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => $minimum, 'max_range' => $maximum],
        ]);
        if ($number === false) {
            throw new RuntimeException("The WireGuard {$field} is invalid.");
        }
        return $number;
    }

    private static function endpoint(string $host): string
    {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $host;
        }
        if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || !str_contains($host, '.')) {
            throw new RuntimeException('An IPv4 endpoint or an IPv4-resolvable WireGuard hostname is required.');
        }
        $resolved = gethostbyname($host);
        if (!filter_var($resolved, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new RuntimeException('The WireGuard endpoint has no usable IPv4 address.');
        }
        return $resolved;
    }

    private static function routeInterface(string $destination): string
    {
        if ($destination !== 'default' && !filter_var($destination, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return '';
        }
        $process = proc_open(
            ['/sbin/route', '-n', 'get', '-inet', $destination],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($process)) {
            return '';
        }
        $output = stream_get_contents($pipes[1], 8192);
        fclose($pipes[1]);
        return proc_close($process) === 0 && !preg_match('/^\s*flags:.*(?:BLACKHOLE|REJECT)/m', $output) &&
            preg_match('/^\s*interface:\s*([\w.-]+)\s*$/m', $output, $match)
            ? $match[1]
            : '';
    }

    private static function validateDefaultGateway(string $newGateway): void
    {
        $default = (new Gateways())->getDefaultGW(null, 'inet');
        if (
            empty($default['gateway']) ||
            ($newGateway !== '' && ($default['name'] ?? '') === $newGateway) ||
            self::isTunnel((string)($default['if'] ?? ''))
        ) {
            throw new RuntimeException('A native IPv4 WAN gateway must take precedence over Blank VPN gateways.');
        }
    }

    private static function checkUnderlay(?string $endpoint = null): void
    {
        $default = self::routeInterface('default');
        if ($default === '' || self::isTunnel($default)) {
            throw new RuntimeException('An active non-VPN IPv4 default route is needed for WireGuard transport.');
        }
        if ($endpoint !== null && self::routeInterface($endpoint) !== $default) {
            throw new RuntimeException('The WireGuard endpoint must be reachable over the active underlying WAN route.');
        }
    }

    private static function isTunnel(string $device): bool
    {
        return preg_match('/^(wg|tun|tap|ovpn[cs]?|ipsec|gif|gre|lo)[0-9]/i', $device) === 1;
    }

    private static function key(string $key): string
    {
        $binary = base64_decode($key, true);
        if ($binary === false || strlen($binary) !== 32 || base64_encode($binary) !== $key || $binary === str_repeat("\0", 32)) {
            throw new RuntimeException('A WireGuard key is invalid.');
        }
        return $key;
    }

    private static function hostAddress(string $value, bool $ipv6): string
    {
        [$address, $prefix] = array_pad(explode('/', $value, 2), 2, '');
        $required = $ipv6 ? '128' : '32';
        if (
            !filter_var($address, FILTER_VALIDATE_IP, $ipv6 ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4) ||
            ($prefix !== '' && $prefix !== $required)
        ) {
            throw new RuntimeException("A WireGuard tunnel requires a valid /{$required} host address.");
        }
        return inet_ntop(inet_pton($address)) . '/' . $required;
    }

    private static function allowedAddresses(string $address6): string
    {
        return $address6 === '' ? '0.0.0.0/0' : '0.0.0.0/0,::/0';
    }

    private static function owner(string $id): string
    {
        return 'bvpn_' . substr(hash('sha256', $id), 0, 20);
    }

    private static function instanceId(array $profile): string
    {
        $id = (string)($profile['instance'] ?? '');
        if (!self::uuid($id)) {
            throw new RuntimeException('The WireGuard instance identifier is invalid.');
        }
        return $id;
    }

    private static function uuid(string $value): bool
    {
        return preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $value) === 1;
    }
}
