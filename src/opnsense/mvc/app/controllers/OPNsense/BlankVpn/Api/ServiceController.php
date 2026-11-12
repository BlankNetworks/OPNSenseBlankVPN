<?php

namespace OPNsense\BlankVpn\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\Diagnostics;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\ProxyCatalog;
use OPNsense\BlankVpn\ProxyImport;
use OPNsense\BlankVpn\ProxyRuntime;
use OPNsense\BlankVpn\Resolver;
use OPNsense\BlankVpn\SmartRouting;
use OPNsense\BlankVpn\WireGuard;

class ServiceController extends ApiControllerBase
{
    public function dashboardAction()
    {
        return $this->respond(function () {
            $model = new BlankVpn();
            $settings = Policy::settings($model);
            $settings['availableInterfaces'] = array_values(Policy::availableInterfaces());
            $profiles = Policy::profiles($model);
            $proxyRoutes = ProxyRuntime::routes($model);
            $assignments = Policy::assignments($model);
            $services = SmartRouting::services($model);
            $diagnostics = new Diagnostics();
            $discovery = $diagnostics->devices();
            $runtime = $profiles === [] ? [] : WireGuard::runtimeRecords();
            $health = Firewall::health();
            $loaded = $settings['enabled'] ? Firewall::loadedRules() : [];
            $warnings = $discovery['warnings'];
            if ($settings['enabled'] && $loaded === null) {
                $warnings[] = 'The active firewall rules are unavailable.';
            }
            foreach ($profiles as $id => $profile) {
                $status = WireGuard::status($profile, $runtime);
                $owned = WireGuard::check($profile);
                if (!$owned['ok']) {
                    $warnings[] = $profile['name'] . ': ' . $owned['error'];
                    $status['status'] = 'Native configuration changed';
                }
                $checked = $health[$id] ?? [];
                $profiles[$id] = array_intersect_key(
                    $profile,
                    array_flip(['id', 'name', 'relay', 'identity', 'interface', 'address6', 'dns'])
                ) + $status + [
                    'reachability' => time() - ($checked['checkedAt'] ?? 0) > 180 ? 'unverified or stale'
                        : (($checked['probeSucceeded'] ?? false) ? 'router probe succeeded' : 'router probe failed'),
                    'checkedAt' => $checked['checkedAt'] ?? null
                ];
            }
            $proxyStatus = ProxyRuntime::lastStatus();
            foreach ($proxyRoutes as $id => $route) {
                $checked = $health[$id] ?? [];
                $running = in_array($id, $proxyStatus['active'], true);
                $profiles[$id] = array_intersect_key($route, array_flip(['id', 'name', 'node', 'kind', 'core', 'protocol', 'interface'])) + [
                    'status' => $proxyStatus['errors'][$id] ?? ($running ? 'Local tunnel ready' : 'Proxy tunnel stopped'),
                    'reachability' => time() - ($checked['checkedAt'] ?? 0) > 300 ? 'unverified or stale'
                        : (($checked['probeSucceeded'] ?? false) ? 'proxy probe succeeded' : 'proxy probe failed')
                ];
            }
            foreach ($assignments as $id => $row) {
                $rule = $loaded[Policy::marker('device', $id)] ?? null;
                $guard = ($loaded[Policy::marker('kill', $id)]['action'] ?? '') === 'block';
                $applied = $rule['gateway'] ?? ($guard ? 'IPv4 internet blocked' : 'Normal network policy');
                $assignments[$id] = $row + [
                    'device' => $row['interface'] . '/' . $row['mac'],
                    'verified' => false,
                    'killSwitchActive' => $guard && $row['failure'] === 'block',
                    'appliedRoute' => $applied
                ];
            }
            $learned = SmartRouting::active($settings, $services) ? SmartRouting::status() : [];
            foreach ($services as $id => &$service) {
                $service['learned'] = $learned[$id] ?? null;
                $service['routing'] = [];
                foreach ($settings['smartInterfaces'] as $interface) {
                    $key = $id . ':' . $interface;
                    $guard = ($loaded[Policy::marker('service_guard', $key)]['action'] ?? '') === 'block';
                    $service['routing'][$interface] = [
                        'gateway' => $loaded[Policy::marker('service', $key)]['gateway'] ?? null,
                        'guard' => $guard
                    ];
                }
            }
            unset($service);
            if (!self::nativeWritesAvailable()) {
                $warnings[] = 'This build requires standard OPNsense WebGUI mode to manage native settings.';
            }
            $discovery['warnings'] = $warnings;
            $username = $this->getUserName();
            return $discovery + [
                'profiles' => array_values($profiles),
                'proxyCores' => ProxyRuntime::capabilities(),
                'assignments' => array_values($assignments),
                'settings' => $settings,
                'services' => array_values($services),
                'servicePresets' => SmartRouting::PRESETS,
                'canManage' => self::nativeWritesAvailable() && is_string($username) &&
                    (new ACL())->isPageAccessible($username, '/api/blankvpn/service/assign')
            ];
        });
    }

    public function relaysAction()
    {
        return $this->respond(fn () => (new Mullvad())->relays(), false, true);
    }

    public function refreshRelaysAction()
    {
        return $this->respond(fn () => (new Mullvad())->relays(true), true, true);
    }

    public function accountAction()
    {
        return $this->respond(fn () => (new Mullvad())->account($this->input('account', 64)), true, true, true);
    }

    public function registerAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $relayId = $this->input('relay', 100);
            $name = $this->name($relayId);
            $account = $this->input('account', 64);
            $mullvad = new Mullvad();
            $existing = Policy::profiles(new BlankVpn());
            foreach ($existing as $profile) {
                if ($profile['relay'] === $relayId && $relayId !== '') {
                    if (!empty($profile['accountBinding'])) {
                        $mullvad->verifyBinding($account, $profile['accountBinding']);
                    }
                    if (!WireGuard::check($profile)['ok']) {
                        throw new \DomainException('The existing exit needs repair before it can be reused.');
                    }
                    return ['profile' => $profile['id'], 'reused' => true, 'message' => 'The existing exit was reused.'];
                }
            }
            $dnsPort = Resolver::freePort($existing);
            $relay = $this->relay($mullvad, $relayId);
            WireGuard::preflight($relay['ipv4']);
            $identity = $mullvad->register($account, $relayId);
            $result = $this->addProfile($name, $relayId, $identity, $relay, $dnsPort);
            try {
                $mullvad->completeRegistration($identity['registrationReceipt']);
            } catch (\Throwable) {
                $result['warning'] = 'The tunnel was saved. A local registration recovery record still needs cleanup.';
            }
            return $result;
        }), true, true, true);
    }

    public function retargetProfileAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $relayId = $this->input('relay', 100);
            $relay = $this->relay(new Mullvad(), $relayId);
            $result = Operations::change(function (BlankVpn $model) use ($id, $relayId, $relay) {
                $profiles = Policy::profiles($model);
                $profile = $profiles[$id] ?? null;
                if ($profile === null || $profile['relay'] === '') {
                    throw new \DomainException('Select a locally registered Mullvad profile to change its server.');
                }
                foreach (Policy::assignments($model) as $row) {
                    if ($row['profile'] === $id || $row['backup'] === $id) {
                        throw new \DomainException('Move all devices off this shared exit before changing its server.');
                    }
                }
                $this->requireUnusedByService($model, $id);
                foreach ($profiles as $other) {
                    if ($other['id'] !== $id && $other['relay'] === $relayId) {
                        throw new \DomainException('A tunnel for that relay already exists. Use that profile.');
                    }
                }
                $node = $model->profiles->profile->getChild($id);
                $ownership = WireGuard::retarget($profile, $relay);
                unset($ownership['id'], $ownership['name'], $ownership['relay']);
                $node->relay = $relayId;
                if ($profile['name'] === $profile['relay']) {
                    $node->name = $relayId;
                }
                $node->ownership = json_encode($ownership, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                $health = Firewall::health();
                unset($health[$id]);
                Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
                return ['id' => $id, 'added' => $ownership, 'reload' => Policy::settings($model)['enabled']];
            });
            return ['profile' => $result['id']];
        }), true, true);
    }

    private function relay(Mullvad $mullvad, string $relayId): array
    {
        foreach ($mullvad->relays()['relays'] as $candidate) {
            if ($candidate['id'] === $relayId && $candidate['active']) {
                return $candidate;
            }
        }
        throw new \DomainException('Choose a currently available Mullvad WireGuard relay.');
    }

    public function importProfileAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            WireGuard::preflight();
            $mullvad = new Mullvad();
            $config = $mullvad->parseConfig($this->input('config', 16384));
            $identity = $config;
            $identity['publicKey'] = $mullvad->derivePublicKey($config['privateKey']);
            $dnsPort = Resolver::freePort(Policy::profiles(new BlankVpn()));
            return $this->addProfile($this->name(), '', $identity, $config, $dnsPort);
        }), true, true, true);
    }

    private function addProfile(string $name, string $relayId, array $identity, array $relay, int $dnsPort): array
    {
        $result = Operations::change(function (BlankVpn $model) use ($name, $relayId, $identity, $relay, $dnsPort) {
            $node = $model->profiles->profile->add();
            $id = (string)$node->getAttribute('uuid');
            $source = explode('/', $identity['address'] ?? '')[0];
            foreach (Policy::localNetworks(Policy::settings($model)) as $network) {
                if (Policy::contains($network, $source)) {
                    throw new \DomainException('This WireGuard IPv4 address overlaps a configured local network.');
                }
            }
            $ownership = WireGuard::create($id, $identity, $relay);
            $ownership['dnsPort'] = $dnsPort;
            if (isset($identity['accountBinding'])) {
                $ownership['accountBinding'] = $identity['accountBinding'];
            }
            $ownership['dns'] = array_values(array_slice($identity['dns'] ?? [], 0, 4));
            $node->name = $name;
            $node->relay = $relayId;
            $node->ownership = json_encode($ownership, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            return ['id' => $id, 'added' => $ownership, 'reload' => Policy::settings($model)['enabled']];
        });
        return ['profile' => $result['id']];
    }

    public function removeProfileAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            Operations::change(function (BlankVpn $model) use ($id) {
                $profile = Policy::routes($model)[$id] ?? null;
                if ($profile === null) {
                    throw new \DomainException('This VPN profile no longer exists.');
                }
                foreach (Policy::assignments($model) as $assignment) {
                    if ($assignment['profile'] === $id || $assignment['backup'] === $id) {
                        throw new \DomainException('Remove this profile from every device policy before deleting it.');
                    }
                }
                $this->requireUnusedByService($model, $id);
                if (($profile['kind'] ?? '') === 'proxy') {
                    $model->proxyRoutes->route->del($id);
                    return ['reload' => Policy::settings($model)['enabled']];
                }
                WireGuard::remove($profile);
                $model->profiles->profile->del($id);
                return ['removed' => $profile, 'reload' => Policy::settings($model)['enabled']];
            });
            return [];
        }), true, true);
    }

    public function settingsAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $enabled = $this->flag('enabled');
            $interfaces = $this->listInput('interfaces');
            $strict = $this->listInput('strictInterfaces');
            $smart = $this->listInput('smartInterfaces');
            $local = $this->listInput('localNetworks');
            $hostname = strtolower(trim($this->input('hostname', 120, 'opnsense.home.arpa')));
            if (array_diff($interfaces, array_keys(Policy::availableInterfaces())) ||
                array_diff($strict, $interfaces) || array_diff($smart, $interfaces)) {
                throw new \DomainException('Choose assigned LAN or VLAN interfaces for Smart Routing and strict management.');
            }
            if (array_intersect($strict, $smart)) {
                throw new \DomainException('Use Smart Routing on a managed interface with normal internet as its default.');
            }
            if ($enabled && $interfaces === []) {
                throw new \DomainException('Choose a LAN or VLAN for Blank VPN to manage.');
            }
            if ($enabled) {
                Policy::segmentNetworks($strict);
                if (!Firewall::dnsRedirectionAvailable()) {
                    throw new \DomainException('OPNsense automatic NAT reflection for port forwards conflicts with Blank VPN DNS redirection.');
                }
            }
            if (!Resolver::validHostname($hostname)) {
                throw new \DomainException('Enter a valid dashboard hostname under home.arpa.');
            }
            $networks = [];
            foreach ($local as $network) {
                $canonical = Policy::cidr($network);
                if ($canonical === null) {
                    throw new \DomainException('Enter local exclusions as IPv4 or IPv6 CIDRs with a specific prefix.');
                }
                $networks[] = $canonical;
            }
            Operations::change(function (BlankVpn $model) use ($enabled, $interfaces, $strict, $smart, $networks, $hostname) {
                $before = Policy::settings($model);
                $reset = [];
                foreach (Policy::assignments($model) as $row) {
                    if (!in_array($row['interface'], $interfaces, true)) {
                        throw new \DomainException('Remove saved assignments before removing their managed interface.');
                    }
                    if ($enabled && !$before['enabled'] && $row['profile'] !== '' && $row['failure'] === 'block') {
                        $reset[] = $row['ip'];
                    }
                }
                $model->settings->enabled = $enabled ? '1' : '0';
                $model->settings->interfaces = implode(',', $interfaces);
                $model->settings->strictInterfaces = implode(',', $strict);
                $model->settings->smartInterfaces = implode(',', $smart);
                $model->settings->localNetworks = implode(',', array_unique($networks));
                $model->settings->hostname = $hostname;
                $newStrict = $enabled ? array_values(array_diff($strict, $before['enabled'] ? $before['strictInterfaces'] : [])) : [];
                return [
                    'reload' => $before['enabled'] || $enabled,
                    'strictActivation' => $newStrict,
                    'killSwitchReset' => array_values(array_unique($reset)),
                    'settings' => Policy::settings($model)
                ];
            });
            return [];
        }), true, true);
    }

    public function assignAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $ip = $this->input('ip', 45);
            $mac = strtolower($this->input('mac', 17));
            $interface = $this->input('interface', 20);
            $label = trim($this->input('label', 120));
            $profile = $this->input('profile', 64);
            $backup = $this->input('backup', 64);
            $failure = $profile === '' ? 'block' : $this->input('failure', 12, 'block');
            if (
                !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                !Policy::validMac($mac) || !Policy::interfaceId($interface) || !Policy::failure($failure) ||
                !preg_match('/^[^\p{C}<>]{0,100}$/uD', $label)
            ) {
                throw new \DomainException('Choose a valid reserved IPv4 device, interface and routing policy.');
            }
            if (!(new Diagnostics())->hasReservation($interface, $ip, $mac)) {
                throw new \DomainException('Create a unique IPv4 DHCP reservation for this MAC and interface first.');
            }
            $result = Operations::change(function (BlankVpn $model) use ($ip, $mac, $interface, $label, $profile, $backup, $failure) {
                $settings = Policy::settings($model);
                if (!in_array($interface, $settings['interfaces'], true)) {
                    throw new \DomainException('Add this device’s LAN or VLAN under Routing settings before saving the policy.');
                }
                $profiles = Policy::routes($model);
                if ($profile !== '' && (!isset($profiles[$profile]) || !self::routeConfigured($profiles[$profile]))) {
                    throw new \DomainException('The selected exit is missing or its configuration has changed.');
                }
                if ($failure === 'backup' && ($backup === $profile || !isset($profiles[$backup]) || !self::routeConfigured($profiles[$backup]))) {
                    throw new \DomainException('Choose a different, configured backup exit.');
                }
                $node = null;
                $prior = [];
                foreach (Policy::assignments($model) as $id => $row) {
                    if ($row['interface'] !== $interface) {
                        continue;
                    }
                    if ($row['mac'] === $mac) {
                        $node = $model->assignments->assignment->getChild($id);
                        $prior = $row;
                    } elseif ($row['ip'] === $ip) {
                        throw new \DomainException('This IPv4 address already has an assignment. Remove that assignment first.');
                    }
                }
                if ($node === null) {
                    $node = $model->assignments->assignment->add();
                }
                $node->ip = $ip;
                $node->mac = $mac;
                $node->interface = $interface;
                $node->label = $label;
                $node->profile = $profile;
                $node->backup = $failure === 'backup' ? $backup : '';
                $node->failure = $failure;
                $newKillSwitch = $settings['enabled'] && $profile !== '' && $failure === 'block' &&
                    (($prior['ip'] ?? '') !== $ip || ($prior['profile'] ?? '') !== $profile || ($prior['failure'] ?? '') !== 'block');
                return [
                    'settings' => $settings, 'reload' => $settings['enabled'],
                    'killSwitchReset' => $newKillSwitch ? [$ip] : []
                ];
            });
            $reset = $result['killSwitchReset'] !== [];
            $result = ['applied' => $result['reload'], 'killSwitchReset' => $reset];
            if ($result['applied'] && !$reset && $this->flag('switchNow')) {
                try {
                    $result['reconnected'] = Operations::switchDevice($ip, Policy::settings(new BlankVpn()));
                } catch (\Throwable) {
                    $result['warning'] = 'The policy was applied. Existing internet sessions could not be checked.';
                }
            }
            return $result;
        }), true, true);
    }

    public function removeAssignmentAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $result = Operations::change(function (BlankVpn $model) use ($id) {
                $row = Policy::assignments($model)[$id] ?? null;
                if ($row === null) {
                    throw new \DomainException('This device policy no longer exists.');
                }
                $model->assignments->assignment->del($id);
                return ['ip' => $row['ip'], 'reload' => Policy::settings($model)['enabled']];
            });
            if ($result['reload']) {
                try {
                    return ['reconnected' => Operations::switchDevice($result['ip'], Policy::settings(new BlankVpn()))];
                } catch (\Throwable) {
                    return ['warning' => 'The policy was removed. Existing internet sessions could not be checked.'];
                }
            }
            return [];
        }), true, true);
    }

    public function saveServiceAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $name = $this->name();
            $domains = SmartRouting::domains($this->input('domains', 2048));
            $profileId = $this->input('profile', 64);
            return Operations::change(function (BlankVpn $model) use ($id, $name, $domains, $profileId) {
                $services = SmartRouting::services($model);
                if ($id !== '' && !isset($services[$id])) {
                    throw new \DomainException('This Smart Routing service no longer exists.');
                }
                if ($id === '' && count($services) >= SmartRouting::MAX_SERVICES) {
                    throw new \DomainException('Remove an existing service before adding another.');
                }
                SmartRouting::checkOverlap($services, $id, $domains);
                $profile = Policy::routes($model)[$profileId] ?? [];
                if ($profile === [] || !SmartRouting::canResolve($profile) || !self::routeConfigured($profile)) {
                    throw new \DomainException('Select a configured VPN or proxy exit with DNS support.');
                }
                $node = $id === '' ? $model->services->service->add() : $model->services->service->getChild($id);
                $node->name = $name;
                $node->domains = implode(',', $domains);
                $node->profile = $profileId;
                return ['reload' => Policy::settings($model)['enabled']];
            });
        }), true, true);
    }

    public function removeServiceAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            return Operations::change(function (BlankVpn $model) use ($id) {
                if (!$model->services->service->del($id)) {
                    throw new \DomainException('This Smart Routing service no longer exists.');
                }
                return ['reload' => Policy::settings($model)['enabled']];
            });
        }), true, true);
    }

    private function requireUnusedByService(BlankVpn $model, string $profileId): void
    {
        foreach (SmartRouting::services($model) as $service) {
            if ($service['profile'] === $profileId) {
                throw new \DomainException('Move Smart Routing services off this exit first.');
            }
        }
    }

    public function proxyCatalogAction()
    {
        return $this->respond(fn () => ProxyCatalog::publicView(), false, true);
    }

    public function importProxiesAction()
    {
        return $this->respond(fn () => Operations::exclusive(
            fn () => ProxyCatalog::import($this->input('body', ProxyImport::MAX_BYTES))
        ), true, true, true);
    }

    public function addSubscriptionAction()
    {
        return $this->respond(fn () => Operations::exclusive(fn () => ProxyCatalog::addFeed(
            $this->input('name', 96),
            $this->input('url', 2048),
            $this->flag('auto'),
            array_column(ProxyRuntime::routes(new BlankVpn()), 'node')
        )), true, true, true);
    }

    public function refreshSubscriptionAction()
    {
        return $this->respond(fn () => Operations::exclusive(fn () => ProxyCatalog::refreshFeed(
            $this->input('id', 64),
            array_column(ProxyRuntime::routes(new BlankVpn()), 'node')
        )), true, true);
    }

    public function removeSubscriptionAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            ProxyCatalog::removeFeed($this->input('id', 64), array_column(ProxyRuntime::routes(new BlankVpn()), 'node'));
            return [];
        }), true, true);
    }

    public function removeProxyNodeAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            ProxyCatalog::removeNode($this->input('id', 64), array_column(ProxyRuntime::routes(new BlankVpn()), 'node'));
            return [];
        }), true, true);
    }

    public function enableProxyExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $node = ProxyCatalog::read()['nodes'][$id] ?? null;
            if (!is_array($node)) {
                throw new \DomainException('Import the proxy node before enabling its exit.');
            }
            ProxyRuntime::preflight($node['core']);
            return Operations::change(function (BlankVpn $model) use ($id, $node) {
                $routes = ProxyRuntime::routes($model);
                $occupied = array_column($routes, 'slot');
                foreach ($routes as $route) {
                    if ($route['node'] === $id) {
                        throw new \DomainException('This server already has its own exit.');
                    }
                }
                $free = array_diff(range(0, ProxyRuntime::SLOTS - 1), $occupied);
                if ($free === []) {
                    throw new \DomainException('Remove an existing proxy exit to free a runtime slot.');
                }
                $route = $model->proxyRoutes->route->add();
                $route->name = $node['name'];
                $route->node = $id;
                $route->core = $node['core'];
                $route->protocol = $node['protocol'];
                $route->slot = (string)reset($free);
                return ['reload' => Policy::settings($model)['enabled']];
            });
        }), true, true);
    }

    private static function routeConfigured(array $profile): bool
    {
        return ($profile['kind'] ?? '') === 'proxy'
            ? isset(ProxyCatalog::read()['nodes'][$profile['node']])
            : WireGuard::check($profile)['ok'];
    }

    public function connectionsAction($ip = '')
    {
        return $this->respond(function () use ($ip) {
            return (new Diagnostics())->connections(rawurldecode((string)$ip));
        });
    }

    private function name(string $default = ''): string
    {
        $name = trim($this->input('name', 120)) ?: $default;
        if (!preg_match('/^[^\p{C}<>]{1,64}$/uD', $name)) {
            throw new \DomainException('Enter a profile name between 1 and 64 characters.');
        }
        return $name;
    }

    private function input(string $field, int $max, string $default = ''): string
    {
        $value = $this->request->getPost($field, null, $default);
        if (!is_string($value) || strlen($value) > $max) {
            throw new \DomainException('A submitted Blank VPN field is invalid.');
        }
        return $value;
    }

    private function listInput(string $field): array
    {
        $items = $this->request->getPost($field, null, []);
        if (is_string($items)) {
            $items = array_filter(preg_split('/[\s,]+/', trim($items)), 'strlen');
        }
        if (!is_array($items) || count($items) > 32) {
            throw new \DomainException('A submitted Blank VPN list exceeds the supported size.');
        }
        foreach ($items as $item) {
            if (!is_string($item) || strlen($item) > 50) {
                throw new \DomainException('A submitted Blank VPN list contains an invalid item.');
            }
        }
        return array_values(array_unique($items));
    }

    private function flag(string $field): bool
    {
        return in_array($this->request->getPost($field), [true, 1, '1', 'true'], true);
    }

    private static function nativeWritesAvailable(): bool
    {
        return !isset(Config::getInstance()->object()->system->webgui->noroot) &&
            !is_file('/var/run/www_non_root');
    }

    private function respond(
        callable $work,
        bool $post = false,
        bool $allowRuntimeMessage = false,
        bool $requireHttps = false
    ): array {
        $this->response->setHeader('Cache-Control', 'no-store');
        if ($post && !$this->request->isPost()) {
            return ['ok' => false, 'error' => 'Send this operation as POST.'];
        }
        try {
            if ($requireHttps && !$this->request->isSecure()) {
                throw new \DomainException('Open the OPNsense WebGUI over HTTPS before sending VPN credentials, proxy nodes, or subscription URLs.');
            }
            if ($post && !self::nativeWritesAvailable()) {
                throw new \DomainException('This build requires standard OPNsense WebGUI mode for management actions.');
            }
            return ['ok' => true] + $work();
        } catch (\DomainException | \InvalidArgumentException $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        } catch (\RuntimeException $error) {
            if ($allowRuntimeMessage && $error::class === \RuntimeException::class) {
                return ['ok' => false, 'error' => $error->getMessage()];
            }
            syslog(LOG_WARNING, 'Blank VPN operation did not complete.');
        } catch (\Throwable) {
            syslog(LOG_ERR, 'Blank VPN operation failed unexpectedly.');
        }
        return ['ok' => false, 'error' => 'Blank VPN could not complete this operation.'];
    }
}
