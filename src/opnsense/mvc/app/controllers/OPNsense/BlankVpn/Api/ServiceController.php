<?php

namespace OPNsense\BlankVpn\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\Diagnostics;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\NativeVpn;
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
    private const MULLVAD_SESSION = 'blankvpn_mullvad_login';

    public function dashboardAction()
    {
        return $this->respond(function () {
            $model = new BlankVpn();
            $settings = Policy::settings($model);
            $routing = Policy::routingSettings($settings);
            $settings['dashboardAddresses'] = Resolver::dashboardAddresses();
            $settings['tailscaleInstalled'] = is_executable('/usr/local/bin/tailscale');
            $settings['tailscaleExitAdvertised'] =
                (string)(Config::getInstance()->object()->OPNsense->tailscale->settings->advertiseExitNode ?? '') === '1';
            $port = (string)Config::getInstance()->object()->system->webgui->port;
            $settings['dashboardPort'] = ctype_digit($port) && (int)$port <= 65535 && (int)$port > 0 ? (int)$port : 443;
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
            foreach (NativeVpn::routes($model) as $id => $route) {
                $checked = $health[$id] ?? [];
                $profiles[$id] = $route + [
                    'status' => !$route['configured'] ? 'Native gateway changed' :
                        ($route['address'] === '' ? 'Tunnel IPv4 unavailable' : 'Tunnel interface up'),
                    'reachability' => time() - ($checked['checkedAt'] ?? 0) > 180 ? 'unverified or stale'
                        : (($checked['probeSucceeded'] ?? false) ? 'router probe succeeded' : 'router probe failed')
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
                $row['mode'] = Policy::mode($row);
                $row['killSwitch'] = Policy::killSwitch($row);
                $assignments[$id] = $row + [
                    'device' => $row['interface'] . '/' . (($row['kind'] ?? '') === 'tailnet' ? $row['ip'] : $row['mac']),
                    'verified' => false,
                    'killSwitchActive' => $guard && $rule === null && $row['killSwitch'],
                    'appliedRoute' => $applied
                ];
            }
            $learned = SmartRouting::active($routing, $services) ? SmartRouting::status() : [];
            foreach ($services as $id => &$service) {
                $service['learned'] = $learned[$id] ?? null;
                $service['routing'] = [];
                foreach ($routing['smartInterfaces'] as $interface) {
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
            $acl = new ACL();
            $canManage = self::nativeWritesAvailable() && is_string($username) &&
                $acl->isPageAccessible($username, '/api/blankvpn/service/assign');
            $mullvadUser = $canManage ? $this->mullvadUser() : null;
            return $discovery + [
                'profiles' => array_values($profiles),
                'proxyCores' => ProxyRuntime::capabilities(),
                'canManageCores' => self::nativeWritesAvailable() && is_string($username) &&
                    $acl->isPageAccessible($username, '/api/blankvpn/core/status'),
                'mullvadSignedIn' => $this->mullvadToken() !== null,
                'mullvadLoginSaved' => $mullvadUser !== null && (new Mullvad())->hasSavedAccount($mullvadUser),
                'assignments' => array_values($assignments),
                'settings' => $settings,
                'activeSmartInterfaces' => $routing['smartInterfaces'],
                'services' => array_values($services),
                'servicePresets' => SmartRouting::PRESETS,
                'canManage' => $canManage
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

    public function testRelayAction()
    {
        return $this->respond(function () {
            $relay = $this->relay(new Mullvad(), $this->input('relay', 100));
            $address = $relay['ipv4'];
            if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_GLOBAL_RANGE)) {
                throw new \DomainException('The relay has no public IPv4 endpoint.');
            }
            $output = Resolver::command(['/sbin/ping', '-n', '-c', '1', '-W', '1500', '-t', '3', $address], false);
            $reply = preg_match('/\btime[=<]([0-9]+(?:[.,][0-9]+)?) ms\b/', $output, $matches);
            return ['relay' => $relay['id'], 'replied' => $reply === 1,
                'milliseconds' => $reply === 1 ? (float)str_replace(',', '.', $matches[1]) : null];
        }, true, true);
    }

    public function testExitAction()
    {
        return $this->respond(function () {
            $route = Policy::routes(new BlankVpn())[$this->input('id', 64)] ?? null;
            if ($route === null || !self::routeConfigured($route)) {
                throw new \DomainException('Select a configured exit.');
            }
            if (($route['kind'] ?? '') === 'proxy') {
                $probe = ProxyRuntime::probe($route);
            } else {
                $installed = Firewall::probePathInstalled($route, Firewall::loadedRules() ?? []);
                $probe = ($route['kind'] ?? '') === 'native'
                    ? WireGuard::probeSource($installed ? $route['address'] : '')
                    : WireGuard::probe($route, $installed);
            }
            return ['reachable' => $probe['reachable'] ?? null, 'milliseconds' => $probe['milliseconds'] ?? null];
        }, true, true);
    }

    public function accountAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $user = $this->mullvadUser();
            $save = $this->flag('saveLogin');
            if ($save && $user === null) {
                throw new \DomainException('Use a WebGUI login to save a Mullvad account.');
            }
            $account = $this->input('account', 64);
            $mullvad = new Mullvad();
            $login = $mullvad->authenticate($account);
            if ($user !== null) {
                $mullvad->saveAccount($user, $save ? $account : null);
                $this->storeMullvadSession($user, $login);
            }
            return $login['account'] + ['saved' => $save];
        }), true, true, true);
    }

    public function restoreMullvadAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $user = $this->mullvadUser();
            $mullvad = new Mullvad();
            $account = $user === null ? null : $mullvad->savedAccount($user);
            if ($account === null) {
                throw new \DomainException('There is no saved Mullvad login for this WebGUI user.');
            }
            $login = $mullvad->authenticate($account);
            $this->storeMullvadSession($user, $login);
            return $login['account'] + ['saved' => true];
        }), true, true, true);
    }

    public function logoutMullvadAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $user = $this->mullvadUser();
            if ($user !== null) {
                (new Mullvad())->saveAccount($user, null);
                $this->session->remove(self::MULLVAD_SESSION);
            }
            return [];
        }), true, true, true);
    }

    private function mullvadUser(): ?string
    {
        if ($this->isExternalClient() || $this->request->getScheme() !== 'https') {
            return null;
        }
        $user = $this->getUserName();
        return is_string($user) && $user !== '' ? $user : null;
    }

    private function storeMullvadSession(string $user, array $login): void
    {
        $this->session->set(self::MULLVAD_SESSION, [
            'token' => $login['token'], 'expires' => $login['expires'], 'user' => $user
        ]);
    }

    private function mullvadToken(): ?string
    {
        $user = $this->mullvadUser();
        if ($user === null) {
            return null;
        }
        $login = $this->session->get(self::MULLVAD_SESSION);
        return is_array($login) && ($login['expires'] ?? 0) > time() &&
            ($login['user'] ?? null) === $user ? ($login['token'] ?? null) : null;
    }

    public function registerAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $relayId = $this->input('relay', 100);
            $name = $this->name($relayId);
            $account = $this->input('account', 64);
            $token = $account === '' ? $this->mullvadToken() : null;
            $mullvad = new Mullvad();
            if ($account === '' && $token === null) {
                $user = $this->mullvadUser();
                $saved = $user === null ? null : $mullvad->savedAccount($user);
                if ($saved === null) {
                    throw new \DomainException('Sign in to Mullvad before adding an exit.');
                }
                $login = $mullvad->authenticate($saved);
                $this->storeMullvadSession($user, $login);
                $token = $login['token'];
            }
            $existing = Policy::profiles(new BlankVpn());
            foreach ($existing as $profile) {
                if ($profile['relay'] === $relayId && $relayId !== '') {
                    if (!empty($profile['accountBinding'])) {
                        if ($token !== null) {
                            $mullvad->verifyBindingWithToken($token, $profile['accountBinding']);
                        } else {
                            $mullvad->verifyBinding($account, $profile['accountBinding']);
                        }
                    }
                    if (!WireGuard::check($profile)['ok']) {
                        throw new \DomainException('The existing exit needs repair before it can be reused.');
                    }
                    return ['profile' => $profile['id'], 'reused' => true, 'message' => 'The existing exit was reused.'];
                }
            }
            $dnsPort = Resolver::freePort(Policy::routes(new BlankVpn()));
            $relay = $this->relay($mullvad, $relayId);
            WireGuard::preflight($relay['ipv4']);
            $identity = $token !== null ? $mullvad->registerWithToken($token, $relayId) : $mullvad->register($account, $relayId);
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
                $this->requireUnusedByRouting($model, $id);
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
            $config = $mullvad->parseConfig($this->input('config', 16384), trim($this->input('dns', 128)));
            $identity = $config;
            $identity['publicKey'] = $mullvad->derivePublicKey($config['privateKey']);
            $dnsPort = Resolver::freePort(Policy::routes(new BlankVpn()));
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

    public function addNativeExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $name = $this->name();
            $id = $this->input('gateway', 64);
            $dns = trim($this->input('dns', 64));
            $gateway = NativeVpn::gateways()[$id] ?? null;
            if ($gateway === null || !filter_var($dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                Policy::contains('127.0.0.0/8', $dns) || Policy::contains('224.0.0.0/4', $dns) ||
                in_array($dns, ['0.0.0.0', '255.255.255.255'], true)) {
                throw new \DomainException('Choose a configured tunnel gateway and enter its IPv4 DNS resolver.');
            }
            return Operations::change(function (BlankVpn $model) use ($name, $id, $dns, $gateway) {
                foreach (Policy::routes($model) as $existing) {
                    if (($existing['interface'] ?? '') === $gateway['interface']) {
                        throw new \DomainException('This tunnel interface already has an exit.');
                    }
                }
                $port = Resolver::freePort(Policy::routes($model));
                $node = $model->nativeRoutes->route->add();
                $node->name = $name;
                $node->gatewayId = $id;
                $node->gatewayName = $gateway['gateway'];
                $node->device = $gateway['interface'];
                $node->logicalInterface = $gateway['logicalInterface'];
                $node->protocol = $gateway['protocol'];
                $node->dns = $dns;
                $node->dnsPort = (string)$port;
                return ['profile' => (string)$node->getAttribute('uuid'), 'reload' => Policy::settings($model)['enabled']];
            });
        }), true, true);
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
                $this->requireUnusedByRouting($model, $id);
                if (($profile['kind'] ?? '') === 'proxy') {
                    $model->proxyRoutes->route->del($id);
                    return ['reload' => Policy::settings($model)['enabled']];
                }
                if (($profile['kind'] ?? '') === 'native') {
                    $model->nativeRoutes->route->del($id);
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
            $current = Policy::settings(new BlankVpn());
            $tailscale = $this->request->hasPost('tailscaleInterfaces')
                ? $this->listInput('tailscaleInterfaces') : $current['tailscaleInterfaces'];
            $assignedOnly = $this->flag('smartAssignedOnly');
            $local = $this->listInput('localNetworks');
            $hostname = strtolower(trim($this->input('hostname', 120, $current['hostname'])));
            $bind = $this->input('dashboardBind', 12, $current['dashboardBind']);
            $coverage = $this->input('coverage', 12, $current['coverage']);
            $networkMode = $this->input('networkMode', 12, $current['networkMode']);
            $networkProfile = $this->input('networkProfile', 64, $current['networkProfile']);
            $networkKillSwitch = $this->request->hasPost('networkKillSwitch')
                ? ($this->flag('networkKillSwitch') ? '1' : '0') : null;
            if (!in_array($coverage, ['network', 'device'], true) ||
                !in_array($networkMode, ['full', 'multi', 'blocked', 'disabled'], true)) {
                throw new \DomainException('Choose a coverage scope and routing mode.');
            }
            if ($coverage !== 'network' || $networkMode !== 'full') {
                $networkProfile = '';
            }
            $this->validateDashboardBinding($hostname, $bind);
            if (array_diff($interfaces, array_keys(Policy::availableInterfaces())) ||
                array_diff($strict, $interfaces) || array_diff($smart, $interfaces)) {
                throw new \DomainException('Choose assigned LAN or VLAN interfaces for Multi-Path and device rules.');
            }
            $this->validateTransitInterfaces($tailscale, $interfaces, $strict);
            if (array_intersect($strict, $smart)) {
                throw new \DomainException('Use Multi-Path on a selected interface with normal internet as its default.');
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
            $networks = [];
            foreach ($local as $network) {
                $canonical = Policy::cidr($network);
                if ($canonical === null) {
                    throw new \DomainException('Enter local exclusions as IPv4 or IPv6 CIDRs with a specific prefix.');
                }
                $networks[] = $canonical;
            }
            Operations::change(function (BlankVpn $model) use (
                $enabled, $interfaces, $strict, $smart, $tailscale, $assignedOnly, $networks,
                $hostname, $bind, $coverage, $networkMode, $networkProfile, $networkKillSwitch
            ) {
                $before = Policy::settings($model);
                if ($coverage === 'network') {
                    $segments = array_values(array_diff($interfaces, $tailscale));
                    if ($enabled && $networkMode !== 'disabled') {
                        if ($segments === []) {
                            throw new \DomainException('Choose a LAN or VLAN for Whole-Network coverage.');
                        }
                        Policy::segmentNetworks($segments);
                    }
                    if ($enabled && $networkMode === 'full') {
                        $route = Policy::routes($model)[$networkProfile] ?? [];
                        if ($route === [] || !SmartRouting::canResolve($route) || !self::routeConfigured($route)) {
                            throw new \DomainException('Choose a configured VPN or proxy exit with DNS for Whole-Network coverage.');
                        }
                    }
                }
                $reset = [];
                foreach (Policy::assignments($model) as $row) {
                    if (!in_array($row['interface'], $interfaces, true)) {
                        throw new \DomainException('Remove saved assignments before removing their managed interface.');
                    }
                    $mode = Policy::mode($row);
                    if (($row['kind'] ?? '') === 'tailnet' && !in_array($row['interface'], $tailscale, true)) {
                        throw new \DomainException('Remove the saved Tailscale assignments before removing their transit interface.');
                    }
                    if ($mode === 'multi' && !in_array($row['interface'], $smart, true)) {
                        throw new \DomainException('Move Multi-Path assignments before removing their service routing interface.');
                    }
                    if ($enabled && $coverage === 'device' && (!$before['enabled'] || $before['coverage'] !== 'device') &&
                        ($mode === 'blocked' ||
                        ($mode === 'full' && $row['failure'] !== 'wan') || Policy::killSwitch($row))) {
                        $reset[] = $row['ip'];
                        if (!empty($row['ipv6'])) {
                            $reset[] = $row['ipv6'];
                        }
                    }
                }
                $model->settings->enabled = $enabled ? '1' : '0';
                $model->settings->interfaces = implode(',', $interfaces);
                $model->settings->coverage = $coverage;
                $model->settings->networkMode = $networkMode;
                $model->settings->networkProfile = $networkProfile;
                if ($networkKillSwitch !== null) {
                    $model->settings->networkKillSwitch = $networkKillSwitch;
                }
                $model->settings->strictInterfaces = implode(',', $strict);
                $model->settings->smartInterfaces = implode(',', $smart);
                $model->settings->smartAssignedOnly = $assignedOnly ? '1' : '0';
                $model->settings->tailscaleInterfaces = implode(',', $tailscale);
                $model->settings->localNetworks = implode(',', array_unique($networks));
                $model->settings->hostname = $hostname;
                $model->settings->dashboardBind = $bind;
                $after = Policy::settings($model);
                $oldRouting = Policy::routingSettings($before);
                $newRouting = Policy::routingSettings($after);
                $newStrict = $enabled
                    ? array_diff($newRouting['strictInterfaces'], $before['enabled'] ? $oldRouting['strictInterfaces'] : [])
                    : [];
                $oldNetwork = $before['enabled'] && $before['coverage'] === 'network' && $before['networkMode'] !== 'disabled'
                    ? $oldRouting['interfaces'] : [];
                $newNetwork = $enabled && $coverage === 'network' && $networkMode !== 'disabled'
                    ? $newRouting['interfaces'] : [];
                $networkChanged = $oldNetwork !== $newNetwork || ($newNetwork !== [] &&
                    ($networkMode !== $before['networkMode'] || $networkProfile !== $before['networkProfile'] ||
                        $after['networkKillSwitch'] !== $before['networkKillSwitch']));
                return [
                    'reload' => $before['enabled'] || $enabled,
                    'resetSegments' => array_values(array_unique(array_merge(
                        $newStrict, $networkChanged ? [...$oldNetwork, ...$newNetwork] : []
                    ))),
                    'killSwitchReset' => array_values(array_unique($reset)),
                    'settings' => $after
                ];
            });
            return [];
        }), true, true);
    }

    public function disableAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            Operations::change(function (BlankVpn $model) {
                $settings = Policy::settings($model);
                $model->settings->enabled = '0';
                return ['reload' => $settings['enabled']];
            });
            return [];
        }), true, true);
    }

    public function tailscaleSettingsAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $hostname = strtolower(trim($this->input('hostname', 120)));
            $bind = $this->input('dashboardBind', 12);
            $tailscale = $this->listInput('tailscaleInterfaces');
            $this->validateDashboardBinding($hostname, $bind);
            Operations::change(function (BlankVpn $model) use ($hostname, $bind, $tailscale) {
                $before = Policy::settings($model);
                $this->validateTransitInterfaces($tailscale, $before['interfaces'], $before['strictInterfaces']);
                foreach (Policy::assignments($model) as $row) {
                    if (($row['kind'] ?? '') === 'tailnet' && !in_array($row['interface'], $tailscale, true)) {
                        throw new \DomainException('Remove the saved Tailscale device rules before unchecking their interface.');
                    }
                }
                $model->settings->tailscaleInterfaces = implode(',', $tailscale);
                $model->settings->hostname = $hostname;
                $model->settings->dashboardBind = $bind;
                $after = Policy::settings($model);
                $reset = [];
                if ($after['enabled'] && $after['coverage'] === 'network' && $after['networkMode'] !== 'disabled') {
                    $old = Policy::routingSettings($before)['interfaces'];
                    $new = Policy::routingSettings($after)['interfaces'];
                    if ($new === []) {
                        throw new \DomainException('Leave at least one interface for Whole-Network coverage.');
                    }
                    $reset = [...array_diff($old, $new), ...array_diff($new, $old)];
                    Policy::segmentNetworks($reset);
                }
                return ['reload' => $after['enabled'], 'resetSegments' => $reset, 'settings' => $after];
            });
            return [];
        }), true, true);
    }

    private function validateTransitInterfaces(array $tailscale, array $interfaces, array $strict): void
    {
        if (array_diff($tailscale, $interfaces) || array_intersect($tailscale, $strict) ||
            array_filter($tailscale, static fn (string $interface): bool => !Policy::tailnetInterface($interface))) {
            throw new \DomainException('Choose a dedicated interface enabled in Network for Tailscale traffic.');
        }
    }

    private function validateDashboardBinding(string $hostname, string $bind): void
    {
        if (!in_array($bind, ['lan', 'tailnet'], true)) {
            throw new \DomainException('Choose the home or Tailscale address for the dashboard.');
        }
        if (!Resolver::validHostname($hostname)) {
            throw new \DomainException('Enter blankvpn.local or a valid dashboard hostname under home.arpa.');
        }
    }

    public function assignAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $ip = $this->input('ip', 45);
            $mac = strtolower($this->input('mac', 17));
            $kind = $this->input('kind', 12, 'lan');
            $ipv6 = Policy::ipv6Address(trim($this->input('ipv6', 45)));
            $interface = $this->input('interface', 20);
            $label = trim($this->input('label', 120));
            $profile = $this->input('profile', 64);
            $backup = $this->input('backup', 64);
            $mode = $this->input('mode', 12, $profile === '' ? 'default' : 'full');
            if (!in_array($mode, ['full', 'multi', 'disabled', 'blocked', 'default'], true) ||
                !in_array($kind, ['lan', 'tailnet'], true) || ($mode === 'full' && $profile === '')) {
                throw new \DomainException('Choose a valid routing mode. Select an exit if you use one VPN or proxy.');
            }
            $profile = $mode === 'full' ? $profile : '';
            $killSwitch = $this->request->hasPost('killSwitch')
                ? ($this->flag('killSwitch') ? '1' : '0') : null;
            $failure = $profile === '' ? 'block' : $this->input('failure', 12, $killSwitch === '0' ? 'wan' : 'block');
            if ($mode === 'full' && $killSwitch === '1') {
                $failure = 'block';
            } elseif ($mode === 'full' && $killSwitch === '0' && $failure === 'block') {
                $failure = 'wan';
            }
            if (
                !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                ($kind === 'lan' && !Policy::validMac($mac)) || !Policy::interfaceId($interface) || !Policy::failure($failure) ||
                !preg_match('/^[^\p{C}<>]{0,100}$/uD', $label)
            ) {
                throw new \DomainException('Choose a valid reserved IPv4 device, interface and routing policy.');
            }
            if ($kind === 'tailnet' && (!Policy::tailnetAddress($ip) || !Policy::tailnetAddress($ipv6, true))) {
                throw new \DomainException('Enter both the Tailscale IPv4 and IPv6 addresses for this peer.');
            }
            if ($kind === 'lan' && !(new Diagnostics())->hasReservation($interface, $ip, $mac)) {
                throw new \DomainException('Create a unique IPv4 DHCP reservation for this MAC and interface first.');
            }
            $result = Operations::change(function (BlankVpn $model) use (
                $ip, $ipv6, $mac, $kind, $mode, $interface, $label, $profile, $backup, $failure, $killSwitch
            ) {
                $settings = Policy::settings($model);
                if (!in_array($interface, $settings['interfaces'], true)) {
                    throw new \DomainException('Add this device’s LAN or VLAN under Routing settings before saving the policy.');
                }
                if ($kind === 'tailnet' && (!in_array($interface, $settings['tailscaleInterfaces'], true) ||
                    !Policy::tailnetInterface($interface))) {
                    throw new \DomainException('Select a configured Tailscale transit interface that preserves peer addresses.');
                }
                if ($mode === 'multi' && !in_array($interface, $settings['smartInterfaces'], true)) {
                    throw new \DomainException('Enable Multi-Path service routing on this interface under Settings first.');
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
                    $tailnet = ($row['kind'] ?? '') === 'tailnet';
                    if ($kind === 'tailnet' && $tailnet && $row['ip'] === $ip ||
                        $kind === 'lan' && !$tailnet && $row['mac'] === $mac) {
                        $node = $model->assignments->assignment->getChild($id);
                        $prior = $row;
                    } elseif ($row['ip'] === $ip || ($ipv6 !== '' && ($row['ipv6'] ?? '') === $ipv6)) {
                        throw new \DomainException('This address already has an assignment on the selected interface.');
                    }
                }
                if ($node === null) {
                    $node = $model->assignments->assignment->add();
                }
                $node->ip = $ip;
                $node->mac = $kind === 'lan' ? $mac : '';
                $node->ipv6 = $ipv6;
                $node->kind = $kind;
                $node->mode = $mode;
                $node->interface = $interface;
                $node->label = $label;
                $node->profile = $profile;
                $node->backup = $failure === 'backup' ? $backup : '';
                $node->failure = $failure;
                // Older clients express the one-exit policy through failure instead of a checkbox.
                $node->killSwitch = $killSwitch ?? ($mode === 'multi' ? ($prior['killSwitch'] ?? '') : '');
                $changed = ($prior['ip'] ?? '') !== $ip || ($prior['ipv6'] ?? '') !== $ipv6 ||
                    Policy::mode($prior) !== $mode || ($prior['profile'] ?? '') !== $profile ||
                    ($prior['backup'] ?? '') !== ($failure === 'backup' ? $backup : '') ||
                    ($prior['failure'] ?? '') !== $failure ||
                    Policy::killSwitch($prior) !== Policy::killSwitch(Policy::fields($node));
                return [
                    'settings' => $settings, 'reload' => $settings['enabled'],
                    'killSwitchReset' => $settings['enabled'] && $changed ?
                        array_values(array_unique(array_filter([$ip, $ipv6, $prior['ip'] ?? '', $prior['ipv6'] ?? '']))) : []
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
            $domains = SmartRouting::domains($this->input('domains', SmartRouting::MAX_DOMAIN_BYTES));
            $profileId = $this->input('profile', 64);
            return Operations::change(function (BlankVpn $model) use ($id, $name, $domains, $profileId) {
                $services = SmartRouting::services($model);
                if ($id !== '' && !isset($services[$id])) {
                    throw new \DomainException('This Multi-Path list no longer exists.');
                }
                if ($id === '' && count($services) >= SmartRouting::MAX_SERVICES) {
                    throw new \DomainException('Remove an existing service before adding another.');
                }
                if ($profileId !== '') {
                    SmartRouting::checkOverlap(SmartRouting::boundServices($services), $id, $domains);
                    $profile = Policy::routes($model)[$profileId] ?? [];
                    if ($profile === [] || !SmartRouting::canResolve($profile) || !self::routeConfigured($profile)) {
                        throw new \DomainException('Select a configured VPN or proxy exit with DNS support.');
                    }
                }
                $node = $id === '' ? $model->services->service->add() : $model->services->service->getChild($id);
                $node->name = $name;
                $node->domains = implode(',', $domains);
                $node->profile = $profileId;
                return ['reload' => Policy::settings($model)['enabled'] &&
                    ($profileId !== '' || ($services[$id]['profile'] ?? '') !== '')];
            });
        }), true, true);
    }

    public function removeServiceAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            return Operations::change(function (BlankVpn $model) use ($id) {
                $service = SmartRouting::services($model)[$id] ?? null;
                if ($service === null || !$model->services->service->del($id)) {
                    throw new \DomainException('This Multi-Path list no longer exists.');
                }
                return ['reload' => Policy::settings($model)['enabled'] && $service['profile'] !== ''];
            });
        }), true, true);
    }

    private function requireUnusedByRouting(BlankVpn $model, string $profileId): void
    {
        if (Policy::settings($model)['networkProfile'] === $profileId) {
            throw new \DomainException('Choose a different exit for Whole-Network coverage first.');
        }
        foreach (SmartRouting::services($model) as $service) {
            if ($service['profile'] === $profileId) {
                throw new \DomainException('Move Multi-Path lists off this exit first.');
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

    public function addProxyNodeAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $node = ProxyImport::manual(
                $this->name(), $this->input('protocol', 24), trim($this->input('host', 255)),
                $this->input('port', 5), trim($this->input('username', 255)), $this->input('secret', 2048),
                trim($this->input('cipher', 80)), trim($this->input('parameters', 4096))
            );
            ProxyCatalog::saveManual([$node['id'] => $node]);
            return ['id' => $node['id']];
        }), true, true, true);
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

    public function setSubscriptionAutoAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            ProxyCatalog::setAutoRefresh($this->input('id', 64), $this->flag('auto'));
            return [];
        }), true, true);
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
        return match ($profile['kind'] ?? '') {
            'proxy' => isset(ProxyCatalog::read()['nodes'][$profile['node']]),
            'native' => $profile['configured'],
            default => WireGuard::check($profile)['ok']
        };
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
            if ($requireHttps && $this->request->getScheme() !== 'https') {
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
            syslog(LOG_ERR, 'Blank VPN ' . $error::class . ' at ' . basename($error->getFile()) . ':' . $error->getLine());
        }
        return ['ok' => false, 'error' => 'Blank VPN could not complete this operation.'];
    }
}
