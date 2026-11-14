<?php

namespace OPNsense\BlankVpn\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\DeviceIdentity;
use OPNsense\BlankVpn\Diagnostics;
use OPNsense\BlankVpn\Firewall;
use OPNsense\BlankVpn\Ivpn;
use OPNsense\BlankVpn\Mullvad;
use OPNsense\BlankVpn\MystVpn;
use OPNsense\BlankVpn\NativeVpn;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\ProxyCatalog;
use OPNsense\BlankVpn\ProxyImport;
use OPNsense\BlankVpn\ProxyRuntime;
use OPNsense\BlankVpn\Resolver;
use OPNsense\BlankVpn\SmartRouting;
use OPNsense\BlankVpn\VpnProviders;
use OPNsense\BlankVpn\WireGuard;

class ServiceController extends ApiControllerBase
{
    private const MULLVAD_SESSION = 'blankvpn_mullvad_login';

    public function dashboardAction()
    {
        return $this->respond(function () {
            $model = new BlankVpn();
            $settings = Policy::settings($model);
            $routing = Policy::effectiveRouting($model);
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
            $lanInterfaces = array_diff($settings['interfaces'] ?: ['lan'], $settings['tailscaleInterfaces']);
            $discovery['devices'] = array_values(array_filter($discovery['devices'],
                static fn (array $device): bool => in_array($device['interface'], $lanInterfaces, true)));
            $reservationIndex = DeviceIdentity::index($diagnostics->reservations());
            foreach ($discovery['devices'] as &$device) {
                $reserved = DeviceIdentity::effective($device, $reservationIndex);
                $device['macBindingSupported'] = empty($device['addressConflict']) &&
                    ($reserved === $device['ipv4'] || !empty($device['leaseProvider']));
            }
            unset($device);
            $effectiveAssignments = Policy::routingAssignments($assignments, $diagnostics);
            $tailnet = $settings['tailscaleInstalled'] ? $diagnostics->tailnetStatus() : [];
            $settings['dashboardMagicDns'] = Resolver::magicDnsFromStatus($tailnet);
            $settings['tailscaleSetup'] = $diagnostics->nativeTailnetSetup($tailnet);
            $discovery['tailnetDevices'] = Diagnostics::tailnetPeers($tailnet);
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
                if (!empty($profile['disabled'])) {
                    $status['status'] = 'Disabled';
                } elseif (!$owned['ok']) {
                    $warnings[] = $profile['name'] . ': ' . $owned['error'];
                    $status['status'] = 'Native configuration changed';
                }
                $checked = $health[$id] ?? [];
                $profiles[$id] = array_intersect_key(
                    $profile,
                    array_flip(['id', 'name', 'relay', 'identity', 'interface', 'address6', 'dns', 'disabled', 'provider', 'providerLocation', 'providerServer'])
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
            $proxyNodes = [];
            $managedNord = [];
            try {
                $proxyNodes = $proxyRoutes !== [] ? ProxyCatalog::read()['nodes'] : [];
                $managedNord = ProxyCatalog::managedNord();
            } catch (\RuntimeException $error) {
                $warnings[] = $error->getMessage();
            }
            foreach ($proxyRoutes as $id => $route) {
                $route['name'] = $proxyNodes[$route['node']]['name'] ?? $route['name'];
                $managed = $managedNord[$route['node']] ?? [];
                unset($managedNord[$route['node']]);
                $checked = $health[$id] ?? [];
                $running = in_array($id, $proxyStatus['active'], true);
                $profiles[$id] = array_intersect_key($route, array_flip(['id', 'name', 'node', 'kind', 'core', 'protocol', 'interface'])) + [
                    'status' => $proxyStatus['errors'][$id] ?? ($running ? 'Local tunnel ready' : 'Proxy tunnel stopped'),
                    'reachability' => time() - ($checked['checkedAt'] ?? 0) > 300 ? 'unverified or stale'
                        : (($checked['probeSucceeded'] ?? false) ? 'proxy probe succeeded' : 'proxy probe failed')
                ] + $managed;
            }
            $gatewayNames = array_column($profiles, 'name', 'interface');
            foreach ($managedNord as $id => $server) {
                $profiles['proxy-' . $id] = ['id' => 'proxy-' . $id, 'node' => $id, 'kind' => 'proxy'] + $server;
            }
            $activeLists = SmartRouting::activeServices($routing, $services);
            $bypass = SmartRouting::usesBypass($routing);
            $multiActive = !$bypass && $activeLists !== [];
            foreach ($assignments as $id => $row) {
                $rule = $loaded[Policy::marker('device', $id)] ?? null;
                $guard = ($loaded[Policy::marker('kill', $id)]['action'] ?? '') === 'block';
                $gateway = $rule['gateway'] ?? null;
                $mode = Policy::mode($row);
                $applied = $gateway !== null ? ($gatewayNames[$gateway] ?? $gateway)
                    : ($guard ? 'Internet blocked' : match ($mode) {
                        'multi' => $multiActive ? 'Multi-Path domain lists' : 'Waiting for domain lists',
                        'full' => 'Using regular internet',
                        'full_multi' => 'Base route unavailable',
                        default => 'Regular internet'
                    });
                $row['mode'] = $mode;
                $row['killSwitch'] = Policy::killSwitch($row);
                $row['onDemand'] = Policy::onDemand($row);
                $row['bindMac'] = Policy::bindsMac($row);
                $row['effectiveIp'] = $effectiveAssignments[$id]['ip'];
                $row['paused'] = Policy::assignmentPaused($row);
                $assignments[$id] = $row + [
                    'device' => $row['interface'] . '/' . (($row['kind'] ?? '') === 'tailnet' ? $row['ip'] : $row['mac']),
                    'verified' => false,
                    'killSwitchActive' => $guard && $rule === null && $row['killSwitch'] && $row['effectiveIp'] !== '',
                    'appliedRoute' => match (true) {
                        $row['effectiveIp'] === '' => 'Waiting for DHCP reservation',
                        $row['interface'] === Policy::TAILSCALE_DEVICE && !$settings['tailscaleSetup']['ready'] =>
                            'Exit node setup needed',
                        $loaded === null => 'Firewall status unavailable',
                        $rule !== null && $row['bindMac'] && ($rule['source'] ?? '') !== $row['effectiveIp'] =>
                            'Waiting for firewall update',
                        default => $applied
                    }
                ];
            }
            $settings['networkRouting'] = [];
            if ($settings['enabled'] && $settings['coverage'] === 'network') {
                foreach ($routing['interfaces'] as $interface) {
                    $id = 'network:' . $interface;
                    $settings['networkRouting'][$interface] = [
                        'gateway' => $loaded[Policy::marker('device', $id)]['gateway'] ?? null,
                        'blocked' => ($loaded[Policy::marker('kill', $id)]['action'] ?? null) === 'block'
                            && empty($loaded[Policy::marker('device', $id)]['gateway'])
                    ];
                }
            }
            $learned = $activeLists !== [] && !$bypass ? SmartRouting::status() : [];
            foreach ($services as $id => &$service) {
                $service['learned'] = $learned[$id] ?? null;
                $service['routing'] = [];
                if (!isset($activeLists[$id])) {
                    continue;
                }
                if ($bypass) {
                    foreach ($routing['interfaces'] as $interface) {
                        $key = 'network:' . $interface;
                        $service['routing'][$interface] = [
                            'bypass' => ($loaded[Policy::marker('bypass', $key)]['action'] ?? '') === 'match',
                            'guard' => $settings['networkRouting'][$interface]['blocked'] ?? false
                        ];
                    }
                    continue;
                }
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
            $systemUser = self::nativeWritesAvailable() ? $this->accountUser() : null;
            $accountUser = $canManage ? $systemUser : null;
            $providers = new VpnProviders();
            $savedProviders = [];
            foreach (VpnProviders::LOGIN_PROVIDERS as $provider) {
                $savedProviders[$provider] = $accountUser !== null && $providers->hasSaved($provider, $accountUser);
            }
            $mystAuth = [];
            $ivpnAuth = [];
            if ($accountUser !== null) {
                try {
                    $mystAuth = (new MystVpn($accountUser))->authStatus();
                } catch (\RuntimeException $error) {
                    $discovery['warnings'][] = $error->getMessage();
                }
                try {
                    $ivpnAuth = (new Ivpn($accountUser))->authStatus();
                } catch (\RuntimeException $error) {
                    $discovery['warnings'][] = $error->getMessage();
                }
            }
            $savedProviders['mysterium'] = !empty($mystAuth['authenticated']);
            $savedProviders['ivpn'] = !empty($ivpnAuth['saved']);
            return $discovery + [
                'profiles' => array_values($profiles),
                'proxyCores' => ProxyRuntime::capabilities(),
                'canManageCores' => self::nativeWritesAvailable() && is_string($username) &&
                    $acl->isPageAccessible($username, '/api/blankvpn/core/status'),
                'canManageUpdates' => $systemUser !== null &&
                    $acl->isPageAccessible($username, '/api/blankvpn/update/status'),
                'canWriteUpdates' => $systemUser !== null && $acl->hasPrivilege($username, 'page-all') &&
                    !$acl->hasPrivilege($username, 'user-config-readonly'),
                'canManageBackups' => $systemUser !== null &&
                    $acl->isPageAccessible($username, '/api/blankvpn/backup/export') &&
                    !$acl->hasPrivilege($username, 'user-config-readonly'),
                'mullvadSignedIn' => $this->mullvadToken() !== null,
                'mullvadLoginSaved' => $accountUser !== null && (new Mullvad())->hasSavedAccount($accountUser),
                'vpnProviders' => VpnProviders::CATALOG,
                'providerAccounts' => $savedProviders,
                'mystAuth' => $mystAuth,
                'ivpnAuth' => $ivpnAuth,
                'nativeGateways' => $canManage ? array_values(NativeVpn::gateways()) : [],
                'assignments' => array_values($assignments),
                'settings' => $settings,
                'activeSmartInterfaces' => $routing['smartInterfaces'],
                'services' => array_values($services),
                'servicePresets' => SmartRouting::PRESETS,
                'canManage' => $canManage
            ];
        });
    }

    public function discoverDevicesAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $settings = Policy::settings(new BlankVpn());
            if ($settings['coverage'] === 'network') {
                return ['probed' => 0];
            }
            $interfaces = array_diff($settings['interfaces'] ?: ['lan'], $settings['tailscaleInterfaces']);
            return (new Diagnostics())->probeLanNeighbors($interfaces);
        }), true, true);
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
            return ['relay' => $relay['id']] + WireGuard::pingRelay($relay['ipv4']);
        }, true, true);
    }

    public function testExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $model = new BlankVpn();
            $route = Policy::routes($model)[$this->input('id', 64)] ?? null;
            if ($route === null) {
                throw new \DomainException('Select a configured exit.');
            }
            return $this->probeExit($model, $route);
        }), true, true);
    }

    public function testDeviceRouteAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $model = new BlankVpn();
            $settings = Policy::settings($model);
            $id = $this->input('id', 64);
            $assignment = Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics())[$id] ?? null;
            if (!$settings['enabled'] || $settings['coverage'] !== 'device' || $assignment === null ||
                $assignment['ip'] === '' || !Policy::usesBase(Policy::mode($assignment))) {
                throw new \DomainException('Assign a base server to this device before testing its route.');
            }
            $routes = Policy::routes($model);
            $assigned = $routes[$assignment['profile']] ?? null;
            if ($assigned === null) {
                throw new \DomainException('The assigned VPN or proxy is unavailable.');
            }
            $marker = Policy::marker('device', $id);
            $loaded = Firewall::loadedRules();
            $gateway = $loaded[$marker]['gateway'] ?? null;
            $backup = $assignment['failure'] === 'backup' ? ($routes[$assignment['backup']] ?? null) : null;
            $usingBackup = $gateway !== null && $gateway === ($backup['interface'] ?? null);
            $route = $usingBackup ? $backup : $assigned;
            $ruleLoaded = $gateway !== null && $gateway === ($route['interface'] ?? null);
            $probe = $this->probeExit($model, $route);
            $observed = 'inactive';
            if ($loaded === null) {
                $observed = 'unavailable';
            } elseif ($ruleLoaded) {
                try {
                    $observed = (new Diagnostics())->hasRoutedTraffic($assignment['ip'], $marker) ? 'seen' : 'unseen';
                } catch (\RuntimeException) {
                    $observed = 'unavailable';
                }
            }
            return $probe + ['deviceTraffic' => $observed, 'usingBackup' => $usingBackup];
        }), true, true);
    }

    private function probeExit(BlankVpn $model, array $route): array
    {
        if (($route['kind'] ?? '') === 'proxy') {
            return ProxyRuntime::testNode($route['node'], $route);
        }
        if (!self::routeConfigured($route)) {
            $detail = ($route['kind'] ?? '') === 'native' ? 'The attached OPNsense gateway changed.'
                : (WireGuard::check($route)['error'] ?? 'The WireGuard configuration is unavailable.');
            throw new \DomainException($detail);
        }
        $loaded = Firewall::loadedRules();
        if ($loaded === null) {
            throw new \RuntimeException('Blank VPN could not read the active firewall rules from configd.');
        }
        if (!Firewall::probePathInstalled($route, $loaded)) {
            Firewall::reload($model);
            if (!Firewall::probePathInstalled($route, Firewall::loadedRules() ?? [])) {
                throw new \RuntimeException('OPNsense did not load the protected test route. Check the exit gateway and firewall status.');
            }
        }
        return ($route['kind'] ?? '') === 'native'
            ? WireGuard::probeSource($route['address'])
            : WireGuard::probe($route, true);
    }

    public function testProxyNodeAction()
    {
        return $this->respond(fn () => Operations::exclusive(fn () =>
            ProxyRuntime::testNode($this->input('id', 64))
        ), true, true);
    }

    public function accountAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $user = $this->accountUser();
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
            $user = $this->accountUser();
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

    public function mullvadAccountStatusAction()
    {
        return $this->respond(function () {
            $token = $this->mullvadToken();
            if ($token === null) {
                throw new \DomainException('Sign in to Mullvad to refresh the device slot count.');
            }
            return (new Mullvad())->accountWithToken($token);
        }, false, true, true);
    }

    public function logoutMullvadAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $user = $this->accountUser();
            if ($user !== null) {
                (new Mullvad())->saveAccount($user, null);
                $this->session->remove(self::MULLVAD_SESSION);
            }
            return [];
        }), true, true, true);
    }

    private function accountUser(): ?string
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
        $user = $this->accountUser();
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
            $mullvad = new Mullvad();
            $token = $this->requireMullvadToken($mullvad);
            $model = new BlankVpn();
            $profiles = Policy::profiles($model);
            foreach ($profiles as $id => $profile) {
                if ($relayId !== '' && $profile['relay'] === $relayId) {
                    $saved = $mullvad->routerProfiles($token, [$id => $profile])[$id] ?? null;
                    if ($saved === null) {
                        throw new \DomainException('This server is linked to a different Mullvad account.');
                    }
                    if (!$saved['registered']) {
                        throw new \DomainException('Mullvad no longer lists this server’s device registration. Remove the saved server before adding it again.');
                    }
                    return ['profile' => $id, 'message' => 'This Mullvad server is already added.'];
                }
            }
            $relay = $this->relay($mullvad, $relayId);
            $dnsPort = Resolver::freePort(Policy::routes($model));
            WireGuard::preflight($relay['ipv4']);
            $occupiedKeys = array_unique([...array_column($profiles, 'identityKey'), ...WireGuard::identityKeys()]);
            $identity = $mullvad->registerRouterWithToken($token, $relayId, $occupiedKeys);
            return $this->addProfile($name, $relayId, $identity, $relay, $dnsPort)
                + ['message' => 'Mullvad server added. Choose it in Network Settings to route a device.'];
        }), true, true, true);
    }

    private function requireMullvadToken(Mullvad $mullvad): string
    {
        $account = $this->input('account', 64);
        if ($account !== '') {
            return $mullvad->authenticate($account)['token'];
        }
        $token = $this->mullvadToken();
        if ($token !== null) {
            return $token;
        }
        $user = $this->accountUser();
        $saved = $user === null ? null : $mullvad->savedAccount($user);
        if ($saved === null) {
            throw new \DomainException('Sign in to Mullvad before adding a server.');
        }
        $login = $mullvad->authenticate($saved);
        $this->storeMullvadSession($user, $login);
        return $login['token'];
    }

    public function retargetProfileAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $relayId = $this->input('relay', 100);
            $model = new BlankVpn();
            $profiles = Policy::profiles($model);
            $mullvad = new Mullvad();
            $token = $this->requireMullvadToken($mullvad);
            $profile = isset($profiles[$id]) ? ($mullvad->routerProfiles($token, [$id => $profiles[$id]])[$id] ?? null) : null;
            if (empty($profile['registered'])) {
                throw new \DomainException('Choose a registered Mullvad tunnel linked to this account.');
            }
            foreach ($profiles as $candidateId => $candidate) {
                if ($candidateId !== $id && $candidate['relay'] === $relayId) {
                    throw new \DomainException('This Mullvad server is already added.');
                }
            }
            if ($profile['relay'] === $relayId) {
                return ['profile' => $id, 'message' => 'This Mullvad server is already added.'];
            }
            return $this->switchMullvadServer($profile, $relayId, $this->relay($mullvad, $relayId));
        }), true, true, true);
    }

    private function switchMullvadServer(array $profile, string $relayId, array $relay): array
    {
        $id = $profile['id'];
        $result = Operations::change(function (BlankVpn $model) use ($profile, $id, $relayId, $relay) {
            foreach (Policy::assignments($model) as $row) {
                if ($row['profile'] === $id || $row['backup'] === $id) {
                    throw new \DomainException('Move all devices off this tunnel before switching servers.');
                }
            }
            $this->requireUnusedByRouting($model, $id);
            $node = $model->profiles->profile->getChild($id);
            $ownership = WireGuard::retarget($profile, $relay);
            if (!empty($profile['disabled'])) {
                WireGuard::setEnabled($ownership, true);
            }
            unset($ownership['disabled']);
            unset($ownership['id'], $ownership['name'], $ownership['relay'], $ownership['registered']);
            $node->relay = $relayId;
            if ($profile['name'] === $profile['relay']) {
                $node->name = $relayId;
            }
            $node->ownership = json_encode($ownership, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $health = Firewall::health();
            unset($health[$id]);
            Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
            return ['id' => $id, 'added' => $ownership, 'reload' => true];
        });
        return ['profile' => $result['id'], 'message' => 'Mullvad server switched. The router kept its device registration.'];
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

    public function mystBeginAuthAction()
    {
        return $this->respond(fn () => Operations::exclusive(
            fn () => (new MystVpn($this->requireProviderUser()))->beginAuth()
        ), true, true, true);
    }

    public function mystPollAuthAction()
    {
        return $this->respond(fn () => Operations::exclusive(
            fn () => (new MystVpn($this->requireProviderUser()))->pollAuth()
        ), true, true, true);
    }

    public function mystLocationsAction()
    {
        return $this->respond(fn () => Operations::exclusive(
            fn () => (new MystVpn($this->requireProviderUser()))->locations(
                $this->input('ipType', 16, 'hosting'), $this->flag('refresh')
            )
        ), true, true, true);
    }

    public function addMystExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $model = new BlankVpn();
            foreach (Policy::routes($model) as $route) {
                if (($route['provider'] ?? '') === 'mysterium') {
                    throw new \DomainException('Remove the existing Mysterium VPN tunnel before adding another Mysterium location.');
                }
            }
            $id = $this->input('server', 256);
            $myst = new MystVpn($this->requireProviderUser());
            $locations = $myst->locations($this->input('ipType', 16, 'hosting'))['locations'];
            $location = array_column($locations, null, 'id')[$id] ?? null;
            if ($location === null) {
                throw new \DomainException('Choose an available Mysterium VPN location.');
            }
            $name = $this->name($location['name']);
            $dnsPort = Resolver::freePort(Policy::routes($model));
            WireGuard::preflight();
            $dns = trim($this->input('dns', 64));
            $config = $myst->provision($location['countryCode'], $location['ipType'], $location['region'], $dns);
            if (!SmartRouting::canResolve($config)) {
                throw new \DomainException('This Mysterium configuration did not provide IPv4 DNS. Enter an IPv4 DNS resolver and try again.');
            }
            $identity = $config;
            $identity['publicKey'] = $config['identityPublicKey'];
            $config['name'] = $location['name'];
            $result = $this->addProfile($name, '', $identity, $config, $dnsPort, 'mysterium', $id);
            try {
                $myst->completeProvision($config['provisionReceipt']);
            } catch (\RuntimeException) {
                $result['warning'] = 'The tunnel was added. Blank VPN could not clear the temporary Mysterium setup record.';
            }
            return $result;
        }), true, true, true);
    }

    public function ivpnLoginAction()
    {
        return $this->respond(fn () => Operations::exclusive(
            fn () => (new Ivpn($this->requireProviderUser()))->login(
                trim($this->input('account', 64)), trim($this->input('confirmation', 16))
            )
        ), true, true, true);
    }

    public function ivpnServersAction()
    {
        return $this->respond(function () {
            $ivpn = new Ivpn($this->requireProviderUser());
            $status = $ivpn->authStatus(true);
            if (empty($status['authenticated'])) {
                throw new \DomainException($status['message'] ?? 'Sign in to IVPN before choosing a server.');
            }
            $servers = $ivpn->servers(trim($this->input('country', 8)));
            $choices = [];
            foreach ($servers as $id => $server) {
                $choices[] = ['id' => $id, 'name' => $server['name']];
            }
            return ['servers' => $choices];
        }, true, true, true);
    }

    public function addIvpnExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('server', 96);
            $model = new BlankVpn();
            foreach (Policy::profiles($model) as $profile) {
                if (($profile['provider'] ?? '') !== 'ivpn' || empty($profile['providerLocation'])) {
                    continue;
                }
                if ($profile['providerLocation'] === $id) {
                    return ['profile' => $profile['id'], 'message' => 'This IVPN server is already added.'];
                }
                throw new \DomainException('Remove the existing account-based IVPN tunnel before adding a different IVPN server.');
            }
            $ivpn = new Ivpn($this->requireProviderUser());
            $dnsPort = Resolver::freePort(Policy::routes($model));
            WireGuard::preflight();
            [$identity, $relay] = $ivpn->configuration($id, trim($this->input('country', 8)));
            return $this->addProfile($this->name($relay['name']), '', $identity, $relay, $dnsPort, 'ivpn', $id);
        }), true, true, true);
    }

    public function providerLoginAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $provider = VpnProviders::validate($this->input('provider', 32), true);
            $user = $this->requireProviderUser();
            $credentials = [
                'username' => trim($this->input('username', 32)),
                'secret' => $provider === 'pia' ? $this->input('secret', 512) : trim($this->input('secret', 512))
            ];
            $providers = new VpnProviders();
            $providers->authenticate($provider, $credentials);
            $providers->save($provider, $user, $credentials);
            return ['saved' => true];
        }), true, true, true);
    }

    public function providerLogoutAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $provider = $this->input('provider', 32);
            $user = $this->requireProviderUser();
            if ($provider === 'mysterium') {
                (new MystVpn($user))->logout();
            } elseif ($provider === 'ivpn') {
                foreach (Policy::profiles(new BlankVpn()) as $profile) {
                    if (($profile['provider'] ?? '') === 'ivpn' && !empty($profile['providerLocation'])) {
                        throw new \DomainException('Remove the account-based IVPN tunnel before signing out to keep its active connection intact.');
                    }
                }
                (new Ivpn($user))->logout();
            } else {
                (new VpnProviders())->save(VpnProviders::validate($provider, true), $user, null);
            }
            return [];
        }), true, true, true);
    }

    private function requireProviderUser(): string
    {
        $user = $this->accountUser();
        if ($user === null) {
            throw new \DomainException('Sign in to the OPNsense WebGUI over HTTPS to manage VPN accounts.');
        }
        return $user;
    }

    private function providerAccount(VpnProviders $providers, string $provider): array
    {
        $credentials = $providers->saved($provider, $this->requireProviderUser());
        if ($credentials === null) {
            throw new \DomainException('Sign in and save your login before choosing a server.');
        }
        return $providers->authenticate($provider, $credentials);
    }

    public function providerServersAction()
    {
        return $this->respond(function () {
            $provider = VpnProviders::validate($this->input('provider', 32), true);
            $providers = new VpnProviders();
            $servers = $providers->servers($provider, $this->providerAccount($providers, $provider),
                trim($this->input('country', 8)));
            $choices = [];
            foreach ($servers as $id => $server) {
                $choices[] = ['id' => $id, 'name' => $server['name']];
            }
            return ['servers' => $choices];
        }, true, true, true);
    }

    public function addProviderExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $provider = VpnProviders::validate($this->input('provider', 32), true);
            $id = $this->input('server', 96);
            $model = new BlankVpn();
            $useNordRuntime = false;
            foreach (Policy::profiles($model) as $profile) {
                if (($profile['provider'] ?? '') !== $provider) {
                    continue;
                }
                if (($profile['providerLocation'] ?? '') === $id) {
                    return ['profile' => $profile['id'], 'message' => 'This server is already added.'];
                }
                $useNordRuntime = $provider === 'nord';
            }
            if ($provider === 'nord') {
                $nodes = ProxyCatalog::managedNord();
                foreach ($nodes as $node) {
                    if ($node['providerLocation'] === $id) {
                        $route = array_column(ProxyRuntime::routes($model), null, 'node')[$node['id']] ?? [];
                        return ['profile' => $route['id'] ?? 'proxy-' . $node['id'], 'message' => 'This NordVPN server is already added.'];
                    }
                }
                $useNordRuntime = $useNordRuntime || $nodes !== [];
            }
            $providers = new VpnProviders();
            $auth = $this->providerAccount($providers, $provider);
            $servers = $providers->servers($provider, $auth, trim($this->input('country', 8)));
            $server = $servers[$id] ?? null;
            if ($server === null) {
                throw new \DomainException('Refresh the provider server list and choose an available server.');
            }
            $name = $this->name($server['name']);
            if ($useNordRuntime) {
                ProxyRuntime::preflight('mihomo');
                WireGuard::preflight($server['ipv4']);
                [$identity, $relay] = $providers->configuration($provider, $auth, $id, $server);
                $node = VpnProviders::nordProxyNode($identity, $relay, $id);
                $node['name'] = $name;
                $node['customName'] = true;
                $saved = ProxyCatalog::saveManagedNord($node);
                return ['profile' => 'proxy-' . $saved['id']];
            }
            $dnsPort = Resolver::freePort(Policy::routes($model));
            WireGuard::preflight($server['ipv4'] ?? null);
            [$identity, $relay] = $providers->configuration($provider, $auth, $id, $server);
            return $this->addProfile($name, '', $identity, $relay, $dnsPort, $provider, $id);
        }), true, true, true);
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
            $provider = VpnProviders::validate($this->input('provider', 32, 'other'));
            return $this->addProfile($this->name(), '', $identity, $config, $dnsPort, $provider);
        }), true, true, true);
    }

    private function addProfile(
        string $name,
        string $relayId,
        array $identity,
        array $relay,
        int $dnsPort,
        string $provider = '',
        string $location = ''
    ): array {
        $result = Operations::change(function (BlankVpn $model) use ($name, $relayId, $identity, $relay, $dnsPort, $provider, $location) {
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
            if ($provider !== '') {
                $ownership['provider'] = $provider;
            }
            if ($location !== '') {
                $ownership['providerLocation'] = $location;
                $ownership['providerServer'] = $relay['name'];
            }
            if (isset($identity['accountBinding'])) {
                $ownership['accountBinding'] = $identity['accountBinding'];
            }
            $ownership['dns'] = array_values(array_slice($identity['dns'] ?? [], 0, 4));
            $node->name = $name;
            $node->relay = $relayId;
            $node->ownership = json_encode($ownership, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            return ['id' => $id, 'added' => $ownership, 'reload' => true];
        });
        return ['profile' => $result['id']];
    }

    public function addNativeExitAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $name = $this->name();
            $provider = VpnProviders::validate($this->input('provider', 32, 'other'));
            $id = $this->input('gateway', 64);
            $dns = trim($this->input('dns', 64));
            $gateway = NativeVpn::gateways()[$id] ?? null;
            if ($gateway === null || !filter_var($dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                Policy::contains('127.0.0.0/8', $dns) || Policy::contains('224.0.0.0/4', $dns) ||
                in_array($dns, ['0.0.0.0', '255.255.255.255'], true)) {
                throw new \DomainException('Choose a configured tunnel gateway and enter its IPv4 DNS resolver.');
            }
            return Operations::change(function (BlankVpn $model) use ($name, $id, $dns, $gateway, $provider) {
                foreach (Policy::routes($model) as $existing) {
                    if (($existing['interface'] ?? '') === $gateway['interface']) {
                        throw new \DomainException('This tunnel interface already has an exit.');
                    }
                }
                $port = Resolver::freePort(Policy::routes($model));
                $node = $model->nativeRoutes->route->add();
                $node->name = $name;
                $node->provider = $provider;
                $node->gatewayId = $id;
                $node->gatewayName = $gateway['gateway'];
                $node->device = $gateway['interface'];
                $node->logicalInterface = $gateway['logicalInterface'];
                $node->protocol = $gateway['protocol'];
                $node->dns = $dns;
                $node->dnsPort = (string)$port;
                return ['profile' => (string)$node->getAttribute('uuid'), 'reload' => true];
            });
        }), true, true);
    }

    public function renameProfileAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $name = $this->name();
            return Operations::change(function (BlankVpn $model) use ($id, $name) {
                $route = Policy::profiles($model)[$id] ?? NativeVpn::routes($model)[$id] ?? null;
                if ($route === null) {
                    throw new \DomainException('This VPN exit is no longer saved.');
                }
                $node = ($route['kind'] ?? '') === 'native'
                    ? $model->nativeRoutes->route->getChild($id)
                    : $model->profiles->profile->getChild($id);
                $node->name = $name;
                return [];
            });
        }), true, true);
    }

    public function renameProxyNodeAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            ProxyCatalog::renameNode($this->input('id', 64), $this->input('name', 256));
            return [];
        }), true, true);
    }

    public function setMullvadEnabledAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $this->setMullvadTunnelEnabled($this->input('id', 64), $this->flag('enabled'));
            return [];
        }), true, true);
    }

    private function setMullvadTunnelEnabled(string $id, bool $enabled): void
    {
        Operations::change(function (BlankVpn $model) use ($id, $enabled) {
            $profile = Policy::profiles($model)[$id] ?? null;
            if ($profile === null || $profile['relay'] === '') {
                throw new \DomainException('Choose a saved Mullvad server.');
            }
            if ($enabled === empty($profile['disabled'])) {
                return [];
            }
            if (!$enabled) {
                $this->requireUnusedByRouting($model, $id);
                foreach (Policy::assignments($model) as $row) {
                    if (in_array($id, [$row['profile'], $row['backup']], true)) {
                        throw new \DomainException('Remove this server from device rules before disabling it.');
                    }
                }
            }
            WireGuard::setEnabled($profile, $enabled);
            $ownership = array_diff_key($profile, array_flip(['id', 'name', 'relay']));
            $ownership['disabled'] = !$enabled;
            $model->profiles->profile->getChild($id)->ownership = json_encode($ownership, JSON_THROW_ON_ERROR);
            return [$enabled ? 'added' : 'removed' => $ownership, 'reload' => true];
        });
    }

    public function removeManagedNordAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            if (!isset(ProxyCatalog::managedNord()[$id])) {
                throw new \DomainException('This NordVPN server is no longer saved.');
            }
            $route = array_column(ProxyRuntime::routes(new BlankVpn()), null, 'node')[$id] ?? null;
            if ($route !== null) {
                Operations::change(function (BlankVpn $model) use ($route) {
                    $profileId = $route['id'];
                    $this->requireUnusedByRouting($model, $profileId);
                    foreach (Policy::assignments($model) as $row) {
                        if (in_array($profileId, [$row['profile'], $row['backup']], true)) {
                            throw new \DomainException('Remove this server from device rules before deleting it.');
                        }
                    }
                    $model->proxyRoutes->route->del($profileId);
                    return ['reload' => Policy::settings($model)['enabled']];
                });
            }
            ProxyCatalog::removeManagedNord($id);
            return [];
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
                    return ['reload' => true];
                }
                if ($profile['relay'] !== '' && !empty($profile['accountBinding'])) {
                    (new Mullvad())->rememberRouterKey($profile['accountBinding'], WireGuard::ownedPrivateKey($profile));
                }
                WireGuard::remove($profile);
                $model->profiles->profile->del($id);
                return ['removed' => $profile, 'reload' => true];
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
                !in_array($networkMode, ['full', 'multi', 'full_multi', 'blocked', 'disabled'], true)) {
                throw new \DomainException('Choose a coverage scope and routing mode.');
            }
            if ($coverage !== 'network' || !Policy::usesBase($networkMode)) {
                $networkProfile = '';
            }
            if ($networkMode === 'full_multi') {
                $networkKillSwitch = '1';
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
            if ($enabled && $interfaces === [] && ($coverage !== 'device' || !Policy::nativeTailnetConfigured())) {
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
                $route = [];
                if ($coverage === 'network') {
                    $segments = array_values(array_diff($interfaces, $tailscale));
                    if ($enabled && $networkMode !== 'disabled') {
                        if ($segments === []) {
                            throw new \DomainException('Choose a LAN or VLAN for Whole-Network coverage.');
                        }
                        Policy::segmentNetworks($segments);
                    }
                    if ($enabled && Policy::usesBase($networkMode)) {
                        $networkProfile = $this->resolveProxyChoice($model, $networkProfile);
                        $route = Policy::routes($model)[$networkProfile] ?? [];
                        if ($route === [] || !SmartRouting::canResolve($route) || !self::routeConfigured($route)) {
                            throw new \DomainException('Choose a configured VPN tunnel or an enabled proxy with DNS for Whole-Network coverage.');
                        }
                    }
                }
                $reset = [];
                $assignments = Policy::routingAssignments(Policy::assignments($model), new Diagnostics());
                foreach ($assignments as $row) {
                    $nativeTailnet = ($row['kind'] ?? '') === 'tailnet' && $row['interface'] === Policy::TAILSCALE_DEVICE;
                    if (!$nativeTailnet && !in_array($row['interface'], $interfaces, true)) {
                        throw new \DomainException('Remove saved assignments before removing their managed interface.');
                    }
                    $mode = Policy::mode($row);
                    if (($row['kind'] ?? '') === 'tailnet' && $row['interface'] !== Policy::TAILSCALE_DEVICE &&
                        !in_array($row['interface'], $tailscale, true)) {
                        throw new \DomainException('Remove the saved Tailscale assignments before removing their transit interface.');
                    }
                    if ($mode === 'multi' && in_array($row['interface'], $strict, true)) {
                        throw new \DomainException('Remove Multi-Path device rules before enabling Block devices without a rule on their interface.');
                    }
                    if ($enabled && $coverage === 'device' && !Policy::assignmentPaused($row) &&
                        (!$before['enabled'] || $before['coverage'] !== 'device') &&
                        ($nativeTailnet || $mode === 'blocked' ||
                        ($mode === 'full' && $row['failure'] !== 'wan') || Policy::killSwitch($row))) {
                        if ($row['ip'] !== '') {
                            $reset[] = $row['ip'];
                        }
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
                $combinedSegments = $networkChanged && ($before['networkMode'] === 'full_multi' || $networkMode === 'full_multi')
                    ? array_values(array_unique([...$oldNetwork, ...$newNetwork])) : [];
                if ($combinedSegments !== []) {
                    array_push($reset, ...Policy::segmentNetworks($combinedSegments));
                }
                return [
                    'reload' => $before['enabled'] || $enabled,
                    'resetSegments' => array_values(array_unique(array_merge(
                        $newStrict, $networkChanged && $combinedSegments === [] ? [...$oldNetwork, ...$newNetwork] : []
                    ))),
                    'killSwitchReset' => array_values(array_unique($reset)),
                    'networkProxy' => $newNetwork !== [] && Policy::usesBase($networkMode) &&
                        ($route['kind'] ?? '') === 'proxy' ? $route : null,
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
            $dashboardName = $bind === 'tailnet' ? Resolver::magicDnsName() : $hostname;
            Operations::change(function (BlankVpn $model) use ($hostname, $bind, $tailscale, $dashboardName) {
                $before = Policy::settings($model);
                $this->validateTransitInterfaces($tailscale, $before['interfaces'], $before['strictInterfaces']);
                foreach (Policy::assignments($model) as $row) {
                    if (($row['kind'] ?? '') === 'tailnet' && $row['interface'] !== Policy::TAILSCALE_DEVICE &&
                        !in_array($row['interface'], $tailscale, true)) {
                        throw new \DomainException('Remove the saved Tailscale device rules before unchecking their interface.');
                    }
                }
                $model->settings->tailscaleInterfaces = implode(',', $tailscale);
                $model->settings->hostname = $hostname;
                $model->settings->dashboardBind = $bind;
                Resolver::allowDashboardHostname(Config::getInstance()->object(), $dashboardName);
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
                $combined = $after['coverage'] === 'network' && $after['networkMode'] === 'full_multi';
                return [
                    'reload' => $after['enabled'],
                    'resetSegments' => $combined ? [] : $reset,
                    'killSwitchReset' => $combined ? Policy::segmentNetworks($reset) : [],
                    'settings' => $after
                ];
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
            if ($kind === 'tailnet' && $interface === '') {
                $interface = Policy::TAILSCALE_DEVICE;
            }
            $nativeTailnet = $kind === 'tailnet' && $interface === Policy::TAILSCALE_DEVICE;
            $label = trim($this->input('label', 120));
            $profile = $this->input('profile', 80);
            $backup = $this->input('backup', 80);
            $mode = $this->input('mode', 12, $profile === '' ? 'default' : 'full');
            if (!in_array($mode, ['full', 'multi', 'full_multi', 'disabled', 'blocked', 'default'], true) ||
                !in_array($kind, ['lan', 'tailnet'], true) || (Policy::usesBase($mode) && $profile === '')) {
                throw new \DomainException('Choose a valid routing mode. Select an exit if you use one VPN or proxy.');
            }
            $profile = Policy::usesBase($mode) ? $profile : '';
            $killSwitch = $this->request->hasPost('killSwitch')
                ? ($this->flag('killSwitch') ? '1' : '0') : null;
            $failure = $profile === '' ? 'block' : $this->input('failure', 12, $killSwitch === '0' ? 'wan' : 'block');
            if ($mode === 'full_multi') {
                $killSwitch = '1';
                $failure = 'block';
            } elseif ($mode === 'full' && $killSwitch === '1') {
                $failure = 'block';
            } elseif ($mode === 'full' && $killSwitch === '0' && $failure === 'block') {
                $failure = 'wan';
            }
            if (
                !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
                ($kind === 'lan' && !Policy::validMac($mac)) ||
                (!$nativeTailnet && !Policy::interfaceId($interface)) || !Policy::failure($failure) ||
                !preg_match('/^[^\p{C}<>]{0,100}$/uD', $label)
            ) {
                throw new \DomainException('Choose a valid reserved IPv4 device, interface and routing policy.');
            }
            if ($kind === 'tailnet' && (!Policy::tailnetAddress($ip) ||
                (!$nativeTailnet && !Policy::tailnetAddress($ipv6, true)))) {
                throw new \DomainException($nativeTailnet ? 'Enter the iPad or other device’s Tailscale IPv4 address.'
                    : 'Enter both the Tailscale IPv4 and IPv6 addresses for this peer.');
            }
            if ($nativeTailnet) {
                $diagnostics = new Diagnostics();
                $status = $diagnostics->tailnetStatus();
                $setup = $diagnostics->nativeTailnetSetup($status);
                if (!$setup['ready']) {
                    throw new \DomainException($setup['reason']);
                }
                $peer = $diagnostics->tailnetPeer($ip, $status);
                if ($peer === null) {
                    throw new \DomainException('OPNsense could not verify this Tailscale peer and both addresses. Open Tailscale on the device, confirm its IPv4 address, and try again.');
                }
                $ipv6 = $peer['ipv6'][0];
                $label = $label !== '' ? $label : ($peer['name'] ?? '');
            }
            $provider = '';
            $bindMac = $kind === 'lan' && $this->request->hasPost('bindMac')
                ? ($this->flag('bindMac') ? '1' : '0') : null;
            $onDemand = $this->request->hasPost('onDemand')
                ? ($this->flag('onDemand') ? '1' : '0') : null;
            if ($kind === 'lan') {
                $diagnostics = new Diagnostics();
                if ($bindMac === '1') {
                    $ip = DeviceIdentity::reservation($interface, $mac, $diagnostics->reservations()) ?? $ip;
                }
                if (!$diagnostics->hasReservation($interface, $ip, $mac)) {
                    if ($this->flag('reserveIp') || $bindMac === '1') {
                        $provider = $diagnostics->reservationProvider($interface, $ip, $mac);
                    }
                    if ($provider === '') {
                        throw new \DomainException('A DHCP reservation is required. Refresh to reserve the device’s current lease, or create a reservation in OPNsense.');
                    }
                }
            }
            $result = Operations::change(function (BlankVpn $model) use (
                $ip, $ipv6, $mac, $kind, $mode, $interface, $label, $profile, $backup, $failure, $killSwitch, $provider, $nativeTailnet, $bindMac, $onDemand
            ) {
                $settings = Policy::settings($model);
                if (!$nativeTailnet && !in_array($interface, $settings['interfaces'], true)) {
                    throw new \DomainException('Add this device’s LAN or VLAN under Routing settings before saving the policy.');
                }
                if ($kind === 'tailnet' && !$nativeTailnet && (!in_array($interface, $settings['tailscaleInterfaces'], true) ||
                    !Policy::tailnetInterface($interface))) {
                    throw new \DomainException('Select a configured Tailscale transit interface that preserves peer addresses.');
                }
                if ($mode === 'multi' && in_array($interface, $settings['strictInterfaces'], true)) {
                    throw new \DomainException('Turn off Block devices without a rule on this interface to use Multi-Path.');
                }
                $profile = $this->resolveProxyChoice($model, $profile);
                $backup = $failure === 'backup' ? $this->resolveProxyChoice($model, $backup, [$profile]) : '';
                $profiles = Policy::routes($model);
                if ($profile !== '' && (!isset($profiles[$profile]) || !self::routeConfigured($profiles[$profile]) ||
                    ($mode === 'full_multi' && !SmartRouting::canResolve($profiles[$profile])))) {
                    throw new \DomainException('The selected exit is missing or its configuration has changed.');
                }
                if ($failure === 'backup' && ($backup === $profile || !isset($profiles[$backup]) || !self::routeConfigured($profiles[$backup]))) {
                    throw new \DomainException('Choose a different, configured backup exit.');
                }
                $node = null;
                $prior = [];
                $configuredAssignments = Policy::assignments($model);
                $effectiveAssignments = Policy::routingAssignments($configuredAssignments, new Diagnostics());
                foreach ($configuredAssignments as $id => $row) {
                    if ($row['interface'] !== $interface) {
                        continue;
                    }
                    $tailnet = ($row['kind'] ?? '') === 'tailnet';
                    if ($kind === 'tailnet' && $tailnet && $row['ip'] === $ip ||
                        $kind === 'lan' && !$tailnet && $row['mac'] === $mac) {
                        $node = $model->assignments->assignment->getChild($id);
                        $prior = $effectiveAssignments[$id];
                    } elseif ($effectiveAssignments[$id]['ip'] === $ip || ($ipv6 !== '' && ($row['ipv6'] ?? '') === $ipv6)) {
                        throw new \DomainException('This address already has an assignment on the selected interface.');
                    }
                }
                if ($provider !== '') {
                    (new Diagnostics())->reserveDevice($provider, $interface, $ip, $mac);
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
                $node->bindMac = $kind === 'lan' ? $bindMac ?? ($prior['bindMac'] ?? '0') : '0';
                $node->onDemand = $onDemand ?? ($prior['onDemand'] ?? '1');
                // Older clients express the one-exit policy through failure instead of a checkbox.
                $node->killSwitch = $killSwitch ?? ($mode === 'multi' ? ($prior['killSwitch'] ?? '') : '');
                $changed = ($prior['ip'] ?? '') !== $ip || ($prior['ipv6'] ?? '') !== $ipv6 ||
                    Policy::mode($prior) !== $mode || ($prior['profile'] ?? '') !== $profile ||
                    ($prior['backup'] ?? '') !== ($failure === 'backup' ? $backup : '') ||
                    ($prior['failure'] ?? '') !== $failure ||
                    Policy::killSwitch($prior) !== Policy::killSwitch(Policy::fields($node)) ||
                    Policy::bindsMac($prior) !== Policy::bindsMac(Policy::fields($node));
                $live = $settings['enabled'] && !Policy::assignmentPaused($prior);
                return [
                    'settings' => $settings, 'reload' => $live, 'dhcpProvider' => $provider,
                    'killSwitchReset' => $live && $changed ?
                        array_values(array_unique(array_filter([$ip, $ipv6, $prior['ip'] ?? '', $prior['ipv6'] ?? '']))) : []
                ];
            });
            $reset = $result['killSwitchReset'] !== [];
            $result = ['applied' => $result['reload'], 'killSwitchReset' => $reset];
            if ($provider !== '') {
                $result['message'] = 'IP address reserved and device rule saved.';
            }
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

    public function setTailnetRuleEnabledAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            if (!$this->request->hasPost('enabled')) {
                throw new \DomainException('Choose whether to enable or disable this Tailscale rule.');
            }
            $enable = $this->flag('enabled');
            $result = Operations::change(function (BlankVpn $model) use ($id, $enable) {
                $row = Policy::assignments($model)[$id] ?? null;
                if (($row['kind'] ?? '') !== 'tailnet') {
                    throw new \DomainException('Select a saved Tailscale rule.');
                }
                if (Policy::assignmentPaused($row) === !$enable) {
                    return ['killSwitchReset' => []];
                }
                $settings = Policy::settings($model);
                $live = $settings['enabled'] && $settings['coverage'] === 'device';
                if ($enable && $live && $row['interface'] === Policy::TAILSCALE_DEVICE) {
                    $diagnostics = new Diagnostics();
                    $setup = $diagnostics->nativeTailnetSetup($diagnostics->tailnetStatus());
                    if (!$setup['ready']) {
                        throw new \DomainException($setup['reason']);
                    }
                }
                $model->assignments->assignment->getChild($id)->paused = $enable ? '0' : '1';
                return [
                    'reload' => $live,
                    'killSwitchReset' => $live ? array_values(array_filter([$row['ip'], $row['ipv6'] ?? ''])) : []
                ];
            });
            return ['killSwitchReset' => $result['killSwitchReset'] !== []];
        }), true, true);
    }

    public function removeAssignmentAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            $result = Operations::change(function (BlankVpn $model) use ($id) {
                $row = Policy::routingAssignments(Policy::assignments($model), new Diagnostics())[$id] ?? null;
                if ($row === null) {
                    throw new \DomainException('This device policy no longer exists.');
                }
                $model->assignments->assignment->del($id);
                $settings = Policy::settings($model);
                $nativeTailnet = $row['interface'] === Policy::TAILSCALE_DEVICE;
                return [
                    'ip' => $row['ip'], 'reload' => $settings['enabled'],
                    'killSwitchReset' => $settings['enabled'] && $nativeTailnet
                        ? array_values(array_filter([$row['ip'], $row['ipv6'] ?? ''])) : []
                ];
            });
            if ($result['killSwitchReset'] !== []) {
                return ['killSwitchReset' => true];
            }
            if ($result['reload'] && $result['ip'] !== '') {
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
            return $this->saveDomainList($id, $this->input('profile', 80), $name, $domains);
        }), true, true);
    }

    public function setServiceDestinationAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            if ($id === '') {
                throw new \DomainException('Choose a saved Multi-Path list.');
            }
            return $this->saveDomainList($id, $this->input('profile', 80));
        }), true, true);
    }

    private function saveDomainList(string $id, string $profileId, ?string $name = null, ?array $domains = null): array
    {
        return Operations::change(function (BlankVpn $model) use ($id, $name, $domains, $profileId) {
            $services = SmartRouting::services($model);
            $previous = $services[$id] ?? null;
            if ($id !== '' && $previous === null) {
                throw new \DomainException('This Multi-Path list no longer exists.');
            }
            if ($id === '' && count($services) >= SmartRouting::MAX_SERVICES) {
                throw new \DomainException('Remove an existing service before adding another.');
            }
            $domains ??= $previous['domains'];
            if ($profileId !== '') {
                $bypass = $profileId === SmartRouting::BYPASS;
                $sameMode = array_filter(SmartRouting::boundServices($services), static fn (array $service): bool =>
                    ($service['profile'] === SmartRouting::BYPASS) === $bypass);
                SmartRouting::checkOverlap($sameMode, $id, $domains);
                if (!$bypass) {
                    $profileId = $this->resolveProxyChoice($model, $profileId);
                    $profile = Policy::routes($model)[$profileId] ?? [];
                    if ($profile === [] || !SmartRouting::canResolve($profile) || !self::routeConfigured($profile)) {
                        throw new \DomainException('Select a configured VPN or proxy server with DNS support.');
                    }
                }
            }
            $node = $id === '' ? $model->services->service->add() : $model->services->service->getChild($id);
            if ($name !== null) {
                $node->name = $name;
                $node->domains = implode(',', $domains);
            }
            $node->profile = $profileId;
            $settings = Policy::effectiveRouting($model);
            $current = ['profile' => $profileId, 'domains' => $domains];
            $changed = $profileId !== ($previous['profile'] ?? '') || $domains !== ($previous['domains'] ?? []);
            $active = SmartRouting::active($settings, array_filter([$previous, $current]));
            return $this->serviceChange($model, $settings, $changed && $active);
        });
    }

    private function serviceChange(BlankVpn $model, array $settings, bool $reload): array
    {
        $reset = [];
        if ($reload) {
            $assignments = Policy::routingAssignments(Policy::assignments($model, true), new Diagnostics());
            $reset = Operations::combinedStateScopes($settings, $assignments);
        }
        return ['reload' => $reload, 'killSwitchReset' => $reset];
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
                $settings = Policy::effectiveRouting($model);
                return $this->serviceChange($model, $settings, SmartRouting::active($settings, [$service]));
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
            fn () => ProxyCatalog::import($this->input('body', ProxyImport::MAX_BYTES), $this->input('name', 256))
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
            $node['customName'] = true;
            ProxyCatalog::saveManual([$node['id'] => $node]);
            return ['id' => $node['id']];
        }), true, true, true);
    }

    public function addSubscriptionAction()
    {
        return $this->respond(fn () => Operations::exclusive(fn () => ProxyCatalog::addFeed(
            $this->input('name', 96),
            $this->input('url', ProxyCatalog::MAX_URL_BYTES),
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
            ProxyCatalog::setEnabled($this->input('id', 64), true);
            return [];
        }), true, true);
    }

    public function disableProxyNodeAction()
    {
        return $this->respond(fn () => Operations::exclusive(function () {
            $id = $this->input('id', 64);
            if (in_array($id, array_column(ProxyRuntime::routes(new BlankVpn()), 'node'), true)) {
                Operations::change(function (BlankVpn $model) use ($id) {
                    $routes = array_column(ProxyRuntime::routes($model), null, 'node');
                    $route = $routes[$id] ?? null;
                    if ($route !== null) {
                        $this->requireUnusedByRouting($model, $route['id']);
                        foreach (Policy::assignments($model) as $row) {
                            if (in_array($route['id'], [$row['profile'], $row['backup']], true)) {
                                throw new \DomainException('Remove this server from device rules before disabling it.');
                            }
                        }
                        $model->proxyRoutes->route->del($route['id']);
                    }
                    return ['reload' => Policy::settings($model)['enabled']];
                });
            }
            ProxyCatalog::setEnabled($id, false);
            return [];
        }), true, true);
    }

    private function resolveProxyChoice(BlankVpn $model, string $choice, array $keep = []): string
    {
        if (!preg_match('/^proxy-([a-f0-9]{64})$/D', $choice, $match)) {
            return $choice;
        }
        $id = $match[1];
        $node = ProxyCatalog::read()['nodes'][$id] ?? null;
        if ($node === null || !empty($node['disabled'])) {
            throw new \DomainException('Choose an enabled proxy server.');
        }
        $routes = ProxyRuntime::routes($model);
        foreach ($routes as $route) {
            if ($route['node'] === $id) {
                return $route['id'];
            }
        }
        ProxyRuntime::preflight($node['core']);
        ProxyRuntime::prepareTunnelDriver();
        $free = array_diff(range(0, ProxyRuntime::SLOTS - 1), array_column($routes, 'slot'));
        if ($free === []) {
            $used = [...$keep, Policy::settings($model)['networkProfile']];
            foreach (Policy::assignments($model) as $row) {
                array_push($used, $row['profile'], $row['backup']);
            }
            array_push($used, ...array_column(SmartRouting::services($model), 'profile'));
            foreach ($routes as $route) {
                if (!in_array($route['id'], $used, true)) {
                    $model->proxyRoutes->route->del($route['id']);
                    $free = [$route['slot']];
                    break;
                }
            }
        }
        if ($free === []) {
            throw new \DomainException('Eight proxy servers are already assigned. Remove an assignment to use another server.');
        }
        $route = $model->proxyRoutes->route->add();
        $route->name = $node['name'];
        $route->node = $id;
        $route->core = $node['core'];
        $route->protocol = $node['protocol'];
        $route->slot = (string)reset($free);
        return (string)$route->getAttribute('uuid');
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
            if ($allowRuntimeMessage && get_class($error) === \RuntimeException::class) {
                return ['ok' => false, 'error' => $error->getMessage()];
            }
            syslog(LOG_WARNING, 'Blank VPN operation did not complete.');
        } catch (\Throwable $error) {
            $reference = gmdate('His') . '-' . getmypid();
            syslog(LOG_ERR, 'Blank VPN ' . $reference . ' ' . get_class($error) . ' at ' .
                basename($error->getFile()) . ':' . $error->getLine());
            return ['ok' => false, 'error' => 'Blank VPN encountered an unexpected error. Log reference ' . $reference . '.'];
        }
        return ['ok' => false, 'error' => 'Blank VPN could not complete this operation.'];
    }
}
