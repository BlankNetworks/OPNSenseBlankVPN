(() => {
    'use strict';

    function start() {
        const byId = (id) => document.getElementById('bv-' + id);
        const root = document.getElementById('blankvpn');
        if (!root) {
            return;
        }

        const modes = {
            full: 'Use one VPN or proxy', multi: 'Multi-Path', full_multi: 'Base VPN + Multi-Path',
            disabled: 'Off', blocked: 'Blocked'
        };

        function usesBaseServer(mode) {
            return mode === 'full' || mode === 'full_multi';
        }

        function requireKillSwitch(control, required) {
            if (required && control.dataset.previousChecked === undefined) {
                control.dataset.previousChecked = String(control.checked);
                control.checked = true;
            } else if (!required && control.dataset.previousChecked !== undefined) {
                control.checked = control.dataset.previousChecked === 'true';
                delete control.dataset.previousChecked;
            }
        }
        const insecureWebGui = window.location.protocol === 'http:';
        const bypassDestination = 'bypass';
        let serviceOrder = new Intl.Collator(undefined, {sensitivity: 'base', numeric: true});
        const maxDomainBytes = 131072;
        const testDisplays = new WeakMap();
        const state = {
            profiles: [],
            selectedVpns: new Set(),
            selectedProxies: new Set(),
            assignments: [],
            devices: [],
            tailnetDevices: [],
            tailnetStatusAvailable: false,
            discoveryTruncated: false,
            proxyPage: 0,
            proxySortByPing: false,
            vpnSortByPing: false,
            vpnFixedOrder: null,
            proxyFixedOrder: null,
            bulkPing: {kind: '', sort: false, stop: false},
            proxyCatalogLoaded: false,
            proxyCatalogRequest: null,
            services: [],
            serviceTests: new Map(),
            proxyNodes: [],
            proxyFeeds: [],
            proxyCores: {},
            canManageCores: false,
            canManageUpdates: false,
            canWriteUpdates: false,
            canManageBackups: false,
            update: null,
            updateTimer: null,
            updateAction: '',
            backup: null,
            section: 'vpns',
            provider: 'mullvad',
            vpnProviders: {},
            providerAccounts: {},
            mystAuth: {},
            ivpnAuth: {},
            ivpnConfirmationAccount: '',
            nativeGateways: [],
            providerLocations: new Map(),
            serviceDestinations: new Map(),
            mullvadSignedIn: false,
            presets: {},
            editingService: null,
            domainRead: 0,
            relays: [],
            tests: new Map(),
            proxyTestRunning: false,
            nameEditor: null,
            settings: null,
            availableInterfaces: [],
            canManage: true,
            editing: null,
            assignmentDevice: null,
            networkDevice: null,
            busy: false,
            dashboardRequest: null,
            deviceAvailabilityRequest: null,
            deviceAvailabilityRevision: 0,
            deviceRefreshRunning: false,
            settingsDirty: false,
            tailnetRoutingDirty: false,
            catalogLoaded: false,
            signingIn: false,
            mullvadLoginSaved: false,
            restoreAttempted: false,
            tailscaleDirty: false,
            loginRevision: 0,
            activeSmartInterfaces: [],
            language: {locale: 'en_US', translations: {}}
        };

        function translated(source) {
            return state.language.translations?.[source] || source;
        }

        function applyLanguage(language) {
            if (!language || typeof language.locale !== 'string') {
                return;
            }
            state.language = language;
            root.lang = language.locale.replace('_', '-');
            root.dir = language.locale === 'fa_IR' ? 'rtl' : 'ltr';
            serviceOrder = new Intl.Collator(root.lang, {sensitivity: 'base', numeric: true});
            for (const element of root.querySelectorAll('[data-bv-i18n]')) {
                element.textContent = translated(element.dataset.bvI18n);
            }
        }

        function array(value) {
            if (Array.isArray(value)) {
                return value;
            }
            return value && typeof value === 'object' ? Object.values(value) : [];
        }

        function list(value) {
            if (Array.isArray(value)) {
                return value.filter(Boolean);
            }
            return String(value || '').split(/[,\n]/).map((item) => item.trim()).filter(Boolean);
        }

        function shown(value, fallback = 'Unknown') {
            return value === null || value === undefined || value === '' ? fallback : String(value);
        }

        function date(value) {
            if (!value || value === '0') {
                return 'Unknown';
            }
            const isNumber = typeof value === 'number' || /^\d+$/.test(String(value));
            const timestamp = Number(value);
            const parsed = new Date(isNumber ? (timestamp < 1e12 ? timestamp * 1000 : timestamp) : value);
            return Number.isNaN(parsed.getTime()) ? shown(value) : parsed.toLocaleString(state.language.locale.replace('_', '-'));
        }

        function errorMessage(error, fallback) {
            return error instanceof Error ? error.message : fallback;
        }

        async function api(action, payload, path = '', controller = 'service') {
            const method = payload === undefined ? 'GET' : 'POST';
            if (insecureWebGui && ['addProxyNode', 'addSubscription', 'importProxies', 'providerLogin', 'ivpnLogin', 'importProfile'].includes(action)) {
                throw new Error('Open the OPNsense WebGUI over HTTPS before submitting credentials or configuration files.');
            }
            const request = {
                url: '/api/blankvpn/' + controller + '/' + action + path,
                method,
                dataType: 'json',
                cache: false,
                timeout: controller === 'core' ? 240000 : controller === 'update' ? 90000 : 45000
            };
            if (payload instanceof FormData) {
                request.contentType = false;
                request.processData = false;
                request.data = payload;
            } else if (method === 'POST') {
                request.contentType = 'application/json; charset=UTF-8';
                request.data = JSON.stringify(payload);
            }
            let response;
            try {
                response = await window.jQuery.ajax(request);
            } catch (xhr) {
                const message = xhr?.responseJSON?.error || xhr?.responseJSON?.message;
                if (typeof message === 'string' && message) {
                    throw new Error(message);
                }
                if ([401, 403].includes(xhr?.status)) {
                    throw new Error('OPNsense denied this request. Check your session and privileges.');
                }
                if (method === 'POST' && !xhr?.status) {
                    const error = new Error('The router did not return a result. Refresh the dashboard to check what changed before retrying.');
                    error.ambiguous = true;
                    throw error;
                }
                throw new Error('The router did not return a readable result.');
            }
            const catalogWithCache = (['relays', 'refreshRelays'].includes(action) && Array.isArray(response?.relays))
                || (action === 'mystLocations' && Array.isArray(response?.locations) && response.locations.length > 0);
            if (response?.ok === false || (response?.error && !catalogWithCache)) {
                throw new Error(response.error || 'The operation failed.');
            }
            if (!response || (method === 'POST' && response.ok !== true && !catalogWithCache)) {
                throw new Error('The router returned an unrecognized response.');
            }
            return response;
        }

        function notice(text, type = 'info') {
            const status = byId('message');
            status.dataset.kind = type;
            byId('message-title').hidden = type !== 'danger';
            byId('message-detail').textContent = text;
            byId('message-dismiss').hidden = type !== 'danger' || !text;
            status.hidden = !text;
        }

        function cell(row, text, label, detail) {
            row.setAttribute('role', 'row');
            const target = row.insertCell();
            target.setAttribute('role', 'cell');
            target.textContent = shown(text, '—');
            if (label) {
                target.dataset.label = label;
            }
            if (detail) {
                const sub = document.createElement('small');
                sub.className = 'text-muted';
                sub.textContent = detail;
                target.append(sub);
            }
            return target;
        }

        function empty(body, text, columns = 6) {
            body.replaceChildren();
            const target = cell(body.insertRow(), text);
            target.colSpan = columns;
            target.className = 'bv-empty text-muted';
        }

        function serverControls(row) {
            const target = row.insertCell();
            target.setAttribute('role', 'cell');
            target.className = 'bv-server-actions-cell';
            const controls = document.createElement('div');
            controls.className = 'bv-server-controls';
            target.append(controls);
            return controls;
        }

        function button(label, callback, accessibleLabel) {
            const element = document.createElement('button');
            element.type = 'button';
            element.className = 'btn btn-default btn-sm';
            element.textContent = label;
            element.addEventListener('click', callback);
            if (accessibleLabel) {
                element.setAttribute('aria-label', accessibleLabel);
            }
            return element;
        }

        function nameEditor(row, name, id, action, render, onSave, renderDetails = null) {
            const edit = button('Edit', () => {
                state.nameEditor = {id, action, draft: name};
                render();
                root.querySelector('.bv-name-editor input')?.focus();
            }, 'Edit ' + (renderDetails ? 'name and WireGuard port' : 'name') + ' for ' + name);
            const current = state.nameEditor;
            if (current?.id !== id || current.action !== action) {
                return edit;
            }
            const form = document.createElement('form');
            form.className = 'bv-inline-form bv-name-editor';
            const input = document.createElement('input');
            input.className = 'form-control';
            input.required = true;
            input.maxLength = 64;
            input.value = current.draft;
            input.setAttribute('aria-label', 'Name for ' + name);
            input.addEventListener('input', () => { current.draft = input.value; });
            const save = document.createElement('button');
            save.type = 'submit';
            save.className = 'btn btn-primary btn-sm';
            save.textContent = 'Save name';
            const cancel = button('Cancel', () => {
                state.nameEditor = null;
                render();
            });
            form.append(input, save, cancel);
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                const renamed = input.value.trim();
                if (!renamed) {
                    input.focus();
                    return;
                }
                void mutate(save, () => api(action, {id, name: renamed}), 'Server name saved.', () => {
                    if (state.nameEditor === current) {
                        state.nameEditor = null;
                    }
                    onSave(renamed);
                    render();
                });
            });
            const nameCell = row.querySelector('[data-server-name]');
            nameCell.append(form);
            if (renderDetails) {
                nameCell.append(renderDetails(current));
            }
            return null;
        }

        function mullvadPortEditor(profile, editor) {
            const savedPort = Number(profile.port || 51820);
            const form = document.createElement('form');
            form.className = 'bv-inline-form bv-mullvad-port';
            const label = document.createElement('label');
            label.textContent = 'WireGuard port (UDP)';
            const select = document.createElement('select');
            select.className = 'form-control';
            select.append(new Option('51820 (default)', '51820'), new Option('53', '53'));
            select.value = String(editor.port ?? savedPort);
            label.append(select);
            const save = document.createElement('button');
            save.type = 'submit';
            save.className = 'btn btn-primary btn-sm';
            save.textContent = 'Save port';
            const updateSave = () => { save.disabled = Number(select.value) === savedPort; };
            select.addEventListener('change', () => {
                editor.port = Number(select.value);
                updateSave();
            });
            updateSave();
            const restore = button('Restore device', (event) =>
                void mutate(event.currentTarget, () => api('restoreMullvadDevice', {id: profile.id}),
                    'Mullvad device restored. Test this server again.', () => {
                        state.tests.delete('exit:' + profile.id);
                        state.nameEditor = null;
                    }),
            'Restore this saved WireGuard key in Mullvad if its registration was removed');
            form.append(label, save, restore);
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                const port = Number(select.value);
                if (![51820, 53].includes(port) || port === savedPort) {
                    return;
                }
                void mutate(save, () => api('setMullvadPort', {id: profile.id, port}),
                    'Mullvad WireGuard port saved.', (result) => {
                        profile.port = result.port;
                        state.tests.delete('exit:' + profile.id);
                        state.tests.delete('tailnet-base:' + profile.id);
                        for (const assignment of state.assignments) {
                            if ([assignment.profile, assignment.backup].includes(profile.id)) {
                                state.tests.delete('device:' + assignment.id);
                            }
                        }
                        renderProfiles();
                    });
            });
            return form;
        }

        function options(select, choices, placeholder, previous = select.value) {
            select.replaceChildren(new Option(placeholder, ''));
            const groups = new Map();
            for (const choice of choices) {
                const option = new Option(choice.label, choice.value);
                if (!choice.group) {
                    select.append(option);
                    continue;
                }
                if (!groups.has(choice.group)) {
                    const group = document.createElement('optgroup');
                    group.label = choice.group;
                    select.append(group);
                    groups.set(choice.group, group);
                }
                groups.get(choice.group).append(option);
            }
            select.value = choices.some((choice) => choice.value === previous) ? previous : '';
        }

        function providerName(profile) {
            if (state.vpnProviders[profile.provider]) {
                return state.vpnProviders[profile.provider].name;
            }
            if (profile.kind === 'proxy') {
                const core = {mihomo: 'Mihomo', xray: 'Xray', 'sing-box': 'sing-box'}[profile.core];
                return core ? core + ' proxies' : 'Proxy servers';
            }
            return profile.relay ? 'Mullvad' : 'Other VPN';
        }

        function compareServers(a, b) {
            return serviceOrder.compare(providerName(a), providerName(b))
                || serviceOrder.compare(a.name || a.id, b.name || b.id);
        }

        function exitChoice(profile) {
            return {value: profile.id, label: profile.name || profile.relay || profile.id, group: providerName(profile)};
        }

        function renderProvider() {
            const provider = state.provider;
            const details = state.vpnProviders[provider];
            const mullvad = provider === 'mullvad';
            const signedIn = state.providerAccounts[provider] === true && !insecureWebGui;
            const supportedLogin = Boolean(details?.login);
            const password = details?.login === 'password';
            const browserLogin = details?.login === 'browser';
            const ivpn = provider === 'ivpn';
            const nodes = byId('provider-panel');
            byId('mullvad-provider').hidden = !mullvad;
            nodes.hidden = mullvad || !details;
            if (nodes.hidden) {
                return;
            }
            byId('provider-title').textContent = details.name;
            const guide = byId('provider-guide');
            guide.parentElement.hidden = !details.guide;
            guide.href = details.guide || '#';
            byId('provider-login').hidden = signedIn || insecureWebGui || !supportedLogin || browserLogin || ivpn;
            byId('ivpn-login').hidden = !ivpn || signedIn || insecureWebGui;
            const totp = ivpn && state.ivpnAuth.challenge === 'totp';
            byId('ivpn-confirmation-field').hidden = !totp;
            byId('ivpn-confirmation').required = totp;
            byId('ivpn-account').required = !totp || !state.ivpnConfirmationAccount;
            byId('myst-login').hidden = signedIn || insecureWebGui || !browserLogin;
            const approve = byId('myst-approve');
            const approvalUrl = state.mystAuth.approvalUrl;
            const pending = state.mystAuth.pending === true && typeof approvalUrl === 'string'
                && approvalUrl.startsWith('https://app.mysteriumvpn.com/oauth/authorize?');
            approve.hidden = !pending;
            approve.href = pending ? approvalUrl : '#';
            byId('myst-poll').hidden = !pending;
            byId('myst-begin').hidden = pending;
            byId('provider-user-field').hidden = !password;
            byId('provider-user').required = password;
            byId('provider-secret-label').textContent = password ? 'PIA password'
                : provider === 'azire' ? 'AzireVPN API token' : 'NordVPN router login token';
            byId('provider-status').textContent = supportedLogin
                ? insecureWebGui ? translated('Open the OPNsense WebGUI over HTTPS to sign in.')
                    : signedIn ? (ivpn && state.ivpnAuth.message ? state.ivpnAuth.message : translated('Login saved on this router.'))
                    : browserLogin && pending ? translated('Approve the sign-in in Mysterium VPN, then select Check approval.')
                    : browserLogin && state.mystAuth.status === 'expired' ? translated('The approval link expired. Sign in again.')
                    : ivpn && state.ivpnAuth.message ? state.ivpnAuth.message
                    : translated('Sign in to load the provider’s WireGuard servers.')
                : 'Import a WireGuard profile or add a VPN tunnel already configured in OPNsense.';
            byId('provider-logout').hidden = !signedIn;
            byId('provider-server-form').hidden = !signedIn;
            byId('myst-type-field').hidden = !browserLogin;
            byId('myst-dns-field').hidden = !browserLogin;
            byId('provider-country-field').hidden = provider !== 'nord' && !ivpn;
            byId('provider-country').disabled = provider !== 'nord' && !ivpn;
            byId('provider-import').hidden = insecureWebGui || ['express', 'vypr'].includes(provider);
            const saved = new Set(state.profiles.filter((item) => item.provider === provider).map((item) => item.providerLocation));
            const current = state.providerLocations.get(provider);
            const country = browserLogin ? byId('myst-type').value
                : byId('provider-country').disabled ? '' : byId('provider-country').value.trim().toUpperCase();
            const choices = current?.country === country ? current.servers.map((server) => ({
                value: server.id, label: server.name + (saved.has(server.id) ? ' (saved)' : '')
            })) : [];
            options(byId('provider-server'), choices, choices.length ? 'Choose a server' : 'Load servers');
            byId('provider-save').disabled = !byId('provider-server').value || saved.has(byId('provider-server').value);
            options(byId('native-gateway'), state.nativeGateways.map((item) => ({
                value: item.id, label: item.gateway + ' · ' + item.protocol
            })), 'Choose a tunnel gateway');
        }

        async function loadProviderServers(refresh = false) {
            const provider = state.provider;
            if (provider === 'mullvad' || !state.providerAccounts[provider] || insecureWebGui) {
                return;
            }
            const field = byId('provider-country');
            if (!field.reportValidity()) {
                return;
            }
            const myst = provider === 'mysterium';
            const country = myst ? byId('myst-type').value : field.disabled ? '' : field.value.trim().toUpperCase();
            const reload = byId('provider-reload');
            if (reload.disabled) {
                return;
            }
            const status = byId('provider-server-status');
            reload.disabled = true;
            status.textContent = 'Loading servers…';
            try {
                const result = myst ? await api('mystLocations', {ipType: country, refresh})
                    : provider === 'ivpn' ? await api('ivpnServers', {country})
                    : await api('providerServers', {provider, country});
                const servers = array(myst ? result.locations : result.servers);
                state.providerLocations.set(provider, {country, servers});
                if (provider === state.provider) {
                    status.textContent = servers.length + (myst ? ' locations available.' : ' servers available.')
                        + (result.stale ? ' Showing the last available list.' : '');
                    renderProvider();
                }
            } catch (error) {
                if (provider === state.provider) {
                    status.textContent = '';
                    notice(errorMessage(error, 'The server list could not be loaded.'), 'danger');
                }
            } finally {
                reload.disabled = false;
            }
        }

        function renderUpdate(data) {
            state.update = {...data, pollUntil: data.pollUntil || state.update?.pollUntil ||
                (data.running ? Date.now() + 600000 : 0)};
            const status = byId('update-status');
            const message = state.updateAction === 'check' ? 'Checking for an update…'
                : state.updateAction === 'apply' ? 'Starting update…' : data.message;
            const summary = [data.installed ? 'Installed ' + data.installed : '',
                data.available ? 'Available ' + data.available : '', message];
            status.textContent = summary.filter(Boolean).join(' · ');
            byId('update-check').hidden = !state.canWriteUpdates;
            byId('update-apply').hidden = !state.canWriteUpdates;
            const disabled = !state.canWriteUpdates || !data.supported || data.running || !!state.updateAction;
            byId('update-check').disabled = disabled;
            byId('update-apply').disabled = disabled || !data.enabled || !data.available;
            clearTimeout(state.updateTimer);
            if (data.running) {
                state.updateTimer = window.setTimeout(() => void refreshUpdate(true), 4000);
            }
        }

        async function refreshUpdate(retry = false) {
            try {
                const result = await api('status', undefined, '', 'update');
                if (state.updateAction) {
                    return;
                }
                const previous = state.update;
                renderUpdate(result);
                if (previous?.running && !result.running) {
                    const installed = previous.installed && previous.installed !== result.installed;
                    notice(result.message || (installed ? 'Update installed.' : 'Update ended. Check package status.'),
                        result.phase === 'failed' ? 'danger' : 'success');
                }
            } catch (error) {
                if (retry && Date.now() < (state.update?.pollUntil || 0)) {
                    state.updateTimer = window.setTimeout(() => void refreshUpdate(true), 4000);
                    return;
                }
                notice(errorMessage(error, 'Could not read package update status.'), 'danger');
            }
        }

        function restoreAvailability() {
            const selected = Boolean(byId('backup-file').files[0]);
            const enabled = state.settings?.enabled === true;
            byId('backup-check').disabled = !selected || enabled || state.busy;
            byId('backup-restore').disabled = !state.backup || enabled || state.busy;
            if (enabled) {
                byId('backup-preview').textContent = 'Disable VPN routing in Network Settings before restoring a backup.';
            } else if (!state.backup) {
                byId('backup-preview').textContent = '';
            }
        }

        function renderSystem() {
            byId('system-updates').hidden = !state.canManageUpdates;
            byId('system-backups').hidden = !state.canManageBackups;
            restoreAvailability();
        }

        function showSection(section) {
            if (state.bulkPing.kind && section !== state.bulkPing.kind) {
                state.bulkPing.stop = true;
            }
            state.section = section;
            for (const button of root.querySelectorAll('[data-bv-section]')) {
                const active = button.dataset.bvSection === section;
                button.setAttribute('aria-pressed', String(active));
            }
            for (const panel of root.querySelectorAll('[data-bv-panel]')) {
                panel.hidden = panel.dataset.bvPanel !== section;
            }
            if (section === 'proxies' && state.canManage && !state.proxyCatalogLoaded) {
                void refreshProxyCatalog();
            }
            if (section === 'vpns') {
                restoreSavedLogin();
            }
            if (section === 'smart') {
                renderServices();
            }
            if (section === 'system') {
                renderSystem();
                if (state.canManageUpdates) {
                    void refreshUpdate();
                }
            }
            if (section === 'network') {
                renderDeviceRules();
            } else {
                byId('assignment').hidden = true;
                state.editing = null;
                closeNetworkDevice();
            }
        }

        function profileName(id) {
            const profile = state.profiles.find((item) => item.id === id);
            const proxy = typeof id === 'string' && id.startsWith('proxy-')
                ? state.proxyNodes.find((item) => 'proxy-' + item.id === id) : null;
            return id === bypassDestination ? 'Bypass (direct internet)'
                : profile?.name || profile?.relay || proxy?.name || (id ? 'Unavailable server' : 'Normal internet');
        }

        function networkName(id) {
            if (id === 'tailscale0') {
                return 'Tailscale exit node';
            }
            const entry = state.availableInterfaces.find((item) => item.id === id);
            if (!entry) {
                return shown(id);
            }
            return entry.device && entry.name !== entry.device
                ? [entry.device, entry.name].filter(Boolean).join(' · ') : (entry.device || entry.name || id);
        }

        function networkRouteStatus(route, mode) {
            if (route.statusKnown === false) {
                return 'Firewall status unavailable';
            }
            const server = state.profiles.find((profile) => profile.interface === route.gateway);
            const status = route.outage ? (mode === 'full_multi' ? 'Base server unavailable · Default traffic blocked'
                : 'Kill Switch blocking internet') : route.wanFallback ? 'Direct internet fallback'
                : server?.name || route.gateway || (route.blocked ? 'Internet blocked'
                    : usesBaseServer(mode) ? 'Base route unavailable' : mode === 'multi' ? 'Multi-Path' : 'Regular internet');
            const count = route.blockedServices || 0;
            return status + (count > 0 ? ' · ' + count + ' Multi-Path ' + (count === 1 ? 'list blocked' : 'lists blocked') : '');
        }

        function renderDeviceRules() {
            const body = byId('device-list');
            const tailnetBody = byId('tailnet-device-list');
            const wholeNetwork = byId('coverage').value === 'network';
            const wholeTailnet = byId('tailnet-coverage').value === 'network';
            const tailnetPolicy = coverageSettings(true);
            const wholeNetworkApplies = wholeNetwork && state.settings?.enabled &&
                state.settings.coverage === 'network' && state.settings.networkMode !== 'disabled';
            const allowBypass = supportsNetworkDeviceBypass(byId('network-mode').value);
            const bypassApplies = wholeNetworkApplies && supportsNetworkDeviceBypass(state.settings.networkMode);
            const savedKillSwitch = bypassApplies && state.settings.networkKillSwitch === true;
            const allowNewBypass = allowBypass && !byId('network-kill').checked;
            byId('add-device').hidden = wholeNetwork;
            byId('device-guide').textContent = wholeNetwork
                ? 'Edit device names here. Device Bypass requires the Whole-Network Kill Switch to be off. To assign individual servers, choose Only Devices I choose.'
                : 'Refresh to find LAN devices and current DHCP leases. Select a device to set up its routing rule.';
            const managed = list(state.settings?.interfaces);
            const transit = list(state.settings?.tailscaleInterfaces);
            const unboundInterfaces = list(state.settings?.killSwitchUnboundInterfaces);
            const nativeTailnet = state.settings?.tailscaleSetup?.ready === true;
            const lanAssignments = new Map();
            const tailnetByIPv4 = new Map();
            const tailnetByIPv6 = new Map();
            for (const assignment of state.assignments) {
                if (assignment.kind === 'tailnet') {
                    if (assignment.ip && !tailnetByIPv4.has(assignment.ip)) {
                        tailnetByIPv4.set(assignment.ip, assignment);
                    }
                    if (assignment.ipv6 && !tailnetByIPv6.has(assignment.ipv6)) {
                        tailnetByIPv6.set(assignment.ipv6, assignment);
                    }
                } else {
                    const key = assignment.interface + '/' + assignment.mac;
                    if (!lanAssignments.has(key)) {
                        lanAssignments.set(key, assignment);
                    }
                }
            }
            const seen = new Set();
            const rows = [];
            for (const device of [...state.devices, ...state.tailnetDevices]) {
                const tailnet = device.kind === 'tailnet';
                const assignment = tailnet
                    ? tailnetByIPv4.get(device.ipv4) || list(device.ipv6).map((ip) => tailnetByIPv6.get(ip)).find(Boolean)
                    : lanAssignments.get(device.interface + '/' + device.mac);
                if (assignment) {
                    seen.add(assignment.id);
                }
                rows.push({device, assignment});
            }
            for (const assignment of state.assignments) {
                if (!seen.has(assignment.id)) {
                    rows.push({device: null, assignment});
                }
            }
            body.replaceChildren();
            tailnetBody.replaceChildren();
            for (const {device, assignment} of rows) {
                const tailnet = (device?.kind || assignment?.kind) === 'tailnet';
                const row = (tailnet ? tailnetBody : body).insertRow();
                row.dataset.deviceKey = device ? deviceKey(device) : assignment
                    ? deviceKey(assignment.kind === 'tailnet'
                        ? {kind: 'tailnet', ipv4: assignment.ip, ipv6: assignment.ipv6}
                        : {interface: assignment.interface, mac: assignment.mac}) : '';
                const policy = tailnet ? tailnetPolicy : state.settings;
                const networkDraft = tailnet ? wholeTailnet : wholeNetwork;
                const networkApplies = networkDraft && policy?.enabled && policy.coverage === 'network' && policy.networkMode !== 'disabled';
                const name = assignment?.label || device?.name || device?.ipv4 || assignment?.ip || 'Unnamed device';
                const bindMac = assignment?.bindMac === true;
                const macBindingSupported = device?.macBindingSupported === true;
                const observedIp = device?.currentIpv4 || device?.ipv4 || '';
                const effectiveIp = assignment?.effectiveIp ?? observedIp;
                const reservationIp = assignment?.reservationIp || device?.reservationIpv4 || '';
                const reserveAddress = device?.stable === true ? device.reservationIpv4 || observedIp : observedIp;
                const ip = observedIp || effectiveIp || assignment?.ip || '';
                const offline = !tailnet
                    ? device ? device.online === false : Boolean(assignment && !state.discoveryTruncated)
                    : device ? device.online === false : Boolean(assignment && state.tailnetStatusAvailable);
                const ipv6 = list(device?.ipv6 || assignment?.ipv6);
                const routableV6 = ipv6.filter(address => !address.toLowerCase().startsWith('fe80:'));
                const interfaceId = assignment?.interface || device?.interface ||
                    (tailnet && nativeTailnet ? 'tailscale0' : (tailnet && transit.length === 1 ? transit[0] : ''));
                const reserved = tailnet ? Boolean(ip && (nativeTailnet || ipv6.length)) : device?.stable === true;
                const reserveIp = !tailnet && !reserved && Boolean(device?.leaseProvider);
                const canUseInterface = tailnet ? nativeTailnet || transit.length > 0 : managed.includes(interfaceId) && !transit.includes(interfaceId);
                const blocked = assignment?.killSwitchActive === true;
                const paused = assignment?.paused === true;
                const bypass = assignment?.networkBypass === true;
                const networkRoute = networkApplies ? policy.networkRouting?.[interfaceId] : null;
                const waitingForAddress = bindMac && !effectiveIp;
                const staleReservation = !!(observedIp && device?.reservationIpv4 && device.reservationIpv4 !== observedIp);
                let status;
                if (networkRoute?.outage) {
                    status = networkRouteStatus(networkRoute, policy.networkMode);
                } else if (wholeNetwork && !tailnet && bypass) {
                    status = 'Bypass saved';
                    if (bypassApplies && canUseInterface) {
                        if (savedKillSwitch || assignment.networkBypassStatus === 'kill-switch') {
                            status = 'Bypass paused by Kill Switch';
                        } else if (assignment.networkBypassStatus === 'direct') {
                            status = 'Direct internet';
                        } else if (assignment.networkBypassStatus === 'guard') {
                            status = 'Direct internet unavailable';
                        } else if (waitingForAddress) {
                            status = 'Waiting for device address';
                        } else if (assignment.networkBypassStatus === 'pending') {
                            status = 'Bypass pending';
                        }
                    }
                } else if (networkApplies && canUseInterface) {
                    status = networkRoute ? networkRouteStatus(networkRoute, policy.networkMode) : 'Covered by network rule';
                } else if (assignment) {
                    status = assignment.mode === 'default' ? 'No individual rule' : paused ? 'Disabled'
                        : networkDraft ? 'Individual rule paused' : !policy?.enabled
                        ? 'Saved · Routing off' : waitingForAddress ? 'Waiting for DHCP' : assignment.appliedRoute || 'Rule saved';
                } else if (!canUseInterface) {
                    status = tailnet ? 'Exit node setup needed' : 'Interface outside coverage';
                } else if (!tailnet && device?.addressConflict) {
                    status = 'DHCP address conflict';
                } else if (macBindingSupported && reserved) {
                    status = 'Ready to follow MAC';
                } else if (!reserved && !reserveIp) {
                    status = tailnet ? 'Both Tailscale addresses needed' : 'DHCP reservation needed';
                } else {
                    status = reserveIp ? 'Current lease can be reserved' : 'Ready to assign';
                }
                const addresses = [...new Set([(bindMac ? effectiveIp || observedIp || reservationIp || assignment.ip : ip),
                    ...list(device?.ipv4Addresses), ...ipv6].filter(Boolean))];
                const identity = [device?.mac || assignment?.mac, device?.arpConfirmed === false ? 'DHCP lease' : ''];
                const deviceCell = cell(row, name, 'Device', tailnet ? 'Tailscale' : identity.filter(Boolean).join(' · '));
                setOfflineBadge(deviceCell, offline, tailnet);
                const addressDetail = addresses.slice(1);
                if (waitingForAddress) {
                    if (observedIp) {
                        addressDetail.push(device.online === false ? 'Last reported lease' : 'Discovered IP');
                    }
                    const addAddressDetail = (label, address) => {
                        if (address && address !== observedIp) {
                            addressDetail.push(addresses[0] === address ? label : label + ' ' + address);
                        }
                    };
                    addAddressDetail('DHCP reservation', reservationIp !== assignment.ip ? reservationIp : '');
                    addAddressDetail('Saved IP', assignment.ip);
                }
                cell(row, addresses[0], 'Addresses', addressDetail.join(' · '));
                if (tailnet) {
                    cell(row, device?.online ? 'Online' : device || offline ? 'Offline' : 'Unknown', 'Availability');
                } else {
                    cell(row, interfaceId ? networkName(interfaceId) : '—', 'Interface');
                }
                const keepReady = assignment && (tailnet || assignment.mode === 'full_multi');
                const onDemand = assignment?.mode === 'full' && assignment.onDemand !== false && !keepReady;
                const ruleDetail = [assignment?.profile ? profileName(assignment.profile) : '',
                    onDemand ? 'On Demand' : keepReady && usesBaseServer(assignment.mode) ? 'Always on' : ''];
                if (bindMac) {
                    ruleDetail.push('Follows MAC address');
                }
                const networkRule = networkApplies && canUseInterface;
                const bypassActive = networkRule && !tailnet && bypassApplies && assignment?.networkBypassStatus === 'direct' && !savedKillSwitch;
                const rule = networkRule ? (bypassActive ? 'Bypass VPN' : (modes[policy.networkMode] || 'Whole-Network coverage'))
                    : networkDraft ? (assignment && assignment.mode !== 'default' ? 'Individual rule saved' : 'No rule')
                        : assignment ? modes[assignment.mode] || 'No rule' : 'No rule';
                const ruleNote = networkRule && !bypassActive && usesBaseServer(policy.networkMode)
                    ? 'Configured server · ' + profileName(policy.networkProfile)
                    : networkDraft ? '' : ruleDetail.filter(Boolean).join(' · ');
                cell(row, rule, 'Rule', ruleNote);
                const statusDetail = [];
                if (!tailnet && !canUseInterface) {
                    statusDetail.push('Select this interface in Routing coverage and save.');
                }
                if (staleReservation) {
                    statusDetail.push('DHCP reservation is ' + device.reservationIpv4 + '. Update it to match the current address.');
                } else if (!tailnet && device?.addressConflict) {
                    statusDetail.push('Check the device’s DHCP lease and reservation in OPNsense.');
                }
                if (!networkDraft && !paused && assignment?.killSwitch) {
                    statusDetail.push(blocked ? 'Kill Switch blocking internet' : 'Kill Switch on');
                }
                if (!networkDraft && !tailnet && unboundInterfaces.includes(interfaceId)) {
                    statusDetail.push('Internet is blocked on this interface until the protected device has a confirmed IPv4 address.');
                }
                cell(row, status, 'Status', statusDetail.join(' '));
                const ping = cell(row, '—', 'Ping');
                const actions = row.insertCell();
                actions.setAttribute('role', 'cell');
                if (state.canManage) {
                    const discovered = device ? {
                        ip: waitingForAddress ? assignment.ip : ip, reserveAddress, effectiveIp,
                        ipv6: tailnet || routableV6.length === 1 ? routableV6[0] : '',
                        interface: interfaceId, mac: device.mac, label: (device.name || '').replace(/[<>]/g, '').slice(0, 80),
                        reserved, reserveIp: reserveIp && !offline, canUseInterface, macBindingSupported,
                        addressConflict: device.addressConflict === true
                    } : null;
                    if (networkDraft && !tailnet) {
                        const eligible = !tailnet && !transit.includes(interfaceId) && canUseInterface && (assignment ||
                            (!device?.addressConflict && device?.mac && ip && (reserved || (reserveIp && !offline))));
                        const showBypass = bypass || (eligible && allowNewBypass);
                        if (assignment || eligible) {
                            actions.append(button('Edit', () => openNetworkDevice(assignment, discovered, showBypass),
                                'Edit ' + name));
                        }
                        if (showBypass) {
                            const action = bypass ? 'Use network rule' : 'Bypass VPN';
                            actions.append(button(action, (event) => {
                                if (assignment) {
                                    void mutate(event.currentTarget,
                                        () => api('setNetworkDevice', {id: assignment.id, networkBypass: !bypass}),
                                        bypass ? 'Device bypass removed.' : 'Device bypass saved.', closeNetworkDevice);
                                } else {
                                    openNetworkDevice(null, discovered, true, true);
                                }
                            }, action + ' for ' + name));
                        }
                    } else if (networkDraft && tailnet && assignment) {
                        actions.append(button('Edit', () => openNetworkDevice(assignment, discovered, false), 'Edit ' + name));
                    } else if (!networkDraft && assignment) {
                        actions.append(button('Edit', () => openAssignment(assignment, tailnet ? 'tailnet' : 'lan', discovered), 'Edit ' + name));
                        if (policy?.enabled && !paused && usesBaseServer(assignment.mode) && assignment.profile) {
                            appendConnectionTest(actions, 'testDeviceRoute', assignment.id, name, {ping});
                        }
                        if (tailnet) {
                            const action = paused ? 'Enable' : 'Disable';
                            actions.append(button(action, (event) => {
                                if (!paused && assignment.killSwitch &&
                                    !window.confirm('Disable this Tailscale rule? Its Kill Switch will also pause.')) {
                                    return;
                                }
                                void mutate(event.currentTarget,
                                    () => api('setTailnetRuleEnabled', {id: assignment.id, enabled: paused}),
                                    paused ? 'Tailscale rule enabled.' : 'Tailscale rule disabled.',
                                    () => state.tests.delete('device:' + assignment.id));
                            }, action + ' ' + name));
                        }
                    } else if ((tailnet || canUseInterface) && !device?.addressConflict) {
                        actions.append(button('Select', () => openAssignment(null, tailnet ? 'tailnet' : 'lan', discovered), 'Select ' + name));
                    }
                }
            }
            if (!body.rows.length) {
                empty(body, 'No LAN devices or DHCP leases found. Press Refresh.', 7);
            }
            byId('add-tailnet-peer').hidden = wholeTailnet || (!nativeTailnet && !transit.length);
            if (!tailnetBody.rows.length) {
                empty(tailnetBody, nativeTailnet && !wholeTailnet
                    ? 'No Tailscale peers listed. Add a device by its Tailscale IP.'
                    : 'No Tailscale peers listed.', 7);
            }
            const online = state.tailnetDevices.filter(device => device.online).length;
            byId('tailnet-count').textContent = state.tailnetDevices.length ? online + ' online' : '';
            byId('tailnet-routing-hint').textContent = nativeTailnet || transit.length ? ''
                : state.settings?.tailscaleSetup?.reason || 'Check Tailscale Settings for exit node setup.';
            const tailnetSelected = byId('routing-scope').value === 'tailscale';
            const count = (tailnetSelected ? state.tailnetDevices : state.devices).length;
            const rules = state.assignments.filter((row) => (row.kind === 'tailnet') === tailnetSelected).length;
            const counts = [count + (count === 1 ? ' device found' : ' devices found')];
            counts.push(rules + (rules === 1 ? ' saved rule' : ' saved rules'));
            byId('observed').textContent = counts.join(' · ');
        }

        function deviceKey(device) {
            return device.kind === 'tailnet' ? 'tailnet/' + (device.ipv4 || list(device.ipv6)[0] || '')
                : device.interface + '/' + device.mac;
        }

        function setOfflineBadge(deviceCell, offline, tailnet) {
            const existing = deviceCell.querySelector('.bv-offline');
            if (!offline) {
                existing?.remove();
                return;
            }
            const badge = existing || document.createElement('span');
            badge.className = 'bv-offline';
            badge.textContent = 'Offline';
            badge.title = tailnet ? 'Tailscale reports this peer offline' : 'No recent LAN activity detected';
            if (!existing) {
                deviceCell.insertBefore(badge, deviceCell.firstElementChild);
            }
        }

        async function refreshDeviceAvailability() {
            if (state.dashboardRequest || state.deviceAvailabilityRequest) {
                return;
            }
            const revision = state.deviceAvailabilityRevision;
            state.deviceAvailabilityRequest = (async () => {
                const data = await api('deviceAvailability');
                if (revision !== state.deviceAvailabilityRevision) {
                    return;
                }
                const lan = new Map(array(data.devices).map(device => [deviceKey(device), device]));
                const tailnet = new Map(array(data.tailnetDevices).map(device =>
                    [deviceKey({...device, kind: 'tailnet'}), device]));
                state.discoveryTruncated = data.truncated === true;
                state.tailnetStatusAvailable = data.tailnetStatusAvailable === true;
                for (const device of state.devices) {
                    const current = lan.get(deviceKey(device));
                    device.online = data.lanStatusAvailable !== true ? null
                        : current ? current.online === true : state.discoveryTruncated ? null : false;
                }
                for (const device of state.tailnetDevices) {
                    const current = tailnet.get(deviceKey(device));
                    device.online = !state.tailnetStatusAvailable ? null : current ? current.online === true : false;
                }
                const observed = new Map([...state.devices, ...state.tailnetDevices]
                    .map(device => [deviceKey(device), device]));
                for (const [body, isTailnet] of [[byId('device-list'), false], [byId('tailnet-device-list'), true]]) {
                    for (const row of body.rows) {
                        const device = observed.get(row.dataset.deviceKey);
                        const current = isTailnet ? tailnet.get(row.dataset.deviceKey) : lan.get(row.dataset.deviceKey);
                        if (!row.dataset.deviceKey) {
                            continue;
                        }
                        const online = device?.online ?? (isTailnet ? !state.tailnetStatusAvailable ? null
                            : current ? current.online === true : false
                            : data.lanStatusAvailable !== true || state.discoveryTruncated ? null
                                : current ? current.online === true : false);
                        setOfflineBadge(row.cells[0], online === false, isTailnet);
                        if (isTailnet) {
                            row.cells[2].textContent = online === true ? 'Online'
                                : online === false ? 'Offline' : 'Unknown';
                        }
                    }
                }
                const online = state.tailnetDevices.filter(device => device.online === true).length;
                byId('tailnet-count').textContent = state.tailnetDevices.length ? online + ' online' : '';
            })().catch(() => {
                if (revision !== state.deviceAvailabilityRevision) {
                    return;
                }
                for (const device of [...state.devices, ...state.tailnetDevices]) {
                    device.online = null;
                }
                for (const row of byId('tailnet-device-list').rows) {
                    if (row.dataset.deviceKey) {
                        setOfflineBadge(row.cells[0], false, true);
                        row.cells[2].textContent = 'Unknown';
                    }
                }
                for (const row of byId('device-list').rows) {
                    if (row.dataset.deviceKey) {
                        setOfflineBadge(row.cells[0], false, false);
                    }
                }
            }).finally(() => {
                state.deviceAvailabilityRequest = null;
            });
            return state.deviceAvailabilityRequest;
        }

        function vpnStatus(profile) {
            if (profile.disabled) {
                return 'Disabled';
            }
            const test = state.tests.get(profile.node ? 'proxy:' + profile.node : 'exit:' + profile.id);
            if (test?.kind === 'fail') {
                return 'Error';
            }
            if (test?.kind === 'pass' || ['router probe succeeded', 'proxy probe succeeded'].includes(profile.reachability)) {
                return 'Ready';
            }
            return 'Standby';
        }

        function vpnServers() {
            const servers = state.profiles.filter((profile) => profile.kind !== 'proxy' || profile.provider === 'nord');
            if (state.vpnFixedOrder) {
                return servers.sort((a, b) => fixedPosition(state.vpnFixedOrder, a.id)
                    - fixedPosition(state.vpnFixedOrder, b.id) || compareServers(a, b));
            }
            if (!state.vpnSortByPing) {
                return servers.sort(compareServers);
            }
            return servers.sort((a, b) =>
                testLatency(a.node ? 'proxy:' + a.node : 'exit:' + a.id)
                - testLatency(b.node ? 'proxy:' + b.node : 'exit:' + b.id) || compareServers(a, b));
        }

        function testLatency(key) {
            const test = state.tests.get(key);
            return test?.kind === 'pass' && Number.isFinite(test.milliseconds) ? test.milliseconds : Infinity;
        }

        function fixedPosition(order, id) {
            const position = order.indexOf(id);
            return position < 0 ? Infinity : position;
        }

        function proxyServers() {
            const nodes = state.proxyNodes.filter((node) => node.provider !== 'nord');
            if (state.proxyFixedOrder) {
                return nodes.sort((a, b) => fixedPosition(state.proxyFixedOrder, a.id)
                    - fixedPosition(state.proxyFixedOrder, b.id));
            }
            if (!state.proxySortByPing) {
                return nodes;
            }
            return nodes.sort((a, b) => {
                const left = testLatency('proxy:' + a.id);
                const right = testLatency('proxy:' + b.id);
                return left === right ? 0 : left - right;
            });
        }

        function profileInUse(id) {
            return state.settings?.networkProfile === id || state.settings?.tailnetNetworkProfile === id
                || state.assignments.some((assignment) => [assignment.profile, assignment.backup].includes(id))
                || state.services.some((service) => service.profile === id);
        }

        function removalReason(kind, item) {
            if (!state.canManage) {
                return 'You do not have permission to remove servers.';
            }
            if (kind === 'vpn') {
                return profileInUse(item.id) ? 'Remove this server from routing policies first.' : '';
            }
            return state.profiles.some((profile) => profile.node === item.id)
                ? 'Disable this server before removing it.' : '';
        }

        function serverSelection(kind) {
            return kind === 'vpn' ? state.selectedVpns : state.selectedProxies;
        }

        function selectionItems(kind) {
            return kind === 'vpn' ? vpnServers() : proxyServers();
        }

        function updateServerSelection(kind) {
            const selected = serverSelection(kind);
            const items = selectionItems(kind);
            const removable = new Set(items.filter((item) => !removalReason(kind, item)).map((item) => item.id));
            for (const id of selected) {
                if (!removable.has(id)) {
                    selected.delete(id);
                }
            }
            const all = byId(kind + '-select-all');
            all.checked = removable.size > 0 && selected.size === removable.size;
            all.indeterminate = selected.size > 0 && selected.size < removable.size;
            all.disabled = state.busy || removable.size === 0;
            byId(kind + '-remove-selected').disabled = state.busy || selected.size === 0;
            const protectedCount = items.length - removable.size;
            byId(kind + '-selected-count').textContent = selected.size + ' selected'
                + (kind === 'proxy' && items.length > 50 ? ' across all pages' : '')
                + (protectedCount ? ' · ' + protectedCount + ' unavailable for removal' : '');
            for (const checkbox of root.querySelectorAll('[data-server-selection="' + kind + '"]')) {
                checkbox.checked = selected.has(checkbox.value);
                checkbox.disabled = state.busy || !removable.has(checkbox.value);
            }
        }

        function serverSelectionCell(row, kind, item) {
            const target = row.insertCell();
            target.setAttribute('role', 'cell');
            target.className = 'bv-server-selection-cell';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = item.id;
            checkbox.dataset.serverSelection = kind;
            const name = item.name || item.serverName || item.relay || item.id;
            const reason = removalReason(kind, item);
            checkbox.setAttribute('aria-label', 'Select ' + name + (reason ? '. ' + reason : ''));
            checkbox.title = reason || 'Select ' + name;
            checkbox.disabled = state.busy || Boolean(reason);
            checkbox.checked = serverSelection(kind).has(item.id);
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    serverSelection(kind).add(item.id);
                } else {
                    serverSelection(kind).delete(item.id);
                }
                updateServerSelection(kind);
            });
            target.append(checkbox);
        }

        function toggleAllServers(kind, checked) {
            const selected = serverSelection(kind);
            selected.clear();
            if (checked) {
                for (const item of selectionItems(kind)) {
                    if (!removalReason(kind, item)) {
                        selected.add(item.id);
                    }
                }
            }
            updateServerSelection(kind);
        }

        async function removeSelectedServers(kind, control) {
            if (state.busy) {
                return;
            }
            updateServerSelection(kind);
            const selected = serverSelection(kind);
            const items = selectionItems(kind).filter((item) => selected.has(item.id));
            const fromSubscription = kind === 'proxy' && items.some((item) =>
                array(item.sources).some((source) => state.proxyFeeds.some((feed) => feed.id === source)));
            if (!items.length || !window.confirm('Remove ' + items.length + ' selected '
                + (kind === 'vpn' ? 'VPN' : 'proxy') + ' server' + (items.length === 1 ? '' : 's') + ' from this router?'
                + (fromSubscription ? ' Their subscriptions will remain. Refreshing a subscription can import its servers again.' : ''))) {
                return;
            }
            const selection = kind === 'vpn' ? {
                profiles: items.filter((item) => !(item.node && item.provider === 'nord')).map((item) => item.id),
                nodes: items.filter((item) => item.node && item.provider === 'nord').map((item) => item.node)
            } : items.map((item) => item.id);
            await mutate(control, () => api(kind === 'vpn' ? 'removeProfiles' : 'removeProxyNodes', {
                selection: JSON.stringify(selection)
            }), items.length + ' server' + (items.length === 1 ? '' : 's') + ' removed.', () => {
                for (const item of items) {
                    selected.delete(item.id);
                    state.tests.delete(kind === 'proxy' || item.node ? 'proxy:' + (item.node || item.id) : 'exit:' + item.id);
                    if (state.nameEditor?.id === (item.node || item.id)) {
                        state.nameEditor = null;
                    }
                }
                state.proxyCatalogLoaded = false;
            });
            updateServerSelection(kind);
        }

        function renderBulkPingControls(kind, count) {
            for (const mode of ['all', 'sort']) {
                const control = byId(kind === 'vpns' ? 'vpn-ping-' + mode : 'proxy-ping-' + mode);
                const active = state.bulkPing.kind === kind && state.bulkPing.sort === (mode === 'sort');
                control.textContent = (active ? 'Stop ' : '') + (mode === 'sort' ? 'Ping & Sort' : 'Ping All');
                control.disabled = !count || (Boolean(state.bulkPing.kind) && !active);
            }
        }

        function renderProfiles() {
            const body = byId('profile-list');
            const vpns = vpnServers();
            renderBulkPingControls('vpns', vpns.length);
            if (!vpns.length) {
                empty(body, 'No VPN servers have been added.', 7);
            } else {
                body.replaceChildren();
                for (const profile of vpns) {
                    const row = body.insertRow();
                    const used = state.assignments.filter((assignment) =>
                        [assignment.profile, assignment.backup].includes(profile.id)).length;
                    const services = state.services.filter((service) => service.profile === profile.id).length;
                    serverSelectionCell(row, 'vpn', profile);
                    const name = cell(row, profile.name || profile.relay, '', used + ' device assignment' + (used === 1 ? '' : 's')
                        + ' · ' + services + ' service' + (services === 1 ? '' : 's'));
                    name.dataset.serverName = profile.id;
                    name.querySelector('small').title = name.querySelector('small').textContent;
                    const server = cell(row, providerName(profile), '', profile.relay || profile.providerServer || profile.gateway || profile.protocol || 'Imported WireGuard');
                    server.querySelector('small').title = server.querySelector('small').textContent;
                    const status = cell(row, vpnStatus(profile), 'Status');
                    status.className = 'bv-vpn-status';
                    status.dataset.vpnStatus = profile.id;
                    status.setAttribute('aria-live', 'polite');
                    const port = profile.port || state.proxyNodes.find((node) => node.id === profile.node)?.port;
                    cell(row, port || '—', 'Port');
                    const ping = cell(row, '—', 'Ping');
                    ping.className = 'bv-ping-cell';
                    const actions = serverControls(row);
                    const remove = button('Remove', (event) => removeProfile(profile, event.currentTarget),
                        'Remove ' + profileName(profile.id));
                    remove.disabled = Boolean(removalReason('vpn', profile));
                    remove.title = removalReason('vpn', profile);
                    if (state.canManage) {
                        const dormant = profile.node && profile.id.startsWith('proxy-');
                        appendConnectionTest(actions, dormant ? 'testProxyNode' : 'testExit',
                            dormant ? profile.node : profile.id, profileName(profile.id),
                            {nodeId: profile.node, disabled: profile.disabled === true, ping});
                        const edit = nameEditor(row, profile.name || profile.relay, profile.node || profile.id,
                            profile.node ? 'renameProxyNode' : 'renameProfile', renderProfiles, (name) => { profile.name = name; },
                            profile.relay ? (editor) => mullvadPortEditor(profile, editor) : null);
                        if (edit) {
                            actions.append(edit);
                        }
                        if (profile.relay) {
                            const disabled = profile.disabled === true;
                            const toggle = button(disabled ? 'Enable' : 'Disable', (event) =>
                                void mutate(event.currentTarget, () => api('setMullvadEnabled', {id: profile.id, enabled: disabled}),
                                    disabled ? 'Mullvad server enabled.' : 'Mullvad server disabled.',
                                    () => state.tests.delete('exit:' + profile.id)));
                            toggle.disabled = remove.disabled && !disabled;
                            actions.append(toggle);
                        }
                        actions.append(remove);
                    }
                }
            }

            updateServerSelection('vpn');
            const choices = routingServers().map(exitChoice);
            const select = byId('profile');
            const selected = select.value;
            if (selected && !choices.some((choice) => choice.value === selected)) {
                choices.push({value: selected, label: 'Unavailable VPN profile'});
            }
            options(select, choices, 'Normal internet', selected);
            updateFailure();
        }

        function checkedInterfaces(id) {
            return [...byId(id).querySelectorAll('input:checked')].map((input) => input.value);
        }

        function availablePorts() {
            return [...state.availableInterfaces].sort((a, b) => {
                if (a.id === 'lan' || b.id === 'lan') {
                    return Number(b.id === 'lan') - Number(a.id === 'lan');
                }
                return (a.device || a.id).localeCompare(b.device || b.id, undefined, {numeric: true});
            });
        }

        function renderInterfaceChoices(id, ports, selected, emptyText) {
            const target = byId(id);
            target.replaceChildren();
            const missing = selected.filter((value) => !ports.some((port) => port.id === value));
            for (const port of [...ports, ...missing.map((value) => ({id: value, name: 'Unavailable interface'}))]) {
                const label = document.createElement('label');
                const input = document.createElement('input');
                input.type = 'checkbox';
                input.value = port.id;
                input.checked = selected.includes(port.id);
                const title = document.createElement('span');
                title.textContent = port.device || port.id;
                if (port.name && port.name !== port.device) {
                    const alias = document.createElement('small');
                    alias.textContent = port.name;
                    title.append(alias);
                }
                label.append(input, title);
                target.append(label);
            }
            if (!target.children.length) {
                const note = document.createElement('p');
                note.className = 'text-muted';
                note.textContent = emptyText;
                target.append(note);
            }
        }

        function renderInterfaceRules(ports, settings) {
            const target = byId('interface-rules');
            target.replaceChildren();
            for (const port of ports) {
                const label = document.createElement('label');
                label.dataset.interface = port.id;
                label.textContent = networkName(port.id);
                const select = document.createElement('select');
                select.className = 'form-control';
                select.append(new Option('Use device rules', ''), new Option('Use Multi-Path domain lists', 'smart'),
                    new Option('Block devices without a rule', 'strict'));
                select.value = list(settings.strictInterfaces).includes(port.id) ? 'strict'
                    : list(settings.smartInterfaces).includes(port.id) ? 'smart' : '';
                if (list(settings.tailscaleInterfaces).includes(port.id)) {
                    select.querySelector('[value="strict"]').disabled = true;
                }
                label.append(select);
                target.append(label);
            }
        }

        function coverageSettings(tailnet) {
            const settings = state.settings;
            return !tailnet || !settings ? settings : {
                enabled: settings.tailnetEnabled,
                coverage: settings.tailnetCoverage,
                networkMode: settings.tailnetNetworkMode,
                networkProfile: settings.tailnetNetworkProfile,
                networkKillSwitch: settings.tailnetNetworkKillSwitch,
                networkRouting: settings.tailnetNetworkRouting
            };
        }

        function selectRoutingScope(scope) {
            byId('routing-scope').value = scope;
            const tailnet = scope === 'tailscale';
            byId('local-routing').hidden = tailnet || !state.canManage;
            byId('tailnet-coverage-panel').hidden = !tailnet || !state.canManage;
            byId('lan-devices').hidden = tailnet;
            byId('tailnet-devices').hidden = !tailnet;
            byId('assignment').hidden = true;
            state.editing = null;
            closeNetworkDevice();
            renderDeviceRules();
        }

        function renderSettings() {
            const settings = state.settings;
            for (const tailnet of [false, true]) {
                const field = (id) => byId((tailnet ? 'tailnet-' : '') + id);
                const saved = coverageSettings(tailnet);
                const dirty = tailnet ? state.tailnetRoutingDirty : state.settingsDirty;
                const select = field('network-profile');
                const savedExit = dirty ? select.value : (saved?.networkProfile || '');
                const choices = routableExits().map(exitChoice);
                if (savedExit && !choices.some((choice) => choice.value === savedExit)) {
                    choices.push({value: savedExit, label: 'Unavailable server'});
                }
                options(select, choices, 'Choose a server', savedExit);
                if (saved && !dirty) {
                    field('coverage').value = saved.coverage || 'device';
                    field('network-mode').value = saved.networkMode || 'disabled';
                    field('network-kill').checked = saved.networkKillSwitch ?? saved.networkMode !== 'multi';
                }
                const enabled = saved?.enabled === true;
                const toggle = byId(tailnet ? 'toggle-tailnet-routing' : 'toggle-routing');
                toggle.classList.toggle('bv-routing-on', enabled);
                toggle.textContent = enabled ? 'Disable VPN' : 'Enable VPN';
                updateCoverage(tailnet);
            }
            const tailnet = coverageSettings(true);
            const test = byId('tailnet-base-test');
            test.hidden = !tailnet?.enabled || tailnet.coverage !== 'network' || !usesBaseServer(tailnet.networkMode);
            test.replaceChildren();
            if (!test.hidden) {
                appendConnectionTest(test, 'testTailnetBase', tailnet.networkProfile, 'Tailscale base', {title: 'Test base route'});
            }
            byId('routing-enabled').hidden = !settings?.enabled;
            if (settings && !state.settingsDirty) {
                const transit = list(settings.tailscaleInterfaces);
                const ports = availablePorts().filter((port) => !transit.includes(port.id));
                renderInterfaceChoices('managed', ports, list(settings.interfaces), 'No assigned LAN or VLAN interfaces.');
                renderInterfaceRules(ports, settings);
                byId('smart-assigned').checked = settings.smartAssignedOnly === true;
                byId('local').value = list(settings.localNetworks).join(', ');
            }
            const showingTailnet = byId('routing-scope').value === 'tailscale';
            byId('local-routing').hidden = showingTailnet || !state.canManage;
            byId('tailnet-coverage-panel').hidden = !showingTailnet || !state.canManage;
            updateCoverage();
            renderDeviceRules();
        }

        function routableExits() {
            return routingServers().filter(hasVpnDns);
        }

        function hasVpnDns(profile) {
            return profile.kind === 'proxy' || list(profile.dns).some((ip) => !ip.includes(':'));
        }

        function routingServers() {
            const activeNodes = new Set(state.profiles.map((profile) => profile.node).filter(Boolean));
            return [...state.profiles.filter((profile) => !profile.disabled), ...state.proxyNodes.filter((node) => !node.disabled && !activeNodes.has(node.id))
                .map((node) => ({...node, id: 'proxy-' + node.id, kind: 'proxy'}))].sort(compareServers);
        }

        function updateCoverage(tailnet = false) {
            const field = (id) => byId((tailnet ? 'tailnet-' : '') + id);
            const network = field('coverage').value === 'network';
            const mode = field('network-mode').value;
            const combined = mode === 'full_multi';
            const baseServer = usesBaseServer(mode);
            const exit = field('network-profile');
            const kill = field('network-kill');
            const supportsKillSwitch = baseServer || mode === 'multi';
            if (!tailnet) {
                const selected = checkedInterfaces('managed');
                byId('device-options').hidden = network;
                for (const label of byId('interface-rules').children) {
                    label.hidden = !selected.includes(label.dataset.interface);
                }
            }
            field('network-fields').hidden = !network;
            field('network-kill-field').hidden = !network || !supportsKillSwitch;
            kill.disabled = !network || !supportsKillSwitch;
            const killSwitch = kill.checked;
            field('network-profile-label').textContent = combined ? 'Base server' : 'Saved server';
            field('network-profile-field').hidden = !network || !baseServer;
            exit.required = network && baseServer;
            const summary = {
                full: exit.value
                    ? 'Default traffic uses ' + profileName(exit.value) + '.'
                        + (killSwitch ? ' The Kill Switch blocks internet if the server goes offline. Bypass is unavailable while the Kill Switch is on.'
                            : ' Traffic uses direct internet if the server goes offline.')
                    : 'Add a VPN or proxy server, then select it here.',
                multi: 'Matching destinations use your Multi-Path servers. '
                    + (killSwitch ? 'Only destinations with a working VPN or proxy can connect. Bypass is unavailable while the Kill Switch is on.'
                        : 'Other traffic uses regular internet.'),
                full_multi: exit.value
                    ? 'Default traffic uses ' + profileName(exit.value) + '. Matching destinations use their Multi-Path servers. '
                        + (killSwitch ? 'If a Multi-Path server goes offline, only its destinations are blocked. If the base server goes offline, only default traffic is blocked. Bypass is unavailable while the Kill Switch is on.'
                            : 'Traffic assigned to the base server uses direct internet if it goes offline. Bypass uses direct internet.')
                    : 'Choose a base server for default traffic. Set destination overrides in Multi-Path.',
                blocked: tailnet ? 'Internet is blocked for clients using the exit node.' : 'Internet is blocked on the selected LANs and VLANs.',
                disabled: 'Devices use your normal OPNsense routing.'
            };
            field('coverage-note').textContent = network ? summary[mode]
                : tailnet ? 'Assign routing rules to individual Tailscale peers below.'
                    : 'Select the interfaces to manage, then assign routing rules to individual LAN devices below.';
            const saved = coverageSettings(tailnet);
            const ipv6Interfaces = list(saved?.killSwitchIpv6Interfaces).map(networkName);
            const unboundInterfaces = list(saved?.killSwitchUnboundInterfaces).map(networkName);
            const active = Object.entries(saved?.networkRouting || {}).map(([id, route]) =>
                networkName(id) + ' · ' + networkRouteStatus(route, saved.networkMode));
            const activeCoverage = saved?.networkMode === 'full_multi' ? 'Whole-Network + Multi-Path' : 'Whole-Network coverage';
            const activeKillSwitch = usesBaseServer(saved?.networkMode) || saved?.networkMode === 'multi'
                ? ' · Kill Switch ' + ((saved.networkKillSwitch ?? saved.networkMode !== 'multi') ? 'on' : 'off') : '';
            byId(tailnet ? 'current-tailnet-routing' : 'current-routing').textContent = !saved?.enabled ? 'Active routing · Off'
                : saved.coverage === 'network' ? 'Active routing · ' + activeCoverage + activeKillSwitch
                    + (active.length ? ' · ' + active.join(' / ') : '')
                    : 'Active routing · Only Devices I choose' +
                        (ipv6Interfaces.length ? ' · Public IPv6 blocked on ' + ipv6Interfaces.join(', ') : '') +
                        (unboundInterfaces.length ? ' · Internet blocked on ' + unboundInterfaces.join(', ') +
                            ' until protected devices have confirmed IPv4 addresses' : '');
        }

        function renderTailscale() {
            const settings = state.settings;
            if (!settings) {
                return;
            }
            const address = settings.dashboardAddresses?.tailnet;
            byId('tailscale-status').textContent = address
                ? 'Connected · ' + address + (settings.tailscaleExitAdvertised ? ' · Exit node advertised' : '')
                : settings.tailscaleInstalled ? 'Tailscale installed. Connect OPNsense to your tailnet.'
                    : 'Install the OPNsense Tailscale plugin to connect this router.';
            byId('native-tailscale').hidden = !settings.tailscaleInstalled;
            const selected = list(settings.tailscaleInterfaces);
            byId('add-tailnet-device').hidden = settings.tailnetCoverage === 'network' || selected.length === 0;
            byId('native-tailnet-status').textContent = settings.tailscaleSetup?.ready
                ? 'Ready. Choose Tailscale under Network Settings → Routing coverage.'
                : settings.tailscaleSetup?.reason || '';
            const snat = byId('native-snat-status');
            snat.textContent = settings.tailscaleSetup?.disableSnat ? '✓ Disable SNAT checked' : 'Disable SNAT unchecked';
            snat.classList.toggle('bv-setting-checked', settings.tailscaleSetup?.disableSnat === true);
            snat.hidden = !settings.tailscaleInstalled;
            if (!state.tailscaleDirty) {
                byId('hostname').value = settings.hostname || 'blankvpn.home.arpa';
                byId('dashboard-bind').value = settings.dashboardBind || 'lan';
                const eligible = availablePorts().filter((port) => port.id.startsWith('opt')
                    && !list(settings.strictInterfaces).includes(port.id));
                renderInterfaceChoices('tailnet-interfaces', eligible, selected,
                    'No dedicated Ethernet or VLAN links are available.');
            }
            renderDashboardAddress();
        }

        function renderDashboardAddress() {
            const settings = state.settings;
            const home = byId('dashboard-bind').value === 'lan';
            const address = settings?.dashboardAddresses?.[home ? 'lan' : 'tailnet'];
            const port = settings?.dashboardPort || 443;
            const suffix = (port === 443 ? '' : ':' + port) + '/ui/blankvpn/index';
            const hostname = byId('hostname').value.trim().toLowerCase();
            const localName = hostname === 'blankvpn.local';
            const magicDns = settings?.dashboardMagicDns;
            const validLocalName = localName || /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+home\.arpa$/.test(hostname);
            const host = home && validLocalName ? hostname : (home ? address : magicDns || address);
            const link = byId('dashboard-link');
            link.hidden = !host;
            if (host) {
                link.href = 'https://' + host + suffix;
                link.textContent = link.href;
            }
            const direct = byId('address-link');
            byId('address-row').hidden = !address || host === address;
            if (address) {
                direct.href = 'https://' + address + suffix;
                direct.textContent = direct.href;
            }
            byId('dashboard-hostname-field').hidden = !home;
            byId('use-local-name').hidden = !home;
            byId('bind-address').textContent = !address ? 'The selected interface has no IPv4 address yet.'
                : home ? (localName ? 'Publish this name with Bonjour on your home network.'
                    : 'Point this name at ' + address + ' in the DNS your home devices use.')
                    : magicDns ? 'Tailscale uses your router’s MagicDNS name. Use the IP link if MagicDNS is unavailable on your device.'
                        : 'MagicDNS is unavailable. Open the dashboard using its Tailscale IP.';
            byId('bonjour').hidden = !localName || !home || !address;
            byId('bonjour-command').textContent = byId('bonjour').hidden ? ''
                : 'dns-sd -P "Blank VPN & Proxy" _https._tcp local ' + port + ' blankvpn.local ' + address;
        }

        function domainDestinations() {
            return [
                {value: bypassDestination, label: 'Bypass (direct internet)'},
                ...routingServers().map((profile) => {
                    const choice = exitChoice(profile);
                    return hasVpnDns(profile) ? choice : {...choice, label: choice.label + ' (IP entries only)'};
                })
            ];
        }

        function renderServices() {
            if (state.section !== 'smart') {
                return;
            }
            const choices = domainDestinations();
            const knownDestinations = new Set(choices.map((choice) => choice.value));
            const choicesFor = (current) => current && !knownDestinations.has(current)
                ? [...choices, {value: current, label: 'Unavailable server'}] : choices;
            const interfaces = state.activeSmartInterfaces;
            const settings = state.settings;
            const networkMode = settings?.coverage === 'network' ? settings.networkMode : '';
            const active = interfaces.length && state.services.some((service) => service.profile && service.profile !== bypassDestination);
            byId('smart-status').textContent = active
                ? 'Routing matching destinations on ' + interfaces.map(networkName).join(', ') + '.'
                : 'Choose a server and enable Multi-Path under Routing coverage.';
            byId('use-lan').hidden = usesBaseServer(networkMode) ||
                !state.availableInterfaces.some((item) => item.id === 'lan')
                || interfaces.includes('lan') || list(settings?.strictInterfaces).includes('lan');
            const body = byId('service-list');
            if (state.services.length === 0) {
                empty(body, 'No saved lists.', 4);
            } else {
                body.replaceChildren();
                for (const service of state.services) {
                    const row = body.insertRow();
                    const entries = list(service.domains);
                    const saved = service.profile || '';
                    const scope = {local: 'Local', tailscale: 'Tailscale', both: 'Local and Tailscale'}[service.scope || 'both'];
                    const summary = cell(row, service.name, 'Service and entries',
                        scope + ' · ' + entries.length + (entries.length === 1 ? ' entry' : ' entries'));
                    const pingResult = document.createElement('small');
                    pingResult.className = 'bv-service-ping';
                    pingResult.setAttribute('role', 'status');
                    const previousTest = state.serviceTests.get(service.id);
                    pingResult.textContent = previousTest?.profile === saved ? previousTest.text : '';
                    pingResult.dataset.result = previousTest?.profile === saved ? previousTest.kind : '';
                    summary.append(pingResult);
                    const destination = row.insertCell();
                    destination.dataset.label = 'Server';
                    if (state.canManage) {
                        const form = document.createElement('form');
                        form.className = 'bv-inline-form';
                        const select = document.createElement('select');
                        select.className = 'form-control';
                        select.setAttribute('aria-label', 'Destination for ' + service.name);
                        const current = state.serviceDestinations.get(service.id) ?? saved;
                        options(select, choicesFor(current), 'Leave unassigned', current);
                        const save = document.createElement('button');
                        save.type = 'submit';
                        save.className = 'btn btn-default btn-sm';
                        save.textContent = 'Save';
                        save.setAttribute('aria-label', 'Save destination for ' + service.name);
                        save.disabled = select.value === saved;
                        select.addEventListener('change', () => {
                            save.disabled = select.value === saved;
                            if (save.disabled) {
                                state.serviceDestinations.delete(service.id);
                            } else {
                                state.serviceDestinations.set(service.id, select.value);
                            }
                        });
                        form.addEventListener('submit', (event) => {
                            event.preventDefault();
                            if (select.value !== saved) {
                                const profile = select.value;
                                void mutate(save, () => api('setServiceDestination', {id: service.id, profile}),
                                    'Destination saved. Open a new connection to use the updated route.', () => {
                                        state.serviceDestinations.delete(service.id);
                                    }).then(() => {
                                        save.disabled = select.value === saved;
                                    });
                            }
                        });
                        form.append(select, save);
                        destination.append(form);
                    } else {
                        destination.textContent = saved ? profileName(saved) : 'Unassigned';
                    }
                    const isBypass = saved === bypassDestination;
                    const status = Object.entries(service.routing || {}).map(([id, rule]) =>
                        networkName(id) + ' · ' + (rule.bypass ? 'Direct internet'
                            : rule.gateway ? state.profiles.find((profile) => profile.interface === rule.gateway)?.name || rule.gateway
                                : rule.guard ? (isBypass ? 'Direct internet unavailable' : 'Selected server unavailable · Matching traffic blocked')
                                    : 'Inactive'));
                    const applicable = [coverageSettings(false), coverageSettings(true)]
                        .filter((policy, index) => policy?.enabled && (service.scope === (index ? 'tailscale' : 'local')
                            || !service.scope || service.scope === 'both'));
                    const bypassPaused = isBypass && applicable.some((policy) => policy.coverage === 'network' &&
                        supportsNetworkDeviceBypass(policy.networkMode) && policy.networkKillSwitch);
                    const blocked = isBypass && applicable.length > 0 &&
                        applicable.every((policy) => policy.coverage === 'network' && policy.networkMode === 'blocked');
                    const inactive = blocked ? 'Internet blocked' : bypassPaused ? 'Bypass paused by Kill Switch' : 'Inactive';
                    cell(row, saved ? (status.join(' / ') || inactive) : 'Saved',
                        'Routing', Number.isInteger(service.learned) ? service.learned + ' learned addresses' : '');
                    const actions = row.insertCell();
                    if (state.canManage) {
                        const test = button('Ping', async () => {
                            test.disabled = true;
                            pingResult.textContent = 'Testing ' + profileName(saved) + '…';
                            pingResult.dataset.result = 'pending';
                            try {
                                const profile = state.profiles.find((item) => item.id === saved);
                                const node = state.proxyNodes.find((item) => 'proxy-' + item.id === saved);
                                if (!profile && !node) {
                                    throw new Error('The selected server is unavailable.');
                                }
                                const reply = profile ? await api('testExit', {id: saved})
                                    : await api('testProxyNode', {id: node.id});
                                const passed = reply.reachable === true;
                                state.serviceTests.set(service.id, {profile: saved, kind: passed ? 'pass' : 'fail',
                                    text: passed ? profileName(saved) + ' · HTTPS ' + reply.milliseconds + ' ms'
                                        : reply.detail || 'The server did not respond.'});
                            } catch (error) {
                                state.serviceTests.set(service.id, {profile: saved, kind: 'fail',
                                    text: errorMessage(error, 'The server test failed.')});
                            } finally {
                                const result = state.serviceTests.get(service.id);
                                pingResult.textContent = result.text;
                                pingResult.dataset.result = result.kind;
                                test.disabled = false;
                            }
                        }, 'Ping server for ' + service.name);
                        test.disabled = !saved || isBypass;
                        actions.append(test);
                        actions.append(button('Edit', () => editService(service), 'Edit ' + service.name));
                    }
                    actions.append(button('Download', () => downloadEntries(service.name, entries),
                        'Download ' + service.name + ' list'));
                    if (state.canManage) {
                        actions.append(button('Remove', (event) => {
                            if (window.confirm('Remove the Multi-Path list for ' + service.name + '?')) {
                                void mutate(event.currentTarget, () => api('removeService', {id: service.id}),
                                    'Multi-Path list removed.', () => {
                                        state.serviceDestinations.delete(service.id);
                                        if (state.editingService === service.id) {
                                            editService();
                                        }
                                    });
                            }
                        }, 'Remove ' + service.name));
                    }
                }
            }

            const select = byId('service-profile');
            options(select, choicesFor(select.value), 'Leave unassigned');
            options(byId('service-preset'), Object.keys(state.presets).map((name) => ({value: name, label: name})),
                'Custom list');
        }

        function downloadEntries(name, entries) {
            const filename = name.trim().replace(/[^a-z0-9_.-]+/gi, '-') || 'multi-path';
            const url = URL.createObjectURL(new Blob([entries.join('\n') + '\n'], {type: 'text/plain'}));
            const link = document.createElement('a');
            link.href = url;
            link.download = filename + '.txt';
            link.click();
            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        }

        function editService(service = null) {
            state.editingService = service?.id || null;
            state.domainRead++;
            byId('service-form').reset();
            byId('service-name').value = service?.name || '';
            const exit = byId('service-profile');
            if (service?.profile && ![...exit.options].some((option) => option.value === service.profile)) {
                exit.add(new Option('Unavailable server', service.profile));
            }
            exit.value = service?.profile || '';
            byId('service-scope').value = service?.scope || (service ? 'both' : byId('routing-scope').value);
            byId('service-domains').value = list(service?.domains).join('\n');
            byId('domain-file-status').textContent = '';
            byId('download-domains').disabled = !service;
            byId('cancel-service').hidden = !service;
            if (service) {
                byId('service-name').focus();
            }
        }

        function refreshProxyCatalog() {
            if (!state.proxyCatalogRequest) {
                state.proxyCatalogRequest = fetchProxyCatalog().finally(() => {
                    state.proxyCatalogRequest = null;
                });
            }
            return state.proxyCatalogRequest;
        }

        async function reloadProxyCatalog() {
            if (state.proxyCatalogRequest) {
                await state.proxyCatalogRequest;
            }
            return refreshProxyCatalog();
        }

        async function fetchProxyCatalog() {
            try {
                const catalog = await api('proxyCatalog');
                state.proxyNodes = array(catalog.nodes);
                const active = new Set(state.proxyNodes.map((node) => 'proxy:' + node.id));
                for (const key of state.tests.keys()) {
                    if (key.startsWith('proxy:') && !active.has(key)) {
                        state.tests.delete(key);
                    }
                }
                state.proxyFeeds = array(catalog.feeds);
                state.proxyCatalogLoaded = true;
                renderProxyCatalog();
                if (state.settings) {
                    renderProfiles();
                    renderSettings();
                    renderServices();
                }
            } catch (error) {
                notice(errorMessage(error, 'Proxy catalog unavailable.'), 'danger');
            }
        }

        function coreApi(action, payload) {
            return api(action, payload, '', 'core');
        }

        function renderCores(data) {
            const cores = array(data.cores);
            const body = byId('core-list');
            body.replaceChildren();
            const storage = data.storage || {};
            byId('core-storage').textContent = data.pending ? 'A core change is in progress.'
                : [data.architecture ? 'FreeBSD ' + data.architecture : '',
                    formatBytes(Math.floor(storage.freeBytes || 0)) + ' free on the state filesystem',
                    formatBytes(storage.coreBytes) + ' core updates',
                    formatBytes(storage.catalogBytes) + ' proxy catalog',
                    formatBytes(storage.reserveBytes) + ' reserved as free space'].filter(Boolean).join(' · ');
            for (const core of cores) {
                const row = body.insertRow();
                cell(row, core.id === 'mihomo' ? 'Mihomo (Clash)' : core.id);
                cell(row, core.installed ? shown(core.version, 'Installed') : 'Unavailable', '',
                    core.installed ? core.source : '');
                cell(row, core.available?.version || '—');
                const actions = row.insertCell();
                if (core.update) {
                    actions.append(button('Install', (event) => {
                        if (window.confirm('Install ' + core.id + ' ' + core.available.version + '? Its proxy tunnels will briefly restart.')) {
                            void mutate(event.currentTarget, () => coreApi('install', {
                                core: core.id, digest: core.available.sha256
                            }), 'Core updated.', renderCores);
                        }
                    }, 'Install update for ' + core.id));
                }
                if (core.rollback) {
                    actions.append(button('Roll back', (event) => {
                        if (window.confirm('Roll back ' + core.id + '? Its proxy tunnels will briefly restart.')) {
                            void mutate(event.currentTarget, () => coreApi('rollback', {core: core.id}),
                                'Core rolled back.', renderCores);
                        }
                    }, 'Roll back ' + core.id));
                }
            }
            options(byId('core-upload-id'), cores.filter((core) => core.available)
                .map((core) => ({value: core.id, label: core.id + ' ' + core.available.version})), 'Choose an approved release');
            byId('core-upload-id').onchange = () => {
                const selected = cores.find((core) => core.id === byId('core-upload-id').value);
                byId('core-upload-id').dataset.digest = selected?.available?.sha256 || '';
            };
            byId('core-upload-id').onchange();
        }

        async function refreshCores() {
            try {
                renderCores(await coreApi('status'));
            } catch (error) {
                byId('core-storage').textContent = errorMessage(error, 'Core status is unavailable.');
            }
        }

        function renderProxyCatalog() {
            const missing = ['mihomo', 'tun2socks'].filter((core) => state.proxyCores[core] !== true);
            byId('proxy-cores').textContent = missing.length
                ? 'Install ' + missing.join(' and ') + ' to enable proxy tunnels. You can import and inspect servers now.'
                : 'Proxy transport ready. Xray and sing-box servers require their corresponding core.';
            const subscriptions = byId('subscription-list');
            subscriptions.replaceChildren();
            if (!state.proxyFeeds.length) {
                empty(subscriptions, 'No proxy subscriptions.', 5);
            }
            for (const feed of state.proxyFeeds) {
                const row = subscriptions.insertRow();
                cell(row, feed.name, '', feed.auto ? 'Automatic refresh' : 'Manual refresh');
                cell(row, feed.count ?? 0, '', feed.skipped ? feed.skipped + ' entries skipped' : '');
                const usage = feed.usage || {};
                const used = Number.isInteger(usage.upload) && Number.isInteger(usage.download)
                    ? formatBytes(usage.upload + usage.download) || '0 B' : '';
                const cap = usage.total === 0 ? 'Unlimited' : formatBytes(usage.total);
                const data = [used ? used + ' used' : '', cap].filter(Boolean).join(' / ');
                const expiry = usage.expire > 0
                    ? (usage.expire <= Date.now() / 1000 ? 'Expired ' : 'Expires ') + date(usage.expire) : '';
                cell(row, data || '—', '', expiry);
                cell(row, date(feed.updated), '', feed.error || '');
                const actions = row.insertCell();
                actions.append(button('Refresh', (event) => void mutate(event.currentTarget,
                    () => api('refreshSubscription', {id: feed.id}), 'Subscription refreshed.', () => void reloadProxyCatalog())));
                actions.append(button(feed.auto ? 'Pause auto-refresh' : 'Enable auto-refresh', (event) => {
                    const auto = !feed.auto;
                    void mutate(event.currentTarget, () => api('setSubscriptionAuto', {id: feed.id, auto}),
                        auto ? 'Automatic refresh enabled.' : 'Automatic refresh paused.', () => void reloadProxyCatalog());
                }));
                actions.append(button('Remove', (event) => {
                    if (window.confirm('Remove this proxy subscription? Any enabled server keeps its current settings.')) {
                        void mutate(event.currentTarget, () => api('removeSubscription', {id: feed.id}),
                            'Subscription removed.', () => void reloadProxyCatalog());
                    }
                }));
            }

            const nodes = proxyServers();
            renderBulkPingControls('proxies', nodes.length);
            const pages = Math.max(1, Math.ceil(nodes.length / 50));
            state.proxyPage = Math.min(state.proxyPage, pages - 1);
            const offset = state.proxyPage * 50;
            const results = nodes.slice(offset, offset + 50);
            byId('proxy-count').textContent = nodes.length > results.length
                ? (offset + 1) + '–' + (offset + results.length) + ' of ' + nodes.length + ' servers'
                : nodes.length + (nodes.length === 1 ? ' server' : ' servers');
            byId('proxy-pages').hidden = pages < 2;
            byId('proxy-prev').disabled = state.proxyPage === 0;
            byId('proxy-next').disabled = state.proxyPage + 1 >= pages;
            const servers = byId('proxy-list');
            servers.replaceChildren();
            if (!results.length) {
                empty(servers, 'Import a server or subscription to get started.', 7);
            }
            const feedNames = new Map(state.proxyFeeds.map((feed) => [feed.id, feed.name]));
            for (const node of results) {
                const row = servers.insertRow();
                serverSelectionCell(row, 'proxy', node);
                const displayName = node.name || node.serverName || node.host;
                const groups = [...new Set(array(node.sources).map((source) => feedNames.get(source)).filter(Boolean))];
                const name = cell(row, groups.length ? groups.join(' · ') : displayName,
                    'Name / Group', groups.length ? displayName : '');
                name.dataset.serverName = node.id;
                const address = endpoint(node.host, node.port);
                const server = cell(row, node.serverName || node.host, 'Server', address);
                server.querySelector('small').title = address;
                if (node.legacy) {
                    const warning = document.createElement('span');
                    warning.textContent = 'Legacy';
                    warning.title = 'Legacy or unencrypted transport';
                    const detail = server.querySelector('small');
                    detail.append(' · ', warning);
                    detail.title = address + ' · ' + warning.title;
                }
                cell(row, proxyProtocol(node).toUpperCase(), 'Protocol');
                const exit = state.profiles.find((profile) => profile.node === node.id);
                const status = node.disabled ? 'Disabled' : exit?.status || 'Ready to assign';
                const core = cell(row, node.core, 'Core', status);
                core.querySelector('small').title = status;
                const ping = cell(row, '—', 'Ping');
                ping.className = 'bv-ping-cell';
                const actions = serverControls(row);
                appendConnectionTest(actions, exit ? 'testExit' : 'testProxyNode', exit?.id || node.id, node.name,
                    {nodeId: node.id, ping});
                const edit = nameEditor(row, node.name, node.id, 'renameProxyNode',
                    renderProxyCatalog, (name) => { node.name = name; });
                if (edit) {
                    actions.append(edit);
                }
                const disabled = node.disabled === true;
                const enable = button(disabled ? 'Enable' : 'Disable', (event) =>
                    void mutate(event.currentTarget, () => api(disabled ? 'enableProxyExit' : 'disableProxyNode', {id: node.id}),
                        disabled ? 'Proxy enabled.' : 'Proxy disabled.', () => void reloadProxyCatalog()));
                const assigned = exit && profileInUse(exit.id);
                enable.disabled = !disabled && Boolean(assigned);
                if (enable.disabled) {
                    enable.title = 'Remove this server from routing rules first.';
                }
                actions.append(enable);
                const remove = button('Remove', (event) => {
                    if (window.confirm('Remove “' + node.name + '” from the proxy list?')) {
                        void mutate(event.currentTarget, () => api('removeProxyNode', {id: node.id}),
                            'Server removed.', () => void reloadProxyCatalog());
                    }
                }, 'Remove ' + node.name);
                remove.disabled = Boolean(removalReason('proxy', node));
                remove.title = removalReason('proxy', node);
                actions.append(remove);
            }
            updateServerSelection('proxy');
        }

        function proxyProtocol(node) {
            return node.protocol === 'socks' ? 'socks5' : node.protocol;
        }

        function renderWarnings(warnings) {
            const node = byId('warnings');
            node.replaceChildren();
            for (const warning of warnings) {
                const entry = document.createElement('li');
                entry.textContent = typeof warning === 'string' ? warning : shown(warning?.message, '');
                if (entry.textContent) {
                    node.append(entry);
                }
            }
            node.hidden = !node.children.length;
        }

        function refreshDashboard() {
            if (!state.dashboardRequest) {
                state.dashboardRequest = fetchDashboard().finally(() => {
                    state.dashboardRequest = null;
                });
            }
            return state.dashboardRequest;
        }

        async function refreshSignInStatus() {
            if (state.dashboardRequest) {
                await state.dashboardRequest;
            }
            await refreshDashboard();
        }

        async function fetchDashboard() {
            state.deviceAvailabilityRevision++;
            const refresh = byId('refresh');
            const loginRevision = state.loginRevision;
            refresh.disabled = true;
            try {
                const data = await api('dashboard');
                applyLanguage(data.language);
                state.profiles = array(data.profiles);
                for (const profile of state.profiles) {
                    if (profile.provider !== 'mullvad' || profile.reachability !== 'router probe succeeded') {
                        continue;
                    }
                    const key = 'exit:' + profile.id;
                    const test = state.tests.get(key);
                    if (test?.kind === 'fail' && Number(profile.checkedAt) > Number(test.checkedAt || 0)) {
                        state.tests.delete(key);
                    }
                }
                state.assignments = array(data.assignments);
                state.devices = array(data.devices);
                state.tailnetDevices = array(data.tailnetDevices);
                state.tailnetStatusAvailable = data.tailnetStatusAvailable === true;
                state.discoveryTruncated = data.truncated === true;
                state.services = array(data.services);
                const serviceIds = new Set(state.services.map((service) => service.id));
                for (const id of state.serviceTests.keys()) {
                    if (!serviceIds.has(id)) {
                        state.serviceTests.delete(id);
                    }
                }
                state.proxyCores = data.proxyCores || {};
                state.canManageCores = data.canManageCores === true;
                state.canManageUpdates = data.canManageUpdates === true && !insecureWebGui;
                state.canWriteUpdates = data.canWriteUpdates === true && state.canManageUpdates;
                state.canManageBackups = data.canManageBackups === true && !insecureWebGui;
                byId('core-manager').hidden = !state.canManageCores;
                state.presets = data.servicePresets || {};
                state.vpnProviders = data.vpnProviders || {mullvad: {name: 'Mullvad'}};
                state.providerAccounts = data.providerAccounts || {};
                state.mystAuth = data.mystAuth || {};
                state.ivpnAuth = data.ivpnAuth || {};
                state.nativeGateways = array(data.nativeGateways);
                const providers = Object.entries(state.vpnProviders).map(([value, details]) => ({value, label: details.name}))
                    .sort((a, b) => serviceOrder.compare(a.label, b.label));
                options(byId('provider'), providers, 'Choose a VPN service', byId('provider').value || state.provider);
                renderProvider();
                state.settings = data.settings;
                renderSystem();
                state.canManage = data.canManage !== false;
                state.activeSmartInterfaces = list(data.activeSmartInterfaces || data.settings?.smartInterfaces);
                if (!state.signingIn && loginRevision === state.loginRevision) {
                    const signedIn = data.mullvadSignedIn === true && !insecureWebGui;
                    const saved = data.mullvadLoginSaved === true && !insecureWebGui;
                    if (saved !== state.mullvadLoginSaved) {
                        byId('save-login').checked = saved;
                        state.restoreAttempted = false;
                    }
                    state.mullvadLoginSaved = saved;
                    if (state.mullvadSignedIn && !signedIn) {
                        byId('account-status').textContent = saved ? 'Reconnecting saved Mullvad login…'
                            : 'Mullvad sign-in expired. Sign in again to add servers.';
                    }
                    setMullvadSignedIn(signedIn);
                    if (signedIn && !byId('account-status').textContent) {
                        byId('account-status').textContent = 'Signed in to Mullvad.';
                        refreshMullvadAccount();
                    }
                    restoreSavedLogin();
                }
                if (!state.canManage && state.section === 'proxies') {
                    showSection('network');
                }
                root.dataset.canManage = String(state.canManage);
                if (!state.canManage) {
                    byId('assignment').hidden = true;
                    state.editing = null;
                    closeNetworkDevice();
                }
                state.availableInterfaces = array(data.settings?.availableInterfaces || data.availableInterfaces);
                if (!byId('assignment').hidden && byId('device-kind').value === 'tailnet') {
                    renderAssignmentInterfaces();
                }
                renderProfiles();
                if (state.catalogLoaded) {
                    renderRelays();
                }
                renderServices();
                renderProxyCatalog();
                renderSettings();
                renderTailscale();
                renderWarnings(array(data.warnings));
                if (state.canManage && !state.proxyCatalogLoaded) {
                    await refreshProxyCatalog();
                }
            } catch (error) {
                byId('observed').textContent = 'Devices and rules could not be refreshed.';
                notice(errorMessage(error, 'Network settings are unavailable.'), 'danger');
                if (!byId('device-list').children.length) {
                    empty(byId('device-list'), 'Saved rules are unavailable.');
                }
            } finally {
                refresh.disabled = state.deviceRefreshRunning;
            }
        }

        function updateFailure() {
            const mode = byId('mode').value;
            const full = mode === 'full';
            const combined = mode === 'full_multi';
            const baseServer = usesBaseServer(mode);
            const primary = baseServer ? byId('profile').value : '';
            const failover = byId('failure');
            const tailnet = byId('device-kind').value === 'tailnet';
            const interfaceField = byId('interface');
            const automatic = tailnet && (interfaceField.value === 'tailscale0' ||
                list(state.settings?.tailscaleInterfaces).length === 0);
            byId('assignment-interface-field').hidden = automatic;
            interfaceField.required = !automatic;
            byId('save-device').disabled = (automatic && !state.settings?.tailscaleSetup?.ready && !state.editing)
                || (!tailnet && state.assignmentDevice?.addressConflict === true);
            byId('mac-field').hidden = tailnet;
            byId('mac').required = !tailnet;
            byId('ipv6-field').hidden = automatic;
            byId('ipv6').required = tailnet && !automatic;
            byId('profile-label').textContent = combined ? 'Base server' : 'Saved server';
            byId('profile-field').hidden = !baseServer;
            byId('profile').required = baseServer;
            const kill = byId('device-kill');
            const supportsKillSwitch = baseServer || mode === 'multi';
            byId('device-kill-field').hidden = !supportsKillSwitch;
            kill.disabled = !supportsKillSwitch || combined;
            requireKillSwitch(kill, combined);
            const allowOnDemand = full && !tailnet;
            byId('device-on-demand-field').hidden = !allowOnDemand;
            byId('device-on-demand-note').hidden = !supportsKillSwitch;
            byId('device-on-demand').disabled = !allowOnDemand;
            byId('device-on-demand-note').textContent = allowOnDemand && byId('device-on-demand').checked
                ? 'Automatically uses this rule when the device connects. Shared tunnels may stay ready.'
                : 'Keep the tunnel ready while this rule is enabled.';
            const killSwitch = supportsKillSwitch && kill.checked;
            byId('failure-field').hidden = !full || !primary || killSwitch;
            const showBackup = full && primary && !killSwitch && failover.value === 'backup';
            byId('backup-field').hidden = !showBackup;
            byId('backup').required = Boolean(showBackup);
            const servers = routingServers();
            options(byId('backup'), servers.filter((profile) => profile.id !== primary).map(exitChoice), 'Choose a backup server');
            const profile = servers.find((item) => item.id === primary);
            byId('profile').setCustomValidity(primary && !profile ? 'Choose an available route.'
                : combined && profile && !hasVpnDns(profile) ? 'Choose a base server with VPN DNS.' : '');
            const interfaceId = byId('interface').value.trim();
            const notes = [];
            if (tailnet) {
                notes.push(automatic ? (state.settings?.tailscaleSetup?.ready
                    ? 'Traffic uses this rule when the device selects OPNsense as its exit node.'
                    : state.settings?.tailscaleSetup?.reason || 'Check Tailscale Settings for exit node setup.')
                    : 'Use the peer addresses seen on the configured gateway link.');
            }
            if (mode === 'multi' || combined) {
                notes.push('Matching destinations use their Multi-Path servers.');
                notes.push(combined ? 'Default traffic uses the base server.'
                    : killSwitch ? 'Other internet traffic is blocked.' : 'Other traffic uses regular internet.');
                if (!state.services.some((service) => service.profile && service.profile !== bypassDestination)) {
                    notes.push('Assign a server to a list in Multi-Path Settings.');
                }
            }
            if (mode === 'blocked') {
                notes.push('Internet is blocked for the assigned addresses. Approved local access follows your firewall rules.');
            }
            if (killSwitch) {
                notes.push(combined ? 'An offline Multi-Path server blocks only its matching destinations. An offline base server blocks internet.'
                    : full ? 'The Kill Switch blocks internet for this device if its server goes offline.'
                        : 'If a Multi-Path server goes offline, its matching destinations are blocked.');
                notes.push('Bypass is unavailable while the Kill Switch is on.');
            } else if (supportsKillSwitch) {
                notes.push('Bypass uses direct internet when available.');
            }
            const strict = list(state.settings?.strictInterfaces).includes(interfaceId);
            if (killSwitch && !tailnet) {
                notes.push('Public IPv6 is blocked for this interface while a LAN device has Kill Switch enabled.');
            } else if ((full || mode === 'blocked' || killSwitch) && !automatic && !strict && !byId('ipv6').value.trim()) {
                notes.push('Enter a stable IPv6 address to cover it too.');
            }
            byId('route-note').textContent = notes.join(' ');
        }

        function deviceMacBinding() {
            return !byId('device-bind-mac').disabled && byId('device-bind-mac').checked;
        }

        function reserveDeviceAddress() {
            const observed = state.assignmentDevice;
            return byId('device-kind').value === 'lan' &&
                Boolean(observed?.reserveIp && observed.canUseInterface) &&
                (!state.editing || state.editing.bindMac === true);
        }

        function updateDeviceIdentity() {
            const observed = state.assignmentDevice;
            const saved = state.editing;
            const tailnet = byId('device-kind').value === 'tailnet';
            const supportsMac = !tailnet && (observed?.macBindingSupported === true || saved?.bindMac === true);
            byId('device-bind-mac-field').hidden = !supportsMac;
            byId('device-bind-mac').disabled = !supportsMac;
            const bindMac = deviceMacBinding();
            const reserve = reserveDeviceAddress();
            const waitingForAddress = saved?.bindMac && bindMac && !saved.effectiveIp;
            if (!tailnet && (observed || saved)) {
                const observedAddress = observed?.reserveAddress || observed?.ip || saved?.ip || '';
                byId('ip').value = bindMac ? (observed?.effectiveIp || saved?.effectiveIp ||
                    (waitingForAddress && reserve ? observed.reserveAddress : observed?.ip) || saved?.ip || '')
                    : (saved && !saved.bindMac ? saved.ip : observedAddress);
            }
            byId('save-device').textContent = reserve ? 'Reserve IP and save rule' : 'Save device rule';
            let note = '';
            if (observed && !observed.canUseInterface && !tailnet) {
                note = 'Select this interface under Routing coverage and save, then refresh.';
            } else if (observed?.addressConflict) {
                note = 'Check the device’s DHCP lease and reservation in OPNsense, then refresh.';
            } else if (bindMac) {
                note = 'The rule follows changes to the DHCP reservation for this MAC on the selected interface.';
                if (reserve) {
                    note += ' Saving reserves the current address.';
                }
                if (waitingForAddress) {
                    note += ' Waiting for DHCP. The rule can be edited now and will follow the next confirmed reservation.';
                }
            } else if (reserve) {
                note = 'Save this device’s current address as a DHCP reservation and apply the rule.';
            } else if (tailnet && observed && !observed.reserved) {
                note = 'This peer needs both Tailscale addresses.';
            } else if (tailnet && !observed && !saved) {
                note = 'Use the device’s IPv4 address from the Tailscale app. OPNsense verifies the peer when you save.';
            } else if (tailnet && saved && !state.settings?.tailscaleSetup?.ready) {
                note = 'Changes are saved for the next time the Tailscale exit node is ready.';
            } else if (!tailnet && !observed?.reserved && (!saved || saved.bindMac === true)) {
                note = 'Use the device’s reserved DHCP address and MAC.';
            }
            byId('identity').textContent = note;
        }

        function renderAssignmentInterfaces(previous = byId('interface').value) {
            const managed = list(state.settings?.interfaces);
            const tailnet = list(state.settings?.tailscaleInterfaces);
            const peer = byId('device-kind').value === 'tailnet';
            const choices = availablePorts().filter((port) => managed.includes(port.id)
                && (peer ? tailnet.includes(port.id) : !tailnet.includes(port.id)))
                .map((port) => ({value: port.id, label: networkName(port.id)}));
            if (peer && (state.settings?.tailscaleSetup?.ready || previous === 'tailscale0')) {
                choices.unshift({value: 'tailscale0', label: networkName('tailscale0')});
            }
            if (state.editing && previous && !choices.some((choice) => choice.value === previous)) {
                choices.push({value: previous, label: networkName(previous)});
            }
            options(byId('interface'), choices, choices.length ? 'Choose an interface' : 'Enable an interface first',
                previous || (peer && state.settings?.tailscaleSetup?.ready ? 'tailscale0'
                    : (choices.length === 1 ? choices[0].value : '')));
        }

        function supportsNetworkDeviceBypass(mode) {
            return usesBaseServer(mode) || mode === 'multi';
        }

        function closeNetworkDevice() {
            byId('network-device').hidden = true;
            state.networkDevice = null;
        }

        function openNetworkDevice(assignment, discovered, showBypass, enableBypass = false) {
            byId('assignment').hidden = true;
            state.editing = null;
            state.networkDevice = {assignment, discovered, showBypass};
            const name = byId('network-device-name');
            name.value = assignment?.label || discovered?.label || discovered?.ip || '';
            byId('network-device-bypass-field').hidden = !showBypass;
            byId('network-device-bypass').checked = enableBypass || assignment?.networkBypass === true;
            const reserve = !assignment && discovered?.reserveIp;
            const notes = [];
            if (showBypass) {
                notes.push('Bypass sends this device’s IPv4 traffic directly to the internet while supported Whole-Network coverage is active and its Kill Switch is off.');
            }
            if (reserve) {
                notes.push('Saving reserves the device’s current DHCP address.');
            }
            byId('network-device-note').textContent = notes.join(' ');
            byId('network-device').hidden = false;
            name.focus();
        }

        function openAssignment(assignment = null, kind = 'lan', discovered = null) {
            closeNetworkDevice();
            state.editing = assignment;
            state.assignmentDevice = discovered;
            const device = assignment || discovered;
            const locked = Boolean(device);
            byId('assignment').hidden = false;
            byId('assignment-title').textContent = assignment ? 'Edit device rule' : 'Add device rule';
            byId('ip').value = device?.ip || '';
            byId('mac').value = device?.mac || '';
            byId('ipv6').value = device?.ipv6 || '';
            byId('device-kind').value = assignment?.kind || kind;
            byId('device-kind').disabled = locked;
            renderAssignmentInterfaces(device?.interface || '');
            byId('mode').value = modes[assignment?.mode] ? assignment.mode : 'full';
            byId('ip').readOnly = locked;
            byId('ipv6').readOnly = Boolean(discovered && kind === 'tailnet');
            byId('interface').disabled = Boolean(device?.interface);
            byId('mac').readOnly = locked;
            byId('device-label').value = device?.label || '';
            const selected = assignment?.profile || '';
            const choices = routingServers().map(exitChoice);
            if (selected && !choices.some((choice) => choice.value === selected)) {
                choices.push({value: selected, label: 'Unavailable VPN profile'});
            }
            options(byId('profile'), choices, 'Choose a server', selected);
            byId('failure').value = assignment?.failure === 'backup' ? 'backup' : 'wan';
            requireKillSwitch(byId('device-kill'), false);
            byId('device-kill').checked = (usesBaseServer(assignment?.mode) || assignment?.mode === 'multi')
                ? (assignment.killSwitch ?? assignment.failure === 'block') : true;
            byId('device-on-demand').checked = assignment?.onDemand !== false;
            byId('device-bind-mac').checked = assignment ? assignment.bindMac === true
                : discovered?.macBindingSupported === true;
            updateDeviceIdentity();
            updateFailure();
            byId('backup').value = assignment?.backup || '';
            byId('remove-assignment').hidden = !assignment;
            byId('assignment-title').focus();
        }

        async function mutate(control, operation, success, onSuccess, recover) {
            if (state.busy) {
                return;
            }
            state.busy = true;
            updateServerSelection('vpn');
            updateServerSelection('proxy');
            control = control || byId('refresh');
            control.disabled = true;
            notice('Waiting for the router…');
            try {
                const result = await operation();
                const message = typeof result.message === 'string' ? result.message : success;
                const reconnectWarning = result.reconnected?.incomplete
                    ? ' Some existing sessions could not be reset.' : '';
                const warning = result.warning ? ' ' + result.warning : reconnectWarning;
                notice(message + (result.killSwitchReset ? ' Previous connections from the assigned addresses were reset.' : '')
                    + warning, warning ? 'warning' : 'success');
                if (onSuccess) {
                    onSuccess(result);
                }
                if (state.dashboardRequest) {
                    await state.dashboardRequest;
                }
                await refreshDashboard();
            } catch (error) {
                if (error.ambiguous && recover) {
                    try {
                        if (await recover()) {
                            notice(success, 'success');
                            return;
                        }
                    } catch (_) {
                        // Keep the original request error when the status check also fails.
                    }
                }
                notice(errorMessage(error, 'The operation could not be completed.'), 'danger');
            } finally {
                state.busy = false;
                control.disabled = false;
                updateServerSelection('vpn');
                updateServerSelection('proxy');
            }
        }

        function removeProfile(profile, control) {
            if (!window.confirm('Remove “' + profileName(profile.id) + '” from this router?')) {
                return;
            }
            const operation = profile.node && profile.provider === 'nord'
                ? () => api('removeManagedNord', {id: profile.node})
                : () => api('removeProfile', {id: profile.id});
            void mutate(control, operation, 'VPN server removed.', () => {
                if (profile.node) {
                    state.proxyNodes = state.proxyNodes.filter((node) => node.id !== profile.node);
                    state.proxyCatalogLoaded = false;
                }
                state.tests.delete(profile.node ? 'proxy:' + profile.node : 'exit:' + profile.id);
            });
        }

        function relayCity(relay) {
            return relay.country + ' / ' + relay.city;
        }

        function renderRelays() {
            const relays = state.relays;
            const countries = [...new Set(relays.map((item) => item.country).filter(Boolean))].sort();
            options(byId('country'), countries.map((value) => ({value, label: value})), 'All countries');
            const country = byId('country').value;
            const fromCountry = relays.filter((item) => !country || item.country === country);
            const cities = new Map(fromCountry.filter((item) => item.city)
                .map((item) => [relayCity(item), country ? item.city : item.city + ', ' + item.country]));
            const cityChoices = [...cities].map(([value, label]) => ({value, label}))
                .sort((left, right) => left.label.localeCompare(right.label));
            options(byId('city'), cityChoices, 'All cities');
            const city = byId('city').value;
            const servers = fromCountry.filter((item) => !city || relayCity(item) === city)
                .sort((left, right) => String(left.hostname || left.id).localeCompare(String(right.hostname || right.id)));
            const previousRelay = byId('relay').value;
            options(byId('relay'), servers.map((relay) => ({
                value: relay.id,
                label: (relay.hostname || relay.id) + (relay.active === false ? ' (unavailable)' : '')
            })), 'Select a server');
            [...byId('relay').options].slice(1).forEach((option, index) => {
                option.disabled = servers[index].active === false;
            });
            if (servers.some((server) => server.id === previousRelay && server.active === false)) {
                byId('relay').value = '';
            }
            renderRelayChoice();
        }

        function renderRelayChoice() {
            const relay = state.relays.find((item) => item.id === byId('relay').value && item.active !== false);
            byId('relay-choice').textContent = relay
                ? [relay.country, relay.city, relay.hostname || relay.id].filter(Boolean).join(' · ')
                : '';
            const result = relay && state.tests.get('relay:' + relay.id);
            byId('relay-test').textContent = result?.text || '';
            byId('relay-test').dataset.result = result?.kind || '';
            const register = byId('register');
            const saved = relay && state.profiles.some((profile) => profile.relay === relay.id);
            register.textContent = saved ? 'Already added' : 'Add server';
            register.disabled = !relay || !state.mullvadSignedIn || Boolean(saved);
            byId('test-relay').disabled = !relay || !state.mullvadSignedIn ||
                state.tests.get('relay:' + relay.id)?.kind === 'pending';
        }

        async function pingRelay() {
            const relay = byId('relay').value;
            const key = 'relay:' + relay;
            await testConnection('testRelay', relay, key, false);
        }

        function appendConnectionTest(actions, action, id, name, {nodeId, disabled = false, title = 'Test', ping} = {}) {
            const key = nodeId ? 'proxy:' + nodeId
                : ({testDeviceRoute: 'device:', testTailnetBase: 'tailnet-base:'}[action] || 'exit:') + id;
            const control = button(title, () => void testConnection(action, id, key, Boolean(nodeId)), title + ' ' + name);
            control.dataset.testKey = key;
            control.dataset.proxyTest = String(Boolean(nodeId));
            control.dataset.disabled = String(disabled);

            const status = document.createElement(ping ? 'div' : 'small');
            status.className = ping ? 'bv-ping-result' : 'bv-test-result';
            status.dataset.testResult = key;
            const detail = document.createElement('span');
            detail.setAttribute('role', 'status');
            const dismiss = button('×', () => {
                const result = state.tests.get(key);
                if (result?.kind === 'fail') {
                    result.dismissed = true;
                    refreshConnectionTests(key);
                    control.focus();
                }
            }, 'Dismiss test error for ' + name);
            dismiss.className = 'bv-test-dismiss';
            let error;
            if (ping) {
                error = button('Failed', () => {
                    const dialog = byId('ping-dialog');
                    const result = state.tests.get(key);
                    byId('ping-dialog-title').textContent = name + (result?.kind === 'fail' ? ' · Test failed' : ' · Route test');
                    byId('ping-dialog-detail').textContent = result?.text || '';
                    dialog.showModal();
                }, 'Show test error for ' + name);
                error.className = 'bv-ping-error';
                status.append(detail, error, dismiss);
                ping.replaceChildren(status);
            } else {
                status.append(detail, dismiss);
                actions.append(status);
            }
            actions.prepend(control);
            testDisplays.set(control, {status, detail, dismiss, error, name});
            updateConnectionTest(control);
        }

        function updateConnectionTest(control) {
            const {status, detail, dismiss, error, name} = testDisplays.get(control);
            const result = state.tests.get(control.dataset.testKey);
            control.disabled = control.dataset.disabled === 'true' || result?.kind === 'pending' ||
                Boolean(state.bulkPing.kind) || (control.dataset.proxyTest === 'true' && state.proxyTestRunning);
            const failed = result?.kind === 'fail' && result.dismissed !== true;
            if (error) {
                const routeTest = result?.routeTest === true && !result.dismissed && Boolean(result.latency);
                const label = routeTest ? result.latency : failed ? 'Failed' : result?.kind === 'pass' ? result.latency
                    : result?.kind === 'pending' ? 'Testing…' : '—';
                detail.textContent = routeTest ? result.text : label;
                detail.classList.toggle('bv-ping-announcement', failed || routeTest);
                error.hidden = !failed && !routeTest;
                error.textContent = label;
                error.title = failed || routeTest ? result.text : '';
                if (routeTest) {
                    error.setAttribute('aria-label', result.text);
                } else {
                    error.setAttribute('aria-label', 'Show test error for ' + name);
                }
            } else {
                status.hidden = !result || result.dismissed === true;
                detail.textContent = result?.text || '';
            }
            dismiss.hidden = !failed;
            status.dataset.result = result?.dismissed ? '' : result?.kind || '';
        }

        function refreshConnectionTests(key, proxy = false) {
            const selector = proxy ? '[data-proxy-test="true"]' : '[data-test-key="' + CSS.escape(key) + '"]';
            for (const control of root.querySelectorAll(selector)) {
                updateConnectionTest(control);
            }
        }

        async function testConnection(action, id, key, proxy) {
            if (state.tests.get(key)?.kind === 'pending' || (proxy && state.proxyTestRunning)) {
                return;
            }
            if (proxy) {
                state.proxyTestRunning = true;
            }
            const relay = action === 'testRelay';
            state.tests.set(key, {kind: 'pending', text: relay ? 'Pinging from OPNsense…' : 'Testing HTTPS…'});
            if (relay) {
                renderRelayChoice();
            } else {
                refreshConnectionTests(key, proxy);
            }
            try {
                const result = await api(action, relay ? {relay: id} : {id});
                if (action === 'testDeviceRoute' || action === 'testTailnetBase') {
                    const target = action === 'testTailnetBase' ? 'Base server'
                        : result.usingBackup ? 'Backup server' : 'Assigned server';
                    const reachability = result.reachable === true
                        ? target + ' · router HTTPS ' + result.milliseconds + ' ms'
                        : target + ' · ' + (result.detail || 'router HTTPS failed');
                    const offlinePeers = Array.isArray(result.offlinePeers)
                        ? result.offlinePeers.filter(name => typeof name === 'string' && name !== '').slice(0, 5) : [];
                    const unseen = offlinePeers.length
                        ? 'No completed connection observed from the device. Offline Tailscale peers: '
                            + offlinePeers.join(', ') + '. Connect the test device, select OPNsense as its exit node, '
                            + 'open a new page, and try again.'
                        : 'No completed connection observed from the device. Open a new page on the device and try again.';
                    const observation = {
                        seen: 'Recent device traffic seen in both directions',
                        partial: 'Some recent device connections received replies. Other TCP attempts have no observed reply.',
                        oneway: 'Recent TCP attempts reached the selected route. OPNsense saw no reply for those attempts.',
                        unseen,
                        inactive: result.forwardingIssue || 'Device rule has no active VPN path',
                        unavailable: 'Device traffic status unavailable'
                    };
                    const kind = result.reachable !== true || result.deviceTraffic === 'inactive' ? 'fail'
                        : result.deviceTraffic === 'seen' ? 'pass' : 'unverified';
                    state.tests.set(key, {kind, text: reachability + ' · ' + observation[result.deviceTraffic], routeTest: true,
                        latency: result.reachable === true ? result.milliseconds + ' ms' : null});
                    return;
                }
                state.tests.set(key, relay ? (result.replied
                    ? {kind: 'pass', text: 'ICMP reply · ' + result.milliseconds + ' ms'}
                    : {kind: 'fail', text: 'No ICMP reply. The WireGuard service may still be available.'})
                    : result.reachable === true
                    ? {kind: 'pass', text: 'HTTPS passed · ' + result.milliseconds + ' ms',
                        latency: result.milliseconds + ' ms', milliseconds: Number(result.milliseconds)}
                    : {kind: 'fail', text: result.detail || 'The HTTPS test did not complete.',
                        checkedAt: result.checkedAt || Math.floor(Date.now() / 1000)});
            } catch (error) {
                state.tests.set(key, {kind: 'fail', text: errorMessage(error, 'The connection test could not be completed.'),
                    checkedAt: Math.floor(Date.now() / 1000)});
            } finally {
                if (proxy) {
                    state.proxyTestRunning = false;
                }
                if (relay) {
                    renderRelayChoice();
                } else {
                    refreshConnectionTests(key, proxy);
                }
                if (action === 'testExit' || action === 'testProxyNode') {
                    const profile = state.profiles.find((item) =>
                        item.id === id || (item.node && 'proxy:' + item.node === key));
                    const status = [...byId('profile-list').querySelectorAll('[data-vpn-status]')]
                        .find((cell) => cell.dataset.vpnStatus === profile?.id);
                    if (status && profile) {
                        status.textContent = vpnStatus(profile);
                    }
                }
            }
        }

        function setMullvadSignedIn(signedIn) {
            state.mullvadSignedIn = signedIn;
            byId('login-form').hidden = signedIn || insecureWebGui;
            byId('register-form').hidden = !signedIn;
            byId('restore-login').hidden = insecureWebGui || signedIn || !state.mullvadLoginSaved;
            byId('sign-out').hidden = insecureWebGui || (!signedIn && !state.mullvadLoginSaved);
            byId('sign-out').textContent = state.mullvadLoginSaved
                ? (signedIn ? 'Sign out and forget login' : 'Forget saved login') : 'Sign out';
            renderRelayChoice();
            if (signedIn && !state.catalogLoaded) {
                void loadRelays();
            }
        }

        function restoreSavedLogin() {
            if (state.section === 'vpns' && state.canManage && state.mullvadLoginSaved && !state.mullvadSignedIn
                && state.provider === 'mullvad' && !state.signingIn && !state.restoreAttempted) {
                void inspectAccount(true);
            }
        }

        async function loadRelays(refresh = false) {
            const status = byId('relay-status');
            const button = byId('refresh-relays');
            if (button.disabled) {
                return;
            }
            button.disabled = true;
            status.textContent = 'Loading Mullvad relay catalog…';
            try {
                const response = await api(refresh ? 'refreshRelays' : 'relays', refresh ? {} : undefined);
                state.catalogLoaded = true;
                state.relays = array(response.relays);
                renderRelays();
                const count = state.relays.length;
                const updated = response.fetchedAt ?? response.updated;
                const refreshError = response.refreshError || response.error;
                status.textContent = count + ' WireGuard server' + (count === 1 ? '' : 's')
                    + (updated ? ' · Updated ' + date(updated) : '')
                    + (response.stale ? ' · Catalog is stale or unavailable' : '');
                if (refreshError) {
                    status.textContent += ' · ' + refreshError;
                }
            } catch (error) {
                status.textContent = errorMessage(error, 'Relay catalog unavailable.')
                    + (state.relays.length ? ' Showing the previous results.' : '');
            } finally {
                button.disabled = false;
            }
        }

        function accountNumber() {
            const value = byId('account').value.replace(/[\s-]/g, '');
            if (!/^\d{16}$/.test(value)) {
                throw new Error(translated('Enter the 16-digit Mullvad account number.'));
            }
            return value;
        }

        async function inspectAccount(restore = false) {
            const control = byId(restore ? 'restore-login' : 'inspect-account');
            const target = byId('account-status');
            if (insecureWebGui || state.signingIn) {
                return;
            }
            control.disabled = true;
            byId('sign-out').disabled = true;
            state.signingIn = true;
            state.restoreAttempted = true;
            state.loginRevision++;
            target.textContent = translated(restore ? 'Reconnecting saved Mullvad login…' : 'Signing in to Mullvad…');
            try {
                const payload = restore ? {} : {account: accountNumber(), saveLogin: byId('save-login').checked};
                byId('account').value = '';
                const response = await api(restore ? 'restoreMullvad' : 'account', payload);
                state.mullvadLoginSaved = response.saved === true;
                state.restoreAttempted = false;
                byId('save-login').checked = state.mullvadLoginSaved;
                setMullvadSignedIn(true);
                renderMullvadAccount(response);
            } catch (error) {
                if (error.ambiguous) {
                    state.signingIn = false;
                    try {
                        await refreshSignInStatus();
                        if (state.mullvadSignedIn) {
                            target.textContent = translated('Signed in to Mullvad.');
                            refreshMullvadAccount();
                            notice(translated('Mullvad sign-in completed.'), 'success');
                            return;
                        }
                    } catch (_) {
                        // Report the original request error if status cannot be confirmed.
                    }
                }
                setMullvadSignedIn(false);
                target.textContent = '';
                notice(errorMessage(error, 'Account information is unavailable.'), 'danger');
            } finally {
                state.signingIn = false;
                control.disabled = false;
                byId('sign-out').disabled = false;
            }
            if (state.mullvadSignedIn) {
                void refreshSignInStatus();
            }
        }

        function renderMullvadAccount(response) {
            const target = byId('account-status');
            const devices = array(response.devices);
            const limit = response.maxDevices ?? response.limit;
            const expiry = response.expiresAt ?? response.expiry;
            target.textContent = (state.mullvadLoginSaved ? 'Signed in to Mullvad. Login saved. ' : 'Signed in to Mullvad. ') + devices.length + (limit ? ' of ' + limit : '') + ' device slots used.'
                + (expiry ? (response.expired ? ' Account expired ' : ' Account expires ') + date(expiry) + '.' : '')
                + (!response.expired && (response.canAddDevices === false || response.availableSlots === 0)
                    ? ' New registrations are unavailable. A registration from a removed server may be reusable.' : '');
            if (devices.length) {
                const names = document.createElement('ul');
                for (const device of devices) {
                    const entry = document.createElement('li');
                    entry.textContent = shown(device.name, 'Registered WireGuard device');
                    names.append(entry);
                }
                target.append(names);
            }
        }

        function refreshMullvadAccount() {
            if (state.mullvadSignedIn) {
                void api('mullvadAccountStatus').then((response) => {
                    if (state.mullvadSignedIn) {
                        renderMullvadAccount(response);
                    }
                }).catch(() => {});
            }
        }

        function endpoint(value, port) {
            if (!value || typeof value === 'object') {
                return '—';
            }
            return port ? (String(value).includes(':') ? '[' + value + ']:' + port : value + ':' + port) : value;
        }

        function toBytes(value) {
            if (value === null || value === undefined || value === '') {
                return null;
            }
            const parsed = Number(value);
            return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
        }

        function formatBytes(value) {
            const amount = toBytes(value);
            if (amount === null) {
                return '';
            }
            if (amount < 1024) {
                return amount + ' B';
            }
            const units = ['KiB', 'MiB', 'GiB', 'TiB'];
            let size = amount / 1024;
            let unit = 0;
            while (size >= 1024 && unit < units.length - 1) {
                size /= 1024;
                unit += 1;
            }
            return size.toFixed(1) + ' ' + units[unit];
        }

        byId('message-dismiss').addEventListener('click', (event) => {
            const focused = document.activeElement === event.currentTarget;
            notice('');
            if (focused) {
                root.querySelector('[data-bv-section][aria-pressed="true"]')?.focus();
            }
        });
        byId('close-ping-dialog').addEventListener('click', () => byId('ping-dialog').close());
        byId('refresh').addEventListener('click', async (event) => {
            const control = event.currentTarget;
            state.deviceRefreshRunning = true;
            control.disabled = true;
            let failure = '';
            try {
                await state.dashboardRequest;
                if (state.canManage) {
                    byId('observed').textContent = 'Finding LAN and Tailscale devices…';
                    await api('discoverDevices', {});
                }
            } catch (error) {
                failure = errorMessage(error, 'The active LAN check could not finish.');
            } finally {
                await refreshDashboard();
                if (failure) {
                    notice(failure, 'warning');
                }
                state.deviceRefreshRunning = false;
                control.disabled = false;
            }
        });
        byId('add-device').addEventListener('click', () => openAssignment());
        byId('add-tailnet-peer').addEventListener('click', () => openAssignment(null, 'tailnet'));
        byId('close-network-device').addEventListener('click', () => {
            closeNetworkDevice();
            byId('refresh').focus();
        });
        byId('network-device-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const current = state.networkDevice;
            if (!current) {
                return;
            }
            const {assignment, discovered, showBypass} = current;
            const coverage = byId(assignment?.kind === 'tailnet' ? 'tailnet-coverage' : 'coverage');
            if (coverage.value !== 'network') {
                return;
            }
            const label = byId('network-device-name').value.trim();
            if (!label) {
                byId('network-device-name').focus();
                return;
            }
            let payload = {label};
            if (assignment) {
                payload.id = assignment.id;
            } else {
                if (discovered.reserveIp && !window.confirm('Reserve this IP address and save the device? OPNsense will reload the DHCP service.')) {
                    return;
                }
                payload = {...payload, ip: discovered.reserveAddress, mac: discovered.mac,
                    interface: discovered.interface, reserveIp: discovered.reserveIp, bindMac: discovered.macBindingSupported};
            }
            if (showBypass) {
                const bypass = byId('network-device-bypass').checked;
                if (bypass !== (assignment?.networkBypass === true)) {
                    payload.networkBypass = bypass;
                }
            }
            void mutate(event.submitter, () => api('setNetworkDevice', payload), 'Device saved.', closeNetworkDevice);
        });
        byId('close-assignment').addEventListener('click', () => {
            byId('assignment').hidden = true;
            state.editing = null;
            byId('add-device').focus();
        });
        byId('mode').addEventListener('change', updateFailure);
        byId('device-kind').addEventListener('change', () => {
            renderAssignmentInterfaces();
            updateDeviceIdentity();
            updateFailure();
        });
        byId('ipv6').addEventListener('input', updateFailure);
        byId('profile').addEventListener('change', updateFailure);
        byId('failure').addEventListener('change', updateFailure);
        byId('device-kill').addEventListener('change', updateFailure);
        byId('device-on-demand').addEventListener('change', updateFailure);
            byId('device-bind-mac').addEventListener('change', updateDeviceIdentity);
        byId('interface').addEventListener('change', updateFailure);
        byId('assign-form').addEventListener('submit', (event) => {
            event.preventDefault();
            if (byId('save-device').disabled) {
                return;
            }
            const reserveIp = reserveDeviceAddress();
            if (reserveIp && !window.confirm('Reserve this IP address and save the rule? OPNsense will reload the DHCP service.')) {
                return;
            }
            const mode = byId('mode').value;
            const payload = {
                ...(state.editing ? {id: state.editing.id} : {}),
                reserveIp,
                ip: byId('ip').value.trim(),
                interface: byId('interface').value.trim(),
                mac: byId('mac').value.trim(),
                ipv6: byId('ipv6').value.trim(),
                kind: byId('device-kind').value,
                mode,
                label: byId('device-label').value.trim(),
                profile: byId('profile').value,
                backup: byId('backup').required ? byId('backup').value : '',
                killSwitch: mode === 'full_multi' || (!byId('device-kill').disabled && byId('device-kill').checked),
                onDemand: !byId('device-on-demand').disabled && byId('device-on-demand').checked,
                failure: byId('device-kill').checked || mode !== 'full' ? 'block' : byId('failure').value
            };
            if (payload.kind === 'lan') {
                payload.bindMac = deviceMacBinding();
            }
            void mutate(event.submitter, () => api('assign', payload), 'Device assignment saved.', () => {
                if (state.editing) {
                    state.tests.delete('device:' + state.editing.id);
                }
                byId('assignment').hidden = true;
                state.editing = null;
            });
        });
        byId('remove-assignment').addEventListener('click', (event) => {
            const id = state.editing?.id;
            const strict = list(state.settings?.strictInterfaces).includes(state.editing?.interface);
            const explanation = strict ? ' This strict interface blocks unassigned clients.'
                : ' The device will use the normal network policy and any Multi-Path rules.';
            if (id && window.confirm('Remove this device assignment?' + explanation)) {
                void mutate(event.currentTarget, () => api('removeAssignment', {id}), 'Device assignment removed.', () => {
                    byId('assignment').hidden = true;
                    state.editing = null;
                });
            }
        });
        if (insecureWebGui) {
            const target = new URL(window.location.href);
            target.protocol = 'https:';
            byId('secure-link').href = target.href;
            byId('login-http').hidden = false;
            byId('proxy-http').hidden = false;
        }
        setMullvadSignedIn(false);
        byId('provider-picker').addEventListener('submit', (event) => {
            event.preventDefault();
            const provider = byId('provider').value;
            if (state.busy || !state.vpnProviders[provider]) {
                return;
            }
            if (provider !== state.provider) {
                state.provider = provider;
                state.ivpnConfirmationAccount = '';
                for (const id of ['provider-login', 'ivpn-login', 'provider-server-form', 'provider-import', 'provider-native']) {
                    byId(id).reset();
                }
                const locationFilter = state.providerLocations.get(provider)?.country;
                byId('provider-country').value = ['nord', 'ivpn'].includes(provider) ? locationFilter || '' : '';
                byId('myst-type').value = provider === 'mysterium' ? locationFilter || 'hosting' : 'hosting';
                byId('provider-server-status').textContent = '';
                byId('provider-manual').open = !state.vpnProviders[provider].login;
                byId('account').value = '';
            }
            renderProvider();
            if (provider === 'mullvad') {
                restoreSavedLogin();
            } else if (!state.providerLocations.has(provider)) {
                void loadProviderServers();
            }
        });
        function bindSignIn(formId, buttonId, signIn) {
            const form = byId(formId);
            const control = byId(buttonId);
            const run = () => {
                if (form.reportValidity()) {
                    signIn(control);
                }
            };
            control.addEventListener('click', run);
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                run();
            });
            form.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' && event.target.tagName === 'INPUT') {
                    event.preventDefault();
                    run();
                }
            });
        }
        bindSignIn('provider-login', 'provider-sign-in', (control) => {
            const provider = state.provider;
            const secret = byId('provider-secret');
            const payload = {provider, username: byId('provider-user').value.trim(), secret: secret.value};
            if (state.busy || insecureWebGui) {
                return;
            }
            secret.value = '';
            void mutate(control, () => api('providerLogin', payload), translated('VPN login saved.'), () => {
                state.providerAccounts[provider] = true;
                state.providerLocations.delete(provider);
                byId('provider-login').reset();
                renderProvider();
                void loadProviderServers();
            }, async () => {
                await refreshSignInStatus();
                if (state.providerAccounts[provider] === true) {
                    void loadProviderServers();
                    return true;
                }
                return false;
            });
        });
        function updateMystAuth(result) {
            state.mystAuth = result;
            state.providerAccounts.mysterium = result.authenticated === true;
            renderProvider();
            if (result.authenticated) {
                void loadProviderServers();
            }
        }

        byId('myst-begin').addEventListener('click', (event) => {
            void mutate(event.currentTarget, () => api('mystBeginAuth', {}), translated('Mysterium approval link created.'), updateMystAuth,
                async () => {
                    await refreshSignInStatus();
                    return state.mystAuth.pending === true || state.providerAccounts.mysterium === true;
                });
        });
        byId('myst-poll').addEventListener('click', (event) => {
            void mutate(event.currentTarget, async () => {
                const result = await api('mystPollAuth', {});
                return {...result, message: result.authenticated ? 'Mysterium VPN login saved.'
                    : result.pending ? 'Mysterium is still waiting for approval.' : 'Start a new Mysterium sign-in.'};
            }, translated('Mysterium VPN sign-in checked.'), updateMystAuth, async () => {
                await refreshSignInStatus();
                if (state.providerAccounts.mysterium === true) {
                    void loadProviderServers();
                    return true;
                }
                return state.mystAuth.pending === true;
            });
        });
        byId('myst-type').addEventListener('change', () => {
            renderProvider();
            void loadProviderServers();
        });
        bindSignIn('ivpn-login', 'ivpn-sign-in', (control) => {
            if (state.busy || insecureWebGui) {
                return;
            }
            const account = byId('ivpn-account');
            const confirmation = byId('ivpn-confirmation');
            const payload = {account: account.value.trim() || state.ivpnConfirmationAccount, confirmation: confirmation.value.trim()};
            account.value = '';
            confirmation.value = '';
            void mutate(control, async () => {
                const result = await api('ivpnLogin', payload);
                return {...result, message: result.message || (result.authenticated ? 'IVPN login saved.' : 'Finish signing in to IVPN.')};
            }, translated('IVPN sign-in checked.'), (result) => {
                state.ivpnAuth = result;
                state.ivpnConfirmationAccount = result.challenge === 'totp' ? payload.account : '';
                state.providerAccounts.ivpn = result.saved === true;
                renderProvider();
                if (result.saved) {
                    void loadProviderServers();
                }
            }, async () => {
                await refreshSignInStatus();
                if (state.providerAccounts.ivpn === true) {
                    void loadProviderServers();
                    return true;
                }
                if (state.ivpnAuth.challenge === 'totp') {
                    state.ivpnConfirmationAccount = payload.account;
                    renderProvider();
                    return true;
                }
                return false;
            });
        });
        byId('provider-logout').addEventListener('click', (event) => {
            const provider = state.provider;
            void mutate(event.currentTarget, () => api('providerLogout', {provider}), 'Signed out. Saved tunnels can still be used.', () => {
                state.providerAccounts[provider] = false;
                if (provider === 'mysterium') {
                    state.mystAuth = {};
                } else if (provider === 'ivpn') {
                    state.ivpnAuth = {};
                    state.ivpnConfirmationAccount = '';
                }
                state.providerLocations.delete(provider);
                byId('provider-server-status').textContent = '';
                renderProvider();
            });
        });
        byId('provider-reload').addEventListener('click', () => void loadProviderServers(true));
        byId('provider-country').addEventListener('input', renderProvider);
        byId('provider-server').addEventListener('change', renderProvider);
        byId('provider-server-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const provider = state.provider;
            const payload = {
                provider, server: byId('provider-server').value, name: byId('provider-name').value.trim(),
                country: byId('provider-country').disabled ? '' : byId('provider-country').value.trim().toUpperCase()
            };
            const operation = provider === 'mysterium' ? () => api('addMystExit', {
                server: payload.server, name: payload.name, ipType: byId('myst-type').value, dns: byId('myst-dns').value.trim()
            }) : provider === 'ivpn' ? () => api('addIvpnExit', {server: payload.server, name: payload.name, country: payload.country})
                : () => api('addProviderExit', payload);
            void mutate(event.submitter, operation, 'VPN server added.', () => {
                byId('provider-name').value = '';
                byId('provider-server').value = '';
            }).then(renderProvider);
        });
        byId('import-file').addEventListener('change', async () => {
            const input = byId('import-file');
            const file = input.files[0];
            const provider = state.provider;
            if (!file) {
                return;
            }
            if (file.size > 16384) {
                notice('Choose a WireGuard configuration under 16 KiB.', 'danger');
                return;
            }
            try {
                const config = await file.text();
                if (state.provider === provider && input.files[0] === file) {
                    byId('import-config').value = config;
                }
            } catch (error) {
                notice(errorMessage(error, 'The configuration file could not be read.'), 'danger');
            }
        });
        byId('provider-import').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {provider: state.provider, name: byId('import-name').value.trim(),
                dns: byId('import-dns').value.trim(), config: byId('import-config').value};
            void mutate(event.submitter, () => api('importProfile', payload), 'WireGuard tunnel saved.',
                () => byId('provider-import').reset());
        });
        byId('provider-native').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {provider: state.provider, name: byId('native-name').value.trim(),
                dns: byId('native-dns').value.trim(), gateway: byId('native-gateway').value};
            void mutate(event.submitter, () => api('addNativeExit', payload), 'OPNsense VPN tunnel added.',
                () => byId('provider-native').reset());
        });
        byId('refresh-relays').addEventListener('click', () => void loadRelays(true));
        byId('country').addEventListener('change', renderRelays);
        byId('city').addEventListener('change', renderRelays);
        byId('relay').addEventListener('change', renderRelayChoice);
        byId('test-relay').addEventListener('click', () => void pingRelay());
        bindSignIn('login-form', 'inspect-account', () => void inspectAccount());
        byId('restore-login').addEventListener('click', () => void inspectAccount(true));
        byId('sign-out').addEventListener('click', (event) => {
            void mutate(event.currentTarget, () => api('logoutMullvad', {}), 'Signed out of Mullvad.', () => {
                state.loginRevision++;
                state.mullvadLoginSaved = false;
                state.restoreAttempted = false;
                byId('save-login').checked = true;
                setMullvadSignedIn(false);
                byId('account-status').textContent = '';
            });
        });
        byId('register-form').addEventListener('submit', (event) => {
            event.preventDefault();
            if (!state.mullvadSignedIn || byId('register').disabled) {
                return;
            }
            const payload = {relay: byId('relay').value, name: byId('register-name').value.trim(),
                port: Number(byId('register-port').value)};
            void mutate(event.submitter, () => api('register', payload), 'Mullvad server added.', (result) => {
                if (result.profile) {
                    state.tests.delete('exit:' + result.profile);
                }
                byId('register-name').value = '';
                byId('register-port').value = '51820';
                byId('relay').value = '';
            }).then(() => {
                renderRelayChoice();
                refreshMullvadAccount();
            });
        });
        byId('use-lan').addEventListener('click', () => {
            showSection('network');
            selectRoutingScope('local');
            const port = byId('managed').querySelector('[value="lan"]');
            if (!port) {
                return;
            }
            port.checked = true;
            if (byId('coverage').value === 'network') {
                byId('network-mode').value = 'multi';
            } else {
                byId('interface-rules').querySelector('[data-interface="lan"] select').value = 'smart';
                byId('smart-assigned').checked = true;
                byId('advanced').open = true;
            }
            state.settingsDirty = true;
            updateCoverage();
            port.focus();
        });
        byId('service-preset').addEventListener('change', (event) => {
            const preset = event.target.value;
            if (Array.isArray(state.presets[preset])) {
                byId('service-name').value = preset;
                byId('service-domains').value = state.presets[preset].join('\n');
                byId('download-domains').disabled = false;
            }
        });
        byId('cancel-service').addEventListener('click', () => editService());
        byId('service-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                id: state.editingService || '',
                name: byId('service-name').value.trim(),
                profile: byId('service-profile').value,
                scope: byId('service-scope').value,
                domains: byId('service-domains').value.trim()
            };
            const message = payload.profile ? 'Multi-Path list saved with ' + profileName(payload.profile) + '.'
                : 'Multi-Path list saved. Choose a destination when ready.';
            void mutate(event.submitter, () => api('saveService', payload), message, () => {
                state.serviceDestinations.delete(payload.id);
                editService();
            });
        });
        byId('service-file').addEventListener('change', async (event) => {
            const input = event.currentTarget;
            const read = ++state.domainRead;
            const file = input.files[0];
            if (!file) {
                return;
            }
            const status = byId('domain-file-status');
            if (file.size > maxDomainBytes) {
                status.textContent = 'Choose a list file up to 128 KiB.';
                input.value = '';
                return;
            }
            try {
                const content = await file.text();
                if (state.domainRead !== read) {
                    return;
                }
                byId('service-domains').value = content;
                if (!byId('service-name').value.trim()) {
                    byId('service-name').value = file.name.replace(/\.(txt|csv)$/i, '').replace(/[<>]/g, '').slice(0, 64);
                }
                byId('download-domains').disabled = !content.trim();
                status.textContent = file.name + ' loaded. Save the list to keep it.';
                input.value = '';
            } catch {
                if (state.domainRead === read) {
                    status.textContent = 'Could not read the file. Paste its entries into the editor.';
                }
            }
        });
        byId('service-domains').addEventListener('input', (event) => {
            byId('download-domains').disabled = !event.target.value.trim();
        });
        byId('download-domains').addEventListener('click', () => {
            const name = byId('service-name').value.trim().replace(/[^a-z0-9_.-]+/gi, '-') || 'multi-path';
            const entries = byId('service-domains').value.trim();
            const url = URL.createObjectURL(new Blob([entries + '\n'], {type: 'text/plain'}));
            const link = document.createElement('a');
            link.href = url;
            link.download = name + '.txt';
            link.click();
            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        });
        for (const button of root.querySelectorAll('[data-bv-section]')) {
            button.addEventListener('click', () => showSection(button.dataset.bvSection));
        }

        function manualFields() {
            const protocol = byId('manual-protocol').value;
            const basic = ['socks5', 'http', 'https'].includes(protocol);
            const uuid = ['vless', 'vmess', 'tuic'].includes(protocol);
            byId('manual-user-label').textContent = uuid ? 'UUID' : 'Username';
            byId('manual-user-field').hidden = !basic && !uuid;
            byId('manual-username').required = uuid;
            byId('manual-secret-field').hidden = ['vless', 'vmess'].includes(protocol);
            byId('manual-secret').required = !basic && !byId('manual-secret-field').hidden;
            byId('manual-cipher-field').hidden = protocol !== 'ss';
            byId('manual-cipher').required = protocol === 'ss';
            byId('manual-params-field').hidden = protocol === 'http' || protocol === 'https';
            byId('manual-note').hidden = protocol !== 'vless' && protocol !== 'socks5';
            byId('manual-note').textContent = protocol === 'socks5'
                ? 'For a provider that offers TLS or UDP, use tls=true, sni=hostname, or udp=true. Join multiple options with &.'
                : 'For REALITY, include security=reality, sni, pbk (public key), sid (short ID), and fp (fingerprint) in the link parameters, joined by &.';
        }

        byId('manual-protocol').addEventListener('change', manualFields);
        byId('proxy-manual').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {name: byId('manual-name').value.trim(), protocol: byId('manual-protocol').value,
                host: byId('manual-host').value.trim(), port: byId('manual-port').value};
            for (const [field, wrapper] of [['username', 'user'], ['secret', 'secret'], ['cipher', 'cipher'], ['parameters', 'params']]) {
                if (!byId('manual-' + wrapper + '-field').hidden) {
                    payload[field] = byId('manual-' + field).value;
                }
            }
            void mutate(event.submitter, () => api('addProxyNode', payload), 'Proxy server added.', () => {
                event.target.reset();
                manualFields();
                void reloadProxyCatalog();
            });
        });
        manualFields();

        byId('core-manager').addEventListener('toggle', () => {
            if (byId('core-manager').open && state.canManageCores) {
                void refreshCores();
            }
        });
        byId('core-check').addEventListener('click', (event) => {
            void mutate(event.currentTarget, () => coreApi('check', {}), 'Approved core catalog refreshed.', renderCores);
        });
        byId('core-upload').addEventListener('submit', (event) => {
            event.preventDefault();
            const select = byId('core-upload-id');
            const file = byId('core-archive').files[0];
            if (!file || !select.dataset.digest) {
                return;
            }
            if (file.size > 100 * 1024 * 1024) {
                notice('Choose an approved archive smaller than 100 MiB.', 'danger');
                return;
            }
            if (!window.confirm('Verify and install this archive? Its proxy tunnels will briefly restart.')) {
                return;
            }
            const data = new FormData();
            data.append('core', select.value);
            data.append('digest', select.dataset.digest);
            data.append('upload', '1');
            data.append('archive', file);
            void mutate(event.submitter, () => coreApi('install', data), 'Core archive installed.', (result) => {
                event.target.reset();
                renderCores(result);
            });
        });
        for (const kind of ['vpn', 'proxy']) {
            byId(kind + '-select-all').addEventListener('change', (event) => {
                toggleAllServers(kind, event.currentTarget.checked);
            });
            byId(kind + '-remove-selected').addEventListener('click', (event) => {
                void removeSelectedServers(kind, event.currentTarget);
            });
        }
        byId('proxy-prev').addEventListener('click', () => {
            state.proxyPage--;
            renderProxyCatalog();
        });
        byId('proxy-next').addEventListener('click', () => {
            state.proxyPage++;
            renderProxyCatalog();
        });
        async function bulkPing(kind, sort) {
            const status = byId(kind === 'vpns' ? 'vpn-ping-status' : 'proxy-ping-status');
            if (state.bulkPing.kind) {
                if (state.bulkPing.kind === kind && state.bulkPing.sort === sort) {
                    state.bulkPing.stop = true;
                    status.textContent = 'Stopping after the current server…';
                }
                return;
            }
            if (state.proxyTestRunning) {
                status.textContent = 'Wait for the current server test to finish.';
                return;
            }
            const items = kind === 'vpns' ? vpnServers() : proxyServers();
            if (!items.length) {
                return;
            }
            state.bulkPing = {kind, sort, stop: false};
            if (kind === 'vpns') {
                state.vpnFixedOrder = items.map((item) => item.id);
            } else {
                state.proxyFixedOrder = items.map((item) => item.id);
            }
            kind === 'vpns' ? renderProfiles() : renderProxyCatalog();
            let checked = 0;
            try {
                for (const item of items) {
                    if (state.bulkPing.stop) {
                        break;
                    }
                    status.textContent = 'Testing ' + (checked + 1) + ' of ' + items.length + ' servers…';
                    const exit = kind === 'vpns' ? item : state.profiles.find((profile) => profile.node === item.id);
                    const dormant = kind === 'vpns' && item.node && item.id.startsWith('proxy-');
                    const action = !exit || dormant ? 'testProxyNode' : 'testExit';
                    const id = action === 'testProxyNode' ? item.node || item.id : exit.id;
                    const key = kind === 'proxies' || item.node ? 'proxy:' + (item.node || item.id) : 'exit:' + item.id;
                    await testConnection(action, id, key, kind === 'proxies' || Boolean(item.node));
                    checked++;
                }
            } finally {
                const stopped = state.bulkPing.stop;
                state.bulkPing = {kind: '', sort: false, stop: false};
                if (sort && !stopped) {
                    if (kind === 'vpns') {
                        state.vpnFixedOrder = null;
                        state.vpnSortByPing = true;
                    } else {
                        state.proxyFixedOrder = null;
                        state.proxySortByPing = true;
                    }
                }
                status.textContent = (stopped ? 'Stopped after ' : sort ? 'Sorted ' : 'Tested ') +
                    checked + ' of ' + items.length + ' servers.' +
                    (stopped ? '' : sort ? ' Lowest HTTPS latency first; failed tests last.' : ' Order unchanged.');
                if (sort && !stopped) {
                    if (kind === 'vpns') {
                        renderProfiles();
                    } else {
                        state.proxyPage = 0;
                        renderProxyCatalog();
                    }
                } else {
                    renderBulkPingControls(kind, items.length);
                    for (const control of root.querySelectorAll('[data-test-key]')) {
                        updateConnectionTest(control);
                    }
                }
            }
        }
        byId('vpn-ping-all').addEventListener('click', () => void bulkPing('vpns', false));
        byId('vpn-ping-sort').addEventListener('click', () => void bulkPing('vpns', true));
        byId('proxy-ping-all').addEventListener('click', () => void bulkPing('proxies', false));
        byId('proxy-ping-sort').addEventListener('click', () => void bulkPing('proxies', true));
        byId('proxy-import').addEventListener('submit', (event) => {
            event.preventDefault();
            const body = byId('proxy-body').value.trim();
            const name = byId('proxy-import-name').value.trim();
            void mutate(event.submitter, () => api('importProxies', {body, name}), 'Proxy servers imported.', (result) => {
                event.target.reset();
                notice(result.imported + ' servers imported' + (result.skipped ? ' · ' + result.skipped + ' skipped' : ''), 'success');
                void reloadProxyCatalog();
            });
        });
        byId('subscription-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                name: byId('subscription-name').value.trim(), url: byId('subscription-url').value.trim(),
                auto: byId('subscription-auto').checked
            };
            void mutate(event.submitter, () => api('addSubscription', payload), 'Proxy subscription added.', () => {
                event.target.reset();
                void reloadProxyCatalog();
            });
        });
        byId('use-local-name').addEventListener('click', () => {
            byId('hostname').value = 'blankvpn.local';
            byId('dashboard-bind').value = 'lan';
            state.tailscaleDirty = true;
            renderDashboardAddress();
            byId('bonjour').open = true;
        });
        byId('tailscale-form').addEventListener('input', () => {
            state.tailscaleDirty = true;
            renderDashboardAddress();
        });
        byId('tailscale-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                hostname: byId('hostname').value.trim(),
                dashboardBind: byId('dashboard-bind').value,
                tailscaleInterfaces: checkedInterfaces('tailnet-interfaces')
            };
            void mutate(event.submitter, () => api('tailscaleSettings', payload), 'Tailscale settings saved.', () => {
                state.tailscaleDirty = false;
            });
        });
        byId('add-tailnet-device').addEventListener('click', () => {
            showSection('network');
            selectRoutingScope('tailscale');
            openAssignment(null, 'tailnet');
        });
        byId('toggle-routing').addEventListener('click', (event) => {
            if (state.settings?.enabled && window.confirm('Disable Local routing and its Kill Switch?')) {
                event.preventDefault();
                void mutate(event.currentTarget, () => api('disable', {}), 'Local VPN routing disabled.', () => {
                    state.settingsDirty = false;
                });
            } else if (state.settings?.enabled) {
                event.preventDefault();
            }
        });
        byId('routing-scope').addEventListener('change', (event) => selectRoutingScope(event.target.value));
        byId('tailnet-coverage-form').addEventListener('input', () => {
            state.tailnetRoutingDirty = true;
            byId('assignment').hidden = true;
            updateCoverage(true);
            renderDeviceRules();
        });
        byId('tailnet-coverage-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const enabled = event.submitter === byId('toggle-tailnet-routing') ||
                coverageSettings(true)?.enabled === true;
            const payload = {
                enabled,
                coverage: byId('tailnet-coverage').value,
                networkMode: byId('tailnet-network-mode').value,
                networkProfile: byId('tailnet-network-profile').required ? byId('tailnet-network-profile').value : '',
                networkKillSwitch: byId('tailnet-network-kill').checked
            };
            const saved = coverageSettings(true);
            const changed = !saved?.enabled || ['coverage', 'networkMode', 'networkProfile', 'networkKillSwitch']
                .some((field) => payload[field] !== saved[field]);
            if (changed && enabled && payload.coverage === 'network' && payload.networkMode !== 'disabled'
                && !window.confirm('Apply this route to all clients using the OPNsense Tailscale exit node? Internet connections may reconnect.')) {
                return;
            }
            void mutate(event.submitter, () => api('tailnetRouting', payload),
                enabled ? 'Tailscale VPN routing saved and enabled.' : 'Tailscale settings saved; VPN remains disabled.', () => {
                state.tailnetRoutingDirty = false;
            });
        });
        byId('toggle-tailnet-routing').addEventListener('click', (event) => {
            if (coverageSettings(true)?.enabled && window.confirm('Disable Tailscale routing and its Kill Switch?')) {
                event.preventDefault();
                void mutate(event.currentTarget, () => api('tailnetRouting', {enabled: false}), 'Tailscale VPN routing disabled.', () => {
                    state.tailnetRoutingDirty = false;
                });
            } else if (coverageSettings(true)?.enabled) {
                event.preventDefault();
            }
        });
        byId('settings-form').addEventListener('input', (event) => {
            state.settingsDirty = true;
            if (event.target !== byId('local')) {
                updateCoverage();
            }
            if ([byId('coverage'), byId('network-mode'), byId('network-kill')].includes(event.target)) {
                closeNetworkDevice();
                if (event.target === byId('coverage')) {
                    byId('assignment').hidden = true;
                    state.editing = null;
                }
                renderDeviceRules();
            }
        });
        byId('settings-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const enabled = event.submitter === byId('toggle-routing') || state.settings?.enabled === true;
            const interfaces = checkedInterfaces('managed');
            const rules = [...byId('interface-rules').children].filter((label) => interfaces.includes(label.dataset.interface));
            const selected = (type) => rules.filter((label) => label.querySelector('select').value === type)
                .map((label) => label.dataset.interface);
            const networkMode = byId('network-mode').value;
            const payload = {
                enabled,
                networkKillSwitch: byId('network-kill').checked,
                coverage: byId('coverage').value,
                networkMode,
                networkProfile: byId('network-profile').required ? byId('network-profile').value : '',
                interfaces,
                strictInterfaces: selected('strict'),
                smartInterfaces: selected('smart'),
                smartAssignedOnly: byId('smart-assigned').checked,
                localNetworks: list(byId('local').value)
            };
            const knownStrict = list(state.settings?.strictInterfaces);
            if (payload.enabled && payload.coverage === 'device' && payload.strictInterfaces.length
                && (!state.settings?.enabled || payload.strictInterfaces.some((item) => !knownStrict.includes(item)))
                && !window.confirm('Enable strict VPN routing? Unassigned devices on these interfaces can lose internet access.')) {
                return;
            }
            const current = state.settings;
            const wideChange = payload.enabled && payload.coverage === 'network' && payload.networkMode !== 'disabled'
                && (!current?.enabled || current.coverage !== 'network' || current.networkMode !== payload.networkMode
                    || current.networkProfile !== payload.networkProfile
                    || current.networkKillSwitch !== payload.networkKillSwitch
                    || list(current.interfaces).filter((id) => !list(current.tailscaleInterfaces).includes(id)).join(',') !== payload.interfaces.join(','));
            const networkLabel = networkMode === 'full_multi' ? 'Whole-Network + Multi-Path' : modes[networkMode];
            if (wideChange && !window.confirm('Apply ' + networkLabel + ' to all devices on the selected networks? Existing internet connections may reconnect.')) {
                return;
            }
            void mutate(event.submitter, () => api('settings', payload),
                enabled ? 'Local VPN routing saved and enabled.' : 'Local settings saved; VPN remains disabled.', () => {
                state.settingsDirty = false;
            });
        });
        window.addEventListener('pagehide', () => {
            state.bulkPing.stop = true;
            byId('account').value = '';
            byId('proxy-body').value = '';
            byId('subscription-url').value = '';
            byId('manual-secret').value = '';
            byId('manual-parameters').value = '';
        });

        async function runUpdate(action, payload = {}) {
            if (state.updateAction || !state.canWriteUpdates || !state.update?.supported || state.update.running) {
                return;
            }
            state.updateAction = action;
            renderUpdate(state.update);
            try {
                const result = await api(action, payload, '', 'update');
                renderUpdate({...result, pollUntil: Date.now() + 600000});
            } catch (error) {
                notice(errorMessage(error, 'The package update operation failed.'), 'danger');
            } finally {
                state.updateAction = '';
                renderUpdate(state.update);
            }
        }

        byId('update-check').addEventListener('click', () => void runUpdate('check'));
        byId('update-apply').addEventListener('click', () => {
            const version = state.update?.available;
            if (version && state.update.enabled) {
                void runUpdate('apply', {version});
            }
        });
        byId('backup-download').addEventListener('click', async (event) => {
            const control = event.currentTarget;
            control.disabled = true;
            try {
                const data = await api('export', {}, '', 'backup');
                const url = URL.createObjectURL(new Blob([JSON.stringify(data.backup, null, 2) + '\n'],
                    {type: 'application/json'}));
                const link = document.createElement('a');
                link.href = url;
                link.download = 'blank-vpn-routing-settings.json';
                link.click();
                window.setTimeout(() => URL.revokeObjectURL(url), 1000);
            } catch (error) {
                notice(errorMessage(error, 'The settings backup could not be downloaded.'), 'danger');
            } finally {
                control.disabled = false;
            }
        });
        byId('backup-file').addEventListener('change', () => {
            state.backup = null;
            restoreAvailability();
        });
        byId('backup-check').addEventListener('click', async (event) => {
            const control = event.currentTarget;
            const file = byId('backup-file').files[0];
            if (!file || file.size > 2097152) {
                notice('Choose a settings backup file up to 2 MiB.', 'danger');
                return;
            }
            state.backup = null;
            control.disabled = true;
            byId('backup-restore').disabled = true;
            try {
                const backup = await file.text();
                const result = await api('preview', {backup}, '', 'backup');
                if (byId('backup-file').files[0] !== file) {
                    return;
                }
                state.backup = {backup, confirmation: result.confirmation};
                const preview = result.preview;
                byId('backup-preview').textContent = 'Restore ' + preview.assignments + ' device rules and '
                    + preview.services + ' domain lists, replacing ' + preview.existingAssignments + ' rules and '
                    + preview.existingServices + ' lists. VPN routing remains disabled.';
            } catch (error) {
                notice(errorMessage(error, 'The settings backup could not be previewed.'), 'danger');
            } finally {
                restoreAvailability();
            }
        });
        byId('backup-restore').addEventListener('click', (event) => {
            if (!state.backup || !window.confirm('Replace the router’s saved Blank VPN & Proxy routing settings with this backup?')) {
                return;
            }
            void mutate(event.currentTarget, () => api('restore', state.backup, '', 'backup'),
                'Settings restored. VPN routing remains disabled.', () => {
                    state.backup = null;
                    state.settingsDirty = false;
                    byId('backup-file').value = '';
                }).then(restoreAvailability);
        });

        const appearance = byId('appearance');
        try {
            const saved = localStorage.getItem('blankvpn-appearance');
            if (['system', 'day', 'night'].includes(saved)) {
                appearance.value = saved;
            }
        } catch {
            appearance.value = 'system';
        }
        root.dataset.appearance = appearance.value;
        appearance.addEventListener('change', () => {
            root.dataset.appearance = appearance.value;
            try {
                localStorage.setItem('blankvpn-appearance', appearance.value);
            } catch {
                // The current theme still applies when browser storage is unavailable.
            }
        });
        void refreshDashboard();
        window.setInterval(() => {
            if (document.hidden || state.busy) {
                return;
            }
            if (state.section === 'network' && root.contains(document.activeElement)) {
                void refreshDeviceAvailability();
            } else if (byId('assignment').hidden && !root.contains(document.activeElement)) {
                void refreshDashboard();
            }
        }, 30000);
    }

    window.jQuery(start);
})();
