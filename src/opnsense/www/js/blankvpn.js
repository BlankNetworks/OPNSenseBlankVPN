(() => {
    'use strict';

    function start() {
        const byId = (id) => document.getElementById('bv-' + id);
        const root = document.getElementById('blankvpn');
        if (!root) {
            return;
        }

        const modes = {full: 'Use one VPN or proxy', multi: 'Multi-Path', disabled: 'Off', blocked: 'Blocked'};
        const insecureWebGui = window.location.protocol === 'http:';
        const maxDomainBytes = 131072;
        const state = {
            profiles: [],
            assignments: [],
            services: [],
            proxyNodes: [],
            proxyFeeds: [],
            proxyCores: {},
            canManageCores: false,
            section: 'vpns',
            mullvadSignedIn: false,
            presets: {},
            editingService: null,
            domainRead: 0,
            relays: [],
            settings: null,
            availableInterfaces: [],
            canManage: true,
            editing: null,
            connectionTarget: null,
            busy: false,
            dashboardRequest: null,
            settingsDirty: false,
            catalogLoaded: false,
            signingIn: false,
            mullvadLoginSaved: false,
            restoreAttempted: false,
            testingRelay: false,
            tailscaleDirty: false,
            loginRevision: 0,
            activeSmartInterfaces: []
        };

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
            return Number.isNaN(parsed.getTime()) ? shown(value) : parsed.toLocaleString();
        }

        function errorMessage(error, fallback) {
            return error instanceof Error ? error.message : fallback;
        }

        async function api(action, payload, path = '', controller = 'service') {
            const method = payload === undefined ? 'GET' : 'POST';
            if (insecureWebGui && ['addProxyNode', 'addSubscription', 'importProxies'].includes(action)) {
                throw new Error('Open the OPNsense WebGUI over HTTPS before submitting proxy settings.');
            }
            const request = {
                url: '/api/blankvpn/' + controller + '/' + action + path,
                method,
                dataType: 'json',
                cache: false,
                timeout: controller === 'core' ? 240000 : 45000
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
                    throw new Error('The router did not return a result. Refresh the dashboard to check what changed before retrying.');
                }
                throw new Error('The router did not return a readable result.');
            }
            const catalogWithCache = ['relays', 'refreshRelays'].includes(action) && Array.isArray(response?.relays);
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
            status.className = 'alert alert-' + type;
            status.textContent = text;
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

        function exitChoice(profile) {
            return {value: profile.id, label: profileName(profile.id),
                group: profile.kind === 'proxy' ? 'Proxy exits' : 'VPN exits'};
        }

        function showSection(section) {
            state.section = section;
            for (const button of root.querySelectorAll('[data-bv-section]')) {
                const active = button.dataset.bvSection === section;
                button.setAttribute('aria-pressed', String(active));
            }
            for (const panel of root.querySelectorAll('[data-bv-panel]')) {
                panel.hidden = panel.dataset.bvPanel !== section;
            }
            if (section === 'proxies' && state.canManage) {
                void refreshProxyCatalog();
            }
            if (section === 'vpns') {
                restoreSavedLogin();
            }
            if (section !== 'network') {
                byId('assignment').hidden = true;
                state.editing = null;
                byId('connections').hidden = true;
                state.connectionTarget = null;
            }
        }

        function profileName(id) {
            const profile = state.profiles.find((item) => item.id === id);
            return profile?.name || profile?.relay || (id ? 'Unavailable VPN profile' : 'Normal internet');
        }

        function networkName(id) {
            const entry = state.availableInterfaces.find((item) => item.id === id);
            if (!entry) {
                return shown(id);
            }
            return entry.device && entry.name !== entry.device
                ? [entry.device, entry.name].filter(Boolean).join(' · ') : (entry.device || entry.name || id);
        }

        function renderDeviceRules() {
            const body = byId('device-list');
            const wholeNetwork = state.settings?.coverage === 'network';
            byId('add-device').hidden = wholeNetwork;
            body.replaceChildren();
            if (!state.assignments.length) {
                empty(body, 'No saved device rules.');
                return;
            }
            for (const assignment of state.assignments) {
                const row = body.insertRow();
                const name = assignment.label || assignment.ip;
                cell(row, name, '', assignment.kind === 'tailnet' ? 'Tailscale device' : assignment.mac);
                cell(row, assignment.ip, 'Addresses', assignment.ipv6);
                cell(row, networkName(assignment.interface), 'Interface');
                cell(row, modes[assignment.mode] || 'Normal internet', 'Rule',
                    assignment.profile ? profileName(assignment.profile) : '');
                const status = wholeNetwork ? 'Paused by Whole-Network coverage'
                    : !state.settings?.enabled ? 'Routing off'
                        : assignment.appliedRoute || 'Rule saved';
                cell(row, status, 'Status', !wholeNetwork && assignment.killSwitchActive ? 'Kill switch active' : '');
                const actions = row.insertCell();
                actions.setAttribute('role', 'cell');
                if (state.canManage) {
                    actions.append(button('Edit', () => openAssignment(assignment), 'Edit ' + name));
                }
                actions.append(button('Connections', () => openConnections(assignment.ip, name), 'Connections for ' + name));
            }
        }

        function renderProfiles() {
            const body = byId('profile-list');
            const vpns = state.profiles.filter((profile) => profile.kind !== 'proxy');
            if (!vpns.length) {
                empty(body, 'No VPN exits have been added.');
            } else {
                body.replaceChildren();
                for (const profile of vpns) {
                    const row = body.insertRow();
                    const used = state.assignments.filter((assignment) =>
                        [assignment.profile, assignment.backup].includes(profile.id)).length;
                    const network = state.settings?.networkProfile === profile.id;
                    const services = state.services.filter((service) => service.profile === profile.id).length;
                    cell(row, profile.name || profile.relay, '', used + ' device assignment' + (used === 1 ? '' : 's')
                        + ' · ' + services + ' service' + (services === 1 ? '' : 's'));
                    cell(row, profile.relay || profile.gateway || profile.protocol || 'Imported WireGuard', '', profile.protocol);
                    cell(row, profile.interface, '', profile.ipv6 ? 'IPv6 configured' : '');
                    cell(row, date(profile.handshake ?? profile.latestHandshake));
                    const received = formatBytes(profile.receivedBytes ?? profile.received);
                    const sent = formatBytes(profile.sentBytes ?? profile.sent);
                    const transfer = received || sent
                        ? 'Tunnel counters · ' + (received || '—') + ' received · ' + (sent || '—') + ' sent'
                        : '';
                    const status = [
                        shown(profile.status),
                        profile.reachability,
                        transfer
                    ].filter(Boolean);
                    cell(row, status.shift(), '', status.join(' · '));
                    const actions = row.insertCell();
                    const remove = button('Remove', (event) => removeProfile(profile, event.currentTarget),
                        'Remove ' + profileName(profile.id));
                    remove.disabled = network || used > 0 || services > 0;
                    if (remove.disabled) {
                        remove.title = 'Remove this exit from routing policies first.';
                    }
                    if (state.canManage) {
                        actions.append(button('Test exit', (event) => void testExit(event.currentTarget, profile, 'vpn-test')));
                        actions.append(remove);
                    }
                }
            }

            const choices = state.profiles.map(exitChoice);
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

        function renderSettings() {
            const select = byId('network-profile');
            const savedExit = state.settingsDirty ? select.value : (state.settings?.networkProfile || '');
            const choices = routableExits().map(exitChoice);
            if (savedExit && !choices.some((choice) => choice.value === savedExit)) {
                choices.push({value: savedExit, label: 'Unavailable exit'});
            }
            options(select, choices, 'Choose an exit', savedExit);
            const settings = state.settings;
            if (settings && !state.settingsDirty) {
                byId('coverage').value = settings.coverage || 'device';
                byId('network-mode').value = settings.networkMode || 'disabled';
                byId('enabled').checked = settings.enabled === true || settings.enabled === '1';
                const ports = availablePorts();
                renderInterfaceChoices('managed', ports, list(settings.interfaces), 'No assigned home Ethernet or VLAN interfaces.');
                renderInterfaceRules(ports, settings);
                byId('smart-assigned').checked = settings.smartAssignedOnly === true;
                byId('local').value = list(settings.localNetworks).join(', ');
            }
            updateCoverage();
        }

        function routableExits() {
            return state.profiles.filter((profile) => profile.kind === 'proxy'
                || list(profile.dns).some((ip) => !ip.includes(':')));
        }

        function updateCoverage() {
            const network = byId('coverage').value === 'network';
            const mode = byId('network-mode').value;
            const exit = byId('network-profile');
            const selected = checkedInterfaces('managed');
            byId('device-options').hidden = network;
            for (const label of byId('interface-rules').children) {
                label.hidden = !selected.includes(label.dataset.interface);
            }
            byId('network-fields').hidden = !network;
            byId('network-profile-field').hidden = !network || mode !== 'full';
            exit.required = network && mode === 'full';
            const summary = {
                full: exit.value
                    ? 'All selected LANs and VLANs use ' + profileName(exit.value) + '. Internet is blocked if the exit is unavailable.'
                    : 'Add a VPN or proxy exit, then select it here.',
                multi: 'All selected LANs and VLANs use your domain lists. Other traffic uses normal internet.',
                blocked: 'Internet is blocked on the selected LANs and VLANs.',
                disabled: 'Devices use your normal OPNsense routing.'
            };
            byId('coverage-note').textContent = network ? summary[mode]
                : 'Select the ports you want to manage, then add rules for individual devices below.';
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
            byId('add-tailnet-device').hidden = settings.coverage === 'network' || selected.length === 0;
            if (!state.tailscaleDirty) {
                byId('hostname').value = settings.hostname || 'blankvpn.home.arpa';
                byId('dashboard-bind').value = settings.dashboardBind || 'lan';
                const eligible = availablePorts().filter((port) => port.id.startsWith('opt')
                    && list(settings.interfaces).includes(port.id) && !list(settings.strictInterfaces).includes(port.id));
                renderInterfaceChoices('tailnet-interfaces', eligible, selected,
                    'Enable a dedicated Ethernet or VLAN link on the Network page first.');
            }
            renderDashboardAddress();
        }

        function renderDashboardAddress() {
            const settings = state.settings;
            const address = settings?.dashboardAddresses?.[byId('dashboard-bind').value];
            const port = settings?.dashboardPort || 443;
            const suffix = (port === 443 ? '' : ':' + port) + '/ui/blankvpn/index';
            const hostname = settings?.hostname || 'blankvpn.home.arpa';
            const url = 'https://' + hostname + suffix;
            const link = byId('dashboard-link');
            link.href = url;
            link.textContent = url;
            const direct = byId('address-link');
            byId('address-row').hidden = !address;
            if (address) {
                direct.href = 'https://' + address + suffix;
                direct.textContent = direct.href;
            }
            byId('bind-address').textContent = address
                ? 'Point the dashboard name at ' + address + ' in your DNS.'
                : 'The selected interface has no IPv4 address yet.';
        }

        function renderServices() {
            const interfaces = state.activeSmartInterfaces;
            const active = state.settings?.enabled && interfaces.length && state.services.some((service) => service.profile);
            byId('smart-status').textContent = active
                ? 'Routing matched DNS traffic on ' + interfaces.map(networkName).join(', ') + '.'
                : 'Saved lists start routing after you choose an exit and enable Multi-Path.';
            byId('use-lan').hidden = !state.availableInterfaces.some((item) => item.id === 'lan')
                || interfaces.includes('lan') || list(state.settings?.strictInterfaces).includes('lan');
            const body = byId('service-list');
            if (state.services.length === 0) {
                empty(body, 'No saved domain lists.', 4);
            } else {
                body.replaceChildren();
                for (const service of state.services) {
                    const row = body.insertRow();
                    const domains = list(service.domains);
                    cell(row, service.name, '', domains.length + (domains.length === 1 ? ' domain' : ' domains'));
                    cell(row, service.profile ? profileName(service.profile) : 'Unassigned');
                    const status = Object.entries(service.routing || {}).map(([id, rule]) =>
                        networkName(id) + ' · ' + (rule.gateway || (rule.guard ? 'Tunnel unavailable' : 'Inactive')));
                    cell(row, service.profile ? (status.join(' · ') || 'Inactive') : 'Saved', '',
                        Number.isInteger(service.learned) ? service.learned + ' learned addresses' : '');
                    const actions = row.insertCell();
                    if (state.canManage) {
                        actions.append(button('Edit', () => editService(service), 'Edit ' + service.name));
                        actions.append(button('Remove', (event) => {
                            if (window.confirm('Remove the Multi-Path list for ' + service.name + '?')) {
                                void mutate(event.currentTarget, () => api('removeService', {id: service.id}),
                                    'Service removed.', () => {
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
            const choices = routableExits().map(exitChoice);
            if (select.value && !choices.some((choice) => choice.value === select.value)) {
                choices.push({value: select.value, label: 'Unavailable exit'});
            }
            options(select, choices, 'Leave unassigned');
            options(byId('service-preset'), Object.keys(state.presets).map((name) => ({value: name, label: name})),
                'Custom list');
        }

        function editService(service = null) {
            state.editingService = service?.id || null;
            state.domainRead++;
            byId('service-form').reset();
            byId('service-name').value = service?.name || '';
            const exit = byId('service-profile');
            if (service?.profile && ![...exit.options].some((option) => option.value === service.profile)) {
                exit.add(new Option('Unavailable exit', service.profile));
            }
            exit.value = service?.profile || '';
            byId('service-domains').value = list(service?.domains).join('\n');
            byId('domain-file-status').textContent = '';
            byId('download-domains').disabled = !service;
            byId('cancel-service').hidden = !service;
            if (service) {
                byId('service-name').focus();
            }
        }

        async function refreshProxyCatalog() {
            try {
                const catalog = await api('proxyCatalog');
                state.proxyNodes = array(catalog.nodes);
                state.proxyFeeds = array(catalog.feeds);
                renderProxyCatalog();
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
                        if (window.confirm('Install ' + core.id + ' ' + core.available.version + '? Its proxy exits will briefly restart.')) {
                            void mutate(event.currentTarget, () => coreApi('install', {
                                core: core.id, digest: core.available.sha256
                            }), 'Core updated.', renderCores);
                        }
                    }, 'Install update for ' + core.id));
                }
                if (core.rollback) {
                    actions.append(button('Roll back', (event) => {
                        if (window.confirm('Roll back ' + core.id + '? Its proxy exits will briefly restart.')) {
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
                ? 'Install ' + missing.join(' and ') + ' to enable proxy exits. You can import and inspect servers now.'
                : 'Proxy transport ready. Xray and sing-box exits require their corresponding core.';
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
                    () => api('refreshSubscription', {id: feed.id}), 'Subscription refreshed.', () => void refreshProxyCatalog())));
                actions.append(button(feed.auto ? 'Pause auto-refresh' : 'Enable auto-refresh', (event) => {
                    const auto = !feed.auto;
                    void mutate(event.currentTarget, () => api('setSubscriptionAuto', {id: feed.id, auto}),
                        auto ? 'Automatic refresh enabled.' : 'Automatic refresh paused.', () => void refreshProxyCatalog());
                }));
                actions.append(button('Remove', (event) => {
                    if (window.confirm('Remove this proxy subscription? Any enabled exit keeps its current server.')) {
                        void mutate(event.currentTarget, () => api('removeSubscription', {id: feed.id}),
                            'Subscription removed.', () => void refreshProxyCatalog());
                    }
                }));
            }

            const query = byId('proxy-search').value.trim().toLowerCase();
            const filtered = state.proxyNodes.filter((node) => [node.name, node.host, node.protocol, node.core]
                .some((value) => typeof value === 'string' && value.toLowerCase().includes(query)));
            const results = filtered.slice(0, 40);
            byId('proxy-count').textContent = filtered.length > results.length
                ? 'Showing 40 of ' + filtered.length + ' servers. Refine your search to find more.'
                : filtered.length + (filtered.length === 1 ? ' server' : ' servers');
            const servers = byId('proxy-list');
            servers.replaceChildren();
            if (!results.length) {
                empty(servers, query ? 'No matching servers.' : 'Import a server or subscription to get started.', 4);
            }
            for (const node of results) {
                const row = servers.insertRow();
                cell(row, node.name, '', endpoint(node.host, node.port));
                cell(row, node.protocol, '', node.legacy ? 'Legacy or unencrypted transport' : '');
                const exit = state.profiles.find((profile) => profile.node === node.id);
                cell(row, node.core, '', exit?.status || '');
                const actions = row.insertCell();
                if (exit) {
                    actions.append(button('Test exit', (event) => void testExit(event.currentTarget, exit, 'proxy-test')));
                }
                if (exit) {
                    const disable = button('Remove exit', (event) => removeProfile(exit, event.currentTarget));
                    disable.disabled = state.assignments.some((item) => [item.profile, item.backup].includes(exit.id))
                        || state.services.some((item) => item.profile === exit.id);
                    actions.append(disable);
                }
                const enable = button(exit ? 'Exit enabled' : 'Enable exit', (event) =>
                    void mutate(event.currentTarget, () => api('enableProxyExit', {id: node.id}), 'Proxy exit enabled.'));
                enable.disabled = Boolean(exit) || missing.length > 0 || state.proxyCores[node.core] !== true;
                if (!exit && enable.disabled) {
                    enable.title = 'Install the required proxy cores first.';
                }
                actions.append(enable);
                const remove = button('Remove', (event) => void mutate(event.currentTarget,
                    () => api('removeProxyNode', {id: node.id}), 'Server removed.', () => void refreshProxyCatalog()));
                remove.disabled = Boolean(exit);
                actions.append(remove);
            }
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

        async function fetchDashboard() {
            const refresh = byId('refresh');
            const loginRevision = state.loginRevision;
            refresh.disabled = true;
            try {
                const data = await api('dashboard');
                state.profiles = array(data.profiles);
                state.assignments = array(data.assignments);
                state.services = array(data.services);
                state.proxyCores = data.proxyCores || {};
                state.canManageCores = data.canManageCores === true;
                byId('core-manager').hidden = !state.canManageCores;
                state.presets = data.servicePresets || {};
                state.settings = data.settings;
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
                            : 'Mullvad sign-in expired. Sign in again to add exits.';
                    }
                    setMullvadSignedIn(signedIn);
                    if (signedIn && !byId('account-status').textContent) {
                        byId('account-status').textContent = 'Signed in to Mullvad.';
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
                }
                state.availableInterfaces = array(data.settings?.availableInterfaces || data.availableInterfaces);
                renderDeviceRules();
                renderProfiles();
                if (state.catalogLoaded) {
                    renderRelays();
                }
                renderServices();
                renderProxyCatalog();
                renderSettings();
                renderTailscale();
                renderWarnings(array(data.warnings));
                const count = state.assignments.length;
                const routing = data.settings?.enabled === true || data.settings?.enabled === '1';
                byId('observed').textContent = count + ' saved rule' + (count === 1 ? '' : 's')
                    + ' · ' + (routing ? 'Routing enabled' : 'Routing disabled')
                    + ' · Refreshed ' + new Date().toLocaleTimeString();
            } catch (error) {
                byId('observed').textContent = 'Network settings could not be refreshed.';
                notice(errorMessage(error, 'Saved rules are unavailable.'), 'danger');
                if (!byId('device-list').children.length) {
                    empty(byId('device-list'), 'Saved rules are unavailable.');
                }
            } finally {
                refresh.disabled = false;
            }
        }

        function updateFailure() {
            const mode = byId('mode').value;
            const full = mode === 'full';
            const primary = full ? byId('profile').value : '';
            const failover = byId('failure');
            const tailnet = byId('device-kind').value === 'tailnet';
            byId('mac-field').hidden = tailnet;
            byId('mac').required = !tailnet;
            byId('ipv6').required = tailnet;
            byId('profile-field').hidden = !full;
            byId('profile').required = full;
            byId('failure-field').hidden = !primary;
            const showBackup = primary && failover.value === 'backup';
            byId('backup-field').hidden = !showBackup;
            byId('backup').required = Boolean(showBackup);
            options(byId('backup'), state.profiles.filter((profile) => profile.id !== primary).map(exitChoice), 'Choose a backup exit');
            const profile = state.profiles.find((item) => item.id === primary);
            byId('profile').setCustomValidity(primary && !profile ? 'Choose an available route.' : '');
            const interfaceId = byId('interface').value.trim();
            const notes = [];
            if (tailnet) {
                notes.push('Use the peer IPv4 and IPv6 addresses seen on your source-preserving transit interface.');
            }
            if (mode === 'multi') {
                notes.push(list(state.settings?.smartInterfaces).includes(interfaceId)
                    ? 'Matched services use their assigned exits. Other traffic uses normal internet.'
                    : 'In Network → More routing options, select Use Multi-Path domain lists for this interface.');
            }
            if (mode === 'blocked') {
                notes.push('Internet is blocked for the assigned addresses. Approved local access follows your firewall rules.');
            }
            if (mode === 'full' || mode === 'blocked') {
                const strict = list(state.settings?.strictInterfaces).includes(interfaceId);
                if (!strict && !byId('ipv6').value.trim()) {
                    notes.push('Enter a stable IPv6 address to cover it too.');
                }
            }
            byId('route-note').textContent = notes.join(' ');
        }

        function renderAssignmentInterfaces(previous = byId('interface').value) {
            const managed = list(state.settings?.interfaces);
            const tailnet = list(state.settings?.tailscaleInterfaces);
            const peer = byId('device-kind').value === 'tailnet';
            const choices = availablePorts().filter((port) => managed.includes(port.id)
                && (peer ? tailnet.includes(port.id) : !tailnet.includes(port.id)))
                .map((port) => ({value: port.id, label: networkName(port.id)}));
            if (state.editing && previous && !choices.some((choice) => choice.value === previous)) {
                choices.push({value: previous, label: networkName(previous)});
            }
            options(byId('interface'), choices, choices.length ? 'Choose an interface' : 'Enable an interface first',
                previous || (choices.length === 1 ? choices[0].value : ''));
        }

        function openAssignment(assignment = null, kind = 'lan') {
            state.editing = assignment;
            byId('assignment').hidden = false;
            byId('assignment-title').textContent = assignment ? 'Edit device rule' : 'Add device rule';
            byId('ip').value = assignment?.ip || '';
            byId('mac').value = assignment?.mac || '';
            byId('ipv6').value = assignment?.ipv6 || '';
            byId('device-kind').value = assignment?.kind || kind;
            byId('device-kind').disabled = Boolean(assignment);
            renderAssignmentInterfaces(assignment?.interface || '');
            byId('mode').value = modes[assignment?.mode] ? assignment.mode : (assignment && !assignment.profile ? 'disabled' : 'full');
            byId('ip').readOnly = Boolean(assignment);
            byId('interface').disabled = Boolean(assignment);
            byId('mac').readOnly = Boolean(assignment);
            byId('device-label').value = assignment?.label || '';
            const selected = assignment?.profile || '';
            const choices = state.profiles.map(exitChoice);
            if (selected && !choices.some((choice) => choice.value === selected)) {
                choices.push({value: selected, label: 'Unavailable VPN profile'});
            }
            options(byId('profile'), choices, 'Choose an exit', selected);
            byId('failure').value = assignment?.failure || 'block';
            byId('switch-now').checked = false;
            updateFailure();
            byId('backup').value = assignment?.backup || '';
            byId('identity').textContent = byId('device-kind').value === 'tailnet' ? ''
                : 'Use the device’s reserved DHCP address and MAC.';
            byId('remove-assignment').hidden = !assignment;
            byId('assignment-title').focus();
        }

        async function mutate(control, operation, success, onSuccess) {
            if (state.busy) {
                return;
            }
            state.busy = true;
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
                notice(errorMessage(error, 'The operation could not be completed.'), 'danger');
            } finally {
                state.busy = false;
                control.disabled = false;
            }
        }

        function removeProfile(profile, control) {
            if (!window.confirm('Remove exit “' + profileName(profile.id) + '” from this router?')) {
                return;
            }
            void mutate(control, () => api('removeProfile', {id: profile.id}), 'Exit removed.');
        }

        function relayCity(relay) {
            return relay.country + ' / ' + relay.city;
        }

        function renderRelays() {
            const retarget = byId('retarget');
            const assigned = new Set([
                state.settings?.networkProfile,
                ...state.assignments.flatMap((row) => [row.profile, row.backup]),
                ...state.services.map((service) => service.profile)
            ]);
            const reusable = state.profiles.filter((profile) => profile.relay && !assigned.has(profile.id));
            byId('retarget-row').hidden = reusable.length === 0;
            options(retarget, reusable.map(exitChoice), 'Create a new exit');
            const countries = [...new Set(state.relays.map((item) => item.country).filter(Boolean))].sort();
            options(byId('country'), countries.map((value) => ({value, label: value})), 'All countries');
            const country = byId('country').value;
            const fromCountry = state.relays.filter((item) => !country || item.country === country);
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
            const register = byId('register');
            register.disabled = !relay || !state.mullvadSignedIn;
            register.textContent = byId('retarget').value ? 'Change server' : 'Add Mullvad exit';
            byId('test-relay').disabled = !relay || !state.mullvadSignedIn || state.testingRelay;
        }

        async function pingRelay() {
            const relay = byId('relay').value;
            const status = byId('relay-test');
            state.testingRelay = true;
            renderRelayChoice();
            status.textContent = 'Pinging ' + relay + ' from OPNsense…';
            try {
                const result = await api('testRelay', {relay});
                status.textContent = relay + (result.replied
                    ? ' replied in ' + result.milliseconds + ' ms.'
                    : ' did not answer ICMP. The WireGuard service may still be available.');
            } catch (error) {
                status.textContent = errorMessage(error, 'Could not ping ' + relay + '.');
            } finally {
                state.testingRelay = false;
                renderRelayChoice();
            }
        }

        async function testExit(control, exit, output) {
            const status = byId(output);
            const name = profileName(exit.id);
            control.disabled = true;
            status.textContent = 'Testing internet access through ' + name + '…';
            try {
                const result = await api('testExit', {id: exit.id});
                status.textContent = name + (result.reachable === true
                    ? ' passed the HTTPS test (' + result.milliseconds + ' ms).'
                    : result.reachable === false ? ' did not pass the HTTPS test.'
                        : ' could not be tested. Check that routing is enabled and the tunnel rules are loaded.');
            } catch (error) {
                status.textContent = errorMessage(error, 'The exit test could not be completed.');
            } finally {
                control.disabled = false;
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
                && !state.signingIn && !state.restoreAttempted) {
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
                throw new Error('Enter the 16-digit Mullvad account number.');
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
            target.textContent = restore ? 'Reconnecting saved Mullvad login…' : 'Signing in to Mullvad…';
            try {
                const payload = restore ? {} : {account: accountNumber(), saveLogin: byId('save-login').checked};
                byId('account').value = '';
                const response = await api(restore ? 'restoreMullvad' : 'account', payload);
                state.mullvadLoginSaved = response.saved === true;
                state.restoreAttempted = false;
                byId('save-login').checked = state.mullvadLoginSaved;
                setMullvadSignedIn(true);
                const devices = array(response.devices);
                const limit = response.maxDevices ?? response.limit;
                const expiry = response.expiresAt ?? response.expiry;
                target.textContent = (state.mullvadLoginSaved ? 'Signed in to Mullvad. Login saved. ' : 'Signed in to Mullvad. ') + devices.length + (limit ? ' of ' + limit : '') + ' device slots used.'
                    + (expiry ? (response.expired ? ' Account expired ' : ' Account expires ') + date(expiry) + '.' : '')
                    + (response.canAddDevices === false ? ' Mullvad reports that this account cannot add a device.' : '');
                if (devices.length) {
                    const names = document.createElement('ul');
                    for (const device of devices) {
                        const entry = document.createElement('li');
                        entry.textContent = shown(device.name, 'Registered WireGuard device');
                        names.append(entry);
                    }
                    target.append(names);
                }
            } catch (error) {
                setMullvadSignedIn(false);
                target.textContent = errorMessage(error, 'Account information is unavailable.');
            } finally {
                state.signingIn = false;
                control.disabled = false;
                byId('sign-out').disabled = false;
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

        function traffic(record) {
            const counters = record.bytes;
            const bytes = Array.isArray(counters)
                ? counters.map(toBytes)
                : [toBytes(record.bytesIn ?? record.bytes_in), toBytes(record.bytesOut ?? record.bytes_out)];
            const total = toBytes(Array.isArray(counters) ? null : counters);
            if (total === null && bytes.every((value) => value === null)) {
                return 'Unavailable';
            }
            return formatBytes(total ?? bytes.reduce((sum, value) => sum + (value || 0), 0));
        }

        async function loadConnections() {
            const target = state.connectionTarget;
            if (!target) {
                return;
            }
            const body = byId('connection-list');
            const control = byId('refresh-connections');
            control.disabled = true;
            empty(body, 'Loading active connections…');
            try {
                const response = await api('connections', undefined, '/' + encodeURIComponent(target.ip));
                if (state.connectionTarget !== target) {
                    return;
                }
                const rows = array(response.connections || response.states);
                byId('connections-note').textContent = response.truncated
                    ? 'Showing a bounded sample of active states. Traffic counters cover the displayed states.'
                    : 'These sessions traverse OPNsense. Traffic counters cover the displayed states.';
                if (!rows.length) {
                    empty(body, 'No matching active firewall states.');
                    return;
                }
                body.replaceChildren();
                for (const record of rows) {
                    const row = body.insertRow();
                    cell(row, record.protocol || record.proto);
                    cell(row, endpoint(record.source || record.src, record.sourcePort || record.src_port));
                    cell(row, endpoint(record.destination || record.dst, record.destinationPort || record.dst_port));
                    cell(row, record.state);
                    cell(row, record.age);
                    cell(row, traffic(record));
                }
            } catch (error) {
                if (state.connectionTarget === target) {
                    empty(body, errorMessage(error, 'Active connections are unavailable.'));
                }
            } finally {
                if (state.connectionTarget === target) {
                    control.disabled = false;
                }
            }
        }

        function openConnections(ip, name) {
            state.connectionTarget = {ip, name};
            byId('connections').hidden = false;
            byId('connections-label').textContent = name === ip ? ip : name + ' · ' + ip;
            byId('connections-title').focus();
            void loadConnections();
        }

        byId('refresh').addEventListener('click', () => void refreshDashboard());
        byId('add-device').addEventListener('click', () => openAssignment());
        byId('close-assignment').addEventListener('click', () => {
            byId('assignment').hidden = true;
            state.editing = null;
            byId('add-device').focus();
        });
        byId('mode').addEventListener('change', updateFailure);
        byId('device-kind').addEventListener('change', () => {
            renderAssignmentInterfaces();
            byId('identity').textContent = byId('device-kind').value === 'tailnet' ? ''
                : 'Use the device’s reserved DHCP address and MAC.';
            updateFailure();
        });
        byId('ipv6').addEventListener('input', updateFailure);
        byId('profile').addEventListener('change', updateFailure);
        byId('failure').addEventListener('change', updateFailure);
        byId('interface').addEventListener('change', updateFailure);
        byId('assign-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                ip: byId('ip').value.trim(),
                interface: byId('interface').value.trim(),
                mac: byId('mac').value.trim(),
                ipv6: byId('ipv6').value.trim(),
                kind: byId('device-kind').value,
                mode: byId('mode').value,
                label: byId('device-label').value.trim(),
                profile: byId('profile').value,
                backup: byId('backup').required ? byId('backup').value : '',
                failure: byId('profile').value ? byId('failure').value : 'block',
                switchNow: byId('switch-now').checked
            };
            void mutate(event.submitter, () => api('assign', payload), 'Device assignment saved.', () => {
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
        byId('close-connections').addEventListener('click', () => {
            state.connectionTarget = null;
            byId('connections').hidden = true;
            byId('refresh').focus();
        });
        byId('refresh-connections').addEventListener('click', () => void loadConnections());

        if (insecureWebGui) {
            const target = new URL(window.location.href);
            target.protocol = 'https:';
            byId('secure-link').href = target.href;
            byId('login-http').hidden = false;
            byId('proxy-http').hidden = false;
        }
        setMullvadSignedIn(false);
        byId('refresh-relays').addEventListener('click', () => void loadRelays(true));
        byId('country').addEventListener('change', renderRelays);
        byId('city').addEventListener('change', renderRelays);
        byId('relay').addEventListener('change', renderRelayChoice);
        byId('test-relay').addEventListener('click', () => void pingRelay());
        byId('retarget').addEventListener('change', renderRelayChoice);
        byId('login-form').addEventListener('submit', (event) => {
            event.preventDefault();
            void inspectAccount();
        });
        byId('restore-login').addEventListener('click', () => void inspectAccount(true));
        byId('sign-out').addEventListener('click', (event) => {
            void mutate(event.currentTarget, () => api('logoutMullvad', {}), 'Signed out of Mullvad.', () => {
                state.loginRevision++;
                state.mullvadLoginSaved = false;
                state.restoreAttempted = false;
                byId('save-login').checked = false;
                setMullvadSignedIn(false);
                byId('account-status').textContent = '';
            });
        });
        byId('register-form').addEventListener('submit', (event) => {
            event.preventDefault();
            if (!state.mullvadSignedIn || byId('register').disabled) {
                return;
            }
            const payload = {relay: byId('relay').value, name: byId('register-name').value.trim()};
            const reused = byId('retarget').value;
            void mutate(event.submitter, () => reused
                ? api('retargetProfile', {id: reused, relay: payload.relay})
                : api('register', payload), reused ? 'Mullvad exit moved to ' + payload.relay + '.'
                : 'Mullvad exit added for ' + payload.relay + '.', () => {
                byId('register-name').value = '';
                byId('retarget').value = '';
                byId('relay').value = '';
            }).then(renderRelayChoice);
        });
        byId('use-lan').addEventListener('click', () => {
            showSection('network');
            const port = byId('managed').querySelector('[value="lan"]');
            if (!port) {
                return;
            }
            byId('enabled').checked = true;
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
                domains: byId('service-domains').value.trim()
            };
            const message = payload.profile ? 'Domain list saved with ' + profileName(payload.profile) + '.'
                : 'Domain list saved. Choose an exit when ready.';
            void mutate(event.submitter, () => api('saveService', payload), message, () => editService());
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
                status.textContent = 'Choose a domain list up to 128 KiB.';
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
                    status.textContent = 'Could not read the file. Paste its domains into the editor.';
                }
            }
        });
        byId('service-domains').addEventListener('input', (event) => {
            byId('download-domains').disabled = !event.target.value.trim();
        });
        byId('download-domains').addEventListener('click', () => {
            const name = byId('service-name').value.trim().replace(/[^a-z0-9_.-]+/gi, '-') || 'domains';
            const domains = byId('service-domains').value.trim();
            const url = URL.createObjectURL(new Blob([domains + '\n'], {type: 'text/plain'}));
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
            byId('manual-params-field').hidden = basic;
            byId('manual-note').hidden = protocol !== 'vless';
            byId('manual-note').textContent = 'For REALITY, include security=reality, sni, pbk (public key), sid (short ID), and fp (fingerprint) in the link parameters, joined by &.';
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
                void refreshProxyCatalog();
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
            if (!window.confirm('Verify and install this archive? Its proxy exits will briefly restart.')) {
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
        byId('proxy-search').addEventListener('input', renderProxyCatalog);
        byId('proxy-import').addEventListener('submit', (event) => {
            event.preventDefault();
            const body = byId('proxy-body').value.trim();
            void mutate(event.submitter, () => api('importProxies', {body}), 'Proxy servers imported.', (result) => {
                event.target.reset();
                notice(result.imported + ' servers imported' + (result.skipped ? ' · ' + result.skipped + ' skipped' : ''), 'success');
                void refreshProxyCatalog();
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
                void refreshProxyCatalog();
            });
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
            openAssignment(null, 'tailnet');
        });
        byId('settings-form').addEventListener('input', () => {
            state.settingsDirty = true;
            updateCoverage();
        });
        byId('settings-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const interfaces = checkedInterfaces('managed');
            const rules = [...byId('interface-rules').children].filter((label) => interfaces.includes(label.dataset.interface));
            const selected = (type) => rules.filter((label) => label.querySelector('select').value === type)
                .map((label) => label.dataset.interface);
            const payload = {
                enabled: byId('enabled').checked,
                coverage: byId('coverage').value,
                networkMode: byId('network-mode').value,
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
                    || list(current.interfaces).join(',') !== payload.interfaces.join(','));
            if (wideChange && !window.confirm('Apply ' + modes[payload.networkMode] + ' to all devices on the selected networks? Existing internet connections may reconnect.')) {
                return;
            }
            void mutate(event.submitter, () => api('settings', payload), 'Routing settings saved.', () => {
                state.settingsDirty = false;
            });
        });
        window.addEventListener('pagehide', () => {
            byId('account').value = '';
            byId('proxy-body').value = '';
            byId('subscription-url').value = '';
            byId('manual-secret').value = '';
            byId('manual-parameters').value = '';
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
            if (!document.hidden && !state.busy && byId('assignment').hidden && !root.contains(document.activeElement)) {
                void refreshDashboard();
            }
        }, 30000);
    }

    window.jQuery(start);
})();
