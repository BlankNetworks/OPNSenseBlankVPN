(() => {
    'use strict';

    function start() {
        const byId = (id) => document.getElementById('bv-' + id);
        const root = document.getElementById('blankvpn');
        if (!root) {
            return;
        }

        const state = {
            devices: [],
            profiles: [],
            assignments: [],
            services: [],
            proxyNodes: [],
            proxyFeeds: [],
            proxyCores: {},
            section: 'devices',
            mullvadSignedIn: false,
            presets: {},
            editingService: null,
            relays: [],
            settings: null,
            availableInterfaces: [],
            canManage: true,
            editing: null,
            connectionTarget: null,
            busy: false,
            dashboardRequest: null,
            settingsDirty: false,
            catalogLoaded: false
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

        async function api(action, payload, path = '') {
            const method = payload === undefined ? 'GET' : 'POST';
            const request = {
                url: '/api/blankvpn/service/' + action + path,
                method,
                dataType: 'json',
                cache: false,
                timeout: 45000
            };
            if (method === 'POST') {
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
                button.classList.toggle('btn-primary', active);
                button.classList.toggle('btn-default', !active);
            }
            for (const panel of root.querySelectorAll('[data-bv-panel]')) {
                panel.hidden = panel.dataset.bvPanel !== section;
                if (!panel.hidden && panel.tagName === 'DETAILS') {
                    panel.open = true;
                }
            }
            if (section !== 'devices') {
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

        function deviceIp(device) {
            return device.ip || device.reservationIpv4 || list(device.ipv4)[0] || list(device.ipv6)[0] || '';
        }

        function deviceAssignment(device) {
            const ips = new Set([device.ip, ...list(device.ipv4Addresses || device.ipv4), ...list(device.ipv6)].filter(Boolean));
            return state.assignments.find((assignment) =>
                assignment.interface === device.interface && ips.has(assignment.ip)
                && (!assignment.mac || !device.mac || assignment.mac.toLowerCase() === device.mac.toLowerCase())
            );
        }

        function networkName(id) {
            const entry = state.availableInterfaces.find((item) => item.id === id);
            return entry?.name ? (entry.name === id ? id : entry.name + ' (' + id + ')') : shown(id);
        }

        function renderDevices() {
            const body = byId('device-list');
            const entries = state.devices.map((device) => ({device, assignment: deviceAssignment(device)}));
            const matched = new Set(entries.map(({assignment}) => assignment?.id));
            for (const assignment of state.assignments) {
                if (!matched.has(assignment.id)) {
                    entries.push({
                        assignment,
                        device: {ip: assignment.ip, mac: assignment.mac, interface: assignment.interface}
                    });
                }
            }
            if (!entries.length) {
                empty(body, 'No device observations or saved assignments. Add a local IP address to begin.');
                return;
            }

            body.replaceChildren();
            for (const {device, assignment} of entries) {
                const row = body.insertRow();
                const ip = assignment?.ip || deviceIp(device);
                const name = assignment?.label || device.name || ip || 'Unnamed device';
                const ipv4 = list(device.ipv4Addresses || device.ipv4);
                const ipv6 = list(device.ipv6);
                cell(row, name, '', device.mac);
                cell(row, ipv4.join(', ') || ipv6.join(', ') || ip, 'Addresses', ipv4.length ? ipv6.join(', ') : '');
                cell(row, device.interfaceName || networkName(device.interface), 'Network',
                    device.stable === true ? 'Fixed IPv4 reservation' : '');
                const seen = device.lastSeen ? 'Seen ' + date(device.lastSeen) : 'Last seen unknown';
                cell(
                    row,
                    assignment ? profileName(assignment.profile) : 'Network default',
                    'Assignment',
                    assignment?.profile
                        ? (assignment.failure === 'backup' ? 'Backup: ' + profileName(assignment.backup)
                            : assignment.failure === 'wan' ? 'Falls back to normal internet' : (assignment.killSwitchActive ? 'IPv4 kill switch installed' : 'IPv4 kill switch configured'))
                        : ''
                );
                const assignedProfile = state.profiles.find((profile) => profile.id === assignment?.profile);
                const observed = assignment?.profile
                    ? shown(assignedProfile?.status, 'Tunnel status unknown')
                    : seen;
                const egress = assignment?.profile
                    ? (assignment.verified === true ? 'Egress verified'
                        : 'Client egress unverified')
                    : '';
                const applied = assignment?.appliedRoute;
                const appliedText = typeof applied === 'string' && applied
                    ? 'Rules report ' + (state.profiles.some((profile) => profile.id === applied) ? profileName(applied) : applied)
                    : '';
                cell(row, observed, 'Status', [appliedText, egress, egress ? seen : ''].filter(Boolean).join(' · '));
                const actions = row.insertCell();
                actions.setAttribute('role', 'cell');
                if (state.canManage && ip && device.interface) {
                    actions.append(button('Assign', () => openAssignment(device, assignment), 'Assign ' + name));
                }
                if (ip) {
                    actions.append(button('Connections', () => openConnections(ip, name), 'Connections for ' + name));
                }
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
                    remove.disabled = used > 0 || services > 0;
                    if (remove.disabled) {
                        remove.title = 'Change device and service assignments before removing this exit.';
                    }
                    if (state.canManage) {
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

        function renderSettings() {
            if (!state.settings || state.settingsDirty) {
                return;
            }
            const settings = state.settings;
            byId('enabled').checked = settings.enabled === true || settings.enabled === '1';
            byId('hostname').value = settings.hostname || '';
            byId('managed').value = list(settings.interfaces).join(', ');
            byId('strict').value = list(settings.strictInterfaces).join(', ');
            byId('smart-interfaces').value = list(settings.smartInterfaces).join(', ');
            byId('local').value = list(settings.localNetworks).join(', ');
        }

        function renderServices() {
            const interfaces = list(state.settings?.smartInterfaces);
            const active = state.settings?.enabled && interfaces.length && state.services.length;
            byId('smart-status').textContent = active
                ? 'Monitoring regular DNS on ' + interfaces.map(networkName).join(', ') + '.'
                : 'Enable Smart Routing on a managed LAN or VLAN and add a service.';
            byId('use-lan').hidden = !state.availableInterfaces.some((item) => item.id === 'lan')
                || interfaces.includes('lan') || list(state.settings?.strictInterfaces).includes('lan');
            const body = byId('service-list');
            if (state.services.length === 0) {
                empty(body, 'No service rules. Choose Netflix or enter your own domains.', 4);
            } else {
                body.replaceChildren();
                for (const service of state.services) {
                    const row = body.insertRow();
                    cell(row, service.name, '', list(service.domains).join(', '));
                    cell(row, profileName(service.profile));
                    const status = Object.entries(service.routing || {}).map(([id, rule]) =>
                        networkName(id) + ' · ' + (rule.gateway || (rule.guard ? 'Tunnel unavailable' : 'Inactive')));
                    cell(row, status.join('; ') || 'Inactive', '',
                        Number.isInteger(service.learned) ? service.learned + ' learned addresses' : '');
                    const actions = row.insertCell();
                    if (state.canManage) {
                        actions.append(button('Edit', () => editService(service), 'Edit ' + service.name));
                        actions.append(button('Remove', (event) => {
                            if (window.confirm('Remove Smart Routing for ' + service.name + '?')) {
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
            const choices = state.profiles.filter((profile) => profile.kind === 'proxy' || list(profile.dns).some((ip) => !ip.includes(':')))
                .map(exitChoice);
            options(select, choices, 'Choose an exit');
            byId('save-service').disabled = !choices.length;
            options(byId('service-preset'), Object.keys(state.presets).map((name) => ({value: name, label: name})),
                'Custom service');
        }

        function editService(service = null) {
            state.editingService = service?.id || null;
            byId('service-form').reset();
            byId('service-name').value = service?.name || '';
            byId('service-profile').value = service?.profile || '';
            byId('service-domains').value = list(service?.domains).join(', ');
            byId('save-service').textContent = service ? 'Save service' : 'Add service';
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
            refresh.disabled = true;
            try {
                const data = await api('dashboard');
                state.devices = array(data.devices);
                state.profiles = array(data.profiles);
                state.assignments = array(data.assignments);
                state.services = array(data.services);
                state.proxyCores = data.proxyCores || {};
                state.presets = data.servicePresets || {};
                state.settings = data.settings;
                state.canManage = data.canManage !== false;
                if (state.mullvadSignedIn && data.mullvadSignedIn !== true) {
                    byId('account-status').textContent = 'Mullvad sign-in expired. Sign in again to add exits.';
                }
                state.mullvadSignedIn = data.mullvadSignedIn === true;
                byId('sign-out').hidden = !state.mullvadSignedIn;
                if (state.mullvadSignedIn && !byId('account-status').textContent) {
                    byId('account-status').textContent = 'Signed in to Mullvad.';
                }
                const gateways = array(data.nativeGateways);
                options(byId('native-gateway'), gateways.map((item) => ({
                    value: item.id, label: item.gateway + ' · ' + item.protocol
                })), gateways.length ? 'Choose a VPN gateway' : 'Configure a tunnel gateway in OPNsense');
                byId('native-add').disabled = !gateways.length;
                if (!state.canManage && ['proxies', 'settings'].includes(state.section)) {
                    showSection('devices');
                }
                root.dataset.canManage = String(state.canManage);
                if (!state.canManage) {
                    byId('assignment').hidden = true;
                    state.editing = null;
                }
                state.availableInterfaces = array(data.settings?.availableInterfaces || data.availableInterfaces);
                const datalist = byId('interface-list');
                datalist.replaceChildren(...state.availableInterfaces.map(
                    (item) => new Option(networkName(item.id), item.id)
                ));
                renderDevices();
                renderProfiles();
                renderServices();
                renderProxyCatalog();
                renderSettings();
                renderWarnings(array(data.warnings));
                const count = state.devices.length;
                const routing = data.settings?.enabled === true || data.settings?.enabled === '1';
                byId('observed').textContent = count + ' observed device' + (count === 1 ? '' : 's')
                    + ' · ' + (routing ? 'Routing enabled' : 'Routing disabled')
                    + ' · Refreshed ' + new Date().toLocaleTimeString();
            } catch (error) {
                byId('observed').textContent = 'Device observations could not be refreshed.';
                notice(errorMessage(error, 'Device observations are unavailable.'), 'danger');
                if (!byId('device-list').children.length) {
                    empty(byId('device-list'), 'Device observations are unavailable.');
                }
            } finally {
                refresh.disabled = false;
            }
        }

        function updateFailure() {
            const primary = byId('profile').value;
            const failover = byId('failure');
            byId('failure-field').hidden = !primary;
            const showBackup = primary && failover.value === 'backup';
            byId('backup-field').hidden = !showBackup;
            byId('backup').required = Boolean(showBackup);
            const choices = state.profiles.filter((profile) => profile.id !== primary)
                .map(exitChoice);
            options(byId('backup'), choices, 'Choose a backup exit');
            const profile = state.profiles.find((item) => item.id === primary);
            byId('profile').setCustomValidity(primary && !profile ? 'Choose an available route.' : '');
            const notes = [];
            if (profile) {
                const strict = list(state.settings?.strictInterfaces).includes(byId('interface').value.trim());
                notes.push(strict ? 'This strict interface blocks internet-bound IPv6.'
                    : 'This policy covers the selected IPv4 address. IPv6 follows your normal firewall rules.');
                if (failover.value === 'block') {
                    notes.push('Applying a new kill switch resets connections originating from this IPv4 address.');
                }
                if (profile.dns) {
                    notes.push('Profile DNS: ' + shown(profile.dns) + '.');
                }
            }
            byId('route-note').textContent = notes.join(' ');
        }

        function openAssignment(device = {}, assignment) {
            state.editing = assignment || null;
            byId('assignment').hidden = false;
            byId('assignment-title').textContent = 'Device assignment';
            byId('ip').value = assignment?.ip || deviceIp(device);
            byId('interface').value = assignment?.interface || device.interface || '';
            byId('mac').value = assignment?.mac || device.mac || '';
            byId('ip').readOnly = Boolean(assignment);
            byId('interface').readOnly = Boolean(assignment);
            byId('mac').readOnly = Boolean(assignment);
            byId('device-label').value = assignment?.label || device.name || '';
            const selected = assignment?.profile || '';
            const choices = state.profiles.map(exitChoice);
            if (selected && !choices.some((choice) => choice.value === selected)) {
                choices.push({value: selected, label: 'Unavailable VPN profile'});
            }
            options(byId('profile'), choices, 'Normal internet', selected);
            byId('failure').value = assignment?.failure || 'block';
            byId('switch-now').checked = false;
            updateFailure();
            byId('backup').value = assignment?.backup || '';
            byId('identity').textContent = device.stable === true
                ? 'A matching reservation was observed for this address.'
                : 'Address stability is unverified. A VPN assignment requires a fixed IPv4 reservation on a managed interface.';
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
                notice(message + (result.killSwitchReset ? ' Previous connections from this IPv4 address were reset.' : '')
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
                ...state.assignments.flatMap((row) => [row.profile, row.backup]),
                ...state.services.map((service) => service.profile)
            ]);
            const reusable = state.profiles.filter((profile) => profile.relay && !assigned.has(profile.id));
            byId('retarget-row').hidden = reusable.length === 0;
            options(retarget, reusable.map(exitChoice), 'Use a new profile');
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

        async function inspectAccount() {
            const control = byId('inspect-account');
            const target = byId('account-status');
            control.disabled = true;
            target.textContent = 'Signing in…';
            state.mullvadSignedIn = false;
            byId('sign-out').hidden = true;
            try {
                const account = accountNumber();
                const response = await api('account', {account});
                byId('account').value = '';
                state.mullvadSignedIn = true;
                byId('sign-out').hidden = false;
                const devices = array(response.devices);
                const limit = response.maxDevices ?? response.limit;
                const expiry = response.expiresAt ?? response.expiry;
                target.textContent = devices.length + (limit ? ' of ' + limit : '') + ' device slots used.'
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
                target.textContent = errorMessage(error, 'Account information is unavailable.');
            } finally {
                control.disabled = false;
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
        byId('profile').addEventListener('change', updateFailure);
        byId('failure').addEventListener('change', updateFailure);
        byId('interface').addEventListener('change', updateFailure);
        byId('assign-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                ip: byId('ip').value.trim(),
                interface: byId('interface').value.trim(),
                mac: byId('mac').value.trim(),
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
                : ' The device will use the normal network policy and any Smart Routing rules.';
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

        byId('tunnels').addEventListener('toggle', () => {
            if (byId('tunnels').open && !state.catalogLoaded) {
                void loadRelays();
            }
        });
        byId('refresh-relays').addEventListener('click', () => void loadRelays(true));
        byId('country').addEventListener('change', renderRelays);
        byId('city').addEventListener('change', renderRelays);
        byId('inspect-account').addEventListener('click', () => void inspectAccount());
        byId('sign-out').addEventListener('click', (event) => {
            void mutate(event.currentTarget, () => api('logoutMullvad', {}), 'Signed out of Mullvad.', () => {
                state.mullvadSignedIn = false;
                byId('account').value = '';
                byId('account-status').textContent = '';
                byId('sign-out').hidden = true;
            });
        });
        byId('account').addEventListener('input', () => {
            byId('account-status').textContent = '';
        });
        byId('register-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {relay: byId('relay').value, name: byId('register-name').value.trim()};
            const reused = byId('retarget').value;
            if (reused) {
                void mutate(event.submitter, () => api('retargetProfile', {id: reused, relay: payload.relay}),
                    'Mullvad profile server changed.', () => {
                        event.target.reset();
                        byId('account-status').textContent = '';
                        renderRelays();
                    });
                return;
            }
            if (!state.mullvadSignedIn) {
                notice('Sign in to Mullvad before adding an exit.', 'danger');
                byId('account').focus();
                return;
            }
            void mutate(event.submitter, () => api('register', payload), 'Mullvad exit added.', () => {
                event.target.reset();
                renderRelays();
            });
        });
        byId('import-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {name: byId('import-name').value.trim(), config: byId('import-config').value};
            void mutate(event.submitter, () => api('importProfile', payload), 'WireGuard exit imported.', () => {
                event.target.reset();
            });
        });
        byId('use-lan').addEventListener('click', () => {
            showSection('settings');
            byId('enabled').checked = true;
            byId('managed').value = [...new Set([...list(byId('managed').value), 'lan'])].join(', ');
            byId('smart-interfaces').value = [...new Set([...list(byId('smart-interfaces').value), 'lan'])].join(', ');
            state.settingsDirty = true;
            byId('smart-interfaces').focus();
        });
        byId('service-preset').addEventListener('change', (event) => {
            const preset = event.target.value;
            if (Array.isArray(state.presets[preset])) {
                byId('service-name').value = preset;
                byId('service-domains').value = state.presets[preset].join(', ');
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
            void mutate(event.submitter, () => api('saveService', payload), 'Smart Routing service saved.', () => editService());
        });
        byId('proxies').addEventListener('toggle', () => {
            if (byId('proxies').open && state.canManage) {
                void refreshProxyCatalog();
            }
        });
        for (const button of root.querySelectorAll('[data-bv-section]')) {
            button.addEventListener('click', () => showSection(button.dataset.bvSection));
        }
        byId('native-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {name: byId('native-name').value.trim(), gateway: byId('native-gateway').value,
                dns: byId('native-dns').value.trim()};
            void mutate(event.submitter, () => api('addNativeExit', payload), 'VPN exit added.', () => event.target.reset());
        });

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
        byId('settings-form').addEventListener('input', () => {
            state.settingsDirty = true;
        });
        byId('settings-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const payload = {
                enabled: byId('enabled').checked,
                hostname: byId('hostname').value.trim(),
                interfaces: list(byId('managed').value),
                strictInterfaces: list(byId('strict').value),
                smartInterfaces: list(byId('smart-interfaces').value),
                localNetworks: list(byId('local').value)
            };
            const knownStrict = list(state.settings?.strictInterfaces);
            if (payload.enabled && payload.strictInterfaces.length
                && (!state.settings?.enabled || payload.strictInterfaces.some((item) => !knownStrict.includes(item)))
                && !window.confirm('Enable strict VPN routing? Unassigned devices on these interfaces can lose internet access.')) {
                return;
            }
            void mutate(event.submitter, () => api('settings', payload), 'Routing settings saved.', () => {
                state.settingsDirty = false;
            });
        });
        window.addEventListener('pagehide', () => {
            byId('account').value = '';
            byId('import-config').value = '';
            byId('proxy-body').value = '';
            byId('subscription-url').value = '';
            byId('manual-secret').value = '';
            byId('manual-parameters').value = '';
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
