const requests = [];
let settingsError = null;
let exitTestError = null;
let bulkRemoveError = null;
let tailnetTraffic = 'unseen';
const updateStatus = {ok:true, supported:true, enabled:false, running:false, installed:'0.1.39',
    available:'', message:'Check for a Blank VPN & Proxy update.'};
const routingBackup = {schema:1, version:1, routing:{enabled:false}, assignments:[], services:[]};
let updatePolls = 0;
const reply = {
    dashboard: {
        devices: [{ipv4: '10.0.0.20', ipv4Addresses: ['10.0.0.20', '10.0.0.21'], ipv6: ['fd00::20'], mac:'02:00:00:00:00:20', interface:'lan', interfaceName:'LAN', name:'<b>Device</b>', lastSeen:'2026-11-12T13:30:00Z', stable:true}],
        tailnetDevices: [{kind:'tailnet', name:'Remote iPad', ipv4:'100.101.102.104', ipv6:['fd7a:115c:a1e0::104'], online:true}],
        profiles: [{id:'vpn1', name:'Canada', relay:'ca-test-wg-001', port:51820, interface:'wg1', dns:['10.64.0.1'], latestHandshake:1794490200, status:'Recent handshake', receivedBytes:4096, sentBytes:2048}],
        assignments: [{id:'device1',ip:'10.0.0.20',mac:'02:00:00:00:00:20',interface:'lan',
            label:'<b>Device rule</b>',mode:'disabled',profile:'',kind:'lan'}],
        services: [],
        canManageCores: true,
        mullvadSignedIn: false,
        vpnProviders: {mullvad:{name:'Mullvad',login:'mullvad'}, pia:{name:'Private Internet Access',login:'password'},
            hide:{name:'hide.me'}, azire:{name:'AzireVPN',login:'token'}, nord:{name:'NordVPN',login:'token'},
            mysterium:{name:'Mysterium VPN',login:'browser'}, ivpn:{name:'IVPN',login:'account'}},
        providerAccounts: {pia:false,azire:true},
        proxyCores: {mihomo:true,tun2socks:true,xray:true,"sing-box":true},
        servicePresets: {Netflix:['netflix.com','nflxvideo.net']},
        settings: {dashboardBind:'lan',dashboardAddresses:{lan:'10.0.0.1',tailnet:'100.101.102.103'},dashboardMagicDns:'opnsense.tailnet.ts.net',enabled:false, interfaces:['lan','opt2'], availableInterfaces:[{id:'opt1', name:'VLAN 2', device:'vlan02'},
            {id:'opt2', name:'LAN 6', device:'igc5'}, {id:'lan', name:'LAN 1', device:'igc0'}],
            tailscaleInterfaces:['opt2'], tailscaleInstalled:true, tailscaleExitAdvertised:true, strictInterfaces:[], localNetworks:[], hostname:'opnsense.home.arpa'},
        warnings: []
    },
    relays: {relays:[{id:'ca-test-wg-001',country:'Canada',countryCode:'ca',cityCode:'yyz',city:'Test',hostname:'ca-test-wg-001',active:true},{id:'ca-test-wg-002',country:'Canada',countryCode:'ca',cityCode:'yyz',city:'Test',hostname:'ca-test-wg-002',active:false},
        {id:'jp-test-wg-001',country:'Japan',countryCode:'jp',cityCode:'nrt',city:'Test',hostname:'jp-test-wg-001',active:true}], stale:false, fetchedAt:1794490200},
    connections: {connections:[{protocol:'tcp', source:'10.0.0.20', sourcePort:1234, destination:'2001:db8::25', destinationPort:443, age:'00:00:10', bytes:[1024,1024]}]},
    status: {ok:true, cores:[{id:'mihomo',version:'1.19.34',installed:true,source:'Bundled',
        available:{version:'1.19.35',sha256:'a'.repeat(64)},update:true,rollback:false}],
        storage:{freeBytes:1073741824,coreBytes:0,catalogBytes:1024,reserveBytes:67108864}},
    check: {ok:true, cores:[], storage:{freeBytes:1073741824,coreBytes:0,catalogBytes:1024,reserveBytes:67108864}},
    account: {ok:true, devices:[{name:'Test router'}], maxDevices:5, expiresAt:'2027-01-01'},
    proxyCatalog: {nodes:[{id:'proxy-1', name:'Example proxy', serverName:'Example proxy', host:'192.0.2.9', port:1080, core:'mihomo',
        protocol:'socks5', legacy:true, sources:['feed-1'], options:{udp:true, tls:{serverName:'proxy.example.test'}}}], feeds:[{id:'feed-1', name:'Test feed', count:1, auto:true, usage:{upload:1024,download:1024,total:1048576,expire:1798761600}}]},
    importProxies: {ok:true, imported:1, skipped:0},
    mullvadAccountStatus: {ok:true, devices:[{name:'Test router'}], maxDevices:5, availableSlots:1, canAddDevices:true},
    providerServers: {ok:true, servers:[{id:'chicago',name:'Chicago'}]},
    testRelay: {ok:true, replied:true, milliseconds:12.345},
    testExit: {ok:true, reachable:true, milliseconds:45.2},
    testProxyNode: {ok:true, reachable:false, detail:'The proxy connection timed out.'},
    refreshRelays: {ok:true, relays:[{id:'ca-test-wg-003',country:'Canada',countryCode:'ca',cityCode:'yyz',city:'Test',hostname:'ca-test-wg-003',active:true}], stale:true, error:'Provider unavailable'}
};
window.confirm = () => true;
window.jQuery = (ready) => document.addEventListener('DOMContentLoaded', ready);
window.jQuery.ajax = async (request) => {
    const [, , , controller, action] = request.url.split('/');
    const data = request.data ? JSON.parse(request.data) : null;
    requests.push({controller, action, method:request.method, data});
    if (controller === 'update') {
        if (action === 'check') {
            await new Promise(resolve => setTimeout(resolve, 5));
            Object.assign(updateStatus, {enabled:true, available:'0.1.40', message:'An update is ready to install.'});
        }
        if (action === 'apply') {
            Object.assign(updateStatus, {running:true, phase:'installing', message:'Installing package.'});
        }
        if (action === 'status' && updateStatus.running && ++updatePolls === 2) {
            Object.assign(updateStatus, {running:false, phase:'done', installed:'0.1.40',
                available:'', message:'Update installed.'});
        }
        return structuredClone(updateStatus);
    }
    if (controller === 'backup') {
        if (action === 'export') {
            return {ok:true, backup:structuredClone(routingBackup)};
        }
        if (action === 'preview') {
            return {ok:true, confirmation:'fixture-confirmation', preview:{assignments:0, services:0,
                existingAssignments:2, existingServices:1}};
        }
        if (action === 'restore') {
            return {ok:true};
        }
    }
    if (action === 'testServiceRoute') {
        return data.id === 'unavailable-demo'
            ? {ok:true, host:'www.example.net', results:{lan:'Selected server unavailable. Matching traffic is blocked'}}
            : {ok:true, host:'www.youtube.com', results:{lan:'DNS and firewall match New York'}};
    }
    if (action === 'account') {
        reply.dashboard.mullvadSignedIn = true;
        reply.dashboard.mullvadLoginSaved = data.saveLogin;
        return structuredClone({...reply.account, saved:data.saveLogin});
    }
    if (action === 'restoreMullvad') {
        reply.dashboard.mullvadSignedIn = true;
        return structuredClone({...reply.account, saved:true});
    }
    if (action === 'logoutMullvad') {
        reply.dashboard.mullvadSignedIn = false;
        reply.dashboard.mullvadLoginSaved = false;
    }
    if (action === 'providerLogin' || action === 'providerLogout') {
        reply.dashboard.providerAccounts[data.provider] = action === 'providerLogin';
    }
    if (action === 'mystBeginAuth') {
        reply.dashboard.mystAuth = {pending:true, status:'pending',
            approvalUrl:'https://app.mysteriumvpn.com/oauth/authorize?request_id=test'};
        return {ok:true, ...reply.dashboard.mystAuth};
    }
    if (action === 'mystPollAuth') {
        reply.dashboard.mystAuth = {authenticated:true, status:'authenticated'};
        reply.dashboard.providerAccounts.mysterium = true;
        return {ok:true, ...reply.dashboard.mystAuth};
    }
    if (action === 'mystLocations') {
        return {ok:true, locations:[{id:'myst-loc', name:'United States · New York'}]};
    }
    if (action === 'ivpnLogin') {
        const authorized = data.confirmation === '123456';
        reply.dashboard.ivpnAuth = authorized ? {authenticated:true, saved:true, status:'authenticated'}
            : {authenticated:false, status:'pending', challenge:'totp', message:'Enter your authenticator code.'};
        reply.dashboard.providerAccounts.ivpn = authorized;
        return {ok:true, ...reply.dashboard.ivpnAuth};
    }
    if (action === 'ivpnServers') {
        return {ok:true, servers:[{id:'ivpn-loc', name:'Canada · Toronto'}]};
    }
    if (action === 'addMystExit' || action === 'addIvpnExit') {
        const provider = action === 'addMystExit' ? 'mysterium' : 'ivpn';
        reply.dashboard.profiles.push({id:provider + '1', name:data.name, provider, providerLocation:data.server,
            interface:'wg4', dns:['9.9.9.9']});
    }
    if (action === 'addProviderExit') {
        reply.dashboard.profiles.push({id:'pia1',name:data.name,provider:data.provider,providerLocation:data.server,
            interface:'wg2',dns:['10.0.0.2']});
    }
    if (action === 'register') {
        reply.dashboard.profiles.push({id:'vpn2',name:data.name,provider:'mullvad',relay:data.relay,
            interface:'wg3',port:data.port,dns:['10.64.0.1']});
        return {ok:true, profile:'vpn2'};
    }
    if (action === 'removeProfiles' || action === 'removeProxyNodes') {
        if (bulkRemoveError) return {ok:false, error:bulkRemoveError};
        const selected = JSON.parse(data.selection);
        if (action === 'removeProfiles') {
            reply.dashboard.profiles = reply.dashboard.profiles.filter(profile =>
                !selected.profiles.includes(profile.id) && !selected.nodes.includes(profile.node));
            reply.proxyCatalog.nodes = reply.proxyCatalog.nodes.filter(node => !selected.nodes.includes(node.id));
            return {ok:true, removed:selected.profiles.length + selected.nodes.length};
        }
        reply.proxyCatalog.nodes = reply.proxyCatalog.nodes.filter(node => !selected.includes(node.id));
        return {ok:true, removed:selected.length};
    }
    if (action === 'removeProfile') {
        reply.dashboard.profiles = reply.dashboard.profiles.filter(profile => profile.id !== data.id);
    }
    if (action === 'setServiceDestination') {
        reply.dashboard.services.find(x => x.id === data.id).profile = data.profile;
    }
    if (action === 'renameProfile') {
        reply.dashboard.profiles.find(x => x.id === data.id).name = data.name;
    }
    if (action === 'setMullvadEnabled') {
        reply.dashboard.profiles.find(x => x.id === data.id).disabled = !data.enabled;
    }
    if (action === 'setMullvadPort') {
        reply.dashboard.profiles.find(x => x.id === data.id).port = data.port;
        return {ok:true, port:data.port};
    }
    if (action === 'assign' && data.kind === 'tailnet') {
        const existing = reply.dashboard.assignments.find(row => row.id === 'tailnet1');
        const fields = {...data, label: data.label || 'Remote iPad', ipv6: data.ipv6 || 'fd7a:115c:a1e0::104'};
        if (existing) Object.assign(existing, fields);
        else reply.dashboard.assignments.push({id:'tailnet1', ...fields});
    }
    if (action === 'assign' && data.kind === 'lan' && data.mac === '02:00:00:00:00:31') {
        const existing = reply.dashboard.assignments.find(row => row.id === 'mac-device');
        const fields = {...data, effectiveIp:existing?.effectiveIp ?? data.ip};
        if (existing) Object.assign(existing, fields);
        else reply.dashboard.assignments.push({id:'mac-device', ...fields});
    }
    if (action === 'setNetworkDevice') {
        const existing = reply.dashboard.assignments.find(row => row.id === data.id);
        const status = data.networkBypass === undefined ? {} : {networkBypassStatus:data.networkBypass ? 'direct' : ''};
        if (existing) {
            Object.assign(existing, data, status);
        } else {
            reply.dashboard.assignments.push({id:'network-device1', kind:'lan', mode:'default',
                profile:'', networkBypass:false, ...data, ...status});
        }
    }
    if (action === 'setTailnetRuleEnabled') {
        reply.dashboard.assignments.find(row => row.id === data.id).paused = !data.enabled;
    }
    if (action === 'testTailnetBase') {
        return {ok:true, reachable:true, milliseconds:22.4, deviceTraffic:'unseen'};
    }
    if (action === 'testDeviceRoute') {
        return {ok:true, reachable:true, milliseconds:22.4, deviceTraffic:data.id === 'tailnet1' ? tailnetTraffic : 'seen', usingBackup:false};
    }
    if (action === 'testExit' && exitTestError) {
        return {ok:true, reachable:false, detail:exitTestError};
    }
    if (action === 'renameProxyNode') {
        reply.proxyCatalog.nodes.find(x => x.id === data.id).name = data.name;
    }
    if (action === 'saveService') {
        reply.dashboard.services = [{id:'list1', name:data.name, profile:data.profile, domains:data.domains.split(/[,\s]+/)}];
    }
    if (action === 'disable') {
        reply.dashboard.settings.enabled = false;
    }
    if (action === 'tailnetRouting') {
        for (const [key, value] of Object.entries(data)) {
            reply.dashboard.settings['tailnet' + key[0].toUpperCase() + key.slice(1)] = value;
        }
    }
    if (action === 'settings' && settingsError) {
        return {ok:false, error:settingsError};
    }
    if (action === 'settings' || action === 'tailscaleSettings') {
        Object.assign(reply.dashboard.settings, data);
    }
    if (action === 'setSubscriptionAuto') reply.proxyCatalog.feeds[0].auto = data.auto;
    if (action === 'disableProxyNode' || action === 'enableProxyExit') {
        reply.proxyCatalog.nodes.find(x => x.id === data.id).disabled = action === 'disableProxyNode';
    }
    if (action === 'discoverDevices') {
        if (!reply.dashboard.devices.some(device => device.ipv4 === '10.0.0.30')) {
            reply.dashboard.devices.push({ipv4:'10.0.0.30', interface:'lan',
                name:'New console', mac:'02:00:00:00:00:30', stable:false, arpConfirmed:false, leaseProvider:'Dnsmasq DHCP'});
            reply.dashboard.devices.push({ipv4:'10.0.2.45', interface:'opt1',
                name:'Guest phone', mac:'02:00:00:00:00:45', stable:false, arpConfirmed:false, leaseProvider:'Dnsmasq DHCP'});
            reply.dashboard.devices.push({ipv4:'10.0.0.46', interface:'lan', name:'Changed reservation',
                mac:'02:00:00:00:00:46', stable:false, arpConfirmed:true, addressConflict:true, reservationIpv4:'10.0.0.16'});
            reply.dashboard.devices.push({ipv4:'10.0.0.31', currentIpv4:'10.0.0.31', interface:'lan',
                name:'Laptop', mac:'02:00:00:00:00:31', stable:false, leaseProvider:'Kea DHCPv4', macBindingSupported:true});
        }
    }
    return structuredClone(reply[action] || {ok:true});
};

const bv = (id) => document.getElementById('bv-'+id);
const wait = () => new Promise(resolve => setTimeout(resolve, 20));
const assert = (value, message) => { if (!value) throw Error(message); };
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await wait();
    assert(bv('system-page').contains(bv('appearance')) &&
        !document.querySelector('.bv-hero').contains(bv('appearance')) && bv('system-page').hidden,
        'Appearance must be located in System Settings.');
    assert(bv('device-list').textContent.includes('<b>Device rule</b>'), 'device name should remain literal text');
    assert(!bv('device-list').querySelector('b'), 'device name injected HTML');
    assert(bv('device-list').textContent.includes('10.0.0.21') &&
        bv('tailnet-device-list').textContent.includes('100.101.102.104') &&
        bv('tailnet-device-list').textContent.includes('Online'), 'LAN and Tailscale addresses must be shown in separate lists');
    bv('appearance').value = 'night';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(document.getElementById('blankvpn')).colorScheme === 'dark', 'night theme did not apply');
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(document.getElementById('blankvpn')).colorScheme === 'light', 'day theme did not apply');
    assert(!bv('tunnels').hidden && !bv('login-form').hidden && bv('register-form').hidden, 'login is not the starting page');
    assert(document.querySelector('[data-bv-section="vpns"]').textContent === 'VPN Login' &&
        bv('vpn-page-title').textContent === 'VPN Service' &&
        bv('provider').labels[0].classList.contains('sr-only') &&
        bv('vpn-page-title').closest('section').contains(bv('register-form')) &&
        bv('vpn-page-title').closest('section').contains(bv('provider-server-form')) &&
        bv('saved-vpn-title').textContent === 'Saved VPN servers' &&
        bv('saved-vpn-title').closest('section').contains(bv('profile-list')) &&
        bv('saved-vpn-title').nextElementSibling.textContent.includes('Network Settings'),
        'Adding and managing saved servers must appear in separate VPN Login sections.');
    assert(!requests.some(x => x.action === 'relays'), 'server list loaded before sign-in');
    assert(getComputedStyle(bv('appearance')).backgroundImage === 'none', 'host select decoration was not suppressed');
    document.querySelector('[data-bv-section="network"]').click();
    const ports = bv('managed').querySelectorAll('input');
    const checked = ports[0].closest('label');
    assert(getComputedStyle(checked).color === 'rgb(23, 56, 102)' &&
        getComputedStyle(checked).backgroundColor === 'rgb(237, 243, 255)', 'day interface highlight lost contrast');
    bv('save-routing').focus();
    assert(getComputedStyle(bv('save-routing')).backgroundColor === 'rgb(38, 75, 134)', 'host theme overrode the focused day button');
    bv('appearance').value = 'night';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(checked).color === 'rgb(220, 233, 255)' &&
        getComputedStyle(checked).backgroundColor === 'rgb(35, 52, 80)' &&
        getComputedStyle(bv('save-routing')).color === 'rgb(20, 36, 63)', 'night controls lost contrast');
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(ports.length === 3 && ports[0].value === 'lan' && ports[0].parentElement.textContent.includes('igc0') &&
        bv('managed').textContent.includes('vlan02'), 'Ethernet ports and VLANs should be listed with the main port first');
    bv('device-list').querySelector('button').click();
    assert(bv('ip').value === '10.0.0.20' && bv('interface').value === 'lan', 'saved rule did not populate');
    bv('mode').value = 'full';
    bv('profile').value = 'vpn1';
    bv('profile').dispatchEvent(new Event('change'));
    bv('assign-form').requestSubmit(bv('assign-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.method === 'POST' && x.data.profile === 'vpn1' &&
        x.data.failure === 'block' && x.data.killSwitch === true && x.data.onDemand === true && x.data.bindMac === false),
        'Legacy reservation rules must keep their identity and default to On Demand.');
    assert(bv('assignment').hidden, 'successful assignment did not close');
    bv('add-device').click();
    bv('device-kind').value = 'tailnet';
    bv('device-kind').dispatchEvent(new Event('change'));
    bv('mode').value = 'blocked';
    bv('mode').dispatchEvent(new Event('change'));
    assert(bv('ipv6').required && bv('profile-field').hidden && bv('mac-field').hidden, 'Tailscale block form has incorrect fields');
    bv('close-assignment').click();
    assert(!bv('device-list').textContent.includes('Connections') && !bv('connections'),
        'Connection inspection must be removed from Network Settings.');
    document.querySelector('[data-bv-section="vpns"]').click();
    assert(!bv('tunnels').hidden && bv('register-form').hidden, 'VPN login did not open');
    bv('account').value = '1234567890123456';
    bv('save-login').checked = true;
    bv('inspect-account').click();
    await wait();
    assert(bv('account-status').textContent.includes('1 of 5') && bv('login-form').hidden &&
        !bv('register-form').hidden, 'successful sign-in did not switch to server selection');
    assert(requests.some(x => x.action === 'account' && x.data.saveLogin === true) &&
        bv('account-status').textContent.includes('Login saved'), 'saved login did not round-trip');
    reply.dashboard.mullvadSignedIn = false;
    bv('refresh').click();
    await wait();
    assert(requests.some(x => x.action === 'restoreMullvad' && !Object.hasOwn(x.data, 'account')) &&
        !bv('register-form').hidden, 'saved login did not restore the server picker');
    assert(bv('relay').options.length === 4 && bv('relay').options[2].disabled, 'server availability not enforced');
    assert(!bv('mullvad-batches') && !bv('relay-list') && bv('profile-list').rows.length === 1,
        'Mullvad must list configured tunnels and offer individual server selection.');
    bv('country').value = 'Canada';
    bv('country').dispatchEvent(new Event('change'));
    assert(bv('relay').options.length === 3 && bv('relay').options[2].disabled,
        'The country filter must keep the individual server picker usable.');
    bv('relay').value = 'ca-test-wg-001';
    bv('relay').dispatchEvent(new Event('change'));
    assert(bv('relay-choice').textContent.includes('Canada') && bv('register').disabled &&
        bv('register').textContent === 'Already added', 'an already saved server must show Already added');
    bv('test-relay').click();
    await wait();
    assert(bv('relay-test').textContent.includes('12.345 ms') &&
        requests.some(x => x.action === 'testRelay' && x.data.relay === 'ca-test-wg-001'), 'per-relay ping missing');
    const vpnRow = bv('profile-list').rows[0];
    const vpnTest = vpnRow.querySelector('[data-test-key]');
    const vpnStatus = (id) => bv('profile-list').querySelector('[data-vpn-status="' + id + '"]')?.textContent;
    const vpnPing = vpnRow.querySelector('[data-test-result]');
    assert(vpnTest.textContent === 'Test' && vpnStatus('vpn1') === 'Standby' &&
        bv('profile-list').closest('table').tHead.rows[0].cells[3].textContent === 'Status' &&
        bv('profile-list').closest('table').tHead.rows[0].cells[4].textContent === 'Port' &&
        bv('profile-list').closest('table').tHead.rows[0].cells[5].textContent === 'Ping' &&
        vpnRow.cells[4].textContent.includes('51820') &&
        vpnPing.closest('td') !== vpnTest.closest('td') && vpnPing.firstElementChild.textContent === '—',
        'The VPN Ping column must be separate from the Test action and available before testing.');
    const geometry = (row) => [row, ...row.cells, row.querySelector('[data-test-key]')].map((element) => {
        const {x, y, width, height} = element.getBoundingClientRect();
        // Keyboard focus may scroll an offscreen control into view; compare document geometry.
        return [x + window.scrollX, y + window.scrollY, width, height];
    });
    const steady = (row, before) => geometry(row).every((rect, index) =>
        rect.every((value, dimension) => Math.abs(value - before[index][dimension]) < .5));
    const textFitsOnOneLine = (element) => {
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
        const range = document.createRange();
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            if (node.textContent.trim()) {
                range.selectNodeContents(node);
                const lines = [...range.getClientRects()].filter((rect) => rect.width > 0);
                const cell = element.getBoundingClientRect();
                return lines.length === 1 && lines[0].left >= cell.left - 1 && lines[0].right <= cell.right + 1;
            }
        }
        return false;
    };
    const checkServerLayout = (row, name, status) => {
        const table = row.closest('table');
        const tableBounds = table.getBoundingClientRect();
        const frame = table.parentElement.getBoundingClientRect();
        const actions = row.querySelector('[data-test-key]').closest('td');
        const buttons = [...actions.querySelectorAll('button')].map(button => button.getBoundingClientRect());
        assert(tableBounds.width <= frame.width + 1 &&
            buttons.every(button => button.width > 0 && button.left >= frame.left - 1 && button.right <= frame.right + 1),
            name + ' must fit the available space with all actions visible.');
        if (status) {
            assert(textFitsOnOneLine(status), 'VPN status must stay on a single line.');
        }
        const presentation = getComputedStyle(table).display;
        if (document.documentElement.clientWidth >= 1200) {
            const alignment = getComputedStyle(row.cells[1]).textAlign;
            assert(presentation === 'table' && ['left', 'start'].includes(alignment),
                name + ' must align server names with their desktop table heading.');
            assert(buttons.every(button => Math.abs(button.top - buttons[0].top) < 1),
                name + ' must keep its desktop actions in one row.');
            const identityStyle = getComputedStyle(row.cells[1]);
            const detailStyle = getComputedStyle(row.querySelector('small'));
            const expectedContent = parseFloat(identityStyle.lineHeight) + parseFloat(detailStyle.lineHeight) +
                parseFloat(detailStyle.marginTop);
            const expectedHeight = Math.max(buttons[0].height, expectedContent) +
                parseFloat(identityStyle.paddingTop) + parseFloat(identityStyle.paddingBottom);
            assert(row.getBoundingClientRect().height <= expectedHeight + 4,
                name + ' must keep its desktop row compact (' +
                Math.round(row.getBoundingClientRect().height) + 'px, expected up to ' + Math.ceil(expectedHeight + 4) + 'px).');
        } else {
            const identity = row.cells[1].getBoundingClientRect();
            assert(presentation !== 'table' && buttons[0].top >= identity.bottom - 1,
                name + ' must stack its details and actions when the available space is narrow.');
        }
    };
    checkServerLayout(vpnRow, 'Saved VPN servers', vpnRow.querySelector('[data-vpn-status]'));
    const beforeVpn = geometry(vpnRow);
    vpnTest.click();
    assert(vpnTest.disabled && vpnPing.firstElementChild.textContent === 'Testing…' && steady(vpnRow, beforeVpn),
        'Starting the VPN test must preserve the layout.');
    await wait();
    assert(vpnStatus('vpn1') === 'Ready' && vpnPing.firstElementChild.textContent === '45.2 ms' && steady(vpnRow, beforeVpn),
        'The VPN ping result must preserve layout and set Ready status.');
    const editMullvad = (name) => bv('profile-list').querySelector('[aria-label="Edit name and WireGuard port for ' + name + '"]');
    editMullvad('Canada').click();
    const vpnName = bv('profile-list').querySelector('.bv-name-editor');
    vpnName.querySelector('input').value = 'Canada home';
    vpnName.requestSubmit(vpnName.querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'renameProfile' && x.data.id === 'vpn1' && x.data.name === 'Canada home') &&
        bv('profile-list').textContent.includes('Canada home') &&
        bv('profile-list').querySelector('[data-test-result]').textContent.includes('45.2 ms'), 'VPN rename lost the row or its result');
    exitTestError = 'The HTTPS test did not complete through the tunnel. '.repeat(14);
    const renamedVpn = bv('profile-list').rows[0];
    const renamedGeometry = geometry(renamedVpn);
    renamedVpn.querySelector('[data-test-key]').click();
    await wait();
    const vpnError = renamedVpn.querySelector('.bv-ping-error');
    assert(vpnStatus('vpn1') === 'Error' && !vpnError.hidden && vpnError.title === exitTestError &&
        steady(renamedVpn, renamedGeometry), 'A long error must stay in the Ping column without expanding the VPN row.');
    vpnError.click();
    assert(bv('ping-dialog').open && bv('ping-dialog-detail').textContent === exitTestError,
        'The Ping result must retain the complete error details.');
    bv('ping-dialog').close();
    renamedVpn.querySelector('.bv-test-dismiss').click();
    assert(vpnError.hidden && renamedVpn.querySelector('[data-test-result] span').textContent === '—' &&
        vpnStatus('vpn1') === 'Error' && steady(renamedVpn, renamedGeometry),
        'Dismissing the error details must preserve the server status and layout. ' +
        JSON.stringify({hidden:vpnError.hidden, status:vpnStatus('vpn1'), before:renamedGeometry, after:geometry(renamedVpn)}));
    exitTestError = null;
    [...bv('profile-list').querySelectorAll('button')].find(button => button.textContent === 'Disable').click();
    await wait();
    assert(reply.dashboard.profiles[0].disabled && vpnStatus('vpn1') === 'Disabled' &&
        bv('register').disabled && bv('register').textContent === 'Already added' &&
        ![...bv('network-profile').options].some(option => option.value === 'vpn1'),
        'A disabled Mullvad server must stay saved and leave the routing picker.');
    assert(textFitsOnOneLine(bv('profile-list').querySelector('[data-vpn-status="vpn1"]')),
        'The Disabled status must stay on a single line.');
    [...bv('profile-list').querySelectorAll('button')].find(button => button.textContent === 'Enable').click();
    await wait();
    assert(!reply.dashboard.profiles[0].disabled && vpnStatus('vpn1') === 'Standby',
        'The existing Mullvad tunnel must be re-enabled without stale test status.');
    bv('profile-list').querySelector('[data-test-key]').click();
    await wait();
    editMullvad('Canada home').click();
    const portForm = bv('profile-list').querySelector('.bv-mullvad-port');
    const portChoice = portForm.querySelector('select');
    const savePort = portForm.querySelector('button');
    assert(portChoice.value === '51820' && [...portChoice.options].map(x => x.value).join(',') === '51820,53' && savePort.disabled,
        'Existing Mullvad tunnels must show the default port and the supported alternate.');
    portChoice.value = '53';
    portChoice.dispatchEvent(new Event('change'));
    assert(!savePort.disabled && requests.every(x => x.action !== 'setMullvadPort'),
        'Changing the port selector must wait for explicit save.');
    const assignmentBeforePort = JSON.stringify(reply.dashboard.assignments);
    portForm.requestSubmit(savePort);
    await wait();
    assert(requests.some(x => x.action === 'setMullvadPort' && x.data.id === 'vpn1' && x.data.port === 53) &&
        bv('profile-list').querySelector('.bv-mullvad-port select').value === '53' &&
        bv('profile-list').rows[0].cells[4].textContent.includes('53') &&
        bv('profile-list').querySelector('[data-test-result]').firstElementChild.textContent === '—' &&
        JSON.stringify(reply.dashboard.assignments) === assignmentBeforePort,
        'Saving a Mullvad port must keep the assigned tunnel and clear its old Ping result.');
    [...bv('profile-list').querySelector('.bv-name-editor').querySelectorAll('button')]
        .find(button => button.textContent === 'Cancel').click();
    assert(bv('account').value === '', 'successful sign-in retained account input');
    bv('country').value = 'Japan';
    bv('country').dispatchEvent(new Event('change'));
    bv('relay').value = 'jp-test-wg-001';
    bv('relay').dispatchEvent(new Event('change'));
    bv('register-name').value = 'Japan home';
    assert(bv('register-port').value === '51820', 'New Mullvad tunnels must default to the standard WireGuard port.');
    bv('register-port').value = '53';
    assert(bv('register').textContent === 'Add server' && !bv('register').disabled && !bv('retarget'),
        'Mullvad should offer an independent Add server action.');
    const routingBeforeAdd = structuredClone({assignments:reply.dashboard.assignments, settings:reply.dashboard.settings});
    const requestCountBeforeAdd = requests.length;
    bv('register-form').requestSubmit(bv('register'));
    await wait();
    const addRequests = requests.slice(requestCountBeforeAdd).filter(request => request.method === 'POST');
    assert(addRequests.length === 1 && addRequests[0].action === 'register' &&
        Object.keys(addRequests[0].data).sort().join(',') === 'name,port,relay' && addRequests[0].data.port === 53 &&
        addRequests[0].data.relay === 'jp-test-wg-001' && addRequests[0].data.name === 'Japan home' &&
        bv('register-port').value === '51820',
        'Add server must send the selected UDP port and reset the port selector for the next tunnel.');
    assert(reply.dashboard.profiles[0].relay === 'ca-test-wg-001' &&
        bv('profile-list').textContent.includes('Japan home') &&
        [...bv('network-profile').options].some(option => option.value === 'vpn2') &&
        JSON.stringify(routingBeforeAdd) === JSON.stringify({assignments:reply.dashboard.assignments, settings:reply.dashboard.settings}),
        'Adding a server must preserve the prior server and routing assignments.');
    bv('profile-list').querySelector('[aria-label="Remove Japan home"]').click();
    await wait();
    assert(requests.some(x => x.action === 'removeProfile' && x.data.id === 'vpn2') &&
        !bv('profile-list').textContent.includes('Japan home') && bv('profile-list').textContent.includes('Canada home'),
        'Removing a saved server must keep the other saved server.');
    document.querySelector('[data-bv-section="smart"]').click();
    const formatHelp = bv('service-format').textContent;
    assert(['*.example.com', '*.example.*', '*.cn', '203.0.113.42/32', '198.51.100.0/24', '2001:db8::/32']
        .every(example => formatHelp.includes(example)) && formatHelp.includes('invalid'),
        'Multi-Path must show domain wildcard and IP syntax.');
    bv('service-preset').value = 'Netflix';
    bv('service-preset').dispatchEvent(new Event('change'));
    assert(bv('service-domains').value === 'netflix.com\nnflxvideo.net', 'Netflix preset domains not populated');
    const originalProfiles = reply.dashboard.profiles;
    reply.dashboard.profiles = [];
    bv('refresh').click();
    await wait();
    const importedEntries = 'netflix.com\n*.nflxvideo.net\nnflximg.net,198.51.100.0/24\n203.0.113.5\n2001:db8::/32';
    const data = new DataTransfer();
    data.items.add(new File([importedEntries], 'Netflix.txt'));
    bv('service-file').files = data.files;
    // Headless Chrome can exhaust its virtual time budget before native file IO returns.
    const nativeText = File.prototype.text;
    File.prototype.text = async function () {
        assert(this.name === 'Netflix.txt', 'wrong domain file was read');
        return importedEntries;
    };
    try {
        bv('service-file').dispatchEvent(new Event('change'));
        await wait();
    } finally {
        File.prototype.text = nativeText;
    }
    assert(bv('domain-file-status').textContent.includes('Netflix.txt') && !bv('download-domains').disabled,
        'domain file was not loaded');
    bv('service-form').requestSubmit(bv('save-service'));
    await wait();
    assert(requests.some(x => x.action === 'saveService' && x.data.profile === '' &&
        x.data.domains === importedEntries) && bv('service-list').querySelector('select').value === '' &&
        bv('service-list').textContent.includes('6 entries'),
        'Multi-Path must keep mixed domain and IP entries before a destination is assigned.');
    reply.dashboard.profiles = originalProfiles;
    bv('refresh').click();
    await wait();
    bv('service-list').querySelector('[aria-label="Edit Netflix"]').click();
    bv('service-profile').value = 'vpn1';
    bv('service-form').requestSubmit(bv('save-service'));
    await wait();
    assert(requests.some(x => x.action === 'saveService' && x.data.id === 'list1' && x.data.profile === 'vpn1' &&
        x.data.domains.includes('*.nflxvideo.net') && x.data.domains.includes('198.51.100.0/24') &&
        x.data.domains.includes('203.0.113.5') && x.data.domains.includes('2001:db8::/32')),
        'The saved mixed list could not be edited or bound to an exit.');
    const destination = bv('service-list').querySelector('select');
    destination.value = 'bypass';
    destination.dispatchEvent(new Event('change'));
    assert(!requests.some(x => x.action === 'setServiceDestination') &&
        reply.dashboard.services[0].profile === 'vpn1', 'Changing a destination must wait for Save.');
    destination.form.querySelector('button').click();
    await wait();
    assert(requests.some(x => x.action === 'setServiceDestination' && x.data.id === 'list1' &&
        x.data.profile === 'bypass' && !Object.hasOwn(x.data, 'domains')) &&
        reply.dashboard.services[0].domains.includes('*.nflxvideo.net') &&
        reply.dashboard.services[0].domains.includes('198.51.100.0/24') &&
        bv('service-list').querySelector('select').value === 'bypass',
        'The list destination must change without submitting or altering the domains.');
    const switchBack = bv('service-list').querySelector('select');
    switchBack.value = 'vpn1';
    switchBack.dispatchEvent(new Event('change'));
    switchBack.form.querySelector('button').click();
    await wait();
    bv('use-lan').click();
    assert(bv('interface-rules').querySelector('[data-interface="lan"] select').value === 'smart' &&
        bv('managed').querySelector('[value="lan"]').checked, 'main Ethernet Multi-Path shortcut did not prefill');
    document.querySelector('[data-bv-section="proxies"]').click();
    await wait();
    bv('core-manager').open = true;
    await wait();
    assert(bv('core-list').textContent.includes('Mihomo (Clash)') &&
        bv('core-storage').textContent.includes('1.0 GiB free'), 'core status and storage not displayed');
    bv('core-check').click();
    await wait();
    assert(requests.some(x => x.action === 'check' && x.method === 'POST'), 'approved catalog check did not run');
    assert(bv('proxy-list').textContent.includes('Example proxy'), 'proxy catalog not displayed');
    const proxyRow = bv('proxy-list').rows[0];
    assert([...proxyRow.closest('table').tHead.rows[0].cells].slice(1).map(cell => cell.textContent.trim()).join(',') ===
        'Name,Server,Protocol,Core,Ping,Action' && proxyRow.cells[1].textContent.includes('Example proxy') &&
        proxyRow.cells[2].textContent.includes('192.0.2.9:1080') && proxyRow.cells[2].textContent.includes('Legacy'),
        'Proxy name and server details must be separate and retain the requested column order and transport warning.');
    const proxyTest = proxyRow.querySelector('[data-test-key]');
    const proxyPing = proxyRow.querySelector('[data-test-result]');
    checkServerLayout(proxyRow, 'Proxy servers');
    const beforeProxy = geometry(proxyRow);
    proxyTest.click();
    assert(proxyPing.firstElementChild.textContent === 'Testing…' && steady(proxyRow, beforeProxy),
        'Starting the proxy test must preserve the layout.');
    await wait();
    const failedTest = proxyPing.querySelector('.bv-ping-error');
    assert(requests.some(x => x.action === 'testProxyNode' && x.data.id === 'proxy-1') &&
        !failedTest.hidden && failedTest.title.includes('The proxy connection timed out.') &&
        failedTest.textContent === 'Failed' && steady(proxyRow, beforeProxy),
        'The proxy failure should remain in the Ping column without moving buttons.');

    assert([...proxyTest.closest('td').querySelectorAll('button')].map(button => button.textContent).join(',') === 'Test,Edit,Disable,Remove',
        'proxy row actions must use simple labels');
    assert(getComputedStyle(failedTest).color === 'rgb(142, 39, 60)',
        'Failed test result lost its warning color.');
    const proxySettingsBeforeRename = structuredClone(reply.proxyCatalog.nodes[0]);
    bv('proxy-list').querySelector('[aria-label="Edit name for Example proxy"]').click();
    const proxyName = bv('proxy-list').querySelector('.bv-name-editor');
    proxyName.querySelector('input').value = 'SOCKS5 office';
    proxyName.requestSubmit(proxyName.querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'renameProxyNode' && x.data.id === 'proxy-1' && x.data.name === 'SOCKS5 office') &&
        bv('proxy-list').textContent.includes('SOCKS5 office') &&
        bv('proxy-list').querySelector('.bv-ping-error').title.includes('timed out'), 'Proxy rename lost the row or its result');
    const renamedProxyRequest = requests.findLast(x => x.action === 'renameProxyNode');
    assert(Object.keys(renamedProxyRequest.data).sort().join(',') === 'id,name' &&
        JSON.stringify({...reply.proxyCatalog.nodes[0], name:proxySettingsBeforeRename.name}) === JSON.stringify(proxySettingsBeforeRename) &&
        bv('proxy-list').rows[0].cells[1].textContent.includes('SOCKS5 office') &&
        bv('proxy-list').rows[0].cells[2].textContent.includes('Example proxy') &&
        bv('proxy-list').rows[0].cells[2].textContent.includes('192.0.2.9:1080'),
        'Renaming must change only the display name and retain original server identity, endpoint, transport, sources, and options.');
    assert(bv('subscription-list').textContent.includes('Test feed'), 'proxy subscription not displayed');
    assert(bv('subscription-list').textContent.includes('2.0 KiB used / 1.0 MiB'), 'subscription quota not displayed');
    assert(bv('subscription-auto').checked, 'auto-refresh should default on for new subscriptions');
    bv('subscription-list').querySelectorAll('button')[1].click();
    await wait();
    assert(requests.some(x => x.action === 'setSubscriptionAuto' && x.data.id === 'feed-1' && x.data.auto === false),
        'existing subscription refresh schedule did not update');
    bv('manual-name').value = 'Manual example';
    bv('manual-host').value = '192.0.2.8';
    bv('manual-port').value = '1080';
    bv('proxy-manual').requestSubmit(bv('proxy-manual').querySelector('button'));
    await wait();
    assert(requests.some(x => x.action === 'addProxyNode' && x.data.protocol === 'socks5'), 'manual proxy was not submitted');
    const buttonByText = (id, label) => [...bv(id).querySelectorAll('button')].find((button) => button.textContent === label);
    buttonByText('proxy-list', 'Disable').click();
    await wait();
    assert(requests.some(x => x.action === 'disableProxyNode' && x.data.id === 'proxy-1') &&
        buttonByText('proxy-list', 'Enable'), 'imported proxies must start enabled and be switchable');
    buttonByText('proxy-list', 'Enable').click();
    await wait();
    assert(requests.some(x => x.action === 'enableProxyExit' && x.data.id === 'proxy-1'), 'proxy could not be re-enabled');
    reply.proxyCatalog.nodes.unshift(...Array.from({length:55}, (_, index) => ({
        id:'bulk-' + index, name:'Server ' + index, host:'192.0.2.6', port:1080, protocol:'vless', core:'mihomo'
    })));
    buttonByText('subscription-list', 'Refresh').click();
    await wait();
    assert(!bv('proxy-search') && !bv('proxy-filter'), 'Proxy search and protocol filtering controls should be absent.');
    assert(bv('proxy-count').textContent.includes('1–50 of 56'), 'large catalog page count is incorrect');
    bv('proxy-next').click();
    assert(bv('proxy-count').textContent.includes('51–56 of 56') && bv('proxy-next').disabled &&
        bv('proxy-list').textContent.includes('SOCKS5 office'), 'later pages must include all servers');
    bv('proxy-prev').click();
    assert(bv('proxy-prev').disabled && bv('proxy-count').textContent.includes('1–50 of 56'), 'back navigation must restore the first page');
    reply.proxyCatalog.nodes.splice(0, 55);
    bv('proxy-body').value = 'socks5://192.0.2.9:1080';
    bv('proxy-import-name').value = 'Private SOCKS';
    bv('proxy-import').requestSubmit(bv('proxy-import').querySelector('button'));
    await wait();
    assert(requests.some(x => x.action === 'importProxies' && x.data.name === 'Private SOCKS') &&
        bv('proxy-body').value === '' && bv('proxy-import-name').value === '', 'proxy import was not submitted and cleared');
    document.querySelector('[data-bv-section="tailscale"]').click();
    assert(!bv('tailscale-page').hidden && bv('tailscale-status').textContent.includes('Exit node advertised') &&
        !bv('native-tailscale').hidden, 'Tailscale page or native status missing');
    assert(bv('dashboard-link').href === 'https://opnsense.home.arpa/ui/blankvpn/index',
        'standalone dashboard address missing');
    bv('dashboard-bind').value = 'tailnet';
    bv('dashboard-bind').dispatchEvent(new Event('input', {bubbles:true}));
    assert(bv('dashboard-link').hostname === 'opnsense.tailnet.ts.net' &&
        bv('address-link').hostname === '100.101.102.103' && bv('dashboard-hostname-field').hidden,
        'Tailscale dashboard must show MagicDNS and its direct IP.');
    bv('tailscale-form').requestSubmit(bv('tailscale-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'tailscaleSettings' && x.data.dashboardBind === 'tailnet' &&
        x.data.tailscaleInterfaces.includes('opt2') && !Object.hasOwn(x.data, 'interfaces')), 'Tailscale save was not scoped');
    bv('add-tailnet-device').click();
    assert(!bv('assignment').hidden && bv('device-kind').value === 'tailnet' &&
        bv('interface').value === 'opt2', 'Tailscale device rule did not use the selected link');
    bv('close-assignment').click();
    document.querySelector('[data-bv-section="tailscale"]').click();
    bv('use-local-name').click();
    assert(bv('hostname').value === 'blankvpn.local' && bv('dashboard-bind').value === 'lan' &&
        bv('bonjour').open && bv('bonjour-command').textContent.endsWith('blankvpn.local 10.0.0.1'),
        'Local name preset did not select the home address and show the Bonjour command.');
    bv('tailscale-form').requestSubmit(bv('tailscale-form').querySelector('button[type=submit]'));
    await wait();
    assert(bv('dashboard-link').hostname === 'blankvpn.local' && bv('address-link').hostname === '10.0.0.1',
        'Saved hostname and direct address did not update.');
    document.querySelector('[data-bv-section="network"]').click();
    bv('routing-scope').value = 'local';
    bv('routing-scope').dispatchEvent(new Event('change'));
    assert(bv('save-routing').textContent === 'Save and Enable VPN' && bv('routing-enabled').hidden &&
        bv('network-kill-field').hidden, 'Disabled routing did not show the enable action.');
    bv('settings-form').requestSubmit(bv('settings-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.interfaces.includes('lan') &&
      x.data.smartInterfaces.includes('lan') && x.data.enabled === true &&
      !Object.hasOwn(x.data, 'dashboardBind')), 'network save was not scoped');
    assert(bv('save-routing').classList.contains('bv-enabled') && !bv('routing-enabled').hidden,
        'Verified enabled state did not turn the button green.');
    bv('refresh').click();
    await wait();
    assert(requests.some(x => x.action === 'discoverDevices') && bv('device-list').textContent.includes('New console'),
        'Manual refresh must discover and display LAN devices.');
    const discoveryRows = [...bv('device-list').rows];
    const consoleRow = discoveryRows.find(row => row.cells[0].textContent.includes('New console'));
    const outsideRow = discoveryRows.find(row => row.cells[0].textContent.includes('Guest phone'));
    const changedRow = discoveryRows.find(row => row.cells[0].textContent.includes('Changed reservation'));
    assert(consoleRow.cells[0].textContent.includes('DHCP lease') && !consoleRow.textContent.includes('Online'),
        'A lease-only device must be identified without claiming it is online.');
    assert(outsideRow.textContent.includes('Interface outside coverage') &&
        outsideRow.textContent.includes('Select this interface in Routing coverage and save') && !outsideRow.querySelector('button'),
        'Devices on unmanaged LANs should be visible without allowing a rule until coverage is saved.');
    assert(changedRow.cells[1].textContent === '10.0.0.46' &&
        changedRow.textContent.includes('DHCP reservation is 10.0.0.16') && !changedRow.querySelector('button'),
        'Show the current device address and explain why a conflicting reservation must be corrected before assignment.');
    const savedInterfaces = [...reply.dashboard.settings.interfaces];
    const vlan = bv('managed').querySelector('[value="opt1"]');
    vlan.click();
    assert(!bv('device-list').querySelector('[aria-label="Select Guest phone"]'),
        'Marking the VLAN in a draft must leave the guest device unavailable for assignment.');
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    bv('device-list').querySelector('[aria-label="Select Guest phone"]').click();
    assert(bv('ip').value === '10.0.2.45' && bv('interface').value === 'opt1',
        'After saving VLAN coverage, selecting its DHCP device should fill its observed address and interface.');
    bv('close-assignment').click();
    reply.dashboard.settings.interfaces = savedInterfaces;
    bv('refresh').click();
    await wait();
    bv('device-list').querySelector('[aria-label="Select New console"]').click();
    assert(bv('ip').value === '10.0.0.30' && bv('mac').value === '02:00:00:00:00:30' &&
        bv('interface').value === 'lan' && bv('device-kill').checked && bv('device-on-demand').checked &&
        bv('device-bind-mac-field').hidden, 'Selecting a LAN device must fill the reservation fallback rule.');
    bv('mode').value = 'full';
    bv('mode').dispatchEvent(new Event('change'));
    bv('profile').value = 'proxy-proxy-1';
    bv('profile').dispatchEvent(new Event('change'));
    assert(!bv('save-device').disabled && bv('save-device').textContent === 'Reserve IP and save rule',
        'A detected DHCP lease must offer one-step reservation and routing.');
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.ip === '10.0.0.30' &&
        x.data.reserveIp && x.data.profile === 'proxy-proxy-1' && x.data.killSwitch && x.data.onDemand && !x.data.bindMac),
        'New proxies must be ready to assign without a separate enable action.');
    bv('device-list').querySelector('[aria-label="Select Laptop"]').click();
    assert(bv('device-bind-mac').checked && !bv('device-bind-mac-field').hidden &&
        bv('device-on-demand').checked && bv('device-kill').checked &&
        bv('save-device').textContent === 'Reserve IP and save rule' && bv('identity').textContent.includes('Saving reserves the current address'),
        'Supported LAN devices must default to MAC binding and explain the initial DHCP reservation.');
    bv('device-bind-mac').click();
    assert(bv('save-device').textContent === 'Reserve IP and save rule',
        'Turning off MAC binding must offer DHCP reservation for a verified current lease.');
    bv('device-bind-mac').click();
    bv('device-on-demand').click();
    assert(bv('device-on-demand-note').textContent === 'Keep the tunnel ready while this rule is enabled.' &&
        bv('device-kill').checked, 'On Demand must be independent of Kill Switch.');
    bv('profile').value = 'vpn1';
    bv('profile').dispatchEvent(new Event('change'));
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.ip === '10.0.0.31' && x.data.bindMac === true &&
        x.data.onDemand === false && x.data.reserveIp === true && x.data.killSwitch === true),
        'MAC binding must save the initial DHCP reservation and persist the explicit On Demand setting.');
    const laptop = reply.dashboard.devices.find(device => device.mac === '02:00:00:00:00:31');
    const macRule = reply.dashboard.assignments.find(row => row.id === 'mac-device');
    laptop.ipv4 = laptop.currentIpv4 = laptop.reservationIpv4 = macRule.effectiveIp = '10.0.0.32';
    laptop.stable = true;
    bv('refresh').click();
    await wait();
    const laptopRow = bv('device-list').querySelector('[aria-label="Edit Laptop"]').closest('tr');
    assert(laptopRow.textContent.includes('10.0.0.32') && laptopRow.textContent.includes('Follows MAC address') &&
        !laptopRow.textContent.includes('On Demand'), 'The saved MAC rule must follow the address and show its saved On Demand setting.');
    laptopRow.querySelector('[aria-label="Edit Laptop"]').click();
    assert(bv('ip').value === '10.0.0.32' && bv('device-bind-mac').checked && !bv('device-on-demand').checked,
        'Editing a MAC-bound rule must use the effective address and preserve the saved controls.');
    bv('close-assignment').click();
    macRule.effectiveIp = '';
    laptop.online = false;
    bv('refresh').click();
    await wait();
    const waitingLaptop = bv('device-list').querySelector('[aria-label="Edit Laptop"]').closest('tr');
    assert(waitingLaptop.textContent.includes('Waiting for DHCP') && waitingLaptop.cells[1].textContent.includes('10.0.0.32') &&
        waitingLaptop.cells[1].textContent.includes('Saved IP 10.0.0.31') &&
        waitingLaptop.cells[0].querySelector('.bv-offline')?.textContent === 'Offline',
        'An offline MAC rule retains the previous saved IP and the most recent observed lease.');
    reply.dashboard.devices = reply.dashboard.devices.filter(device => device !== laptop);
    bv('refresh').click();
    await wait();
    const offlineLaptop = bv('device-list').querySelector('[aria-label="Edit Laptop"]').closest('tr');
    assert(offlineLaptop.cells[0].querySelector('.bv-offline') && offlineLaptop.cells[1].textContent.includes('10.0.0.31') &&
        offlineLaptop.cells[1].textContent.includes('Saved IP'),
        'An undiscovered device must keep its saved rule and IPv4 address visible.');
    offlineLaptop.querySelector('[aria-label="Edit Laptop"]').click();
    assert(bv('ip').value === '10.0.0.31' && !bv('device-on-demand').disabled,
        'A MAC rule waiting for DHCP must remain editable.');
    bv('device-kill').checked = false;
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.id === 'mac-device' && x.data.bindMac &&
        x.data.ip === '10.0.0.31' && x.data.killSwitch === false && x.data.reserveIp === false),
        'Editing an offline MAC rule must save the existing rule without attempting to reserve an old address.');
    assert(bv('tailnet-devices').hidden && !bv('local-routing').hidden,
        'Local coverage shows the local policy and LAN devices.');
    bv('routing-scope').value = 'tailscale';
    bv('routing-scope').dispatchEvent(new Event('change'));
    assert(!bv('tailnet-devices').hidden && bv('lan-devices').hidden && bv('local-routing').hidden &&
        !bv('tailnet-coverage-panel').hidden && bv('tailnet-count').textContent.includes('1 online') &&
        bv('tailnet-snat-note').textContent.includes('Disable SNAT'),
        'Tailscale coverage shows only its own policy and peers.');
    bv('tailnet-coverage').value = 'network';
    bv('tailnet-network-mode').value = 'full_multi';
    bv('tailnet-network-profile').value = 'vpn1';
    bv('tailnet-network-mode').dispatchEvent(new Event('input', {bubbles:true}));
    assert(bv('tailnet-network-profile').required && !bv('tailnet-network-kill-field').hidden &&
        bv('tailnet-network-profile-label').textContent === 'Base server',
        'Combined Tailscale coverage requires its own base server.');
    bv('tailnet-coverage-form').requestSubmit(bv('save-tailnet-routing'));
    await wait();
    assert(requests.some(x => x.action === 'tailnetRouting' && x.data.networkProfile === 'vpn1' &&
        !Object.hasOwn(x.data, 'interfaces')) && reply.dashboard.settings.coverage === 'device' &&
        reply.dashboard.settings.tailnetCoverage === 'network',
        'Saving Whole-Network Tailscale coverage must not change Local device coverage.');
    bv('tailnet-base-test').querySelector('button').click();
    await wait();
    const baseResult = bv('tailnet-base-test').querySelector('[data-test-result]');
    assert(requests.some(x => x.action === 'testTailnetBase') && baseResult.dataset.result === 'unverified' &&
        baseResult.textContent.includes('router HTTPS') && baseResult.textContent.includes('No completed connection'),
        'A successful Tailscale base probe with no observed peer traffic stays unverified.');
    bv('tailnet-coverage').value = 'device';
    bv('tailnet-coverage').dispatchEvent(new Event('input', {bubbles:true}));
    bv('tailnet-coverage-form').requestSubmit(bv('save-tailnet-routing'));
    await wait();
    bv('tailnet-device-list').querySelector('[aria-label="Select Remote iPad"]').click();
    assert(bv('ip').value === '100.101.102.104' && bv('ipv6').value === 'fd7a:115c:a1e0::104' &&
        bv('interface').value === 'opt2' && bv('device-kind').value === 'tailnet', 'Existing gateway link rules must remain available.');
    bv('close-assignment').click();
    reply.dashboard.settings.tailscaleInterfaces = [];
    reply.dashboard.settings.tailscaleSetup = {ready:false, disableSnat:true, reason:'Apply Tailscale settings from the LAN.'};
    bv('refresh').click();
    await wait();
    bv('tailnet-device-list').querySelector('[aria-label="Select Remote iPad"]').click();
    assert(bv('assignment-interface-field').hidden && bv('save-device').disabled &&
        bv('route-note').textContent.includes('Apply Tailscale settings'), 'Unconfigured exit node must give an actionable message.');
    bv('close-assignment').click();
    reply.dashboard.settings.tailscaleSetup = {ready:true, disableSnat:true, reason:''};
    bv('refresh').click();
    await wait();
    bv('tailnet-device-list').querySelector('[aria-label="Select Remote iPad"]').click();
    assert(bv('assignment-interface-field').hidden && !bv('interface').required &&
        bv('interface').value === 'tailscale0' && !bv('switch-now') &&
        bv('device-on-demand').disabled && bv('device-on-demand-field').hidden && bv('device-bind-mac-field').hidden,
        'Native peer rules must select the Tailscale interface automatically without a reconnect toggle.');
    bv('profile').value = 'vpn1';
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.kind === 'tailnet' && x.data.interface === 'tailscale0' &&
        x.data.ip === '100.101.102.104' && x.data.profile === 'vpn1' && x.data.onDemand === false &&
        !Object.hasOwn(x.data, 'bindMac') && !Object.hasOwn(x.data, 'switchNow')),
        'Selecting a native exit peer must submit both the interface and the chosen VPN server.');
    reply.dashboard.tailnetDevices[0].online = false;
    bv('refresh').click();
    await wait();
    const offlinePeer = bv('tailnet-device-list').querySelector('[aria-label="Edit Remote iPad"]').closest('tr');
    assert(offlinePeer.cells[0].querySelector('.bv-offline')?.textContent === 'Offline' &&
        offlinePeer.textContent.includes('Always on'),
        'An offline Tailscale device keeps its VPN ready.');
    offlinePeer.querySelector('[aria-label="Edit Remote iPad"]').click();
    assert(bv('device-on-demand').disabled && bv('device-on-demand-field').hidden,
        'Tailscale peer rules keep the VPN ready even while the peer is offline.');
    bv('close-assignment').click();
    reply.dashboard.settings.tailscaleSetup = {ready:false, disableSnat:true, reason:'Tailscale is disconnected.'};
    bv('refresh').click();
    await wait();
    bv('tailnet-device-list').querySelector('[aria-label="Edit Remote iPad"]').click();
    assert(!bv('save-device').disabled && bv('identity').textContent.includes('Changes are saved'),
        'An existing native Tailscale rule can be edited while the exit node is offline.');
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.id === 'tailnet1' && x.data.interface === 'tailscale0' &&
        x.data.ip === '100.101.102.104'),
        'An offline Tailscale edit preserves the identity of the previously verified rule.');
    reply.dashboard.settings.tailscaleSetup = {ready:true, disableSnat:true, reason:''};
    reply.dashboard.tailnetDevices = [];
    bv('refresh').click();
    await wait();
    assert(!bv('add-tailnet-peer').hidden && bv('native-snat-status').classList.contains('bv-setting-checked'),
        'A missing peer needs a manual IP fallback and a checked SNAT indicator.');
    bv('add-tailnet-peer').click();
    bv('ip').value = '100.101.102.104';
    bv('profile').value = 'vpn1';
    assert(bv('ipv6-field').hidden && !bv('ipv6').required && bv('assign-form').checkValidity(),
        'Manual native lookup only needs the Tailscale IPv4 address.');
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.kind === 'tailnet' &&
        x.data.ip === '100.101.102.104' && x.data.ipv6 === '' && x.data.profile === 'vpn1'),
        'A missing peer must be looked up by IPv4 when saving the chosen server.');
    const tailnetTable = bv('tailnet-device-list');
    const peerPing = tailnetTable.querySelector('[data-test-result="device:tailnet1"]').closest('td');
    assert(peerPing.dataset.label === 'Ping' && peerPing.querySelector('[role="status"]').textContent === '—',
        'The Tailscale row must reserve its Ping cell before a test.');
    tailnetTable.querySelector('[aria-label="Test Remote iPad"]').click();
    await wait();
    const latency = peerPing.querySelector('button');
    assert(latency.textContent === '22.4 ms' && !latency.hidden &&
        requests.some(x => x.action === 'testDeviceRoute' && x.data.id === 'tailnet1'),
        'Tailscale Test must update the existing Ping cell even without a completed peer connection.');
    latency.click();
    assert(bv('ping-dialog').open && bv('ping-dialog-detail').textContent.includes('No completed connection observed'),
        'Clicking the measured latency explains the separate peer traffic result.');
    bv('ping-dialog').close();
    tailnetTraffic = 'oneway';
    tailnetTable.querySelector('[aria-label="Test Remote iPad"]').click();
    await wait();
    latency.click();
    assert(bv('ping-dialog-detail').textContent.includes('OPNsense saw no reply') &&
        bv('ping-dialog-detail').textContent.includes('router HTTPS 22.4 ms'),
        'A router HTTPS success does not conceal unanswered TCP attempts from the peer.');
    bv('ping-dialog').close();
    tailnetTable.querySelector('[aria-label="Disable Remote iPad"]').click();
    await wait();
    assert(tailnetTable.textContent.includes('Disabled') && !tailnetTable.querySelector('[aria-label="Test Remote iPad"]') &&
        reply.dashboard.assignments.find(row => row.id === 'tailnet1').profile === 'vpn1',
        'Pausing a Tailscale rule must retain the server and hide Ping.');
    tailnetTable.querySelector('[aria-label="Enable Remote iPad"]').click();
    await wait();
    assert(tailnetTable.querySelector('[aria-label="Test Remote iPad"]') &&
        requests.some(x => x.action === 'setTailnetRuleEnabled' && x.data.id === 'tailnet1' && x.data.enabled),
        'Re-enabling a Tailscale rule restores the saved route and Ping.');
    tailnetTable.querySelector('[aria-label="Edit Remote iPad"]').click();
    bv('mode').value = 'full_multi';
    bv('mode').dispatchEvent(new Event('change'));
    assert(bv('profile').required && bv('profile-label').textContent === 'Base server' &&
        bv('device-kill').checked && bv('device-kill').disabled && bv('failure-field').hidden &&
        bv('route-note').textContent.includes('Bypass is unavailable while the Kill Switch is on.'),
        'Combined Tailscale rules must require a base server and prevent WAN fallback.');
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.kind === 'tailnet' && x.data.mode === 'full_multi' &&
        x.data.profile === 'vpn1' && x.data.failure === 'block' && x.data.killSwitch === true && x.data.onDemand === false) &&
        tailnetTable.querySelector('[aria-label="Test Remote iPad"]') && tailnetTable.textContent.includes('Base VPN + Multi-Path'),
        'A combined Tailscale rule must keep the base ready and retain its Ping test.');
    Object.assign(reply.dashboard.assignments[0], {mode:'full',profile:'vpn1'});
    bv('refresh').click();
    await wait();
    bv('device-list').querySelector('[aria-label="Test <b>Device rule</b>"]').click();
    await wait();
    assert(bv('device-list').querySelector('[data-test-result="device:device1"]').textContent.includes('22.4 ms') &&
        requests.some(x => x.action === 'testDeviceRoute' && x.data.id === 'device1'), 'LAN rules use the same Ping check.');
    const deviceRuleRow = bv('device-list').querySelector('[aria-label="Edit <b>Device rule</b>"]').closest('tr');
    bv('local').dispatchEvent(new Event('input', {bubbles:true}));
    assert(bv('device-list').contains(deviceRuleRow), 'Typing a draft local network must not rebuild device rows.');
    bv('device-list').querySelector('[aria-label="Edit <b>Device rule</b>"]').click();
    bv('device-kill').checked = false;
    bv('mode').value = 'full_multi';
    bv('mode').dispatchEvent(new Event('change'));
    assert(bv('device-kill').checked && bv('device-kill').disabled &&
        bv('route-note').textContent.includes('Public IPv6 is blocked for this interface'),
        'Combined LAN rule must enforce the Kill Switch and explain the interface-wide public IPv6 block.');
    bv('mode').value = 'full';
    bv('mode').dispatchEvent(new Event('change'));
    assert(!bv('device-kill').checked && !bv('device-kill').disabled, 'Switching away from combined mode should restore the draft preference.');
    bv('mode').value = 'multi';
    bv('mode').dispatchEvent(new Event('change'));
    bv('device-kill').click();
    assert(bv('route-note').textContent.includes('Other internet traffic is blocked.') &&
        bv('route-note').textContent.includes('its matching destinations are blocked'),
        'A checked Multi-Path device must explain that unmatched traffic and destinations on a failed route are blocked.');
    bv('device-kill').click();
    bv('mode').value = 'full_multi';
    bv('mode').dispatchEvent(new Event('change'));
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.kind === 'lan' && x.data.mode === 'full_multi' &&
        x.data.profile === 'vpn1' && x.data.failure === 'block' && x.data.killSwitch === true),
        'LAN rules need to submit the combined mode and enforced Kill Switch.');
    reply.dashboard.settings.killSwitchIpv6Interfaces = ['lan'];
    reply.dashboard.settings.killSwitchUnboundInterfaces = ['lan'];
    bv('refresh').click();
    await wait();
    assert(bv('current-routing').textContent.includes('Public IPv6 blocked on igc0') &&
        bv('current-routing').textContent.includes('until protected devices have confirmed IPv4 addresses') &&
        bv('device-list').textContent.includes('Internet is blocked on this interface until the protected device has a confirmed IPv4 address.'),
        'The dashboard must explain IPv6 coverage and the temporary IPv4 block for an unbound protected device.');
    delete reply.dashboard.settings.killSwitchIpv6Interfaces;
    delete reply.dashboard.settings.killSwitchUnboundInterfaces;
    bv('routing-scope').value = 'local';
    bv('routing-scope').dispatchEvent(new Event('change'));
    bv('coverage').value = 'network';
    bv('network-mode').value = 'full';
    bv('network-mode').dispatchEvent(new Event('input', {bubbles:true}));
    bv('network-profile').value = 'vpn1';
    bv('network-profile').dispatchEvent(new Event('input', {bubbles:true}));
    assert(!bv('network-kill-field').hidden && bv('network-kill').checked &&
        bv('network-kill-field').previousElementSibling.contains(bv('managed')),
        'Whole-Network coverage did not show Kill Switch below Interface.');
    assert(!bv('network-profile-field').hidden && bv('coverage-note').textContent.includes('Canada'),
        'network exit selection had no visible effect');
    reply.dashboard.profiles.push({id:'proxy1', name:'Chicago proxy', kind:'proxy', node:'proxy-1', interface:'tun200'});
    bv('refresh').click();
    await wait();
    bv('network-profile').value = 'proxy1';
    bv('network-profile').dispatchEvent(new Event('input', {bubbles:true}));
    settingsError = 'LAN needs a Static IPv4 address on the router.';
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(bv('message-detail').textContent === settingsError && !bv('message-title').hidden &&
        bv('message').dataset.kind === 'danger' && getComputedStyle(bv('message')).color === 'rgb(142, 39, 60)' &&
        parseFloat(getComputedStyle(bv('message')).borderLeftWidth) > 1, 'Day error style is unreadable');
    assert(bv('network-profile').value === 'proxy1' && reply.dashboard.settings.coverage === 'device',
        'Rejected proxy routing must retain the selection, report a readable error, and preserve saved routing.');
    bv('appearance').value = 'night';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(bv('message')).color === 'rgb(255, 211, 221)', 'Night error text lost contrast.');
    const dismiss = bv('message-dismiss');
    assert(!dismiss.hidden && dismiss.textContent === '×' && dismiss.getAttribute('aria-label') === 'Dismiss error',
        'Errors need a visible and labeled dismiss control.');
    dismiss.focus();
    dismiss.click();
    assert(bv('message').hidden && dismiss.hidden && bv('network-profile').value === 'proxy1' &&
        document.activeElement === document.querySelector('[data-bv-section="network"]'),
        'Dismissing the error must preserve the form and move focus to the current page.');
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(!bv('message').hidden && !dismiss.hidden && bv('message-detail').textContent === settingsError,
        'A later failure must reopen the error banner.');
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    settingsError = null;
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.coverage === 'network' &&
        x.data.networkMode === 'full' && x.data.networkProfile === 'proxy1' && x.data.networkKillSwitch === true) &&
        bv('add-device').hidden && reply.dashboard.settings.networkProfile === 'proxy1',
        'Whole-Network proxy coverage settings did not apply.');
    const networkAssign = reply.dashboard.assignments[0];
    assert(bv('device-list').textContent.includes('New console') &&
        bv('device-list').textContent.includes('Covered by network rule') &&
        bv('device-list').querySelector('[aria-label="Edit New console"]') &&
        bv('device-guide').textContent.includes('Only Devices I choose'),
        'Whole-Network coverage must let users edit discovered devices and explain individual assignments.');
    assert(!bv('device-list').querySelector('[aria-label^="Bypass VPN"]') &&
        bv('coverage-note').textContent.includes('Bypass is unavailable while the Kill Switch is on.'),
        'Checked Whole-Network Kill Switch must prevent bypass selection and explain it.');
    bv('network-kill').click();
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    bv('device-list').querySelector('[aria-label="Edit <b>Device rule</b>"]').click();
    assert(!bv('network-device').hidden && !bv('network-device-bypass-field').hidden && bv('assignment').hidden,
        'Editing a Whole-Network device must offer Bypass without changing its individual rule.');
    bv('network-device-name').value = 'Renamed LAN device';
    bv('network-device-form').requestSubmit(bv('save-network-device'));
    await wait();
    assert(networkAssign.label === 'Renamed LAN device' && networkAssign.mode === 'full' && networkAssign.profile === 'vpn1' &&
        bv('device-list').querySelector('[aria-label="Edit Renamed LAN device"]'),
        'A Whole-Network name edit must preserve the saved mode and server.');
    bv('device-list').querySelector('[aria-label="Bypass VPN for Renamed LAN device"]').click();
    await wait();
    assert(networkAssign.networkBypass === true && bv('device-list').textContent.includes('Direct internet'),
        'A saved device can bypass Whole-Network coverage from its row and show a confirmed direct route.');
    networkAssign.networkBypassStatus = 'guard';
    bv('refresh').click();
    await wait();
    assert(bv('device-list').textContent.includes('Direct internet unavailable'),
        'A loaded guard must show the direct route unavailable.');
    bv('device-list').querySelector('[aria-label="Bypass VPN for New console"]').click();
    assert(bv('network-device-bypass').checked && bv('network-device-note').textContent.includes('DHCP address'),
        'A new device bypass must identify its DHCP reservation before saving.');
    bv('network-device-form').requestSubmit(bv('save-network-device'));
    await wait();
    assert(requests.some(x => x.action === 'setNetworkDevice' && x.data.label === 'New console' &&
        x.data.ip === '10.0.0.30' && x.data.reserveIp === true && x.data.networkBypass === true),
        'Saving a new device bypass must store the current identity and exception.');
    bv('network-kill').click();
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(networkAssign.networkBypass === true && bv('device-list').textContent.includes('Bypass paused by Kill Switch') &&
        bv('device-list').querySelector('[aria-label="Use network rule for Renamed LAN device"]'),
        'Checking the Kill Switch must pause existing bypass preferences while still allowing removal.');
    reply.dashboard.settings.networkRouting = {lan:{gateway:'wg1',outage:true}};
    bv('refresh').click();
    await wait();
    assert(bv('current-routing').textContent.includes('Kill Switch blocking internet') &&
        bv('device-list').textContent.includes('Kill Switch blocking internet'),
        'Reported Whole-Network outage must override stale base and bypass statuses.');
    delete reply.dashboard.settings.networkRouting;
    bv('network-kill').click();
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    bv('routing-scope').value = 'tailscale';
    bv('routing-scope').dispatchEvent(new Event('change'));
    bv('tailnet-coverage').value = 'network';
    bv('tailnet-coverage').dispatchEvent(new Event('input', {bubbles:true}));
    assert(!bv('tailnet-device-list').querySelector('[aria-label^="Bypass VPN"]'),
        'Tailscale peers use the independently saved network policy.');
    bv('tailnet-device-list').querySelector('[aria-label="Edit Remote iPad"]').click();
    assert(bv('network-device-bypass-field').hidden,
        'A saved Tailscale device name must be editable without a Whole-Network bypass control.');
    bv('network-device-name').value = 'Renamed iPad';
    bv('network-device-form').requestSubmit(bv('save-network-device'));
    await wait();
    assert(requests.some(x => x.action === 'setNetworkDevice' && x.data.id === 'tailnet1' &&
        x.data.label === 'Renamed iPad' && x.data.networkBypass === undefined) &&
        reply.dashboard.assignments.find(row => row.id === 'tailnet1').mode === 'full_multi',
        'Renaming a Tailscale peer must preserve its routing without submitting a bypass field.');
    bv('tailnet-coverage').value = 'device';
    bv('tailnet-coverage').dispatchEvent(new Event('input', {bubbles:true}));
    bv('routing-scope').value = 'local';
    bv('routing-scope').dispatchEvent(new Event('change'));
    bv('coverage').value = 'device';
    bv('coverage').dispatchEvent(new Event('input', {bubbles:true}));
    assert(!bv('device-list').querySelector('[aria-label^="Bypass VPN"], [aria-label^="Use network rule"]'),
        'Only Devices I choose must hide Whole-Network bypass controls.');
    assert(bv('device-list').querySelector('[aria-label="Edit New console"]').closest('tr').textContent.includes('No individual rule'),
        'A device saved for Whole-Network coverage alone must stay unassigned in individual coverage.');
    bv('device-list').querySelector('[aria-label="Edit Renamed LAN device"]').click();
    assert(!bv('assignment').hidden && bv('network-device').hidden && bv('profile').value === 'vpn1',
        'Only Devices I choose must still show the saved individual assignment.');
    bv('close-assignment').click();
    bv('coverage').value = 'network';
    bv('coverage').dispatchEvent(new Event('input', {bubbles:true}));
    bv('device-list').querySelector('[aria-label="Use network rule for Renamed LAN device"]').click();
    await wait();
    assert(networkAssign.networkBypass === false && networkAssign.mode === 'full' &&
        bv('device-list').querySelector('[aria-label="Bypass VPN for Renamed LAN device"]'),
        'Removing a Whole-Network bypass must preserve the individual rule.');
    assert(dismiss.hidden, 'Success messages must hide the error dismiss control.');
    bv('network-kill').click();
    bv('network-mode').value = 'full_multi';
    bv('network-mode').dispatchEvent(new Event('input', {bubbles:true}));
    bv('network-profile').value = '';
    assert(bv('network-profile').required && !bv('network-profile').checkValidity() &&
        bv('network-profile-label').textContent === 'Base server' && bv('network-kill').checked && !bv('network-kill').disabled,
        'Combined network mode must require a base server and allow toggling the Kill Switch.');
    bv('network-profile').value = 'proxy1';
    bv('network-profile').dispatchEvent(new Event('input', {bubbles:true}));
    assert(bv('coverage-note').textContent.includes('Default traffic uses Chicago proxy') &&
        bv('coverage-note').textContent.includes('Matching destinations use their Multi-Path servers.'),
        'Combined network mode must describe both the base server and the domain overrides.');
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.coverage === 'network' &&
        x.data.networkMode === 'full_multi' && x.data.networkProfile === 'proxy1' && x.data.networkKillSwitch === true) &&
        bv('current-routing').textContent.includes('Whole-Network + Multi-Path'),
        'Whole-Network + Multi-Path settings did not apply.');
    bv('network-kill').click();
    assert(!bv('network-kill').checked && bv('coverage-note').textContent.includes('uses direct internet if it goes offline'),
        'The draft must explain direct fallback with Kill Switch off.');
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    bv('refresh').click();
    await wait();
    assert(!bv('network-kill').checked && !bv('network-kill').disabled &&
        reply.dashboard.settings.networkKillSwitch === false && bv('current-routing').textContent.includes('Kill Switch off'),
        'Combined network coverage must submit and reload the saved Kill Switch off state.');
    bv('network-kill').click();
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(bv('network-kill').checked && reply.dashboard.settings.networkKillSwitch === true &&
        bv('current-routing').textContent.includes('Kill Switch on'),
        'Combined network coverage must allow turning the Kill Switch back on.');
    reply.dashboard.settings.networkRouting = {lan:{gateway:'tun200', outage:false, statusKnown:true, blockedServices:1}};
    const renderedService = bv('service-list').firstElementChild;
    reply.dashboard.services.push({id:'youtube-demo', name:'YouTube', domains:['youtube.com','googlevideo.com'],
        profile:'vpn1', routing:{lan:{gateway:'wg1'}}},
    {id:'unavailable-demo', name:'Unavailable route', domains:['example.net'], profile:'vpn1',
        routing:{lan:{guard:true, gateway:null}}});
    bv('refresh').click();
    await wait();
    const effectiveRow = bv('device-list').querySelector('[aria-label="Edit Renamed LAN device"]').closest('tr');
    assert(bv('current-routing').textContent.includes('Chicago proxy · 1 Multi-Path list blocked') &&
        bv('coverage-note').textContent.includes('only its destinations are blocked') &&
        effectiveRow.cells[3].textContent.includes('Configured server · Chicago proxy') &&
        !effectiveRow.cells[3].textContent.includes('On Demand') &&
        !bv('current-routing').textContent.includes('Kill Switch blocking internet'),
        'A healthy base stays visible and the device row must show the effective network policy while an override is blocked.');
    assert(bv('service-list').firstElementChild === renderedService &&
        !bv('service-list').textContent.includes('YouTube'), 'Refresh must defer rendering the hidden Multi-Path panel.');
    document.querySelector('[data-bv-section="smart"]').click();
    assert(bv('service-scope').value === 'local',
        'Multi-Path offers independent list coverage.');
    const youtubeRow = [...bv('service-list').rows].find(row => row.cells[0].textContent.includes('YouTube'));
    youtubeRow.querySelector('[aria-label="Test route for YouTube"]').click();
    await wait();
    assert(requests.some(x => x.action === 'testServiceRoute' && x.data.id === 'youtube-demo') &&
        bv('service-test-dialog').open && bv('service-test-detail').textContent.includes('www.youtube.com') &&
        bv('service-test-detail').textContent.includes('DNS and firewall match New York'),
        'The Multi-Path test reports its hostname and result without changing the service row layout.');
    bv('service-test-dialog').close();
    const downRow = [...bv('service-list').rows].find(row => row.cells[0].textContent.includes('Unavailable route'));
    assert(downRow.cells[2].textContent.includes('Selected server unavailable · Matching traffic blocked') &&
        !youtubeRow.cells[2].textContent.includes('Matching traffic blocked'),
        'A failed override should only change the status for its matching service.');
    downRow.querySelector('[aria-label="Test route for Unavailable route"]').click();
    await wait();
    assert(bv('service-test-detail').textContent.includes('Selected server unavailable. Matching traffic is blocked'),
        'The route test should display service-specific blocking.');
    bv('service-test-dialog').close();
    reply.dashboard.settings.networkRouting.lan = {gateway:null, outage:true, statusKnown:true, blockedServices:0};
    bv('refresh').click();
    await wait();
    assert(bv('current-routing').textContent.includes('Base server unavailable · Default traffic blocked') &&
        [...bv('service-list').rows].find(row => row.cells[0].textContent.includes('YouTube')).cells[2].textContent
            .includes('Canada'),
        'The base outage must be shown independently of the healthy override.');
    delete reply.dashboard.settings.networkRouting;
    reply.dashboard.services = reply.dashboard.services.filter(service => !['youtube-demo', 'unavailable-demo'].includes(service.id));
    reply.dashboard.services.push({id:'bypass-demo', name:'Direct test', domains:['example.net'], profile:'bypass', scope:'local',
        routing:{}});
    bv('refresh').click();
    await wait();
    const directServiceRow = () => [...bv('service-list').rows].find(row => row.cells[0].textContent.includes('Direct test'));
    assert(directServiceRow().cells[2].textContent.includes('Bypass paused by Kill Switch'),
        'A saved Bypass row must show the Kill Switch is preventing direct internet.');
    reply.dashboard.settings.networkKillSwitch = false;
    reply.dashboard.services.at(-1).routing = {lan:{bypass:true}, opt1:{bypass:false, guard:true}};
    bv('refresh').click();
    await wait();
    const directRow = directServiceRow();
    assert(directRow.cells[2].textContent.includes('Direct internet') &&
        directRow.cells[2].textContent.includes('Direct internet unavailable'),
        'Bypass status must distinguish a direct route from an unavailable direct gateway.');
    reply.dashboard.settings.networkMode = 'blocked';
    delete reply.dashboard.services.at(-1).routing;
    bv('refresh').click();
    await wait();
    assert(directServiceRow().cells[2].textContent.includes('Internet blocked'),
        'Bypass must disclose an explicit Whole-Network block.');
    reply.dashboard.settings.networkMode = 'full_multi';
    reply.dashboard.settings.networkKillSwitch = true;
    reply.dashboard.services.pop();
    bv('refresh').click();
    await wait();
    document.querySelector('[data-bv-section="network"]').click();
    assert(bv('disable-routing').parentElement.contains(bv('local-routing-title')) &&
        getComputedStyle(bv('disable-routing')).backgroundColor === 'rgb(177, 40, 60)',
        'Disable Local routing must be red in the Local routing header.');
    bv('disable-routing').click();
    await wait();
    assert(requests.some(x => x.action === 'disable') && bv('routing-enabled').hidden &&
        !bv('save-routing').classList.contains('bv-enabled') && bv('network-kill').checked &&
        reply.dashboard.settings.tailnetEnabled === true,
        'Disabling VPN did not preserve the saved kill switch and clear the green state.');
    document.querySelector('[data-bv-section="vpns"]').click();
    bv('country').value = '';
    bv('country').dispatchEvent(new Event('change'));
    bv('refresh-relays').click();
    await wait();
    assert(bv('relay').options[1].value === 'ca-test-wg-003', 'cached relay lost after refresh error');
    assert(bv('relay-status').textContent.includes('Provider unavailable'), 'stale catalog warning omitted');
    bv('provider').value = 'pia';
    bv('provider').dispatchEvent(new Event('change'));
    assert(!bv('mullvad-provider').hidden && bv('provider-panel').hidden, 'Provider switched before Apply.');
    bv('provider-picker').requestSubmit();
    assert(bv('mullvad-provider').hidden && !bv('provider-login').hidden &&
        bv('provider-title').textContent === 'Private Internet Access', 'Apply did not show the chosen provider login.');
    bv('provider-user').value = 'p12345';
    bv('provider-secret').value = 'fixture-password';
    bv('provider-login').querySelector('button').click();
    await wait();
    assert(reply.dashboard.providerAccounts.pia && !bv('provider-server-form').hidden &&
        bv('provider-secret').value === '' && bv('provider-server').options.length === 2,
        'Provider sign-in must be saved, clear the password and load the catalog.');
    bv('provider-server').value = 'chicago';
    bv('provider-server').dispatchEvent(new Event('change'));
    bv('provider-name').value = 'A Chicago server';
    assert(bv('provider-save').textContent === 'Add server', 'Other providers must offer Add server.');
    bv('provider-save').click();
    await wait();
    assert(requests.some(x => x.action === 'addProviderExit' && x.data.provider === 'pia' && x.data.server === 'chicago'),
        'Add server did not use the selected provider server.');
    bv('provider').value = 'azire';
    bv('provider-picker').requestSubmit();
    await wait();
    assert(!bv('provider-logout').hidden && reply.dashboard.providerAccounts.pia,
        'Selecting another service must preserve earlier logins.');
    bv('provider-logout').click();
    await wait();
    assert(!reply.dashboard.providerAccounts.azire && reply.dashboard.providerAccounts.pia &&
        reply.dashboard.mullvadSignedIn, 'Signing out must affect only the selected account.');
    const groups = [...bv('network-profile').querySelectorAll('optgroup')].map(x => x.label);
    assert(groups.includes('Mullvad') && groups.includes('Private Internet Access') &&
        groups.indexOf('Mullvad') < groups.indexOf('Private Internet Access') &&
        [...bv('network-profile').options].some(x => x.value === 'pia1'), 'Routing choices must group by VPN service.');
    bv('provider').value = 'mysterium';
    bv('provider-picker').requestSubmit();
    assert(!bv('myst-login').hidden && bv('provider-login').hidden, 'Mysterium must use browser approval.');
    bv('myst-begin').click();
    await wait();
    assert(!bv('myst-approve').hidden && bv('myst-approve').href.startsWith('https://app.mysteriumvpn.com/'),
        'Missing Mysterium approval link.');
    bv('myst-poll').click();
    await wait();
    bv('provider-server').value = 'myst-loc';
    bv('provider-server').dispatchEvent(new Event('change'));
    bv('provider-name').value = 'Mysterium New York';
    bv('provider-save').click();
    await wait();
    assert(requests.some(x => x.action === 'addMystExit' && x.data.server === 'myst-loc' && x.data.ipType === 'hosting') &&
        bv('profile-list').textContent.includes('Mysterium New York'), 'Mysterium location did not reach the saved tunnel list.');
    bv('provider').value = 'ivpn';
    bv('provider-picker').requestSubmit();
    assert(!bv('ivpn-login').hidden && bv('provider-login').hidden, 'IVPN account login did not open.');
    bv('ivpn-account').value = 'i-ABCD-EFGH-IJKL';
    bv('ivpn-login').querySelector('button').click();
    await wait();
    assert(!bv('ivpn-confirmation-field').hidden && bv('ivpn-confirmation').required, 'IVPN confirmation field missing.');
    assert(bv('ivpn-account').value === '' && !bv('ivpn-account').required, 'IVPN account ID must not remain visible.');
    bv('ivpn-confirmation').value = '123456';
    bv('ivpn-login').querySelector('button').click();
    await wait();
    bv('provider-server').value = 'ivpn-loc';
    bv('provider-server').dispatchEvent(new Event('change'));
    bv('provider-name').value = 'IVPN Toronto';
    bv('provider-save').click();
    await wait();
    assert(requests.some(x => x.action === 'addIvpnExit' && x.data.server === 'ivpn-loc') &&
        bv('profile-list').textContent.includes('IVPN Toronto'), 'IVPN server did not reach the saved tunnel list.');
    const nordNode = 'b'.repeat(64);
    reply.dashboard.profiles.push({id:'proxy-' + nordNode, node:nordNode, kind:'proxy', provider:'nord',
        providerLocation:'jp100.nordvpn.com', providerServer:'Japan', name:'Nord Japan'});
    bv('refresh').click();
    await wait();
    assert(bv('profile-list').textContent.includes('Nord Japan') &&
        [...bv('network-profile').querySelectorAll('optgroup')].some(group =>
            group.label === 'NordVPN' && group.querySelector('option').value === 'proxy-' + nordNode),
        'A userspace Nord tunnel must appear in both VPN Login and the NordVPN routing group.');
    document.querySelector('[data-bv-section="network"]').click();
    bv('routing-scope').value = 'tailscale';
    bv('routing-scope').dispatchEvent(new Event('change'));
    bv('add-tailnet-peer').click();
    assert([...bv('profile').options].some(option => option.value === 'mysterium1') &&
        [...bv('profile').options].some(option => option.value === 'ivpn1') &&
        [...bv('profile').options].some(option => option.value === 'proxy-' + nordNode),
        'Provider tunnels must be available to a Tailscale device.');
    bv('close-assignment').click();
    assert(document.documentElement.scrollWidth <= window.innerWidth, 'document has horizontal overflow');
    document.querySelector('[data-bv-section="network"]').click();
    bv('routing-scope').value = 'local';
    bv('routing-scope').dispatchEvent(new Event('change'));
    const expected = window.innerWidth < 768 ? 'block' : 'table';
    assert(getComputedStyle(bv('device-list').closest('table')).display === expected, 'incorrect device layout for viewport');
    const system = document.querySelector('[data-bv-section="system"]');
    assert(system.textContent === 'System Settings' && !requests.some(x => x.controller === 'update'),
        'System Settings must be visible and update status must wait until the page is opened.');
    system.click();
    assert(!bv('system-page').hidden && bv('network-page').hidden && bv('appearance').labels[0].textContent.includes('Appearance') &&
        bv('system-updates').hidden && bv('system-backups').hidden && system.getAttribute('aria-pressed') === 'true',
        'The System tab must preserve appearance controls and hide unprivileged update and backup controls.');
    bv('appearance').value = 'night';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(localStorage.getItem('blankvpn-appearance') === 'night' &&
        getComputedStyle(document.getElementById('blankvpn')).colorScheme === 'dark',
        'Changing appearance in System Settings must apply and persist the theme.');
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    reply.dashboard.canManageUpdates = true;
    reply.dashboard.canWriteUpdates = true;
    reply.dashboard.canManageBackups = true;
    bv('refresh').click();
    await wait();
    assert(!bv('system-updates').hidden && !bv('system-backups').hidden,
        'System update and backup privileges must expose their separate sections.');
    system.click();
    await wait();
    assert(requests.some(x => x.controller === 'update' && x.action === 'status' && x.method === 'GET') &&
        !requests.some(x => x.controller === 'update' && x.method === 'POST') &&
        bv('update-check').textContent === 'Check for update' && !bv('update-check').hidden &&
        !bv('update-check').disabled && bv('update-apply').textContent === 'Update' &&
        !bv('update-apply').hidden && bv('update-apply').disabled &&
        bv('update-status').textContent.includes('Installed 0.1.39'),
        'The update page must report its installed release and offer check and update without a separate enable step.');
    const nativeTimeout = window.setTimeout;
    window.setTimeout = (callback, milliseconds, ...args) => nativeTimeout(callback,
        milliseconds === 4000 ? 50 : milliseconds, ...args);
    try {
        bv('update-check').click();
        assert(bv('update-check').disabled && bv('update-apply').disabled &&
            bv('update-status').textContent.includes('Checking for an update'), 'Check must show when it is in progress.');
        await wait();
        assert(requests.some(x => x.controller === 'update' && x.action === 'check' && x.method === 'POST') &&
            bv('update-status').textContent.includes('Available 0.1.40') && !bv('update-apply').disabled,
            'Checking for an update must reveal the available version and enable the Update button.');
        bv('update-apply').click();
        await wait();
        assert(requests.some(x => x.controller === 'update' && x.action === 'apply' && x.method === 'POST' &&
                x.data.version === '0.1.40') && bv('update-apply').disabled && bv('update-check').disabled &&
            bv('update-status').textContent.includes('Installing package'), 'Apply must request only the displayed version.');
        await new Promise(resolve => nativeTimeout(resolve, 150));
        assert(updatePolls === 2 && bv('update-status').textContent.includes('Installed 0.1.40') &&
            bv('message-detail').textContent === 'Update installed.' && !bv('update-check').disabled &&
            bv('update-apply').disabled,
            'Update completion must refresh the installed version and restore check availability.');
    } finally {
        window.setTimeout = nativeTimeout;
    }
    let backupDownload = '';
    let downloadedBlob;
    const nativeCreateObjectURL = URL.createObjectURL;
    const nativeClick = HTMLAnchorElement.prototype.click;
    try {
        URL.createObjectURL = function (blob) {
            downloadedBlob = blob;
            return nativeCreateObjectURL.call(this, blob);
        };
        HTMLAnchorElement.prototype.click = function () { backupDownload = this.download; };
        bv('backup-download').click();
        await wait();
    } finally {
        URL.createObjectURL = nativeCreateObjectURL;
        HTMLAnchorElement.prototype.click = nativeClick;
    }
    assert(requests.some(x => x.controller === 'backup' && x.action === 'export' && x.method === 'POST') &&
        backupDownload === 'blank-vpn-routing-settings.json' && downloadedBlob?.type === 'application/json',
        'Authorized backup export must download a JSON file.');
    const backupFile = bv('backup-file');
    const backupText = JSON.stringify(routingBackup);
    const selectBackup = (name) => {
        const clipboard = new DataTransfer();
        clipboard.items.add(new File([backupText], name, {type:'application/json'}));
        backupFile.files = clipboard.files;
        backupFile.dispatchEvent(new Event('change'));
    };
    reply.dashboard.settings.enabled = true;
    bv('refresh').click();
    await wait();
    selectBackup('routing-backup.json');
    assert(bv('backup-check').disabled && bv('backup-restore').disabled &&
        bv('backup-preview').textContent.includes('Disable VPN routing'),
        'The restore workflow must require disabled routing.');
    reply.dashboard.settings.enabled = false;
    bv('refresh').click();
    await wait();
    assert(!bv('backup-check').disabled && bv('backup-restore').disabled,
        'A new backup must be previewed before restoration.');
    const readBackup = File.prototype.text;
    File.prototype.text = async () => backupText;
    try {
        bv('backup-check').click();
        await wait();
        assert(requests.some(x => x.controller === 'backup' && x.action === 'preview' && x.method === 'POST' &&
            x.data.backup === backupText) && !bv('backup-restore').disabled &&
            bv('backup-preview').textContent.includes('replacing 2 rules and 1 lists'),
            'A preview must show the replacement counts and enable the confirmed restore.');
        selectBackup('new-backup.json');
        assert(bv('backup-restore').disabled, 'Selecting another file must invalidate the preview.');
        bv('backup-check').click();
        await wait();
        bv('backup-restore').click();
        await wait();
    } finally {
        File.prototype.text = readBackup;
    }
    assert(requests.some(x => x.controller === 'backup' && x.action === 'restore' && x.method === 'POST' &&
            x.data.backup === backupText && x.data.confirmation === 'fixture-confirmation') &&
        backupFile.files.length === 0 && bv('backup-restore').disabled && reply.dashboard.settings.enabled === false,
        'Restore must send the reviewed backup and confirmation, clear the file and leave routing off.');
    // Exercise list selection independently of the routing scenarios above.
    const savedDashboard = structuredClone(reply.dashboard);
    const savedCatalog = structuredClone(reply.proxyCatalog);
    const selectionInput = (kind, id) => document.querySelector('[data-server-selection="' + kind + '"][value="' + id + '"]');
    const bulkRequests = (action) => requests.filter(request => request.action === action);
    const refreshLists = async (catalog = false) => {
        bv('refresh').click();
        await wait();
        if (catalog) {
            buttonByText('subscription-list', 'Refresh').click();
            await wait();
        }
    };
    const nordBulkId = 'nord-bulk-node';
    reply.dashboard.profiles = [
        {id:'bulk-vpn-a', name:'Alpha VPN', relay:'alpha-wg-001', port:53, interface:'wg1'},
        {id:'bulk-vpn-b', name:'Beta VPN', relay:'beta-wg-001', port:51820, interface:'wg2'},
        {id:'bulk-vpn-held', name:'Protected VPN', relay:'held-wg-001', port:51820, interface:'wg3'},
        {id:'proxy-' + nordBulkId, name:'Nord bulk VPN', kind:'proxy', provider:'nord', node:nordBulkId, port:443},
        {id:'proxy-held', name:'Protected proxy', kind:'proxy', node:'bulk-proxy-held', interface:'tun200'}
    ];
    reply.dashboard.assignments = [{id:'held-assignment', mode:'full', profile:'bulk-vpn-held'},
        {id:'held-proxy-assignment', mode:'full', profile:'proxy-held'}];
    reply.dashboard.services = [];
    Object.assign(reply.dashboard.settings, {networkProfile:'', tailnetNetworkProfile:'', coverage:'device',
        tailnetCoverage:'device', enabled:false, tailnetEnabled:false});
    reply.proxyCatalog.nodes = [
        {id:'bulk-proxy-held', name:'Protected proxy', serverName:'Held original', host:'192.0.2.7', port:443, protocol:'trojan', core:'mihomo'},
        ...Array.from({length:56}, (_, index) => ({id:'bulk-proxy-' + index, name:'Proxy ' + String(index).padStart(2, '0'),
            serverName:'Imported ' + index, host:'192.0.2.6', port:443, protocol:'trojan', core:'mihomo'})),
        {id:nordBulkId, name:'Nord bulk VPN', provider:'nord', host:'jp100.nordvpn.com', port:443, protocol:'wireguard', core:'sing-box'}
    ];
    await refreshLists(true);
    document.querySelector('[data-bv-section="vpns"]').click();
    assert(bv('vpn-remove-selected').disabled && !bv('vpn-select-all').checked &&
        selectionInput('vpn', 'bulk-vpn-held').disabled && !selectionInput('vpn', 'bulk-vpn-a').disabled &&
        selectionInput('vpn', 'bulk-vpn-a').closest('td').cellIndex === 0,
        'VPN selection must start empty in the far-left column and protect assigned profiles.');
    selectionInput('vpn', 'bulk-vpn-a').click();
    assert(bv('vpn-select-all').indeterminate && !bv('vpn-remove-selected').disabled &&
        bulkRequests('removeProfiles').length === 0, 'Selecting VPNs must not remove anything and must set the partial header state.');
    await refreshLists();
    assert(selectionInput('vpn', 'bulk-vpn-a').checked && bv('vpn-select-all').indeterminate,
        'VPN selection must survive a dashboard refresh by profile identity.');
    reply.dashboard.settings.tailnetNetworkProfile = 'bulk-vpn-a';
    await refreshLists();
    assert(selectionInput('vpn', 'bulk-vpn-a').disabled && !selectionInput('vpn', 'bulk-vpn-a').checked &&
        bv('vpn-remove-selected').disabled, 'A newly assigned Tailscale base must be protected and removed from the pending selection.');
    reply.dashboard.settings.tailnetNetworkProfile = '';
    await refreshLists();
    selectionInput('vpn', 'bulk-vpn-a').click();
    selectionInput('vpn', 'bulk-vpn-b').click();
    assert(bv('vpn-selected-count').textContent.includes('2'), 'The VPN selected count must track individual checks.');
    let bulkConfirmation = '';
    window.confirm = (message) => { bulkConfirmation = message; return false; };
    bv('vpn-remove-selected').click();
    await wait();
    assert(bulkConfirmation.includes('2') && bulkRequests('removeProfiles').length === 0 &&
        selectionInput('vpn', 'bulk-vpn-a').checked, 'Cancelling VPN bulk removal must keep both records and selection.');
    window.confirm = () => true;
    bulkRemoveError = 'The selected VPN is now assigned. Remove it from routing policies first.';
    bv('vpn-remove-selected').click();
    await wait();
    assert(reply.dashboard.profiles.some(profile => profile.id === 'bulk-vpn-a') &&
        selectionInput('vpn', 'bulk-vpn-a').checked && !bv('vpn-remove-selected').disabled &&
        bv('message-detail').textContent.includes('now assigned'),
        'A failed VPN bulk removal must retain its selection and report the backend error.');
    bulkRemoveError = null;
    bv('vpn-remove-selected').click();
    await wait();
    const vpnBatch = bulkRequests('removeProfiles').at(-1);
    const vpnSelected = JSON.parse(vpnBatch.data.selection);
    assert(vpnBatch.method === 'POST' && vpnSelected.profiles.sort().join(',') === 'bulk-vpn-a,bulk-vpn-b' &&
        vpnSelected.nodes.length === 0 && !selectionInput('vpn', 'bulk-vpn-a') && !selectionInput('vpn', 'bulk-vpn-b') &&
        selectionInput('vpn', 'bulk-vpn-held').disabled && bv('vpn-remove-selected').disabled,
        'One VPN batch request must remove only the checked profiles and clear its selection after success.');
    bv('vpn-select-all').click();
    assert(bv('vpn-select-all').checked && !bv('vpn-select-all').indeterminate &&
        selectionInput('vpn', 'proxy-' + nordBulkId).checked && !selectionInput('vpn', 'bulk-vpn-held').checked,
        'Select all VPNs must include managed Nord profiles and exclude assigned profiles.');
    bv('vpn-remove-selected').click();
    await wait();
    const nordBatch = JSON.parse(bulkRequests('removeProfiles').at(-1).data.selection);
    assert(nordBatch.profiles.length === 0 && nordBatch.nodes.join(',') === nordBulkId &&
        bv('vpn-select-all').disabled && bv('vpn-remove-selected').disabled,
        'Managed Nord bulk removal must send its node identity and leave assigned VPNs intact.');
    reply.dashboard.assignments = reply.dashboard.assignments.filter(assignment => assignment.id !== 'held-assignment');
    await refreshLists();
    bv('vpn-select-all').click();
    bv('vpn-remove-selected').click();
    await wait();
    assert(bv('profile-list').textContent.includes('No VPN servers') && bv('vpn-select-all').disabled &&
        !bv('vpn-select-all').checked && !bv('vpn-select-all').indeterminate && bv('vpn-remove-selected').disabled &&
        bv('profile-list').rows[0].cells[0].colSpan === 7,
        'Removing every eligible VPN must produce a correctly spanned empty list and reset all selection controls.');
    document.querySelector('[data-bv-section="proxies"]').click();
    assert(bv('proxy-count').textContent.includes('1–50 of 57') && selectionInput('proxy', 'bulk-proxy-held').disabled,
        'Proxy pagination must exclude managed VPN nodes and protect the active proxy.');
    selectionInput('proxy', 'bulk-proxy-0').click();
    assert(bv('proxy-select-all').indeterminate && bulkRequests('removeProxyNodes').length === 0,
        'Proxy selection must set the partial header without removing a server.');
    bv('proxy-next').click();
    selectionInput('proxy', 'bulk-proxy-55').click();
    assert(bv('proxy-selected-count').textContent.includes('2'), 'Proxy selected count must span both pages.');
    bv('proxy-prev').click();
    assert(selectionInput('proxy', 'bulk-proxy-0').checked, 'Changing proxy pages must preserve selected node identities.');
    await refreshLists(true);
    assert(selectionInput('proxy', 'bulk-proxy-0').checked && bv('proxy-selected-count').textContent.includes('2'),
        'Proxy selections must survive a catalog reload.');
    bv('proxy-select-all').click();
    assert(bv('proxy-select-all').checked && !bv('proxy-select-all').indeterminate &&
        bv('proxy-selected-count').textContent.includes('56') && !selectionInput('proxy', 'bulk-proxy-held').checked,
        'Proxy select all must select every removable server across pages and exclude protected servers.');
    bv('proxy-next').click();
    assert(selectionInput('proxy', 'bulk-proxy-55').checked, 'Select all must include proxy nodes outside the current page.');
    window.confirm = (message) => { bulkConfirmation = message; return false; };
    bv('proxy-remove-selected').click();
    await wait();
    assert(bulkConfirmation.includes('56') && bulkRequests('removeProxyNodes').length === 0 &&
        selectionInput('proxy', 'bulk-proxy-55').checked,
        'Cancelling proxy bulk removal must leave the full catalog and selection intact.');
    window.confirm = () => true;
    bulkRemoveError = 'A selected proxy is in use. Refresh its routing policies.';
    bv('proxy-remove-selected').click();
    await wait();
    assert(reply.proxyCatalog.nodes.length === 57 && selectionInput('proxy', 'bulk-proxy-55').checked &&
        !bv('proxy-remove-selected').disabled && bv('message-detail').textContent.includes('in use'),
        'A failed proxy batch must preserve selection and show the returned error.');
    bulkRemoveError = null;
    bv('proxy-remove-selected').click();
    await wait();
    const proxyBatch = bulkRequests('removeProxyNodes').at(-1);
    const proxySelected = JSON.parse(proxyBatch.data.selection);
    assert(proxyBatch.method === 'POST' && proxySelected.length === 56 && new Set(proxySelected).size === 56 &&
        proxySelected.includes('bulk-proxy-55') && !proxySelected.includes('bulk-proxy-held') &&
        reply.proxyCatalog.nodes.length === 1 && bv('proxy-pages').hidden && bv('proxy-select-all').disabled &&
        bv('proxy-remove-selected').disabled && selectionInput('proxy', 'bulk-proxy-held').disabled,
        'A single proxy batch must remove selections from every page, preserve assigned servers, and reset pagination.');
    reply.dashboard.profiles = [];
    reply.dashboard.assignments = [];
    await refreshLists();
    bv('proxy-select-all').click();
    bv('proxy-remove-selected').click();
    await wait();
    assert(reply.proxyCatalog.nodes.length === 0 && bv('proxy-list').textContent.includes('Import a server') &&
        bv('proxy-list').rows[0].cells[0].colSpan === 7 && bv('proxy-select-all').disabled &&
        !bv('proxy-select-all').checked && !bv('proxy-select-all').indeterminate && bv('proxy-remove-selected').disabled,
        'Removing all proxy servers must leave a correctly spanned empty list with disabled selection controls.');
    reply.dashboard = savedDashboard;
    reply.proxyCatalog = savedCatalog;
    await refreshLists(true);
    system.click();
    reply.dashboard.canManageUpdates = false;
    bv('refresh').click();
    await wait();
    assert(bv('system-updates').hidden && !bv('system-backups').hidden,
        'Backup visibility must be independent from package update privileges.');
    reply.dashboard.canManageBackups = false;
    reply.dashboard.canManage = false;
    bv('refresh').click();
    await wait();
    assert(!bv('system-page').hidden && bv('system-updates').hidden && bv('system-backups').hidden,
        'Read-only users must retain System Settings appearance access.');
    document.querySelector('[data-bv-section="network"]').click();
    assert(getComputedStyle(bv('service-form')).display === 'none', 'service management visible to read-only user');
    assert(getComputedStyle(bv('add-device')).display === 'none', 'management controls were visible to read-only user');
    assert(!bv('device-list').querySelector('button') && !bv('tailnet-device-list').querySelector('button'),
        'Read-only device controls must exclude rule editing.');
    assert(bv('vpn-select-all').disabled && bv('proxy-select-all').disabled &&
        bv('vpn-remove-selected').disabled && bv('proxy-remove-selected').disabled &&
        [...document.querySelectorAll('[data-server-selection]')].every(input => input.disabled),
        'Read-only access must disable every server selection and bulk removal control.');
    document.body.setAttribute('data-fixture-result', 'PASS');
  } catch (error) {
    document.body.setAttribute('data-fixture-result', 'FAIL ' + error.message);
  }
});
