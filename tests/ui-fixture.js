const requests = [];
let settingsError = null;
const reply = {
    dashboard: {
        devices: [{ipv4: '10.0.0.20', ipv4Addresses: ['10.0.0.20', '10.0.0.21'], ipv6: ['fd00::20'], mac:'02:00:00:00:00:20', interface:'lan', interfaceName:'LAN', name:'<b>Device</b>', lastSeen:'2026-11-12T13:30:00Z', stable:true}],
        tailnetDevices: [{kind:'tailnet', name:'Remote iPad', ipv4:'100.101.102.104', ipv6:['fd7a:115c:a1e0::104'], online:true}],
        profiles: [{id:'vpn1', name:'Canada', relay:'ca-test-wg-001', interface:'wg1', dns:['10.64.0.1'], latestHandshake:1794490200, status:'Recent handshake', receivedBytes:4096, sentBytes:2048}],
        assignments: [{id:'device1',ip:'10.0.0.20',mac:'02:00:00:00:00:20',interface:'lan',
            label:'<b>Device rule</b>',mode:'disabled',profile:'',kind:'lan'}],
        services: [],
        canManageCores: true,
        mullvadSignedIn: false,
        vpnProviders: {mullvad:{name:'Mullvad',login:'mullvad'}, pia:{name:'Private Internet Access',login:'password'},
            hide:{name:'hide.me'}, azire:{name:'AzireVPN',login:'token'}},
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
    proxyCatalog: {nodes:[{id:'proxy-1', name:'Example proxy', host:'192.0.2.9', port:1080, core:'mihomo',
        protocol:'socks5', legacy:true, sources:['feed-1']}], feeds:[{id:'feed-1', name:'Test feed', count:1, auto:true, usage:{upload:1024,download:1024,total:1048576,expire:1798761600}}]},
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
    const action = request.url.split('/')[4];
    const data = request.data ? JSON.parse(request.data) : null;
    requests.push({action, method:request.method, data});
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
    if (action === 'addProviderExit') {
        reply.dashboard.profiles.push({id:'pia1',name:data.name,provider:data.provider,providerLocation:data.server,
            interface:'wg2',dns:['10.0.0.2']});
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
    if (action === 'assign' && data.kind === 'tailnet') {
        const existing = reply.dashboard.assignments.find(row => row.id === 'tailnet1');
        const fields = {...data, label: data.label || 'Remote iPad', ipv6: data.ipv6 || 'fd7a:115c:a1e0::104'};
        if (existing) Object.assign(existing, fields);
        else reply.dashboard.assignments.push({id:'tailnet1', ...fields});
    }
    if (action === 'setTailnetRuleEnabled') {
        reply.dashboard.assignments.find(row => row.id === data.id).paused = !data.enabled;
    }
    if (action === 'testDeviceRoute') {
        return {ok:true, reachable:true, milliseconds:22.4, deviceTraffic:'seen', usingBackup:false};
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
                name:'New console', mac:'02:00:00:00:00:30', stable:false, leaseProvider:'Dnsmasq DHCP'});
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
    assert(requests.some(x => x.action === 'assign' && x.method === 'POST' && x.data.profile === 'vpn1' && x.data.failure === 'block' && x.data.killSwitch === true), 'incorrect assignment payload');
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
        bv('register').textContent === 'Enabled', 'an already configured Mullvad server must show Enabled');
    bv('test-relay').click();
    await wait();
    assert(bv('relay-test').textContent.includes('12.345 ms') &&
        requests.some(x => x.action === 'testRelay' && x.data.relay === 'ca-test-wg-001'), 'per-relay ping missing');
    assert(bv('profile-list').querySelector('button').textContent === 'Test', 'VPN button must say Test');
    bv('profile-list').querySelector('button').click();
    await wait();
    assert(bv('profile-list').querySelector('[data-test-result]').textContent.includes('45.2 ms'), 'exit HTTPS test missing');
    bv('profile-list').querySelector('[aria-label="Edit name for Canada"]').click();
    const vpnName = bv('profile-list').querySelector('.bv-name-editor');
    vpnName.querySelector('input').value = 'Canada home';
    vpnName.requestSubmit(vpnName.querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'renameProfile' && x.data.id === 'vpn1' && x.data.name === 'Canada home') &&
        bv('profile-list').textContent.includes('Canada home') &&
        bv('profile-list').querySelector('[data-test-result]').textContent.includes('45.2 ms'), 'VPN rename lost the row or its result');
    [...bv('profile-list').querySelectorAll('button')].find(button => button.textContent === 'Disable').click();
    await wait();
    assert(reply.dashboard.profiles[0].disabled && ![...bv('network-profile').options].some(option => option.value === 'vpn1'),
        'A disabled Mullvad server must leave the routing picker.');
    [...bv('profile-list').querySelectorAll('button')].find(button => button.textContent === 'Enable').click();
    await wait();
    assert(!reply.dashboard.profiles[0].disabled, 'The existing Mullvad tunnel must be re-enabled.');
    assert(bv('account').value === '', 'successful sign-in retained account input');
    bv('country').value = 'Japan';
    bv('country').dispatchEvent(new Event('change'));
    bv('relay').value = 'jp-test-wg-001';
    bv('relay').dispatchEvent(new Event('change'));
    assert(bv('register').textContent === 'Use server' && !bv('retarget'), 'Mullvad should offer automatic tunnel selection');
    bv('register-form').requestSubmit(bv('register'));
    await wait();
    assert(requests.some(x => x.action === 'register' && x.data.relay === 'jp-test-wg-001' &&
        !Object.hasOwn(x.data, 'account')), 'registration payload failed');
    document.querySelector('[data-bv-section="smart"]').click();
    bv('service-preset').value = 'Netflix';
    bv('service-preset').dispatchEvent(new Event('change'));
    assert(bv('service-domains').value === 'netflix.com\nnflxvideo.net', 'Netflix preset domains not populated');
    const originalProfiles = reply.dashboard.profiles;
    reply.dashboard.profiles = [];
    bv('refresh').click();
    await wait();
    const importedDomains = 'netflix.com\n*.nflxvideo.net\nnflximg.net';
    const data = new DataTransfer();
    data.items.add(new File([importedDomains], 'Netflix.txt'));
    bv('service-file').files = data.files;
    // Headless Chrome can exhaust its virtual time budget before native file IO returns.
    const nativeText = File.prototype.text;
    File.prototype.text = async function () {
        assert(this.name === 'Netflix.txt', 'wrong domain file was read');
        return importedDomains;
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
        x.data.domains.includes('nflximg.net')) && bv('service-list').querySelector('select').value === '',
        'domain list did not save without any exits');
    reply.dashboard.profiles = originalProfiles;
    bv('refresh').click();
    await wait();
    bv('service-list').querySelector('[aria-label="Edit Netflix"]').click();
    bv('service-profile').value = 'vpn1';
    bv('service-form').requestSubmit(bv('save-service'));
    await wait();
    assert(requests.some(x => x.action === 'saveService' && x.data.id === 'list1' && x.data.profile === 'vpn1' &&
        x.data.domains.includes('nflxvideo.net')), 'saved list could not be bound to an exit');
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
    [...bv('proxy-list').querySelectorAll('button')].find((item) => item.textContent === 'Test').click();
    await wait();
    assert(requests.some(x => x.action === 'testProxyNode' && x.data.id === 'proxy-1') &&
        bv('proxy-list').querySelector('[data-test-result]').textContent.includes('The proxy connection timed out.'), 'saved proxy test did not report its failure');

    assert([...bv('proxy-list').querySelectorAll('button')].map(button => button.textContent).join(',') === 'Test,Edit,Disable,Remove',
        'proxy row actions must use simple labels');
    const failedTest = bv('proxy-list').querySelector('[data-result="fail"]');
    assert(getComputedStyle(failedTest).backgroundColor === 'rgb(255, 240, 241)' &&
        getComputedStyle(failedTest, '::before').content.includes('Test failed'), 'Failed test row lost its warning treatment');
    bv('proxy-list').querySelector('[aria-label="Edit name for Example proxy"]').click();
    const proxyName = bv('proxy-list').querySelector('.bv-name-editor');
    proxyName.querySelector('input').value = 'SOCKS5 office';
    proxyName.requestSubmit(proxyName.querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'renameProxyNode' && x.data.id === 'proxy-1' && x.data.name === 'SOCKS5 office') &&
        bv('proxy-list').textContent.includes('SOCKS5 office') &&
        bv('proxy-list').querySelector('[data-test-result]').textContent.includes('timed out'), 'Proxy rename lost the row or its result');
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
    assert(bv('proxy-count').textContent.includes('1–50 of 56'), 'large catalog page count is incorrect');
    bv('proxy-next').click();
    assert(bv('proxy-list').textContent.includes('SOCKS5 office'), 'later pages must include all servers');
    bv('proxy-filter').value = 'socks5';
    bv('proxy-filter').dispatchEvent(new Event('input'));
    assert(bv('proxy-count').textContent === '1 server' && bv('proxy-list').textContent.includes('SOCKS5 office'),
        'SOCKS5 filter must find a server outside the first page');
    reply.proxyCatalog.nodes.splice(0, 55);
    bv('proxy-filter').value = '';
    bv('proxy-filter').dispatchEvent(new Event('input'));
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
    bv('device-list').querySelector('[aria-label="Select New console"]').click();
    assert(bv('ip').value === '10.0.0.30' && bv('mac').value === '02:00:00:00:00:30' &&
        bv('interface').value === 'lan' && bv('device-kill').checked, 'Selecting a LAN device must fill the rule.');
    bv('mode').value = 'full';
    bv('mode').dispatchEvent(new Event('change'));
    bv('profile').value = 'proxy-proxy-1';
    bv('profile').dispatchEvent(new Event('change'));
    assert(!bv('save-device').disabled && bv('save-device').textContent === 'Reserve IP and save rule',
        'A detected DHCP lease must offer one-step reservation and routing.');
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.ip === '10.0.0.30' &&
        x.data.reserveIp && x.data.profile === 'proxy-proxy-1' && x.data.killSwitch), 'New proxies must be ready to assign without a separate enable action.');
    assert(bv('tailnet-devices').tagName === 'DETAILS' && !bv('tailnet-devices').open &&
        bv('tailnet-count').textContent.includes('1 online') &&
        getComputedStyle(bv('tailnet-devices').querySelector('.bv-disclosure-link')).textDecorationLine === 'underline',
        'Tailscale device list must be collapsible with an underlined label.');
    bv('tailnet-devices').open = true;
    assert(bv('tailnet-snat-note').textContent.trim().startsWith('*') &&
        bv('tailnet-snat-note').textContent.includes('Disable SNAT') &&
        bv('tailnet-snat-note').textContent.includes('Apply'),
        'The expanded list must show the Disable SNAT step.');
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
        bv('interface').value === 'tailscale0' && !bv('switch-now'),
        'Native peer rules must select the Tailscale interface automatically without a reconnect toggle.');
    bv('profile').value = 'vpn1';
    bv('assign-form').requestSubmit(bv('save-device'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.data.kind === 'tailnet' && x.data.interface === 'tailscale0' &&
        x.data.ip === '100.101.102.104' && x.data.profile === 'vpn1' && !Object.hasOwn(x.data, 'switchNow')),
        'Selecting a native exit peer must submit both the interface and the chosen VPN server.');
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
    tailnetTable.querySelector('[aria-label="Ping Remote iPad"]').click();
    await wait();
    assert(tailnetTable.querySelector('[data-test-result="device:tailnet1"]').textContent.includes('Device traffic seen') &&
        requests.some(x => x.action === 'testDeviceRoute' && x.data.id === 'tailnet1'), 'Tailscale rule Ping must display an inline result.');
    tailnetTable.querySelector('[aria-label="Disable Remote iPad"]').click();
    await wait();
    assert(tailnetTable.textContent.includes('Disabled') && !tailnetTable.querySelector('[aria-label="Ping Remote iPad"]') &&
        reply.dashboard.assignments.find(row => row.id === 'tailnet1').profile === 'vpn1',
        'Pausing a Tailscale rule must retain the server and hide Ping.');
    tailnetTable.querySelector('[aria-label="Enable Remote iPad"]').click();
    await wait();
    assert(tailnetTable.querySelector('[aria-label="Ping Remote iPad"]') &&
        requests.some(x => x.action === 'setTailnetRuleEnabled' && x.data.id === 'tailnet1' && x.data.enabled),
        'Re-enabling a Tailscale rule restores the saved route and Ping.');
    Object.assign(reply.dashboard.assignments[0], {mode:'full',profile:'vpn1'});
    bv('refresh').click();
    await wait();
    bv('device-list').querySelector('[aria-label="Ping <b>Device rule</b>"]').click();
    await wait();
    assert(bv('device-list').querySelector('[data-test-result="device:device1"]').textContent.includes('22.4 ms') &&
        requests.some(x => x.action === 'testDeviceRoute' && x.data.id === 'device1'), 'LAN rules use the same Ping check.');
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
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    settingsError = null;
    bv('settings-form').requestSubmit(bv('save-routing'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.coverage === 'network' &&
        x.data.networkMode === 'full' && x.data.networkProfile === 'proxy1' && x.data.networkKillSwitch === true) &&
        bv('add-device').hidden && reply.dashboard.settings.networkProfile === 'proxy1',
        'Whole-Network proxy coverage settings did not apply.');
    assert(bv('disable-routing').parentElement.contains(bv('settings-title')) &&
        getComputedStyle(bv('disable-routing')).backgroundColor === 'rgb(177, 40, 60)',
        'Disable VPN must be red at the top of routing settings.');
    bv('disable-routing').click();
    await wait();
    assert(requests.some(x => x.action === 'disable') && bv('routing-enabled').hidden &&
        !bv('save-routing').classList.contains('bv-enabled') && bv('network-kill').checked,
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
    bv('provider-save').click();
    await wait();
    assert(requests.some(x => x.action === 'addProviderExit' && x.data.provider === 'pia' && x.data.server === 'chicago'),
        'Save did not use the selected provider server.');
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
    assert(document.documentElement.scrollWidth <= window.innerWidth, 'document has horizontal overflow');
    document.querySelector('[data-bv-section="network"]').click();
    const expected = window.innerWidth < 768 ? 'block' : 'table';
    assert(getComputedStyle(bv('device-list').closest('table')).display === expected, 'incorrect device layout for viewport');
    reply.dashboard.canManage = false;
    bv('refresh').click();
    await wait();
    assert(getComputedStyle(bv('service-form')).display === 'none', 'service management visible to read-only user');
    assert(getComputedStyle(bv('add-device')).display === 'none', 'management controls were visible to read-only user');
    assert(!bv('device-list').querySelector('button') && !bv('tailnet-device-list').querySelector('button'),
        'Read-only device controls must exclude rule editing.');
    document.body.setAttribute('data-fixture-result', 'PASS');
  } catch (error) {
    document.body.setAttribute('data-fixture-result', 'FAIL ' + error.message);
  }
});
