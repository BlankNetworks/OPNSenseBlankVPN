const requests = [];
const reply = {
    dashboard: {
        devices: [{ipv4: '10.0.0.20', ipv4Addresses: ['10.0.0.20', '10.0.0.21'], ipv6: ['fd00::20'], mac:'02:00:00:00:00:20', interface:'lan', interfaceName:'LAN', name:'<b>Device</b>', lastSeen:'2026-11-12T13:30:00Z', stable:true}],
        profiles: [{id:'vpn1', name:'Canada', relay:'ca-test-wg-001', interface:'wg1', dns:['10.64.0.1'], latestHandshake:1794490200, status:'Recent handshake', receivedBytes:4096, sentBytes:2048}],
        assignments: [{id:'device1',ip:'10.0.0.20',mac:'02:00:00:00:00:20',interface:'lan',
            label:'<b>Device rule</b>',mode:'disabled',profile:'',kind:'lan'}],
        services: [],
        canManageCores: true,
        mullvadSignedIn: false,
        mullvadBatches: {worldwide:false,countries:[],cities:[]},
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
    if (action === 'saveMullvadBatch') {
        const batches = reply.dashboard.mullvadBatches;
        const add = data.action === 'add';
        if (data.country === '') {
            batches.worldwide = add;
        } else if (data.city) {
            const key = data.country + ':' + data.city;
            batches.cities = add ? [...new Set([...batches.cities, key])] : batches.cities.filter((city) => city !== key);
        } else if (add && !batches.countries.includes(data.country)) {
            batches.countries.push(data.country);
        } else if (!add) {
            batches.countries = batches.countries.filter((country) => country !== data.country);
        }
        return structuredClone({ok:true, batches});
    }
    if (action === 'saveService') {
        reply.dashboard.services = [{id:'list1', name:data.name, profile:data.profile, domains:data.domains.split(/[,\s]+/)}];
    }
    if (action === 'disable') {
        reply.dashboard.settings.enabled = false;
    }
    if (action === 'settings' || action === 'tailscaleSettings') {
        Object.assign(reply.dashboard.settings, data);
    }
    if (action === 'setSubscriptionAuto') reply.proxyCatalog.feeds[0].auto = data.auto;
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
    assert(!bv('device-list').textContent.includes('10.0.0.21'), 'automatically observed device leaked into the rules table');
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
    bv('device-list').querySelectorAll('button')[1].click();
    await wait();
    assert(bv('connection-list').textContent.includes('[2001:db8::25]:443'), 'IPv6 destination rendering failed');
    assert(bv('connection-list').textContent.includes('2.0 KiB'), 'connection bytes not rendered');
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
    bv('mullvad-batches').open = true;
    bv('batch-scope').value = 'ca';
    bv('batch-scope').dispatchEvent(new Event('change'));
    assert(bv('batch-status').textContent === '2 servers' && !bv('save-batch').disabled, 'country count was incorrect');
    bv('save-batch').click();
    await wait();
    assert(requests.some(x => x.action === 'saveMullvadBatch' && x.data.country === 'ca' && x.data.action === 'add') &&
        bv('relay-list').value === 'ca' && bv('relay').options.length === 3 && bv('relay').options[2].disabled,
        'saved country batch should select all relays for that country, including unavailable ones');
    bv('batch-scope').value = 'all';
    bv('batch-scope').dispatchEvent(new Event('change'));
    bv('save-batch').click();
    await wait();
    assert(requests.some(x => x.action === 'saveMullvadBatch' && x.data.country === '' && x.data.action === 'add') &&
        bv('relay-list').value === 'all' && bv('relay').options.length === 4 &&
        !requests.some(x => x.action === 'register'), 'adding the worldwide batch should save every relay without activating an exit');
    bv('relay-list').value = 'ca';
    bv('relay-list').dispatchEvent(new Event('change'));
    bv('remove-batch').click();
    await wait();
    assert(requests.some(x => x.action === 'saveMullvadBatch' && x.data.country === '' && x.data.action === 'remove') &&
        bv('relay-list').value === 'ca' && bv('relay-list').options.length === 2, 'removing worldwide should leave the country batch selected');
    bv('refresh').click();
    await wait();
    assert(bv('relay-list').value === 'ca' && bv('relay').options.length === 3, 'saved batch was lost on dashboard refresh');
    bv('relay').value = 'ca-test-wg-001';
    bv('relay').dispatchEvent(new Event('change'));
    assert(bv('relay-choice').textContent.includes('Canada') && !bv('register').disabled, 'relay selection did not update');
    bv('test-relay').click();
    await wait();
    assert(bv('relay-test').textContent.includes('12.345 ms') &&
        requests.some(x => x.action === 'testRelay' && x.data.relay === 'ca-test-wg-001'), 'per-relay ping missing');
    bv('profile-list').querySelector('button').click();
    await wait();
    assert(bv('profile-list').querySelector('[data-test-result]').textContent.includes('45.2 ms'), 'exit HTTPS test missing');
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'register' && x.data.relay === 'ca-test-wg-001' && !Object.hasOwn(x.data, 'account')), 'registration payload failed');
    assert(bv('account').value === '', 'successful registration retained account input');
    bv('relay').value = 'ca-test-wg-001';
    bv('retarget').value = 'vpn1';
    bv('relay').dispatchEvent(new Event('change'));
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'retargetProfile' && x.data.id === 'vpn1' &&
      !Object.hasOwn(x.data, 'account')), 'retarget must reuse a profile without an account number');
    bv('batch-scope').value = 'jp:nrt';
    bv('batch-scope').dispatchEvent(new Event('change'));
    bv('save-batch').click();
    await wait();
    assert(bv('relay-list').value === 'jp:nrt' && bv('relay').options[1].value === 'jp-test-wg-001',
        'City batch must expose its saved relay.');
    bv('activate-batch').click();
    await wait();
    assert(requests.some(x => x.action === 'register' && x.data.relay === 'jp-test-wg-001') &&
        bv('batch-operation').textContent.includes('1 exit added'), 'Batch activation must use the available device slot.');
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
        x.data.domains.includes('nflximg.net')) && bv('service-list').textContent.includes('Unassigned'),
        'domain list did not save without any exits');
    reply.dashboard.profiles = originalProfiles;
    bv('refresh').click();
    await wait();
    bv('service-list').querySelector('button').click();
    bv('service-profile').value = 'vpn1';
    bv('service-form').requestSubmit(bv('save-service'));
    await wait();
    assert(requests.some(x => x.action === 'saveService' && x.data.id === 'list1' && x.data.profile === 'vpn1' &&
        x.data.domains.includes('nflxvideo.net')), 'saved list could not be bound to an exit');
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
    [...bv('proxy-list').querySelectorAll('button')].find((item) => item.textContent === 'Test server').click();
    await wait();
    assert(requests.some(x => x.action === 'testProxyNode' && x.data.id === 'proxy-1') &&
        bv('proxy-list').querySelector('[data-test-result]').textContent.includes('The proxy connection timed out.'), 'saved proxy test did not report its failure');

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
    [...bv('proxy-list').querySelectorAll('button')].find((item) => item.textContent === 'Enable exit').click();
    await wait();
    assert(requests.some(x => x.action === 'enableProxyExit' && x.data.id === 'proxy-1'), 'proxy was not selected individually');
    bv('proxy-body').value = 'socks5://192.0.2.9:1080';
    bv('proxy-import').requestSubmit(bv('proxy-import').querySelector('button'));
    await wait();
    assert(requests.some(x => x.action === 'importProxies') && bv('proxy-body').value === '', 'proxy import was not submitted and cleared');
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
    bv('settings-form').requestSubmit(bv('settings-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.coverage === 'network' &&
        x.data.networkMode === 'full' && x.data.networkProfile === 'vpn1' && x.data.networkKillSwitch === true) &&
        bv('add-device').hidden,
        'Whole-Network coverage settings did not apply');
    bv('disable-routing').click();
    await wait();
    assert(requests.some(x => x.action === 'disable') && bv('routing-enabled').hidden &&
        !bv('save-routing').classList.contains('bv-enabled') && bv('network-kill').checked,
        'Disabling VPN did not preserve the saved kill switch and clear the green state.');
    document.querySelector('[data-bv-section="vpns"]').click();
    bv('relay-list').value = '';
    bv('relay-list').dispatchEvent(new Event('change'));
    bv('refresh-relays').click();
    await wait();
    assert(bv('relay').options[1].value === 'ca-test-wg-003', 'cached relay lost after refresh error');
    assert(bv('relay-status').textContent.includes('Provider unavailable'), 'stale catalog warning omitted');
    assert(document.documentElement.scrollWidth <= window.innerWidth, 'document has horizontal overflow');
    document.querySelector('[data-bv-section="network"]').click();
    const expected = window.innerWidth < 768 ? 'block' : 'table';
    assert(getComputedStyle(bv('device-list').closest('table')).display === expected, 'incorrect device layout for viewport');
    reply.dashboard.canManage = false;
    bv('refresh').click();
    await wait();
    assert(getComputedStyle(bv('service-form')).display === 'none', 'service management visible to read-only user');
    assert(getComputedStyle(bv('add-device')).display === 'none', 'management controls were visible to read-only user');
    assert(bv('device-list').querySelectorAll('button').length === 1, 'read-only device controls incorrect');
    document.body.setAttribute('data-fixture-result', 'PASS');
  } catch (error) {
    document.body.setAttribute('data-fixture-result', 'FAIL ' + error.message);
  }
});
