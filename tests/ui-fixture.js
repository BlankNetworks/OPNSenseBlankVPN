const requests = [];
const reply = {
    dashboard: {
        devices: [{ipv4: '10.0.0.20', ipv4Addresses: ['10.0.0.20', '10.0.0.21'], ipv6: ['fd00::20'], mac:'02:00:00:00:00:20', interface:'lan', interfaceName:'LAN', name:'<b>Device</b>', lastSeen:'2026-11-12T13:30:00Z', stable:true}],
        profiles: [{id:'vpn1', name:'Canada', relay:'ca-test-wg-001', interface:'wg1', dns:['10.64.0.1'], latestHandshake:1794490200, status:'Recent handshake', receivedBytes:4096, sentBytes:2048}],
        assignments: [],
        services: [],
        canManageCores: true,
        nativeGateways: [{id:'gw1', gateway:'NORD', protocol:'OpenVPN'}],
        mullvadSignedIn: false,
        proxyCores: {mihomo:true,tun2socks:true,xray:true,"sing-box":true},
        servicePresets: {Netflix:['netflix.com','nflxvideo.net']},
        settings: {dashboardBind:'lan',dashboardAddresses:{lan:'10.0.0.1',tailnet:'100.101.102.103'},enabled:true, interfaces:['lan'], availableInterfaces:[{id:'lan', name:'LAN'}], strictInterfaces:[], localNetworks:[], hostname:'opnsense.home.arpa'},
        warnings: []
    },
    relays: {relays:[{id:'ca-test-wg-001',country:'Canada',city:'Test',hostname:'ca-test-wg-001',active:true},{id:'ca-test-wg-002',country:'Canada',city:'Test',hostname:'ca-test-wg-002',active:false}], stale:false, fetchedAt:1794490200},
    connections: {connections:[{protocol:'tcp', source:'10.0.0.20', sourcePort:1234, destination:'2001:db8::25', destinationPort:443, age:'00:00:10', bytes:[1024,1024]}]},
    status: {ok:true, cores:[{id:'mihomo',version:'1.19.34',installed:true,source:'Bundled',
        available:{version:'1.19.35',sha256:'a'.repeat(64)},update:true,rollback:false}],
        storage:{freeBytes:1073741824,coreBytes:0,catalogBytes:1024,reserveBytes:67108864}},
    check: {ok:true, cores:[], storage:{freeBytes:1073741824,coreBytes:0,catalogBytes:1024,reserveBytes:67108864}},
    account: {ok:true, devices:[{name:'Test router'}], maxDevices:5, expiresAt:'2027-01-01'},
    proxyCatalog: {nodes:[{id:'proxy-1', name:'Example proxy', host:'192.0.2.9', port:1080, core:'mihomo',
        protocol:'socks5', legacy:true, sources:['feed-1']}], feeds:[{id:'feed-1', name:'Test feed', count:1, auto:true, usage:{upload:1024,download:1024,total:1048576,expire:1798761600}}]},
    importProxies: {ok:true, imported:1, skipped:0},
    refreshRelays: {ok:true, relays:[{id:'ca-test-wg-003',country:'Canada',city:'Test',hostname:'ca-test-wg-003',active:true}], stale:true, error:'Provider unavailable'}
};
window.jQuery = (ready) => document.addEventListener('DOMContentLoaded', ready);
window.jQuery.ajax = async (request) => {
    const action = request.url.split('/')[4];
    requests.push({action, method:request.method, data:request.data ? JSON.parse(request.data) : null});
    if (action === 'account') reply.dashboard.mullvadSignedIn = true;
    if (action === 'logoutMullvad') reply.dashboard.mullvadSignedIn = false;
    return structuredClone(reply[action] || {ok:true});
};

const bv = (id) => document.getElementById('bv-'+id);
const wait = () => new Promise(resolve => setTimeout(resolve, 20));
const assert = (value, message) => { if (!value) throw Error(message); };
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await wait();
    assert(bv('device-list').textContent.includes('<b>Device</b>'), 'device name should remain literal text');
    assert(!bv('device-list').querySelector('b'), 'device name injected HTML');
    assert(bv('device-list').textContent.includes('10.0.0.21'), 'additional IPv4 omitted');
    bv('appearance').value = 'night';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(document.getElementById('blankvpn')).colorScheme === 'dark', 'night theme did not apply');
    bv('appearance').value = 'day';
    bv('appearance').dispatchEvent(new Event('change'));
    assert(getComputedStyle(document.getElementById('blankvpn')).colorScheme === 'light', 'day theme did not apply');
    bv('device-list').querySelector('button').click();
    assert(bv('ip').value === '10.0.0.20', 'assignment address not populated');
    assert(bv('identity').textContent.includes('reservation was observed'), 'reservation not shown');
    bv('profile').value = 'vpn1';
    bv('profile').dispatchEvent(new Event('change'));
    bv('assign-form').requestSubmit(bv('assign-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.method === 'POST' && x.data.profile === 'vpn1' && x.data.failure === 'block'), 'incorrect assignment payload');
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
    assert(!bv('tunnels').hidden && bv('tunnels').open, 'VPN section did not open');
    bv('native-name').value = 'NordVPN';
    bv('native-gateway').value = 'gw1';
    bv('native-dns').value = '192.0.2.9';
    bv('native-form').requestSubmit(bv('native-add'));
    await wait();
    assert(requests.some(x => x.action === 'addNativeExit' && x.data.gateway === 'gw1'), 'native VPN gateway was not submitted');
    await wait();
    assert(bv('relay').options.length === 3 && bv('relay').options[2].disabled, 'server availability not enforced');
    bv('account').value = '1234567890123456';
    bv('inspect-account').click();
    await wait();
    assert(bv('account-status').textContent.includes('1 of 5'), 'account slots not rendered');
    bv('relay').value = 'ca-test-wg-001';
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'register' && x.data.relay === 'ca-test-wg-001' && !Object.hasOwn(x.data, 'account')), 'registration payload failed');
    assert(bv('account').value === '', 'successful registration retained account input');
    bv('relay').value = 'ca-test-wg-001';
    bv('retarget').value = 'vpn1';
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'retargetProfile' && x.data.id === 'vpn1' &&
      !Object.hasOwn(x.data, 'account')), 'retarget must reuse a profile without an account number');
    document.querySelector('[data-bv-section="smart"]').click();
    bv('service-preset').value = 'Netflix';
    bv('service-preset').dispatchEvent(new Event('change'));
    assert(bv('service-domains').value === 'netflix.com, nflxvideo.net', 'Netflix preset domains not populated');
    bv('service-profile').value = 'vpn1';
    bv('service-form').requestSubmit(bv('save-service'));
    await wait();
    assert(requests.some(x => x.action === 'saveService' && x.data.profile === 'vpn1' &&
        x.data.domains.includes('nflxvideo.net')), 'service rule payload failed');
    bv('use-lan').click();
    assert(bv('smart-interfaces').value === 'lan' && bv('managed').value === 'lan', 'LAN setup did not prefill');
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
    assert(bv('subscription-list').textContent.includes('Test feed'), 'proxy subscription not displayed');
    assert(bv('subscription-list').textContent.includes('2.0 KiB used / 1.0 MiB'), 'subscription quota not displayed');
    bv('manual-name').value = 'Manual example';
    bv('manual-host').value = '192.0.2.8';
    bv('manual-port').value = '1080';
    bv('proxy-manual').requestSubmit(bv('proxy-manual').querySelector('button'));
    await wait();
    assert(requests.some(x => x.action === 'addProxyNode' && x.data.protocol === 'socks5'), 'manual proxy was not submitted');
    bv('proxy-list').querySelector('button').click();
    await wait();
    assert(requests.some(x => x.action === 'enableProxyExit' && x.data.id === 'proxy-1'), 'proxy was not selected individually');
    bv('proxy-body').value = 'socks5://192.0.2.9:1080';
    bv('proxy-import').requestSubmit(bv('proxy-import').querySelector('button'));
    await wait();
    assert(requests.some(x => x.action === 'importProxies') && bv('proxy-body').value === '', 'proxy import was not submitted and cleared');
    bv('settings').open = true;
    bv('dashboard-bind').value = 'tailnet';
    bv('dashboard-bind').dispatchEvent(new Event('change'));
    assert(bv('bind-address').textContent.includes('100.101.102.103'), 'Tailscale dashboard address not displayed');
    bv('settings-form').requestSubmit(bv('settings-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.interfaces[0] === 'lan' &&
      x.data.smartInterfaces[0] === 'lan' && x.data.dashboardBind === 'tailnet'), 'routing settings did not serialize');
    bv('refresh-relays').click();
    await wait();
    assert(bv('relay').options[1].value === 'ca-test-wg-003', 'cached relay lost after refresh error');
    assert(bv('relay-status').textContent.includes('Provider unavailable'), 'stale catalog warning omitted');
    assert(document.documentElement.scrollWidth <= window.innerWidth, 'document has horizontal overflow');
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
