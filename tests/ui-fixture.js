const requests = [];
const reply = {
    dashboard: {
        devices: [{ipv4: '10.0.0.20', ipv4Addresses: ['10.0.0.20', '10.0.0.21'], ipv6: ['fd00::20'], mac:'02:00:00:00:00:20', interface:'lan', interfaceName:'LAN', name:'<b>Device</b>', lastSeen:'2026-11-12T13:30:00Z', stable:true}],
        profiles: [{id:'vpn1', name:'Canada', relay:'ca-test-wg-001', interface:'wg1', dns:['10.64.0.1'], latestHandshake:1794490200, status:'Recent handshake', receivedBytes:4096, sentBytes:2048}],
        assignments: [],
        services: [],
        servicePresets: {Netflix:['netflix.com','nflxvideo.net']},
        settings: {enabled:true, interfaces:['lan'], availableInterfaces:[{id:'lan', name:'LAN'}], strictInterfaces:[], localNetworks:[], hostname:'opnsense.home.arpa'},
        warnings: []
    },
    relays: {relays:[{id:'ca-test-wg-001',country:'Canada',city:'Test',hostname:'ca-test-wg-001',active:true},{id:'ca-test-wg-002',country:'Canada',city:'Test',hostname:'ca-test-wg-002',active:false}], stale:false, fetchedAt:1794490200},
    connections: {connections:[{protocol:'tcp', source:'10.0.0.20', sourcePort:1234, destination:'2001:db8::25', destinationPort:443, age:'00:00:10', bytes:[1024,1024]}]},
    account: {ok:true, devices:[{name:'Test router'}], maxDevices:5, expiresAt:'2027-01-01'},
    refreshRelays: {ok:true, relays:[{id:'ca-test-wg-003',country:'Canada',city:'Test',hostname:'ca-test-wg-003',active:true}], stale:true, error:'Provider unavailable'}
};
window.jQuery = (ready) => document.addEventListener('DOMContentLoaded', ready);
window.jQuery.ajax = async (request) => {
    const action = request.url.split('/')[4];
    requests.push({action, method:request.method, data:request.data ? JSON.parse(request.data) : null});
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
    bv('device-list').querySelector('button').click();
    assert(bv('ip').value === '10.0.0.20', 'assignment address not populated');
    assert(bv('identity').textContent.includes('reservation was observed'), 'reservation not shown');
    bv('profile').value = 'vpn1';
    bv('profile').dispatchEvent(new Event('change'));
    bv('assign-form').requestSubmit(bv('assign-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'assign' && x.method === 'POST' && x.data.profile === 'vpn1' && x.data.failure === 'block'), 'incorrect assignment payload');
    assert(bv('assignment').hidden, 'successful assignment did not close');
    bv('device-list').querySelectorAll('button')[1].click();
    await wait();
    assert(bv('connection-list').textContent.includes('[2001:db8::25]:443'), 'IPv6 destination rendering failed');
    assert(bv('connection-list').textContent.includes('2.0 KiB'), 'connection bytes not rendered');
    bv('tunnels').open = true;
    await wait();
    assert(bv('relay').options.length === 3 && bv('relay').options[2].disabled, 'server availability not enforced');
    bv('account').value = '1234567890123456';
    bv('inspect-account').click();
    await wait();
    assert(bv('account-status').textContent.includes('1 of 5'), 'account slots not rendered');
    bv('relay').value = 'ca-test-wg-001';
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'register' && x.data.relay === 'ca-test-wg-001'), 'registration payload failed');
    assert(bv('account').value === '', 'successful registration retained account input');
    bv('relay').value = 'ca-test-wg-001';
    bv('retarget').value = 'vpn1';
    bv('register-form').requestSubmit(bv('register-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'retargetProfile' && x.data.id === 'vpn1' &&
      !Object.hasOwn(x.data, 'account')), 'retarget must reuse a profile without an account number');
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
    bv('settings').open = true;
    bv('settings-form').requestSubmit(bv('settings-form').querySelector('button[type=submit]'));
    await wait();
    assert(requests.some(x => x.action === 'settings' && x.data.interfaces[0] === 'lan' &&
      x.data.smartInterfaces[0] === 'lan'), 'routing settings did not serialize');
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
