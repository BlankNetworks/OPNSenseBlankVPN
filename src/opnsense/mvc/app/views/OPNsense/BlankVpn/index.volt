<link href="{{ cache_safe('/ui/css/blankvpn.css') }}" rel="stylesheet">
<script src="{{ cache_safe('/ui/js/blankvpn.js') }}" defer></script>

<div id="blankvpn" class="blankvpn">
    <header class="bv-heading bv-hero">
        <div>
            <h1>Blank VPN</h1>
            <p class="text-muted">Route selected services or IPv4 devices through a VPN or proxy exit.</p>
        </div>
        <div class="bv-actions bv-utilities">
            <label for="bv-appearance" class="sr-only">Appearance</label>
            <select id="bv-appearance" class="form-control" aria-label="Appearance">
                <option value="system">System theme</option>
                <option value="day">Day</option>
                <option value="night">Night</option>
            </select>
            <button id="bv-refresh" type="button" class="btn btn-default">Refresh devices</button>
        </div>
    </header>

    <div id="bv-message" class="alert" role="status" aria-live="polite" hidden></div>
    <ul id="bv-warnings" class="alert alert-warning bv-warnings" hidden></ul>

    <nav class="bv-actions bv-navigation" aria-label="Blank VPN sections">
        <button type="button" class="btn btn-primary" data-bv-section="devices" aria-pressed="true">Devices</button>
        <button type="button" class="btn btn-default" data-bv-section="vpns" aria-pressed="false">VPNs</button>
        <button type="button" class="btn btn-default" data-bv-section="proxies" aria-pressed="false" data-manage-only>Proxies</button>
        <button type="button" class="btn btn-default" data-bv-section="smart" aria-pressed="false">Multi-Path</button>
        <button type="button" class="btn btn-default" data-bv-section="settings" aria-pressed="false" data-manage-only>Settings</button>
    </nav>

    <section class="bv-panel" data-bv-panel="smart" aria-labelledby="bv-smart-title" hidden>
        <div class="bv-heading">
            <div>
                <h2 id="bv-smart-title">Multi-Path Tunneling</h2>
                <p id="bv-smart-status" class="text-muted"></p>
            </div>
            <button id="bv-use-lan" data-manage-only type="button" class="btn btn-default">Set up Multi-Path on LAN</button>
        </div>
        <div class="bv-scroll">
            <table class="table bv-table bv-services">
                <thead>
                    <tr>
                        <th scope="col">Service and domains</th>
                        <th scope="col">Exit</th>
                        <th scope="col">Routing</th>
                        <th scope="col"><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody id="bv-service-list"></tbody>
            </table>
        </div>
        <form id="bv-service-form" data-manage-only>
            <div class="bv-fields">
                <label>Service preset
                    <select id="bv-service-preset" class="form-control"><option value="">Custom service</option></select>
                </label>
                <label>Service name
                    <input id="bv-service-name" class="form-control" type="text" maxlength="64" required>
                </label>
                <label>Exit
                    <select id="bv-service-profile" class="form-control" required></select>
                </label>
            </div>
            <label>Domains and subdomains
                <textarea id="bv-service-domains" class="form-control" rows="2" maxlength="2048" placeholder="netflix.com, *.nflxvideo.net" spellcheck="false" required></textarea>
            </label>
            <p class="text-muted">Each domain includes its subdomains. Smart Routing learns addresses from regular DNS on the selected LANs. Cached addresses, encrypted DNS, and shared CDNs can affect coverage.</p>
            <div class="bv-actions">
                <button id="bv-save-service" type="submit" class="btn btn-primary">Add service</button>
                <button id="bv-cancel-service" type="button" class="btn btn-default" hidden>Cancel edit</button>
            </div>
        </form>
    </section>

    <section class="bv-panel" data-bv-panel="devices" aria-labelledby="bv-devices-title">
        <div class="bv-heading">
            <div>
                <h2 id="bv-devices-title">Devices</h2>
                <p id="bv-observed" class="text-muted">Loading observations…</p>
            </div>
            <button id="bv-add-device" data-manage-only type="button" class="btn btn-default">Assign an IP address</button>
        </div>
        <div class="bv-scroll">
            <table class="table bv-table bv-devices" role="table">
                <thead role="rowgroup">
                    <tr role="row">
                        <th scope="col" role="columnheader">Device</th>
                        <th scope="col" role="columnheader">Addresses</th>
                        <th scope="col" role="columnheader">Network</th>
                        <th scope="col" role="columnheader">Assignment</th>
                        <th scope="col" role="columnheader">Observed status</th>
                        <th scope="col" role="columnheader"><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody id="bv-device-list" role="rowgroup"></tbody>
            </table>
        </div>
    </section>

    <section id="bv-assignment" class="bv-panel" aria-labelledby="bv-assignment-title" hidden>
        <div class="bv-heading">
            <h2 id="bv-assignment-title" tabindex="-1">Device assignment</h2>
            <button id="bv-close-assignment" type="button" class="btn btn-default">Close</button>
        </div>
        <form id="bv-assign-form">
            <div class="bv-fields">
                <label>Device label <input id="bv-device-label" type="text" class="form-control" maxlength="80"></label>
                <label>Address source
                    <select id="bv-device-kind" class="form-control">
                        <option value="lan">LAN DHCP reservation</option>
                        <option value="tailnet">Tailscale peer on a routed link</option>
                    </select>
                </label>
                <label>IPv4 address <input id="bv-ip" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                <label>Interface
                    <input id="bv-interface" type="text" class="form-control" list="bv-interface-list" autocomplete="off" required>
                    <datalist id="bv-interface-list"></datalist>
                </label>
                <label id="bv-mac-field">MAC address <input id="bv-mac" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                <label>IPv6 address <input id="bv-ipv6" type="text" class="form-control" autocomplete="off" spellcheck="false"></label>
                <label>Routing mode
                    <select id="bv-mode" class="form-control">
                        <option value="full">Full Tunneling</option>
                        <option value="multi">Multi-Path Tunneling</option>
                        <option value="disabled">Disabled (No VPN)</option>
                        <option value="blocked">Blocked (No Internet)</option>
                    </select>
                </label>
                <label id="bv-profile-field">Exit <select id="bv-profile" class="form-control"></select></label>
                <label id="bv-failure-field">If the exit fails
                    <select id="bv-failure" class="form-control">
                        <option value="block">Block IPv4 internet (kill switch)</option>
                        <option value="backup">Use a backup exit</option>
                        <option value="wan">Use normal internet</option>
                    </select>
                </label>
                <label id="bv-backup-field" hidden>Backup exit <select id="bv-backup" class="form-control"></select></label>
            </div>
            <p id="bv-identity" class="text-muted"></p>
            <p id="bv-route-note" class="text-muted"></p>
            <label class="bv-check">
                <input id="bv-switch-now" type="checkbox">
                Reconnect affected internet sessions for this device
            </label>
            <p class="text-muted">Reconnecting may interrupt downloads, streams, or calls.</p>
            <div class="bv-actions">
                <button type="submit" class="btn btn-primary">Apply assignment</button>
                <button id="bv-remove-assignment" type="button" class="btn btn-default" hidden>Remove assignment</button>
            </div>
        </form>
    </section>

    <section id="bv-connections" class="bv-panel" aria-labelledby="bv-connections-title" hidden>
        <div class="bv-heading">
            <div>
                <h2 id="bv-connections-title" tabindex="-1">Connections</h2>
                <p id="bv-connections-label" class="text-muted"></p>
            </div>
            <div class="bv-actions">
                <button id="bv-refresh-connections" type="button" class="btn btn-default">Refresh</button>
                <button id="bv-close-connections" type="button" class="btn btn-default">Close</button>
            </div>
        </div>
        <p id="bv-connections-note" class="text-muted">These sessions traverse OPNsense. Counters are for the displayed states.</p>
        <div class="bv-scroll">
            <table class="table bv-table bv-connections-table">
                <thead>
                    <tr>
                        <th scope="col">Protocol</th>
                        <th scope="col">Source</th>
                        <th scope="col">Destination</th>
                        <th scope="col">State</th>
                        <th scope="col">Age</th>
                        <th scope="col">Traffic</th>
                    </tr>
                </thead>
                <tbody id="bv-connection-list"></tbody>
            </table>
        </div>
    </section>

    <details class="bv-panel" id="bv-tunnels" data-bv-panel="vpns" hidden>
        <summary>VPN exits</summary>
        <p class="text-muted">Choose an existing exit when multiple devices should share a tunnel.</p>
        <div class="bv-scroll">
            <table class="table bv-table bv-profiles">
                <thead>
                    <tr>
                        <th scope="col">Profile</th>
                        <th scope="col">Server</th>
                        <th scope="col">Tunnel</th>
                        <th scope="col">Latest handshake</th>
                        <th scope="col">Observed status</th>
                        <th scope="col"><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody id="bv-profile-list"></tbody>
            </table>
        </div>

        <div class="bv-grid" data-manage-only>
            <section aria-labelledby="bv-register-title">
                <h3 id="bv-register-title">Add a Mullvad exit</h3>
                <form id="bv-register-form">
                    <div class="bv-fields">
                        <label>Mullvad account number
                            <input id="bv-account" type="password" class="form-control" inputmode="numeric" autocomplete="off" maxlength="23">
                        </label>
                        <label>Profile name
                            <input id="bv-register-name" type="text" class="form-control" maxlength="64" placeholder="Defaults to server name">
                        </label>
                    </div>
                    <button id="bv-inspect-account" type="button" class="btn btn-default">Sign in to Mullvad</button>
                    <button id="bv-sign-out" type="button" class="btn btn-default" hidden>Sign out</button>
                    <div id="bv-account-status" class="bv-account-status" aria-live="polite"></div>
                    <div class="bv-heading bv-relay-heading">
                        <p id="bv-relay-status" class="text-muted" aria-live="polite">Relay catalog has not been loaded.</p>
                        <button id="bv-refresh-relays" type="button" class="btn btn-default">Refresh catalog</button>
                    </div>
                    <div class="bv-fields">
                        <label>Country <select id="bv-country" class="form-control"><option value="">All countries</option></select></label>
                        <label>City <select id="bv-city" class="form-control"><option value="">All cities</option></select></label>
                        <label>Exact server <select id="bv-relay" class="form-control" required><option value="">Select a server</option></select></label>
                    </div>
                    <p class="text-muted">Adding a new exit generates a WireGuard key on this router and uses one Mullvad device slot. Multiple LAN devices can share the same exit.</p>
                    <label id="bv-retarget-row" hidden>Reuse an unassigned Mullvad profile
                        <select id="bv-retarget" class="form-control"><option value="">Use a new profile</option></select>
                    </label>
                    <button type="submit" class="btn btn-primary">Add Mullvad exit</button>
                </form>
            </section>

            <section aria-labelledby="bv-import-title">
                <h3 id="bv-import-title">Import a WireGuard exit</h3>
                <form id="bv-import-form">
                    <label>Profile name <input id="bv-import-name" type="text" class="form-control" maxlength="80" required></label>
                    <label>WireGuard configuration
                        <textarea id="bv-import-config" class="form-control bv-config-text" rows="9" maxlength="16384" autocomplete="off" spellcheck="false" required></textarea>
                    </label>
                    <p class="text-muted">Paste a WireGuard configuration from your provider. For manual Mullvad setup, download one from the <a href="https://mullvad.net/en/account/wireguard-config" target="_blank" rel="noopener noreferrer">Mullvad WireGuard generator</a>.</p>
                    <button type="submit" class="btn btn-primary">Import exit</button>
                </form>
            </section>
            <section aria-labelledby="bv-native-title">
                <h3 id="bv-native-title">Use an OPNsense VPN tunnel</h3>
                <p class="text-muted">Set up the provider’s OpenVPN or WireGuard client in OPNsense and assign it an IPv4 gateway. Use this for NordVPN, ExpressVPN and other providers with manual configuration.</p>
                <form id="bv-native-form">
                    <label>Profile name <input id="bv-native-name" type="text" class="form-control" maxlength="64" required></label>
                    <label>VPN gateway <select id="bv-native-gateway" class="form-control" required></select></label>
                    <label>DNS resolver IPv4 address
                        <input id="bv-native-dns" type="text" class="form-control" autocomplete="off" spellcheck="false" required>
                    </label>
                    <button id="bv-native-add" type="submit" class="btn btn-primary">Add VPN exit</button>
                </form>
            </section>
        </div>
    </details>

    <details class="bv-panel" id="bv-proxies" data-bv-panel="proxies" data-manage-only hidden>
        <summary>Proxy servers and subscriptions</summary>
        <p id="bv-proxy-cores" class="text-muted"></p>
        <details id="bv-core-manager" class="bv-panel" hidden>
            <summary>Core updates and storage</summary>
            <div class="bv-heading">
                <p id="bv-core-storage" class="text-muted" aria-live="polite"></p>
                <button id="bv-core-check" type="button" class="btn btn-default">Check for updates</button>
            </div>
            <div class="bv-scroll">
                <table class="table bv-table">
                    <thead><tr><th scope="col">Core</th><th scope="col">Installed</th><th scope="col">Approved release</th><th scope="col">Actions</th></tr></thead>
                    <tbody id="bv-core-list"></tbody>
                </table>
            </div>
            <form id="bv-core-upload">
                <div class="bv-fields">
                    <label>Core <select id="bv-core-upload-id" class="form-control" required></select></label>
                    <label>Approved archive <input id="bv-core-archive" class="form-control" type="file" accept=".gz,.zip,application/gzip,application/zip" required></label>
                </div>
                <button type="submit" class="btn btn-default">Verify and install archive</button>
            </form>
            <p class="text-muted">Installing or rolling back a core briefly interrupts exits that use it.</p>
        </details>
        <div class="bv-grid">
            <form id="bv-proxy-import">
                <label>Proxy links or configuration
                    <textarea id="bv-proxy-body" class="form-control bv-config-text" rows="4"
                        placeholder="Proxy links, Clash YAML, Xray JSON or sing-box JSON" autocomplete="off" spellcheck="false" required></textarea>
                </label>
                <button type="submit" class="btn btn-primary">Import servers</button>
            </form>
            <form id="bv-subscription-form">
                <label>Subscription name
                    <input id="bv-subscription-name" class="form-control" type="text" maxlength="96" required>
                </label>
                <label>HTTPS subscription URL
                    <input id="bv-subscription-url" class="form-control" type="password" maxlength="2048" autocomplete="off" required>
                </label>
                <label class="bv-check"><input type="checkbox" id="bv-subscription-auto"> Refresh every six hours</label>
                <button type="submit" class="btn btn-primary">Add subscription</button>
            </form>
        </div>
        <details class="bv-panel">
            <summary>Add a proxy manually</summary>
            <form id="bv-proxy-manual">
                <div class="bv-fields">
                    <label>Server name <input id="bv-manual-name" class="form-control" maxlength="64" required></label>
                    <label>Protocol
                        <select id="bv-manual-protocol" class="form-control">
                            <option value="socks5">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option>
                            <option value="ss">Shadowsocks</option><option value="vmess">VMess</option><option value="vless">VLESS / REALITY</option>
                            <option value="trojan">Trojan</option><option value="hysteria">Hysteria</option><option value="hysteria2">Hysteria2</option>
                            <option value="tuic">TUIC</option><option value="anytls">AnyTLS</option><option value="snell">Snell</option>
                        </select>
                    </label>
                    <label>Hostname or IP <input id="bv-manual-host" class="form-control" maxlength="255" spellcheck="false" required></label>
                    <label>Port <input id="bv-manual-port" class="form-control" type="number" min="1" max="65535" required></label>
                    <label id="bv-manual-user-field"><span id="bv-manual-user-label">Username</span>
                        <input id="bv-manual-username" class="form-control" maxlength="255" autocomplete="off" spellcheck="false">
                    </label>
                    <label id="bv-manual-secret-field">Password or key
                        <input id="bv-manual-secret" class="form-control" type="password" maxlength="2048" autocomplete="off">
                    </label>
                    <label id="bv-manual-cipher-field" hidden>Cipher
                        <input id="bv-manual-cipher" class="form-control" maxlength="80" placeholder="aes-256-gcm">
                    </label>
                    <label id="bv-manual-params-field" hidden>Advanced link parameters
                        <input id="bv-manual-parameters" class="form-control" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="sni=example.com">
                    </label>
                </div>
                <p id="bv-manual-note" class="text-muted" hidden></p>
                <button type="submit" class="btn btn-primary">Save server</button>
            </form>
        </details>
        <div class="bv-scroll">
            <table class="table bv-table">
                <thead><tr><th scope="col">Subscription</th><th scope="col">Servers</th><th scope="col">Data and expiry</th><th scope="col">Last refresh</th><th scope="col">Actions</th></tr></thead>
                <tbody id="bv-subscription-list"></tbody>
            </table>
        </div>
        <div class="bv-heading">
            <label>Find a server <input id="bv-proxy-search" class="form-control" type="search" autocomplete="off"></label>
            <p id="bv-proxy-count" class="text-muted"></p>
        </div>
        <div class="bv-scroll">
            <table class="table bv-table">
                <thead><tr><th scope="col">Server</th><th scope="col">Protocol</th><th scope="col">Core</th><th scope="col">Actions</th></tr></thead>
                <tbody id="bv-proxy-list"></tbody>
            </table>
        </div>
        <p class="text-muted">Enable an individual server as an exit. It then appears in the device and Smart Routing selectors.</p>
    </details>

    <details class="bv-panel" id="bv-settings" data-bv-panel="settings" data-manage-only hidden>
        <summary>Routing settings</summary>
        <form id="bv-settings-form">
            <label class="bv-check"><input type="checkbox" id="bv-enabled"> Enable Blank VPN routing</label>
            <div class="bv-fields">
                <label>Dashboard hostname
                    <input id="bv-hostname" type="text" class="form-control" placeholder="blankvpn.home.arpa" autocomplete="off" spellcheck="false" maxlength="120">
                </label>
                <label>Bind dashboard IP
                    <select id="bv-dashboard-bind" class="form-control">
                        <option value="lan">Router LAN IPv4</option>
                        <option value="tailnet">Router Tailscale IPv4</option>
                    </select>
                </label>
                <label>Managed interfaces
                    <input id="bv-managed" type="text" class="form-control" placeholder="lan, opt1" autocomplete="off">
                </label>
                <label>Multi-Path interfaces
                    <input id="bv-smart-interfaces" type="text" class="form-control" placeholder="lan" autocomplete="off">
                </label>
                <label>Strict VPN interfaces
                    <input id="bv-strict" type="text" class="form-control" placeholder="opt1" autocomplete="off">
                </label>
                <label>Tailscale transit interfaces
                    <input id="bv-tailnet-interfaces" type="text" class="form-control" placeholder="opt2" autocomplete="off">
                </label>
                <label>Approved local networks
                    <input id="bv-local" type="text" class="form-control" placeholder="IPv4 or IPv6 CIDR ranges" autocomplete="off">
                </label>
            </div>
            <label class="bv-check">
                <input id="bv-smart-assigned" type="checkbox">
                Apply Multi-Path only to devices assigned that mode
            </label>
            <p id="bv-bind-address" class="text-muted" aria-live="polite"></p>
            <p class="text-muted">Add the dashboard name to the WebGUI alternate hostnames and use a trusted certificate. A LAN mDNS publisher can advertise blankvpn.local. Use the Tailscale address, MagicDNS, or split DNS for remote access.</p>
            <p id="bv-settings-note" class="text-muted">Use comma-separated interface IDs. Tailscale transit interfaces must preserve the peer's original IP addresses. Strict VPN interfaces block internet access for unassigned devices.</p>
            <button type="submit" class="btn btn-primary">Save routing settings</button>
        </form>
    </details>
</div>
