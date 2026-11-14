<link href="{{ cache_safe('/ui/css/blankvpn.css') }}" rel="stylesheet">
<script src="{{ cache_safe('/ui/js/blankvpn.js') }}" defer></script>

<div id="blankvpn" class="blankvpn">
    <header class="bv-heading bv-hero">
        <h1>Blank VPN</h1>
    </header>

    <nav class="bv-navigation" aria-label="Blank VPN pages">
        <button type="button" data-bv-section="vpns" aria-controls="bv-tunnels" aria-pressed="true">VPN Login</button>
        <button type="button" data-bv-section="proxies" aria-controls="bv-proxies" aria-pressed="false" data-manage-only>Proxy Login</button>
        <button type="button" data-bv-section="network" aria-controls="bv-network-page" aria-pressed="false">Network Settings</button>
        <button type="button" data-bv-section="smart" aria-controls="bv-smart-page" aria-pressed="false">Multi-Path Settings</button>
        <button type="button" data-bv-section="tailscale" aria-controls="bv-tailscale-page" aria-pressed="false">Tailscale Settings</button>
        <button type="button" data-bv-section="system" aria-controls="bv-system-page" aria-pressed="false">System Settings</button>
    </nav>

    <div id="bv-message" hidden>
        <div role="status" aria-live="polite" aria-atomic="true">
            <strong id="bv-message-title" hidden>Action failed</strong>
            <span id="bv-message-detail"></span>
        </div>
        <button id="bv-message-dismiss" type="button" aria-label="Dismiss error" hidden>×</button>
    </div>
    <ul id="bv-warnings" class="alert alert-warning bv-warnings" hidden></ul>

    <section id="bv-tunnels" data-bv-panel="vpns" aria-label="VPN Login">
        <section class="bv-panel" aria-labelledby="bv-vpn-page-title" data-manage-only>
            <h2 id="bv-vpn-page-title">VPN Service</h2>
            <form id="bv-provider-picker" class="bv-inline-form">
                <label for="bv-provider" class="sr-only">VPN service</label>
                <select id="bv-provider" class="form-control" required>
                    <option value="mullvad">Mullvad</option>
                </select>
                <button type="submit" class="btn btn-primary">Apply</button>
            </form>
            <div class="bv-vpn-provider" id="bv-mullvad-provider">
                <div class="bv-heading">
                    <h3 id="bv-vpn-title">Mullvad VPN</h3>
                    <div class="bv-actions">
                        <button id="bv-restore-login" type="button" class="btn btn-default" hidden>Use saved login</button>
                        <button id="bv-sign-out" type="button" class="btn btn-default" hidden>Sign out</button>
                    </div>
                </div>
                <p id="bv-login-http" class="bv-callout" hidden>
                    Mullvad sign-in requires an HTTPS connection to OPNsense.
                    <a id="bv-secure-link">Open this page over HTTPS</a>, or enable HTTPS under
                    System → Settings → Administration if the router uses HTTP.
                </p>
                <form id="bv-login-form">
                    <label for="bv-account">Mullvad account number</label>
                    <div class="bv-inline-form">
                        <input id="bv-account" type="password" class="form-control" inputmode="numeric" autocomplete="off"
                            maxlength="23" placeholder="16-digit account number" required>
                        <button id="bv-inspect-account" type="submit" class="btn btn-primary">Sign in</button>
                    </div>
                    <label class="bv-check bv-save-login"><input id="bv-save-login" type="checkbox" checked> Save login on this router</label>
                </form>
                <div id="bv-account-status" class="bv-account-status" role="status" aria-live="polite"></div>

                <form id="bv-register-form" hidden>
                    <div class="bv-heading bv-relay-heading">
                        <h4>Choose a server</h4>
                        <button id="bv-refresh-relays" type="button" class="btn btn-default">Refresh servers</button>
                    </div>
                    <p id="bv-relay-status" class="text-muted" aria-live="polite"></p>
                    <div class="bv-fields">
                        <label>Country <select id="bv-country" class="form-control"><option value="">All countries</option></select></label>
                        <label>City <select id="bv-city" class="form-control"><option value="">All cities</option></select></label>
                        <label>Server <select id="bv-relay" class="form-control" required><option value="">Select a server</option></select></label>
                    </div>
                    <div class="bv-actions">
                        <p id="bv-relay-choice" class="text-muted" aria-live="polite"></p>
                        <button id="bv-test-relay" type="button" class="btn btn-default" disabled>Ping server</button>
                        <small id="bv-relay-test" class="bv-test-result" role="status"></small>
                    </div>
                    <div class="bv-fields">
                        <label>Tunnel name <input id="bv-register-name" type="text" class="form-control" maxlength="64"
                            placeholder="Defaults to server name"></label>
                    </div>
                    <div class="bv-actions">
                        <button id="bv-register" type="submit" class="btn btn-primary" disabled>Add server</button>
                        <p class="text-muted">Each saved Mullvad server has its own tunnel. Assign it in Network Settings.</p>
                    </div>
                </form>
            </div>
            <div id="bv-provider-panel" class="bv-vpn-provider" hidden>
                <div class="bv-heading">
                    <h3 id="bv-provider-title"></h3>
                    <button id="bv-provider-logout" type="button" class="btn btn-default" hidden>Sign out</button>
                </div>
                <p><a id="bv-provider-guide" target="_blank" rel="noopener noreferrer">Provider setup guide</a></p>
                <p id="bv-provider-status" role="status"></p>
                <div id="bv-myst-login" class="bv-actions" hidden>
                    <button id="bv-myst-begin" type="button" class="btn btn-primary">Sign in to Mysterium VPN</button>
                    <a id="bv-myst-approve" class="btn btn-default" target="_blank" rel="noopener noreferrer" hidden>Approve sign-in</a>
                    <button id="bv-myst-poll" type="button" class="btn btn-default" hidden>Check approval</button>
                </div>
                <form id="bv-ivpn-login" hidden>
                    <div class="bv-fields">
                        <label>IVPN account ID
                            <input id="bv-ivpn-account" type="password" maxlength="64" autocomplete="off" class="form-control" required>
                        </label>
                        <label id="bv-ivpn-confirmation-field" hidden>Authenticator code
                            <input id="bv-ivpn-confirmation" type="text" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" class="form-control">
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary">Sign in and save</button>
                </form>
                <form id="bv-provider-login" hidden>
                    <div class="bv-fields">
                        <label id="bv-provider-user-field">PIA username
                            <input id="bv-provider-user" type="text" maxlength="32" autocomplete="off" class="form-control">
                        </label>
                        <label><span id="bv-provider-secret-label">Access token</span>
                            <input id="bv-provider-secret" type="password" maxlength="512" autocomplete="off" class="form-control" required>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary">Sign in and save</button>
                </form>
                <form id="bv-provider-server-form" hidden>
                    <div class="bv-fields">
                        <label id="bv-myst-type-field" hidden>IP type
                            <select id="bv-myst-type" class="form-control">
                                <option value="hosting">Hosting</option>
                                <option value="residential">Residential</option>
                            </select>
                        </label>
                        <label id="bv-provider-country-field">Country code
                            <input id="bv-provider-country" type="text" maxlength="2" pattern="[A-Za-z]{2}" placeholder="Optional, e.g. JP" class="form-control">
                        </label>
                        <label>Server
                            <select id="bv-provider-server" class="form-control" required></select>
                        </label>
                        <label>Tunnel name
                            <input id="bv-provider-name" type="text" maxlength="64" placeholder="Defaults to server name" class="form-control">
                        </label>
                    </div>
                    <label id="bv-myst-dns-field" hidden>IPv4 DNS override
                        <input id="bv-myst-dns" type="text" maxlength="64" class="form-control">
                    </label>
                    <div class="bv-actions">
                        <button id="bv-provider-reload" type="button" class="btn btn-default">Load servers</button>
                        <button id="bv-provider-save" type="submit" class="btn btn-primary" disabled>Add server</button>
                    </div>
                    <p id="bv-provider-server-status" class="text-muted" role="status"></p>
                </form>
                <details id="bv-provider-manual">
                    <summary>Add from a VPN configuration</summary>
                    <form id="bv-provider-import">
                        <div class="bv-fields">
                            <label>Tunnel name
                                <input id="bv-import-name" type="text" maxlength="64" class="form-control" required>
                            </label>
                            <label>WireGuard file
                                <input id="bv-import-file" type="file" accept=".conf,.txt" class="form-control">
                            </label>
                            <label>IPv4 DNS override
                                <input id="bv-import-dns" type="text" maxlength="128" class="form-control">
                            </label>
                        </div>
                        <label>WireGuard configuration
                            <textarea id="bv-import-config" maxlength="16384" rows="5" spellcheck="false" class="form-control bv-config-text" required></textarea>
                        </label>
                        <button type="submit" class="btn btn-primary">Import WireGuard</button>
                    </form>
                    <form id="bv-provider-native">
                        <p class="text-muted">For OpenVPN or an existing WireGuard tunnel, configure it in OPNsense and assign it an IPv4 gateway.</p>
                        <div class="bv-fields">
                            <label>Tunnel name
                                <input id="bv-native-name" type="text" maxlength="64" class="form-control" required>
                            </label>
                            <label>OPNsense VPN gateway
                                <select id="bv-native-gateway" class="form-control" required></select>
                            </label>
                            <label>Tunnel IPv4 DNS
                                <input id="bv-native-dns" type="text" maxlength="64" class="form-control" required>
                            </label>
                        </div>
                        <button type="submit" class="btn btn-primary">Add tunnel</button>
                    </form>
                </details>
            </div>
        </section>
        <section class="bv-panel" aria-labelledby="bv-saved-vpn-title">
            <h2 id="bv-saved-vpn-title">Saved VPN servers</h2>
            <p class="text-muted">Use Network Settings to assign a saved server to devices or a whole network.</p>
            <div class="bv-scroll">
                <table class="table bv-table bv-profiles">
                    <thead>
                        <tr>
                            <th scope="col">Profile</th>
                            <th scope="col">VPN service and server</th>
                            <th scope="col">Status</th>
                            <th scope="col"><span class="sr-only">Actions</span></th>
                        </tr>
                    </thead>
                    <tbody id="bv-profile-list"></tbody>
                </table>
            </div>
        </section>
    </section>

    <section class="bv-panel" id="bv-proxies" data-bv-panel="proxies" data-manage-only hidden>
        <h2>Proxies</h2>
        <p id="bv-proxy-http" class="bv-callout" hidden>Open the WebGUI over HTTPS before submitting proxy credentials or subscription links.</p>
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
            <p class="text-muted">Installing or rolling back a core briefly interrupts tunnels that use it.</p>
        </details>
        <div class="bv-grid">
            <form id="bv-proxy-import">
                <label>Server name <span class="text-muted">(optional for a single proxy)</span>
                    <input id="bv-proxy-import-name" class="form-control" type="text" maxlength="64">
                </label>
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
                    <input id="bv-subscription-url" class="form-control" type="password" maxlength="8192" autocomplete="off" required>
                </label>
                <label class="bv-check"><input type="checkbox" id="bv-subscription-auto" checked> Refresh automatically every six hours</label>
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
        <p id="bv-proxy-count" class="text-muted" role="status"></p>
        <div class="bv-scroll">
            <table class="table bv-table">
                <thead><tr><th scope="col">Server</th><th scope="col">Protocol</th><th scope="col">Core</th><th scope="col">Actions</th></tr></thead>
                <tbody id="bv-proxy-list"></tbody>
            </table>
        </div>
        <div class="bv-actions" id="bv-proxy-pages" hidden>
            <button id="bv-proxy-prev" type="button" class="btn btn-default">Previous</button>
            <button id="bv-proxy-next" type="button" class="btn btn-default">Next</button>
        </div>
        <p class="text-muted">Imported servers are ready to assign. A proxy tunnel starts when a routing rule uses it.</p>
    </section>

    <div id="bv-network-page" data-bv-panel="network" hidden>
        <section class="bv-panel" aria-labelledby="bv-settings-title" data-manage-only>
            <div class="bv-heading">
                <h2 id="bv-settings-title">Routing coverage</h2>
                <button type="button" id="bv-disable-routing" class="btn btn-danger" hidden>Disable VPN</button>
            </div>
            <p id="bv-current-routing" class="bv-callout" aria-live="polite"></p>
            <form id="bv-settings-form">
                <label class="bv-coverage-choice">Who should use these routing rules?
                    <select id="bv-coverage" class="form-control">
                        <option value="device">Only Devices I choose</option>
                        <option value="network">Whole-Network coverage</option>
                    </select>
                </label>
                <fieldset class="bv-interface-group">
                    <legend>Interface</legend>
                    <div id="bv-managed" class="bv-interface-list"></div>
                </fieldset>
                <label class="bv-check" id="bv-network-kill-field" hidden>
                    <input type="checkbox" id="bv-network-kill" checked> Kill Switch
                </label>
                <div id="bv-network-fields" class="bv-fields" hidden>
                    <label>How should their internet traffic be routed?
                        <select id="bv-network-mode" class="form-control">
                            <option value="full">Use one VPN or proxy</option>
                            <option value="multi">Use domain lists (Multi-Path)</option>
                            <option value="full_multi">Whole-Network + Multi-Path</option>
                            <option value="blocked">Block internet</option>
                            <option value="disabled">Use regular internet</option>
                        </select>
                    </label>
                    <label id="bv-network-profile-field" hidden><span id="bv-network-profile-label">Saved server</span>
                        <select id="bv-network-profile" class="form-control"></select>
                    </label>
                </div>
                <p id="bv-coverage-note" class="text-muted" aria-live="polite"></p>

                <details class="bv-advanced" id="bv-advanced">
                    <summary>More routing options</summary>
                    <div id="bv-device-options">
                        <div id="bv-interface-rules" class="bv-interface-rules"></div>
                        <label class="bv-check">
                            <input id="bv-smart-assigned" type="checkbox">
                            Use domain lists only for devices with Multi-Path enabled
                        </label>
                    </div>
                    <label>Additional networks that should stay local
                        <input id="bv-local" type="text" class="form-control" placeholder="Example: 192.168.3.0/24"
                            autocomplete="off">
                    </label>
                </details>
                <div class="bv-actions">
                    <button type="submit" id="bv-save-routing" class="btn btn-primary">Save and Enable VPN</button>
                    <span id="bv-routing-enabled" role="status" hidden>VPN routing enabled</span>
                </div>
            </form>
        </section>
        <section id="bv-devices" class="bv-panel" aria-labelledby="bv-devices-title">
            <div class="bv-heading">
                <div>
                    <h2 id="bv-devices-title">Devices and routing rules</h2>
                    <p id="bv-observed" class="text-muted" role="status">Loading devices…</p>
                </div>
                <div class="bv-actions">
                    <button id="bv-refresh" type="button" class="btn btn-default">Refresh</button>
                    <button id="bv-add-device" data-manage-only type="button" class="btn btn-primary">Add device rule</button>
                </div>
            </div>
            <p id="bv-device-guide" class="text-muted">Refresh to find active LAN devices. Select a device to set up its routing rule.</p>
            <h3>LAN devices</h3>
            <div class="bv-scroll">
                <table class="table bv-table bv-devices" role="table">
                    <thead role="rowgroup">
                        <tr role="row">
                            <th scope="col" role="columnheader">Device</th>
                            <th scope="col" role="columnheader">Addresses</th>
                            <th scope="col" role="columnheader">Interface</th>
                            <th scope="col" role="columnheader">Assignment</th>
                            <th scope="col" role="columnheader">Status</th>
                            <th scope="col" role="columnheader"><span class="sr-only">Actions</span></th>
                        </tr>
                    </thead>
                    <tbody id="bv-device-list" role="rowgroup"></tbody>
                </table>
            </div>
            <details id="bv-tailnet-devices" class="bv-advanced">
                <summary><span class="bv-disclosure-link">Tailscale devices</span> <span id="bv-tailnet-count" class="text-muted"></span></summary>
                <p id="bv-tailnet-snat-note" class="text-muted">* For per-device routing through the OPNsense exit node, check <strong>Disable SNAT</strong> under <strong>VPN → Tailscale → Settings → Advanced</strong> and click <strong>Apply</strong>.</p>
                <p id="bv-tailnet-routing-hint" class="text-muted"></p>
                <button type="button" id="bv-add-tailnet-peer" class="btn btn-default" data-manage-only hidden>Add by Tailscale IP</button>
                <div class="bv-scroll">
                    <table class="table bv-table bv-devices" role="table">
                        <thead><tr><th scope="col">Device</th><th scope="col">Addresses</th><th scope="col">Availability</th>
                            <th scope="col">Rule</th><th scope="col">Routing</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
                        <tbody id="bv-tailnet-device-list" role="rowgroup"></tbody>
                    </table>
                </div>
            </details>
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
                            <option value="lan">LAN device</option>
                            <option value="tailnet">Tailscale peer</option>
                        </select>
                    </label>
                    <label>IPv4 address <input id="bv-ip" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                    <label id="bv-assignment-interface-field">Interface
                        <select id="bv-interface" class="form-control" required></select>
                    </label>
                    <label id="bv-mac-field">MAC address <input id="bv-mac" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                    <label id="bv-ipv6-field">IPv6 address <input id="bv-ipv6" type="text" class="form-control" autocomplete="off" spellcheck="false"></label>
                    <label>Routing mode
                        <select id="bv-mode" class="form-control">
                            <option value="full">All traffic through one server</option>
                            <option value="multi">Multi-Path</option>
                            <option value="full_multi">Base VPN + Multi-Path</option>
                            <option value="disabled">Off</option>
                            <option value="blocked">Blocked</option>
                        </select>
                    </label>
                    <label id="bv-profile-field"><span id="bv-profile-label">Saved server</span>
                        <select id="bv-profile" class="form-control"></select>
                    </label>
                    <label id="bv-failure-field">If the server fails
                        <select id="bv-failure" class="form-control">
                            <option value="backup">Use a backup server</option>
                            <option value="wan">Use normal internet</option>
                        </select>
                    </label>
                    <label id="bv-backup-field" hidden>Backup server <select id="bv-backup" class="form-control"></select></label>
                </div>
                <label class="bv-check" id="bv-device-bind-mac-field" hidden>
                    <input type="checkbox" id="bv-device-bind-mac" aria-describedby="bv-identity" checked>
                    Follow DHCP reservation by MAC
                </label>
                <label class="bv-check" id="bv-device-on-demand-field">
                    <input type="checkbox" id="bv-device-on-demand" aria-describedby="bv-device-on-demand-note" checked> On Demand
                </label>
                <p id="bv-device-on-demand-note" class="text-muted">Automatically uses this rule when the device connects.</p>
                <label class="bv-check" id="bv-device-kill-field">
                    <input type="checkbox" id="bv-device-kill" checked> Kill Switch
                </label>
                <p id="bv-identity" class="text-muted"></p>
                <p id="bv-route-note" class="text-muted"></p>
                <div class="bv-actions">
                    <button id="bv-save-device" type="submit" class="btn btn-primary">Save device rule</button>
                    <button id="bv-remove-assignment" type="button" class="btn btn-default" hidden>Remove assignment</button>
                </div>
            </form>
        </section>

    </div>

    <section id="bv-smart-page" class="bv-panel" data-bv-panel="smart" aria-labelledby="bv-smart-title" hidden>
        <div class="bv-heading">
            <div>
                <h2 id="bv-smart-title">Multi-Path Settings</h2>
                <p id="bv-smart-status" class="text-muted"></p>
            </div>
            <button id="bv-use-lan" data-manage-only type="button" class="btn btn-default">Set up Multi-Path on the main Ethernet port</button>
        </div>
        <form id="bv-service-form" class="bv-list-editor" data-manage-only>
            <div class="bv-fields">
                <label>Start from a preset
                    <select id="bv-service-preset" class="form-control"><option value="">Custom list</option></select>
                </label>
                <label>List name
                    <input id="bv-service-name" class="form-control" type="text" maxlength="64" required>
                </label>
                <label>Destination
                    <select id="bv-service-profile" class="form-control"></select>
                </label>
            </div>
            <label>Domains
                <textarea id="bv-service-domains" class="form-control bv-config-text" rows="7" maxlength="131072"
                    placeholder="netflix.com&#10;*.nflxvideo.net&#10;*.cn" spellcheck="false" required></textarea>
            </label>
            <div class="bv-actions bv-file-actions">
                <label>Import or replace from file
                    <input id="bv-service-file" class="form-control" type="file" accept=".txt,.csv,text/plain,text/csv">
                </label>
                <button id="bv-download-domains" type="button" class="btn btn-default" disabled>Download list</button>
            </div>
            <p id="bv-domain-file-status" class="text-muted" role="status"></p>
            <p class="text-muted">Enter domains one per line or separated by commas. A domain includes its subdomains. Use .cn or *.cn for every domain ending in .cn.
                Save a list now and choose a server when it’s ready.</p>
            <div class="bv-actions">
                <button id="bv-save-service" type="submit" class="btn btn-primary">Save list</button>
                <button id="bv-cancel-service" type="button" class="btn btn-default" hidden>Cancel edit</button>
            </div>
        </form>
        <div class="bv-scroll">
            <table class="table bv-table bv-services">
                <thead>
                    <tr>
                        <th scope="col">Service and domains</th>
                        <th scope="col">Server</th>
                        <th scope="col">Routing</th>
                        <th scope="col"><span class="sr-only">Actions</span></th>
                    </tr>
                </thead>
                <tbody id="bv-service-list"></tbody>
            </table>
        </div>
    </section>
    <div id="bv-tailscale-page" data-bv-panel="tailscale" hidden>
        <section class="bv-panel" aria-labelledby="bv-tailscale-title">
            <h2 id="bv-tailscale-title">Tailscale</h2>
            <p id="bv-tailscale-status" class="text-muted" role="status"></p>
            <div class="bv-actions">
                <a id="bv-native-tailscale" class="btn btn-default" href="/ui/tailscale/settings" hidden>Open OPNsense Tailscale settings</a>
                <a href="https://tailscale.com/docs/install/opnsense" target="_blank" rel="noopener noreferrer">Tailscale setup guide</a>
            </div>
            <p>To reach your home network while away, advertise the home subnets in OPNsense Tailscale settings and approve the routes in Tailscale. Enable and approve the exit node there to send internet traffic through home.</p>
        </section>
        <section class="bv-panel" aria-labelledby="bv-dashboard-title">
            <h2 id="bv-dashboard-title">Dashboard address</h2>
            <p><a id="bv-dashboard-link" href="https://blankvpn.home.arpa/ui/blankvpn/index">https://blankvpn.home.arpa/ui/blankvpn/index</a></p>
            <p id="bv-address-row" hidden>Direct IP address <a id="bv-address-link"></a></p>
            <p class="text-muted">Saving adds the dashboard name to OPNsense’s allowed hostnames. A trusted WebGUI certificate must cover the name for browsers to verify HTTPS.</p>
            <form id="bv-tailscale-form" data-manage-only>
                <div class="bv-fields">
                    <label id="bv-dashboard-hostname-field">Home dashboard name
                        <input id="bv-hostname" type="text" class="form-control" placeholder="blankvpn.home.arpa" autocomplete="off"
                            spellcheck="false" maxlength="120" required>
                    </label>
                    <label>Open the dashboard on
                        <select id="bv-dashboard-bind" class="form-control">
                            <option value="lan">Home Ethernet address</option>
                            <option value="tailnet">Tailscale address</option>
                        </select>
                    </label>
                </div>
                <div class="bv-actions">
                    <button type="button" id="bv-use-local-name" class="btn btn-default">Use blankvpn.local</button>
                </div>
                <p id="bv-bind-address" class="text-muted" aria-live="polite"></p>
                <details id="bv-bonjour" class="bv-advanced" hidden>
                    <summary>Publish blankvpn.local on your home network</summary>
                    <p>Run this in Terminal on a Mac on the same home network. Keep it running to make the name available to Bonjour clients.</p>
                    <p><code id="bv-bonjour-command"></code></p>
                </details>
                <section class="bv-advanced" aria-labelledby="bv-tailnet-routing-title">
                    <h3 id="bv-tailnet-routing-title">Route Tailscale devices through Blank VPN</h3>
                    <p id="bv-native-snat-status" hidden></p>
                    <p id="bv-native-tailnet-status" role="status"></p>
                    <p>In OPNsense Tailscale settings, enable <strong>Advertise Exit Node</strong> and the advanced <strong>Disable SNAT</strong> option. Apply from a local connection because Tailscale will restart. Approve the exit node in Tailscale, then select OPNsense as the exit node on each device.</p>
                    <details class="bv-advanced" id="bv-tailnet-routing">
                        <summary>Use a separate Tailscale gateway</summary>
                        <p>For an existing source-preserving gateway, select its dedicated Ethernet or VLAN link here.</p>
                        <fieldset class="bv-interface-group">
                            <legend>Interfaces carrying Tailscale device traffic</legend>
                            <div id="bv-tailnet-interfaces" class="bv-interface-list"></div>
                        </fieldset>
                    </details>
                </section>
                <div class="bv-actions">
                    <button type="submit" class="btn btn-primary">Save Tailscale settings</button>
                    <button type="button" id="bv-add-tailnet-device" class="btn btn-default" hidden>Add Tailscale device rule</button>
                </div>
            </form>
        </section>
    </div>
    <section id="bv-system-page" data-bv-panel="system" aria-labelledby="bv-system-title" hidden>
        <section class="bv-panel">
            <h2 id="bv-system-title">System Settings</h2>
            <div class="bv-fields">
                <label for="bv-appearance">Appearance
                    <select id="bv-appearance" class="form-control">
                        <option value="system">System theme</option>
                        <option value="day">Day</option>
                        <option value="night">Night</option>
                    </select>
                </label>
            </div>
        </section>
        <section id="bv-system-updates" class="bv-panel" aria-labelledby="bv-update-title" hidden>
            <h2 id="bv-update-title">Package updates</h2>
            <p id="bv-update-status" role="status"></p>
            <div class="bv-actions">
                <button type="button" id="bv-update-check" class="btn btn-default" disabled>Check for update</button>
                <button type="button" id="bv-update-apply" class="btn btn-primary" disabled>Update</button>
            </div>
        </section>
        <section id="bv-system-backups" class="bv-panel" aria-labelledby="bv-backup-title" hidden>
            <h2 id="bv-backup-title">Backup and restore</h2>
            <p class="text-muted">Back up routing settings, device rules and domain lists. Restore on this router using its existing tunnels.</p>
            <div class="bv-actions">
                <button type="button" id="bv-backup-download" class="btn btn-default">Download settings backup</button>
            </div>
            <div class="bv-fields">
                <label>Settings backup file
                    <input type="file" id="bv-backup-file" class="form-control" accept=".json,application/json">
                </label>
            </div>
            <p id="bv-backup-preview" role="status"></p>
            <div class="bv-actions">
                <button type="button" id="bv-backup-check" class="btn btn-default" disabled>Preview restore</button>
                <button type="button" id="bv-backup-restore" class="btn btn-primary" disabled>Restore settings</button>
            </div>
        </section>
    </section>
</div>
