<link href="{{ cache_safe('/ui/css/blankvpn.css') }}" rel="stylesheet">
<script src="{{ cache_safe('/ui/js/blankvpn.js') }}" defer></script>

<div id="blankvpn" class="blankvpn">
    <header class="bv-heading">
        <div>
            <h1>Blank VPN</h1>
            <p class="text-muted">Route selected services or IPv4 devices through a VPN or proxy exit.</p>
        </div>
        <button id="bv-refresh" type="button" class="btn btn-default">Refresh devices</button>
    </header>

    <div id="bv-message" class="alert" role="status" aria-live="polite" hidden></div>
    <ul id="bv-warnings" class="alert alert-warning bv-warnings" hidden></ul>

    <section class="bv-panel" aria-labelledby="bv-smart-title">
        <div class="bv-heading">
            <div>
                <h2 id="bv-smart-title">Smart Routing</h2>
                <p id="bv-smart-status" class="text-muted"></p>
            </div>
            <button id="bv-use-lan" data-manage-only type="button" class="btn btn-default">Set up Smart Routing on LAN</button>
        </div>
        <div class="bv-scroll">
            <table class="table bv-table bv-services">
                <thead>
                    <tr>
                        <th scope="col">Service and domains</th>
                        <th scope="col">VPN exit</th>
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

    <section class="bv-panel" aria-labelledby="bv-devices-title">
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
                <label>Local IP address <input id="bv-ip" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                <label>Interface
                    <input id="bv-interface" type="text" class="form-control" list="bv-interface-list" autocomplete="off" required>
                    <datalist id="bv-interface-list"></datalist>
                </label>
                <label>MAC address <input id="bv-mac" type="text" class="form-control" autocomplete="off" spellcheck="false" required></label>
                <label>Internet route <select id="bv-profile" class="form-control"></select></label>
                <label id="bv-failure-field">If the VPN fails
                    <select id="bv-failure" class="form-control">
                        <option value="block">Block IPv4 internet (kill switch)</option>
                        <option value="backup">Use a backup VPN</option>
                        <option value="wan">Use normal internet</option>
                    </select>
                </label>
                <label id="bv-backup-field" hidden>Backup VPN <select id="bv-backup" class="form-control"></select></label>
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

    <details class="bv-panel" id="bv-tunnels">
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
                    <button id="bv-inspect-account" type="button" class="btn btn-default">Check account</button>
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
                    <p class="text-muted">Adding a new exit registers a WireGuard device on this account.</p>
                    <label id="bv-retarget-row" hidden>Reuse an unassigned Mullvad profile
                        <select id="bv-retarget" class="form-control"><option value="">Use a new profile</option></select>
                    </label>
                    <button type="submit" class="btn btn-primary">Register and add exit</button>
                </form>
            </section>

            <section aria-labelledby="bv-import-title">
                <h3 id="bv-import-title">Import a WireGuard exit</h3>
                <form id="bv-import-form">
                    <label>Profile name <input id="bv-import-name" type="text" class="form-control" maxlength="80" required></label>
                    <label>WireGuard configuration
                        <textarea id="bv-import-config" class="form-control bv-config-text" rows="9" maxlength="16384" autocomplete="off" spellcheck="false" required></textarea>
                    </label>
                    <p class="text-muted">Paste a configuration exported for this router. It contains a private key.</p>
                    <button type="submit" class="btn btn-primary">Import exit</button>
                </form>
            </section>
        </div>
    </details>

    <details class="bv-panel" id="bv-proxies" data-manage-only>
        <summary>Proxy servers and subscriptions</summary>
        <p id="bv-proxy-cores" class="text-muted"></p>
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
        <div class="bv-scroll">
            <table class="table bv-table">
                <thead><tr><th scope="col">Subscription</th><th scope="col">Servers</th><th scope="col">Last refresh</th><th scope="col">Actions</th></tr></thead>
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

    <details class="bv-panel" id="bv-settings" data-manage-only>
        <summary>Routing settings</summary>
        <form id="bv-settings-form">
            <label class="bv-check"><input type="checkbox" id="bv-enabled"> Enable Blank VPN routing</label>
            <div class="bv-fields">
                <label>Dashboard hostname
                    <input id="bv-hostname" type="text" class="form-control" placeholder="opnsense.home.arpa" autocomplete="off" spellcheck="false" maxlength="120">
                </label>
                <label>Managed interfaces
                    <input id="bv-managed" type="text" class="form-control" placeholder="lan, opt1" autocomplete="off">
                </label>
                <label>Smart Routing interfaces
                    <input id="bv-smart-interfaces" type="text" class="form-control" placeholder="lan" autocomplete="off">
                </label>
                <label>Strict VPN interfaces
                    <input id="bv-strict" type="text" class="form-control" placeholder="opt1" autocomplete="off">
                </label>
                <label>Approved local networks
                    <input id="bv-local" type="text" class="form-control" placeholder="IPv4 or IPv6 CIDR ranges" autocomplete="off">
                </label>
            </div>
            <p class="text-muted">For clients using your regular resolver, add a local DNS record for the dashboard. Set the hostname in the OPNsense web GUI and use a trusted HTTPS certificate that covers it. To open the dashboard after login, set <code>ui/blankvpn/index</code> as Preferred landing page under System → Access → Users.</p>
            <p id="bv-settings-note" class="text-muted">Use comma-separated interface IDs. Smart Routing keeps the normal route for unmatched traffic. Strict VPN interfaces block internet access for unassigned devices and should use a dedicated network.</p>
            <button type="submit" class="btn btn-primary">Save routing settings</button>
        </form>
    </details>
</div>
