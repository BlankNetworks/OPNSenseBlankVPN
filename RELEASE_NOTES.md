## 0.8.66

- Run safe VPN bulk pings with a bounded four-request pool and a read-only probe endpoint; unavailable probe paths are reported as unverified without changing firewall state.
- Race independent HTTPS checks through one proxy test listener and bound manual test timeouts while keeping proxy core tests serialized.
- Update About and pinned SSH installer instructions.

## 0.8.65

- Host normalized China Rules snapshots in the Blank repository. A weekly GitHub workflow pulls upstream data, validates and publishes the snapshot; routers update from Blank's repository and show the last update and next scheduled pull.
- Record upstream sources, checksums, attribution and license texts with the hosted snapshot. Passwall remains a coverage inspiration; it is not an update source.
- Update About and pinned SSH installer instructions.

## 0.8.64

- Rename the built-in Multi-Path item to **China Rules**.
- Confirm successful downloads with **China Rules applied** and add a Details disclosure explaining sources, rule types, and Shadow matching.
- Replace the unclear Advanced matcher labels with **Route host patterns** and **Stop routing host patterns**.
- Update About and pinned SSH installer instructions.

## 0.8.63

- Send the China rule download and refresh operation as POST so Get Rules can initialize or update the built-in China list.
- Rename the Groups page to Group Lists.
- Update the About version and pinned SSH installer instructions.

## 0.8.62

- Keep provider DNS available for device and Whole-Network routes selected through a saved server group by verifying the active group member's installed tunnel rule.
- Allow Local and Tailscale Whole-Network and per-device routing to save **No VPN or Proxy** so those clients use the regular ISP path.
- Update the About version and pinned SSH installer instructions.

## 0.8.61

- Display the Blank VPN & Proxy name correctly in System Settings update status, including status text containing an incorrectly escaped ampersand.
- Update About and pinned SSH installation instructions for this release.

## 0.8.60

- Add an optional advanced DNS matcher for exact-name, keyword and regular-expression China rules. It starts in shadow mode; enabling it routes matches through the selected VPN, proxy or explicit WAN bypass resolver and learns answers only into the matching PF destination table.
- Keep regular-expression matching semantics without widening exact or pattern rules into DNS suffix rules. Existing suffix, address/CIDR and custom Multi-Path behavior remains on the existing dnsmasq and PF paths.
- Require verified tunnel DNS routes and their PF block guards before using provider DNS endpoints; unmatched provider resolvers fail closed when those checks are not present.
- Use Blank VPN terminology in the interface and backend documentation. OpenWrt Passwall is referenced only as inspiration for the built-in China rule coverage.

## 0.8.59

- Extend Blank's built-in China list with `geosite:cn` domains and `geoip:cn` IPv4/IPv6 ranges from maintained geographic data files, alongside China domain and route feeds. The rule coverage is inspired by OpenWrt Passwall.
- Parse the GeoSite and GeoIP protobuf data with bounded input sizes and validate the CN dataset before atomic replacement. Keep the prior dataset when any source is invalid or too small.
- Treat the China IPv4 and IPv6 CIDR providers as alternatives, so a failed mirror does not block a valid update from the other provider.
- Convert GeoSite regex entries to DNS suffixes only when the regular expression has identical suffix semantics. Keep exact-name, plain, and other regex entries out of routing and report their counts instead of silently widening their match.
- Surface GeoSite/GeoIP counts and the number of exact or pattern rules whose matching semantics differ from Blank's DNS-suffix/PF model, so those differences are visible to operators.
- Update the About and pinned SSH install documentation for 0.8.59.

## 0.8.58

- Add a built-in, unassigned China Multi-Path list seeded on install and upgrade. Refresh its large rule set from China domain and route sources inspired by OpenWrt Passwall, without storing the feed contents in `config.xml`.
- Store validated, merged China domain, IPv4, and IPv6 feeds in a compressed private runtime cache. Failed or unexpectedly small downloads keep the last working rules; updates show per-family counts and source status.
- Group large domain sets into compact DNS rules and use content-addressed PF tables so a refresh applies the new set without expanding ordinary custom-list limits.
- Keep the China list in routing backups as a source marker and destination selection; the large downloaded data is refreshed from its upstream feeds on the target router.
- Add the China feed update guidance and installer version to the About and SSH install documentation.

- VPN Login has a VPN Service picker, an Add server action and a separate Saved VPN servers list. LAN and Tailscale assignments are managed in Network Settings.
- Adding another Mullvad server preserves existing tunnels and rules. Removed tunnels make their device keys available for reuse.
- Saved VPN servers show Standby, Ready, Error or Disabled. Error banners and failed tunnel test details can be dismissed.
- Mysterium VPN supports browser approval and location selection. IVPN supports account-ID sign-in and authenticator codes. Each allows one account-provisioned tunnel at a time.
- Additional NordVPN servers use isolated WireGuard sessions in the bundled Mihomo runtime.
- Browser, provider and routing fixtures exercise setup and state changes. Live paid-account sign-ins and simultaneous forwarding still require router testing.

## 0.8.15

- Per-device On Demand starts enabled for LAN and Tailscale routing rules. Kill Switch remains available per device.
- LAN devices can follow a unique DHCP reservation by MAC address. Blank VPN & Proxy clears affected firewall states after applying an address change.
- System Settings adds theme selection, signed in-dashboard updates, and same-router routing backup and restore.
- The signed Blank Networks repository provides amd64 and ARM64 updates through OPNsense Firmware on supported 26.7 systems.

## 0.8.16

- **Check for update** and **Update** are the two controls for signed package updates in Blank VPN & Proxy. The first successful check adds the package source to OPNsense Firmware.
- Use a base VPN for ordinary internet traffic with Multi-Path service overrides under Whole-Network coverage or in an individual LAN or Tailscale device rule. Combined routing keeps the Kill Switch on.
- The proxy list keeps pagination and removes the duplicate search and protocol filters.
- Device discovery gathers independent router diagnostics concurrently and reuses the DHCP reservation index. The dashboard avoids rebuilding device tables on unrelated edits.

## 0.8.17

- Device discovery uses active LAN DHCP leases alongside ARP. Blank VPN & Proxy shows eligible LAN devices outside the current coverage and displays discovered clients while viewing Whole-Network coverage.
- Multi-Path lists accept domain suffixes, individual IP addresses and CIDRs in the same editor or import file. Explicit IPv4 targets route without DNS learning. The editor shows the exact wildcard syntax.

## 0.8.18

- The dashboard, OPNsense menu, documentation, and release use the name **Blank VPN & Proxy**. The installed package ID remains `os-blank-vpn` for in-place updates.
- Saved LAN rules show **Offline** when the device is out of view and remain editable. MAC-following rules keep a visible IPv4 address while a current DHCP binding is unavailable.
- **Whole-Network + Multi-Path** has an adjustable Kill Switch. With it off, ordinary traffic uses the ISP WAN if the base server fails. Service assignments remain in force.
- **Bypass (direct internet)** uses the ISP WAN for matching domains and IP ranges, including under combined routing. Explicit **Blocked** mode keeps denying internet access.
- Added a YouTube preset for video, image, and API hostnames. A successful server test can clear earlier failed health checks so the route is available sooner.

## 0.8.19

- Whole-Network coverage allows device renaming and a **Bypass VPN** exception for eligible LAN devices. Independent device routing rules are kept for **Only devices I choose**.
- Multi-Path learns addresses through the selected service resolver and filters HTTPS and SVCB hints for routed domains. Ordinary traffic retains the base VPN and base DNS behavior.
- **Test route** checks the saved service’s DNS answer and its live PF table and tunnel rule. Combined coverage also verifies the client DNS redirect when applying rules.

## 0.8.20

- Saved VPN and proxy servers have a dedicated **Ping** column. Testing, reading errors, or clearing results leaves the server rows and actions in place.
- Multi-Path builds its server choices once and renders destination pickers when the tab is open.
- Dashboard refresh reuses a single proxy catalog read and shares WireGuard route lookups within each request.

## 0.8.21

- Whole-Network and device Kill Switches keep public client traffic off the ISP path. Bypass is paused in protected scopes, and a detected outage on any required base or Multi-Path exit closes the scope. Protected DNS uses the selected tunnel or local-only resolution.
- Enabling protection or detecting an outage invalidates affected PF sessions. Unconfirmed device bindings temporarily block public IPv4 on their LAN or VLAN. LAN device rules with a Kill Switch also block public IPv6 on that interface, including temporary addresses.
- Background proxy restarts use bounded retry delays. Healthy workers are kept running, unused tunnels are skipped by routine probes, and idle subscription checks avoid loading the catalog. Failed subscription refreshes retain the last good servers.
- Obsolete firewall table files are cleaned up, and the Mihomo on-disk proxy cache is disabled. Upgrading restarts assigned proxy workers once to apply the cache setting.

## 0.8.22

- Fixed a 0.8.21 regression that blocked Whole-Network + Multi-Path when an override lacked a successful health check. Ordinary traffic and DNS keep using a healthy base. Unavailable overrides block their own destinations. The Kill Switch still blocks direct ISP fallback and closes the protected scope when the base fails.
- A checked Multi-Path rule without a base routes working service lists independently and blocks unmatched destinations.
- An unavailable health probe preserves the last confirmed tunnel status. A verified failure still closes the affected path, and a successful probe reopens it.
- The Network dashboard shows the active Whole-Network route for its devices. Saved individual rules are used when individual coverage is selected.

## 0.8.23

- Saved VPN and proxy servers use compact, aligned rows. Status and ping results stay on one line, and desktop actions sit side by side. The lists switch to a two-column layout when the dashboard has less room.

## 0.8.24

- Network Settings offers independent Local and Tailscale coverage, each with Whole-Network and Only Devices I choose. Multi-Path lists can apply to Local, Tailscale, or both. Existing peer rules and shared lists keep their previous scope.
- Matching Multi-Path destinations use their selected exits ahead of the base VPN or proxy. With Kill Switch enabled, a base outage blocks unmatched traffic while healthy overrides keep working. An unavailable override blocks its own destinations.
- Base and override status are displayed separately. Multi-Path route tests open in a dialog and the list fits narrow screens.

## 0.8.25

- Tailscale exit-node forwarding applies source NAT on the selected VPN or WAN interface and tracks the return traffic to the original peer.
- Whole-Network, individual device and Multi-Path policies share that forwarding path. Unassigned peers in individual coverage can use the regular exit-node WAN path. Protected peers and destinations retain their Kill Switch guards.
- The device table reserves a Ping column. Test fills it with the measured router HTTPS latency, and clicking the value shows whether OPNsense observed a completed connection from the device.

## 0.8.26

- Keep VPNs selected by Tailscale device rules and combined policies ready, including existing rules saved with On Demand. Active Multi-Path exits stay ready alongside the base.
- Clamp TCP on Tailscale VPN paths to fit Tailscale’s MTU and retain DNS return states across interfaces. Route tests check for the installed source NAT and return rule.

## 0.8.27

- Active managed WireGuard exits recover from missing owned runtime interfaces, peers, or default AllowedIPs. Maintenance caps repair attempts and preserves the Kill Switch while checking the recovered path.
- VPN health checks use two independent HTTPS destinations through individually verified firewall routes. Proxy health checks verify the processes and loopback listeners for each assigned exit and retry failed runtimes with backoff.
- Device route tests distinguish recent replies from unanswered TCP attempts, even when a router-side HTTPS probe succeeds.

## 0.8.28

- A successful VPN test requires a bidirectional firewall state on the selected tunnel. The exact test flows are excluded from WAN source NAT so a router connection through the ISP cannot pass as a VPN test.
- Managed WireGuard tests report a missing handshake and the upgrade discards older unverified positive tunnel results. Protected routes retain their fail-closed behavior.
- Saved Mullvad exits support UDP 51820 and 53. Changing a port reuses the existing WireGuard key and keeps the saved routing assignments.
- FreeBSD CI exercises Whole-Network and per-device TCP through real WireGuard peers and checks that a failed tunnel probe cannot fall back to the WAN.

## 0.8.29

- Saved VPN and proxy servers have selection checkboxes, Select all, and Remove selected. Proxy selection covers every page. Removal validates the selection and protects servers referenced by routing settings or device rules.
- Saved VPN servers show Port between Status and Ping.
- Proxy columns are Name, Server, Protocol, Core, Ping, and Action. Edit changes the display name while keeping the original server details and connection settings. Custom names survive subscription refreshes.

## 0.8.30

- Preserve the WireGuard source address for provider DNS over UDP and TCP before outbound WAN NAT. Protected Mullvad DNS now follows the selected tunnel.
- Match the client DNS destination port in OPNsense redirect rules, so Whole-Network and device queries reach the selected VPN or proxy resolver instead of the Kill Switch DNS block.
- Reset existing LAN internet sessions when activating Whole-Network protection, including sessions already translated to a WAN or VPN address. Accept OPNsense's native PF state-kill response while keeping local and Tailscale states outside the reset.
- Reset a device's translated internet sessions when its own routing or Kill Switch policy changes, while retaining other devices and management sessions.

## 0.8.31

- Tailscale readiness checks the daemon's live no-SNAT preference. os-tailscale 1.4 can enable its kernel interface without setting this preference; Blank VPN now explains the missing step instead of reporting peer routing ready.
- Document the protected Tailscale exit-node setup and physical iPhone tests through both a Swiss proxy and Mullvad WireGuard, including the distinction between Tailscale's direct-WAN userspace path and Blank VPN's PF path.

## 0.8.32

- Tailscale base and per-device route tests now identify offline peers when no completed client connection is observed. The result tells the operator to reconnect the test device, select OPNsense as its exit node, and retry. A router HTTPS probe still remains separate from client forwarding evidence.
- Multi-Path route-test and route-detail popups use explicit Close buttons, so the WebGUI can dismiss them even if it intercepts form submissions.
- Record physical iPhone verification of Chicago Whole-Network + Multi-Path routing with YouTube through Stockholm, including the offline-peer incident and recovery. Both WireGuard exits used UDP 51820; the Tailscale management connection and kill switch remained active.

## 0.8.33

- Add a version-pinned SSH installer for first installs and upgrades. It checks OPNsense and the package ABI, verifies the release package checksum, saves a protected configuration backup, and installs the matching architecture.
- Add a one-command SSH path to each release page while retaining the explicit package download, checksum, and installation steps.

## 0.8.34

- Separate blue Save from green Enable VPN and red Disable VPN in both Local and Tailscale routing. Saving a disabled scope keeps it disabled.
- Add serial Ping & Sort for proxy servers, with a stop control and successful HTTPS latencies ordered lowest first.
- Show Multi-Path server ping results in each list row instead of a popup, and add a Download action for every saved list.
- Leave the TUN driver unloaded until a proxy tunnel starts. A fresh install with Tailscale present but no Blank VPN policy no longer triggers a routing sync.

## 0.8.35

- Make Mullvad, password/token, and IVPN sign-in buttons work even when the OPNsense page intercepts form submission. Enter still submits the active sign-in form.
- Recheck router sign-in state when a completed request loses its browser response, including Mysterium approval and the IVPN authenticator step, so a manual page refresh is unnecessary.
- Follow the router's available OPNsense locales for language metadata, translated sign-in labels, and locale-aware dates and server sorting. Missing plugin-specific translations fall back to English.

## 0.8.36

- Keep native Tailscale exit-node traffic on the local ISP WAN when Blank VPN's Tailscale scope is manually disabled, whether or not Local Blank VPN routing remains enabled.
- Install only the peer WAN pass, reply state, and source NAT for that disabled scope. A missing ISP WAN gateway still leaves internet unavailable.

## 0.8.37

- Fix a WebGUI dashboard error caused by calling OPNsense's console-dependent locale helper from PHP CGI. Offer all 20 OPNsense 26.7 locales without that call.
- Add Ping All and Ping & Sort to saved VPN and proxy lists. Explain why pre-add Mullvad ICMP and saved-tunnel HTTPS timings differ, and why proxy Ping does not verify client TUN forwarding.
- Add a latest-release SSH installer that verifies the selected release's published installer digest before running its checksum-checked package installer. Keep version-pinned and manual package commands in every release.
- Remind Mullvad users to review and delete unused tokens or device registrations while keeping active router devices.
- Confirm on a physical iPhone using OPNsense as a Tailscale exit node that disabling Blank VPN's Tailscale scope restores local ISP HTTPS and DNS. A fresh WebGUI reload no longer shows the locale error after the live hotfix.

## 0.8.38

- Add Edit → Restore device for saved Mullvad tunnels whose WireGuard keys were removed from the Mullvad account. It re-registers the existing public key, updates any newly assigned tunnel addresses in the owned OPNsense WireGuard configuration, and keeps the saved server ID, client rules, and Multi-Path assignments.
- Keep the warning precise: a Mullvad device used by a saved tunnel is still needed even when Blank VPN routing is disabled. One live account had four such missing registrations; the remaining New Jersey registration passed a protected HTTPS test while the others had stale handshakes.

## 0.8.39

- Show **Offline** for discovered LAN devices even before a routing rule is saved. Keep offline LAN and Tailscale rows visible and their existing actions available.
- Refresh device availability every 30 seconds while Devices and Routing has focus. Update only the availability labels and badges, so editing controls and drafts retain focus. A failed availability check shows **Unknown** instead of retaining an old Online result.

## 0.8.40

- Reconcile saved Mullvad WireGuard registrations with the account every ten minutes when a protected login is saved. If a registration disappears, restore its existing public key and update the owned native tunnel address, one server per maintenance run. This preserves server IDs and routing rules. A missing registration was confirmed on four live tunnels; the actor that removed them remains unknown.
- Bound recovery retries and keep a per-key cooldown. Never remove another account device to make a slot. Show a dashboard warning when recovery cannot finish because the saved account is unavailable, a slot is full, or configuration apply fails.
- Clear a stale failed Mullvad Ping result after a newer protected tunnel probe succeeds, while keeping fresh failures visible.

## 0.8.41

- Retry a missing Mullvad device registration sooner after an HTTP 400 response. During live recovery, Mullvad briefly rejected a missing key, then accepted the same saved public key on retry. Keep a five-minute per-key cooldown and a separate longer backoff for other failures.
- Show a specific retry warning for that response instead of suggesting the saved login or account slots are wrong. A subsequent healthy account check clears the warning.

## 0.8.42

- Reuse one registered Mullvad WireGuard device key and address across this router's saved relay profiles. Adding another server on the same account no longer consumes another device slot. An existing saved server with no registered key must be repaired or consolidated before adding more servers.
- Route each tunnel's protected HTTPS probes and provider DNS with its own source-port range. This keeps simultaneously active relays distinguishable to PF even when they share the router's device address.
- Stop automatic recovery from recreating deleted legacy per-server registrations when the account already has a registered router key. Preserve the existing per-key retry behavior if no router key remains.
- Verify simultaneous shared-key forwarding across separate WireGuard exits in FreeBSD 15.1 and protected probes across five live Mullvad relays with one account device slot in use. Existing installations with multiple registered keys require consolidation of their saved profiles before those extra account devices can be removed.
- Confirm a Tailscale iPhone browses through the shared-key Chicago exit, with bidirectional client PF states on the selected WireGuard interface, working protected DNS, and loaded kill-switch guards. The Tailscale management connection remains available.

## 0.8.43

- Retry post-install routing reconciliation up to two times after the OPNsense backend restarts. On the live 0.8.42 upgrade, the first reconciliation returned a generic maintenance warning and the immediate manual retry succeeded while all five tunnels and client routing remained healthy.
- Confirm the migrated router's automatic Mullvad recovery reports healthy with only one registered account device and creates no additional keys.

## 0.8.44

- Rename the Proxy server-list column to **Name / Group**. Servers imported by a subscription show its saved group name above the server's display name; manually added servers continue to show their own name. Existing server identity, endpoint, subscription membership, and edit behavior remain unchanged.

## 0.8.45

- Show **No VPN or Proxy · local ISP** on unassigned Tailscale peers under **Only Devices I choose**, and explain this default beside the coverage selector. Removing a peer rule now explains its ISP fallback.
- Confirm on the live router that pausing an iPhone's Full rule sends fresh IPv4 traffic through WAN source NAT and returns the ISP address, while both a numeric-IP site and `example.com` load. Restore the Full rule after the test. No forwarding rule change was needed for this path.
- Exercise Full, Multi-Path, and unassigned Tailscale peers together in the isolated FreeBSD PF regression test. Run that test on every repository push alongside the WireGuard forwarding tests.
- Document Tailscale SSH check mode and its periodic reapproval under the SSH install instructions.

## 0.8.46

- Import decoded `ssr://host:port:protocol:cipher:obfs:password` links as well as base64-encoded SSR links. Keep an existing server's identity when the format changes, and use a link fragment as its display name when no SSR remarks field exists.
- Validate legacy Shadowsocks CFB and RC4 import fixtures with the bundled Mihomo core, plus VLESS XHTTP REALITY with the bundled Xray core. These configuration checks do not imply a particular remote endpoint is reachable or accepts the supplied account.
- Keep TLS certificate checks enabled. Live diagnostics confirmed the router's saved Shadowsocks and Trojan servers work; three saved VLESS REALITY profiles timed out through both Mihomo and Xray, while another REALITY profile worked through both. No client routing or Tailscale management setting was changed.

## 0.8.47

- Load installed core versions when the Proxies page opens, then refresh them when Core updates and storage opens. Show a loading or readable error row instead of an empty table, and add **Reload status** for a direct retry.
- Make installed core versions prominent and keep all four rows visible after **Check for updates**. Report the actual version of an installed system sing-box executable when the bundled one is absent.
- Cover the full four-core table, failed status response, retry, and update check in the browser fixture at desktop and mobile widths.
- Keep the core archive picker inside the Core panel on narrow screens; opening the panel no longer adds page overflow.

## 0.8.56

- Resolve proxy endpoint hostnames with encrypted bootstrap DNS in Mihomo, Xray, and sing-box instead of the router's ordinary system resolver. Keep proxy client DNS on the selected upstream and stop returning unsupported IPv6 answers from the proxy DNS listener.
- Block a known routed device IPv6 address from using ISP egress even when its IPv4 failure action is set to WAN.
- Add regression checks for encrypted proxy DNS configuration, single-device IPv6 fail-open, and document the tested privacy properties and limits for encrypted DNS, WebRTC, IPv6, and peer-to-peer traffic.

## 0.8.57

- In Multi-Path, show Service, Server, Routing, Ping, and Actions as separate columns. Give the Server selector a narrower maximum width and keep row actions wrapped within their column.
- When Ping is pressed for a server group, test the first server in its saved order and display that server's result in the Ping column.

## 0.8.55

- Fix group discovery after dashboard refresh. OPNsense model fields support property access but report `false` from `isset`; reading groups must iterate the model field directly.
- Add a regression test for OPNsense magic-property behavior so saved groups remain visible in Groups, Multi-Path, Whole-Network, and device routing choices after refresh.

## 0.8.54

- Keep the saved group name, members, and ID selected after **Save Group** so the just-saved list remains visible and another save updates it instead of creating a duplicate.
- When removing the group currently open in the editor, clear only that group draft and confirm that its saved VPN and proxy servers remain.
- Cover retained editor state, repeat-save idempotency, routing visibility, login-list separation, and server-preserving group removal in the browser fixture.

## 0.8.53

- Show a live Save Group result and reflect a successful save immediately in the saved group list and every routing server picker, even if a later dashboard refresh fails.
- Keep groups out of VPN Login and Proxy Login. Removing a group deletes only that named selection; its VPN and proxy member servers remain saved.
- Cover saved-list visibility, routing choices, login-list separation, and group-only removal in the browser fixture.

## 0.8.52

- Fix Mullvad tunnel creation when reusing the router's single device key across servers. Check the relay's public endpoint against the active WAN route, and do not mistake the already-local inner tunnel address for a remote WAN destination.
- Add a regression fixture for a WAN-routed relay endpoint alongside a reused WireGuard address that correctly routes to `lo0`.

## 0.8.51

- Make Mullvad **Add server** show its pending, successful, and failed state next to the button. Keep the button disabled during router operations so repeated clicks cannot be silently ignored.
- Show actionable inline guidance when the Mullvad session or server selection is unavailable, and retain the router error when registration fails.
- Cover rejected and successful Mullvad server additions in the responsive browser fixture.

## 0.8.50

- Load the saved VPN and proxy catalog when opening Groups and display a clear loading/error status instead of leaving the server pickers empty. Cover selecting, ordering, and saving VPN and proxy members in the browser fixture.
- Keep a group's current healthy member selected across service refreshes and firewall reloads. Advance to the next configured member only after the active member fails its health check.
- When every member fails, preserve Kill Switch behavior and continue probing one group member at a time. A successful probe resumes routing through the recovered member, which remains selected until it fails.
- Cover sticky selection, ordered advancement, full outage, and recovery behavior in routing regression fixtures.

## 0.8.49

- Add named routing groups with ordered VPN and proxy server members. Users can create and edit groups from the new Groups tab and select groups anywhere a routing destination is chosen.
- Add a backup server to Local and Tailscale Whole-Network coverage. Health checks move traffic to the next healthy group member or backup; when all configured choices fail, the existing Kill Switch policy decides whether traffic is blocked.
- Probe a rotating group member while every member is down, allowing recovered servers to be discovered without keeping every standby proxy runtime active.
- Persist groups and Whole-Network backups in routing backups, including compatibility with older backup files. Cover group failover, backup failover, Kill Switch, recovery probing, API validation, and the responsive Groups UI.

## 0.8.48

- Give Local and Tailscale **Devices and Routing Rules** tables the same Device, Address, Availability, Server, Routing, and Ping columns. Keep the interface name beneath a LAN address and update Availability during device presence polls.
- Add an inline Server dropdown with blue **Save**, **Cancel**, and **Edit** for each manageable device. A server change remains a draft until Save; Cancel restores the saved server. Replace **Select** with **Edit** for unassigned devices.
- Save a new individual Full rule or change an existing Full rule directly from the row. Preserve an existing Base VPN + Multi-Path mode, Kill Switch, backup, On Demand, and MAC binding when changing its base server. Apply saved changes through the existing validated assignment API and switch current sessions when possible. Whole-Network, Multi-Path-only, blocked, and paused rules continue to use Edit or their enable control for policy changes.
- Cover local and Tailscale inline saving, cancellation, refresh preservation, new-device assignment, availability, and responsive table layout in the browser fixture.
