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
