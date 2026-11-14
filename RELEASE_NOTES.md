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
