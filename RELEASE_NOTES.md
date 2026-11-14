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
