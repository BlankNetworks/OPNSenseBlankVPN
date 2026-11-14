- VPN Login has a VPN Service picker, an Add server action and a separate Saved VPN servers list. LAN and Tailscale assignments are managed in Network Settings.
- Adding another Mullvad server preserves existing tunnels and rules. Removed tunnels make their device keys available for reuse.
- Saved VPN servers show Standby, Ready, Error or Disabled. Error banners and failed tunnel test details can be dismissed.
- Mysterium VPN supports browser approval and location selection. IVPN supports account-ID sign-in and authenticator codes. Each allows one account-provisioned tunnel at a time.
- Additional NordVPN servers use isolated WireGuard sessions in the bundled Mihomo runtime.
- Browser, provider and routing fixtures exercise setup and state changes. Live paid-account sign-ins and simultaneous forwarding still require router testing.

## 0.8.15

- Per-device On Demand starts enabled for LAN and Tailscale routing rules. Kill Switch remains available per device.
- LAN devices can follow a unique DHCP reservation by MAC address. Blank VPN clears affected firewall states after applying an address change.
- System Settings adds theme selection, signed in-dashboard updates, and same-router routing backup and restore.
- The signed Blank Networks repository provides amd64 and ARM64 updates through OPNsense Firmware on supported 26.7 systems.
