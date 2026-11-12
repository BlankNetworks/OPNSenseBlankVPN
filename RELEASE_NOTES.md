# Blank VPN 0.5.0

This lab prerelease targets OPNsense Community Edition 26.7 on amd64 with the FreeBSD 15 package ABI.

- Update Mihomo, tun2socks, Xray, and sing-box independently from the plug-in. The core manager checks approved releases and uploads, shows disk space, and supports rollback.
- Choose Full Tunneling, Multi-Path Tunneling, Disabled, or Blocked for an assigned device. Multi-Path supports concurrent service exits, with Netflix, Hulu, and WeChat presets.
- Use the LAN or detected Tailscale IPv4 address as the dashboard binding. Tailscale peer policies require an ingress that preserves the peer’s original addresses.
- Sign in with a Mullvad account number. Adding an exact relay creates and registers a router WireGuard key. Website-generated configurations can also be imported.
- Choose System, Day, or Night appearance in the WebGUI.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
