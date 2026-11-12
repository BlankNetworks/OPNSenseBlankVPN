# Blank VPN 0.8.0

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- **Network** shows assigned Ethernet ports and VLANs as checkboxes, with simpler coverage choices and a list of saved device rules.
- Ping an individual Mullvad relay or test HTTPS through a configured VPN or enabled proxy exit.
- Save Mullvad sign-in on the router and restore it in later WebGUI sessions. Proxy subscriptions can refresh automatically and keep their saved servers when the provider is unavailable.
- The **Tailscale** tab shows the router connection, dashboard address and home exit-node advertisement. Configure peer routing through a source-preserving transit link.
- Import, edit and export Multi-Path domain lists. Save a list and choose its exit later.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
