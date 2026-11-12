# Blank VPN 0.8.2

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- **Save and Enable VPN** enables the saved Network rules. The save button turns green once OPNsense reports routing enabled.
- **Kill Switch** is available per device and below **Interface** for Whole-Network coverage. It blocks WAN fallback in one-exit mode. In Multi-Path it blocks internet for the selected scope and resets existing connections when an assigned exit is detected offline.
- **Tailscale → Dashboard address → Use blankvpn.local** selects the LAN address and shows a Bonjour publishing command. The direct IP link remains available.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
