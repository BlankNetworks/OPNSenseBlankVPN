# Blank VPN 0.8.7

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Server rows use **Test**, **Edit**, **Enable**, and **Remove**. For an enabled proxy, **Disable** frees its routing slot and keeps the server in the catalog.
- Proxy tests include a regional HTTPS endpoint and report upstream TCP, SOCKS5 authentication, and TLS failures where available. SOCKS5 links and manual entries support TLS hostname verification and optional UDP.
- Blank VPN reuses the router’s Mullvad device registration when you switch servers. Existing tunnels are preserved. City, country, and worldwide batches remain available for browsing.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
