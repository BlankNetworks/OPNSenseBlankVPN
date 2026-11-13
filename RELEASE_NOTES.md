# Blank VPN 0.8.8

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Whole-Network coverage accepts LANs with delegated or automatically assigned IPv6 alongside static IPv4. Blank VPN uses current IPv6 prefixes when it resets existing internet sessions.
- Whole-Network proxy setup checks that the tunnel and firewall rules loaded. If they fail, the save reports the problem and restores the previous configuration.
- Failed server tests return a message or a log reference. Routing errors remain readable in day and night mode.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
