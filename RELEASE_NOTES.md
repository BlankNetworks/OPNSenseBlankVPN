# Blank VPN 0.8.9

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Network Settings lists LAN devices and Tailscale peers. Refresh checks the managed LAN for neighbors and shows available IP addresses, MAC addresses, and names. Select a row to fill a device routing rule.
- Proxy Login has a SOCKS5 filter and pagination. Subscriptions accept up to 2,048 entries and 4 MiB.
- Imported proxy servers are enabled for selection by default. Assigning a proxy starts its tunnel when routing is on. Disable is available for unassigned servers.
- Routing shows the active policy and server where the firewall confirms it. Per-device Multi-Path can use saved domain lists without enabling them for the whole interface.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
