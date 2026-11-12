# Blank VPN 0.7.0

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Navigate four pages with a slate and navy theme and single native dropdown indicators.
- Sign in to Mullvad over HTTPS. This release uses OPNsense 26.7’s request wrapper, opens the server picker after sign-in, and shows the selected location before you add an exit. Mullvad is the available account integration.
- Choose device-specific or whole-network coverage on selected LANs and VLANs.
- Import, edit, and export Multi-Path domain lists. Save a list with no exit assigned, then link a VPN or proxy when ready. The Netflix, Hulu, and WeChat presets are available as starting lists.
- Enter proxies individually, import share links, or add a subscription under Proxies.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
