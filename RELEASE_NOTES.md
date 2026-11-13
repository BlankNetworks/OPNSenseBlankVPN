# Blank VPN 0.8.5

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Proxy and VPN tests show results in each server’s row. Fixed a PHP cURL constant that could turn proxy failures into unexpected errors. Manual proxy tests can retry through a second HTTPS destination.
- Save entire Mullvad cities, countries, or the worldwide catalog. Activate servers in a batch up to Mullvad’s available device slots.
- The Tailscale dashboard uses the router’s MagicDNS hostname and shows its direct tailnet IP. Saving allows the hostname in OPNsense while preserving existing aliases.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
