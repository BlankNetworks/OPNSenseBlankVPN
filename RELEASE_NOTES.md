# Blank VPN 0.8.4

This lab prerelease targets OPNsense Community Edition 26.7 with the FreeBSD 15 package ABI.

- **amd64** supports x86-64 OPNsense appliances and VMs.
- **aarch64** supports matching community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs.
- Both packages bundle architecture-matched Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. Core updates and uploaded archives use the router’s CPU architecture.

Use `pkg config ABI` on the router to choose the matching download.

- Test a saved VPN exit with device routing off. Blank VPN verifies the protected router-side probe rule before sending a request.
- Test saved proxy servers with a temporary local listener. Blank VPN loads the TUN driver when a routed exit needs it and uses the router’s resolver to look up proxy endpoints.
- HTTPS subscriptions support validated redirects and IPv4 or IPv6 provider addresses. Failures report the relevant download or import stage without exposing subscription tokens.
- Day and night modes set readable text and background colors for selected interfaces, focused controls, and table cells.

Download the `.pkg` and SHA-256 file below. See the [installation instructions](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding, core rollback, and tunnel-drop behavior still need lab validation.
