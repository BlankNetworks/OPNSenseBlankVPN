# Blank VPN 0.4.0

This lab prerelease targets OPNsense Community Edition 26.7 on amd64 with the FreeBSD 15 package ABI.

- Sign in with a Mullvad account number and add an exact relay.
- Import a provider WireGuard configuration or attach an OPNsense OpenVPN or WireGuard gateway. The README covers NordVPN, ExpressVPN, Surfshark, and Proton VPN.
- Add proxy servers by form, share link, or HTTPS subscription. Subscriptions show quota and expiry when supplied by the provider.
- Assign each reserved IPv4 device to a VPN or proxy exit, select an IPv4 kill switch, or route domain suffixes using Smart Routing.
- Mihomo, tun2socks, Xray, sing-box, and PyYAML are included.

Download the `.pkg` and its SHA-256 file below. See the [installation and verification steps](https://github.com/BlankNetworks/OPNSenseBlankVPN#lab-installation) and [third-party source and license information](https://github.com/BlankNetworks/OPNSenseBlankVPN/blob/main/THIRD_PARTY.md). Live OPNsense forwarding and tunnel-drop behavior still need validation.

