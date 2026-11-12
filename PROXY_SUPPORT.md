# Blank VPN proxy support

Blank VPN imports individual upstreams and can enable up to eight proxy exits. Each enabled node gets a FreeBSD tunnel, private loopback SOCKS and DNS listeners, and a distinct exit in Multi-Path and device policies. The router's existing local and default routing remain the base. Enabled proxy exits are scoped to matched IPv4 traffic. UDP forwarding depends on upstream protocol and transport. IPv6 follows the existing Blank VPN policy, including its strict-interface and learned-destination guards.

## Cores and formats

| Core | Accepted inputs and coverage |
| --- | --- |
| Mihomo 1.19.34 | HTTP, HTTPS, SOCKS5, Shadowsocks including supported stream and AEAD ciphers and SS2022, SSR, VMess, VLESS, Trojan, Hysteria 1 and 2, TUIC, AnyTLS and Snell. Structured Clash nodes also cover the supported WireGuard, SSH, Mieru, MASQUE, Sudoku, ShadowQUIC, GOST relay and TrustTunnel adapters. The core validates each cipher and transport. |
| Xray 26.11.9 | VLESS links using XHTTP, KCP or VLESS Encryption, and individual native HTTP, SOCKS, Shadowsocks, VMess, VLESS, Trojan and Hysteria outbounds. Native structured outbounds can specify compatible transports including REALITY, Vision, XHTTP and supported FinalMask fields. |
| sing-box 1.14.4 | Individual native outbounds for HTTP, SOCKS, Shadowsocks, VMess, VLESS, Trojan, Hysteria 1 and 2, TUIC, AnyTLS, SSH, Naive and ShadowTLS. The bundled FreeBSD build includes QUIC, WireGuard, uTLS, gVisor, and gRPC. Naive requires a sing-box build with Naive outbound support. |
| tun2socks 2.7.0 | FreeBSD IPv4 TUN bridge. Blank VPN programs the gateway rules and runs the proxy engines on loopback. |

The import panel accepts newline-separated links, base64 URI lists, Clash YAML or JSON proxy entries, and native JSON outbound objects or arrays. A provider configuration can include other application settings. The importer extracts individual proxy nodes from the document. TLS certificate verification remains enabled, and file-based credentials, privileged routing settings, and arbitrary chaining are excluded. An explicit plain HTTP or SOCKS endpoint can be used on a trusted network. Imported legacy options are shown in the catalog and remain inactive until an exit is enabled.

For paired plugins or custom protocol settings, use a compatible structured node. A format may parse successfully while a particular core build rejects its cipher, credentials, or transport.

## Source index coverage

The supplied source index was used to identify protocol families, official core schemas, and router integration boundaries. The sources include categories that serve different roles.

| Index sections | Relationship to this implementation |
| --- | --- |
| 01–11 and 29 | Runtime families and compatibility references. Mihomo covers Clash-compatible nodes and several legacy variants. Xray and sing-box have native adapters. Proprietary or vendor-specific nodes require a compatible upstream implementation. |
| 12–15, 19–20 and 28 | Linux router integrations, management panels, installer examples, and client UI references. Blank VPN uses native OPNsense rule and process management. |
| 16–18 and 31 | Subscription parsing and provider format references. WannaFlix and SSRDOG are usable when the supplied feed returns a supported format. Subscription URLs and credentials stay on the router. |
| 21–23 | DNS learning, ordinary proxy protocols, and TUN forwarding. Multi-Path uses PF destination tables and the FreeBSD TUN bridge. |
| 24–27 and 30 | Separate tunnel products, Tor transports, research projects, and Ombra or Obscura references. These need their own verified FreeBSD adapter or a compatible standard proxy endpoint. |

Juicity, raw legacy V2Fly engine execution, separate Trojan forks, full provider-driven proxy groups, and product-specific protocols without a compatible adapter still need implementation. Linux eBPF paths, arbitrary router scripts, and server panel features are outside the client routing adapter.

## Operations

An HTTPS subscription fetch uses a public resolved address and TLS verification. Imported servers remain inactive until you enable them. Refreshes retain the prior usable list on error and retain enabled node configurations when a provider removes or rotates them. Remove an old exit and enable the new node when you want to adopt changed credentials or transport settings.

Proxy transport settings and subscription URLs are saved in the private `/var/db/blank-vpn/proxy-catalog.json` file. Native OPNsense configuration stores the route reference. Back up both when migrating routers, and treat the private catalog as a credential file. The full release installs the pinned cores to `/usr/local/libexec/blankvpn`. The source build also recognizes a root-owned OPNsense sing-box executable at `/usr/local/bin/sing-box`.

Validate a new core in a lab before enabling a production exit. Check that the SOCKS and DNS listeners bind to loopback, that the selected upstream carries traffic, and that loss of the upstream or FreeBSD tunnel leaves protected routes blocked. Verify UDP and DNS independently for each protocol.

## Upstream documentation

- [Mihomo configuration](https://wiki.metacubex.one/en/config/) and [releases](https://github.com/MetaCubeX/mihomo/releases)
- [Xray transport documentation](https://xtls.github.io/en/config/transport.html) and [releases](https://github.com/XTLS/Xray-core/releases)
- [sing-box outbound documentation](https://sing-box.sagernet.org/configuration/outbound/) and [OPNsense sing-box port](https://github.com/opnsense/ports/tree/master/net/sing-box)
- [tun2socks](https://github.com/xjasonlyu/tun2socks)
- [Shadowsocks AEAD and SS2022 specifications](https://shadowsocks.org/) and [ShadowsocksR protocol documentation](https://github.com/shadowsocksrr/shadowsocks-rss)
