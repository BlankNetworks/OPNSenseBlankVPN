# Release components

The full package includes separate upstream executables and a Python YAML parser. License files are installed under `/usr/local/share/blankvpn/licenses`.

| Component | Release | License | Source |
| --- | --- | --- | --- |
| Mihomo | 1.19.34 | GPL-3.0 | [Pinned source](https://github.com/MetaCubeX/mihomo/tree/0455d0d28c4526937380505153e65a843d8612e8) |
| tun2socks | 2.7.0 | MIT | [Pinned source](https://github.com/xjasonlyu/tun2socks/tree/8dda19e8e4613e014f0b12f3e624fdff5e5f23b3) |
| Xray-core | 26.11.9 | MPL-2.0 | [Pinned source](https://github.com/XTLS/Xray-core/tree/676eaf66f8f05d4d558ee7a74b4736623d3feeb9) |
| sing-box | 1.14.4 | GPL-3.0-or-later | [Pinned source](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2) |
| PyYAML | 6.0.3 | MIT | [Pinned source](https://github.com/yaml/pyyaml/tree/49790e73684bebad1df05ef8d828fa12f685bffb) |

The [release staging script](build/prepare-release.sh) verifies the upstream FreeBSD Mihomo, tun2socks, and Xray archives and builds sing-box from the pinned source. Its sing-box build includes QUIC, uTLS, WireGuard, gVisor, and gRPC. Feature availability is documented in [PROXY_SUPPORT.md](PROXY_SUPPORT.md).

Blank VPN bundles the [PIA WireGuard provisioning CA certificate](https://github.com/pia-foss/manual-connections/blob/master/ca.rsa.4096.crt) for PIA registration requests. It does not install the certificate into the system trust store.
