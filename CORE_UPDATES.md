# Proxy core updates

Blank VPN & Proxy includes a baseline build of Mihomo, tun2socks, Xray, and sing-box. Mihomo handles Clash-compatible proxy configurations. Xray and sing-box provide native outbound adapters. Passwall is an OpenWrt interface that manages several upstream cores. Use the FreeBSD builds of the applicable cores on OPNsense.

## Approve a release

Core archives are downloaded from versioned releases in the Blank Networks repository for both supported architectures. Router downloads do not contact the core vendors. The [amd64 catalog](src/share/blankvpn/core-catalog.json) and [aarch64 catalog](src/share/blankvpn/core-catalog-aarch64.json) pin each asset's version, Blank release tag, filename, and SHA-256. The updater accepts only those repository releases and the expected core-specific archive names.

| Core | Verified upstream source | amd64 archive in Blank | aarch64 archive in Blank |
| --- | --- | --- | --- |
| Mihomo | MetaCubeX/mihomo | `mihomo-VERSION-freebsd-amd64.gz` | `mihomo-VERSION-freebsd-aarch64.gz` |
| tun2socks | xjasonlyu/tun2socks | `tun2socks-VERSION-freebsd-amd64.zip` | `tun2socks-VERSION-freebsd-aarch64.zip` |
| Xray | XTLS/Xray-core | `xray-VERSION-freebsd-amd64.zip` | `xray-VERSION-freebsd-aarch64.zip` |
| sing-box | SagerNet/sing-box, built by Blank from a pinned commit | `sing-box-VERSION-freebsd-amd64.gz` | `sing-box-VERSION-freebsd-aarch64.gz` |

The [Mirror approved proxy cores workflow](.github/workflows/mirror-cores.yml) copies the exact pinned upstream archives into Blank releases after checking their SHA-256 and verifying each contains a FreeBSD executable for the target architecture. It also verifies the already Blank-built sing-box assets. It runs when a core catalog or pinned source archive changes, and can be run manually. To approve a newer upstream version, review and update the version, source URL, and digest in `install_proxy_cores.py` and both catalogs; the workflow then publishes the matching Blank-hosted assets. A sing-box update is built from its pinned source through the [sing-box workflow](.github/workflows/cores.yml), after which its catalog entry can be approved and mirrored.

Blank release tags use `cores-CORE-vVERSION` for amd64 and `cores-CORE-vVERSION-aarch64` for ARM64. Each release includes a checksum file and retains source attribution in its release notes.

The catalog digest is checked against the reviewed upstream archive before publication, and the router checks that digest again before installing a core. Review version and digest changes as executable updates.

## Offline or local updates

The **Proxies → Core updates and storage** upload accepts an archive matching an approved catalog entry. An administrator can also use the OPNsense console. If the WebGUI upload limit is below the archive size, transfer the file over your existing management connection and use the root command below.

```sh
cd /usr/local/opnsense/scripts/OPNsense/BlankVpn
php cores.php check
php cores.php install mihomo /path/to/approved-mihomo.gz
php cores.php rollback mihomo
```

To install an independently reviewed local FreeBSD build for the router’s architecture, use `php cores.php install-local CORE VERSION FILE SHA256` as root. This path trusts the operator’s checksum and approval of the executable. The router verifies the file, executable version, and compatible saved exit configurations before activation.

The active and previous override binaries are stored separately from the package and survive upgrades. The bundled core remains available for the first rollback. A crash during activation leaves a recovery record for the next maintenance pass. Keep the state directory on persistent storage if you use OPNsense RAM disk settings.
