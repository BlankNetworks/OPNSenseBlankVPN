# Proxy core updates

Blank VPN includes a baseline build of Mihomo, tun2socks, Xray, and sing-box. Mihomo handles Clash-compatible proxy configurations. Xray and sing-box provide native outbound adapters. Passwall is an OpenWrt interface that manages several upstream cores. Use the FreeBSD builds of the applicable cores on OPNsense.

## Approve a release

Edit [the core catalog](src/share/blankvpn/core-catalog.json) on the repository’s main branch. Each entry specifies the core, numeric version, source, GitHub release tag, asset filename, and lowercase SHA-256. Blank VPN derives the HTTPS URL from these fields and accepts only its catalog repositories and release filename patterns.

| Core | Source value | Release tag | Archive |
| --- | --- | --- | --- |
| Mihomo | `upstream` | `vVERSION` | `mihomo-freebsd-amd64-compatible-vVERSION.gz` |
| tun2socks | `upstream` | `vVERSION` | `tun2socks-freebsd-amd64.zip` |
| Xray | `upstream` | `vVERSION` | `Xray-freebsd-64.zip` |
| Any bundled core, including sing-box | `blanknetworks` | `cores-CORE-vVERSION` | `CORE-VERSION-freebsd-amd64.gz` |

Use the vendor release digest or a digest independently verified against the reviewed archive. The sing-box release workflow takes the upstream version and matching commit and publishes the archive and checksum. Review changes to the catalog as you would executable package changes.

## Offline or local updates

The **Proxies → Core updates and storage** upload accepts an archive matching an approved catalog entry. An administrator can also use the OPNsense console. If the WebGUI upload limit is below the archive size, transfer the file over your existing management connection and use the root command below.

```sh
cd /usr/local/opnsense/scripts/OPNsense/BlankVpn
php cores.php check
php cores.php install mihomo /path/to/approved-mihomo.gz
php cores.php rollback mihomo
```

To install an independently reviewed local FreeBSD amd64 build, use `php cores.php install-local CORE VERSION FILE SHA256` as root. This path trusts the operator’s checksum and approval of the executable. The router verifies the file, executable version, and compatible saved exit configurations before activation.

The active and previous override binaries are stored separately from the package and survive upgrades. The bundled core remains available for the first rollback. A crash during activation leaves a recovery record for the next maintenance pass. Keep the state directory on persistent storage if you use OPNsense RAM disk settings.
