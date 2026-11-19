# China Rules snapshot data

`current.json.gz` is Blank VPN's normalized China-only routing snapshot. It contains domain rules, China IPv4/IPv6 ranges, and the supported CN hostname patterns. The full upstream GeoSite and GeoIP databases are parsed during the weekly build and are not redistributed here.

`manifest.json` records the generation time, the next scheduled weekly refresh (Monday at 06:00 UTC), entry counts, SHA-256 checksums, and the exact upstream feed URLs and hashes used for the snapshot. The package downloads these two files from this directory in the BlankNetworks repository.

## Upstream sources

- Domain and Apple domain lists: [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list), licensed under WTFPL v2. See [LICENSE-WTFPL-2.0](licenses/LICENSE-WTFPL-2.0).
- China IPv4 and IPv6 ranges: [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip), licensed under MIT. See [LICENSE-MIT-gaoyifan](licenses/LICENSE-MIT-gaoyifan).
- GeoSite CN hostname data: [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat), licensed under GPL-3.0. Its published data combines upstream domain sources; its notices and license are retained in [LICENSE-GPL-3.0](licenses/LICENSE-GPL-3.0).
- GeoIP CN ranges: [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) documents that its CN IPv4/IPv6 entries come from `gaoyifan/china-operator-ip`. The weekly parser extracts only CN records and does not redistribute the other GeoLite-derived country records.

This directory hosts a normalized snapshot for Blank VPN & Proxy. It is not an official fork, mirror, or endorsement by the upstream maintainers. The scheduled workflow validates source sizes, parsed counts, rule formats, and checksums before replacing the current snapshot. Failed or incomplete pulls leave the last published snapshot untouched.
