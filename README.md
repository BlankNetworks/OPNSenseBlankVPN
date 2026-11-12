# Blank VPN 0.3.0

Blank VPN is an OPNsense plug-in for assigning Mullvad WireGuard and individually selected proxy exits to services and IPv4 addresses. Smart Routing keeps normal internet as the default on selected LANs and routes destinations learned from service DNS through the configured exit. Several services and clients can share an exit. The dashboard uses OPNsense WebGUI login and permissions.

## Compatibility

This lab candidate targets **OPNsense Community Edition 26.7.x**, **amd64**, package ABI **`FreeBSD:15:amd64`**. It uses the standard WebGUI process mode and the 26.7 native WireGuard and firewall implementation. This package was cross-built on macOS and has yet to be installed or exercised on OPNsense. See [VALIDATION.md](VALIDATION.md) for the tests and deployment gates.

## Build

Run the following from the source directory on a matching OPNsense lab host to build with FreeBSD `pkg create` and verify with `pkg info -F`.

```sh
python3 build/package.py
```

On another development host, build the same package format with the cross-build path. This also checks the manifest, scripts, payload hashes, ownership and permissions.

```sh
python3 build/package.py --cross
```

The package and SHA-256 file are written to `dist/`. No package repository needs to be added to OPNsense.

## Lab installation

1. Use an OPNsense CE 26.7 amd64 VM or spare router with console access. Attach a WAN, a management network and a test client LAN or VLAN. Back up the lab configuration under **System → Configuration → Backups**.
2. Confirm `opnsense-version -v` reports 26.7.x, `opnsense-version -n` reports `opnsense`, and `pkg config ABI` reports `FreeBSD:15:amd64`.
3. Transfer the package and checksum to the lab system. From their directory, verify and install as root.

   ```sh
   sha256 -c "$(awk '{print $1}' os-blank-vpn-0.3.0.pkg.sha256)" os-blank-vpn-0.3.0.pkg
   pkg info -F ./os-blank-vpn-0.3.0.pkg
   pkg add ./os-blank-vpn-0.3.0.pkg
   pkg info os-blank-vpn
   ```

4. Sign in using the current WebGUI HTTPS address and open **VPN → Blank VPN → Devices** or `/ui/blankvpn/index`. Routing starts disabled. The installer registers the dashboard, model, firewall hook, and local maintenance entry.
5. For delegated access, assign **VPN: Blank VPN: View devices and connections** or **VPN: Blank VPN: Manage tunnels and policy routing** in the native user manager. Confirm ACL behavior before delegating either permission.

## Local dashboard address

The default name is `opnsense.home.arpa`. For regular LAN clients, add a host override with the management IPv4 address in the resolver that serves the LAN. For Unbound, use **Services → Unbound DNS → Overrides** and enter host `opnsense` and domain `home.arpa`. Add the full hostname to **System → Settings → Administration → Alternate Hostnames** and select an HTTPS certificate with that hostname in its SAN. The client must trust the issuing CA. Use a local DNS exception on devices that exclusively use an external encrypted resolver.

The managed IPv4 DNS listener serves the configured hostname at the static LAN address. Allow client access to the management IP and GUI port through the existing firewall policy where intended. Use `https://opnsense.home.arpa/ui/blankvpn/index`, including the configured GUI port when it differs from 443. In **System → Access → Users**, set **Preferred landing page** to `ui/blankvpn/index` for any user who wants to open Blank VPN after sign-in.

## Add a Mullvad exit

1. Open the WebGUI over HTTPS and go to **VPN exits**. Enter the Mullvad account number locally, select **Check account**, then choose a country, city, and exact server. For the Netflix example choose Japan. The account number and token are used for the request and kept out of configuration and logs.
2. Choose **Register and add exit**. For a new exit, Blank VPN checks the available slot, generates the private key locally, and verifies the native peer and tunnel. An interrupted registration retains a private recovery key for retry with the same account and server. New registrations record a router-specific account binding, which is checked when an existing exit is requested with an account number.
3. To use your own WireGuard configuration, import a single-peer, full-tunnel configuration with an IPv4 endpoint. An endpoint hostname must resolve to IPv4. Smart Routing requires an IPv4 DNS address on the exit.

## Add proxy servers and subscriptions

Install the upstream FreeBSD proxy runtimes on a matching test router.

```sh
/usr/local/bin/python3.13 /usr/local/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py --xray
```

The command installs Mihomo and tun2socks, with Xray selected by the flag. It verifies SHA-256 hashes from pinned upstream releases. Add the OPNsense `sing-box` package if available for native sing-box outbounds. Clash YAML uses `py313-yaml` from the OPNsense package feed. Review [PROXY_SUPPORT.md](PROXY_SUPPORT.md) for formats, exact versions, routing behavior, and coverage.

1. Open **Proxy servers and subscriptions** over HTTPS. Paste links, a base64 list, a Clash proxy list, or individual native Xray or sing-box outbounds. Alternatively, add an HTTPS subscription URL.
2. Search the imported servers and choose **Enable exit** on the specific server. Each enabled server gets its own exit. Subscription refresh preserves existing selections even when a provider renames or removes a node.
3. Select the exit under **Smart Routing** or **Devices**. A per-IPv4 assignment can use the same kill switch or backup policy as a WireGuard exit. UDP support depends on the selected upstream protocol and transport. IPv4 proxy routing and live failover need native lab verification.

## Route Netflix or another service

1. Select **Set up Smart Routing on LAN** and save the settings. For another network, add its interface ID under both **Managed interfaces** and **Smart Routing interfaces**. Leave strict mode disabled for those interfaces. The router needs a working native resolver on `127.0.0.1:53` and the OPNsense Dnsmasq package with PF ipset support.
2. Under **Smart Routing**, choose **Netflix**, select your Japan exit, and add the service. The preset includes Netflix website and media domains such as `netflix.com`, `nflxvideo.net`, and `nflximg.net`. For a custom service, enter your own domain suffixes. Both `netflix.com` and `*.netflix.com` cover the apex and its subdomains.
3. On the test client, restart the application and refresh its DNS cache. Use ordinary DNS on the managed interface for the test. Check that the learned address count increases and use the router’s packet captures to confirm the intended tunnel and ordinary WAN traffic separately.

Smart Routing forwards matching DNS through the chosen tunnel and uses the regular resolver for other names. Learned IPv4 destinations use the VPN and learned IPv6 destinations are blocked. When the exit is unavailable, known destinations are blocked. Smart Routing classifies DNS-observed IPs. Shared IPs, existing connections, encrypted DNS, HTTPS record address hints, and endpoints obtained without an observed DNS lookup can affect which connections match. If two services learn the same destination IP, the first saved service rule has precedence. Learned entries are aged out after about a day and relearned from DNS. Mullvad exit IPs may be blocked by Netflix. [Mullvad Netflix guidance](https://mullvad.net/en/help/watching-netflix-with-split-tunneling)

## Assign an IPv4 address and enable a kill switch

1. Add the test client’s LAN or VLAN under **Managed interfaces**. Give the client a unique IPv4 DHCP reservation and select it in **Devices**.
2. Choose an exit and **Block IPv4 internet (kill switch)**. Applying a new kill switch resets connections originating from that address, including local sessions. Other clients continue to use their configured routes. The rules preserve configured local network exceptions for new connections.
3. Verify normal traffic from an unassigned test client. Confirm the protected client’s egress goes through WireGuard, then disable the test tunnel and check that its IPv4 internet traffic stops and the unassigned client stays online.
4. If you need to block internet-bound IPv6 for a whole device, use a dedicated **Strict VPN interface**. Strict mode blocks internet-bound IPv6 and internet traffic from unassigned devices. The per-IP rule on a shared LAN covers the reserved IPv4 address. Keep the IPv6 behavior of your existing firewall in mind.

Per-IP rules take precedence over Smart Routing. A selected **Backup VPN** can carry the address when the primary fails. **Normal internet** is an explicit fallback to the normal network policy. VPN health is observed with a router-side probe, while the client path must be checked from that client.

## Upgrade, rollback and removal

- **Upgrade** in a validated lab first. Export the OPNsense configuration, retain the previous package, and verify the new checksum. Use `pkg add -f ./os-blank-vpn-NEW.pkg`. Confirm ACLs, the active PF rules, DNS, and both tested exit paths after the upgrade.
- **Roll back routing** by disabling Blank VPN from the independent management connection. Review native policy after reload. Existing traffic states can remain until expiry or a targeted state reset. Use the console and OPNsense configuration history if the dashboard is inaccessible.
- **Restore a prior build** with the corresponding configuration backup and previous package. Test the backup restoration and confirm that the plug-in and native object versions agree before enabling routing again.
- **Remove** service rules, device assignments, and profiles after disabling routing. Use `pkg -o DEVELOPER_MODE=true delete os-blank-vpn` so the package checks for remaining managed state. Verify that ordinary firewall routing works and remove manually created DNS, alternate-hostname, and landing-page entries if they are no longer needed. Mullvad devices remain registered until you remove them from your account.
- Native OPNsense backups can contain WireGuard private keys. The local state directory `/var/db/blank-vpn` contains the router-specific account binding key and can contain a restricted pending WireGuard key after a failed onboarding. Preserve it across upgrades and when retrying a registration.

## Release notes

- Individually selectable proxy exits from pasted servers and HTTPS subscriptions.
- Mihomo protocol adapter, native Xray and sing-box configurations, and a FreeBSD tun2socks bridge.
- Existing Smart Routing, per-IPv4 policies, and fail-closed firewall rules apply to proxy exits.

- Smart Routing for domain suffixes, including a Netflix preset and custom services, with normal routing as the base.
- Per-IPv4 kill switches on shared LANs, independent of strict VPN segment mode.
- HTTPS-only Mullvad onboarding, account binding, recoverable registration, and native key-pair verification.
- Scoped DNS, routing, and rollback verification. Review [VALIDATION.md](VALIDATION.md) before using the package on the primary router.
