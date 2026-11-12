# Blank VPN 0.5.1

Blank VPN is an OPNsense plug-in for assigning Mullvad, other WireGuard and OpenVPN providers, and individually selected proxy exits to services and IPv4 addresses. Smart Routing keeps normal internet as the default on selected LANs and routes destinations learned from service DNS through the configured exit. Several services and clients can share an exit. The dashboard uses OPNsense WebGUI login and permissions.

## Compatibility

Blank VPN targets OPNsense Community Edition 26.7.x with the FreeBSD 15 package ABI, standard WebGUI process mode, WireGuard, and Dnsmasq.

| Package suffix | OPNsense ABI | Target |
| --- | --- | --- |
| `amd64` | `FreeBSD:15:amd64` | Official x86-64 OPNsense, including Intel and AMD appliances and x86-64 VMs |
| `aarch64` | `FreeBSD:15:aarch64` | Compatible community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs |

OPNsense officially distributes x86-64 images. For NanoPi R4S/R4SE and R5S, start with a board-compatible community OPNsense 26.7 image and check its device notes. Other ARM64 boards need their own working OPNsense image. OpenWrt, Linux firmware, and 32-bit ARM require a different package and runtime. Live OPNsense routing still needs lab verification. [Official hardware support](https://docs.opnsense.org/manual/hardware.html) · [Community NanoPi images](https://github.com/matheusber/opnsense/releases) · [Validation](VALIDATION.md)

## Download

Run `pkg config ABI` on the router, then download the matching package and its SHA-256 file from [GitHub Releases](https://github.com/BlankNetworks/OPNSenseBlankVPN/releases). The full prerelease package includes the proxy runtimes and Clash YAML parser.

## Build

Run the following from the source directory on a matching OPNsense lab host to build with FreeBSD `pkg create` and verify with `pkg info -F`.

```sh
python3 build/package.py
```

On another development host, build the same package format with the cross-build path. This also checks the manifest, scripts, payload hashes, ownership and permissions.

```sh
python3 build/package.py --cross --arch amd64
python3 build/package.py --cross --arch aarch64
```

The package and SHA-256 file are written to `dist/`. To reproduce the bundled release on a Linux development host with Go, run `sh build/prepare-release.sh /tmp/blankvpn-runtime amd64`, followed by `python3 build/package.py --cross --arch amd64 --runtime-dir /tmp/blankvpn-runtime`. For ARM64, use `aarch64` for both commands.

## Lab installation

1. Use an matching OPNsense CE 26.7 VM or spare router with console access. Attach a WAN, a management network and a test client LAN or VLAN. Back up the lab configuration under **System → Configuration → Backups**.
2. Confirm `opnsense-version -v` reports 26.7.x, `opnsense-version -n` reports `opnsense`, and `pkg config ABI` matches the chosen architecture.
3. Transfer the package and checksum to the lab system. From their directory, verify and install as root.

   ```sh
   arch=$(pkg config ABI | cut -d: -f3)
   package="os-blank-vpn-0.5.1-$arch.pkg"
   sha256 -c "$(awk '{print $1}' "$package.sha256")" "$package"
   pkg info -F "./$package"
   pkg add "./$package"
   pkg info os-blank-vpn
   ```

4. Sign in using the current WebGUI HTTPS address and open **VPN → Blank VPN → Devices** or `/ui/blankvpn/index`. Routing starts disabled. The installer registers the dashboard, model, firewall hook, and local maintenance entry.
5. For delegated access, assign **VPN: Blank VPN: View devices and connections** or **VPN: Blank VPN: Manage tunnels and policy routing** in the native user manager. Confirm ACL behavior before delegating either permission.

## Open the dashboard

From a client on your LAN, open your existing OPNsense HTTPS address and select **VPN → Blank VPN → Devices**. The direct path is `https://<router-ip>/ui/blankvpn/index`. Include your WebGUI port if it differs from 443. Use your existing OPNsense login.

For ordinary LAN DNS, set up `blankvpn.home.arpa` as a host override pointing to the router’s LAN IP. In OPNsense Unbound, use **Services → Unbound DNS → Overrides**. Add the hostname under **System → Settings → Administration → Alternate Hostnames** and use a trusted HTTPS certificate covering it. To open Blank VPN immediately after login, set the OPNsense user’s preferred landing page to `ui/blankvpn/index`.

For `BlankVPN.local` on the LAN, set the dashboard name to `blankvpn.local` and publish it from an mDNS responder on that link. The responder publishes the router’s LAN IPv4 address. Leave the OPNsense system domain on its existing DNS domain.

### Open from Tailscale

1. Connect OPNsense to your tailnet, assign its Tailscale interface, and permit HTTPS from your authorized peers in the OPNsense firewall. [Tailscale setup for OPNsense](https://tailscale.com/docs/install/opnsense)
2. Open the router’s Tailscale address or its MagicDNS name with the same WebGUI port and path. In **Blank VPN → Settings**, select **Router Tailscale IPv4** in **Bind dashboard IP**. Blank VPN detects the current router address and uses it for the dashboard name in its managed DNS listeners.
3. For a shared remote hostname, add `blankvpn.home.arpa` to your native resolver with the detected Tailscale address, then configure that resolver as the restricted nameserver for `home.arpa` in Tailscale DNS. To use the exact `BlankVPN.local` spelling from a remote client, add a local hosts entry mapping `blankvpn.local` to the displayed router Tailscale IP and use a trusted WebGUI certificate for that name. Refresh a manual DNS override or hosts entry if the router’s Tailscale IP changes. [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale) · [mDNS link-local scope](https://www.rfc-editor.org/rfc/rfc6762.html)

The dashboard binding chooses the IP advertised by Blank VPN’s managed DNS. WebGUI listeners, certificates, and tailnet access remain under the native OPNsense and Tailscale settings.

## Add a Mullvad exit

1. Open the WebGUI over HTTPS and choose **VPNs → Sign in to Mullvad**. Enter your account number, then choose a country, city, and exact server.
2. Choose **Add Mullvad exit**. Blank VPN checks your device slots, generates a WireGuard key pair locally, registers only the public key with Mullvad, and creates the native tunnel. The account number is cleared from the form after sign-in. The provider token is kept in your WebGUI session for up to ten minutes.
3. Select the exit under **Devices** or **Smart Routing**. Sign-out ends the setup session. Saved tunnels keep running with their WireGuard keys.

Each new Mullvad exit uses one Mullvad device slot. Multiple local devices can use the same exit. An interrupted registration retains a restricted recovery key. Retry with the same account and server to recover it without consuming a second device slot. To set up the key on Mullvad’s website, use the [Mullvad configuration generator](https://mullvad.net/en/account/wireguard-config) and import the resulting file under **VPNs → Import a WireGuard exit**.

## Add other VPN providers

| Provider | Setup path | Provider instructions |
| --- | --- | --- |
| NordVPN | Configure OpenVPN in OPNsense with its service credentials, or use a provider-issued manual WireGuard configuration if available for your account. | [Service credentials](https://support.nordvpn.com/hc/en-us/articles/19685514639633) · [Manual WireGuard](https://support.nordvpn.com/hc/en-us/articles/51264943286545) |
| ExpressVPN | Configure the OpenVPN client in OPNsense with the provider’s manual credentials and server file. | [Manual configuration](https://www.expressvpn.com/support/manage-account/find-manual-configuration-credentials/) |
| Surfshark | Download the server’s WireGuard configuration and import it in Blank VPN. You can also attach a native OpenVPN client. | [WireGuard configuration](https://support.surfshark.com/hc/en-us/articles/6585805595666) · [OPNsense OpenVPN](https://support.surfshark.com/hc/en-us/articles/12434921071890) |
| Proton VPN | Download the server’s WireGuard configuration and import it in Blank VPN. | [WireGuard configuration](https://protonvpn.com/support/wireguard-configurations) |
| Other providers | Use a compatible full-tunnel WireGuard configuration or a native OpenVPN client gateway. | [OPNsense WireGuard selective routing](https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html) |

For a direct import, open **VPNs → Import a WireGuard exit** and paste a one-peer configuration with full-tunnel IPv4 AllowedIPs. The endpoint must resolve over IPv4. The tunnel address is installed with a host prefix for policy routing. Each concurrent WireGuard exit needs a distinct local tunnel address and key pair. Providers that reuse a tunnel address across servers can require using one exit at a time.

For a native tunnel, configure the provider client, assign its interface, and create a named IPv4 gateway in OPNsense. Keep the WAN as the system default, disable any provider-pushed default route or split default routes, and confirm the firewall’s own default traffic still leaves over WAN. Then choose **VPNs → Use an OPNsense VPN tunnel**, select the gateway, and enter the provider’s IPv4 DNS resolver reachable through the tunnel. Device and service assignments can then select the exit by name. OPNsense manages the VPN credentials, certificates, and connection. A selected gateway must remain attached to the same named interface and have a unique active IPv4 tunnel address.

## Add proxy servers and subscriptions

The GitHub release includes Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. The source build can also use independently installed runtimes. Review [PROXY_SUPPORT.md](PROXY_SUPPORT.md) for formats and protocol coverage.

1. Open **Proxies** over HTTPS. Add a single server with **Add a proxy manually**, paste its share link, or import a base64 list, Clash YAML, Xray JSON, or sing-box JSON.
2. For a provider feed, add its direct HTTPS subscription URL. The list shows reported traffic allowance, usage, and expiry when the provider sends those fields. Automatic refresh runs every six hours. An enabled exit retains its server if a later refresh removes it.
3. Choose **Enable exit** on a server, then select the exit under **Multi-Path** or **Devices**. Device assignments can use the IPv4 kill switch or a backup exit. UDP support varies with the upstream protocol and transport.

## Update proxy cores

Open **Proxies → Core updates and storage** as an OPNsense administrator. Select **Check for updates**, then install an approved version or upload its matching archive. Approved archives are checked against their SHA-256, the router’s FreeBSD CPU architecture, reported version, and saved proxy configurations. Core updates retain one rollback version and preserve the bundled baseline. A failed restart restores the prior selection. Proxy exits that depend on the changed core briefly reconnect.

The approved [amd64](src/share/blankvpn/core-catalog.json) and [aarch64](src/share/blankvpn/core-catalog-aarch64.json) catalogs pin specific upstream or Blank Networks release assets. Change the catalog on GitHub to approve a new version independently of the plug-in. The [sing-box workflow](.github/workflows/cores.yml) can publish FreeBSD builds from a pinned upstream tag and commit. After verifying the build, add its version and asset SHA-256 to the catalog. The router fetches the catalog on demand. See [CORE_UPDATES.md](CORE_UPDATES.md) for the exact release format, offline installation and rollback.

Core updates, the private subscription catalog, and recovery state use `/var/db/blank-vpn`. The storage panel shows available space, downloaded core size, and catalog size. Staging keeps at least 64 MiB free for settings and runtime state. The bundled cores are part of the package. OPNsense stores saved assignments and WireGuard settings in its normal configuration. Mullvad sign-in uses a short-lived WebGUI session, with a persistent WireGuard key for each saved exit.

## Choose a device routing mode

| Mode | Internet behavior |
| --- | --- |
| Full Tunneling | Use one VPN or proxy exit, with a kill switch, backup exit, or normal-internet fallback. |
| Multi-Path Tunneling | Use the assigned exits for matching services and ordinary internet for other destinations. |
| Disabled (No VPN) | Follow the native network policy and bypass Blank VPN service routing for the assigned addresses. |
| Blocked (No Internet) | Block internet traffic from the assigned addresses and keep approved local access subject to native firewall rules. |

In **Settings**, select which interfaces use Multi-Path. Enable **Apply Multi-Path only to devices assigned that mode** to keep other devices on their normal route. In **Devices**, choose the mode for each reserved LAN IPv4 address. Add the device’s stable IPv6 address to cover that address as well. On shared LANs, other IPv6 addresses follow the native policy. Use a dedicated strict interface for network-wide internet IPv6 blocking.

You can run multiple provider exits together, with up to 32 VPN profiles and eight active proxy exits. A phone can use Mullvad, a TV ExpressVPN, a tablet a proxy, and a Mac NordVPN. With Multi-Path, select a different exit for each service, such as a Japan exit for Netflix, a USA exit for Hulu, and a China exit for WeChat. Each service uses the domains you enter. Presets are starting lists that you can edit.

### Assign a Tailscale peer

The standard OPNsense FreeBSD Tailscale exit node uses userspace forwarding. PF sees the router’s connection after Tailscale has translated it, so it cannot enforce a per-peer internet policy there. The dashboard is still reachable over that Tailscale interface. [Tailscale forwarding modes](https://tailscale.com/docs/reference/kernel-vs-userspace-routers)

To apply per-peer policy, use a source-preserving routed exit path, such as a Linux Tailscale gateway on a dedicated OPNsense transit interface. Configure return routes for the peer addresses and use an OPNsense packet capture to confirm that both original addresses arrive on that interface before assigning the peer. Under **Settings**, add that OPT or VLAN interface to both **Managed interfaces** and **Tailscale transit interfaces**. Then choose **Devices → Assign an IP address → Tailscale peer on a routed link**, enter the peer IPv4 and IPv6 addresses, and choose a mode. On a failed Full Tunneling exit with a kill switch, the configured peer addresses remain blocked from the internet. [Tailscale source address preservation](https://tailscale.com/docs/features/subnet-routers)

## Route Netflix or another service

1. Select **Set up Multi-Path on LAN** and save the settings. For another network, add its interface ID under both **Managed interfaces** and **Multi-Path interfaces**. Leave strict mode disabled for those interfaces. The router needs a working native resolver on `127.0.0.1:53` and the OPNsense Dnsmasq package with PF ipset support.
2. Under **Multi-Path**, choose **Netflix**, select your Japan exit, and add the service. The preset includes Netflix website and media domains such as `netflix.com`, `nflxvideo.net`, and `nflximg.net`. For a custom service, enter your own domain suffixes. Both `netflix.com` and `*.netflix.com` cover the apex and its subdomains.
3. On the test client, restart the application and refresh its DNS cache. Use ordinary DNS on the managed interface for the test. Check that the learned address count increases and use the router’s packet captures to confirm the intended tunnel and ordinary WAN traffic separately.

Smart Routing forwards matching DNS through the chosen tunnel and uses the regular resolver for other names. Learned IPv4 destinations use the VPN and learned IPv6 destinations are blocked. When the exit is unavailable, known destinations are blocked. Smart Routing classifies DNS-observed IPs. Shared IPs, existing connections, encrypted DNS, HTTPS record address hints, and endpoints obtained without an observed DNS lookup can affect which connections match. If two services learn the same destination IP, the first saved service rule has precedence. Learned entries are aged out after about a day and relearned from DNS. Mullvad exit IPs may be blocked by Netflix. [Mullvad Netflix guidance](https://mullvad.net/en/help/watching-netflix-with-split-tunneling)

## Assign an IPv4 address and enable a kill switch

1. Add the test client’s LAN or VLAN under **Managed interfaces**. Give the client a unique IPv4 DHCP reservation and select it in **Devices**.
2. Choose an exit and **Block IPv4 internet (kill switch)**. Applying a new kill switch resets connections originating from that address, including local sessions. Other clients continue to use their configured routes. The rules preserve configured local network exceptions for new connections.
3. Verify normal traffic from an unassigned test client. Confirm the protected client’s egress goes through WireGuard, then disable the test tunnel and check that its IPv4 internet traffic stops and the unassigned client stays online.
4. If you need to block internet-bound IPv6 for a whole device, use a dedicated **Strict VPN interface**. Strict mode blocks internet-bound IPv6 and internet traffic from unassigned devices. The per-IP rule on a shared LAN covers the reserved IPv4 address. Keep the IPv6 behavior of your existing firewall in mind.

Per-IP rules take precedence over Smart Routing. A selected **Backup exit** can carry the address when the primary fails. **Normal internet** is an explicit fallback to the normal network policy. VPN health is observed with a router-side probe, while the client path must be checked from that client.

## Upgrade, rollback and removal

- **Upgrade** in a validated lab first. Export the OPNsense configuration, retain the previous package, and verify the new checksum. Use `pkg add -f ./os-blank-vpn-NEW.pkg`. Confirm ACLs, the active PF rules, DNS, and both tested exit paths after the upgrade.
- **Roll back routing** by disabling Blank VPN from the independent management connection. Review native policy after reload. Existing traffic states can remain until expiry or a targeted state reset. Use the console and OPNsense configuration history if the dashboard is inaccessible.
- **Restore a prior build** with the corresponding configuration backup and previous package. Test the backup restoration and confirm that the plug-in and native object versions agree before enabling routing again.
- **Remove** service rules, device assignments, and profiles after disabling routing. Use `pkg -o DEVELOPER_MODE=true delete os-blank-vpn` so the package checks for remaining managed state. Verify that ordinary firewall routing works and remove manually created DNS, alternate-hostname, and landing-page entries if they are no longer needed. Mullvad devices remain registered until you remove them from your account.
- Native OPNsense backups can contain WireGuard private keys. The local state directory `/var/db/blank-vpn` contains the router-specific account binding key and can contain a restricted pending WireGuard key after a failed onboarding. Preserve it across upgrades and when retrying a registration.

## Release notes

- Native OpenVPN and WireGuard gateway exits for mainstream providers.
- Mullvad sign-in scoped to the WebGUI session.
- Individually selectable proxy exits from pasted servers and HTTPS subscriptions.
- Mihomo protocol adapter, native Xray and sing-box configurations, and a FreeBSD tun2socks bridge.
- Existing Smart Routing, per-IPv4 policies, and fail-closed firewall rules apply to proxy exits.

- Smart Routing for domain suffixes, including a Netflix preset and custom services, with normal routing as the base.
- Per-IPv4 kill switches on shared LANs, independent of strict VPN segment mode.
- HTTPS-only Mullvad onboarding, account binding, recoverable registration, and native key-pair verification.
- Scoped DNS, routing, and rollback verification. Review [VALIDATION.md](VALIDATION.md) before using the package on the primary router.
