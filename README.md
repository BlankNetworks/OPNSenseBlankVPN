# Blank VPN 0.8.4

Blank VPN is an OPNsense plug-in for assigning Mullvad, other WireGuard and OpenVPN providers, and individually selected proxy exits to services and IPv4 addresses. Multi-Path keeps normal internet as the default on selected LANs and routes destinations learned from service DNS through the configured exit. Several services and clients can share an exit. The dashboard uses OPNsense WebGUI login and permissions.

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

1. Use a matching OPNsense CE 26.7 VM or spare router with console access. Attach a WAN, a management network and a test client LAN or VLAN. Back up the lab configuration under **System → Configuration → Backups**.
2. Confirm `opnsense-version -v` reports 26.7.x, `opnsense-version -n` reports `opnsense`, and `pkg config ABI` matches the chosen architecture.
3. Transfer the matching package and its SHA-256 file to the router. Run these commands one line at a time as root from the same directory. For ARM64, replace `amd64` with `aarch64`.

   ```sh
   sha256sum -c os-blank-vpn-0.8.4-amd64.pkg.sha256 && pkg add -f ./os-blank-vpn-0.8.4-amd64.pkg
   pkg info os-blank-vpn
   ```

4. The package declares its OPNsense, Dnsmasq, PHP cURL, and Python dependencies. It loads the FreeBSD TUN driver when needed. Sign in using the current WebGUI HTTPS address and open **VPN → Blank VPN → Dashboard** or `/ui/blankvpn/index`. Routing starts disabled. The installer registers the dashboard, model, firewall hook, and local maintenance entry.
5. For delegated access, assign **VPN: Blank VPN: View devices and connections** or **VPN: Blank VPN: Manage tunnels and policy routing** in the native user manager. Confirm ACL behavior before delegating either permission.

## Open the dashboard

From a client on your LAN, open your existing OPNsense HTTPS address and select **VPN → Blank VPN → Dashboard**. The direct path is `https://<router-ip>/ui/blankvpn/index`. Include your WebGUI port if it differs from 443. Use your existing OPNsense login.

For ordinary LAN DNS, set up `blankvpn.home.arpa` as a host override pointing to the router’s LAN IP. In OPNsense Unbound, use **Services → Unbound DNS → Overrides**. Add the hostname under **System → Settings → Administration → Alternate Hostnames** and use a trusted HTTPS certificate covering it. To open Blank VPN immediately after login, set the OPNsense user’s preferred landing page to `ui/blankvpn/index`.

For `blankvpn.local` on the home network, open **Tailscale → Dashboard address**, click **Use blankvpn.local**, then click **Save Tailscale settings**. Add `blankvpn.local` to OPNsense **Alternate Hostnames** and use a trusted WebGUI certificate covering the name. Open **Publish blankvpn.local on your home network** to copy a Bonjour command populated with the router’s LAN IP and WebGUI port. Run it in Terminal on a Mac connected to the same link and leave it running, or publish the same address from an existing mDNS responder. Then open `https://blankvpn.local/ui/blankvpn/index`, with the WebGUI port if it differs from 443. For remote Tailscale access, use the direct Tailscale IP or a name resolved through tailnet DNS.

### Open from Tailscale

Open the **Tailscale** tab to see the router’s Tailscale address, its exit-node advertisement, and the direct dashboard URLs. Use **Open OPNsense Tailscale settings** to connect the router, advertise home subnets or the exit node, and approve them in the Tailscale admin console. Permit HTTPS only from peers that should manage OPNsense. [Tailscale setup for OPNsense](https://tailscale.com/docs/install/opnsense) · [Exit-node setup](https://tailscale.com/docs/features/exit-nodes)

Choose **Tailscale address** to resolve the dashboard name to the detected Tailscale IP through Blank VPN’s managed DNS. For other tailnet clients, configure the matching host override in a DNS server reachable over Tailscale and add that server as the restricted nameserver for `home.arpa`. The direct URL is `https://blankvpn.home.arpa/ui/blankvpn/index` with the default hostname and port. Native OPNsense settings control the HTTPS listener and certificate. [Tailscale DNS](https://tailscale.com/docs/reference/dns-in-tailscale)

## Add a Mullvad exit

1. Open the WebGUI over HTTPS and choose **VPN Login → Sign in**. Enter your account number. After sign-in, the server catalog loads automatically. Choose a country, city, and server.
2. Choose **Add Mullvad exit**. Blank VPN checks your device slots, generates a WireGuard key pair locally, registers only the public key with Mullvad, and creates the native tunnel. The account number is cleared from the form after sign-in. Select **Save login on this router** when signing in to restore it automatically in future WebGUI sessions. The router stores the account number in a private file outside the OPNsense configuration export, scoped to your WebGUI user.
3. Select the exit under **Network** or **Multi-Path Settings**. **Sign out and forget login** removes the saved sign-in. Saved tunnels keep running with their WireGuard keys.

Each new Mullvad exit uses one Mullvad device slot. Multiple local devices can use the same exit. An interrupted registration retains a restricted recovery key. Retry with the same account and server to recover it without consuming a second device slot.

VPN Login currently offers Mullvad. Existing exits saved with earlier releases remain available for routing. If the WebGUI opens over HTTP, enable HTTPS under **System → Settings → Administration**, then reopen the dashboard over HTTPS before signing in.

### Add server batches

In **VPN Login**, open **Manage server batches** after signing in. Pick a country or **Worldwide · all servers**, then click **Add batch**. Repeat for any other countries you want to keep handy. Select a saved batch under **Server list**, then narrow it by country, city, or server. **Refresh servers** updates every batch from the latest Mullvad catalog. Unavailable servers remain visible and cannot be activated.

The router saves the selected batches in its OPNsense configuration. Adding or removing a batch leaves existing exits and routing rules intact. To route through a saved server, select it and click **Add Mullvad exit**, then assign the exit under **Network** or **Multi-Path Settings**. Mullvad allows five registered devices per account, and each newly activated exit uses one slot.

### Test servers and exits

Use **Ping server** beside the selected Mullvad relay to send one ICMP echo from OPNsense to its published IPv4 address. An unanswered ping can mean the relay filters ICMP. Use **Test exit** beside a configured VPN or enabled proxy to check an HTTPS request through that exit. Saved WireGuard and native VPN exits can be tested while device routing is off. Their HTTPS probe requires a verified firewall route with a fallback block. A relay ping checks ICMP before activation. The exit test verifies internet access through the configured tunnel.

## Add proxy servers and subscriptions

The GitHub release includes Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. The source build can also use independently installed runtimes. Review [PROXY_SUPPORT.md](PROXY_SUPPORT.md) for formats and protocol coverage.

1. Open **Proxies** over HTTPS. Add a single server with **Add a proxy manually**, paste its share link, or import a base64 list, Clash YAML, Xray JSON, or sing-box JSON.
2. For a provider feed, add its direct HTTPS subscription URL. The router follows public HTTPS redirects after validating each destination and reports DNS, TLS, HTTP, timeout, or format errors. The list shows reported traffic allowance, usage, and expiry when the provider sends those fields. New subscriptions enable automatic refresh every six hours. Change the setting per saved subscription. An enabled exit retains its server if a later refresh removes it.
3. Choose **Test server** to check a saved proxy before enabling it. Choose **Enable exit** on a server to make it available for routing, then select the exit under **Multi-Path** or **Network**. Device assignments can use the IPv4 kill switch or a backup exit. UDP support varies with the upstream protocol and transport.

## Update proxy cores

Open **Proxies → Core updates and storage** as an OPNsense administrator. Select **Check for updates**, then install an approved version or upload its matching archive. Approved archives are checked against their SHA-256, the router’s FreeBSD CPU architecture, reported version, and saved proxy configurations. Core updates retain one rollback version and preserve the bundled baseline. A failed restart restores the prior selection. Proxy exits that depend on the changed core briefly reconnect.

The approved [amd64](src/share/blankvpn/core-catalog.json) and [aarch64](src/share/blankvpn/core-catalog-aarch64.json) catalogs pin specific upstream or Blank Networks release assets. Change the catalog on GitHub to approve a new version independently of the plug-in. The [sing-box workflow](.github/workflows/cores.yml) can publish FreeBSD builds from a pinned upstream tag and commit. After verifying the build, add its version and asset SHA-256 to the catalog. The router fetches the catalog on demand. See [CORE_UPDATES.md](CORE_UPDATES.md) for the exact release format, offline installation and rollback.

Core updates, saved Mullvad logins, the private subscription catalog, and recovery state use `/var/db/blank-vpn`. The storage panel shows available space, downloaded core size, and catalog size. Staging keeps at least 64 MiB free for settings and runtime state. The bundled cores are part of the package. OPNsense stores saved assignments and WireGuard settings in its normal configuration. Each saved Mullvad exit has a persistent WireGuard key.

## Choose routing coverage

Open **Network**, check the Ethernet ports or VLANs under **Interface**, choose who should use the rules, then click **Save and Enable VPN**. The button turns green once routing is enabled. The main home Ethernet port appears first. Devices need to use OPNsense as their gateway for the policy to apply.

- **Only devices I choose** applies saved policies to individual devices. Select **Add device rule** and enter a reserved IPv4 address.
- **Whole-Network coverage** uses one mode for the selected LANs and VLANs. Existing device assignments are saved for when you switch back. Check **Kill Switch** below **Interface** to block internet if the selected exit goes offline. One-exit mode routes IPv4 through that exit and blocks internet-bound IPv6 while the exit is in use. Blocked mode denies internet access on both families. Off restores normal routing. Whole-Network coverage requires static IPv4 and static IPv6 or no IPv6 on the managed segments.


| Mode | Internet behavior |
| --- | --- |
| All traffic through one exit | Use one VPN or proxy exit, with a Kill Switch, backup exit, or regular internet fallback. |
| Multi-Path | Use the assigned exits for matching services and regular internet for other destinations. With Kill Switch checked, an unavailable exit blocks all internet in the selected scope. |
| Off | Follow the native network policy and bypass Blank VPN service routing for the assigned addresses. |
| Blocked | Block internet traffic from the assigned addresses and keep approved local access subject to native firewall rules. |

Under **Network → More routing options**, select **Use Multi-Path domain lists** for the applicable interface and check **Use domain lists only for devices set to Multi-Path** for device-specific use. In **Network**, choose the mode for each reserved LAN IPv4 address. Add the device’s stable IPv6 address to cover that address as well. On shared LANs, other IPv6 addresses follow the native policy. Use a dedicated strict interface for network-wide internet IPv6 blocking.

You can run multiple provider exits together, with up to 32 VPN profiles and eight active proxy exits. A phone can use Mullvad, a TV ExpressVPN, a tablet a proxy, and a Mac NordVPN. With Multi-Path, select a different exit for each service, such as a Japan exit for Netflix, a USA exit for Hulu, and a China exit for WeChat. Each service uses the domains you enter. Presets are starting lists that you can edit.

### Assign a Tailscale peer

The standard OPNsense FreeBSD Tailscale exit node uses userspace forwarding. PF sees the router’s connection after Tailscale has translated it, so it cannot enforce a per-peer internet policy there. The dashboard is still reachable over that Tailscale interface. [Tailscale forwarding modes](https://tailscale.com/docs/reference/kernel-vs-userspace-routers)

To apply per-peer policy, use a Linux Tailscale exit gateway in kernel forwarding mode on a dedicated OPNsense Ethernet or VLAN link. Preserve the peer source addresses, configure the return routes for those addresses through the Linux gateway, and confirm both address families with an OPNsense capture. Advertise and approve the home subnets for remote LAN access. In Blank VPN select **Only devices I choose**, enable the dedicated port under **Network → Interface**, then select the port under **Tailscale → Route Tailscale devices through Blank VPN**. Add a device rule using the peer's Tailscale IPv4 and IPv6 addresses. [Tailscale forwarding modes](https://tailscale.com/docs/reference/kernel-vs-userspace-routers) · [Tailscale subnet routing](https://tailscale.com/docs/features/subnet-routers)

## Route Netflix or another service

1. Open **Multi-Path Settings**. Choose the Netflix preset, paste your own domains, or load a plain-text or comma-separated file. Each list accepts up to 1,000 unique domains and 128 KiB of input. Enter domains on separate lines or separated by commas. Lines may include `#` comments. Both `netflix.com` and `*.netflix.com` cover the apex and its subdomains.
2. Save the list with an exit selected, or leave it unassigned and edit it later. An unassigned list adds no DNS or firewall rules. Edit any list to replace the domains from a file, change its exit, or download the editor contents as a text file.
3. Choose **Multi-Path** under **Whole-Network coverage** on the **Network** page, or enable Multi-Path for selected interfaces under **More routing options** and assign the Multi-Path mode to devices. Use ordinary DNS on the managed interface. Restart the test application and refresh its DNS cache. Check the learned address count and confirm the expected path from the client.

Multi-Path forwards matching DNS through the chosen tunnel and uses the regular resolver for other names. Learned IPv4 destinations use the VPN and learned IPv6 destinations are blocked. When the exit is unavailable, known destinations are blocked. Multi-Path classifies DNS-observed IPs. Shared IPs, existing connections, encrypted DNS, HTTPS record address hints, and endpoints obtained without an observed DNS lookup can affect which connections match. If two services learn the same destination IP, the first saved service rule has precedence. Learned entries are aged out after about a day and relearned from DNS. Mullvad exit IPs may be blocked by Netflix. [Mullvad Netflix guidance](https://mullvad.net/en/help/watching-netflix-with-split-tunneling)

## Enable and test the Kill Switch

1. For **Only devices I choose**, give the client a unique IPv4 DHCP reservation. Add a device rule and check **Kill Switch** in **All traffic through one exit** or **Multi-Path** mode. Add its stable IPv6 address to protect that address too. For **Whole-Network coverage**, check **Kill Switch** below **Interface** to protect both address families on the selected networks.
2. Click **Save and Enable VPN** on Network. From the protected client, confirm the expected internet exit. Start an internet connection, then take the test exit down. Verify the existing connection stops, new internet connections fail, and a client outside the scope can still use the internet. Check that approved local access remains available after reconnecting.
3. Bring the exit back up and verify internet access recovers. In Multi-Path, every assigned exit needs a successful health check before regular internet resumes. A checked Multi-Path rule with no assigned exit blocks internet until an exit is assigned and verified.

Tunnel health is polled. Multi-Path blocks regular internet once the outage is detected and the firewall rules are applied. VPN exits are probed every minute and active proxy exits are checked on a four-minute rotation. A state reset can interrupt existing local sessions on the protected address or network. Shared-LAN device rules cover only the saved IPs, so additional IPv6 addresses require Whole-Network coverage or a dedicated strict interface.

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
- Existing Multi-Path, per-IPv4 policies, and fail-closed firewall rules apply to proxy exits.

- Multi-Path for domain suffixes, including a Netflix preset and custom services, with normal routing as the base.
- Per-IPv4 kill switches on shared LANs, independent of strict VPN segment mode.
- HTTPS-only Mullvad onboarding, account binding, recoverable registration, and native key-pair verification.
- Scoped DNS, routing, and rollback verification. Review [VALIDATION.md](VALIDATION.md) before using the package on the primary router.
