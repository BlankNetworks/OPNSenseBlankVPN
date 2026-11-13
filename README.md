# Blank VPN

Blank VPN is an OPNsense plug-in for assigning Mullvad, other WireGuard and OpenVPN providers, and individually selected proxy exits to services and IPv4 addresses. Multi-Path keeps normal internet as the default on selected LANs and routes destinations learned from service DNS through the configured exit. Several services and clients can share an exit. The dashboard uses OPNsense WebGUI login and permissions.

## Compatibility

Blank VPN targets OPNsense Community Edition 26.7.x with the FreeBSD 15 package ABI, standard WebGUI process mode, WireGuard, and Dnsmasq.

| Package suffix | OPNsense ABI | Target |
| --- | --- | --- |
| `amd64` | `FreeBSD:15:amd64` | Official x86-64 OPNsense, including Intel and AMD appliances and x86-64 VMs |
| `aarch64` | `FreeBSD:15:aarch64` | Compatible community ARM64 OPNsense, including supported NanoPi builds and ARM64 VMs |

OPNsense officially distributes x86-64 images. For NanoPi R4S/R4SE and R5S, start with a board-compatible community OPNsense 26.7 image and check its device notes. Other ARM64 boards need their own working OPNsense image. OpenWrt, Linux firmware, and 32-bit ARM require a different package and runtime. Live OPNsense routing still needs lab verification. [Official hardware support](https://docs.opnsense.org/manual/hardware.html) · [Community NanoPi images](https://github.com/matheusber/opnsense/releases) · [Validation](VALIDATION.md)

<a id="lab-installation"></a>

## Install or upgrade

Use an existing SSH connection or choose **8) Shell** on the local console. For SSH, run `ssh USER@ROUTER` from your computer using your configured SSH account and the router’s LAN address or hostname. Run the install commands from a root shell on the router. Check the edition, version series, and package ABI first. [OPNsense console and SSH](https://docs.opnsense.org/manual/install.html)

```sh
opnsense-version -n
opnsense-version -a
pkg config ABI
```

Choose a release that matches the edition, series, and ABI shown above under [Compatibility](#compatibility). Save an OPNsense configuration backup under **System → Configuration → Backups** before installing or upgrading. Keep console access available when testing routing.

### Download on your computer

1. Open [GitHub Releases](https://github.com/BlankNetworks/OPNSenseBlankVPN/releases) and choose a published **Blank VPN** release. Its install section lists both architectures and links to each `.pkg` and its `.pkg.sha256` file.
2. Download the matching pair and copy both files to `/tmp` on the router. You can use `scp` from your computer with an SSH account already configured on OPNsense. The release page gives the exact filenames and copy command.
3. In the router's root shell, run the **Install downloaded files** commands from the release page. The install runs only after the checksum matches.

### Download from the router over SSH or console

1. Open the same release and find **Download and install on the router** for your architecture.
2. Run its commands **one line at a time** in the router's root shell. They fetch the package from the pinned release URL, verify its SHA-256, and install it. The commands work in the OPNsense default shell.

For an upgrade, follow either path over the existing installation. Verify with `pkg info os-blank-vpn` and open **VPN → Blank VPN → Dashboard** in your existing HTTPS WebGUI. New installations start with routing disabled. The release package includes the proxy runtimes and Clash YAML parser. It declares its OPNsense, Dnsmasq, PHP cURL, and Python dependencies.

For delegated access, assign **VPN: Blank VPN: View devices and connections** or **VPN: Blank VPN: Manage tunnels and policy routing** in the OPNsense user manager.

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

To publish a new version, update `VERSION` in [build/package.py](build/package.py) and record the changes in [RELEASE_NOTES.md](RELEASE_NOTES.md). A push to `main` with `[publish release]` in the head commit message builds and verifies both packages. The workflow uses that version and the verified asset checksums to generate the install commands on the release page.

## Open the dashboard

From a client on your LAN, open your existing OPNsense HTTPS address and select **VPN → Blank VPN → Dashboard**. The direct path is `https://<router-ip>/ui/blankvpn/index`. Include your WebGUI port if it differs from 443. Use your existing OPNsense login.

For ordinary LAN DNS, set up `blankvpn.home.arpa` as a host override pointing to the router’s LAN IP. In OPNsense Unbound, use **Services → Unbound DNS → Overrides**. Add the hostname under **System → Settings → Administration → Alternate Hostnames** and use a trusted HTTPS certificate covering it. To open Blank VPN immediately after login, set the OPNsense user’s preferred landing page to `ui/blankvpn/index`.

For `blankvpn.local` on the home network, open **Tailscale Settings → Dashboard address**, click **Use blankvpn.local**, then click **Save Tailscale settings**. Saving adds `blankvpn.local` to the OPNsense WebGUI’s allowed hostnames. Use a trusted WebGUI certificate covering the name. Open **Publish blankvpn.local on your home network** to copy a Bonjour command populated with the router’s LAN IP and WebGUI port. Run it in Terminal on a Mac connected to the same link and leave it running, or publish the same address from an existing mDNS responder. Then open `https://blankvpn.local/ui/blankvpn/index`, with the WebGUI port if it differs from 443. For remote Tailscale access, use the direct Tailscale IP or a name resolved through tailnet DNS.

### Open from Tailscale

Open the **Tailscale Settings** tab to see the router’s Tailscale address, its exit-node advertisement, and the direct dashboard URLs. Use **Open OPNsense Tailscale settings** to connect the router, advertise home subnets or the exit node, and approve them in the Tailscale admin console. Permit HTTPS only from peers that should manage OPNsense. [Tailscale setup for OPNsense](https://tailscale.com/docs/install/opnsense) · [Exit-node setup](https://tailscale.com/docs/features/exit-nodes)

Choose **Tailscale address** and save to use the router’s MagicDNS hostname and add it to the OPNsense WebGUI’s allowed hostnames. The dashboard also shows the direct Tailscale IP. The package detects and allows the MagicDNS hostname during an upgrade when Tailscale access was already selected. Use the WebGUI’s existing HTTPS certificate settings. The `blankvpn.local` name uses link-local Bonjour for home access. [MagicDNS](https://tailscale.com/docs/features/magicdns)

## Enable a Mullvad server

1. Open **VPN Login**, enter your Mullvad account number, and sign in. Select **Save login on this router** to restore sign-in in future WebGUI sessions. The router stores the account number in a private file scoped to your WebGUI user, outside the OPNsense configuration export.
2. Pick a country, city, and server, then choose **Use server**. The tunnel is available for routing immediately. Disable an unused Mullvad server to pause its tunnel and keep its registration. For the first tunnel on the account, Blank VPN generates a local WireGuard key and registers its public key with Mullvad.
3. To change locations, select a new server. Blank VPN reuses the router’s registration. Blank VPN automatically reuses an available registration from a tunnel with no routing assignments. Free a tunnel first if all existing tunnels are assigned.

The router retains the registration key in private storage across upgrades and tunnel removal. Existing Mullvad tunnels from earlier releases stay available. Mullvad allows up to five registered devices per account. [Mullvad device limits](https://mullvad.net/en/help/using-mullvad-vpn-app#too-many-devices)

VPN Login offers Mullvad. Existing VPN tunnels saved with earlier releases remain available for routing. Use HTTPS to open the dashboard before signing in.

### Add server batches

In **VPN Login**, open **Manage server batches** and choose a city, country, or **Worldwide · all servers**. Click **Add to VPN**. Every server in the batch appears under **VPN tunnels**, where you can search by hostname or location and click **Test** for an ICMP reachability check from the router. Click **Use** to activate the chosen server for routing. An active tunnel's **Test** runs HTTPS through the tunnel. Saved batches share the catalog and use zero additional Mullvad device slots.

### Test servers

Use **Ping server** beside the selected Mullvad server to check ICMP from OPNsense. Use **Test** beside a VPN tunnel or proxy server to verify HTTPS. Results appear on the tested row. The VPN test can run with device routing off and requires a verified firewall route with a fallback block. Proxy tests try HTTPS targets in different regions. For a basic SOCKS5 server, a failed test can also report upstream TCP, SOCKS5 authentication, or TLS errors.

## Add proxy servers and subscriptions

The GitHub release includes Mihomo, tun2socks, Xray, sing-box, and the Clash YAML parser. The source build can also use independently installed runtimes. Review [PROXY_SUPPORT.md](PROXY_SUPPORT.md) for formats and protocol coverage.

1. Open **Proxy Login** over HTTPS. Add a single server with **Add a proxy manually**, paste its share link with an optional server name, or import a base64 list, Clash YAML, Xray JSON, or sing-box JSON.
2. For a provider feed, add its direct HTTPS subscription URL. The router follows public HTTPS redirects after validating each destination and reports DNS, TLS, HTTP, timeout, or format errors. The list shows reported traffic allowance, usage, and expiry when the provider sends those fields. New subscriptions enable automatic refresh every six hours. Change the setting per saved subscription. An enabled exit retains its server if a later refresh removes it.
3. Choose **Test** to check HTTPS through a proxy. Imported servers are enabled by default and appear in the server picker. Assign a server in **Network Settings** or **Multi-Path Settings** to start its tunnel once routing is enabled. **Disable** hides an unused server from the picker. Each subscription supports up to 2,048 entries and 4 MiB.

Use **Edit** beside a saved VPN exit or proxy server. Proxy names also appear in routing choices and survive subscription refreshes when the same server configuration returns.

## Update proxy cores

Open **Proxy Login → Core updates and storage** as an OPNsense administrator. Select **Check for updates**, then install an approved version or upload its matching archive. Approved archives are checked against their SHA-256, the router’s FreeBSD CPU architecture, reported version, and saved proxy configurations. Core updates retain one rollback version and preserve the bundled baseline. A failed restart restores the prior selection. Proxy exits that depend on the changed core briefly reconnect.

The approved [amd64](src/share/blankvpn/core-catalog.json) and [aarch64](src/share/blankvpn/core-catalog-aarch64.json) catalogs pin specific upstream or Blank Networks release assets. Change the catalog on GitHub to approve a new version independently of the plug-in. The [sing-box workflow](.github/workflows/cores.yml) can publish FreeBSD builds from a pinned upstream tag and commit. After verifying the build, add its version and asset SHA-256 to the catalog. The router fetches the catalog on demand. See [CORE_UPDATES.md](CORE_UPDATES.md) for the exact release format, offline installation and rollback.

Core updates, saved Mullvad logins, the private subscription catalog, and recovery state use `/var/db/blank-vpn`. The storage panel shows available space, downloaded core size, and catalog size. Staging keeps at least 64 MiB free for settings and runtime state. The bundled cores are part of the package. OPNsense stores saved assignments and WireGuard settings in its normal configuration. The Mullvad registration key is private and persists across package upgrades.

## Choose routing coverage

Open **Network Settings**, check the Ethernet ports or VLANs under **Interface**, choose who should use the rules, then click **Save and Enable VPN**. The button turns green once routing is enabled. The main home Ethernet port appears first. Devices need to use OPNsense as their gateway for the policy to apply.

- **Only devices I choose** applies saved policies to individual devices. Select **Add device rule** and enter a reserved IPv4 address.
- **Whole-Network coverage** uses one mode for the selected LANs and VLANs. Existing device assignments are saved for when you switch back. Check **Kill Switch** below **Interface** to block internet if the selected exit goes offline. One-exit mode routes IPv4 through that exit and blocks internet-bound IPv6 while the exit is in use. Blocked mode denies internet access on both families. Off restores normal routing. Whole-Network coverage requires a static IPv4 address on each selected router interface. LAN clients can still use DHCP. Blank VPN reads the current LAN IPv6 prefixes for Track Interface, Identity Association, SLAAC, and DHCPv6.


| Mode | Internet behavior |
| --- | --- |
| All traffic through one exit | Use one VPN or proxy exit, with a Kill Switch, backup exit, or regular internet fallback. |
| Multi-Path | Use the assigned exits for matching services and regular internet for other destinations. With Kill Switch checked, an unavailable exit blocks all internet in the selected scope. |
| Off | Follow the native network policy and bypass Blank VPN service routing for the assigned addresses. |
| Blocked | Block internet traffic from the assigned addresses and keep approved local access subject to native firewall rules. |

In **Network Settings**, choose **Only Devices I choose** and press **Refresh** to see LAN devices and Tailscale peers. **Select** fills the addresses and MAC where available. The LAN list shows IPv4 neighbors from OPNsense’s current ARP table. Saved rules stay visible for devices that go offline. For a matching active Kea or Dnsmasq lease, **Reserve IP and save rule** adds a DHCP reservation and applies the rule. For other devices, create a unique reservation in OPNsense first. Selecting Multi-Path for a device uses the domain lists assigned in **Multi-Path Settings**. Add the device’s stable IPv6 address to cover that address as well. On shared LANs, other IPv6 addresses follow the native policy. Use a dedicated strict interface for network-wide internet IPv6 blocking.

You can run multiple provider exits together, with up to 32 VPN profiles and eight active proxy exits. A phone can use Mullvad, a TV ExpressVPN, a tablet a proxy, and a Mac NordVPN. With Multi-Path, select a different exit for each service, such as a Japan exit for Netflix, a USA exit for Hulu, and a China exit for WeChat. Each service uses the domains you enter. Presets are starting lists that you can edit.

### Assign a Tailscale peer

From the LAN or console, open **VPN → Tailscale → Settings**. Use Tailscale 1.104.2 or newer. Enable **Advertise Exit Node** and the advanced **Disable SNAT** setting, then apply. OPNsense uses that setting to pass decrypted traffic into the FreeBSD kernel on `tailscale0` with the peer's original address. Applying the change restarts Tailscale. Approve OPNsense as an exit node in Tailscale admin and select it as the exit node on the client. [OPNsense Tailscale configuration](https://github.com/opnsense/plugins/blob/26.7.9/security/tailscale/src/opnsense/service/templates/OPNsense/Tailscale/rc.conf.d) · [Tailscale exit node setup](https://tailscale.com/docs/features/exit-nodes/how-to/setup)

In Blank VPN open **Tailscale Settings** to check readiness. Then open **Network Settings → Only Devices I choose**, save and enable routing, expand **Tailscale devices**, and select the peer. Blank VPN fills both addresses and automatically uses the OPNsense Tailscale interface. For an existing gateway on Ethernet or VLAN, select its link under **Tailscale Settings → Use a separate Tailscale gateway**. Access to the dashboard still follows the OPNsense firewall and Tailscale grants.

Test the public IPv4 from the peer, verify local management access, then test with the VPN disconnected and Kill Switch on. The routed mode supports IPv4 VPN egress and blocks public IPv6 for a protected one-server rule. Multi-Path learning requires DNS queries visible to the OPNsense packet filter. Tailscale can forward DNS internally through its exit-node resolver, so confirm DNS classification on the client before relying on it. [Tailscale DNS preferences](https://tailscale.com/docs/features/client/manage-preferences)

## Route Netflix or another service

1. Open **Multi-Path Settings**. Choose the Netflix preset, paste your own domains, or load a plain-text or comma-separated file. Each list accepts up to 1,000 unique domains and 128 KiB of input. Enter domains on separate lines or separated by commas. Lines may include `#` comments. Both `netflix.com` and `*.netflix.com` cover the apex and its subdomains.
2. Save the list with an exit selected, or leave it unassigned and edit it later. An unassigned list adds no DNS or firewall rules. Edit any list to replace the domains from a file, change its exit, or download the editor contents as a text file.
3. Choose **Multi-Path** under **Whole-Network coverage** on the **Network Settings** page, or enable Multi-Path for selected interfaces under **More routing options** and assign the Multi-Path mode to devices. Use ordinary DNS on the managed interface. Restart the test application and refresh its DNS cache. Check the learned address count and confirm the expected path from the client.

Multi-Path forwards matching DNS through the chosen tunnel and uses the regular resolver for other names. Learned IPv4 destinations use the VPN and learned IPv6 destinations are blocked. When the exit is unavailable, known destinations are blocked. Multi-Path classifies DNS-observed IPs. Shared IPs, existing connections, encrypted DNS, HTTPS record address hints, and endpoints obtained without an observed DNS lookup can affect which connections match. If two services learn the same destination IP, the first saved service rule has precedence. Learned entries are aged out after about a day and relearned from DNS. Mullvad exit IPs may be blocked by Netflix. [Mullvad Netflix guidance](https://mullvad.net/en/help/watching-netflix-with-split-tunneling)

## Enable and test the Kill Switch

1. For **Only devices I choose**, give the client a unique IPv4 DHCP reservation. Add a device rule and check **Kill Switch** in **All traffic through one exit** or **Multi-Path** mode. Add its stable IPv6 address to protect that address too. For **Whole-Network coverage**, check **Kill Switch** below **Interface** to protect both address families on the selected networks.
2. Click **Save and Enable VPN** on Network. From the protected client, confirm the expected internet exit. Start an internet connection, then take the test exit down. Verify the existing connection stops, new internet connections fail, and a client outside the scope can still use the internet. Check that approved local access remains available after reconnecting.
3. Bring the exit back up and verify internet access recovers. In Multi-Path, every assigned exit needs a successful health check before regular internet resumes. A checked Multi-Path rule with no assigned exit blocks internet until an exit is assigned and verified.

Tunnel health is polled. Multi-Path blocks regular internet once the outage is detected and the firewall rules are applied. VPN exits are probed every minute and active proxy exits are checked on a four-minute rotation. A state reset can interrupt existing local sessions on the protected address or network. Shared-LAN device rules cover only the saved IPs, so additional IPv6 addresses require Whole-Network coverage or a dedicated strict interface.

## Upgrade, rollback and removal

- **Upgrade** in a validated lab first. Export the OPNsense configuration, retain the previous package, and verify the new checksum. Use the verified upgrade commands in [Install or upgrade](#install-or-upgrade). Confirm ACLs, the active PF rules, DNS, and both tested exit paths after the upgrade.
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
