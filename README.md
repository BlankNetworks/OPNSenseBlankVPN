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

If Blank VPN already has **System Settings → Package updates**, follow [Update from the WebGUI](#update-from-the-webgui). For a first install or to bootstrap WebGUI updates from 0.8.14 or earlier, install one release package. You can upgrade over your existing Blank VPN installation.

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

### Update from the WebGUI

1. Sign in as a WebGUI administrator over HTTPS. Open **VPN → Blank VPN → Dashboard → System Settings** and click **Check for update**. The first successful check sets up the signed package source automatically.
2. Click **Update** when a newer version is shown. The WebGUI and VPN connections may briefly reconnect. Reload the dashboard after the update finishes.

Once the first check succeeds, **System → Firmware → Updates** can also find Blank VPN releases. Version 0.8.15 has a separate **Enable signed updates** button. Click it once if you start from that release's WebGUI.

The in-plugin update installs the signed Blank VPN package for OPNsense Community Edition 26.7.x. The OPNsense Firmware page manages system updates. [OPNsense firmware management](https://docs.opnsense.org/manual/firmware.html)

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

To publish a new version, update `VERSION` in [build/package.py](build/package.py) and record the changes in [RELEASE_NOTES.md](RELEASE_NOTES.md). A push to `main` with `[publish release]` in the head commit message builds and verifies both packages. The workflow uses that version and the verified asset checksums to generate the install commands on the release page. After publication it verifies and deploys the signed firmware repository for both architectures.

## Open the dashboard

From a client on your LAN, open your existing OPNsense HTTPS address and select **VPN → Blank VPN → Dashboard**. The direct path is `https://<router-ip>/ui/blankvpn/index`. Include your WebGUI port if it differs from 443. Use your existing OPNsense login.

For ordinary LAN DNS, set up `blankvpn.home.arpa` as a host override pointing to the router’s LAN IP. In OPNsense Unbound, use **Services → Unbound DNS → Overrides**. Add the hostname under **System → Settings → Administration → Alternate Hostnames** and use a trusted HTTPS certificate covering it. To open Blank VPN immediately after login, set the OPNsense user’s preferred landing page to `ui/blankvpn/index`.

For `blankvpn.local` on the home network, open **Tailscale Settings → Dashboard address**, click **Use blankvpn.local**, then click **Save Tailscale settings**. Saving adds `blankvpn.local` to the OPNsense WebGUI’s allowed hostnames. Use a trusted WebGUI certificate covering the name. Open **Publish blankvpn.local on your home network** to copy a Bonjour command populated with the router’s LAN IP and WebGUI port. Run it in Terminal on a Mac connected to the same link and leave it running, or publish the same address from an existing mDNS responder. Then open `https://blankvpn.local/ui/blankvpn/index`, with the WebGUI port if it differs from 443. For remote Tailscale access, use the direct Tailscale IP or a name resolved through tailnet DNS.

### Open from Tailscale

Open the **Tailscale Settings** tab to see the router’s Tailscale address, its exit-node advertisement, and the direct dashboard URLs. Use **Open OPNsense Tailscale settings** to connect the router, advertise home subnets or the exit node, and approve them in the Tailscale admin console. Permit HTTPS only from peers that should manage OPNsense. [Tailscale setup for OPNsense](https://tailscale.com/docs/install/opnsense) · [Exit-node setup](https://tailscale.com/docs/features/exit-nodes)

Choose **Tailscale address** and save to use the router’s MagicDNS hostname and add it to the OPNsense WebGUI’s allowed hostnames. The dashboard also shows the direct Tailscale IP. The package detects and allows the MagicDNS hostname during an upgrade when Tailscale access was already selected. Use the WebGUI’s existing HTTPS certificate settings. The `blankvpn.local` name uses link-local Bonjour for home access. [MagicDNS](https://tailscale.com/docs/features/magicdns)

## VPN Login

Choose a service in **VPN Service** and select **Apply**. Sign in or add a compatible configuration, select a server and choose **Add server**. The server appears in **Saved VPN servers**. Select **Test** to check it or **Remove** to delete it once it is clear of routing rules. Open **Network Settings** to assign a saved server to LAN or Tailscale devices, or to enable Whole-Network coverage.

Account-based setup requires the HTTPS WebGUI. Saved logins belong to your WebGUI user and persist across provider changes and plug-in upgrades. Blank VPN keeps login credentials in private router files outside the OPNsense configuration export. Provider credentials and sessions can expire or be revoked.

| Service | Setup in Blank VPN |
| --- | --- |
| AzireVPN | Sign in with an [AzireVPN API token](https://www.azirevpn.com/docs/api/tokens) that can access your account and IP allocations. |
| IVPN | Sign in with your account ID and enter your authenticator code when prompted. If IVPN requires CAPTCHA, use its account portal to export a WireGuard profile. Blank VPN allows one account-provisioned IVPN tunnel at a time. Remove it before changing locations or signing out. [IVPN CLI guide](https://www.ivpn.net/knowledgebase/general/command-line-client-faq/) |
| Mullvad | Sign in with your account number. Each added server has a separate tunnel and uses an available Mullvad device registration. |
| Mysterium VPN | Start sign-in, approve it in Mysterium's browser flow, then select **Check approval**. Choose a location and IP type. Blank VPN allows one managed Mysterium tunnel at a time. If browser setup fails, import a WireGuard configuration from the Mysterium account portal. [Router configuration guide](https://help.mysteriumvpn.com/en/articles/16010679-how-to-generate-wireguard-configuration-file) |
| NordVPN | Sign in with a [NordVPN router login token](https://support.nordvpn.com/hc/en-us/articles/45535038276753-How-to-generate-a-NordVPN-login-token-to-connect-to-a-VPN-server-on-a-router). The first NordLynx server uses native WireGuard. Additional NordLynx servers use isolated WireGuard sessions in Mihomo, with TCP/UDP forwarding and the same eight active slots shared with proxies. |
| Private Internet Access | Sign in with your PIA username and password. Choose a region to register a local WireGuard key. PIA can expire a registration after inactivity or server restart. Re-add the tunnel if needed. [PIA manual connections](https://github.com/pia-foss/manual-connections) |
| AirVPN, hide.me, OVPN, Proton VPN, Windscribe | Generate a compatible WireGuard profile in the provider portal, then use **Import WireGuard**. You can also attach an existing OPNsense VPN gateway. |
| ExpressVPN, VyprVPN, Other VPN | Attach a compatible OpenVPN or WireGuard tunnel configured in OPNsense with an assigned IPv4 gateway. Use the provider setup guide in the picker. |

VPN and proxy servers appear together in **Network Settings**, grouped alphabetically by service or proxy core. LAN and Tailscale devices can use different servers at the same time, subject to provider limits.

### Add Mullvad servers

1. Open **VPN Login**, enter your Mullvad account number, and sign in. Select **Save login on this router** to restore sign-in in future WebGUI sessions.
2. Pick a country, city and server, then choose **Add server**. Repeat to add another server and keep the existing ones.
3. Test the saved server, then open **Network Settings** to assign it. Each simultaneously saved Mullvad tunnel uses its own device key. Removing a tunnel makes its registered key available for another server. Mullvad allows up to five registered devices per account. [Mullvad device limits](https://mullvad.net/en/help/using-mullvad-vpn-app#too-many-devices)

### Test servers

In **Saved VPN servers**, a new server shows **Standby**. Select **Test** to check HTTPS from the router through that server. A passing test shows **Ready**, and a failed test shows **Error**. Use **×** to dismiss the error details. Routing is configured separately in **Network Settings**.

Use **Ping server** next to a selected Mullvad relay to check ICMP from OPNsense. **Test** can run with device routing off. Native VPN tests use a verified firewall route with a fallback block. Proxy tests try HTTPS targets in different regions. For basic SOCKS5 servers, a failed test can also report upstream TCP, SOCKS5 authentication or TLS errors.

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
| Whole-Network + Multi-Path | Use a base VPN or proxy for ordinary internet traffic and the assigned exits for matching services. The Kill Switch is always on. |
| Off | Follow the native network policy and bypass Blank VPN service routing for the assigned addresses. |
| Blocked | Block internet traffic from the assigned addresses and keep approved local access subject to native firewall rules. |

In **Network Settings**, choose **Only Devices I choose** and press **Refresh** to see LAN devices and Tailscale peers. **Select** fills the addresses and MAC where available. The LAN list shows IPv4 neighbors from OPNsense’s current ARP table. Saved rules stay visible for devices that go offline. For a matching active Kea or Dnsmasq lease, **Reserve IP and save rule** adds a DHCP reservation and applies the rule. For other devices, create a unique reservation in OPNsense first. Selecting Multi-Path for a device uses the domain lists assigned in **Multi-Path Settings**. Add the device’s stable IPv6 address to cover that address as well. On shared LANs, other IPv6 addresses follow the native policy. Use a dedicated strict interface for network-wide internet IPv6 blocking.

**On Demand** is checked by default for new and existing LAN and Tailscale rules that use one server or Multi-Path. With routing enabled, a device’s first matching traffic uses its saved rule. Dedicated WireGuard tunnels with a Kill Switch can idle between uses. Shared tunnels and exits that require monitoring can stay ready. You can use **Kill Switch** with **On Demand**. On Demand leaves Blocked and Off rules as selected.

Check **Follow DHCP reservation by MAC** on a LAN rule to use the device’s unique IPv4 reservation on that Ethernet port or VLAN. If you change the reservation, renew the device’s lease. Blank VPN follows the new address during its next maintenance check and resets affected connections. A missing or conflicting reservation pauses the MAC rule for IPv4. On a shared LAN, IPv4 traffic without a valid binding follows the remaining firewall policy. Use a strict managed interface to block unmatched internet traffic. Keep the client on OPNsense-managed DHCP with a stable MAC address. A manually entered stable IPv6 address remains tied to that address.

You can run multiple provider exits together, with up to 32 VPN profiles and eight active proxy exits. A phone can use Mullvad, a TV ExpressVPN, a tablet a proxy, and a Mac NordVPN. With Multi-Path, select a different exit for each service, such as a Japan exit for Netflix, a USA exit for Hulu, and a China exit for WeChat. Each service uses the domains you enter. Presets are starting lists that you can edit.

Use **Ping** beside an active device rule with a base server for a LAN or Tailscale device. It runs an HTTPS probe from OPNsense through the assigned server and looks for packets in both directions on a firewall state belonging to the device's route. Open a fresh page on the device before running the check.

### Use a base VPN with Multi-Path

For an entire LAN or VLAN, choose **Whole-Network + Multi-Path** and select a **Base VPN or proxy**. For one device or Tailscale peer, choose **Base VPN + Multi-Path** in its device rule. Set each service's exit under **Multi-Path Settings**. For example, set Chicago as the base, Korea for Netflix and Hong Kong for Disney+. Unmatched IPv4 traffic and ordinary DNS use Chicago. Existing Bypass lists have no special routing in the combined mode. Connected local networks and router access are still governed by your OPNsense rules.

The base VPN is required for unmatched internet traffic. The Kill Switch blocks WAN fallback. A learned service whose exit is down is blocked, while other paths can stay up. Domain classification still requires DNS visible to Blank VPN. Unlearned requests use the base. Start a fresh connection after changing a service or clearing the client DNS cache.

Whole-Network + Multi-Path covers all IPv6 on the selected interfaces and blocks public IPv6. Individual rules cover the IPv4 identity and any saved stable IPv6 address, including the peer's Tailscale IPv6 address. For LAN clients with temporary IPv6 addresses, use Whole-Network coverage for that LAN or enable **Block devices without a rule** on a dedicated managed interface.

### Assign a Tailscale peer

From the LAN or console, open **VPN → Tailscale → Settings**. Use Tailscale 1.104.2 or newer. Enable **Advertise Exit Node** and the advanced **Disable SNAT** setting, then apply. OPNsense uses that setting to pass decrypted traffic into the FreeBSD kernel on `tailscale0` with the peer's original address. Applying the change restarts Tailscale. Approve OPNsense as an exit node in Tailscale admin and select it as the exit node on the client. [OPNsense Tailscale configuration](https://github.com/opnsense/plugins/blob/26.7.9/security/tailscale/src/opnsense/service/templates/OPNsense/Tailscale/rc.conf.d) · [Tailscale exit node setup](https://tailscale.com/docs/features/exit-nodes/how-to/setup)

In Blank VPN open **Tailscale Settings** to check readiness. Then open **Network Settings → Only Devices I choose**, save and enable routing, expand **Tailscale devices**, and select the peer. Blank VPN automatically uses the OPNsense Tailscale interface. If the peer is missing from the list, choose **Add by Tailscale IP** and enter its IPv4 address from the Tailscale app. OPNsense verifies both addresses when you save. A green **Disable SNAT checked** label confirms the saved checkbox. The readiness message confirms whether the running daemon can forward through the kernel interface. For an existing gateway on Ethernet or VLAN, select its link under **Tailscale Settings → Use a separate Tailscale gateway**. Use **Disable** beside a saved Tailscale rule to pause its routing and Kill Switch. **Enable** restores the saved rule. While paused, the peer follows the remaining OPNsense policy. Access to the dashboard still follows the OPNsense firewall and Tailscale grants.

Test the public IPv4 from the peer, verify local management access, then test with the VPN disconnected and Kill Switch on. The routed mode supports IPv4 VPN egress and blocks public IPv6 for a protected one-server rule. Multi-Path learning requires DNS queries visible to the OPNsense packet filter. Tailscale can forward DNS internally through its exit-node resolver, so confirm DNS classification on the client before relying on it. [Tailscale DNS preferences](https://tailscale.com/docs/features/client/manage-preferences)

## Route Netflix or another service

1. Open **Multi-Path Settings**. Choose the Netflix preset, paste your own domains, or load a plain-text or comma-separated file. Each list accepts up to 1,000 unique domains and 128 KiB of input. Enter domains on separate lines or separated by commas. Lines may include `#` comments. Both `netflix.com` and `*.netflix.com` cover the apex and its subdomains. Use `.cn` or `*.cn` to match the entire `.cn` top-level domain, including `example.cn` and `service.example.com.cn`.
2. Save the list with an exit selected, or leave it unassigned and edit it later. An unassigned list adds no DNS or firewall rules. Edit any list to replace the domains from a file, change its exit, or download the editor contents as a text file.
3. Choose **Multi-Path** under **Whole-Network coverage** on the **Network Settings** page, or enable Multi-Path for selected interfaces under **More routing options** and assign the Multi-Path mode to devices. Use ordinary DNS on the managed interface. Restart the test application and refresh its DNS cache. Check the learned address count and confirm the expected path from the client.

Use the **Destination** dropdown beside a saved list and choose **Save** to switch servers without editing its domains. Reopen the application or start a new connection and refresh its DNS cache to verify the change.

Choose **Bypass (regular internet)** for domains that should follow the normal OPNsense policy while **Whole-Network coverage → Use one VPN or proxy** is enabled. Bypass uses the native resolver and takes effect when DNS learns the destination IP. The Whole-Network Kill Switch also covers bypassed destinations if the tunnel goes offline.

Multi-Path forwards matching DNS through the chosen tunnel and uses the regular resolver for other names. Learned IPv4 destinations use the VPN and learned IPv6 destinations are blocked. When the exit is unavailable, known destinations are blocked. Multi-Path classifies DNS-observed IPs. Shared IPs, existing connections, encrypted DNS, HTTPS record address hints, and endpoints obtained without an observed DNS lookup can affect which connections match. If two services learn the same destination IP, the first saved service rule has precedence. Learned entries are aged out after about a day and relearned from DNS. Mullvad exit IPs may be blocked by Netflix. [Mullvad Netflix guidance](https://mullvad.net/en/help/watching-netflix-with-split-tunneling)

## Enable and test the Kill Switch

1. For **Only devices I choose**, give the client a unique IPv4 DHCP reservation. Add a device rule and check **Kill Switch** in **All traffic through one exit** or **Multi-Path** mode. Add its stable IPv6 address to protect that address too. For **Whole-Network coverage**, check **Kill Switch** below **Interface** to protect both address families on the selected networks.
2. Click **Save and Enable VPN** on Network. From the protected client, confirm the expected internet exit. Start an internet connection, then take the test exit down. Verify the existing connection stops, new internet connections fail, and a client outside the scope can still use the internet. Check that approved local access remains available after reconnecting.
3. Bring the exit back up and verify internet access recovers. In Multi-Path, every assigned exit needs a successful health check before regular internet resumes. A checked Multi-Path rule with no assigned exit blocks internet until an exit is assigned and verified.

Tunnel health is polled. Multi-Path blocks regular internet once the outage is detected and the firewall rules are applied. VPN exits are probed every minute and active proxy exits are checked on a four-minute rotation. A state reset can interrupt existing local sessions on the protected address or network. Shared-LAN device rules cover only the saved IPs, so additional IPv6 addresses require Whole-Network coverage or a dedicated strict interface.

## Back up and restore routing settings

Open **System Settings → Backup and restore** and choose **Download settings backup**. It saves the Blank VPN routing settings, device rules, Multi-Path lists, and Mullvad server-selection preferences. To restore, disable VPN routing, select the backup made on this router, click **Preview restore**, then confirm **Restore settings**. Existing tunnels are required. Routing stays disabled so you can review the settings before enabling it.

The backup excludes provider credentials, subscription secrets, WireGuard keys, and the native OPNsense configuration. Use **System → Configuration → Backups** for an OPNsense configuration backup. The **Appearance** control under System Settings saves your theme in the browser.

## Upgrade, rollback and removal

- **Upgrade** in a validated lab first. Export the OPNsense configuration, retain the previous package, and verify the new checksum. Use [Update from the WebGUI](#update-from-the-webgui) once signed updates are enabled. Confirm ACLs, the active PF rules, DNS, and both tested exit paths after the upgrade.
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
