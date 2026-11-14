# Blank VPN validation

## Completed

| Check | Result |
| --- | --- |
| OPNsense 26.7 platform and upstream contracts | Reviewed stable/26.7 native WireGuard, gateways, firewall plugin API, configuration locking, diagnostics, ACLs and resolver integration. |
| Mullvad integration references | Reviewed Mullvad’s published WireGuard tools and device API source. |
| Dashboard browser fixture | Passed at 390 × 844 and 1280 × 900 with controlled API responses. Covered input escaping, assignment and retarget requests, read-only controls, connections, counters, account and relay rendering, the Netflix preset, service submission, Multi-Path settings, the proxy import and individual exit controls, MAC and On Demand options, signed-update controls, and routing backup and restore. |
| PHP and XML source | PHP parsed with Tree-sitter. The repository checks workflow runs the PHP fixtures on an Ubuntu runner. MVC, menu and ACL XML parsed. JavaScript syntax checked with Node. |
| Package archives | The release workflow checks the ABI and checksums for both FreeBSD architectures, opens each package with native pkg in a FreeBSD 15.1 guest, and runs the bundled core version commands. |
| Router access | Read-only SSH was blocked by the development environment. No router changes or Mullvad account changes were made. |

Run the dashboard fixture again with `python3 tests/ui_fixture.py /path/to/chromium`. The PHP fixtures under `tests/` require a PHP runtime with SimpleXML. The development Mac had no PHP CLI and could only parse the PHP source.

## Required OPNsense lab checks

A passing lab should confirm all of the following on the exact CE 26.7 build. Use controlled WireGuard peers when Mullvad credentials are unavailable. Record the two sets of results independently.

| Test | Expected result |
| --- | --- |
| pkg registration, dashboard, login and ACLs | Native pkg accepts the archive. Fresh install leaves routing disabled. View-only and unauthorized users cannot change policy. |
| HTTPS and local dashboard DNS | The hostname resolves in each permitted group, the HTTPS certificate is trusted and the existing admin entry still works. |
| Whole-Network + Multi-Path | Confirm unmatched IPv4 and uncategorized DNS take the base tunnel and nominated IPv4 destinations take their assigned exits. Stop the base and each override independently. Confirm direct WAN and public IPv6 stay blocked. Repeat for a LAN and Tailscale device rule with an unaffected neighboring client. |
| Multi-Path and wildcard learning | A fresh apex and subdomain lookup populate the PF table and route matched IPv4 through the chosen exit. Test normal DNS over IPv4 and IPv6, shared destination IPs, and unrelated native WAN traffic. |
| DHCP-only device discovery | Connect or renew a Kea or Dnsmasq client, and confirm Refresh shows its current IPv4 before ARP learns it. Verify a device on an unselected VLAN appears with setup guidance. Confirm conflicting or expired addresses cannot be reserved. |
| Explicit Multi-Path destinations | Add a mixed domain/IP list and verify IPv4 CIDRs route before learned entries, even with no DNS query. Stop the assigned tunnel and confirm matching traffic is blocked. Confirm LAN access and age out only learned PF entries. |
| Proxy runtime and subscription | Verify the pinned core binaries on FreeBSD and the loopback-only listeners, enable two distinct servers, confirm correct route selection and DNS, and exercise refresh, removal, reboot, and transport loss. |
| Shared-LAN per-IP kill switch | A reserved IPv4 address loses internet when its tunnel goes down. Other clients and approved local services remain available. Start with an existing direct session and confirm activation resets it. |
| Two simultaneous exits and a shared exit | Clients select different IPv4 exits. Two clients share an exit. Moving one client leaves the other sessions on their prior path. |
| Direct internet and DNS | Normal clients follow the intended native WAN. VPN clients use tunnel DNS. Local dashboard DNS stays available. Test UDP, TCP, and common encrypted-DNS client behavior. |
| IPv6 | Internet-bound IPv6, including a new temporary address, cannot leave the managed segment. Approved local IPv6 and essential neighbor discovery still work. |
| Failure and recovery | Test tunnel unavailable at startup, loss after use, no egress with a recent handshake, an explicit backup, explicit WAN fallback, reboot, and stopped discovery. Observe the WAN for unexpected client traffic. |
| Identity and state handling | Change or remove the reservation and confirm the old assignment cannot reclassify a new client. Test apply-to-new and Switch now during simultaneous local and internet sessions. |
| Configuration lifecycle | Force apply failure and confirm rollback. Test concurrent administration changes, reboot, upgrade, disable, and guarded removal. |
| On Demand LAN and Tailscale | Create one-server rules with On Demand and Kill Switch together. Send the first request after idle and reboot. Verify egress through the assigned server, including when the Tailscale peer was offline. Stop the tunnel and check that no WAN traffic escapes. Test a shared exit and an existing Multi-Path rule. |
| MAC reservation movement | Change the OPNsense DHCP reservation, renew the test client, and verify routing at the new IPv4 and removal of states at the old one. Assign the original IP to another device, then test conflicting DHCP and ARP claims. |
| Signed package upgrade | Enable the signed repository in System Settings. Confirm Blank VPN appears in OPNsense Firmware and can upgrade from the previous release without modifying other packages. Exercise WebGUI reconnection, retained credentials and package-lock refusal. |
| Routing backup and restore | Export routing settings, change a rule, disable routing, preview the file and restore. Confirm the saved rules return, existing tunnels remain present and routing stays disabled. Reject an edited or different-router file. |
| Provider behavior | Test a real Mullvad exit, cache expiry or API outage, account expiry and full slots. Confirm that changing an unassigned profile preserves its registered device. |

There was no matching OPNsense guest on the development host. Installation and data-plane behavior on physical OPNsense routers, including the NanoPi, still need lab verification. Test real Netflix playback separately because service-side VPN restrictions are independent of correct routing.

## Provider and subscription checks

Sign in to Mullvad over HTTPS and add a relay after the account field clears. Sign out and confirm another relay requires sign-in. Attach a native OpenVPN gateway and import a WireGuard profile. Assign a test device to each exit, stop and restart each tunnel, and check the device’s IPv4 egress and the unassigned client’s WAN path. Import a subscription with provider usage fields and confirm the displayed quota and expiry. Enable one server and verify refresh preserves its route.
