# Blank VPN & Proxy validation

## Completed

| Check | Result |
| --- | --- |
| OPNsense 26.7 platform and upstream contracts | Reviewed stable/26.7 native WireGuard, gateways, firewall plugin API, configuration locking, diagnostics, ACLs and resolver integration. |
| Mullvad integration references | Reviewed Mullvad’s published WireGuard tools and device API source. |
| Dashboard browser fixture | Passed at 390 × 844 and 1280 × 900 with controlled API responses. Covered input escaping, assignment and retarget requests, read-only controls, connections, counters, account and relay rendering, the Netflix preset, service submission, Multi-Path settings, the proxy import and individual exit controls, MAC and On Demand options, signed-update controls, and routing backup and restore. |
| PHP and XML source | The repository checks workflow runs the PHP fixtures and syntax checks. MVC, menu and ACL XML are parsed. JavaScript syntax is checked with Node. |
| Package archives | The release workflow checks the ABI and checksums for both FreeBSD architectures, opens each package with native pkg in a FreeBSD 15.1 guest, and runs the bundled core version commands. |
| Packet-filter fail-closed fixture | The release workflow uses isolated FreeBSD 15.1 networks to test tagged IPv4 and IPv6 WAN blocking, pinned VPN routes, removal of stale WAN states, preserved local access, and recovery. It also verifies that a failed Multi-Path override blocks its own destination while the base VPN and an unrelated WAN client stay online. |
| Physical OPNsense router | Upgraded an amd64 OPNsense 26.7 router from 0.8.29 to the signed 0.8.30 package. Fresh SSH through Tailscale worked after the upgrade and routing tests; Tailscale settings and management routes were not changed. See the dated results below. |

Run the dashboard fixture again with `python3 tests/ui_fixture.py /path/to/chromium`. The PHP fixtures under `tests/` require a PHP runtime with SimpleXML.

## Physical OPNsense verification — 2026-11-15

These results came from one router and its LAN iPad. The protected configuration and pre-upgrade package were backed up, with timed rollback armed for live changes. No credentials or private keys are included here.

| Check | Observation |
| --- | --- |
| Whole-Network proxy browsing | The iPad loaded both a numeric-IP HTTPS page and a hostname HTTPS page. Its observed LAN client states showed bidirectional HTTPS through the selected proxy TUN and no direct WAN HTTPS states. A router-originated HTTPS request forced through the same TUN returned HTTP 200. |
| Proxy exit address and IPv6 | The iPad's Cloudflare trace and a router request through the TUN reported the same public IPv6 exit address and Swiss location. The router had no IPv6 default route, and its LAN IPv6 Kill Switch rule was loaded. The public IPv6 address was the proxy's website-facing exit; this was not an IPv6 packet test from the iPad. |
| Client DNS | OPNsense loaded destination-port-53 redirects for LAN UDP and TCP DNS. The selected proxy's local resolver returned NOERROR for a hostname. Bidirectional client DNS states were observed during the live redirect repair, before the package upgrade. A fresh client DNS packet was not captured after the upgrade. |
| Mullvad DNS and IPv4 | Under a temporary protected Chicago WireGuard policy, provider DNS returned NOERROR over the tunnel and a numeric-IP HTTPS request returned HTTP 200. A router-originated provider DNS query while that profile was unselected later followed WAN and timed out; that unselected query does not validate the selected-client path. The protected Chicago test was not repeated after package installation. |
| State resets | Whole-Network activation removed old direct-WAN and tunnel sessions from the managed LAN client while preserving Tailscale SSH. The per-device reset removed 57 selected translated client state IDs, retained the observed other-client state, and preserved fresh Tailscale SSH. |
| Kill Switch and recovery | Stopping the Blank VPN proxy worker under a timed rollback loaded explicit IPv4 and IPv6 outage blocks without direct WAN client states. The worker and normal proxy route recovered. After package installation, a transient failed proxy health observation left the outage guard active even though the TUN returned HTTP 200; recording a successful probe restored the protected route. The cause and automatic recovery time of that transient observation remain unverified. |
| Tailscale exit-node forwarding | Fresh Tailscale SSH to the router worked. With its separate Blank VPN Tailscale scope disabled and os-tailscale 1.4 **Disable SNAT** off, an iPhone selected OPNsense as its exit node. Both a numeric-IP HTTPS page and a hostname HTTPS page loaded. The numeric-IP page reported exactly the router's direct WAN public address, not the Swiss proxy exit. The iPhone's Tailscale peer counters rose while a `tailscale0` capture and PF state check showed no forwarded peer packets. This confirms the current userspace exit-node path bypasses Blank VPN's PF routing. A client DNS packet was not captured, so the resolver used by the hostname request was not identified. |
| Release checks | Repository PHP, browser, package, and FreeBSD forwarding checks passed for 0.8.30. Both package architectures and the signed repository were published; the router's signed updater installed 0.8.30 successfully. |

Live browsing was verified under Whole-Network proxy coverage, and the Tailscale exit node was verified to use direct WAN in its current userspace mode. The separate per-device browser flow, a fresh post-upgrade client DNS packet, an internet-bound IPv6 packet from the iPad, and protected Tailscale exit-node forwarding still need their own controlled tests.

## Required OPNsense lab checks

A passing lab should confirm all of the following on the exact CE 26.7 build. Use controlled WireGuard peers when Mullvad credentials are unavailable. Record the two sets of results independently.

| Test | Expected result |
| --- | --- |
| pkg registration, dashboard, login and ACLs | Native pkg accepts the archive. Fresh install leaves routing disabled. View-only and unauthorized users cannot change policy. |
| HTTPS and local dashboard DNS | The hostname resolves in each permitted group, the HTTPS certificate is trusted and the existing admin entry still works. |
| Whole-Network + Multi-Path | Confirm unmatched IPv4 and uncategorized DNS take the base tunnel and nominated IPv4 destinations take their assigned exits. Stop an override and verify its domains and IP ranges stop working while base traffic and healthy overrides continue. Stop the base independently and verify unmatched traffic stops while healthy overrides stay reachable. Confirm direct WAN and public IPv6 stay blocked, then verify recovery. Repeat for a LAN and Tailscale device rule with an unaffected neighboring client. |
| Independent routing coverage | Configure a Local base and a different Tailscale base. Confirm matched and unmatched IPv4 paths from one LAN client and a remote client using the exit node with direct router DNS. Switch Tailscale to Only Devices I choose and test a selected and unselected peer. Disable each scope separately and check the other scope and router HTTPS. |
| Multi-Path and wildcard learning | A fresh apex and subdomain lookup populate the PF table and route matched IPv4 through the chosen exit. Test normal DNS over IPv4 and IPv6, shared destination IPs, and unrelated native WAN traffic. |
| DHCP-only device discovery | Connect or renew a Kea or Dnsmasq client, and confirm Refresh shows its current IPv4 before ARP learns it. Verify a device on an unselected VLAN appears with setup guidance. Confirm conflicting or expired addresses cannot be reserved. |
| Explicit Multi-Path destinations | Add a mixed domain/IP list and verify IPv4 CIDRs route before learned entries, even with no DNS query. Stop the assigned tunnel and confirm matching traffic is blocked. Confirm LAN access and age out only learned PF entries. |
| Proxy runtime and subscription | Verify the pinned core binaries on FreeBSD and the loopback-only listeners, enable two distinct servers, confirm correct route selection and DNS, and exercise refresh, removal, reboot, and transport loss. |
| Shared-LAN per-IP Kill Switch | Start with an existing direct session, enable the Kill Switch, and confirm the session is reset. Stop a VPN and a proxy separately. Confirm WAN, DNS and public IPv6 cannot escape. Verify unrelated clients retain IPv4 when the protected device reservation remains confirmed, and verify local access. |
| Two simultaneous exits and a shared exit | Clients select different IPv4 exits. Two clients share an exit. Moving one client leaves the other sessions on their prior path. |
| Direct internet and DNS | Normal clients follow the intended native WAN. VPN clients use tunnel DNS. Local dashboard DNS stays available. Test UDP, TCP, and common encrypted-DNS client behavior. |
| IPv6 | Internet-bound IPv6, including a new temporary address, cannot leave the managed segment. Approved local IPv6 and essential neighbor discovery still work. |
| Failure and recovery | Test tunnel unavailable at startup, loss after use, no direct egress with a recent handshake, an explicit backup, reboot, and stopped discovery. Confirm Bypass is paused with the Kill Switch enabled. Test explicit WAN fallback separately with the Kill Switch off. Observe the WAN for unexpected client traffic. |
| Identity and state handling | Change or remove the reservation and confirm the old assignment cannot reclassify a new client. Test apply-to-new and Switch now during simultaneous local and internet sessions. |
| Configuration lifecycle | Force apply failure and confirm rollback. Test concurrent administration changes, reboot, upgrade, disable, and guarded removal. |
| On Demand LAN and Tailscale | Create one-server rules with On Demand and Kill Switch together. Send the first request after idle and reboot. Verify egress through the assigned server, including when the Tailscale peer was offline. Stop the tunnel and check that no WAN traffic escapes. Test a shared exit and an existing Multi-Path rule. |
| MAC reservation movement | Change the OPNsense DHCP reservation, renew the test client, and verify routing at the new IPv4 and removal of states at the old one. Assign the original IP to another device, then test conflicting DHCP and ARP claims. |
| Signed package upgrade | Enable the signed repository in System Settings. Confirm Blank VPN & Proxy appears in OPNsense Firmware and can upgrade from the previous release without modifying other packages. Exercise WebGUI reconnection, retained credentials and package-lock refusal. |
| Routing backup and restore | Export routing settings, change a rule, disable routing, preview the file and restore. Confirm the saved rules return, existing tunnels remain present and routing stays disabled. Reject an edited or different-router file. |
| Provider behavior | Test a real Mullvad exit, cache expiry or API outage, account expiry and full slots. Confirm that changing an unassigned profile preserves its registered device. |
| Sustained operation | Run a 72-hour soak with concurrent WireGuard and proxy traffic and one normal WAN client. Include idle periods, upstream outages, failed and successful subscription refreshes, process restarts and a router reboot. Record per-worker resident memory and count, PF state and learned-address counts, disk free space, and latency and throughput for the normal WAN client. Compare readings at equivalent idle and load levels for growth across recovery cycles. |

The physical check above covers one amd64 router and one LAN client. ARM64 package behavior, the remaining lab cases, and sustained operation still need separate verification. Test real Netflix playback separately because service-side VPN restrictions are independent of correct routing.

## Provider and subscription checks

Sign in to Mullvad over HTTPS and add a relay after the account field clears. Sign out and confirm another relay requires sign-in. Attach a native OpenVPN gateway and import a WireGuard profile. Assign a test device to each exit, stop and restart each tunnel, and check the device’s IPv4 egress and the unassigned client’s WAN path. Import a subscription with provider usage fields and confirm the displayed quota and expiry. Enable one server and verify refresh preserves its route.
