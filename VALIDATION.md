# Blank VPN validation

## Completed

| Check | Result |
| --- | --- |
| OPNsense 26.7 platform and upstream contracts | Reviewed stable/26.7 native WireGuard, gateways, firewall plugin API, configuration locking, diagnostics, ACLs and resolver integration. |
| Mullvad integration references | Reviewed Mullvad’s published WireGuard tools and device API source. |
| Dashboard browser fixture | Passed at 390 × 844 and 1280 × 900 with controlled API responses. Covered input escaping, assignment and retarget requests, read-only controls, connections, counters, account and relay rendering, the Netflix preset, service submission, Smart Routing settings, and the proxy import and individual exit controls. |
| PHP and XML source | PHP parsed with Tree-sitter. The repository checks workflow runs the PHP fixtures on an Ubuntu runner. MVC, menu and ACL XML parsed. JavaScript syntax checked with Node. |
| Package archive | Cross-built with the FreeBSD pkg manifest format, verified file checksums and modes against source, and inspected with bsdtar. |
| Router access | Read-only SSH was blocked by the development environment. No router changes or Mullvad account changes were made. |

Run the dashboard fixture again with `python3 tests/ui_fixture.py /path/to/chromium`. The PHP fixtures under `tests/` require a PHP runtime with SimpleXML. The development Mac had no PHP CLI and could only parse the PHP source.

## Required OPNsense lab checks

A passing lab should confirm all of the following on the exact CE 26.7 build. Use controlled WireGuard peers when Mullvad credentials are unavailable. Record the two sets of results independently.

| Test | Expected result |
| --- | --- |
| pkg registration, dashboard, login and ACLs | Native pkg accepts the archive. Fresh install leaves routing disabled. View-only and unauthorized users cannot change policy. |
| HTTPS and local dashboard DNS | The hostname resolves in each permitted group, the HTTPS certificate is trusted and the existing admin entry still works. |
| Smart Routing and wildcard learning | A fresh apex and subdomain lookup populate the PF table and route matched IPv4 through the chosen exit. Test normal DNS over IPv4 and IPv6, shared destination IPs, and unrelated native WAN traffic. |
| Proxy runtime and subscription | Verify the pinned core binaries on FreeBSD and the loopback-only listeners, enable two distinct servers, confirm correct route selection and DNS, and exercise refresh, removal, reboot, and transport loss. |
| Shared-LAN per-IP kill switch | A reserved IPv4 address loses internet when its tunnel goes down. Other clients and approved local services remain available. Start with an existing direct session and confirm activation resets it. |
| Two simultaneous exits and a shared exit | Clients select different IPv4 exits. Two clients share an exit. Moving one client leaves the other sessions on their prior path. |
| Direct internet and DNS | Normal clients follow the intended native WAN. VPN clients use tunnel DNS. Local dashboard DNS stays available. Test UDP, TCP, and common encrypted-DNS client behavior. |
| IPv6 | Internet-bound IPv6, including a new temporary address, cannot leave the managed segment. Approved local IPv6 and essential neighbor discovery still work. |
| Failure and recovery | Test tunnel unavailable at startup, loss after use, no egress with a recent handshake, an explicit backup, explicit WAN fallback, reboot, and stopped discovery. Observe the WAN for unexpected client traffic. |
| Identity and state handling | Change or remove the reservation and confirm the old assignment cannot reclassify a new client. Test apply-to-new and Switch now during simultaneous local and internet sessions. |
| Configuration lifecycle | Force apply failure and confirm rollback. Test concurrent administration changes, reboot, upgrade, disable, and guarded removal. |
| Provider behavior | Test a real Mullvad exit, cache expiry or API outage, account expiry and full slots. Confirm that changing an unassigned profile preserves its registered device. |

There was no matching OPNsense guest or FreeBSD pkg executable on the development host. Native installation, PHP execution on OPNsense, actual data-plane routing, proxy TUN forwarding, and leak resistance remain unverified. Test real Netflix playback separately because service-side VPN restrictions are independent of correct routing.

## Provider and subscription checks

Sign in to Mullvad over HTTPS and add a relay after the account field clears. Sign out and confirm another relay requires sign-in. Attach a native OpenVPN gateway and import a WireGuard profile. Assign a test device to each exit, stop and restart each tunnel, and check the device’s IPv4 egress and the unassigned client’s WAN path. Import a subscription with provider usage fields and confirm the displayed quota and expiry. Enable one server and verify refresh preserves its route.
