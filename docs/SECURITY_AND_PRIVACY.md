# Routing privacy and verification limits

Blank VPN & Proxy controls traffic that reaches the OPNsense router and matches an enabled routing policy. It cannot make an unconditional anonymity, DNS-leak, WebRTC, or torrenting guarantee for every device and configuration.

## What protected routing enforces

- Whole-Network Full routing and a Full device rule route IPv4 through the selected VPN or proxy. With Kill Switch enabled, traffic outside connected/local networks is blocked if the selected path is unavailable.
- Client UDP and TCP DNS on port 53 is redirected to the policy's local DNS listener. The listener uses the selected exit's resolver when its route and firewall guard are verified. Protected listeners have no general WAN resolver.
- Client IPv6 egress is not carried through the current Blank VPN & Proxy tunnel interfaces. Whole-Network protection blocks internet-bound IPv6. Device Kill Switch protection blocks upstream IPv6 across the managed LAN or VLAN, including temporary IPv6 addresses. A known IPv6 address on a routed device is now blocked even when its IPv4 failure policy is set to WAN.
- Proxy endpoint hostnames are bootstrap-resolved by the proxy core. Mihomo now uses DNS over TLS to IP-literal resolvers, Xray uses local-mode DNS over HTTPS to IP-literal resolvers, and sing-box uses certificate-validated DNS over TLS. Client domain DNS remains configured through the selected proxy.
- PF guards reject protected traffic that cannot use its selected tunnel. A successful local SOCKS test alone does not verify client traffic through the proxy TUN interface.

These controls apply only when clients use OPNsense as their gateway and the matching policy is enabled. An unassigned device under **Only devices I choose**, **Off**, **Bypass**, and a selected WAN-fallback policy intentionally allow local ISP traffic. Those modes cannot support a no-ISP-egress claim.

## DNS behavior and limits

Port 53 DNS redirection does not identify DNS carried inside HTTPS or TLS. Under Full routing, such encrypted DNS is ordinary client traffic and follows the selected tunnel. Under Multi-Path, the router cannot learn domain-to-address mappings from encrypted DNS, so the connection stays on the applicable base route or policy default. With an ISP fallback, bypass, or no route, the ISP path can carry that encrypted DNS connection.

The router must contact VPN or proxy endpoints over its WAN to establish the tunnel. Proxy endpoint DNS bootstrap is encrypted, but the DNS provider still sees the router's public source address and the proxy endpoint name. Tunnel endpoints and traffic volumes remain visible as network metadata to the ISP.

Do not interpret a passing DNS test as proof that every client app uses the router resolver. Tests should include the actual client, policy, address family, and applications in use.

## IPv6, WebRTC, and peer-to-peer traffic

Current Blank VPN & Proxy client tunnels route IPv4. IPv6 internet traffic is blocked for protected Whole-Network coverage and for a LAN/VLAN with a device Kill Switch. Devices using unprotected, bypass, or fail-open policies can use ISP IPv6; address discovery and temporary IPv6 behavior also depend on the OPNsense interface and client configuration.

WebRTC ICE can disclose local or private interface addresses to a web application or peer independently of the public egress IP. The router does not install browser-specific WebRTC policy. A routed VPN can keep public STUN/TURN traffic on its selected egress while the browser still reports local candidates. Verify WebRTC behavior in the actual browser and device.

The firewall routes ordinary TCP and UDP packets and does not identify torrent protocols. UDP capability varies by proxy protocol, upstream server, and provider; some providers also restrict peer-to-peer traffic or incoming connections. Repository tests cover configuration validation, protected DNS, IPv4/IPv6 firewall guards, and isolated VPN forwarding. They do not certify named torrent clients, every tracker/DHT/uTP flow, every proxy server's UDP support, or provider terms. Bind a P2P client to its intended tunnel when supported and test the exact client and provider before making any P2P safety claim.

## Verification performed by the repository

Automated checks validate generated proxy-core configurations, routing/DNS plans, PF rule ordering, IPv6 guards, tunnel health checks, and isolated FreeBSD forwarding. These checks are not a substitute for testing each supported OPNsense version, WAN, client, app, VPN provider, proxy endpoint, and DNS mode on the target network.
