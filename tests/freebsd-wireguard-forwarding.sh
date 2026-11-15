#!/bin/sh
set -eu

# Exercise the actual WireGuard data path without a network connection outside the VM.
if [ "${1:-}" != --isolated-vm ] || [ "$(uname -s)" != FreeBSD ] ||
    [ "$(id -u)" -ne 0 ] || [ "$(sysctl -n security.jail.jailed)" != 0 ] ||
    [ "$(sysctl -in kern.features.vimage)" != 1 ]; then
    echo 'The WireGuard forwarding test needs root in an isolated FreeBSD VM with VNET.' >&2
    exit 1
fi

kldstat -q -m pf || kldload -n pf
kldstat -q -n if_epair.ko || kldload -n if_epair
kldstat -q -n if_wg.ko || kldload -n if_wg
command -v wg >/dev/null

router="bvwg-router-$$"
client="bvwg-client-$$"
exit_node="bvwg-exit-$$"
ingress=''
underlay=''
router_wg=''
exit_wg=''
stage=$(mktemp -d)

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        jexec "$router" pfctl -vvsr >&2 || :
        jexec "$router" pfctl -vvs nat >&2 || :
        jexec "$router" pfctl -ss >&2 || :
        jexec "$router" wg show >&2 || :
        jexec "$exit_node" wg show >&2 || :
    fi
    if [ -n "$router_wg" ]; then
        jexec "$router" ifconfig "$router_wg" destroy 2>/dev/null || :
    fi
    if [ -n "$exit_wg" ]; then
        jexec "$exit_node" ifconfig "$exit_wg" destroy 2>/dev/null || :
    fi
    for interface in "$ingress" "$underlay"; do
        if [ -n "$interface" ]; then
            ifconfig -j "$router" "$interface" destroy 2>/dev/null || :
        fi
    done
    for jail_name in "$client" "$exit_node" "$router"; do
        jail -r "$jail_name" 2>/dev/null || :
    done
    for interface in "$ingress" "$underlay"; do
        if [ -n "$interface" ]; then
            ifconfig "$interface" destroy 2>/dev/null || :
        fi
    done
    rm -rf "$stage"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

ingress=$(ifconfig epair create)
underlay=$(ifconfig epair create)
client_link="${ingress%a}b"
exit_link="${underlay%a}b"
jail -c "name=$router" persist vnet "vnet.interface=$ingress" "vnet.interface=$underlay"
jail -c "name=$client" persist vnet "vnet.interface=$client_link"
jail -c "name=$exit_node" persist vnet "vnet.interface=$exit_link"

client_addr=100.73.204.22
client_gateway=100.73.204.1
router_underlay=192.0.2.1
exit_underlay=192.0.2.2
router_tunnel=10.130.65.41
exit_tunnel=10.130.65.42
service=198.18.20.1
service_port=8443
probe_port=9443
wireguard_port=51820

jexec "$router" ifconfig "$ingress" inet "$client_gateway/24" up -txcsum -txcsum6
jexec "$client" ifconfig "$client_link" inet "$client_addr/24" up -txcsum -txcsum6
jexec "$router" ifconfig "$underlay" inet "$router_underlay/24" up -txcsum -txcsum6
jexec "$exit_node" ifconfig "$exit_link" inet "$exit_underlay/24" up -txcsum -txcsum6
jexec "$exit_node" ifconfig lo0 inet "$service/32" alias up
jexec "$router" route -n add default "$exit_underlay"
jexec "$client" route -n add default "$client_gateway"
jexec "$router" sysctl net.inet.ip.forwarding=1

router_wg=$(jexec "$router" ifconfig wg create)
exit_wg=$(jexec "$exit_node" ifconfig wg create)
umask 077
wg genkey >"$stage/router.key"
wg genkey >"$stage/exit.key"
router_key=$(wg pubkey <"$stage/router.key")
exit_key=$(wg pubkey <"$stage/exit.key")
jexec "$router" wg set "$router_wg" private-key "$stage/router.key" listen-port 51821 \
    peer "$exit_key" endpoint "$exit_underlay:51820" allowed-ips 0.0.0.0/0
jexec "$exit_node" wg set "$exit_wg" private-key "$stage/exit.key" listen-port 51820 \
    peer "$router_key" allowed-ips "$router_tunnel/32"
jexec "$router" ifconfig "$router_wg" inet "$router_tunnel/32" mtu 1420 up
jexec "$exit_node" ifconfig "$exit_wg" inet "$exit_tunnel/24" mtu 1420 up

pf() {
    jexec "$router" pfctl "$@"
}

write_rules() {
    scope=$1
    # The tunnel has no gateway address. Its WireGuard peer lookup uses the packet destination.
    cat >"$stage/pf.conf" <<EOF
set skip on lo0
table <connected> const { 100.64.0.0/10, 192.0.2.0/24 }
nat on $router_wg inet from $scope to any -> $router_tunnel
block all
block out quick on $underlay inet tagged vpn_client label "plain_wan_guard"
pass out quick on $underlay inet proto udp from $router_underlay to $exit_underlay port $wireguard_port keep state
pass out quick route-to $router_wg inet proto tcp from $router_tunnel to $service port $probe_port keep state label "router_probe"
block out quick inet proto tcp from $router_tunnel to $service port $probe_port
pass in quick on $ingress route-to $router_wg inet from $scope to ! <connected> scrub (max-mss 1240) tag vpn_client keep state (if-bound) label "client_ingress"
block in quick on $ingress inet from $scope to ! <connected>
pass out on $router_wg inet from $router_tunnel scrub (max-mss 1240) tagged vpn_client keep state (floating) label "translated_egress"
EOF
    pf -f "$stage/pf.conf"
    pf -F states
}

listen_tcp() {
    timeout -k 2 7 jexec "$exit_node" sh -c 'printf "%s\n" "$3" | timeout -f -k 2 7 nc -N -l "$1" "$2"' \
        sh "$service" "$1" "$2" &
    listener=$!
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if jexec "$exit_node" sockstat -4l | grep -Fq "$service:$1"; then
            return 0
        fi
        sleep 0.1
    done
    echo "TCP listener did not start on $service:$1." >&2
    exit 1
}

check_tcp() {
    source_jail=$1 source_addr=$2 port=$3 expected=$4
    listen_tcp "$port" "$expected"
    actual=$(jexec "$source_jail" nc -N -w 4 -s "$source_addr" "$service" "$port" </dev/null) || {
        echo "TCP request failed for $expected." >&2
        exit 1
    }
    wait "$listener"
    if [ "$actual" != "$expected" ]; then
        echo "Expected TCP response \"$expected\", got \"$actual\"." >&2
        exit 1
    fi
}

rule_matched() {
    pf -s labels | awk -v label="$1" '$1 == label && $3 > 0 { found=1 } END { exit !found }'
}

check_forwarding() {
    write_rules 100.64.0.0/10
    check_tcp "$router" "$router_tunnel" "$probe_port" 'router probe'
    check_tcp "$client" "$client_addr" "$service_port" 'Whole-Network WireGuard'
    rule_matched translated_egress

    write_rules "$client_addr"
    check_tcp "$client" "$client_addr" "$service_port" 'per-device WireGuard'
    rule_matched translated_egress
}

write_probe_rules() {
    {
        printf 'set skip on lo0\n'
        if [ "$1" = protected ]; then
            printf 'no nat inet proto tcp from %s to %s port %s\n' \
                "$router_tunnel" "$service" "$probe_port"
        fi
        cat <<EOF
nat on $underlay inet from $router_tunnel to any -> $router_underlay
block all
pass out quick on $underlay inet proto udp from $router_underlay to $exit_underlay port $wireguard_port keep state
EOF
        if [ "$2" = available ]; then
            printf 'pass out quick route-to %s inet proto tcp from %s to %s port %s keep state label "router_probe"\n' \
                "$router_wg" "$router_tunnel" "$service" "$probe_port"
        fi
        cat <<EOF
block out quick inet proto tcp from $router_tunnel to $service port $probe_port label "probe_guard"
pass out quick on $underlay inet proto tcp from $router_underlay to $service port $probe_port keep state label "wan_probe"
EOF
    } >"$stage/pf.conf"
    pf -f "$stage/pf.conf"
    pf -F states
}

check_probe_isolation() {
    write_probe_rules legacy available
    check_tcp "$router" "$router_tunnel" "$probe_port" 'legacy WAN false positive'
    rule_matched wan_probe
    if rule_matched router_probe; then
        echo 'The WAN false-positive fixture also matched the tunnel policy.' >&2
        exit 1
    fi

    write_probe_rules protected available
    check_tcp "$router" "$router_tunnel" "$probe_port" 'protected WireGuard probe'
    rule_matched router_probe
    if rule_matched wan_probe; then
        echo 'The protected WireGuard probe escaped through the WAN.' >&2
        exit 1
    fi

    write_probe_rules protected unavailable
    listen_tcp "$probe_port" 'unprotected WAN fallback'
    if jexec "$router" nc -z -w 2 -s "$router_tunnel" "$service" "$probe_port"; then
        echo 'The protected probe succeeded through WAN with no WireGuard route.' >&2
        exit 1
    fi
    wait "$listener" || :
    rule_matched probe_guard
    if rule_matched wan_probe; then
        echo 'The protected probe reached the WAN with no WireGuard route.' >&2
        exit 1
    fi
}

write_dns_rules() {
    protection=$1
    {
        printf 'set skip on lo0\n'
        if [ "$protection" = protected ]; then
            for protocol in tcp udp; do
                printf 'no nat inet proto %s from %s to %s port 53\n' \
                    "$protocol" "$router_tunnel" "$service"
            done
        fi
        cat <<EOF
nat on $underlay inet from $router_tunnel to any -> $router_underlay
block all
pass out quick on $underlay inet proto udp from $router_underlay to $exit_underlay port $wireguard_port keep state
pass out quick route-to $router_wg inet proto udp from $router_tunnel to $service port 53 keep state label "router_dns"
block out quick inet proto udp from $router_tunnel to $service port 53 label "dns_guard"
pass out quick on $underlay inet proto udp from $router_underlay to $service port 53 keep state label "wan_dns"
EOF
    } >"$stage/pf.conf"
    pf -f "$stage/pf.conf"
    pf -F states
}

send_dns_packet() {
    printf 'dns-path-fixture\n' | timeout -k 2 4 jexec "$router" nc -u -w 1 -s "$router_tunnel" "$service" 53 || :
}

check_dns_nat_isolation() {
    write_dns_rules legacy
    send_dns_packet
    rule_matched wan_dns
    if rule_matched router_dns; then
        echo 'The DNS fixture unexpectedly used WireGuard before the NAT exclusion.' >&2
        exit 1
    fi

    write_dns_rules protected
    timeout -k 2 5 jexec "$exit_node" tcpdump -ni "$exit_wg" -c 1 'udp dst port 53' \
        >"$stage/dns-on-wireguard" 2>/dev/null &
    capture=$!
    sleep 0.3
    send_dns_packet
    wait "$capture"
    grep -F "$router_tunnel." "$stage/dns-on-wireguard" >/dev/null
    rule_matched router_dns
    if rule_matched wan_dns; then
        echo 'The protected provider DNS escaped through WAN.' >&2
        exit 1
    fi
}

check_client_dns_redirect() {
    cat >"$stage/pf.conf" <<EOF
set skip on lo0
rdr on $ingress inet proto udp from $client_addr to any port 53 tag client_dns_redirect -> 127.0.0.1 port 47060
block all
pass in quick on $ingress inet proto udp from $client_addr to 127.0.0.1 port 47060 tagged client_dns_redirect keep state label "client_dns_redirected"
EOF
    pf -f "$stage/pf.conf"
    pf -F states
    printf 'client-dns-fixture\n' | timeout -k 2 4 jexec "$client" nc -u -w 1 -s "$client_addr" "$client_gateway" 53 || :
    rule_matched client_dns_redirected
}

pf -e
check_forwarding
if jexec "$router" sysctl -n net.pf.share_forward >/dev/null 2>&1; then
    for enabled in 0 1; do
        jexec "$router" sysctl "net.pf.share_forward=$enabled"
        check_forwarding
    done
fi
echo 'Whole-Network and per-device TCP passed through policy routing, source NAT and two real WireGuard peers.'
check_probe_isolation
echo 'WAN source NAT reproduced the false positive. Probe-specific NAT exclusion keeps the tunnel test on WireGuard and blocks WAN fallback.'
check_dns_nat_isolation
echo 'Provider DNS kept its tunnel source and crossed WireGuard after the targeted NAT exclusion.'
check_client_dns_redirect
echo 'A LAN DNS request with an ephemeral source port reached the protected listener redirect.'

wireguard_port=53
jexec "$exit_node" wg set "$exit_wg" listen-port "$wireguard_port"
jexec "$router" wg set "$router_wg" peer "$exit_key" endpoint "$exit_underlay:$wireguard_port"
test "$(jexec "$router" wg show "$router_wg" public-key)" = "$router_key"
test "$(jexec "$router" wg show "$router_wg" endpoints | cut -f2)" = "$exit_underlay:$wireguard_port"
check_forwarding
echo 'The same WireGuard identity and relay passed forwarded TCP over alternate UDP port 53.'
