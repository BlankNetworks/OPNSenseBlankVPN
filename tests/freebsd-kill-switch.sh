#!/bin/sh
set -eu

# Run inside the disposable FreeBSD CI VM. Each endpoint has its own VNET.
# Only the router jail runs PF or forwards packets. The epairs have no host uplink.
if [ "${1:-}" != --isolated-vm ] || [ "$(uname -s)" != FreeBSD ] ||
    [ "$(id -u)" -ne 0 ] || [ "$(sysctl -n security.jail.jailed)" != 0 ] ||
    [ "$(sysctl -in kern.features.vimage)" != 1 ]; then
    echo 'The PF forwarding test needs root in an isolated FreeBSD VM with VNET.' >&2
    exit 1
fi

kldstat -q -m pf || kldload -n pf
kldstat -q -n if_epair.ko || kldload -n if_epair

router="bvk-router-$$"
client="bvk-client-$$"
wan="bvk-wan-$$"
vpn="bvk-vpn-$$"
override="bvk-override-$$"
lan_link=''
wan_link=''
vpn_link=''
override_link=''
stage=$(mktemp -d)

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        jexec "$router" /sbin/pfctl -vvsr >&2 || :
        jexec "$router" /sbin/pfctl -ss >&2 || :
        for jail_name in "$client" "$wan" "$router"; do
            jexec "$jail_name" ifconfig >&2 || :
            jexec "$jail_name" netstat -rn -f inet6 >&2 || :
            jexec "$jail_name" ndp -an >&2 || :
        done
    fi
    for link in "$lan_link" "$wan_link" "$vpn_link" "$override_link"; do
        if [ -n "$link" ]; then
            ifconfig -j "$router" "$link" destroy 2>/dev/null || :
        fi
    done
    for jail_name in "$client" "$wan" "$vpn" "$override" "$router"; do
        jail -r "$jail_name" 2>/dev/null || :
    done
    for link in "$lan_link" "$wan_link" "$vpn_link" "$override_link"; do
        if [ -n "$link" ]; then
            ifconfig "$link" destroy 2>/dev/null || :
        fi
    done
    rm -rf "$stage"
    exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

lan_link=$(ifconfig epair create)
wan_link=$(ifconfig epair create)
vpn_link=$(ifconfig epair create)
client_link="${lan_link%a}b"
wan_peer="${wan_link%a}b"
vpn_peer="${vpn_link%a}b"
jail -c "name=$router" persist vnet "vnet.interface=$lan_link" "vnet.interface=$wan_link" "vnet.interface=$vpn_link"
jail -c "name=$client" persist vnet allow.raw_sockets "vnet.interface=$client_link"
jail -c "name=$wan" persist vnet "vnet.interface=$wan_peer"
jail -c "name=$vpn" persist vnet "vnet.interface=$vpn_peer"

set_address() {
    jexec "$1" sysctl net.inet6.ip6.dad_count=0
    jexec "$1" ifconfig "$2" inet "$3" up -txcsum -txcsum6
    jexec "$1" ifconfig "$2" inet6 "$4" no_dad
    jexec "$1" ifconfig lo0 up
}

protected4=192.0.2.2
regular4=192.0.2.3
protected6=2001:db8:10::2
regular6=2001:db8:10::3
wan_gateway4=203.0.113.2
wan_gateway6=2001:db8:30::2
wan4=198.18.0.20
wan6=2001:db8:40::2
vpn4=198.18.0.10

set_address "$router" "$lan_link" 192.0.2.1/24 2001:db8:10::1/64
set_address "$router" "$wan_link" 203.0.113.1/24 2001:db8:30::1/64
set_address "$router" "$vpn_link" 198.51.100.1/24 2001:db8:20::1/64
set_address "$client" "$client_link" "$protected4/24" "$protected6/64"
set_address "$wan" "$wan_peer" "$wan_gateway4/24" "$wan_gateway6/64"
set_address "$vpn" "$vpn_peer" 198.51.100.2/24 2001:db8:20::2/64
jexec "$client" ifconfig "$client_link" inet "$regular4/32" alias
jexec "$client" ifconfig "$client_link" inet6 "$regular6/64" alias no_dad
jexec "$wan" ifconfig "$wan_peer" inet "$wan4/32" alias
jexec "$wan" ifconfig "$wan_peer" inet6 "$wan6/128" alias no_dad
jexec "$vpn" ifconfig "$vpn_peer" inet "$vpn4/32" alias

jexec "$router" sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1
jexec "$router" route -n add default "$wan_gateway4"
jexec "$router" route -n add -inet6 default "$wan_gateway6"
jexec "$client" route -n add default 192.0.2.1
jexec "$client" route -n add -inet6 default 2001:db8:10::1
jexec "$wan" route -n add default 203.0.113.1
jexec "$wan" route -n add -inet6 default 2001:db8:30::1
jexec "$vpn" route -n add default 198.51.100.1

pf() {
    jexec "$router" /sbin/pfctl "$@"
}

fail() {
    echo "$*" >&2
    exit 1
}

probe() {
    family=$1 source=$2 target=$3 count=$4 deadline=$5
    shift 5
    jexec "$client" ping "-$family" -n -c "$count" -t "$deadline" -S "$source" "$@" "$target" >"$stage/ping" 2>&1
}

reachable() {
    if ! probe "$@" 3 5 -o; then
        cat "$stage/ping" >&2
        fail "Expected IPv$1 reachability from $2 to $3."
    fi
}

blocked() {
    if probe "$@" 1 2; then
        fail "Unexpected IPv$1 reachability from $2 to $3."
    else
        status=$?
        if [ "$status" -ne 2 ]; then
            cat "$stage/ping" >&2
            fail "The IPv$1 probe failed to run correctly (status $status)."
        fi
    fi
}

rule_matched() {
    pf -s labels | awk -v label="$1" '$1 == label && $3 > 0 { found=1 } END { exit !found }' ||
        fail "Expected a packet to match PF rule $1."
}

has_wan_state() {
    pf -ss | awk -v source="$1" -v target="$2" 'index($0, source) && index($0, target) { found=1 } END { exit !found }'
}

rules="$stage/pf.conf"
tunnel_tag=blankvpn_tunnel_only
write_egress_guard() {
    cat <<EOF
block drop out quick on $wan_link inet tagged $tunnel_tag label "wan_guard_v4"
block drop out quick on $wan_link inet6 tagged $tunnel_tag label "wan_guard_v6"
EOF
}

write_ingress_guard() {
    cat <<EOF
block drop in quick on $lan_link inet from $protected4 to ! <connected> label "lan_guard_v4"
block drop in quick on $lan_link inet6 from $protected6 to ! <connected> label "lan_guard_v6"
EOF
}

# Resolve the IPv6 next hops before using their packet counters as assertions.
reachable 6 "$regular6" 2001:db8:10::1
reachable 6 "$regular6" "$wan_gateway6"
reachable 6 "$regular6" "$wan6"

# Independently demonstrate the tagged WAN guard when an inbound permissive rule
# lets a protected packet reach output evaluation without an established state.
{
    printf 'match in on %s inet from %s tag %s\n' "$lan_link" "$protected4" "$tunnel_tag"
    printf 'match in on %s inet6 from %s tag %s\n' "$lan_link" "$protected6" "$tunnel_tag"
    write_egress_guard
    printf 'pass all no state\n'
} >"$rules"
pf -f "$rules"
pf -e
reachable 4 "$regular4" "$wan4"
reachable 6 "$regular6" "$wan6"
blocked 4 "$protected4" "$wan4"
blocked 6 "$protected6" "$wan6"
rule_matched wan_guard_v4
rule_matched wan_guard_v6
echo 'The tagged WAN guard dropped protected IPv4 and IPv6 without blocking the other client.'

write_protected_rules() {
    {
        printf 'set timeout { icmp.first 90, icmp.error 90 }\n'
        printf 'table <connected> const { 192.0.2.0/24, 2001:db8:10::/64, fe80::/10, ff02::/16 }\n'
        write_egress_guard
        if [ "$1" = healthy ]; then
            printf 'pass in quick on %s route-to (%s 198.51.100.2) inet from %s to ! <connected> tag %s keep state label "vpn_route"\n' \
                "$lan_link" "$vpn_link" "$protected4" "$tunnel_tag"
        fi
        write_ingress_guard
        printf 'pass all keep state\n'
    } >"$rules"
    pf -f "$rules"
}

write_protected_rules healthy
reachable 4 "$protected4" "$vpn4"
rule_matched vpn_route
blocked 6 "$protected6" "$wan6"
rule_matched lan_guard_v6
echo 'The protected IPv4 route used the VPN peer and the IPv6 ingress guard remained active.'

# Simulate an existing unprotected WAN session before the kill switch is applied.
# A filter reload preserves existing state, so check both address families after
# scoped eviction and confirm that a different source retains its WAN state.
printf 'set timeout { icmp.first 90, icmp.error 90 }\npass all keep state\n' >"$rules"
pf -f "$rules"
reachable 4 "$protected4" "$wan4"
reachable 6 "$protected6" "$wan6"
reachable 4 "$regular4" "$wan4"
jexec "$router" ifconfig "$vpn_link" down
write_protected_rules outage
has_wan_state "$protected4" "$wan4" || fail 'Missing stale protected IPv4 state after reload.'
has_wan_state "$protected6" "$wan6" || fail 'Missing stale protected IPv6 state after reload.'
pf -k "$protected4"
pf -k "$protected6"
if has_wan_state "$protected4" "$wan4" || has_wan_state "$protected6" "$wan6"; then
    fail 'Protected WAN state survived scoped eviction.'
fi
has_wan_state "$regular4" "$wan4" || fail 'Scoped eviction removed unrelated WAN state.'
blocked 4 "$protected4" "$wan4"
blocked 6 "$protected6" "$wan6"
rule_matched lan_guard_v4
rule_matched lan_guard_v6
reachable 4 "$regular4" "$wan4"
reachable 6 "$regular6" "$wan6"
reachable 4 "$protected4" 192.0.2.1
reachable 6 "$protected6" 2001:db8:10::1
echo 'Scoped eviction cleared stale protected states. Tunnel loss kept WAN blocked and preserved local access.'

jexec "$router" ifconfig "$vpn_link" up
write_protected_rules healthy
reachable 4 "$protected4" "$vpn4"
blocked 4 "$protected4" "$wan4"
blocked 6 "$protected6" "$wan6"
rule_matched vpn_route
echo 'VPN access recovered while protected direct WAN traffic remained blocked.'

# This service is reachable from any exit. A bad fallthrough to the base VPN
# or WAN therefore responds to the probe and fails the outage assertion.
override4=198.18.0.30
override_link=$(ifconfig epair create)
override_peer="${override_link%a}b"
ifconfig "$override_link" vnet "$router"
jail -c "name=$override" persist vnet "vnet.interface=$override_peer"
set_address "$router" "$override_link" 10.220.1.1/24 2001:db8:50::1/64
set_address "$override" "$override_peer" 10.220.1.2/24 2001:db8:50::2/64
jexec "$override" route -n add default 10.220.1.1
jexec "$override" ifconfig "$override_peer" inet "$override4/32" alias
jexec "$vpn" ifconfig "$vpn_peer" inet "$override4/32" alias
jexec "$wan" ifconfig "$wan_peer" inet "$override4/32" alias

write_combined_rules() {
    {
        printf 'set timeout { icmp.first 90, icmp.error 90 }\n'
        printf 'table <connected> const { 192.0.2.0/24, 2001:db8:10::/64, fe80::/10, ff02::/16 }\n'
        printf 'table <service> const { %s }\n' "$override4"
        write_egress_guard
        printf 'match in on %s inet from %s to ! <connected> tag blankvpn_combined_scope\n' \
            "$lan_link" "$protected4"
        if [ "$1" != override_down ]; then
            printf 'pass in quick on %s route-to (%s 10.220.1.2) inet to <service> tag %s tagged blankvpn_combined_scope keep state label "override_route"\n' \
                "$lan_link" "$override_link" "$tunnel_tag"
        fi
        printf 'block drop in quick on %s inet to <service> tagged blankvpn_combined_scope label "override_guard"\n' \
            "$lan_link"
        if [ "$1" != base_down ]; then
            printf 'pass in quick on %s route-to (%s 198.51.100.2) inet from %s to ! <connected> tag %s keep state label "base_route"\n' \
                "$lan_link" "$vpn_link" "$protected4" "$tunnel_tag"
        fi
        write_ingress_guard
        printf 'pass all keep state\n'
    } >"$rules"
    pf -f "$rules"
}

# Preserve a control client capable of using the same service over the ISP.
reachable 4 "$regular4" "$override4"
write_combined_rules healthy
pf -k "$protected4"
reachable 4 "$protected4" "$vpn4"
reachable 4 "$protected4" "$override4"
rule_matched base_route
rule_matched override_route

jexec "$router" ifconfig "$override_link" down
write_combined_rules override_down
pf -k "$protected4" -k "$override4"
blocked 4 "$protected4" "$override4"
rule_matched override_guard
reachable 4 "$protected4" "$vpn4"
reachable 4 "$regular4" "$override4"
reachable 4 "$regular4" "$wan4"
echo 'An unavailable Multi-Path override blocked only its matched destinations. The base VPN and unrelated WAN client stayed online.'

jexec "$router" ifconfig "$override_link" up
write_combined_rules healthy
reachable 4 "$protected4" "$override4"
rule_matched override_route

jexec "$router" ifconfig "$vpn_link" down
write_combined_rules base_down
pf -k "$protected4"
blocked 4 "$protected4" "$vpn4"
reachable 4 "$protected4" "$override4"
rule_matched override_route
reachable 4 "$regular4" "$override4"
echo 'Losing the base VPN blocked unmatched protected traffic while the healthy Multi-Path override stayed online.'
