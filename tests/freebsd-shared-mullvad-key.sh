#!/bin/sh
set -eu

# Prove two concurrent policy-routed exits can share one WireGuard device key.
if [ "${1:-}" != --isolated-vm ] || [ "$(uname -s)" != FreeBSD ] ||
    [ "$(id -u)" -ne 0 ] || [ "$(sysctl -n security.jail.jailed)" != 0 ] ||
    [ "$(sysctl -in kern.features.vimage)" != 1 ]; then
    echo 'The shared-key test needs root in an isolated FreeBSD VM with VNET.' >&2
    exit 1
fi

kldstat -q -m pf || kldload -n pf
kldstat -q -n if_epair.ko || kldload -n if_epair
kldstat -q -n if_wg.ko || kldload -n if_wg
command -v wg >/dev/null

router="bvshared-router-$$"
client="bvshared-client-$$"
exit1="bvshared-exit1-$$"
exit2="bvshared-exit2-$$"
stage=$(mktemp -d)
ingress=''
underlay1=''
underlay2=''
router_wg1=''
router_wg2=''
exit_wg1=''
exit_wg2=''

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        jexec "$router" pfctl -vvsr >&2 || :
        jexec "$router" pfctl -vvs nat >&2 || :
        jexec "$router" pfctl -ss >&2 || :
    fi
    for item in "$router_wg1" "$router_wg2"; do
        [ -z "$item" ] || jexec "$router" ifconfig "$item" destroy 2>/dev/null || :
    done
    [ -z "$exit_wg1" ] || jexec "$exit1" ifconfig "$exit_wg1" destroy 2>/dev/null || :
    [ -z "$exit_wg2" ] || jexec "$exit2" ifconfig "$exit_wg2" destroy 2>/dev/null || :
    for jail_name in "$client" "$exit1" "$exit2" "$router"; do
        jail -r "$jail_name" 2>/dev/null || :
    done
    for item in "$ingress" "$underlay1" "$underlay2"; do
        [ -z "$item" ] || ifconfig "$item" destroy 2>/dev/null || :
    done
    rm -rf "$stage"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

ingress=$(ifconfig epair create)
underlay1=$(ifconfig epair create)
underlay2=$(ifconfig epair create)
client_link="${ingress%a}b"
exit1_link="${underlay1%a}b"
exit2_link="${underlay2%a}b"
jail -c "name=$router" persist vnet "vnet.interface=$ingress" \
    "vnet.interface=$underlay1" "vnet.interface=$underlay2"
jail -c "name=$client" persist vnet "vnet.interface=$client_link"
jail -c "name=$exit1" persist vnet "vnet.interface=$exit1_link"
jail -c "name=$exit2" persist vnet "vnet.interface=$exit2_link"

client_addr=100.73.204.22
router_tunnel=10.130.65.41
service1=198.18.20.1
service2=198.18.21.1
port=8443
jexec "$router" ifconfig "$ingress" inet 100.73.204.1/24 up -txcsum -txcsum6
jexec "$client" ifconfig "$client_link" inet "$client_addr/24" up -txcsum -txcsum6
jexec "$router" ifconfig "$underlay1" inet 192.0.2.1/24 up -txcsum -txcsum6
jexec "$exit1" ifconfig "$exit1_link" inet 192.0.2.2/24 up -txcsum -txcsum6
jexec "$router" ifconfig "$underlay2" inet 192.0.3.1/24 up -txcsum -txcsum6
jexec "$exit2" ifconfig "$exit2_link" inet 192.0.3.2/24 up -txcsum -txcsum6
jexec "$exit1" ifconfig lo0 inet "$service1/32" alias up
jexec "$exit2" ifconfig lo0 inet "$service2/32" alias up
jexec "$router" route -n add default 192.0.2.2
jexec "$client" route -n add default 100.73.204.1
jexec "$router" sysctl net.inet.ip.forwarding=1

router_wg1=$(jexec "$router" ifconfig wg create)
router_wg2=$(jexec "$router" ifconfig wg create)
exit_wg1=$(jexec "$exit1" ifconfig wg create)
exit_wg2=$(jexec "$exit2" ifconfig wg create)
umask 077
wg genkey >"$stage/router.key"
wg genkey >"$stage/exit1.key"
wg genkey >"$stage/exit2.key"
router_key=$(wg pubkey <"$stage/router.key")
exit1_key=$(wg pubkey <"$stage/exit1.key")
exit2_key=$(wg pubkey <"$stage/exit2.key")
jexec "$router" wg set "$router_wg1" private-key "$stage/router.key" listen-port 51821 \
    peer "$exit1_key" endpoint 192.0.2.2:51820 allowed-ips 0.0.0.0/0
jexec "$router" wg set "$router_wg2" private-key "$stage/router.key" listen-port 51823 \
    peer "$exit2_key" endpoint 192.0.3.2:51822 allowed-ips 0.0.0.0/0
jexec "$exit1" wg set "$exit_wg1" private-key "$stage/exit1.key" listen-port 51820 \
    peer "$router_key" allowed-ips "$router_tunnel/32"
jexec "$exit2" wg set "$exit_wg2" private-key "$stage/exit2.key" listen-port 51822 \
    peer "$router_key" allowed-ips "$router_tunnel/32"
jexec "$router" ifconfig "$router_wg1" inet "$router_tunnel/32" mtu 1420 up
jexec "$router" ifconfig "$router_wg2" inet "$router_tunnel/32" mtu 1420 up
jexec "$exit1" ifconfig "$exit_wg1" inet 10.130.65.42/24 mtu 1420 up
jexec "$exit2" ifconfig "$exit_wg2" inet 10.130.65.43/24 mtu 1420 up
test "$(jexec "$router" wg show "$router_wg1" public-key)" = \
    "$(jexec "$router" wg show "$router_wg2" public-key)"

cat >"$stage/pf.conf" <<EOF
set skip on lo0
nat on $router_wg1 inet from $client_addr to any -> $router_tunnel
nat on $router_wg2 inet from $client_addr to any -> $router_tunnel
block all
pass out quick on $underlay1 inet proto udp from 192.0.2.1 to 192.0.2.2 port 51820 keep state
pass out quick on $underlay2 inet proto udp from 192.0.3.1 to 192.0.3.2 port 51822 keep state
pass in quick on $ingress route-to $router_wg1 inet from $client_addr to $service1 keep state (if-bound) label "shared_exit1"
pass in quick on $ingress route-to $router_wg2 inet from $client_addr to $service2 keep state (if-bound) label "shared_exit2"
pass out on $router_wg1 inet from $router_tunnel to $service1 keep state (floating)
pass out on $router_wg2 inet from $router_tunnel to $service2 keep state (floating)
EOF
jexec "$router" pfctl -e
jexec "$router" pfctl -f "$stage/pf.conf"

check_exit() {
    exit_jail=$1 service=$2 expected=$3
    timeout -k 2 7 jexec "$exit_jail" sh -c \
        'printf "%s\n" "$3" | timeout -f -k 2 7 nc -N -l "$1" "$2"' \
        sh "$service" "$port" "$expected" &
    listener=$!
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if jexec "$exit_jail" sockstat -4l | grep -Fq "$service:$port"; then
            break
        fi
        sleep 0.1
    done
    actual=$(jexec "$client" nc -N -w 4 -s "$client_addr" "$service" "$port" </dev/null)
    wait "$listener"
    test "$actual" = "$expected"
}

check_exit "$exit1" "$service1" 'first Mullvad relay'
check_exit "$exit2" "$service2" 'second Mullvad relay'
check_exit "$exit1" "$service1" 'first relay still active'
jexec "$router" pfctl -s labels | awk '$1 == "shared_exit1" && $3 > 0 { first=1 }
    $1 == "shared_exit2" && $3 > 0 { second=1 } END { exit !(first && second) }'
echo 'Two concurrent WireGuard exits forwarded client TCP using one device key and tunnel address.'
