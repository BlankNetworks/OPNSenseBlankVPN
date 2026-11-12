#!/bin/sh
set -eu

package=$1
arch=$2
test "$(uname -s)" = FreeBSD
test "$(pkg config ABI)" = "FreeBSD:15:$arch"
pkg info -F "$package"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
tar -xf "$package" -C "$stage"
bin="$stage/usr/local/libexec/blankvpn"

"$bin/mihomo" -v | grep -F '1.19.34'
"$bin/tun2socks" --version | grep -F '2.7.0'
"$bin/xray" version | grep -F '26.11.9'
"$bin/sing-box" version | grep -F '1.14.4'
