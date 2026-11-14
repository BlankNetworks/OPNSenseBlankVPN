#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo 'Usage: verify-pkg-repo.sh SITE-DIRECTORY|- PUBLIC-BASE-URL|- VERSION' >&2
    exit 64
fi

site=$1
base_url=$2
version=$3
public_key=$(cd "$(dirname "$0")" && pwd)/repo.pub
package_name=os-blank-vpn
package_origin=opnsense/os-blank-vpn
pkg=${BLANKVPN_PKG:-pkg}
work=$(mktemp -d)
server_pid=
cleanup()
{
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || :
        wait "$server_pid" 2>/dev/null || :
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ "$site" != - ] && [ "$base_url" = - ]; then
    mkdir -p "$work/http"
    python=$(command -v python3 || command -v python3.13)
    "$python" - "$site" "$work/http/port" <<'PY' &
import http.server
import sys
from functools import partial
from pathlib import Path

class RepositoryHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve fresh archive bytes so a signature rejection cannot be masked by a 304.
        if "If-Modified-Since" in self.headers:
            del self.headers["If-Modified-Since"]
        super().do_GET()

handler = partial(RepositoryHandler, directory=sys.argv[1])
with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
    Path(sys.argv[2]).write_text(str(server.server_port), encoding="ascii")
    server.serve_forever()
PY
    server_pid=$!
    for attempt in 1 2 3 4 5; do
        test ! -s "$work/http/port" || break
        sleep 1
    done
    base_url=http://127.0.0.1:$(cat "$work/http/port")
elif [ "$site" != - ] || [ "$base_url" = - ]; then
    echo 'Provide either the local site directory or its deployed HTTPS URL.' >&2
    exit 64
fi

curl -fsS --retry 3 --max-time 20 "$base_url/pkg/repo.pub" -o "$work/downloaded.pub"
cmp -s "$public_key" "$work/downloaded.pub"
test "$(curl -fsS --retry 3 --max-time 20 "$base_url/pkg/26.7/version.txt")" = "$version"
if [ "$site" != - ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | \
        openssl pkey -pubout -out "$work/untrusted.pub"
fi

config()
{
    printf '%s: { url: "%s/pkg/26.7/${ABI}", enabled: true, signature_type: "pubkey", pubkey: "%s", priority: 0 }\n' \
        "$3" "$base_url" "$2" > "$1/$3.conf"
}

for arch in amd64 aarch64; do
    abi=FreeBSD:15:$arch
    directory=$work/$arch
    mkdir -p "$directory/repos" "$directory/db" "$directory/cache" "$directory/fetched"
    config "$directory/repos" "$public_key" BlankNetworks
    set -- -R "$directory/repos" -o ABI="$abi" -o PKG_DBDIR="$directory/db" -o PKG_CACHEDIR="$directory/cache"
    "$pkg" "$@" update -f -r BlankNetworks
    expected="$package_name $version $package_origin $abi"
    test "$("$pkg" "$@" rquery -U -r BlankNetworks -a '%n %v %o %q')" = "$expected"
    "$pkg" "$@" fetch -Uy -r BlankNetworks -o "$directory/fetched" "$package_name-$version"
    package=$directory/fetched/All/$package_name-$version.pkg
    test -f "$package"
    test "$(find "$directory/fetched" -type f -name '*.pkg')" = "$package"
    test "$("$pkg" "$@" query -F "$package" '%n %v %o %q')" = "$expected"
    tar -xOf "$package" /usr/local/share/blankvpn/repo.pub > "$directory/packaged.pub"
    cmp -s "$public_key" "$directory/packaged.pub"
    if [ "$site" != - ]; then
        cmp -s "$package" "$site/pkg/26.7/$abi/All/$package_name-$version.pkg"
        mkdir "$directory/untrusted-repos" "$directory/untrusted-db" "$directory/untrusted-cache"
        config "$directory/untrusted-repos" "$work/untrusted.pub" UntrustedBlankNetworks
        set -- -R "$directory/untrusted-repos" -o ABI="$abi" -o PKG_DBDIR="$directory/untrusted-db" \
            -o PKG_CACHEDIR="$directory/untrusted-cache"
        "$pkg" "$@" update -f -r UntrustedBlankNetworks > "$directory/rejected.log" 2>&1 || :
        grep -Ei 'signature verification failure|invalid signature' "$directory/rejected.log"
        if "$pkg" "$@" rquery -U -r UntrustedBlankNetworks '%n' "$package_name" > "$directory/untrusted-query.log" 2>&1; then
            echo "Unexpectedly accepted a repository signed by another key for $abi." >&2
            exit 1
        fi
    fi
done
