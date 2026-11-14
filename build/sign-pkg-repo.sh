#!/bin/sh
set -eu
set +x

if [ "$#" -ne 1 ]; then
    echo 'Usage: sign-pkg-repo.sh VERSION < private-signing-key' >&2
    exit 64
fi

version=$1
case "$version" in
    ''|*[!0-9.]*) echo 'Invalid Blank VPN & Proxy package version.' >&2; exit 64 ;;
esac

umask 077
signing_dir=$(mktemp -d)
trap 'rm -rf -- "$signing_dir"' EXIT
trap 'exit 1' HUP INT TERM
cat > "$signing_dir/repo.key"
test -s "$signing_dir/repo.key"
cd "$(dirname "$0")/.."
umask 022
sh build/make-pkg-repo.sh dist _site "$version" "$signing_dir/repo.key"
rm -f "$signing_dir/repo.key"
sh build/verify-pkg-repo.sh _site - "$version"
