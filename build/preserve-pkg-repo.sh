#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo 'Usage: preserve-pkg-repo.sh SITE-DIRECTORY PUBLIC-BASE-URL VERSION' >&2
    exit 64
fi

site=$1
base_url=${2%/}
version=$3
case "$base_url" in
    'https://blanknetworks.github.io/OPNSenseBlankVPN') ;;
    *) echo 'Unexpected public repository URL.' >&2; exit 1 ;;
esac

old_version_file=$(mktemp)
trap 'rm -f -- "$old_version_file"' EXIT
trap 'exit 1' HUP INT TERM
status=$(curl -sS --retry 3 --max-time 20 --output "$old_version_file" --write-out '%{http_code}' \
    "$base_url/pkg/26.7/version.txt")
case "$status" in
    404) exit 0 ;; # the initial deployment has no previous catalog
    200) ;;
    *) echo "Could not confirm the currently published package (HTTP $status)." >&2; exit 1 ;;
esac

previous=$(cat "$old_version_file")
case "$previous" in
    ''|*[!0-9.]*) echo 'Unexpected published package version.' >&2; exit 1 ;;
esac
if [ "$version" = "$previous" ]; then
    exit 0
fi
if [ "$(printf '%s\n' "$version" "$previous" | sort -V | tail -1)" != "$version" ]; then
    echo "Refusing to replace published package $previous with an older version $version." >&2
    exit 1
fi

for arch in amd64 aarch64; do
    abi=FreeBSD:15:$arch
    path=pkg/26.7/$abi/All/os-blank-vpn-$previous.pkg
    curl -fsS --retry 3 --max-time 120 --max-filesize 104857600 "$base_url/$path" --output "$site/$path"
done
