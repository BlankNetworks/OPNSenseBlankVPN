#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo 'Usage: make-pkg-repo.sh RELEASE-DIRECTORY SITE-DIRECTORY VERSION SIGNING-KEY' >&2
    exit 64
fi

release=$(cd "$1" && pwd)
site=$2
version=$3
key=$4
public_key=$(dirname "$0")/repo.pub
package_name=os-blank-vpn
package_origin=opnsense/os-blank-vpn
pkg=${BLANKVPN_PKG:-pkg}
unset PKG_REPO_HASH PKG_REPO_SYMLINK

case "$version" in
    ''|*[!0-9.]*) echo 'Invalid Blank VPN & Proxy package version.' >&2; exit 64 ;;
esac
if [ -e "$site" ]; then
    echo 'The repository site output directory must not exist.' >&2
    exit 64
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
openssl pkey -in "$key" -pubout -out "$work/repo.pub"
cmp -s "$public_key" "$work/repo.pub" || {
    echo 'The repository signing key does not match the checked-in public key.' >&2
    exit 1
}

# Keep the signed index readable on supported pkg builds that lack Zstandard.
printf '%s\n' 'version = 2; packing_format = "txz";' > "$work/repo-meta.conf"

for arch in amd64 aarch64; do
    abi=FreeBSD:15:$arch
    original=$package_name-$version-$arch.pkg
    test "$("$pkg" -o ABI="$abi" query -F "$release/$original" '%n %v %o %q')" = "$package_name $version $package_origin $abi"
    test "$(cat "$release/$original.sha256")" = "$(openssl dgst -sha256 < "$release/$original" | awk '{print $NF}')  $original"
    tar -xOf "$release/$original" /usr/local/share/blankvpn/repo.pub > "$work/packaged.pub"
    cmp -s "$public_key" "$work/packaged.pub"
    directory=$site/pkg/26.7/$abi
    mkdir -p "$directory/All"
    cp "$release/$original" "$directory/All/$package_name-$version.pkg"
    "$pkg" -o ABI="$abi" repo -l -m "$work/repo-meta.conf" "$directory" "rsa:$key"
    test -s "$directory/meta.conf"
    test -s "$directory/packagesite.pkg"
    test -s "$directory/data.pkg"
    test -s "$directory/files.pkg"
done

cp "$public_key" "$site/pkg/repo.pub"
printf '%s\n' "$version" > "$site/pkg/26.7/version.txt"
printf '%s\n' '<!doctype html><html lang="en"><meta charset="utf-8"><title>Blank VPN &amp; Proxy package repository</title><h1>Blank VPN &amp; Proxy package repository</h1><p>Signed OPNsense Community Edition 26.7 packages for amd64 and aarch64.</p></html>' > "$site/index.html"
touch "$site/.nojekyll"
