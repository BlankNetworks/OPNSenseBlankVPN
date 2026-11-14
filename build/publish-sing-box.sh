#!/bin/sh
set -eu

version=$1
binary=$2
commit=$3
arch=$4
case "$arch" in
    amd64) suffix="" ;;
    aarch64) suffix="-aarch64" ;;
    *) echo "Unsupported FreeBSD architecture: $arch" >&2; exit 1 ;;
esac
printf '%s\n' "$version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'
printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'
tag="cores-sing-box-v$version$suffix"
artifact="sing-box-$version-freebsd-$arch.gz"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
gzip -nc "$binary" > "$stage/$artifact"
(
    cd "$stage"
    sha256sum "$artifact" > "$artifact.sha256"
    cat "$artifact.sha256"
)
if gh release view "$tag" >/dev/null 2>&1; then
    if [ "$(gh release view "$tag" --json isDraft --jq '.isDraft')" = false ]; then
        gh release view "$tag" --json url --jq '.url'
        exit 0
    fi
    test "$(gh release view "$tag" --json targetCommitish --jq '.targetCommitish')" = "$GITHUB_SHA"
else
    gh release create "$tag" --draft --latest=false --target "$GITHUB_SHA" --title "sing-box $version for FreeBSD $arch" \
        --notes "FreeBSD $arch build for Blank VPN & Proxy. Upstream source and license: https://github.com/SagerNet/sing-box/tree/$commit"
fi
gh release upload "$tag" "$stage/$artifact" "$stage/$artifact.sha256" --clobber
gh release edit "$tag" --draft=false --latest=false
