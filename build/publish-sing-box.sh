#!/bin/sh
set -eu

version=$1
binary=$2
commit=$3
printf '%s\n' "$version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'
printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'
tag="cores-sing-box-v$version"
artifact="sing-box-$version-freebsd-amd64.gz"
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
    gh release create "$tag" --draft --latest=false --target "$GITHUB_SHA" --title "sing-box $version for FreeBSD amd64" \
        --notes "FreeBSD amd64 build for Blank VPN. Upstream source and license: https://github.com/SagerNet/sing-box/tree/$commit"
fi
gh release upload "$tag" "$stage/$artifact" "$stage/$artifact.sha256" --clobber
gh release edit "$tag" --draft=false --latest=false
