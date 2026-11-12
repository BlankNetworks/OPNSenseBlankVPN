#!/bin/sh
set -eu

version=$1
commit=$2
destination=$3
arch=$4
case "$arch" in
    amd64) goarch=amd64 ;;
    aarch64) goarch=arm64 ;;
    *) echo "Unsupported FreeBSD architecture: $arch" >&2; exit 1 ;;
esac
printf '%s\n' "$version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'
printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
source=$(mktemp -d)
trap 'rm -rf "$source"' EXIT

git init --quiet "$source"
git -C "$source" fetch --quiet --depth 1 https://github.com/SagerNet/sing-box.git "refs/tags/v$version"
git -C "$source" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$source" rev-parse HEAD)" = "$commit"
cp "$source/LICENSE" "$destination/LICENSE"

cd "$source"
export GOOS=freebsd GOARCH="$goarch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0 GOTOOLCHAIN=auto
go build -mod=readonly -trimpath -tags with_quic,with_wireguard,with_utls,with_gvisor,with_grpc \
    -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=$version" \
    -o "$destination/sing-box" ./cmd/sing-box
go version -m "$destination/sing-box" | grep -q 'GOOS=freebsd'
go version -m "$destination/sing-box" | grep -q "GOARCH=$goarch"
