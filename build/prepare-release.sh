#!/bin/sh
set -eu

# Run from the repository root on the release runner.
stage=$1
mkdir -p "$stage"/bin "$stage"/licenses "$stage"/yaml
stage=$(cd "$stage" && pwd)
sources=$(mktemp -d)
trap 'rm -rf "$sources"' EXIT

python3 - "$stage/bin" <<'PY'
import runpy
import sys
from pathlib import Path

installer = runpy.run_path("src/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py")
destination = Path(sys.argv[1])
for core in installer["ASSETS"]:
    path = destination / core
    path.write_bytes(installer["binary_for"](core, None))
    path.chmod(0o755)
PY

fetch_source()
{
    name=$1
    repository=$2
    commit=$3
    git init --quiet "$sources/$name"
    git -C "$sources/$name" fetch --quiet --depth 1 "https://github.com/$repository.git" "$commit"
    git -C "$sources/$name" checkout --quiet --detach FETCH_HEAD
    test "$(git -C "$sources/$name" rev-parse HEAD)" = "$commit"
    cp "$sources/$name/LICENSE" "$stage/licenses/$name.txt"
}

fetch_source mihomo MetaCubeX/mihomo 0455d0d28c4526937380505153e65a843d8612e8
fetch_source tun2socks xjasonlyu/tun2socks 8dda19e8e4613e014f0b12f3e624fdff5e5f23b3
fetch_source xray XTLS/Xray-core 676eaf66f8f05d4d558ee7a74b4736623d3feeb9
fetch_source sing-box SagerNet/sing-box c005f35300ce76427dc285481ec5695f5b179cd2
fetch_source pyyaml yaml/pyyaml 49790e73684bebad1df05ef8d828fa12f685bffb
cp "$sources/pyyaml/lib/yaml/"*.py "$stage/yaml/"

(
    cd "$sources/sing-box"
    export GOOS=freebsd GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 GOTOOLCHAIN=auto
    # Use the FreeBSD port's feature tags for the adapters used by Blank VPN.
    go build -mod=readonly -trimpath -tags with_quic,with_wireguard,with_utls,with_gvisor,with_grpc \
        -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4' \
        -o "$stage/bin/sing-box" ./cmd/sing-box
)

for binary in "$stage/bin/"*; do
    go version -m "$binary" | grep -q 'GOOS=freebsd'
    go version -m "$binary" | grep -q 'GOARCH=amd64'
done
