#!/bin/sh
set -eu

# Run from the repository root on the release runner.
stage=$1
arch=$2
case "$arch" in
    amd64) goarch=amd64 ;;
    aarch64) goarch=arm64 ;;
    *) echo "Unsupported FreeBSD architecture: $arch" >&2; exit 1 ;;
esac
mkdir -p "$stage"/bin "$stage"/licenses "$stage"/yaml
stage=$(cd "$stage" && pwd)
sources=$(mktemp -d)
trap 'rm -rf "$sources"' EXIT

python3 - "$stage/bin" "$arch" <<'PY'
import runpy
import sys
from pathlib import Path

installer = runpy.run_path("src/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py")
destination = Path(sys.argv[1])
arch = sys.argv[2]
for core in installer["ASSETS"][arch]:
    path = destination / core
    path.write_bytes(installer["binary_for"](core, None, arch))
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
fetch_source pyyaml yaml/pyyaml 49790e73684bebad1df05ef8d828fa12f685bffb
cp "$sources/pyyaml/lib/yaml/"*.py "$stage/yaml/"

sh build/prepare-sing-box.sh 1.14.4 c005f35300ce76427dc285481ec5695f5b179cd2 "$sources/sing-box" "$arch"
cp "$sources/sing-box/sing-box" "$stage/bin/sing-box"
cp "$sources/sing-box/LICENSE" "$stage/licenses/sing-box.txt"

for binary in "$stage/bin/"*; do
    go version -m "$binary" | grep -q 'GOOS=freebsd'
    go version -m "$binary" | grep -q "GOARCH=$goarch"
done
