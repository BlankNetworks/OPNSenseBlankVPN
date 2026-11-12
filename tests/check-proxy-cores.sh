#!/bin/sh
set -eu

blankvpn_fixtures=$(mktemp -d)
trap 'rm -rf "$blankvpn_fixtures"' EXIT
php tests/proxy.php "$blankvpn_fixtures"
cd "$blankvpn_fixtures"

fetch_verified()
{
    curl -fsSL --retry 2 --max-time 45 "$1" -o "$2"
    printf '%s  %s\n' "$3" "$2" | sha256sum -c -
}

fetch_verified https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-compatible-v1.19.34.gz mihomo.gz 2763f5b414527f7baf6dc57e3f82f3ab561eedf34bfd7c2f2cde1f7e592efe06
fetch_verified https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip xray.zip b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
fetch_verified https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz sing-box.tar.gz 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
gzip -dc mihomo.gz > mihomo
unzip -p xray.zip xray > xray
tar -xOzf sing-box.tar.gz sing-box-1.14.4-linux-amd64/sing-box > sing-box
chmod 755 mihomo xray sing-box

for config in ss ssr vmess ss2022 adapter-bridge; do
    ./mihomo -d "$blankvpn_fixtures" -t -f "$config.json"
done
./xray run -test -config xray.json
./sing-box check -c sing-box.json
