#!/bin/sh
# Resolve the newest published package, then verify its pinned release installer.
set -eu

fail() {
    echo "Blank VPN & Proxy: $*" >&2
    exit 1
}

[ "$(id -u)" = 0 ] || fail 'run this installer as root on OPNsense.'
[ "$(uname -s)" = FreeBSD ] || fail 'this installer runs only on OPNsense/FreeBSD.'
command -v opnsense-version >/dev/null 2>&1 || fail 'OPNsense was not found.'
[ "$(opnsense-version -n)" = opnsense ] || fail 'this router is not OPNsense.'
[ "$(opnsense-version -a)" = 26.7 ] || fail 'OPNsense Community Edition 26.7 is required.'
case "$(pkg config ABI)" in
    FreeBSD:15:amd64) arch=amd64 ;;
    FreeBSD:15:aarch64) arch=aarch64 ;;
    *) fail 'this FreeBSD package ABI is unsupported.' ;;
esac
command -v fetch >/dev/null 2>&1 || fail 'FreeBSD fetch is unavailable.'
command -v php >/dev/null 2>&1 || fail 'The OPNsense PHP runtime is unavailable.'
command -v sha256 >/dev/null 2>&1 || fail 'FreeBSD sha256 is unavailable.'

stage=$(mktemp -d /tmp/blankvpn-latest.XXXXXXXX) || fail 'cannot create a temporary install directory.'
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
fetch -q -o "$stage/releases.json" 'https://api.github.com/repos/BlankNetworks/OPNSenseBlankVPN/releases?per_page=30' ||
    fail 'could not read the published releases.'
selection=$(php -r '
    $releases = json_decode(file_get_contents($argv[1]), true);
    if (!is_array($releases)) { exit(1); }
    $best = null; $digest = null;
    foreach ($releases as $release) {
        if (!empty($release["draft"]) || !preg_match("/^v([0-9]+\\.[0-9]+\\.[0-9]+)$/D", $release["tag_name"] ?? "", $match)) {
            continue;
        }
        $candidate = $match[1];
        $package = "os-blank-vpn-" . $candidate . "-" . $argv[2] . ".pkg";
        $names = array_column($release["assets"] ?? [], "name");
        $pattern = "/sha256 -c ([a-f0-9]{64}) \\/tmp\\/blankvpn-install-" . preg_quote($candidate, "/") . "\\.sh/";
        if (in_array($package, $names, true) && in_array($package . ".sha256", $names, true) &&
            preg_match($pattern, $release["body"] ?? "", $check) &&
            ($best === null || version_compare($candidate, $best, ">"))) {
            $best = $candidate; $digest = $check[1];
        }
    }
    if ($best === null) { exit(1); }
    echo $best, " ", $digest;
' "$stage/releases.json" "$arch") || fail 'no published release matches this router.'
set -- $selection
[ "$#" = 2 ] || fail 'the published installer checksum is missing.'
version=$1
digest=$2

installer="$stage/blankvpn-install-$version.sh"
fetch -q -o "$installer" "https://raw.githubusercontent.com/BlankNetworks/OPNSenseBlankVPN/v$version/scripts/install.sh" ||
    fail 'could not download the selected release installer.'
[ "$(sha256 -q "$installer")" = "$digest" ] || fail 'the release installer checksum does not match.'
grep -Fx "version=$version" "$installer" >/dev/null || fail 'the release installer version does not match.'
echo "Installing latest published Blank VPN & Proxy release $version."
sh "$installer"
