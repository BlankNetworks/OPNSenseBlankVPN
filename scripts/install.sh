#!/bin/sh
# Install the package pinned to this release on a supported OPNsense router.
set -eu

version=0.8.48
repository=BlankNetworks/OPNSenseBlankVPN

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
    *) fail 'this FreeBSD package ABI is unsupported; use the matching release package.' ;;
esac

[ -f /conf/config.xml ] || fail 'the OPNsense configuration is unavailable.'
command -v fetch >/dev/null 2>&1 || fail 'FreeBSD fetch is unavailable.'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable.'

stage=$(mktemp -d /tmp/blankvpn-install.XXXXXXXX) || fail 'cannot create a temporary install directory.'
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM

package="os-blank-vpn-$version-$arch.pkg"
checksum="$package.sha256"
release="https://github.com/$repository/releases/download/v$version"
fetch -o "$stage/$package" "$release/$package" || fail 'package download failed.'
fetch -o "$stage/$checksum" "$release/$checksum" || fail 'checksum download failed.'
(cd "$stage" && sha256sum -c "$checksum") || fail 'package checksum verification failed.'

backup="/conf/backup/config-blankvpn-preinstall-$(date -u +%Y%m%dT%H%M%SZ)-$$.xml"
install -m 600 /conf/config.xml "$backup" || fail 'could not save the protected configuration backup.'
echo "Protected configuration backup: $backup"

pkg add -f "$stage/$package" || fail 'package installation failed; the configuration backup is retained.'
installed=$(pkg query %v os-blank-vpn) || fail 'the installed package could not be verified.'
[ "$installed" = "$version" ] || fail "installed version $installed does not match $version."
echo "Blank VPN & Proxy $version installed. Open VPN → Blank VPN & Proxy → Dashboard."
