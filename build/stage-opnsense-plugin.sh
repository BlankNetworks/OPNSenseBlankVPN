#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=${1:-}
maintainer=${PLUGIN_MAINTAINER:-}

if [ -z "$target" ]; then
    echo 'Usage: PLUGIN_MAINTAINER=email@example.com sh build/stage-opnsense-plugin.sh /path/to/plugins/net/blank-vpn' >&2
    exit 2
fi
case "$maintainer" in
    ''|*[!A-Za-z0-9._+@-]*)
        echo 'Set PLUGIN_MAINTAINER to the submitting maintainer email before staging.' >&2
        exit 2
        ;;
esac
if [ -e "$target/src" ] || [ -e "$target/Makefile" ] || [ -e "$target/+POST_INSTALL" ] ||
    [ -e "$target/+POST_INSTALL.post" ] || [ -e "$target/+POST_DEINSTALL" ] ||
    [ -e "$target/+POST_DEINSTALL.post" ]; then
    echo "The target already contains a plugin; choose an empty directory: $target" >&2
    exit 2
fi

version=$(python3 "$root/build/package.py" --version)
case "$version" in
    *[!0-9.]*|'') echo 'The package version is invalid.' >&2; exit 2 ;;
esac
mkdir -p "$target"
(cd "$root" && tar -cf - --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.pyo' src) |
    tar -xf - -C "$target"
sed -e "s/__PLUGIN_VERSION__/$version/" -e "s/__PLUGIN_MAINTAINER__/$maintainer/" \
    "$root/packaging/opnsense/Makefile.in" > "$target/Makefile"
cp "$root/packaging/opnsense/pkg-descr" "$target/pkg-descr"
cp "$root/packaging/opnsense/+POST_INSTALL.post" "$target/+POST_INSTALL.post"
cp "$root/packaging/opnsense/+POST_DEINSTALL.post" "$target/+POST_DEINSTALL.post"
chmod 755 "$target/+POST_INSTALL.post" "$target/+POST_DEINSTALL.post"
echo "Staged os-blank-vpn $version at $target. Review and build it in the OPNsense plugins tree."
