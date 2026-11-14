#!/usr/bin/env python3
"""Render GitHub release notes using the verified package assets."""

import argparse
import hashlib
from pathlib import Path

from package import LEGACY_ARCHES, NAME, ROOT, SERIES, VERSION, abi


def install_instructions(directory, repository):
    release = f"https://github.com/{repository}/releases"
    commands = [
        "## Install or upgrade",
        "",
        f"If your Blank VPN & Proxy dashboard already has **System Settings → Package updates**, "
        f"[update from the WebGUI](https://github.com/{repository}/blob/v{VERSION}/README.md#update-from-the-webgui). "
        "The standalone packages below are also available for first installs and manual upgrades.",
        "",
        "Use an OPNsense root shell over SSH or select **8) Shell** on the console.",
        f"Confirm `opnsense-version -n` reports `opnsense` and "
        f"`opnsense-version -a` reports `{SERIES}`. Run `pkg config ABI` and use the matching section below.",
        "Save a configuration backup under **System → Configuration → Backups** before installing or upgrading.",
        "Keep console access available when testing routing.",
        "",
    ]
    for arch in LEGACY_ARCHES:
        package = f"{NAME}-{VERSION}-{arch}.pkg"
        checksum = f"{package}.sha256"
        url = f"{release}/download/v{VERSION}/{package}"
        with (directory / package).open("rb") as artifact:
            digest = hashlib.file_digest(artifact, "sha256").hexdigest()
        if (directory / checksum).read_text(encoding="ascii").split() != [digest, package]:
            raise ValueError(f"Checksum or filename mismatch for {package}")

        commands.extend([
            f"### {arch} package",
            "",
            f"Router ABI `{abi(arch)}`.",
            f"Download the [package]({url}) and its [SHA-256 file]({url}.sha256).",
            "",
            "**Install downloaded files**",
            "",
            "From your computer, open a terminal in the folder containing both files. Replace "
            "`USER@ROUTER` with your existing OPNsense SSH user and LAN address or hostname.",
            "",
            "```sh",
            f"scp {package} {checksum} USER@ROUTER:/tmp/",
            "```",
            "",
            "On the router, run each line as root.",
            "",
            "```sh",
            f"cd /tmp && sha256sum -c {checksum} && pkg add -f ./{package}",
            f"pkg info {NAME}",
            "```",
            "",
            "**Download and install on the router**",
            "",
            "Run each line as root. Continue after each line succeeds.",
            "",
            "```sh",
            f"fetch -o /tmp/{package} {url}",
            f"sha256 -c {digest} /tmp/{package} && pkg add -f /tmp/{package}",
            f"pkg info {NAME}",
            "```",
            "",
        ])
    commands.extend([
        f"Check that `pkg info {NAME}` shows **{VERSION}**. Open **VPN → Blank VPN & Proxy → Dashboard** "
        "in the OPNsense HTTPS WebGUI. The same commands install over an existing version. "
        "New installations start with routing disabled.",
        "",
        f"[Setup and compatibility guide](https://github.com/{repository}#install-or-upgrade) · "
        f"[Third-party sources](https://github.com/{repository}/blob/v{VERSION}/THIRD_PARTY.md)",
    ])
    return "\n".join(commands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path, help="Directory containing both packages and checksums")
    parser.add_argument("--repository", default="BlankNetworks/OPNSenseBlankVPN")
    args = parser.parse_args()
    notes = (ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8").strip()
    print(f"# Blank VPN & Proxy {VERSION}\n\n"
          f"This lab prerelease targets OPNsense Community Edition {SERIES} and bundles the proxy runtimes. "
          "The ARM64 package requires a compatible community OPNsense build. "
          "Live forwarding, core rollback, and tunnel-drop behavior still need lab validation.\n")
    print(install_instructions(args.dist, args.repository))
    if notes:
        print(f"\n## Changes\n\n{notes}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
