#!/usr/bin/env python3
"""Verify pinned FreeBSD core archives and mirror them to Blank releases."""

import argparse
import hashlib
import json
import os
import runpy
import subprocess
import tempfile
from pathlib import Path
from urllib.request import build_opener


ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "BlankNetworks/OPNSenseBlankVPN"
MAX_ARCHIVE = 100 * 1024 * 1024


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "aarch64"), required=True)
    args = parser.parse_args()
    installer = runpy.run_path(str(ROOT / "src/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py"))
    suffix = "-aarch64" if args.arch == "aarch64" else ""
    catalog_path = ROOT / "src/share/blankvpn" / f"core-catalog{suffix}.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))["cores"]

    with tempfile.TemporaryDirectory(prefix="blankvpn-core-mirror-") as temporary:
        work = Path(temporary)
        for core, row in catalog.items():
            version = row["version"]
            tag = f"cores-{core}-v{version}{suffix}"
            asset = f"{core}-{version}-freebsd-{args.arch}.{'zip' if core in ('tun2socks', 'xray') else 'gz'}"
            if row != {
                "version": version,
                "source": "blanknetworks",
                "tag": tag,
                "asset": asset,
                "sha256": row["sha256"],
            }:
                raise ValueError(f"{core} catalog does not point to its Blank-hosted release asset")

            archive_path = work / asset
            if core in installer["ASSETS"][args.arch]:
                source_url, expected_digest = installer["ASSETS"][args.arch][core]
                if row["sha256"] != expected_digest:
                    raise ValueError(f"{core} catalog checksum differs from the pinned upstream checksum")
                with build_opener(installer["ReleaseRedirect"]()).open(source_url, timeout=30) as response:
                    archive = response.read(MAX_ARCHIVE + 1)
                if len(archive) > MAX_ARCHIVE:
                    raise ValueError(f"{core} upstream archive is too large")
                installer["verified_binary"](core, archive, expected_digest, args.arch)
                archive_path.write_bytes(archive)
                checksum_path = work / f"{asset}.sha256"
                checksum_path.write_text(f"{expected_digest}  {asset}\n", encoding="ascii")
                mirror_asset = True
            else:
                # sing-box is built and published by the pinned-source workflow.
                command("gh", "release", "download", tag, "--repo", REPOSITORY,
                        "--pattern", asset, "--dir", str(work))
                archive = archive_path.read_bytes()
                installer["verified_binary"](core, archive, row["sha256"], args.arch)
                mirror_asset = False

            release_view = subprocess.run(
                ["gh", "release", "view", tag, "--repo", REPOSITORY, "--json", "assets,isDraft"],
                text=True, capture_output=True, check=False,
            )
            created = release_view.returncode != 0
            if created:
                if not mirror_asset:
                    raise ValueError(f"Expected Blank-hosted sing-box release {tag} was not found")
                upstream = installer["ASSETS"][args.arch].get(core, ("", ""))[0]
                command("gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--latest=false",
                        "--target", os.environ["GITHUB_SHA"], "--title", f"{core} {version} for FreeBSD {args.arch}",
                        "--notes", f"Verified FreeBSD {args.arch} core archive. Upstream: {upstream or 'Blank Networks sing-box build'}")
                existing = []
            else:
                release = json.loads(release_view.stdout)
                existing = release["assets"]
            by_name = {item["name"]: item for item in existing}
            if mirror_asset:
                for path in (archive_path, checksum_path):
                    current = by_name.get(path.name)
                    if current is not None:
                        previous_dir = work / ("previous-" + path.name)
                        previous_dir.mkdir()
                        command("gh", "release", "download", tag, "--repo", REPOSITORY,
                                "--pattern", path.name, "--dir", str(previous_dir))
                        previous = previous_dir / path.name
                        if hashlib.sha256(previous.read_bytes()).digest() != hashlib.sha256(path.read_bytes()).digest():
                            raise ValueError(f"Refusing to replace different published asset {tag}/{path.name}")
                    else:
                        command("gh", "release", "upload", tag, str(path), "--repo", REPOSITORY)
                if created or release["isDraft"]:
                    command("gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")

            # Download the hosted archive and verify it again before the catalog is used.
            if not mirror_asset:
                archive_path.unlink(missing_ok=True)
            hosted_dir = work / ("hosted-" + core)
            hosted_dir.mkdir()
            command("gh", "release", "download", tag, "--repo", REPOSITORY,
                    "--pattern", asset, "--dir", str(hosted_dir))
            installer["verified_binary"](core, (hosted_dir / asset).read_bytes(), row["sha256"], args.arch)
            print(f"Verified {core} {version} from {REPOSITORY}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
