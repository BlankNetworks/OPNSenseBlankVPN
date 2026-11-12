#!/usr/local/bin/python3.13
"""Install the pinned upstream FreeBSD proxy runtimes for Blank VPN."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import platform
import struct
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from zipfile import ZipFile


DESTINATION = Path("/usr/local/libexec/blankvpn")
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
ASSETS = {
    "mihomo": (
        "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-freebsd-amd64-compatible-v1.19.34.gz",
        "28564d6771d2723a800d0c46dc5797d99435650e68fc73499c6ac17aa16942a2",
        (),
    ),
    "tun2socks": (
        "https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-freebsd-amd64.zip",
        "3ebb747aa83ee3157330beb324bbeaf9a742db6a8d24b9bbc96a4125aaeeeaea",
        ("tun2socks", "tun2socks-freebsd-amd64"),
    ),
    "xray": (
        "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-freebsd-64.zip",
        "d86d4b2c7498244b0aea8c936b59154b743401c6c0326c222ce367c229777ba6",
        ("xray",),
    ),
}


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
        }:
            raise ValueError("Unexpected release download destination")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def binary_for(core, archive_directory):
    url, digest, names = ASSETS[core]
    asset = Path(urlsplit(url).path).name
    if archive_directory is None:
        with build_opener(ReleaseRedirect()).open(url, timeout=25) as response:
            archive = response.read(MAX_ARCHIVE + 1)
    else:
        with (archive_directory / asset).open("rb") as source:
            archive = source.read(MAX_ARCHIVE + 1)
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError(f"{core} archive checksum mismatch")
    if not names:
        with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
            binary = compressed.read(MAX_BINARY + 1)
    else:
        with ZipFile(io.BytesIO(archive)) as compressed:
            matches = [item for item in compressed.infolist() if item.filename in names and not item.is_dir()]
            if len(matches) != 1 or matches[0].file_size > MAX_BINARY:
                raise ValueError(f"Unexpected {core} archive layout")
            binary = compressed.read(matches[0])
    if len(binary) < 64 or len(binary) > MAX_BINARY or binary[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", binary, 18)[0] != 62:
        raise ValueError(f"{core} is not an amd64 ELF executable")
    return binary


def install(core, binary):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{core}-", dir=DESTINATION)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(binary)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o755)
        os.replace(temporary, DESTINATION / core)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", action="store_true", help="Also install the Xray adapter")
    parser.add_argument("--archives", type=Path, help="Read verified archives from a local directory")
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != "FreeBSD" or platform.machine() != "amd64":
        parser.error("Run as root on the target FreeBSD amd64 router")
    DESTINATION.mkdir(mode=0o755, parents=True, exist_ok=True)
    state = DESTINATION.stat()
    if DESTINATION.is_symlink() or state.st_uid != 0 or state.st_mode & 0o022:
        parser.error("Unsafe proxy runtime directory")
    cores = ["mihomo", "tun2socks"] + (["xray"] if args.xray else [])
    try:
        binaries = [(core, binary_for(core, args.archives)) for core in cores]
        for core, binary in binaries:
            install(core, binary)
            print(f"Installed verified {core}")
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
