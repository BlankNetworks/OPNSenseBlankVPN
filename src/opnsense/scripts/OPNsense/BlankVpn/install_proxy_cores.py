#!/usr/local/bin/python3.13
"""Install the pinned upstream FreeBSD proxy runtimes for Blank VPN."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from zipfile import ZipFile


MAX_ARCHIVE = 100 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
ELF_MACHINES = {"amd64": 62, "aarch64": 183}
ASSETS = {
    "amd64": {
        "mihomo": (
            "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-freebsd-amd64-compatible-v1.19.34.gz",
            "28564d6771d2723a800d0c46dc5797d99435650e68fc73499c6ac17aa16942a2",
        ),
        "tun2socks": (
            "https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-freebsd-amd64.zip",
            "3ebb747aa83ee3157330beb324bbeaf9a742db6a8d24b9bbc96a4125aaeeeaea",
        ),
        "xray": (
            "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-freebsd-64.zip",
            "d86d4b2c7498244b0aea8c936b59154b743401c6c0326c222ce367c229777ba6",
        ),
    },
    "aarch64": {
        "mihomo": (
            "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-freebsd-arm64-v1.19.34.gz",
            "88234d79d449c98957a1f1cc26093dd9e4ab96d0614a66a64b3b36bf7b52b44f",
        ),
        "tun2socks": (
            "https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-freebsd-arm64.zip",
            "a002504d99fb7c22080cb75eb2de6be1a5b7dc6bd3c2654803823b2a72091903",
        ),
        "xray": (
            "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-freebsd-arm64-v8a.zip",
            "d6d06f71daf393056fa4266c0eba8eaca6ebd0f227e6e3fa126fbf5edf249c8b",
        ),
    },
}


def architecture(machine):
    return {"x86_64": "amd64", "arm64": "aarch64"}.get(machine, machine)


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.username or target.password or target.port not in (None, 443) or target.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
        }:
            raise ValueError("Unexpected release download destination")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def binary_for(core, archive_directory, arch):
    url, digest = ASSETS[arch][core]
    asset = Path(urlsplit(url).path).name
    if archive_directory is None:
        with build_opener(ReleaseRedirect()).open(url, timeout=25) as response:
            archive = response.read(MAX_ARCHIVE + 1)
    else:
        with (archive_directory / asset).open("rb") as source:
            archive = source.read(MAX_ARCHIVE + 1)
    return verified_binary(core, archive, digest, arch)


def is_freebsd_binary(binary, arch):
    if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01":
        return False
    if struct.unpack_from("<H", binary, 18)[0] != ELF_MACHINES[arch]:
        return False
    if binary[7] == 9:
        return True
    offset = struct.unpack_from("<Q", binary, 32)[0]
    entry_size, count = struct.unpack_from("<HH", binary, 54)
    if entry_size < 56 or count > 256 or offset + entry_size * count > len(binary):
        return False
    for i in range(count):
        header = offset + entry_size * i
        if struct.unpack_from("<I", binary, header)[0] != 4:  # PT_NOTE
            continue
        position = struct.unpack_from("<Q", binary, header + 8)[0]
        size = struct.unpack_from("<Q", binary, header + 32)[0]
        end = position + size
        if size > 65536 or end > len(binary):
            continue
        while position + 12 <= end:
            namesz, descsz, note_type = struct.unpack_from("<III", binary, position)
            position += 12
            if namesz == 8 and descsz == 4 and note_type == 1 and position + 12 <= end:
                if binary[position:position + 8] == b"FreeBSD\0":
                    return True
            position += (namesz + 3) // 4 * 4 + (descsz + 3) // 4 * 4
    return False


def verified_binary(core, archive, digest, arch):
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError(f"{core} archive checksum mismatch")
    if archive.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
            binary = compressed.read(MAX_BINARY + 1)
    elif archive.startswith(b"PK\x03\x04"):
        machine = "arm64" if arch == "aarch64" else arch
        names = {core, f"{core}-freebsd-{machine}"}
        with ZipFile(io.BytesIO(archive)) as compressed:
            matches = [item for item in compressed.infolist() if item.filename in names and not item.is_dir()]
            if len(matches) != 1 or matches[0].file_size > MAX_BINARY:
                raise ValueError(f"Unexpected {core} archive layout")
            binary = compressed.read(matches[0])
    else:
        binary = archive
    if len(binary) > MAX_BINARY or not is_freebsd_binary(binary, arch):
        raise ValueError(f"{core} is not a FreeBSD {arch} ELF executable")
    return binary


def stage(core, digest, destination, source, reserve, arch):
    if source.startswith("https://"):
        parsed = urlsplit(source)
        if parsed.netloc != "github.com":
            raise ValueError("Unexpected release host")
        with build_opener(ReleaseRedirect()).open(source, timeout=25) as response:
            archive = response.read(MAX_ARCHIVE + 1)
    else:
        with Path(source).open("rb") as handle:
            archive = handle.read(MAX_ARCHIVE + 1)
    binary = verified_binary(core, archive, digest, arch)
    if len(binary) > shutil.disk_usage(Path(destination).parent).free - int(reserve):
        raise ValueError("Insufficient space for this core and router state")
    with Path(destination).open("wb") as handle:
        os.fchmod(handle.fileno(), 0o700)
        handle.write(binary)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", action="store_true", help="Also install the Xray adapter")
    parser.add_argument("--archives", type=Path, help="Read approved archives from a local directory")
    parser.add_argument("--stage", nargs=5, metavar=("CORE", "SHA256", "DESTINATION", "SOURCE", "RESERVE"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    arch = architecture(platform.machine())
    if os.geteuid() != 0 or platform.system() != "FreeBSD" or arch not in ELF_MACHINES:
        parser.error("Run as root on the target FreeBSD amd64 or aarch64 router")
    try:
        if args.stage:
            stage(*args.stage, arch)
            return
        cli = Path(__file__).with_name("cores.php")
        for core in ["mihomo", "tun2socks"] + (["xray"] if args.xray else []):
            command = ["/usr/local/bin/php", str(cli), "install", core]
            if args.archives:
                asset = Path(urlsplit(ASSETS[arch][core][0]).path).name
                command.append(str(args.archives / asset))
            subprocess.run(command, check=True)
    except (OSError, ValueError, EOFError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
