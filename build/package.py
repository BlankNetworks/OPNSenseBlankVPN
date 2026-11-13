#!/usr/bin/env python3
"""Build and verify a FreeBSD pkg archive for the Blank VPN OPNsense plugin."""

import argparse
import hashlib
import io
import json
import os
import platform
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent.parent
NAME = "os-blank-vpn"
VERSION = "0.8.12"
SERIES = "26.7"
LEGACY_ARCHES = {"amd64": "x86:64", "aarch64": "aarch64:64"}
CORE_INSTALLER = ROOT / "src/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py"
PREFIX = "/usr/local"
DEPENDENCIES = {
    "opnsense": {"origin": "opnsense/opnsense", "version": SERIES},
    "dnsmasq": {"origin": "opnsense/dnsmasq", "version": "2.93"},
    "php85-curl": {"origin": "ftp/php85-curl", "version": "8.5"},
    "python313": {"origin": "lang/python313", "version": "3.13"},
}
VERSION_FILE = PurePosixPath("opnsense/version/blank-vpn")
HOOKS = ("pre-install", "post-install", "pre-deinstall", "post-deinstall")


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def payload(arch, runtime_dir=None):
    source = ROOT / "src"
    files = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part.startswith(".") or part == "__pycache__" for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Unexpected symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file() or not re.fullmatch(r"(?:etc|opnsense|sbin|share)/[a-zA-Z0-9/_.-]+", relative.as_posix()):
            raise ValueError(f"Unexpected payload path: {relative}")
        if relative.suffix in {".pyc", ".pyo"}:
            continue
        if relative.as_posix() == VERSION_FILE.as_posix():
            raise ValueError(f"The build generates {VERSION_FILE}")
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        files[f"{PREFIX}/{relative.as_posix()}"] = (path.read_bytes(), mode)
    if not files:
        raise ValueError("No plugin files found under src/")
    if runtime_dir is not None:
        check_binary = runpy.run_path(str(CORE_INSTALLER))["is_freebsd_binary"]
        for core in ("mihomo", "tun2socks", "xray", "sing-box"):
            binary = (runtime_dir / "bin" / core).read_bytes()
            if not check_binary(binary, arch):
                raise ValueError(f"{core} is not a FreeBSD {arch} ELF executable")
            files[f"{PREFIX}/libexec/blankvpn/{core}"] = (binary, 0o755)
        for name in ("mihomo", "tun2socks", "xray", "sing-box", "pyyaml"):
            license_path = f"licenses/{name}.txt"
            files[f"{PREFIX}/share/blankvpn/{license_path}"] = ((runtime_dir / license_path).read_bytes(), 0o644)
        yaml_files = sorted((runtime_dir / "yaml").glob("*.py"))
        if not any(path.name == "__init__.py" for path in yaml_files):
            raise ValueError("The staged PyYAML source is missing")
        for path in yaml_files:
            files[f"{PREFIX}/share/blankvpn/python/yaml/{path.name}"] = (path.read_bytes(), 0o644)
    return files


def version_info(files, arch):
    digest = hashlib.sha256()
    for name, (data, mode) in files.items():
        digest.update(name.encode("ascii") + b"\0")
        digest.update(mode.to_bytes(2, "big"))
        digest.update(hashlib.sha256(data).digest())
    return {
        "product_abi": SERIES,
        "product_arch": arch,
        "product_conflicts": "",
        "product_email": "N/A",
        "product_hash": digest.hexdigest()[:12],
        "product_id": NAME,
        "product_name": "blank-vpn",
        "product_tier": "3",
        "product_version": VERSION,
        "product_website": "https://github.com/BlankNetworks/OPNSenseBlankVPN",
    }


def abi(arch):
    return f"FreeBSD:15:{arch}"


def build_metadata(files, dependencies, arch):
    version = version_info(files, arch)
    files[f"{PREFIX}/{VERSION_FILE}"] = (
        (json.dumps(version, indent=4) + "\n").encode(),
        0o644,
    )
    return {
        "name": NAME,
        "version": VERSION,
        "origin": f"opnsense/{NAME}",
        "comment": "Per-device VPN and proxy routing with IPv4 kill switches",
        "desc": (ROOT / "pkg-descr").read_text(encoding="utf-8").strip(),
        "maintainer": version["product_email"],
        "www": version["product_website"],
        "abi": abi(arch),
        "arch": f"freebsd:15:{LEGACY_ARCHES[arch]}",
        "prefix": PREFIX,
        "categories": ["net-vpn"],
        "deps": dependencies,
        "annotations": version,
        "flatsize": sum(len(data) for data, _ in files.values()),
    }


def hook_scripts(arch):
    scripts = {}
    for name in HOOKS:
        path = ROOT / "build" / "hooks" / name
        script = path.read_text(encoding="utf-8").replace("@BLANKVPN_ARCH@", arch).strip()
        subprocess.run(["sh", "-n"], input=script, text=True, check=True)
        scripts[name] = script
    return scripts


def native_pkg(arch):
    pkg = "/usr/local/sbin/pkg"
    version = "/usr/local/sbin/opnsense-version"
    if (
        platform.system() != "FreeBSD"
        or not Path(pkg).is_file()
        or not Path(version).is_file()
        or command(version, "-n") != "opnsense"
        or command(version, "-a") != SERIES
        or command(pkg, "config", "ABI") != abi(arch)
    ):
        raise ValueError(
            f"Native build requires OPNsense Community Edition {SERIES} {abi(arch)}. "
            "Use --cross to produce an archive for validation on that target."
        )
    installed = {}
    for name, expected in DEPENDENCIES.items():
        version, origin = command(pkg, "query", "%v %o", name).split()
        if origin != expected["origin"]:
            raise ValueError(f"Unexpected {name} package origin: {origin}")
        installed[name] = {"version": version, "origin": origin}
    return pkg, installed


def create_native(path, work, pkg, metadata, scripts, files, timestamp):
    stage = work / "stage"
    meta = work / "metadata"
    meta.mkdir()
    (meta / "+MANIFEST").write_text(
        json.dumps(metadata | {"scripts": scripts}),
        encoding="utf-8",
    )
    entries = []
    for name, (data, mode) in files.items():
        file = stage / name.lstrip("/")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        file.chmod(mode)
        os.utime(file, (timestamp, timestamp))
        entries.append(f"@(root,wheel,{mode:04o}) {name}\n")
    plist = meta / "plist"
    plist.write_text("".join(entries), encoding="utf-8")
    subprocess.run(
        [pkg, "create", "-f", "txz", "-m", meta, "-r", stage, "-p", plist, "-o", path.parent],
        env=os.environ | {"SOURCE_DATE_EPOCH": str(timestamp)},
        check=True,
    )
    native_name = path.with_name(f"{NAME}-{VERSION}.pkg")
    if not native_name.is_file():
        raise ValueError(f"pkg create did not produce {native_name.name}")
    native_name.rename(path)
    subprocess.run([pkg, "info", "-F", path], check=True)


def tar_add(archive, path, data, mode, timestamp):
    member = tarfile.TarInfo(path)
    member.size = len(data)
    member.mode = mode
    member.uid = member.gid = 0
    member.uname = "root"
    member.gname = "wheel"
    member.mtime = timestamp
    archive.addfile(member, io.BytesIO(data))


def create_cross(path, metadata, scripts, files, timestamp):
    manifest = metadata | {
        "scripts": scripts,
        "files": {
            name: {
                "sum": "1$" + hashlib.sha256(data).hexdigest(),
                "uname": "root",
                "gname": "wheel",
                "perm": f"{mode:04o}",
            }
            for name, (data, mode) in files.items()
        },
    }
    with tarfile.open(path, "w:xz", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in (("+COMPACT_MANIFEST", metadata), ("+MANIFEST", manifest)):
            data = json.dumps(body, separators=(",", ":")).encode()
            tar_add(archive, name, data, 0o644, timestamp)
        for name, (data, mode) in files.items():
            tar_add(archive, name, data, mode, timestamp)


def verify(path, metadata, scripts, files):
    with tarfile.open(path, "r:xz") as archive:
        members = archive.getmembers()
        if [m.name for m in members[:2]] != ["+COMPACT_MANIFEST", "+MANIFEST"]:
            raise ValueError("Package has an invalid manifest layout")
        compact, full = (json.load(archive.extractfile(member)) for member in members[:2])
        for field in ("name", "version", "origin", "abi", "arch", "prefix", "deps", "flatsize"):
            if compact.get(field) != metadata[field] or full.get(field) != metadata[field]:
                raise ValueError(f"Package metadata mismatch for {field}")
        if compact.get("scripts") or compact.get("files"):
            raise ValueError("Package compact manifest includes payload details")
        if full.get("scripts") != scripts:
            raise ValueError("Package hook content mismatch")
        if sorted(full.get("files", {})) != sorted(files):
            raise ValueError("Package manifest does not match the source payload list")
        if sorted(m.name for m in members[2:]) != sorted(files):
            raise ValueError("Package archive does not match the source payload list")
        for member in members[2:]:
            data, mode = files[member.name]
            if (
                not member.isfile()
                or member.mode != mode
                or member.uid != 0
                or member.gid != 0
                or archive.extractfile(member).read() != data
            ):
                raise ValueError(f"Package file differs from source: {member.name}")
            manifest_sum = full["files"][member.name]["sum"]
            if manifest_sum.startswith("1$") and manifest_sum[2:] != hashlib.sha256(data).hexdigest():
                raise ValueError(f"Package manifest checksum mismatch: {member.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--cross", action="store_true", help="Produce the native pkg format on a non-OPNsense host")
    parser.add_argument("--arch", choices=LEGACY_ARCHES, help="Target FreeBSD package architecture")
    parser.add_argument("--output", type=Path, default=ROOT / "dist", help="Output directory")
    parser.add_argument("--runtime-dir", type=Path, help="Include the staged FreeBSD proxy runtimes and licenses")
    args = parser.parse_args()
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    if timestamp < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be nonnegative")
    if args.cross:
        arch = args.arch or "amd64"
        pkg, dependencies = None, DEPENDENCIES
    else:
        normalize = runpy.run_path(str(CORE_INSTALLER))["architecture"]
        arch = args.arch or normalize(platform.machine())
        if arch not in LEGACY_ARCHES:
            parser.error("Use an amd64 or aarch64 OPNsense host, or cross-build with --cross --arch")
        pkg, dependencies = native_pkg(arch)
    files = payload(arch, args.runtime_dir)
    metadata = build_metadata(files, dependencies, arch)
    scripts = hook_scripts(arch)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".blank-vpn-package-", dir=output) as temporary:
        work = Path(temporary)
        package = work / f"{NAME}-{VERSION}-{arch}.pkg"
        if pkg is None:
            create_cross(package, metadata, scripts, files, timestamp)
        else:
            create_native(package, work, pkg, metadata, scripts, files, timestamp)
        verify(package, metadata, scripts, files)
        checksum = hashlib.sha256(package.read_bytes()).hexdigest()
        checksum_file = work / f"{package.name}.sha256"
        checksum_file.write_text(f"{checksum}  {package.name}\n", encoding="ascii")
        shutil.move(package, output / package.name)
        shutil.move(checksum_file, output / checksum_file.name)
    print(f"{output / package.name}\nSHA-256 {checksum}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
