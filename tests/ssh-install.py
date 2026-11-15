#!/usr/bin/env python3
"""Exercise the SSH installer with a disposable router command fixture."""

import hashlib
import os
import runpy
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts/install.sh"
VERSION = runpy.run_path(str(ROOT / "build/package.py"))["VERSION"]
SCRIPT = INSTALLER.read_text(encoding="utf-8")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture(abi="FreeBSD:15:amd64", corrupt=False):
    with tempfile.TemporaryDirectory(prefix="blankvpn-ssh-install-") as directory:
        root = Path(directory)
        config = root / "conf/config.xml"
        backup_dir = root / "conf/backup"
        backup_dir.mkdir(parents=True)
        config.write_text("<opnsense/>\n", encoding="ascii")
        staged = SCRIPT.replace("/conf/config.xml", str(config)).replace(
            "/conf/backup", str(backup_dir)
        ).replace("/tmp/blankvpn-install.XXXXXXXX", str(root / "stage.XXXXXXXX"))
        installer = root / "install.sh"
        installer.write_text(staged, encoding="utf-8")

        package = f"os-blank-vpn-{VERSION}-{abi.rsplit(':', 1)[-1]}.pkg"
        release = root / "release"
        release.mkdir()
        body = b"disposable package fixture\n"
        (release / package).write_bytes(body)
        (release / f"{package}.sha256").write_text(
            f"{hashlib.sha256(body).hexdigest()}  {package}\n", encoding="ascii"
        )
        log = root / "commands.log"
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "fixture-command"
        stub.write_text(f"#!{sys.executable}\n" + '''
import hashlib
import os
import shutil
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
log = Path(os.environ["BLANKVPN_FIXTURE_LOG"])
def record(event):
    with log.open("a", encoding="ascii") as stream:
        stream.write(event + "\\n")
if name == "id" and args == ["-u"]:
    print("0")
elif name == "uname" and args == ["-s"]:
    print("FreeBSD")
elif name == "opnsense-version":
    print({"-n": "opnsense", "-a": "26.7"}[args[0]])
elif name == "pkg" and args == ["config", "ABI"]:
    print(os.environ["BLANKVPN_FIXTURE_ABI"])
elif name == "pkg" and args[:2] == ["add", "-f"]:
    backups = list(Path(os.environ["BLANKVPN_FIXTURE_BACKUPS"]).glob("config-blankvpn-preinstall-*.xml"))
    if len(backups) != 1 or backups[0].stat().st_mode & 0o777 != 0o600:
        sys.exit("protected backup missing before package installation")
    record("pkg_add")
elif name == "pkg" and args == ["query", "%v", "os-blank-vpn"]:
    print(os.environ["BLANKVPN_FIXTURE_VERSION"])
elif name == "fetch" and len(args) == 3 and args[0] == "-o":
    source = Path(os.environ["BLANKVPN_FIXTURE_RELEASE"]) / args[2].rsplit("/", 1)[-1]
    shutil.copyfile(source, args[1])
    if os.environ.get("BLANKVPN_FIXTURE_CORRUPT") == "1" and source.suffix == ".pkg":
        with open(args[1], "ab") as stream:
            stream.write(b"changed")
    record("fetch")
elif name == "sha256sum" and len(args) == 2 and args[0] == "-c":
    digest, filename = Path(args[1]).read_text(encoding="ascii").split()
    actual = hashlib.sha256(Path(filename).read_bytes()).hexdigest()
    if actual != digest:
        sys.exit(1)
    record("checksum_ok")
else:
    sys.exit("unexpected installer command: " + name + " " + " ".join(args))
''', encoding="utf-8")
        stub.chmod(0o755)
        for name in ("id", "uname", "opnsense-version", "pkg", "fetch", "sha256sum"):
            (bin_dir / name).symlink_to(stub)
        environment = os.environ | {
            "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
            "BLANKVPN_FIXTURE_ABI": abi,
            "BLANKVPN_FIXTURE_RELEASE": str(release),
            "BLANKVPN_FIXTURE_BACKUPS": str(backup_dir),
            "BLANKVPN_FIXTURE_LOG": str(log),
            "BLANKVPN_FIXTURE_VERSION": VERSION,
            "BLANKVPN_FIXTURE_CORRUPT": "1" if corrupt else "0",
        }
        result = subprocess.run(["sh", str(installer)], env=environment, capture_output=True, text=True)
        events = log.read_text(encoding="ascii").splitlines() if log.exists() else []
        backups = list(backup_dir.glob("config-blankvpn-preinstall-*.xml"))
        if abi not in ("FreeBSD:15:amd64", "FreeBSD:15:aarch64"):
            check(result.returncode != 0 and not events and not backups, "Unsupported ABI must stop before download")
        elif corrupt:
            check(result.returncode != 0 and events == ["fetch", "fetch"] and not backups,
                  "A bad checksum must stop before backup or installation")
        else:
            check(result.returncode == 0 and events == ["fetch", "fetch", "checksum_ok", "pkg_add"],
                  f"Verified installation did not finish: {result.stderr}")
            check(len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o600,
                  "The installer must retain a protected configuration backup")
        check(not list(root.glob("stage.*")), "The temporary package download was not removed")


def main():
    check(f"version={VERSION}" in SCRIPT, "Installer and package versions differ")
    digest = hashlib.sha256(INSTALLER.read_bytes()).hexdigest()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    check(f"sha256 -c {digest} /tmp/blankvpn-install-{VERSION}.sh" in readme,
          "README does not pin the current installer digest")
    subprocess.run(["sh", "-n", str(INSTALLER)], check=True)
    fixture()
    fixture(abi="FreeBSD:15:aarch64")
    fixture(abi="FreeBSD:15:riscv64")
    fixture(corrupt=True)
    sys.path.insert(0, str(ROOT / "build"))
    from release_notes import install_instructions
    with tempfile.TemporaryDirectory(prefix="blankvpn-release-notes-") as directory:
        release = Path(directory)
        for arch in ("amd64", "aarch64"):
            package = f"os-blank-vpn-{VERSION}-{arch}.pkg"
            body = f"fixture for {arch}".encode("ascii")
            (release / package).write_bytes(body)
            (release / f"{package}.sha256").write_text(
                f"{hashlib.sha256(body).hexdigest()}  {package}\n", encoding="ascii"
            )
        notes = install_instructions(release, "BlankNetworks/OPNSenseBlankVPN")
        check(f"sha256 -c {digest} /tmp/blankvpn-install-{VERSION}.sh" in notes and
              all(f"pkg add -f ./os-blank-vpn-{VERSION}-{arch}.pkg" in notes for arch in ("amd64", "aarch64")),
              "Release notes must contain the verified SSH and manual package install paths")
    print("SSH installer verified both ABIs, backup, checksum rejection, and release instructions.")


if __name__ == "__main__":
    main()
