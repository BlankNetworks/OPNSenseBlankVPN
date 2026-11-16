#!/usr/bin/env python3
"""Check the version-independent SSH installer without touching a router."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/install-latest.sh"


def run(corrupt=False):
    with tempfile.TemporaryDirectory(prefix="blankvpn-latest-fixture-") as name:
        root = Path(name)
        release = root / "release"
        release.mkdir()
        installer = b"#!/bin/sh\nversion=0.8.37\necho fixture-install-ran\n"
        (release / "install.sh").write_bytes(installer + (b"corrupt" if corrupt else b""))
        digest = hashlib.sha256(installer).hexdigest()
        assets = [{"name": f"os-blank-vpn-0.8.37-amd64.pkg"},
                  {"name": f"os-blank-vpn-0.8.37-amd64.pkg.sha256"}]
        releases = [
            {"tag_name": "v0.8.38", "draft": True, "assets": assets, "body": ""},
            {"tag_name": "v0.8.37", "draft": False, "assets": assets,
             "body": f"sha256 -c {digest} /tmp/blankvpn-install-0.8.37.sh"},
            {"tag_name": "v0.8.36", "draft": False, "assets": [], "body": ""},
        ]
        (release / "releases.json").write_text(json.dumps(releases), encoding="utf-8")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "fixture"
        stub.write_text(f"#!{sys.executable}\n" + '''
import hashlib
import os
from pathlib import Path
import shutil
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "id" and args == ["-u"]:
    print("0")
elif name == "uname" and args == ["-s"]:
    print("FreeBSD")
elif name == "opnsense-version":
    print({"-n": "opnsense", "-a": "26.7"}[args[0]])
elif name == "pkg" and args == ["config", "ABI"]:
    print("FreeBSD:15:amd64")
elif name == "fetch" and len(args) == 4 and args[:2] == ["-q", "-o"]:
    source = "releases.json" if "api.github.com" in args[3] else "install.sh"
    shutil.copyfile(Path(os.environ["FIXTURE_RELEASE"]) / source, args[2])
elif name == "sha256" and args[0] == "-q":
    print(hashlib.sha256(Path(args[1]).read_bytes()).hexdigest())
else:
    sys.exit("unexpected latest installer command: " + name + " " + " ".join(args))
''', encoding="utf-8")
        stub.chmod(0o755)
        for command in ("id", "uname", "opnsense-version", "pkg", "fetch", "sha256"):
            (bin_dir / command).symlink_to(stub)
        environment = os.environ | {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                                    "FIXTURE_RELEASE": str(release)}
        result = subprocess.run(["sh", str(SCRIPT)], env=environment, capture_output=True, text=True)
        if corrupt:
            assert result.returncode != 0 and "checksum does not match" in result.stderr
            assert "fixture-install-ran" not in result.stdout
        else:
            assert result.returncode == 0, result.stderr
            assert "release 0.8.37" in result.stdout and "fixture-install-ran" in result.stdout


if __name__ == "__main__":
    subprocess.run(["sh", "-n", str(SCRIPT)], check=True)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "main/scripts/install-latest.sh" in readme
    if shutil.which("php"):
        run()
        run(corrupt=True)
        print("Latest SSH installer verified selection and checksum rejection.")
    else:
        print("Latest SSH installer syntax and documentation verified; PHP fixture runs in CI.")
