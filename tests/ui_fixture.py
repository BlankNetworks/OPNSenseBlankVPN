#!/usr/bin/env python3
"""Run the current dashboard view and assets against a browser API fixture."""

import argparse
import json
import platform
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("chromium", help="Path to a Chromium or Chrome executable")
    parser.add_argument("--no-sandbox", action="store_true", help="Use only with this local fixture in a restricted runner")
    args = parser.parse_args()
    view = (ROOT / "src/opnsense/mvc/app/views/OPNsense/BlankVpn/index.volt").read_text()
    view = re.sub(r"<link[^>]+>\s*|<script\s+src=[^>]+>\s*</script>\s*", "", view)
    css = (ROOT / "src/opnsense/www/css/blankvpn.css").read_text()
    app = (ROOT / "src/opnsense/www/js/blankvpn.js").read_text()
    fixture = (ROOT / "tests/ui-fixture.js").read_text()
    providers = json.loads((ROOT / "src/share/blankvpn/providers.json").read_text())
    provider_data = json.dumps(providers).replace("<", "\\u003c")
    document = (
        '<!doctype html><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width, initial-scale=1">'
        f"<style>{css}</style><body>{view}<script id='provider-fixture' type='application/json'>{provider_data}</script>"
        f"<script>{fixture}</script><script>{app}</script></body>"
    )
    with tempfile.TemporaryDirectory(prefix="blank-vpn-ui-") as directory:
        root = Path(directory)
        path = root / "fixture.html"
        path.write_text(document)
        sandbox_flags = ["--no-sandbox"] if args.no_sandbox else []
        if args.no_sandbox and platform.system() == "Darwin":
            sandbox_flags.append("--single-process")
        for size in ("390,844", "1280,900"):
            result = subprocess.run(
                [args.chromium, *sandbox_flags, "--headless", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                 "--no-default-browser-check", f"--user-data-dir={root / 'profile'}",
                 "--virtual-time-budget=3500", f"--window-size={size}", "--dump-dom", path.as_uri()],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                raise SystemExit(result.stderr or f"Chromium returned {result.returncode}")
            match = re.search(r'data-fixture-result="([^"]+)"', result.stdout)
            if match is None or match[1] != "PASS":
                raise SystemExit(f"Dashboard fixture {size}: {match[1] if match else 'no result'}")
            print(f"Dashboard fixture {size}: PASS")


if __name__ == "__main__":
    main()
