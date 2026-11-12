import gzip
import hashlib
import io
import runpy
import struct
from pathlib import Path
from zipfile import ZipFile

runtime = runpy.run_path(str(
    Path(__file__).resolve().parents[1] /
    "src/opnsense/scripts/OPNsense/BlankVpn/install_proxy_cores.py"
))
check = runtime["verified_binary"]
assert runtime["architecture"]("arm64") == "aarch64"
assert runtime["architecture"]("x86_64") == "amd64"

for arch, machine in runtime["ELF_MACHINES"].items():
    image = bytearray(128)
    image[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<H", image, 18, machine)
    struct.pack_into("<Q", image, 32, 64)
    struct.pack_into("<HH", image, 54, 56, 1)
    image.extend(struct.pack("<III", 8, 4, 1) + b"FreeBSD\0" + struct.pack("<I", 1500000))
    struct.pack_into("<I", image, 64, 4)
    struct.pack_into("<Q", image, 72, 128)
    struct.pack_into("<Q", image, 96, 24)
    image = bytes(image)

    for data in [image, gzip.compress(image)]:
        assert check("mihomo", data, hashlib.sha256(data).hexdigest(), arch) == image
    container = io.BytesIO()
    with ZipFile(container, "w") as zipped:
        suffix = "arm64" if arch == "aarch64" else arch
        zipped.writestr(f"tun2socks-freebsd-{suffix}", image)
        zipped.writestr("../ignored", b"not extracted")
    data = container.getvalue()
    assert check("tun2socks", data, hashlib.sha256(data).hexdigest(), arch) == image

    other = "aarch64" if arch == "amd64" else "amd64"
    for target, data, digest in [(arch, image, "0" * 64), (arch, image.replace(b"FreeBSD", b"GNU...."), None),
                                 (other, image, None)]:
        try:
            check("mihomo", data, digest or hashlib.sha256(data).hexdigest(), target)
        except ValueError:
            continue
        raise AssertionError("Unverified, non-FreeBSD or wrong-architecture binary accepted")
print("Approved archive, checksum, FreeBSD amd64 and aarch64 ELF, and ZIP fixtures passed.")
