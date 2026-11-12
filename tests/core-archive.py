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
image = bytearray(128)
image[:8] = b"\x7fELF\x02\x01\x01\x00"
struct.pack_into("<H", image, 18, 62)
struct.pack_into("<Q", image, 32, 64)
struct.pack_into("<HH", image, 54, 56, 1)
image.extend(struct.pack("<III", 8, 4, 1) + b"FreeBSD\0" + struct.pack("<I", 1500000))
struct.pack_into("<I", image, 64, 4)
struct.pack_into("<Q", image, 72, 128)
struct.pack_into("<Q", image, 96, 24)
image = bytes(image)

for data in [image, gzip.compress(image)]:
    assert check("mihomo", data, hashlib.sha256(data).hexdigest()) == image
container = io.BytesIO()
with ZipFile(container, "w") as zipped:
    zipped.writestr("xray", image)
    zipped.writestr("../ignored", b"not extracted")
data = container.getvalue()
assert check("xray", data, hashlib.sha256(data).hexdigest()) == image
for data, digest in [(image, "0" * 64), (image.replace(b"FreeBSD", b"GNU...."), None)]:
    try:
        check("mihomo", data, digest or hashlib.sha256(data).hexdigest())
    except ValueError:
        continue
    raise AssertionError("Unverified or non-FreeBSD binary accepted")
print("Approved archive, checksum, FreeBSD ELF and ZIP fixtures passed.")
