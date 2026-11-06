# -*- coding: utf-8 -*-
"""Round 3 red team: decode chains, wide-XOR, scheme coverage, analyser DoS."""
import base64
import gzip
import json
import os
import zlib

OUT = os.path.join(os.environ.get("TEMP", "."), "rea-spec3")
os.makedirs(OUT, exist_ok=True)
with open(r"C:\Windows\System32\whoami.exe", "rb") as fh:
    base = fh.read()

C2 = "https://r3.example-corp.net/api/collect"
WIDE = "https://wide.example-corp.net/beacon"
cfg = json.dumps({"c2": C2, "user": "r3", "build": "stage-9"}).encode()


def xor(data, key):
    return bytes(b ^ key for b in data)


def write(name, blob):
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(base + b"\n" + blob + b"\n")
    print(f"{name:34s} +{len(blob):>9,d}")


# 1. XORed UTF-16LE config (very common in Windows loaders)
write("R3a-xor-utf16.exe", xor(WIDE.encode("utf-16-le"), 0x5A))

# 2. nested chain: base64(deflate(xor5a(json)))
write("R3b-b64-deflate-xor.exe", base64.b64encode(zlib.compress(xor(cfg, 0x5A), 9)))

# 3. nested chain: hex(gzip(xor4(json))) with 4-byte key
key = b"\x13\x37\xbe\xef"
write("R3c-hex-gzip-xor4.exe", gzip.compress(bytes(b ^ key[i % 4] for i, b in enumerate(cfg))).hex().encode())

# 4. scheme zoo + host:port + uncommon TLD
zoo = "\n".join([
    "ws=ws://gate.example-corp.net/socket",
    "tcp=tcp://45.77.12.9:4444",
    "smb=\\\\fileserver\\share\\payload.bin",
    "hp=198.51.100.9:8080",
    "shop=https://cdn.example-corp.shop/update",
    "ftp=ftp://files.example-corp.net/drop",
]).encode()
write("R3d-schemes.exe", zoo)

# 5. DoS: 8 MB of repeated MZ (embedded-PE scan)
write("R3e-mz-flood.exe", b"MZ" * 4_000_000)

# 6. DoS: zlib bomb (64 MB of zeros, ~64 KB compressed)
write("R3f-zlib-bomb.exe", zlib.compress(b"\x00" * (64 * 1024 * 1024), 9))

print("OUT", OUT)
