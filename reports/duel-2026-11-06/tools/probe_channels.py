# -*- coding: utf-8 -*-
"""Attacker probe: plant the same secrets through different storage channels
into a real signed Windows PE (overlay), one channel per file, so the
defender's reach per channel can be measured independently."""
import base64
import json
import os
import struct
import sys
import zlib

BASE = r"C:\Windows\System32\whoami.exe"
OUT = os.path.join(os.environ.get("TEMP", "."), "rea-spec")
os.makedirs(OUT, exist_ok=True)

CANARY = "orbit-7f3a91c2d8e4"
C2 = "https://cdn-sync.example-corp.net/v3/poll"
FALLBACK = "http://198.51.100.44:8443/gate.php"
TG = "7482916350:AAH-3xK9pQm2vTn7rLwZs4Yd8eB1cF6gH0jK"
BTC = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
EMAIL = "ops@example-corp.net"
REG = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveSync"
PDB = r"C:\Users\dev\Desktop\loader\bin\Release\svchost.pdb"
MUTEX = r"Global\OBS-9f3c2a"

config = {
    "c2": C2,
    "fallback": FALLBACK,
    "tg": TG,
    "btc": BTC,
    "email": EMAIL,
    "reg": REG,
    "pdb": PDB,
    "mutex": MUTEX,
    "canary": CANARY,
}
raw = json.dumps(config).encode()

with open(BASE, "rb") as fh:
    base = fh.read()

made = {}


def emit(name, blob):
    data = base + blob
    path = os.path.join(OUT, name + ".exe")
    with open(path, "wb") as fh:
        fh.write(data)
    made[name] = (path, len(blob))


# P0 control: plaintext JSON overlay
emit("P0-plain-json-overlay", b"\n" + raw + b"\n")

# P1 zlib stream appended to the file
emit("P1-zlib-json-overlay", zlib.compress(raw, 9))

# P2 base64(zlib(json)) as text
emit("P2-b64-zlib-json", base64.b64encode(zlib.compress(raw, 9)))

# P3 single-byte XOR 0x5a over the json
emit("P3-xor5a-json", bytes(b ^ 0x5A for b in b"\n" + raw + b"\n"))

# P4 hex-encoded url only
emit("P4-hex-url", b"\n" + C2.encode().hex().encode() + b"\n")

# P5 utf-16be url
emit("P5-utf16be-url", C2.encode("utf-16-be"))

# P6 ipv4 as little-endian dword + split domain
split = b"cdn-sync.example" + b"\x00" + b"-corp.net" + b"\x00"
emit("P6-dword-ip-split-domain", struct.pack("<I", 0xCB00714D) + b"\n" + split)

# P7 json with \u escapes for the url
escaped = json.dumps({"c2": C2}).replace(C2, "".join("\\u%04x" % ord(c) for c in C2))
emit("P7-json-uescape", b"\n" + escaped.encode() + b"\n")

# P8 url split by a NUL inside one blob
emit("P8-nul-split-url", b"https://cdn-sync.example" + b"\x00" + b"-corp.net/v3/poll" + b"\x00")

# P9 reversed literal (known channel, control for the ladder)
emit("P9-reversed-url", C2[::-1].encode())

# P10 gzip stream
import gzip
emit("P10-gzip-json", gzip.compress(raw))

# P11 long random-looking base64 with a zlib stream in the middle
emit("P11-b64-noise-prefix", b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 8 + base64.b64encode(zlib.compress(raw, 9)))

# P12 two-part: first half in overlay, second half in a trailing comment
emit("P12-split-across-parts", b"\nhttps://cdn-sync." + b"\n# section 2\n" + b"example-corp.net/v3/poll\n")

for name, (path, n) in sorted(made.items()):
    print(f"{name:34s} +{n:6d} bytes  {path}")
print("BASE", BASE, len(base))
