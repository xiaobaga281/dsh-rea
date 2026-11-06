# -*- coding: utf-8 -*-
"""Attacker round 2: one realistic composite sample + malformed/hostile inputs.

Ground truth is printed so the defender's report can be scored mechanically.
"""
import json
import os
import random
import struct
import zlib

BASE = r"C:\Windows\System32\whoami.exe"
OUT = os.path.join(os.environ.get("TEMP", "."), "rea-spec")
os.makedirs(OUT, exist_ok=True)

HEX_URL = "https://api.example-corp.net/v1/collect"
ESC_URL = "https://ops.example-corp.net/ping"
UTF16_URL = "https://backup.example-corp.net/sync"
TG = "7482916350:AAH-3xK9pQm2vTn7rLwZs4Yd8eB1cF6gH0jK"
CANARY = "orbit-7f3a91c2d8e4"
MUTEX = r"Global\OBS-9f3c2a"
DWORD_IP = 0xCB00714D  # 203.0.113.77

escaped = json.dumps({"c2": ESC_URL})
escaped = escaped.replace(ESC_URL, "".join("\\u%04x" % ord(c) for c in ESC_URL))

overlay = b"\n" + b"\n".join([
    b"[cfg]",
    b"decoy=https://www.microsoft.com/en-us/security",
    ("hex=" + HEX_URL.encode().hex()).encode(),
    ("json=" + escaped).encode(),
    ("tg=" + TG).encode(),
    ("mutex=" + MUTEX).encode(),
    ("canary=" + CANARY).encode(),
    b"markers=FirebaseAnalytics,AppsFlyer,getLastKnownLocation,AdvertisingIdClient",
    b"anti=VMware,VBox,SbieDll.dll,frida",
    b"dword=" + struct.pack("<I", DWORD_IP),
    b"wide=" + UTF16_URL.encode("utf-16-le"),
    b"",
]) + b"\n"

with open(BASE, "rb") as fh:
    base = fh.read()

composite = os.path.join(OUT, "S1-composite.exe")
with open(composite, "wb") as fh:
    fh.write(base + overlay)
print("composite:", composite, len(base), "+", len(overlay))

# --- hostile / malformed inputs ------------------------------------------------
cases = {}
cases["E0-empty.exe"] = b""
cases["E1-onebyte.exe"] = b"M"
cases["E2-text.exe"] = b"this is not a pe file at all\n" * 20
cases["E3-truncated.exe"] = base[:100]
cases["E4-dosheader-only.exe"] = base[:64]
cases["E5-huge-random.bin"] = bytes(random.getrandbits(8) for _ in range(16 * 1024 * 1024))
cases["E6-zeros.bin"] = b"\x00" * (16 * 1024 * 1024)
cases["E7-pe-as-txt.txt"] = base + b"\nhttps://txt-extension.example/x\n"
for name, blob in cases.items():
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(blob)
    print(f"{name:24s} {len(blob):>10,d} bytes")

# unicode / spaces / readonly
import shutil
u = os.path.join(OUT, "S2-恶意样本😀.exe")
shutil.copyfile(composite, u)
s = os.path.join(OUT, "S3-space name.exe")
shutil.copyfile(composite, s)
r = os.path.join(OUT, "S4-readonly.exe")
shutil.copyfile(composite, r)
os.chmod(r, 0o444)
print("unicode:", u)
print("space:", s)
print("readonly:", r)

# junction (needs no admin on Windows 10+)
j = os.path.join(OUT, "J1-junction")
try:
    if os.path.isdir(j):
        os.rmdir(j)
    os.system(f'mklink /J "{j}" "C:\\Windows\\System32" >nul')
    print("junction:", j, "->", os.path.realpath(j))
except Exception as exc:
    print("junction failed:", exc)

# variant for diff_hint: same file, one changed byte in the C2 host
v = bytearray(base + overlay)
at = bytes(v).find(b"ops.example-corp.net")
if at > 0:
    v[at + 1] = ord("b")
variant = os.path.join(OUT, "S1b-composite-mutated.exe")
with open(variant, "wb") as fh:
    fh.write(bytes(v))
print("variant:", variant, "changed byte at", at)

print("\nGROUND TRUTH")
print("  endpoints:", HEX_URL, "|", ESC_URL, "|", UTF16_URL)
print("  ipv4:", "203.0.113.77 (as dword 0xCB00714D)")
print("  telegram token:", TG)
print("  mutex:", MUTEX)
print("  canary:", CANARY)
print("  decoy (must NOT be reported as C2):", "https://www.microsoft.com/en-us/security")
