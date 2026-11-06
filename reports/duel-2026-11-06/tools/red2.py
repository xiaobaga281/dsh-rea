# -*- coding: utf-8 -*-
"""Round 2 red team: payloads the round-1 fixes do not cover.

R1 embedded PE + appended ZIP
R2 encoding zoo: spaced hex, base32, JWT, onion, SSH key, split URL, DWORD IP
R3 opcode-level anti-debug placed in a .text code cave
"""
import base64
import io
import os
import struct
import zipfile

OUT = os.path.join(os.environ.get("TEMP", "."), "rea-spec2")
os.makedirs(OUT, exist_ok=True)
BASE = r"C:\Windows\System32\whoami.exe"
with open(BASE, "rb") as fh:
    base = fh.read()

# ---------------------------------------------------------------- R1 embedded
with open(r"C:\Windows\System32\where.exe", "rb") as fh:
    inner = fh.read()
config = b'{"c2":"https://embedded.example-corp.net/z","build":"staging"}\n'
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("config/settings.json", config)
    z.writestr("readme.txt", "installer payload\n")
zip_bytes = buf.getvalue()
for name, blob in (("R1a-embedded-pe.exe", b"\n" + inner + b"\n"), ("R1b-appended-zip.exe", zip_bytes)):
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(base + blob)
    print(name, len(base), "+", len(blob))

# ---------------------------------------------------------------- R2 encodings
spaced = "68 74 74 70 3a 2f 2f 73 70 61 63 65 64 2e 65 78 61 6d 70 6c 65 2d 63 6f 72 70 2e 6e 65 74 2f 61"
b32 = base64.b32encode(b"https://b32.example-corp.net/b").decode()
jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im9yYml0In0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
onion = "http://duskgytldkxiuqc6ad3f6b7c8d9e0f1g2h3i4j5k6l7m8n9p.onion/panel"
text = "\n".join([
    "[cfg2]",
    "HEXSPACED=" + spaced,
    "B32=" + b32,
    "JWT=" + jwt,
    "ONION=" + onion,
    "SSH=-----BEGIN OPENSSH PRIVATE KEY-----",
    "DWORD=c2_ip=0xCB00714D and ip=3405803837",
    "tail=end",
]).encode() + b"\n"
payload = text + b"SPLIT=" + b"https://split.example" + b"\x00" + b"-corp.net/x" + b"\x00" + b"\n"
with open(os.path.join(OUT, "R2-encoding-zoo.exe"), "wb") as fh:
    fh.write(base + payload)
print("R2 payload", len(payload), "b32", b32[:24] + "...")

# ---------------------------------------------------------------- R3 opcodes
def sections(buf):
    pe = struct.unpack_from("<I", buf, 0x3C)[0]
    coff = pe + 4
    count = struct.unpack_from("<H", buf, coff + 2)[0]
    optsize = struct.unpack_from("<H", buf, coff + 16)[0]
    table = coff + 20 + optsize
    out = []
    for i in range(count):
        at = table + i * 40
        name = buf[at:at + 8].rstrip(b"\x00").decode("latin1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", buf, at + 8)
        out.append((name, va, rawsize, rawptr))
    return out

r3 = bytearray(base)
text_sec = next(s for s in sections(r3) if s[0] == ".text")
name, va, rawsize, rawptr = text_sec
cave = r3.find(b"\x00" * 96, rawptr, rawptr + rawsize)
print("code cave at file", cave, "rva", hex(va + cave - rawptr))
patterns = [
    bytes.fromhex("65 48 8B 04 25 30 00 00 00"),  # mov rax, gs:[0x30]  (PEB)
    bytes.fromhex("64 A1 30 00 00 00"),          # mov eax, fs:[0x30]  (PEB, x86)
    bytes.fromhex("CD 2D"),                       # int 2d
    bytes.fromhex("0F 31"),                       # rdtsc
    bytes.fromhex("0F A2"),                       # cpuid
    bytes.fromhex("0F 01 D0"),                    # xgetbv
    bytes.fromhex("0F 01 F9"),                    # rdtscp
]
blob = b"\x90".join(patterns)
r3[cave:cave + len(blob)] = blob
with open(os.path.join(OUT, "R3-opcode-antidebug.exe"), "wb") as fh:
    fh.write(bytes(r3))
print("R3 patterns", len(patterns), "bytes", len(blob))

print("OUT", OUT)
