# -*- coding: utf-8 -*-
"""Round 4 red team: build-provenance puzzles a corpus-level analyst must solve.

R4a  two droppers, same import lineage, different overlay payload  -> one imphash family
R4b  RSDS CodeView record hidden in overlay (+ a stray fake RSDS decoy)
R4c  synthetic PE with a REAL Rich header (DanS/entries/Rich/HcR?/key)
R4d  entry point beyond the raw data of its section (post-unpack OEP shape)
R4e  variant pair sharing one PDB GUID, plus incremental age, plus another GUID
R4f  managed + native mix: whoami overlay + the .NET exe -> cross pivot noise
"""
import os
import struct

OUT = os.path.join(os.environ.get("TEMP", "."), "rea-spec4")
os.makedirs(OUT, exist_ok=True)
with open(r"C:\Windows\System32\whoami.exe", "rb") as fh:
    base = fh.read()
import glob
import subprocess
hits = glob.glob(os.path.join(os.environ.get("TEMP", "."), "..", "*", "rea-spec3", "R3g-managed.exe")) \
     + glob.glob(os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp\rea-spec3\R3g-managed.exe"))
if hits:
    with open(hits[0], "rb") as fh:
        managed = fh.read()
else:
    cs_src = os.path.join(OUT, "_managed.cs")
    with open(cs_src, "w") as fh:
        fh.write('using System;\nusing System.Net;\nclass Agent{static string c2="https://dotnet.example-corp.net/gate";'
                 'static void Main(){var client=new WebClient();client.Headers.Add("X-Orbit","managed");Console.WriteLine(c2);}}\n')
    csc = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    out_exe = os.path.join(OUT, "_managed.exe")
    subprocess.run([csc, "/nologo", "/target:exe", f"/out:{out_exe}", cs_src], check=True)
    with open(out_exe, "rb") as fh:
        managed = fh.read()

def write(name, blob):
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(blob)
    print(f"{name:28s} {len(blob):>10,d}")

# R4a: same imports (whoami's), different payloads -> imphash cluster
write("R4a1-dropper-A.exe", base + b"\nvariant=A stage=https://a.example-corp.net/x\n")
write("R4a2-dropper-B.exe", base + b"\nvariant=B stage=https://b.example-corp.net/x\n")

# R4b: real-shaped RSDS record + decoy
GUID = bytes.fromhex("0123456789abcdef0123456789abcdef")  # stored mixed-endian
def rsds(guid, age, path):
    return b"RSDS" + guid + struct.pack("<I", age) + path.encode("latin1") + b"\x00"
record = rsds(bytes.fromhex("d4e3f2a1b5c94d8eaa37f1e2d3c4b5a6"), 9, r"C:\build\drop4\Release\drop4.pdb")
decoy = b"RSDS" + os.urandom(16) + b"\xff\xff\xff\xff" + b"not-a-pdb-junk\x00"
write("R4b-codeview.exe", base + b"\n" + record + decoy + b"\n")

# R4c: synthetic Rich header inside the DOS stub of whoami (rewrite bytes
#      between 0x80 and e_lfanew with a valid XOR-embedded block).
e_lfanew = struct.unpack_from("<I", base, 0x3C)[0]
key = 0x11223344
comps = [(255, 32000, 12), (255, 32000, 7), (1, 0, 1)]  # product,build,count
dans = b"\x44\x61\x6e\x53"   # 'DanS' LE
zero = b"\x00\x00\x00\x00"
def x(dword):
    return struct.pack("<I", struct.unpack("<I", dword)[0] ^ key)
block = bytearray()
block += x(dans)                                          # DanS ^ key
block += x(zero)                                          # zero ^ key
for product, build, count in comps:
    compid = (build << 16) | product
    block += x(struct.pack("<I", compid))
    block += x(struct.pack("<I", count))
block += x(b"Rich")
block += x(b"HcR?")
block += struct.pack("<I", key)                          # plain key word
stub = bytearray(base[:e_lfanew])
room = e_lfanew - 0x80
assert len(block) <= room, (len(block), room)
stub[0x80:0x80 + len(block)] = block
write("R4c-rich.exe", bytes(stub) + base[e_lfanew:])

# R4d: entry beyond raw data. Rewrite whoami's .text sizes: virtualSize huge,
#      rawSize tiny, entryRva inside the virtual gap.
mutable = bytearray(base)
pe = struct.unpack_from("<I", mutable, 0x3C)[0]
coff = pe + 4
nsec = struct.unpack_from("<H", mutable, coff + 2)[0]
opt = coff + 20
table = opt + struct.unpack_from("<H", mutable, coff + 16)[0]
first = table
# .text: VirtualSize=0x40000, keep RawSize/RawPointer; entry = VA + 0x30000
vsize, va = struct.unpack_from("<II", mutable, first + 8)
struct.pack_into("<I", mutable, first + 8, 0x40000)
struct.pack_into("<I", mutable, opt + 16, va + 0x30000)   # AddressOfEntryPoint
# also grow SizeOfImage so the VA is 'mapped'
struct.pack_into("<I", mutable, opt + 56, 0x40000 + va + 0x1000)
write("R4d-entry-gap.exe", bytes(mutable))

# R4e: three samples, one shared GUID + ages 7/8 (rebuilds), one different GUID
g1 = bytes.fromhex("aabbccddeeff00112233445566778899")
g2 = bytes.fromhex("99887766554433221100ffeeddccbbaa")
for i, (guid, age) in enumerate([(g1, 7), (g1, 8), (g2, 3)]):
    rec = rsds(guid, age, rf"C:\workers\v\build\{i}\Release\updnet.pdb" if i != 2 else r"C:\build\drop4\Release\drop4.pdb")
    write(f"R4e{i+1}-family.exe", base + b"\n" + rec + b"\n")

# R4f: managed + native together (correlate must not crash or merge wrongly)
write("R4f-managed-copy.exe", managed)
print("OUT", OUT)
