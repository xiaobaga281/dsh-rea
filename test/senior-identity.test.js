/**
 * Build provenance: the identity facts that link samples to each other.
 *
 * These are the senior-report capabilities - imphash lineage, CodeView build
 * identity, the Rich toolchain stamp, entry-point placement, and the overlap
 * fallback that keeps a grown VirtualSize from swallowing later sections.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, copyFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { entryAnomalies, imphashFromImports, peTimeStamp, recoverCodeView, richHeader } from '../lib/static/identity.js';
import { buildCorrelateSamplesTool } from '../lib/surface/analysis-tools.js';
import { rvaToOffset } from '../lib/static/structure.js';

// ------------------------------------------------------------------ helpers --
function pe({ sections = [], entryRva = 0x1000, imports = null } = {}) {
  const headerSize = 0x200;
  // raw data starts past the headers block (pe + 24 + 0xf0 optional + tables),
  // otherwise the first section's bytes overwrite the 'PE' signature.
  let nextVa = 0x1000;
  let nextRaw = 0x500;
  const table = [];
  const blobs = [];
  for (const section of sections) {
    const data = Buffer.isBuffer(section.data) ? section.data : Buffer.from(section.data ?? '', 'latin1');
    table.push({
      name: section.name, virtualSize: section.virtual ?? data.length, virtualAddress: nextVa,
      rawSize: data.length, rawPointer: nextRaw, characteristics: section.characteristics ?? 0xE0000040,
    });
    blobs.push(data);
    nextVa += (section.vaSpan ?? Math.max(data.length, 0x200) + 0xFFF & ~0xFFF);
    nextRaw += Math.max(data.length, 1);
  }
  const size = nextRaw + Math.max(...blobs.map((b) => b.length), 0);
  const bytes = Buffer.alloc(Math.max(size + 0x200, 0x900));
  bytes.write('MZ', 0, 'latin1');
  bytes.writeUInt32LE(headerSize, 0x3c);
  bytes.write('PE\0\0', headerSize, 'latin1');
  bytes.writeUInt16LE(table.length, headerSize + 6);
  bytes.writeUInt32LE(0x4c000000, headerSize + 8);
  bytes.writeUInt16LE(0xf0, headerSize + 20);
  const opt = headerSize + 24;
  bytes.writeUInt16LE(0x20b, opt);
  bytes.writeUInt32LE(entryRva, opt + 16);
  bytes.writeUInt32LE(0x400000, opt + 24);
  bytes.writeUInt32LE(16, opt + 108);
  if (imports) {
    bytes.writeUInt32LE(imports.rva, opt + 112 + 8);
    bytes.writeUInt32LE(imports.size ?? 40, opt + 112 + 12);
  }
  const tableAt = opt + 0xf0;
  table.forEach((section, index) => {
    const at = tableAt + index * 40;
    bytes.write(section.name.padEnd(8, '\0').slice(0, 8), at, 'latin1');
    bytes.writeUInt32LE(section.virtualSize, at + 8);
    bytes.writeUInt32LE(section.virtualAddress, at + 12);
    bytes.writeUInt32LE(section.rawSize, at + 16);
    bytes.writeUInt32LE(section.rawPointer, at + 20);
    bytes.writeUInt32LE(section.characteristics, at + 36);
  });
  table.forEach((section, index) => blobs[index].length > 0 && blobs[index].copy(bytes, section.rawPointer));
  return bytes;
}

const rsds = (guidHex, age, path) => {
  const ageBytes = Buffer.alloc(4);
  ageBytes.writeUInt32LE(age);
  return Buffer.concat([
    Buffer.from('RSDS', 'latin1'),
    Buffer.from(guidHex, 'hex'),
    ageBytes,
    Buffer.from(`${path}\0`, 'latin1'),
  ]);
};

// ------------------------------------------------------------------ imphash --
test('imphash is stable across payload changes and sensitive to import changes', () => {
  const importsA = { dlls: [{ name: 'KERNEL32.dll', functions: ['Sleep', 'GetLastError', '#12'] }, { name: 'USER32.DLL', functions: ['MessageBoxA'] }] };
  const importsB = { dlls: [{ name: 'kernel32.dll', functions: ['Sleep', 'GetLastError', '#12'] }, { name: 'user32.dll', functions: ['MessageBoxA'] }] };
  assert.equal(imphashFromImports(importsA), imphashFromImports(importsB), 'dll case and extension must normalise');
  const changed = { dlls: [{ ...importsA.dlls[0], functions: ['GetLastError', 'Sleep', '#12'] }] };
  assert.notEqual(imphashFromImports(changed), imphashFromImports(importsA), 'import order is part of the hash');
  assert.equal(imphashFromImports({ dlls: [], truncated: false }), null);
  assert.equal(imphashFromImports({ dlls: importsA.dlls, truncated: true }), null, 'a truncated table must not fake a family hash');
});

// ----------------------------------------------------------------- codeview --
test('CodeView record parses with the MSVC mixed-endian GUID', () => {
  const buffer = Buffer.concat([Buffer.alloc(64), rsds('d4e3f2a1b5c94d8eaa37f1e2d3c4b5a6', 9, 'C:\\build\\drop\\Release\\drop.pdb')]);
  const found = recoverCodeView(buffer);
  assert.equal(found.length, 1);
  assert.equal(found[0].guid, 'a1f2e3d4-c9b5-8e4d-aa37f1e2d3c4b5a6');
  assert.equal(found[0].age, 9);
  assert.equal(found[0].path, 'C:\\build\\drop\\Release\\drop.pdb');
});

test('a stray RSDS without a .pdb record is not evidence', () => {
  const junk = Buffer.concat([Buffer.alloc(16), Buffer.from('RSDS', 'latin1'), Buffer.alloc(16, 0x41), Buffer.from([0xff, 0xff, 0xff, 0xff]), Buffer.from('random-data\x00', 'latin1')]);
  assert.deepEqual(recoverCodeView(junk), []);
});

// --------------------------------------------------------------------- rich --
function craftRich(comps, key = 0x11223344) {
  const u32 = (value) => { const b = Buffer.alloc(4); b.writeUInt32LE(value >>> 0); return b; };
  const x = (dword) => u32(dword ^ key);
  const parts = [x(0x536e6144), x(0)];
  for (const [product, build, count] of comps) parts.push(x((build << 16) | product), x(count));
  parts.push(x(0x68636952), x(0x3f526348), u32(key));
  return Buffer.concat(parts);
}

test('the Rich header round-trips and rejects a random stub', () => {
  const body = Buffer.alloc(0x400);
  const block = craftRich([[255, 32000, 12], [1, 0, 1]]);
  const bytes = pe({ sections: [{ name: '.text', data: body }], entryRva: 0x1000 });
  block.copy(bytes, 0x80);
  const rich = richHeader(bytes);
  assert.ok(rich, 'crafted Rich must be found');
  assert.deepEqual(rich.entries.map((e) => [e.product, e.build, e.count]), [[255, 32000, 12], [1, 0, 1]]);
  assert.equal(richHeader(pe({ sections: [{ name: '.text', data: body }] })), null);
});

// -------------------------------------------------------------- entry shape --
test('an entry beyond the raw data is flagged, a normal entry is not', () => {
  const gap = pe({
    sections: [{ name: '.text', data: Buffer.alloc(0x100), virtual: 0x40000, vaSpan: 0x40000, characteristics: 0x60000020 }],
    entryRva: 0x31000,
  });
  const layout = { sections: [{
    name: '.text', virtualAddress: 0x1000, virtualSize: 0x40000, rawPointer: 0x200, rawSize: 0x100, executable: true,
  }], entryRva: 0x31000 };
  assert.ok(entryAnomalies(layout).some((text) => /past the raw data/.test(text)));
  assert.deepEqual(entryAnomalies({ sections: [{ name: '.text', virtualAddress: 0x1000, virtualSize: 0x200, rawPointer: 0x200, rawSize: 0x200, executable: true }], entryRva: 0x1010 }), []);
  assert.ok(entryAnomalies({ sections: [{ name: '.rsrc', virtualAddress: 0x1000, virtualSize: 0x200, rawPointer: 0x200, rawSize: 0x200, executable: true }], entryRva: 0x1010 }).some((text) => /not \.text/.test(text)));
});

// --------------------------------------------------------------- overlap bug --
test('a grown VirtualSize does not swallow a later section', () => {
  const bytes = pe({
    sections: [
      { name: '.text', data: Buffer.alloc(0x100), virtual: 0x40000, vaSpan: 0x40000, characteristics: 0x60000020 },
      { name: '.rdata', data: Buffer.from('IMPORTTABLE', 'latin1'), vaSpan: 0x1000 },
    ],
  });
  const layout = {
    sections: [
      { name: '.text', virtualAddress: 0x1000, virtualSize: 0x40000, rawPointer: 0x200, rawSize: 0x100 },
      { name: '.rdata', virtualAddress: 0x41000, virtualSize: 0xB, rawPointer: 0x300, rawSize: 0xB },
    ],
    sizeOfHeaders: 0x200,
  };
  const at = rvaToOffset(layout, 0x41002);
  assert.equal(at, 0x302, 'must resolve inside .rdata even when .text claims the range');
});

// ---------------------------------------------------------------- timestamp --
test('a future timestamp is annotated, not asserted as a build date', () => {
  const bytes = pe({ sections: [{ name: '.text', data: Buffer.alloc(4) }] });
  bytes.writeUInt32LE(0xD6B86F51, bytes.readUInt32LE(0x3c) + 8); // 2084
  const stamp = peTimeStamp(bytes);
  assert.equal(stamp.raw, 0xD6B86F51);
  assert.match(stamp.note, /future/);
});

// ----------------------------------------------------------------- tool e2e --
test('rea_correlate_samples clusters a corpus by imphash and PDB GUID', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rea-corr-'));
  const shared = rsds('00112233445566778899aabbccddeeff', 7, 'C:\\b\\fam.pdb');
  const twin = rsds('00112233445566778899aabbccddeeff', 8, 'C:\\b\\fam.pdb');
  const other = rsds('ffeeddccbbaa99887766554433221100', 3, 'C:\\b\\other.pdb');
  const base = Buffer.from('MZ');
  const variants = [
    ['a.exe', Buffer.concat([base, shared, Buffer.from('variant-a')])],
    ['b.exe', Buffer.concat([base, twin, Buffer.from('variant-b')])],
    ['c.exe', Buffer.concat([base, other, Buffer.from('variant-c')])],
  ];
  for (const [name, blob] of variants) writeFileSync(join(dir, name), blob);
  const tool = buildCorrelateSamplesTool({ maxBytes: 1024 * 1024, limit: 10, store: null });
  const { text } = await tool.execute({ directory: dir });
  assert.match(text, /CodeView PDB GUID: 1 cluster\(s\)/);
  assert.match(text, /a\.exe, b\.exe/);
  assert.doesNotMatch(text.split('CodeView PDB GUID')[1].split('\n\n')[0], /c\.exe/, 'a different GUID must not join the family');
});
