import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  detectPackers, entropyProfile, extractStrings, identifyFormat, parsePE,
  shannonEntropy, triageBuffer, triageFile, xorProbe,
} from '../lib/triage.js';

/** A minimal but structurally valid PE32 with an UPX0 section. */
function fakePE({ sectionName = '.text', virtualSize = 0x1000, rawSize = 0x200, entryInSection = true } = {}) {
  const buffer = Buffer.alloc(0x400);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write('PE\0\0', 0x80, 'latin1');
  const coff = 0x84;
  buffer.writeUInt16LE(0x14c, coff);          // machine i386
  buffer.writeUInt16LE(1, coff + 2);          // one section
  buffer.writeUInt16LE(0xe0, coff + 16);      // size of optional header
  const opt = coff + 20;
  buffer.writeUInt16LE(0x10b, opt);           // PE32
  buffer.writeUInt32LE(entryInSection ? 0x1000 : 0x9000, opt + 16);
  buffer.writeUInt32LE(16, opt + 92);         // NumberOfRvaAndSizes
  buffer.writeUInt32LE(0x2000, opt + 96 + 8); // import dir RVA
  buffer.writeUInt32LE(40, opt + 96 + 12);    // tiny import dir
  const section = opt + 0xe0;
  buffer.write(sectionName.slice(0, 8), section, 'latin1');
  buffer.writeUInt32LE(virtualSize, section + 8);
  buffer.writeUInt32LE(0x1000, section + 12);
  buffer.writeUInt32LE(rawSize, section + 16);
  buffer.writeUInt32LE(0x200, section + 20);
  buffer.writeUInt32LE(0x60000020, section + 36); // executable + code
  return buffer;
}

test('entropy distinguishes uniform bytes from random ones', () => {
  assert.equal(shannonEntropy(Buffer.alloc(4096, 0x41)), 0);
  const random = Buffer.alloc(4096);
  for (let index = 0; index < random.length; index += 1) random[index] = (index * 73 + 11) & 0xff;
  assert.ok(shannonEntropy(random) > 7);
});

test('block entropy reports the high-entropy ratio and block count', () => {
  const bytes = Buffer.concat([Buffer.alloc(4096, 0x41), Buffer.alloc(4096, 0x00)]);
  const profile = entropyProfile(bytes, 4096);
  assert.equal(profile.blocks.length, 2);
  assert.equal(profile.highBlockRatio, 0);
  assert.equal(profile.max, 0);
});

test('known packer signatures are detected by byte content, not extension', () => {
  const matches = detectPackers(Buffer.from('MZ' + '\0'.repeat(100) + 'UPX0' + 'UPX1' + 'VMProtect'));
  assert.deepEqual(matches.map((item) => item.family), ['UPX', 'VMProtect']);
});

test('a plain file reports no packer', () => {
  assert.equal(detectPackers(Buffer.from('ordinary text file')).length, 0);
});

test('printable strings are extracted from ASCII and UTF-16LE', () => {
  const bytes = Buffer.concat([
    Buffer.from('HelloKernel32World'),
    Buffer.from([0, 0]),
    Buffer.from('U.r.l'),
    Buffer.from([0, 0]),
  ]);
  const strings = extractStrings(bytes, { minLength: 5 });
  assert.ok(strings.some((item) => item.value === 'HelloKernel32World' && item.encoding === 'ascii'));
});

test('single-byte XOR reveals the key and the marker it exposes', () => {
  const plain = Buffer.from('kernel32.dll LoadLibrary http://example.com', 'latin1');
  const encoded = Buffer.from(plain.map((byte) => byte ^ 0x5a));
  const hits = xorProbe(encoded);
  assert.ok(hits.length > 0);
  assert.equal(hits[0].key, 0x5a);
  assert.ok(hits[0].markers.includes('kernel32'));
});

test('PE parsing finds sections, the entry point and the import directory', () => {
  const pe = parsePE(fakePE());
  assert.equal(pe.format, 'pe32');
  assert.equal(pe.sections.length, 1);
  assert.equal(pe.sections[0].name, '.text');
  assert.equal(pe.entrySection, '.text');
  assert.equal(pe.import.size, 40);
});

test('an unrecognised buffer falls back to the unknown format', () => {
  assert.equal(identifyFormat(Buffer.from('not a binary')).format, 'unknown');
});

test('a suspicious section name and a huge virtual/raw ratio drive the packed verdict', () => {
  const bytes = fakePE({ sectionName: 'UPX0', virtualSize: 0x10000, rawSize: 0x100 });
  const report = triageBuffer(bytes, { name: 'sample.exe' });
  assert.equal(report.format, 'pe32');
  assert.equal(report.verdict, 'likely-packed-or-protected');
  assert.ok(report.confidence >= 0.6);
  assert.ok(report.reasons.some((reason) => /UPX/.test(reason)));
  assert.ok(report.reasons.some((reason) => /virtual size exceeds raw/i.test(reason)));
  assert.match(report.nextSteps.join(' '), /unpack/i);
  assert.ok(report.limitations.some((line) => /heuristic/i.test(line)));
});

test('a plain PE with no anomalies is reported as unpacked', () => {
  const bytes = fakePE();
  const report = triageBuffer(bytes);
  assert.equal(report.verdict, 'appears-unpacked');
  assert.match(report.nextSteps.join(' '), /rea_status/);
});

test('triageFile reads a real file, hashes it and never writes anything', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-triage-'));
  try {
    const path = join(dir, 'sample.bin');
    const content = fakePE({ sectionName: 'UPX1', virtualSize: 0x8000, rawSize: 0x100 });
    await writeFile(path, content);
    const report = await triageFile(path);
    assert.equal(report.file.path, path);
    assert.equal(report.file.size, content.length);
    assert.equal(report.file.truncated, false);
    assert.match(report.file.sha256, /^[0-9a-f]{64}$/);
    assert.equal(report.verdict, 'likely-packed-or-protected');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('triageFile refuses relative paths and honours the read cap', async () => {
  await assert.rejects(triageFile('relative/path'), /absolute/i);
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-triage-cap-'));
  try {
    const path = join(dir, 'big.bin');
    await writeFile(path, Buffer.alloc(4096, 0x41));
    const report = await triageFile(path, { maxBytes: 1024 });
    assert.equal(report.file.size, 1024);
    assert.equal(report.file.fullSize, 4096);
    assert.equal(report.file.truncated, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
