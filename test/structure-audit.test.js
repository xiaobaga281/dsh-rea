import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { extractIocs, parsePEImports } from '../lib/intel.js';
import { planNextSteps } from '../lib/plan.js';
import { createResultIndex } from '../lib/result-index.js';
import { triageBuffer } from '../lib/triage.js';
import { buildQueryResultsTool } from '../lib/workflow-tools.js';

/**
 * One PE with two sections whose virtual ranges overlap: the first section
 * claims a grown VirtualSize that swallows the second, which is the R4d
 * malformed-PE shape. The import directory lives in the second section, so a
 * translation that stops at the first "range hit" can never find it.
 */
function overlappingSectionsPE() {
  const b = Buffer.alloc(0x800);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(2, 0x86);
  b.writeUInt16LE(0xe0, 0x94);
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt32LE(16, opt + 92);
  const dd = opt + 96;
  b.writeUInt32LE(0x3000, dd + 8);
  b.writeUInt32LE(0x40, dd + 12);
  const table = opt + 0xe0;
  // .text: raw 0x200..0x2ff but a virtual size that swallows .rdata at 0x3000.
  b.write('.text\0\0\0', table, 'latin1');
  b.writeUInt32LE(0x30000, table + 8);
  b.writeUInt32LE(0x1000, table + 12);
  b.writeUInt32LE(0x100, table + 16);
  b.writeUInt32LE(0x200, table + 20);
  // .rdata: the real home of the import directory at RVA 0x3000 (file 0x400).
  b.write('.rdata\0\0', table + 40, 'latin1');
  b.writeUInt32LE(0x400, table + 48);
  b.writeUInt32LE(0x3000, table + 52);
  b.writeUInt32LE(0x400, table + 56);
  b.writeUInt32LE(0x400, table + 60);
  // IMAGE_IMPORT_DESCRIPTOR: thunks 0x3080, name 0x30c0, FirstThunk 0x3080.
  b.writeUInt32LE(0x3080, 0x400);
  b.writeUInt32LE(0x30c0, 0x40c);
  b.writeUInt32LE(0x3080, 0x410);
  // Thunk array at 0x3080 (file 0x480) -> hint/name at 0x30e0 (file 0x4e0).
  b.writeUInt32LE(0x30e0, 0x480);
  b.write('KERNEL32.dll\0', 0x4c0, 'latin1');
  b.writeUInt16LE(0, 0x4e0);
  b.write('CreateFileA\0', 0x4e2, 'latin1');
  return b;
}

test('the import parse resolves through an overlapping section, not around it', () => {
  const parsed = parsePEImports(overlappingSectionsPE());
  assert.equal(parsed.empty, false);
  assert.equal(parsed.dlls[0].name, 'KERNEL32.dll');
  assert.ok(parsed.dlls[0].functions.includes('CreateFileA'));
});

test('a file with no recognised format gets an explicit verdict, not appears-unpacked', () => {
  const empty = triageBuffer(Buffer.alloc(0), { name: 'empty.bin' });
  assert.equal(empty.verdict, 'unrecognized-format');
  assert.match(empty.reasons.join(' '), /empty/);
  assert.match(empty.nextSteps.join(' '), /not a recognised/);
  assert.doesNotMatch(empty.nextSteps.join(' '), /locate the OEP/);

  const junk = triageBuffer(Buffer.from('just some text, no header at all'), { name: 'junk.txt' });
  assert.equal(junk.verdict, 'unrecognized-format');
  assert.match(junk.reasons.join(' '), /no PE, ELF, Mach-O/);
});

test('a user-agent keeps everything up to its cap instead of stopping at the first space', () => {
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 orbit/3.0';
  const iocs = extractIocs([{ value: ua, offset: 0, encoding: 'ascii' }]);
  const found = iocs.find((item) => item.type === 'useragent');
  assert.ok(found, 'useragent was not extracted');
  assert.match(found.value, /orbit\/3\.0/);
});

test('a sampled window is described as a window, not as the whole file', () => {
  const steps = planNextSteps({
    unresolved: [{
      start: 0, end: 524288, rva: 0x2000,
      sampled: true, windowBytes: 524288, fileBytes: 16 * 1024 * 1024, windows: 32,
    }],
    structure: null,
  });
  const step = steps.find((item) => /breakpoint|Break on/i.test(item.action));
  assert.ok(step, 'no unresolved-region experiment was produced');
  assert.match(step.action, /high-entropy window/);
  assert.match(step.why, /window 1 of 32/);
  assert.match(step.why, /remaining windows have not been examined/);
});

test('query results render the evidence ids and confidence the index holds', async () => {
  const base = await mkdtemp(join(tmpdir(), 'dsh-rea-index-'));
  try {
    const index = createResultIndex({ base });
    await index.record({
      at: new Date().toISOString(),
      tool: 'mcp__rea__inspect_analysis_view',
      hasStructured: true,
      resultChars: 120,
      evidenceIds: ['ev-abc123'],
      evidenceCount: 1,
      confidence: 0.8,
    });
    const tool = buildQueryResultsTool(index);
    const answer = await tool.execute({});
    assert.match(answer.text, /confidence=0\.8/);
    assert.match(answer.text, /ev-abc123/);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
