/**
 * The local structural probe exists so that "no engine installed" stops
 * turning a correct plan into an unscored one. It must still be able to fail:
 * a probe that always succeeds is a free point, not a check.
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildProbeAddressTool } from '../lib/analysis-tools.js';
import { describeVerdict, probeAddress } from '../lib/probe.js';
import { planNextSteps } from '../lib/plan.js';
import { scoreRow } from '../scripts/duel/score.mjs';
import { buildGeneration } from '../scripts/duel/defender.mjs';

const d6 = buildGeneration('D6').buffer;
const IMAGE_BASE = 0x400000;
/** TLS callback: reached through a data pointer, lives in .text. */
const TLS_RVA = 0x9800;
/** Dispatcher table: an array of code pointers in .rdata. */
const TABLE_RVA = 0x1048;

test('a TLS callback address is executable code', () => {
  const result = probeAddress(d6, { address: IMAGE_BASE + TLS_RVA, kind: 'code' });
  assert.equal(result.ok, true);
  assert.equal(result.rva, TLS_RVA);
  assert.equal(result.executable, true);
  assert.equal(result.section, '.text');
  assert.equal(result.verdict, 'code');
});

test('a dispatcher entry is a pointer into executable code', () => {
  const result = probeAddress(d6, { address: TABLE_RVA, kind: 'pointer' });
  assert.equal(result.ok, true);
  assert.equal(result.executable, false, 'the table itself lives in .rdata');
  assert.equal(result.pointer.targetExecutable, true);
  assert.equal(result.verdict, 'pointer');
});

test('the same address fails when the plan claims the wrong kind', () => {
  // A table of pointers in .rdata is not code. If a report said it was, the
  // probe has to say so - otherwise the dimension is decorative.
  const asCode = probeAddress(d6, { address: IMAGE_BASE + TABLE_RVA, kind: 'code' });
  assert.equal(asCode.verdict, 'not-executable');
  assert.match(describeVerdict(asCode), /\.rdata, which is not executable/);
});

test('a dword that points nowhere executable fails the pointer claim', () => {
  const result = probeAddress(d6, { address: IMAGE_BASE + 0x20, kind: 'pointer' });
  assert.equal(result.ok, true);
  assert.equal(result.verdict, 'not-a-code-pointer');
  assert.match(describeVerdict(result), /does not point into an executable section/);
});

test('an unmapped RVA is reported, not guessed', () => {
  const result = probeAddress(d6, { address: 0x900000, kind: 'code' });
  assert.equal(result.ok, true);
  assert.equal(result.verdict, 'unmapped');
  assert.match(describeVerdict(result), /not mapped to file bytes/);
});

test('a VA and its RVA resolve to the same place', () => {
  const va = probeAddress(d6, { address: IMAGE_BASE + TLS_RVA, kind: 'code' });
  const rva = probeAddress(d6, { address: TLS_RVA, kind: 'code' });
  assert.equal(va.rva, rva.rva);
  assert.equal(va.section, rva.section);
});

test('non-PE input is refused instead of decoded', () => {
  const result = probeAddress(Buffer.from('not a pe file'), { address: 0x1000 });
  assert.equal(result.ok, false);
  assert.equal(result.verdict, 'unsupported');
});

test('the tool prints a verdict a script can act on', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-probe-'));
  const file = join(dir, 'd6.exe');
  await writeFile(file, d6);
  try {
    const tool = buildProbeAddressTool();
    const good = await tool.execute({ path: file, address: `0x${(IMAGE_BASE + TLS_RVA).toString(16)}`, kind: 'code' });
    assert.match(good.text, /verdict: code/);
    assert.match(good.text, /section: \.text \| executable: yes/);
    const bad = await tool.execute({ path: file, address: `0x${(IMAGE_BASE + TABLE_RVA).toString(16)}`, kind: 'code' });
    assert.match(bad.text, /verdict: not-executable/);
    const relative = await tool.execute({ path: 'd6.exe', address: '0x409800' });
    assert.match(relative.text, /absolute path/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// -------------------------------------------------------------------- plan --

const structure = {
  imageBase: IMAGE_BASE,
  entryRva: 0x9100,
  importsPresent: false,
  tls: { present: true, callbacks: [{ rva: TLS_RVA, section: '.text' }] },
  dispatchTables: [{ rva: TABLE_RVA, entries: 24, section: '.rdata', confidence: 'low' }],
  hashedApis: null,
};

test('an unavailable engine downgrades the probe instead of dropping it', () => {
  const plan = planNextSteps({
    structure,
    unresolved: [],
    providers: { providers: { ghidra: { ready: false, reason: 'Ghidra 的 JVM 无法创建 tmp/<user>-ghidra' } } },
  });
  const tls = plan.find((entry) => entry.action.includes('TLS callback'));
  assert.equal(tls.probe.tool, 'probe_address');
  assert.equal(tls.probe.tier, 'local');
  assert.equal(tls.probe.kind, 'code');
  assert.equal(tls.probe.rva, TLS_RVA);
  assert.equal(tls.probe.blockedFrom, 'ghidra');
  assert.match(tls.blocked, /tmp\/<user>-ghidra/);

  const table = plan.find((entry) => entry.action.includes('indirect jump'));
  assert.equal(table.probe.kind, 'pointer', 'a table entry must stay a pointer claim');
});

test('a ready engine keeps the engine probe', () => {
  const plan = planNextSteps({
    structure,
    unresolved: [],
    providers: { providers: { ghidra: { ready: true, reason: null } } },
  });
  const tls = plan.find((entry) => entry.action.includes('TLS callback'));
  assert.equal(tls.probe.tool, 'inspect_address_context');
  assert.equal(tls.probe.tier, 'engine');
  assert.equal(tls.probe.kind, 'code');
});

// ------------------------------------------------------------------- score --

const ceiling = {
  endpoints: ['e1'], iocText: ['i1'], tracking: ['t1'], anti: ['a1'],
  watermarks: ['w1'], api: ['api1'], behavior: ['b1'],
};

const perfect = (overrides = {}) => ({
  id: 'D1',
  endpoints: ['e1'], iocText: ['i1'], trackingIds: ['t1'], antiTechniques: ['a1'],
  watermarks: ['w1'], apiHits: ['api1'], behaviorHits: ['b1'],
  noise: [], sealed: [], planOk: true, unresolved: true, unrecoverable: true,
  probe: null,
  ...overrides,
});

test('a local verdict scores, an engine run still needs a name', () => {
  const local = scoreRow(perfect({ probe: { tier: 'local', ok: true, verdict: 'code', name: null } }), ceiling);
  assert.equal(local.recall.verify, 1);

  const engineNamed = scoreRow(perfect({ probe: { tier: 'engine', ok: true, name: 'tls_callback_0' } }), ceiling);
  assert.equal(engineNamed.recall.verify, 1);

  // An engine that answered "available" without a name has not confirmed the
  // claim the plan made, and must not score like one that did.
  const engineAnonymous = scoreRow(perfect({ probe: { tier: 'engine', ok: true, name: null } }), ceiling);
  assert.equal(engineAnonymous.recall.verify, 0);

  const failed = scoreRow(perfect({ probe: { tier: 'local', ok: false, verdict: 'not-executable', name: null } }), ceiling);
  assert.equal(failed.recall.verify, 0);

  const absent = scoreRow(perfect({ probe: null }), ceiling);
  assert.equal(absent.recall.verify, null);
});
