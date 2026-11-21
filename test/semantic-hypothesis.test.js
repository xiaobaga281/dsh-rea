import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { checkSemanticHypothesis, HYPOTHESIS_BOUNDARY, normalizeQuote } from '../lib/compare.js';
import { ghidraLocalReadiness, listFunctionsWithGhidra } from '../lib/ghidra-local.js';
import { parsePEImports } from '../lib/intel.js';
import { createLoopState, recordIteration } from '../lib/recon.js';
import { buildReconstructTool } from '../lib/recon-tools.js';
import { extractDeepStrings } from '../lib/strings.js';
import { readPeLayout } from '../lib/structure.js';

/**
 * Semantic attribution surface: a hypothesis = one-sentence claim + grep-able
 * decompilation evidence + a checkable prediction. The check is falsifiable:
 * every evidence quote must hit the target's own listing, and the prediction
 * must be confirmed by its channel, before the status says verified. An
 * unverified or refuted result is never a pass.
 */

// Two synthetic listing bodies covering the shapes the controls need.
const SYNTHETIC_FUNCTIONS = [
  {
    name: 'FUN_1000', rva: '0x1000', size: 64,
    body: 'undefined4 FUN_1000(longlong param_1)\n{\n  return *(undefined4 *)(*(longlong *)(param_1 + 0x10) + 0x10);\n}',
  },
  {
    name: 'FUN_2000', rva: '0x2000', size: 128,
    body: 'double FUN_2000(double *param_1)\n{\n  if (*param_1 < DAT_18029bd28) {\n    return -0.0;\n  }\n  return helper(*param_1);\n}',
  },
];

const DYNAMIC_IMPORTS = { apiFlat: ['GetTickCount', 'GetProcAddress', 'LoadLibraryW'] };
const PLAIN_IMPORTS = { apiFlat: ['CreateFileA', 'WriteFile'] };

test('calls-target: the named body contains the call -> verified, with the same-channel caveat', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h1', statement: 'FUN_2000 calls helper', functionName: 'FUN_2000',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x2000', quote: 'return helper(*param_1);' }],
    prediction: { kind: 'calls-target', value: 'helper' },
  });
  assert.equal(result.status, 'verified');
  assert.equal(result.sameChannel, true);
  assert.match(result.detail, /same-channel: hypothesis and check both derive from the target's own Ghidra decompilation/);
  assert.match(result.detail, /independent confirmation \(raw disassembly or dynamic trace\) is still open/);
  assert.equal(result.boundary, HYPOTHESIS_BOUNDARY);
});

test('calls-target: the named body has no such call -> refuted, same-channel caveat still carried', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h2', statement: 'FUN_1000 calls helper', functionName: 'FUN_1000',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x1000', quote: 'return *(undefined4 *)' }],
    prediction: { kind: 'calls-target', value: 'helper' },
  });
  assert.equal(result.status, 'refuted');
  assert.match(result.detail, /contains no call to helper/);
  assert.match(result.detail, /same-channel:/);
});

test('calls-target with no inventory stays unverified and never pretends to know', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { functions: null }, {
    id: 'h3', statement: 'FUN_2000 calls helper', functionName: 'FUN_2000',
    prediction: { kind: 'calls-target', value: 'helper' },
  });
  assert.equal(result.status, 'unverified');
  assert.match(result.detail, /cannot run/);
});

test('evidence gate: a quote the listing does not contain refutes the hypothesis', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h4', statement: 'FUN_1000 checks the PEB', functionName: 'FUN_1000',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x1000', quote: 'mov rax, gs:[0x30]' }],
    prediction: { kind: 'calls-target', value: 'helper' },
  });
  assert.equal(result.status, 'refuted');
  assert.match(result.detail, /evidence contradicts the listing/);
  // The original evidence is carried verbatim, only annotated - never rewritten.
  assert.equal(result.evidence[0].quote, 'mov rax, gs:[0x30]');
  assert.equal(result.evidence[0].hit, false);
});

test('evidence gate: a cited location outside the measured inventory is unverified', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h5', statement: 'FUN_dead does something', functionName: 'FUN_dead',
    evidence: [{ channel: 'ghidra-decompile', rva: '0xdead', quote: 'anything' }],
    prediction: { kind: 'calls-target', value: 'helper' },
  });
  assert.equal(result.status, 'unverified');
  assert.match(result.detail, /outside the measured function inventory/);
});

test('import-used: a binary-level claim is verified by the import table alone', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { imports: DYNAMIC_IMPORTS }, {
    id: 'h6', statement: 'the binary imports GetTickCount',
    prediction: { kind: 'import-used', value: 'GetTickCount' },
  });
  assert.equal(result.status, 'verified');
  assert.match(result.detail, /import table contains GetTickCount/);
});

test('import-used: a function-level hit stops at unverified - necessary, not sufficient', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { imports: DYNAMIC_IMPORTS, functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h7', statement: 'FUN_1000 calls GetTickCount', functionName: 'FUN_1000',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x1000', quote: 'return *(undefined4 *)' }],
    prediction: { kind: 'import-used', value: 'GetTickCount' },
  });
  assert.equal(result.status, 'unverified', 'an import-table hit must not verify a function-level claim');
  assert.match(result.detail, /import table contains GetTickCount — necessary, not sufficient: FUN_1000 calling it needs the calls-target channel/);
});

test('import-used: a miss is refuted when the cited body also lacks the name', () => {
  // The target imports dynamic resolvers, so the import table alone could not
  // refute - but the function's own decompilation shows no such call either.
  const result = checkSemanticHypothesis(Buffer.alloc(0), { imports: DYNAMIC_IMPORTS, functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h8', statement: 'FUN_1000 calls MessageBoxA', functionName: 'FUN_1000',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x1000', quote: 'return *(undefined4 *)' }],
    prediction: { kind: 'import-used', value: 'MessageBoxA' },
  });
  assert.equal(result.status, 'refuted');
  assert.match(result.detail, /neither the decompiled body of FUN_1000 nor the import table shows MessageBoxA/);
});

test('import-used: a binary-level miss with dynamic resolvers present stays unverified, absence recorded', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { imports: DYNAMIC_IMPORTS }, {
    id: 'h9', statement: 'the binary imports MessageBoxA',
    prediction: { kind: 'import-used', value: 'MessageBoxA' },
  });
  assert.equal(result.status, 'unverified');
  assert.match(result.detail, /import table does not contain MessageBoxA/);
  assert.match(result.detail, /GetProcAddress\/LoadLibrary-style resolvers/);
});

test('import-used: a binary-level miss with no dynamic resolvers is refuted', () => {
  const result = checkSemanticHypothesis(Buffer.alloc(0), { imports: PLAIN_IMPORTS }, {
    id: 'h10', statement: 'the binary imports MessageBoxA',
    prediction: { kind: 'import-used', value: 'MessageBoxA' },
  });
  assert.equal(result.status, 'refuted');
  assert.match(result.detail, /imports no dynamic-resolution API/);
});

test('string-literal: present in the decoded strings -> verified; absent -> refuted with the runtime caveat', () => {
  const strings = [{ value: 'https://c2.example/gate', offset: 0x400, encoding: 'ascii' }];
  const hit = checkSemanticHypothesis(Buffer.alloc(0), { strings }, {
    id: 'h11', statement: 'the binary carries the C2 URL',
    prediction: { kind: 'string-literal', value: 'https://c2.example/gate' },
  });
  assert.equal(hit.status, 'verified');
  const miss = checkSemanticHypothesis(Buffer.alloc(0), { strings }, {
    id: 'h12', statement: 'the binary carries another URL',
    prediction: { kind: 'string-literal', value: 'https://other.example/x' },
  });
  assert.equal(miss.status, 'refuted');
  assert.match(miss.detail, /constructed only at run time/);
  const noChannel = checkSemanticHypothesis(Buffer.alloc(0), { strings: null }, {
    id: 'h13', statement: 'the binary carries the C2 URL',
    prediction: { kind: 'string-literal', value: 'https://c2.example/gate' },
  });
  assert.equal(noChannel.status, 'unverified');
});

test('constant-at-rva: predicted bytes must equal the bytes at the address', () => {
  // 64 KiB fake image: .rdata at RVA 0x1000 mapped at file offset 0.
  const buffer = Buffer.alloc(0x4000);
  buffer.write('ffffffffffffdfc3', 0xd28, 'hex');
  const layout = {
    imageBase: 0x180000000, sizeOfHeaders: 0x400,
    sections: [{ name: '.rdata', virtualAddress: 0x1000, virtualSize: 0x3000, rawPointer: 0, rawSize: 0x3000 }],
  };
  const hit = checkSemanticHypothesis(buffer, { layout }, {
    id: 'h14', statement: 'DAT_180001d28 holds the -2^63 double',
    prediction: { kind: 'constant-at-rva', rva: '0x180001d28', value: 'ffffffffffffdfc3' },
  });
  assert.equal(hit.status, 'verified', hit.detail);
  assert.match(hit.detail, /bytes at 0x1d28 \(file 0xd28\) equal ffffffffffffdfc3/);
  const miss = checkSemanticHypothesis(buffer, { layout }, {
    id: 'h15', statement: 'DAT_180001d28 holds zero',
    prediction: { kind: 'constant-at-rva', rva: '0x180001d28', value: '0000000000000000' },
  });
  assert.equal(miss.status, 'refuted');
  assert.match(miss.detail, /are ffffffffffffdfc3, not the predicted 0000000000000000/);
  const unmapped = checkSemanticHypothesis(buffer, { layout }, {
    id: 'h16', statement: 'an unmapped constant',
    prediction: { kind: 'constant-at-rva', rva: '0x18000f000', value: '00' },
  });
  assert.equal(unmapped.status, 'unverified');
});

test('a hypothesis with no checkable prediction, or an unknown kind, stays unverified', () => {
  const noPrediction = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h17', statement: 'something happens', functionName: 'FUN_1000',
  });
  assert.equal(noPrediction.status, 'unverified');
  const unknown = checkSemanticHypothesis(Buffer.alloc(0), { functions: SYNTHETIC_FUNCTIONS }, {
    id: 'h18', statement: 'something happens', functionName: 'FUN_1000',
    prediction: { kind: 'loop-shape', value: 'while' },
  });
  assert.equal(unknown.status, 'unverified');
  assert.match(unknown.detail, /unknown prediction kind/);
});

// ---------------------------------------------------------------------------
// Corpus controls against the real target (cached Ghidra inventory).
// ---------------------------------------------------------------------------

const corpus = { buffer: null, context: null };

test('corpus context: sqlite3.dll channels are ready', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  corpus.buffer = await readFile(join('dist', 'corpus', 'sqlite3.dll'));
  const listed = await listFunctionsWithGhidra(join('dist', 'corpus', 'sqlite3.dll'), { maxFunctions: 200, timeoutMs: 300_000 });
  assert.equal(listed.ok, true, listed.reason ?? 'inventory failed');
  corpus.context = {
    layout: readPeLayout(corpus.buffer),
    imports: parsePEImports(corpus.buffer),
    strings: extractDeepStrings(corpus.buffer, { minLength: 4, maxStrings: 4_000 }),
    functions: listed.functions,
  };
  assert.ok(corpus.context.functions.some((fn) => fn.name === 'FUN_180009820'), 'the window holds FUN_180009820');
});

test('positive control: FUN_180009820 compares against the double constant at DAT_18029bd28 -> verified', () => {
  if (!corpus.context) return; // skipped upstream
  const result = checkSemanticHypothesis(corpus.buffer, corpus.context, {
    id: 'pos-constant', statement: 'FUN_180009820 uses the double constant stored at DAT_18029bd28 as a lower bound',
    functionName: 'FUN_180009820', rva: '0x9820',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x9820', quote: 'if (dVar1 < DAT_18029bd28) {' }],
    prediction: { kind: 'constant-at-rva', rva: '0x18029bd28', value: 'ffffffffffffdfc3' },
  });
  assert.equal(result.status, 'verified', result.detail);
  assert.match(result.detail, /equal ffffffffffffdfc3/);
});

test('positive control: FUN_180009820 calls FUN_1801352e0 -> verified through the calls-target channel', () => {
  if (!corpus.context) return;
  const result = checkSemanticHypothesis(corpus.buffer, corpus.context, {
    id: 'pos-calls', statement: 'FUN_180009820 delegates the conversion to FUN_1801352e0',
    functionName: 'FUN_180009820', rva: '0x9820',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x9820', quote: 'FUN_1801352e0(param_1[1],adStackX_8' }],
    prediction: { kind: 'calls-target', value: 'FUN_1801352e0' },
  });
  assert.equal(result.status, 'verified', result.detail);
  assert.match(result.detail, /same-channel:/);
});

test('negative control: FUN_1800096b0 does not call MessageBoxA -> refuted by body and import table', () => {
  if (!corpus.context) return;
  const evidence = [{ channel: 'ghidra-decompile', rva: '0x96b0', quote: 'return *(undefined4 *)(*(longlong *)(param_1 + 0x10) + 0x10);' }];
  const result = checkSemanticHypothesis(corpus.buffer, corpus.context, {
    id: 'neg-messagebox', statement: 'FUN_1800096b0 pops a MessageBoxA dialog',
    functionName: 'FUN_1800096b0', rva: '0x96b0',
    evidence,
    prediction: { kind: 'import-used', value: 'MessageBoxA' },
  });
  assert.equal(result.status, 'refuted', result.detail);
  assert.match(result.detail, /MessageBoxA/);
  // refuted does not rewrite evidence: the quotes come back verbatim.
  assert.deepEqual(result.evidence.map((item) => item.quote), [evidence[0].quote]);
  assert.equal(result.evidence[0].hit, true, 'the evidence itself is genuine - the prediction is what failed');
});

test('negative control: a function-level import hit on a real import stays unverified', () => {
  if (!corpus.context) return;
  assert.ok(corpus.context.imports.apiFlat.some((api) => api === 'GetTickCount'), 'precondition: sqlite3.dll imports GetTickCount');
  const result = checkSemanticHypothesis(corpus.buffer, corpus.context, {
    id: 'neg-import-hit', statement: 'FUN_1800096b0 calls GetTickCount',
    functionName: 'FUN_1800096b0', rva: '0x96b0',
    evidence: [{ channel: 'ghidra-decompile', rva: '0x96b0', quote: 'return *(undefined4 *)(*(longlong *)(param_1 + 0x10) + 0x10);' }],
    prediction: { kind: 'import-used', value: 'GetTickCount' },
  });
  assert.equal(result.status, 'unverified', 'an import-table hit must never verify a function-level claim');
  assert.match(result.detail, /necessary, not sufficient/);
});

// ---------------------------------------------------------------------------
// Loop integration: refuted hypotheses flow back as gaps; the tool actions
// record, check and persist.
// ---------------------------------------------------------------------------

test('a refuted hypothesis flows back as a hypothesis-refuted gap in the next iteration', () => {
  const state = createLoopState({ targetPath: 't', targetSha256: 'ab'.repeat(32), targetSize: 1, budget: 3 });
  state.hypotheses = [{
    id: 'neg-messagebox', statement: 'FUN_1800096b0 pops a MessageBoxA dialog',
    status: 'refuted', detail: 'neither the decompiled body of FUN_1800096b0 nor the import table shows MessageBoxA',
  }];
  recordIteration(state, {
    build: { ok: true, code: 'built' },
    compare: {
      overall: 0.5,
      tiers: {
        t1: { status: 'empty', score: null },
        t2: { status: 'blocked', reason: 'engine off' },
        t3: { status: 'skipped', score: null, unmatched: [] },
      },
      weightsUsed: {},
    },
  });
  const gaps = state.iterations[0].gaps;
  const gap = gaps.find((item) => item.id === 'hypothesis-refuted');
  assert.ok(gap, 'the refuted hypothesis must appear as a gap');
  assert.equal(gap.tier, 'T4');
  assert.match(gap.detail, /neg-messagebox/);
  assert.match(gap.detail, /MessageBoxA/);
  assert.equal(gap.confirm, 'rea_reconstruct action=hypothesis-check');
  // A recorded-but-unchecked or verified hypothesis is not a gap.
  state.hypotheses.push({ id: 'ok', statement: 'fine', status: 'verified', detail: 'x' });
  recordIteration(state, {
    build: { ok: true, code: 'built' },
    compare: { overall: 0.5, tiers: { t1: { status: 'empty', score: null }, t2: { status: 'blocked', reason: 'x' }, t3: { status: 'skipped', score: null, unmatched: [] } }, weightsUsed: {} },
  });
  assert.equal(state.iterations[1].gaps.filter((item) => item.id === 'hypothesis-refuted').length, 1);
});

test('rea_reconstruct hypothesis-record / hypothesis-check persist and decide', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-hypothesis-'));
  try {
    const store = {
      statePath: async (name) => join(dir, name),
      writeState: async (name, content) => {
        const path = join(dir, name);
        await writeFile(path, content, 'utf8');
        return path;
      },
    };
    const tool = buildReconstructTool({ store });
    // The tool enforces absolute target paths; resolve() also gives this test
    // its own cache key, so it pays one cold sqlite3 analysis of its own.
    const target = resolve('dist', 'corpus', 'sqlite3.dll');
    await tool.execute({ action: 'start', target });
    const recorded = await tool.execute({
      action: 'hypothesis-record', target,
      hypothesis: {
        id: 'neg-messagebox', statement: 'FUN_1800096b0 pops a MessageBoxA dialog', functionName: 'FUN_1800096b0',
        evidence: [{ channel: 'ghidra-decompile', rva: '0x96b0', quote: 'return *(undefined4 *)' }],
        prediction: { kind: 'import-used', value: 'MessageBoxA' },
      },
    });
    assert.match(recorded.text, /recorded hypothesis "neg-messagebox" \(function-level, status recorded\)/);
    const checked = await tool.execute({ action: 'hypothesis-check', target, hypothesisId: 'neg-messagebox' });
    assert.match(checked.text, /hypothesis "neg-messagebox" \[function\] -> refuted/);
    assert.match(checked.text, /boundary: status=verified means/);
    // The state file carries the decision for the next iteration's gap build.
    const files = await readdir(dir);
    const stateFile = files.find((name) => name.startsWith('reconstruct-'));
    const state = JSON.parse(await readFile(join(dir, stateFile), 'utf8'));
    const entry = state.hypotheses.find((item) => item.id === 'neg-messagebox');
    assert.equal(entry.status, 'refuted');
    assert.equal(entry.result.evidence[0].quote, 'return *(undefined4 *)');
    // An unknown hypothesisId is refused, not invented.
    const missing = await tool.execute({ action: 'hypothesis-check', target, hypothesisId: 'no-such-id' });
    assert.match(missing.text, /no recorded hypothesis with id "no-such-id"/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// W4: the M1 batch hypothesis files (dist/m1-hypotheses-*.json, generated by
// dist/m1-hypotheses.mjs from the cached inventories). These tests pin the
// file contract and re-decide every verdict against the cached-inventory
// context — the same channels the gate builds, without running Ghidra.
// ---------------------------------------------------------------------------

const M1_SQLITE3 = [
  'FUN_1800013f2', 'FUN_180002545', 'FUN_180008510', 'FUN_180008640',
  'FUN_180008750', 'FUN_180008870', 'FUN_1800089d0', 'FUN_180008f30',
  'FUN_180009070', 'FUN_1800090e0', 'FUN_1800091a0', 'FUN_180009290',
  'FUN_1800096b0', 'FUN_1800096c0', 'FUN_1800096e0', 'FUN_180009740',
  'FUN_180009750', 'FUN_1800097f0', 'FUN_180009820', 'FUN_1800099a0',
  'FUN_180009e80', 'FUN_18000a1e0', 'FUN_18000a8f0', 'FUN_18000ab70',
  'FUN_18000ada0', 'FUN_18000bfd0',
];
const M1_7ZR = ['FUN_00401000', 'FUN_004010ac', 'FUN_0040116f', 'FUN_00401207', 'FUN_0040125a', 'FUN_00401519'];
// The six M1 functions whose bodies offer no testable channel (no string, no
// DAT reference, no call shape): 3-79 byte stubs, getters and flag checks.
const M1_NO_TESTABLE = ['FUN_1800013f2', 'FUN_180002545', 'FUN_1800096b0', 'FUN_1800096c0', 'FUN_180009740', 'FUN_1800099a0'];
const W4_NEGATIVE_IDS = ['neg-sqlite3-messagebox', 'neg-sqlite3-bogus-call', 'neg-7zr-messagebox', 'neg-7zr-bogus-call'];

const W4_FILES = [
  { label: 'sqlite3', path: 'dist/m1-hypotheses-sqlite3.json', cachePrefix: '1ddedeef', corpus: 'dist/corpus/sqlite3.dll', functions: M1_SQLITE3 },
  // 7zr uses the cap-48 window (16bd7722…), the one the batch-2 gate loads.
  { label: '7zr', path: 'dist/m1-hypotheses-7zr.json', cachePrefix: '16bd7722', corpus: 'dist/corpus/7zr.exe', functions: M1_7ZR },
];

const loadCacheByPrefix = (prefix) => {
  const dir = join('ghidra-work', 'cache', 'function-lists', 'v3');
  if (!existsSync(dir)) return null;
  const name = readdirSync(dir).find((file) => file.startsWith(prefix));
  return name ? JSON.parse(readFileSync(join(dir, name), 'utf8')) : null;
};

test('W4 hypothesis files: unique ids, checkable predictions, evidence quotes verbatim in the cached bodies', async (t) => {
  const loaded = [];
  for (const file of W4_FILES) {
    if (!existsSync(file.path)) {
      t.skip(`${file.path} not present (run node dist/m1-hypotheses.mjs first)`);
      return;
    }
    const cache = loadCacheByPrefix(file.cachePrefix);
    if (!cache) {
      t.skip(`no cached function inventory with prefix ${file.cachePrefix}`);
      return;
    }
    loaded.push({ ...file, cache, hypotheses: JSON.parse(readFileSync(file.path, 'utf8')) });
  }
  for (const { label, cache, hypotheses, functions } of loaded) {
    const ids = hypotheses.map((hypothesis) => hypothesis.id);
    assert.equal(new Set(ids).size, ids.length, `${label}: hypothesis ids must be unique`);
    const positives = hypotheses.filter((hypothesis) => !hypothesis.id.startsWith('neg-'));
    const covered = new Set(positives.map((hypothesis) => hypothesis.functionName));
    for (const name of functions) {
      if (M1_NO_TESTABLE.includes(name)) {
        assert.equal(covered.has(name), false, `${label}: ${name} is pinned no-testable and must carry no hypothesis`);
      } else {
        assert.ok(covered.has(name), `${label}: ${name} must carry at least one hypothesis`);
      }
    }
    for (const hypothesis of positives) {
      assert.ok(
        ['string-literal', 'constant-at-rva', 'import-used', 'calls-target'].includes(hypothesis.prediction?.kind),
        `${label}: ${hypothesis.id} needs a known prediction kind`,
      );
      assert.ok(String(hypothesis.prediction?.value ?? '').length > 0, `${label}: ${hypothesis.id} needs a prediction value`);
      const fn = cache.functions.find((item) => item.name === hypothesis.functionName);
      assert.ok(fn, `${label}: ${hypothesis.id} cites a function inside the cached window`);
      assert.equal(hypothesis.rva, fn.rva, `${label}: ${hypothesis.id} rva matches the inventory`);
      assert.ok((hypothesis.evidence ?? []).length > 0, `${label}: ${hypothesis.id} carries evidence`);
      for (const evidence of hypothesis.evidence ?? []) {
        const hit = normalizeQuote(fn.body).includes(normalizeQuote(evidence.quote));
        assert.equal(hit, true, `${label}: ${hypothesis.id} quote must appear verbatim in the cached body of ${fn.name}`);
      }
    }
    for (const hypothesis of hypotheses.filter((item) => item.id.startsWith('neg-'))) {
      assert.ok(W4_NEGATIVE_IDS.includes(hypothesis.id), `${label}: ${hypothesis.id} is one of the pinned negative controls`);
    }
  }
});

test('W4 verdicts reproduce against the cached-inventory context: 41 verified positives, 4 refuted negatives', async (t) => {
  const loaded = [];
  for (const file of W4_FILES) {
    if (!existsSync(file.path) || !existsSync(file.corpus)) {
      t.skip(`${file.path} or ${file.corpus} not present`);
      return;
    }
    const cache = loadCacheByPrefix(file.cachePrefix);
    if (!cache) {
      t.skip(`no cached function inventory with prefix ${file.cachePrefix}`);
      return;
    }
    const buffer = readFileSync(file.corpus);
    loaded.push({
      hypotheses: JSON.parse(readFileSync(file.path, 'utf8')),
      buffer,
      context: {
        layout: readPeLayout(buffer),
        imports: parsePEImports(buffer),
        strings: extractDeepStrings(buffer, { minLength: 4, maxStrings: 4_000 }),
        functions: cache.functions,
      },
    });
  }
  let verified = 0;
  let refuted = 0;
  for (const { hypotheses, buffer, context } of loaded) {
    for (const hypothesis of hypotheses) {
      const result = checkSemanticHypothesis(buffer, context, hypothesis);
      if (hypothesis.id.startsWith('neg-')) {
        assert.equal(result.status, 'refuted', `${hypothesis.id} is a negative control and must refute: ${result.detail}`);
        refuted += 1;
      } else {
        assert.equal(result.status, 'verified', `${hypothesis.id} must verify: ${result.detail}`);
        if (hypothesis.prediction.kind === 'calls-target') {
          assert.equal(result.sameChannel, true, `${hypothesis.id}: the same-channel caveat must travel with a calls-target verified`);
        }
        verified += 1;
      }
    }
  }
  assert.equal(verified, 41, 'every positive W4 hypothesis verifies against the cached context');
  assert.equal(refuted, 4, 'every pinned negative control refutes');
});

test('W4 coverage fold: fixed 32-function denominator, negatives counted separately', async (t) => {
  const mod = await import('../dist/m1-coverage.mjs').catch(() => null);
  if (!mod) {
    t.skip('dist/m1-coverage.mjs is not present');
    return;
  }
  const records = [
    { target: 'dist/corpus/sqlite3.dll', hypotheses: [
      { id: 'FUN_180008750-dat', prediction: { kind: 'constant-at-rva' }, status: 'verified', sameChannel: false },
      { id: 'FUN_180008750-call', prediction: { kind: 'calls-target' }, status: 'verified', sameChannel: true },
      { id: 'FUN_1800096b0-call', prediction: { kind: 'calls-target' }, status: 'refuted', sameChannel: true },
      { id: 'neg-sqlite3-messagebox', prediction: { kind: 'import-used' }, status: 'refuted' },
    ] },
    // A second run of the same target: identical hypothesis ids must fold into
    // one entry each, and the target may be spelled with another prefix.
    { target: 'elsewhere/dist/corpus/sqlite3.dll', hypotheses: [
      { id: 'FUN_180008750-dat', prediction: { kind: 'constant-at-rva' }, status: 'verified' },
    ] },
  ];
  const { totals, perFunction } = mod.computeM1Coverage(records);
  assert.equal(totals.functions, 32, 'the denominator is the fixed M1 set');
  const withHypotheses = perFunction.filter((entry) => entry.hypotheses.length > 0);
  assert.equal(withHypotheses.length, 2);
  const f750 = perFunction.find((entry) => entry.name === 'FUN_180008750');
  assert.equal(f750.status, 'verified');
  assert.equal(f750.hypotheses.length, 2, 'duplicate ids across records fold into one');
  const f96b0 = perFunction.find((entry) => entry.name === 'FUN_1800096b0');
  assert.equal(f96b0.status, 'refuted', 'a function whose only hypothesis was refuted counts as refuted, not verified');
  const missing = perFunction.find((entry) => entry.name === 'FUN_1800013f2');
  assert.equal(missing.status, 'no-testable-hypothesis', 'a function without a hypothesis stays in the denominator as unverified');
  assert.equal(totals.verified, 1);
  assert.equal(totals.refuted, 1);
  assert.equal(totals.unverified, 30);
  assert.equal(totals.withHypotheses, 2);
  assert.equal(totals.negativeControls, 1, 'each distinct negative control is counted once');
  assert.equal(totals.negativeRefuted, 1);
  assert.equal(totals.sameChannelVerified, 1);
});
