import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildReadiness } from '../lib/build.js';
import { ghidraLocalReadiness } from '../lib/ghidra-local.js';

/**
 * Function-level restoration gate, pinned end to end.
 *
 * The gate's Ghidra inventory cache keys on the exact path string it is handed
 * (lib/ghidra-local.js listCachePath), so every run below passes the same
 * relative strings from the package root: an absolute path is a different
 * cache key and would pay a full cold analysis of the sqlite3 cap-200 window,
 * which the ProbeAddress list budget can truncate. Exit codes are read from
 * spawnSync's status, not from a pipe, because `| tail` reports the tail's
 * status and would swallow a failing gate.
 *
 * The gate itself appends one machine-readable JSON line per run to
 * dist/restore-gates.jsonl (scripts/recon-restore.mjs --record); each test
 * reads the last line and pins its own verdict there too, so the structured
 * record a validator aligns against cannot silently drift from what ran.
 */

const pkgRoot = fileURLToPath(new URL('..', import.meta.url));
const gateRecords = join(pkgRoot, 'dist', 'restore-gates.jsonl');

// Nine restored bodies: the six pinned by the first review plus the decompiled
// FUN_180009750 / FUN_180009820 / FUN_1800099a0. Draft: test/fixtures/sqlite3-restored.c.
const SQLITE3_FUNCTIONS = [
  'FUN_1800096b0', 'FUN_1800096c0', 'FUN_1800096e0', 'FUN_180009070',
  'FUN_180009740', 'FUN_1800097f0', 'FUN_180009750', 'FUN_180009820',
  'FUN_1800099a0',
].join(',');

// The gate runs are serial within this file, so the last record line is the
// one this test just produced.
function lastGateRecord() {
  const lines = readFileSync(gateRecords, 'utf8').trim().split(/\r?\n/).filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

function runGate(args) {
  return spawnSync(process.execPath, ['scripts/recon-restore.mjs', ...args], {
    cwd: pkgRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 300_000,
  });
}

test('restore gate: nine decompiled sqlite3 functions pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const run = runGate([
    'dist/corpus/sqlite3.dll',
    '--functions', SQLITE3_FUNCTIONS,
    '--draft', 'test/fixtures/sqlite3-restored.c',
    '--threshold', '0.75',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /9\/9 functions/);
  assert.match(run.stdout, /coverage 100\.0%/);
  assert.match(run.stdout, /below threshold 0/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/sqlite3.dll');
  assert.equal(record.metric, 'semantic');
  assert.equal(record.threshold, 0.75);
  assert.equal(record.exit, 0);
  assert.equal(record.result.matched, 9);
  assert.equal(record.result.belowThreshold, 0);
});

test('restore gate: the same nine functions fail a text review at 99% (negative control)', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  // Same function list, same draft: pseudocode-level text similarity of an
  // honest hand-written draft stays far below 99%, so every function must be
  // reported below threshold and the gate must refuse.
  const run = runGate([
    'dist/corpus/sqlite3.dll',
    '--functions', SQLITE3_FUNCTIONS,
    '--draft', 'test/fixtures/sqlite3-restored.c',
    '--metric', 'text',
    '--threshold', '0.99',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 1, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(text, threshold 99%\): ran/);
  assert.match(run.stdout, /9\/9 functions/);
  assert.match(run.stdout, /below threshold 9/);
  const record = lastGateRecord();
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 9);
});

test('restore gate: two decompiled 7zr functions pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  // --max-functions 24 is required: there is no cap-200 inventory cached for
  // 7zr.exe, and the relative path string is what hits the cap-24 cache.
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', 'FUN_00401207,FUN_00401519',
    '--draft', 'test/fixtures/7zr-restored.c',
    '--metric', 'semantic',
    '--threshold', '0.75',
    '--max-functions', '24',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /2\/2 functions/);
  assert.match(run.stdout, /below threshold 0/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'semantic');
  assert.equal(record.exit, 0);
  assert.equal(record.result.matched, 2);
  assert.equal(record.result.belowThreshold, 0);
});

test('restore gate: the same two 7zr functions fail a text review at 99% (negative control)', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  // Mirror of the sqlite3 negative control: the honest 32-bit-derived draft
  // scores far below 99% on pseudocode text, so the gate must refuse with
  // every requested function reported below threshold.
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', 'FUN_00401207,FUN_00401519',
    '--draft', 'test/fixtures/7zr-restored.c',
    '--metric', 'text',
    '--threshold', '0.99',
    '--max-functions', '24',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 1, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(text, threshold 99%\): ran/);
  assert.match(run.stdout, /2\/2 functions/);
  assert.match(run.stdout, /below threshold 2/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 2);
});

// Batch 2 (stratified sample, dist/m1-sample.mjs): seventeen more sqlite3
// functions covering switch-heavy, loop+write and the small/mid/large size
// tiers. Draft: test/fixtures/sqlite3-restored-b2.c. Same review floor as the
// first nine.
const SQLITE3_B2_FUNCTIONS = [
  'FUN_1800013f2', 'FUN_180002545', 'FUN_180008510', 'FUN_180008640',
  'FUN_180008750', 'FUN_180008870', 'FUN_1800089d0', 'FUN_180008f30',
  'FUN_1800090e0', 'FUN_1800091a0', 'FUN_180009290', 'FUN_180009e80',
  'FUN_18000a1e0', 'FUN_18000a8f0', 'FUN_18000ab70', 'FUN_18000ada0',
  'FUN_18000bfd0',
].join(',');

// Batch 2 for 7zr.exe: the window's hard register-variable shapes
// (unaff_EBP, extraout_ECX/EDX, the ExceptionList SEH slot). Draft:
// test/fixtures/7zr-restored-b2.c.
const Z7R_B2_FUNCTIONS = 'FUN_00401000,FUN_004010ac,FUN_0040116f,FUN_0040125a';

test('restore gate: seventeen stratified sqlite3 functions pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const run = runGate([
    'dist/corpus/sqlite3.dll',
    '--functions', SQLITE3_B2_FUNCTIONS,
    '--draft', 'test/fixtures/sqlite3-restored-b2.c',
    '--threshold', '0.75',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /17\/17 functions/);
  assert.match(run.stdout, /coverage 100\.0%/);
  assert.match(run.stdout, /below threshold 0/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/sqlite3.dll');
  assert.equal(record.metric, 'semantic');
  assert.equal(record.threshold, 0.75);
  assert.equal(record.exit, 0);
  assert.equal(record.result.matched, 17);
  assert.equal(record.result.belowThreshold, 0);
});

test('restore gate: the seventeen stratified sqlite3 functions fail a text review at 99% (negative control)', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const run = runGate([
    'dist/corpus/sqlite3.dll',
    '--functions', SQLITE3_B2_FUNCTIONS,
    '--draft', 'test/fixtures/sqlite3-restored-b2.c',
    '--metric', 'text',
    '--threshold', '0.99',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 1, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(text, threshold 99%\): ran/);
  assert.match(run.stdout, /17\/17 functions/);
  assert.match(run.stdout, /below threshold 17/);
  const record = lastGateRecord();
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 17);
});

test('restore gate: four stratified 7zr functions (register/SEH shapes) pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  // --max-functions 48: the rebuild carries ~30 CRT/startup functions before
  // the batch functions, so the first batch's cap of 24 would drop them from
  // the rebuilt inventory ("no counterpart"). 48 covers both sides; the 7zr
  // target inventory is cached at this cap by the batch-1 gate runs.
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', Z7R_B2_FUNCTIONS,
    '--draft', 'test/fixtures/7zr-restored-b2.c',
    '--metric', 'semantic',
    '--threshold', '0.75',
    '--max-functions', '48',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /4\/4 functions/);
  assert.match(run.stdout, /below threshold 0/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'semantic');
  assert.equal(record.threshold, 0.75);
  assert.equal(record.exit, 0);
  assert.equal(record.result.matched, 4);
  assert.equal(record.result.belowThreshold, 0);
});

test('restore gate: the four stratified 7zr functions fail a text review at 99% (negative control)', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', Z7R_B2_FUNCTIONS,
    '--draft', 'test/fixtures/7zr-restored-b2.c',
    '--metric', 'text',
    '--threshold', '0.99',
    '--max-functions', '48',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 1, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(text, threshold 99%\): ran/);
  assert.match(run.stdout, /4\/4 functions/);
  assert.match(run.stdout, /below threshold 4/);
  const record = lastGateRecord();
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 4);
});

// ---------------------------------------------------------------------------
// W4: the M1 semantic-attribution batch. Hypotheses ride along with the gate
// additively (scripts/recon-restore.mjs): the T2 verdict alone decides the
// exit code, and the per-hypothesis checks are appended to the JSONL record.
// The hypothesis files are generated by dist/m1-hypotheses.mjs from the cached
// inventories; the sqlite3 file carries 34 positive hypotheses + 2 negative
// controls, the 7zr file 7 + 2.
// ---------------------------------------------------------------------------

test('restore gate: W4 hypotheses ride along with the sqlite3 batch-1 review, exit code stays T2-only', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  if (!existsSync(join(pkgRoot, 'dist', 'm1-hypotheses-sqlite3.json'))) {
    t.skip('W4 hypothesis file not generated yet (node dist/m1-hypotheses.mjs)');
    return;
  }
  const run = runGate([
    'dist/corpus/sqlite3.dll',
    '--functions', SQLITE3_FUNCTIONS,
    '--draft', 'test/fixtures/sqlite3-restored.c',
    '--threshold', '0.75',
    '--hypotheses', 'dist/m1-hypotheses-sqlite3.json',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /9\/9 functions/);
  const record = lastGateRecord();
  assert.equal(record.exit, 0, 'the T2 verdict alone decides the exit code');
  assert.equal(record.hypotheses.length, 36);
  const statuses = {};
  for (const hypothesis of record.hypotheses) {
    statuses[hypothesis.status] = (statuses[hypothesis.status] ?? 0) + 1;
    if (hypothesis.id.startsWith('neg-')) {
      assert.equal(hypothesis.status, 'refuted', `${hypothesis.id} is a negative control and must refute`);
    } else {
      assert.equal(hypothesis.status, 'verified', `${hypothesis.id} must verify: ${hypothesis.detail}`);
    }
  }
  assert.equal(statuses.verified, 34);
  assert.equal(statuses.refuted, 2, 'exactly the two negative controls refute');
});

test('restore gate: W4 hypotheses ride along with the 7zr batch-1 review, exit code stays T2-only', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  if (!existsSync(join(pkgRoot, 'dist', 'm1-hypotheses-7zr.json'))) {
    t.skip('W4 hypothesis file not generated yet (node dist/m1-hypotheses.mjs)');
    return;
  }
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', 'FUN_00401207,FUN_00401519',
    '--draft', 'test/fixtures/7zr-restored.c',
    '--metric', 'semantic',
    '--threshold', '0.75',
    '--max-functions', '24',
    '--hypotheses', 'dist/m1-hypotheses-7zr.json',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /2\/2 functions/);
  const record = lastGateRecord();
  assert.equal(record.exit, 0, 'the T2 verdict alone decides the exit code');
  assert.equal(record.hypotheses.length, 9);
  const statuses = {};
  for (const hypothesis of record.hypotheses) {
    statuses[hypothesis.status] = (statuses[hypothesis.status] ?? 0) + 1;
    if (hypothesis.id.startsWith('neg-')) {
      assert.equal(hypothesis.status, 'refuted', `${hypothesis.id} is a negative control and must refute`);
    } else {
      assert.equal(hypothesis.status, 'verified', `${hypothesis.id} must verify: ${hypothesis.detail}`);
    }
  }
  assert.equal(statuses.verified, 7);
  assert.equal(statuses.refuted, 2, 'exactly the two negative controls refute');
});

test('the al-khaser adversarial corpus keeps its closed-loop evidence: gate records and inputs stay in place', () => {
  // The first function-level loop against a REAL adversarial binary (official
  // al-khaser v1.1.0 x64 release). Read-only pin: the corpus, the draft and
  // both gate outcomes must stay reachable, so the evidence chain in
  // docs/reconstruction-plan.md §13 cannot silently rot.
  const exe = join('dist', 'corpus-adv', 'al-khaser_x64.exe');
  const draft = join('test', 'fixtures', 'al-khaser-restored.c');
  assert.equal(existsSync(exe), true, 'the al-khaser corpus binary is missing');
  assert.equal(existsSync(draft), true, 'the al-khaser restoration draft is missing');

  const lines = readFileSync(join('dist', 'restore-gates.jsonl'), 'utf8')
    .split(/\r?\n/).filter((line) => line.includes('al-khaser') || line.includes('7zr-ultra') || line.includes('sqlite3.dll'))
    .map((line) => JSON.parse(line));
  const latest = (predicate) => [...lines].reverse().find(predicate);
  // The trio record: the first closed loop on the real adversarial binary.
  const trio = latest((record) => record.metric === 'semantic' && record.requested.length === 3);
  assert.ok(trio, 'no 3-function semantic gate record for al-khaser');
  assert.equal(trio.threshold, 0.75);
  assert.equal(trio.exit, 0, 'the 3-function review must pass the 0.75 floor');
  assert.ok(trio.result.score >= 0.85, `semantic score regressed: ${trio.result.score}`);
  assert.equal(trio.result.belowThreshold, 0);
  // The 5-function record: TLS callback + CRT string teardown added.
  const five = latest((record) => record.metric === 'semantic' && record.requested.length === 5);
  assert.ok(five, 'no 5-function semantic gate record for al-khaser');
  assert.equal(five.exit, 0, 'the 5-function review must pass the 0.75 floor');
  assert.ok(five.result.score >= 0.85, `5-function score regressed: ${five.result.score}`);
  assert.equal(five.result.matched, 5);
  assert.equal(five.result.belowThreshold, 0);
  // The packed variant: ultra-brute pack -> static unpack -> 4/4 restore.
  const ultra = latest((record) => record.metric === 'semantic' && String(record.target).includes('7zr-ultra-unpacked'));
  assert.ok(ultra, 'no gate record for the unpacked ultra-brute image');
  assert.equal(ultra.exit, 0);
  assert.equal(ultra.result.matched, 4);
  assert.ok(ultra.result.score >= 0.99, `ultra-brute unpack score: ${ultra.result.score}`);
  // Negative controls keep discriminating on both al-khaser sets.
  const negatives = lines.filter((record) => record.metric === 'text' && record.exit === 1);
  assert.ok(negatives.length >= 2, 'both al-khaser negative controls must be recorded');
  for (const neg of negatives) {
    assert.equal(neg.threshold, 0.99);
    assert.equal(neg.result.belowThreshold, neg.result.functions);
  }
  // Export-surface record: sqlite3 requested BY EXPORT NAME through the
  // overlay (plan §13 residual #8 closed) - 2/2 at the 0.75 floor, negative
  // control discriminating.
  const exportPositive = latest((record) => record.metric === 'semantic'
    && String(record.target).includes('sqlite3.dll')
    && Array.isArray(record.requested) && record.requested.includes('sqlite3_value_int'));
  assert.ok(exportPositive, 'no export-name gate record for sqlite3');
  assert.equal(exportPositive.exit, 0);
  assert.equal(exportPositive.result.matched, 2);
  assert.ok(exportPositive.result.score >= 0.95, `export-name score: ${exportPositive.result.score}`);
  const exportNegative = lines.filter((record) => record.metric === 'text'
    && String(record.target).includes('sqlite3.dll')
    && Array.isArray(record.requested) && record.requested.includes('sqlite3_value_int'));
  assert.ok(exportNegative.some((record) => record.exit === 1), 'the export-name negative control must be recorded');
});
