/**
 * Explicit real-corpus restoration suite: positive semantic gates, negative
 * text controls, W4 hypothesis riders and fresh-record binding. It is separate
 * from the default suite because it starts Ghidra and compiles real drafts.
 *
 * @module dsh-rea-restore/scripts/recon/restore-real
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildReadiness } from '../../lib/restore/build.js';
import { ghidraLocalReadiness } from '../../lib/restore/ghidra-local.js';

/**
 * Function-level restoration gate, pinned end to end.
 *
 * The gate's Ghidra inventory cache keys on target content and inventory
 * configuration. These tests keep stable relative target strings so records
 * remain easy to align with the reviewed corpus paths. Exit codes are read from
 * spawnSync's status, not from a pipe, because `| tail` reports the tail's
 * status and would swallow a failing gate.
 *
 * The gate itself appends one machine-readable JSON line per run to
 * dist/restore-gates.jsonl (scripts/recon/restore.mjs --record); each test
 * reads the last line and pins its own verdict there too, so the structured
 * record a validator aligns against cannot silently drift from what ran.
 */

const pkgRoot = fileURLToPath(new URL('../..', import.meta.url));
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
function readGateRecords() {
  if (!existsSync(gateRecords)) return [];
  return readFileSync(gateRecords, 'utf8').trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function runGate(args) {
  const previousRecordCount = readGateRecords().length;
  const startedAt = new Date().toISOString();
  const run = spawnSync(process.execPath, ['scripts/recon/restore.mjs', ...args, '--max-functions', '200'], {
    cwd: pkgRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 1_800_000,
  });
  const records = readGateRecords();
  run.startedAt = startedAt;
  run.finishedAt = new Date().toISOString();
  run.previousRecordCount = previousRecordCount;
  run.recordCount = records.length;
  run.record = records.length === previousRecordCount + 1 ? records[records.length - 1] : null;
  return run;
}

function recordForRun(run) {
  assert.equal(run.recordCount, run.previousRecordCount + 1, 'the gate must append exactly one new record');
  assert.ok(run.record, 'the gate record for this run is missing');
  const record = run.record;
  const digestFile = (path) => createHash('sha256').update(readFileSync(resolve(pkgRoot, path))).digest('hex');
  assert.equal(record.schemaVersion, 2, 'fresh gate evidence must use schema v2');
  assert.match(record.recordedAt ?? '', /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(record.recordedAt >= run.startedAt && record.recordedAt <= run.finishedAt, 'the gate record must belong to this run');
  assert.match(record.targetSha256 ?? '', /^[a-f0-9]{64}$/i, 'targetSha256 must be bound');
  assert.match(record.sourceSha256 ?? '', /^[a-f0-9]{64}$/i, 'sourceSha256 must be bound');
  assert.equal(record.targetSha256, digestFile(record.target), 'targetSha256 must match the reviewed target bytes');
  assert.equal(record.sourceSha256, digestFile(record.draftPath), 'sourceSha256 must match the reviewed draft bytes');
  assert.ok(Array.isArray(record.gateFailures), 'fresh gate evidence must carry gate failures');
  if (record.exit === 0) {
    assert.match(record.rebuiltSha256 ?? '', /^[a-f0-9]{64}$/i, 'a fresh pass must bind the rebuilt bytes');
    assert.equal(record.rebuiltSha256, digestFile(record.rebuiltPath), 'rebuiltSha256 must match the reviewed rebuilt bytes');
    assert.deepEqual(record.gateFailures, [], 'a fresh pass must have no gate failures');
  }
  return record;
}

function identityBoundPass(record, target, draftPath) {
  try {
    return record?.schemaVersion === 2 && record.exit === 0
      && record.targetSha256 === createHash('sha256').update(readFileSync(target)).digest('hex')
      && record.sourceSha256 === createHash('sha256').update(readFileSync(draftPath)).digest('hex')
      && record.rebuiltSha256 === createHash('sha256').update(readFileSync(record.rebuiltPath)).digest('hex')
      && Array.isArray(record.gateFailures) && record.gateFailures.length === 0;
  } catch {
    return false;
  }
}

test('a gate assertion cannot reuse a record from an earlier run', () => {
  assert.doesNotMatch(readFileSync(fileURLToPath(import.meta.url), 'utf8'), /\bconst identityBoundPass\b/, 'historical checks must not shadow the shared digest verifier');
  assert.throws(() => recordForRun({ previousRecordCount: 4, recordCount: 4, record: null }), /exactly one new record/);
  assert.throws(() => recordForRun({ previousRecordCount: 4, recordCount: 5, record: null }), /record for this run is missing/);
  const digest = (path) => createHash('sha256').update(readFileSync(resolve(pkgRoot, path))).digest('hex');
  const base = {
    previousRecordCount: 4, recordCount: 5,
    startedAt: '2026-11-24T00:00:00.000Z', finishedAt: '2026-11-24T00:01:00.000Z',
    record: {
      schemaVersion: 2, recordedAt: '2026-11-24T00:00:30.000Z', exit: 0,
      target: 'package.json', draftPath: 'index.js', rebuiltPath: 'client.js',
      targetSha256: digest('package.json'), sourceSha256: digest('index.js'), rebuiltSha256: digest('client.js'), gateFailures: [],
    },
  };
  assert.equal(recordForRun(base).exit, 0);
  assert.equal(identityBoundPass(base.record, 'package.json', 'index.js'), true);
  assert.equal(identityBoundPass({ ...base.record, rebuiltSha256: 'c'.repeat(64) }, 'package.json', 'index.js'), false);
  assert.equal(identityBoundPass({ ...base.record, rebuiltPath: 'missing.exe' }, 'package.json', 'index.js'), false);
  for (const [field, value, pattern] of [
    ['schemaVersion', 1, /schema v2/],
    ['recordedAt', '2026-11-23T23:59:59.000Z', /belong to this run/],
    ['targetSha256', 'a'.repeat(64), /target bytes/],
    ['sourceSha256', undefined, /sourceSha256|targetSha256/],
    ['sourceSha256', 'b'.repeat(64), /draft bytes/],
    ['rebuiltSha256', undefined, /rebuilt bytes/],
    ['rebuiltSha256', 'c'.repeat(64), /rebuilt bytes/],
    ['gateFailures', ['old failure'], /no gate failures/],
  ]) {
    const record = { ...base.record, [field]: value };
    assert.throws(() => recordForRun({ ...base, record }), pattern, field);
  }
});

test('restore gate: nine decompiled sqlite3 functions pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
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
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 9);
});

test('restore gate: two decompiled 7zr functions pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
    return;
  }
  // All pages are aggregated; the shared 200-function page size reuses the
  // complete inventory rather than treating a small window as full coverage.
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', 'FUN_00401207,FUN_00401519',
    '--draft', 'test/fixtures/7zr-restored.c',
    '--metric', 'semantic',
    '--threshold', '0.75',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(semantic, threshold 75%\): ran/);
  assert.match(run.stdout, /2\/2 functions/);
  assert.match(run.stdout, /below threshold 0/);
  const record = recordForRun(run);
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'semantic');
  assert.equal(record.exit, 0);
  assert.equal(record.result.matched, 2);
  assert.equal(record.result.belowThreshold, 0);
});

test('restore gate: the same two 7zr functions fail a text review at 99% (negative control)', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 1, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /T2 \(text, threshold 99%\): ran/);
  assert.match(run.stdout, /2\/2 functions/);
  assert.match(run.stdout, /below threshold 2/);
  const record = recordForRun(run);
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
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
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
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 17);
});

test('restore gate: four stratified 7zr functions (register/SEH shapes) pass the semantic review floor', async (t) => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
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
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
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
  const record = recordForRun(run);
  assert.equal(record.target, 'dist/corpus/7zr.exe');
  assert.equal(record.metric, 'text');
  assert.equal(record.threshold, 0.99);
  assert.equal(record.exit, 1);
  assert.equal(record.result.belowThreshold, 4);
});

// ---------------------------------------------------------------------------
// W4: the M1 semantic-attribution batch. Hypotheses ride along with the gate
// additively (scripts/recon/restore.mjs): the T2 verdict alone decides the
// exit code, and the per-hypothesis checks are appended to the JSONL record.
// The hypothesis files are generated by dist/m1-hypotheses.mjs from the cached
// inventories; the sqlite3 file carries 34 positive hypotheses + 2 negative
// controls, the 7zr file 7 + 2.
// ---------------------------------------------------------------------------

test('restore gate: W4 hypotheses ride along with the sqlite3 batch-1 review, exit code stays T2-only', async () => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
    return;
  }
  if (!existsSync(join(pkgRoot, 'dist', 'm1-hypotheses-sqlite3.json'))) {
    assert.fail('W4 sqlite3 hypothesis file is missing; generate it with node dist/m1-hypotheses.mjs');
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
  const record = recordForRun(run);
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

test('restore gate: W4 hypotheses ride along with the 7zr batch-1 review, exit code stays T2-only', async () => {
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    assert.fail(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    assert.fail(`no build engine (${builder.reason})`);
    return;
  }
  if (!existsSync(join(pkgRoot, 'dist', 'm1-hypotheses-7zr.json'))) {
    assert.fail('W4 7zr hypothesis file is missing; generate it with node dist/m1-hypotheses.mjs');
    return;
  }
  const run = runGate([
    'dist/corpus/7zr.exe',
    '--functions', 'FUN_00401207,FUN_00401519',
    '--draft', 'test/fixtures/7zr-restored.c',
    '--metric', 'semantic',
    '--threshold', '0.75',
    '--hypotheses', 'dist/m1-hypotheses-7zr.json',
  ]);
  assert.equal(run.error, undefined, `the gate run was interrupted: ${run.error}`);
  assert.equal(run.status, 0, `exit ${run.status}\nstdout tail: ${run.stdout?.slice(-800)}\nstderr tail: ${run.stderr?.slice(-800)}`);
  assert.match(run.stdout, /2\/2 functions/);
  const record = recordForRun(run);
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

test('the al-khaser legacy evidence stays selectable by exact case identity', () => {
  // These records predate SHA fields. They remain historical pins, never fresh
  // pass evidence; any record that carries identity fields must match today's bytes.
  const exe = join('dist', 'corpus-adv', 'al-khaser_x64.exe');
  const draft = join('test', 'fixtures', 'al-khaser-restored.c');
  assert.equal(existsSync(exe), true, 'the al-khaser corpus binary is missing');
  assert.equal(existsSync(draft), true, 'the al-khaser restoration draft is missing');

  const lines = readFileSync(join('dist', 'restore-gates.jsonl'), 'utf8')
    .split(/\r?\n/).filter(Boolean)
    .map((line) => JSON.parse(line));
  const latest = (predicate) => [...lines].reverse().find(predicate);
  const matches = (record, target, draftPath, requested, metric, threshold) => {
    const pathKey = (value) => String(value ?? '').replace(/\\/g, '/');
    if (!record || pathKey(record.target) !== pathKey(target) || record.metric !== metric || record.threshold !== threshold) return false;
    if (JSON.stringify(record.requested) !== JSON.stringify(requested)) return false;
    if (record.draftPath !== undefined && pathKey(record.draftPath) !== pathKey(draftPath)) return false;
    if (record.targetSha256 !== undefined && record.targetSha256 !== createHash('sha256').update(readFileSync(target)).digest('hex')) return false;
    if (record.sourceSha256 !== undefined && record.sourceSha256 !== createHash('sha256').update(readFileSync(draftPath)).digest('hex')) return false;
    return true;
  };
  const trioNames = ['FUN_140018a14', 'FUN_1400184ec', 'FUN_1400187f0'];
  const fiveNames = [...trioNames, 'tls_callback_0', 'FUN_14000a210'];
  const trio = latest((record) => matches(record, exe, draft, trioNames, 'semantic', 0.75));
  assert.ok(trio, 'no exact 3-function semantic gate record for al-khaser');
  const five = latest((record) => matches(record, exe, draft, fiveNames, 'semantic', 0.75));
  assert.ok(five, 'no exact 5-function semantic gate record for al-khaser');
  for (const [record, label] of [[trio, '3-function'], [five, '5-function']]) {
    if (identityBoundPass(record, exe, draft)) {
      assert.equal(record.exit, 0);
      assert.ok(record.result.score >= 0.85, `${label} semantic score regressed: ${record.result.score}`);
      assert.equal(record.result.belowThreshold, 0);
      if (label === '5-function') assert.equal(record.result.matched, 5);
    } else {
      assert.equal(record.schemaVersion, undefined, `${label} legacy pin must not masquerade as fresh identity-bound evidence`);
    }
  }
  const ultraTarget = join('dist', 'corpus-adv', '7zr-ultra-unpacked.exe');
  const ultraNames = ['FUN_00401000', 'FUN_004010ac', 'FUN_0040116f', 'FUN_0040125a'];
  const ultra = latest((record) => matches(record, ultraTarget, join('test', 'fixtures', '7zr-restored-b2.c'), ultraNames, 'semantic', 0.75));
  assert.ok(ultra, 'no exact gate record for the unpacked ultra-brute image');
  if (identityBoundPass(ultra, ultraTarget, join('test', 'fixtures', '7zr-restored-b2.c'))) {
    assert.equal(ultra.exit, 0);
    assert.equal(ultra.result.matched, 4);
    assert.ok(ultra.result.score >= 0.99, `ultra-brute unpack score: ${ultra.result.score}`);
  } else {
    assert.equal(ultra.schemaVersion, undefined, 'the ultra-brute legacy pin is historical only');
  }
  const negatives = [
    ...lines.filter((record) => matches(record, exe, draft, trioNames, 'text', 0.99)),
    ...lines.filter((record) => matches(record, exe, draft, fiveNames, 'text', 0.99)),
  ];
  assert.equal(negatives.length, 2, 'both exact al-khaser negative controls must be recorded');
  for (const neg of negatives) {
    assert.equal(neg.exit, 1);
    assert.equal(neg.result.belowThreshold, neg.result.functions);
  }
  const sqliteTarget = join('dist', 'corpus', 'sqlite3.dll');
  const exportNames = ['sqlite3_value_int', 'sqlite3_stricmp'];
  const exportDraft = join('test', 'fixtures', 'sqlite3-exports-restored.c');
  const exportPositive = latest((record) => matches(record, sqliteTarget, exportDraft, exportNames, 'semantic', 0.75));
  assert.ok(exportPositive, 'no exact export-name gate record for sqlite3');
  if (identityBoundPass(exportPositive, sqliteTarget, exportDraft)) {
    assert.equal(exportPositive.exit, 0);
    assert.equal(exportPositive.result.matched, 2);
    assert.ok(exportPositive.result.score >= 0.95, `export-name score: ${exportPositive.result.score}`);
  } else {
    assert.equal(exportPositive.schemaVersion, undefined, 'the export-name legacy pin is historical only');
  }
  const exportNegative = lines.filter((record) => matches(record, sqliteTarget, exportDraft, exportNames, 'text', 0.99));
  assert.ok(exportNegative.some((record) => record.exit === 1), 'the exact export-name negative control must be recorded');
});
