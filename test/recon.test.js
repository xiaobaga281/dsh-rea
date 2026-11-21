import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createArtifactStore } from '../lib/artifacts.js';
import { buildReadiness, compileC } from '../lib/build.js';
import { ghidraLocalReadiness } from '../lib/ghidra-local.js';
import { createLoopState, gapsFromComparison, rankDecoderCandidates, recordIteration, renderHandoff, CONVERGENCE } from '../lib/recon.js';
import { buildReconstructTool } from '../lib/recon-tools.js';
import { TIERS, tierSource, generateSpecimen } from '../scripts/recon/specimen.mjs';

function fakeCompare({ overall = 1, missing = [], added = [], unmatched = [], t2 = 'ran', t2Score = 1, mismatches = [] } = {}) {
  return {
    overall,
    tiers: {
      t1: {
        status: 'ran',
        score: overall,
        imports: { recall: missing.length === 0 ? 1 : 0.5, precision: added.length === 0 ? 1 : 0.5, missing, added },
        strings: { recall: 1 },
        sections: { jaccard: 1 },
      },
      t2: { status: t2, score: t2 === 'ran' ? t2Score : null, reason: t2 === 'ran' ? null : 'Ghidra is not ready', ...(mismatches.length > 0 ? { mismatches } : {}) },
      t3: { status: unmatched.length > 0 ? 'ran' : 'ran', score: unmatched.length > 0 ? 0.5 : 1, unmatched },
    },
    weightsUsed: { t1: 0.55, t2: 0.3, t3: 0.15 },
  };
}

function fakeStore(dir) {
  return {
    async statePath(name) {
      await mkdir(dir, { recursive: true });
      return join(dir, name);
    },
    async writeState(name, body) {
      await mkdir(dir, { recursive: true });
      const path = join(dir, name);
      await writeFile(path, body, 'utf8');
      return path;
    },
    async write(name, body) {
      await mkdir(dir, { recursive: true });
      const path = join(dir, name);
      await writeFile(path, body, 'utf8');
      return path;
    },
  };
}

test('a loop state clamps its budget and names the sealed intake', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, unresolvedRegions: 2, budget: 99 });
  assert.equal(state.budget, 20);
  assert.match(state.intake.note, /sealed values/);
  assert.equal(state.status, 'running');
});

test('gaps name what would settle them, and a blocked tier is a gap with a reason', () => {
  const gaps = gapsFromComparison(fakeCompare({ overall: 0.4, missing: ['getcomputernamea'], added: ['writeprocessmemory'], unmatched: ['https://x'], t2: 'blocked' }));
  const ids = gaps.map((gap) => gap.id);
  assert.ok(ids.includes('imports-missing'));
  assert.ok(ids.includes('imports-added'));
  assert.ok(ids.includes('literals-unmatched'));
  assert.ok(ids.includes('t2-blocked'));
  for (const gap of gaps) {
    assert.ok(gap.action.length > 0);
    if (gap.id !== 't2-blocked') assert.ok(gap.confirm, `${gap.id} has no confirmation path`);
  }
});

test('the loop converges only when the tiers agree, and an empty measurement blocks', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'b'.repeat(64), targetSize: 10, budget: 2 });
  recordIteration(state, { build: { ok: true }, compare: fakeCompare({ overall: CONVERGENCE }) });
  assert.equal(state.status, 'converged');

  const empty = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'c'.repeat(64), targetSize: 10, budget: 2 });
  recordIteration(empty, { build: { ok: true }, compare: { ...fakeCompare(), overall: null } });
  assert.equal(empty.status, 'blocked');
  assert.match(empty.reason, /no measurable tier/);

  const weak = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'd'.repeat(64), targetSize: 10, budget: 1 });
  recordIteration(weak, { build: { ok: true }, compare: fakeCompare({ overall: 0.99, missing: ['a'] }) });
  assert.equal(weak.status, 'budget-exhausted');
});

test('a spent budget with sealed regions and unmatched literals ends unreachable, not exhausted', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'e'.repeat(64), targetSize: 10, unresolvedRegions: 1, budget: 1 });
  recordIteration(state, { build: { ok: true }, compare: fakeCompare({ overall: 0.8, unmatched: ['secret'] }) });
  assert.equal(state.status, 'unreachable');
  assert.match(state.reason, /dynamic plan/);
});

test('every tier template produces compilable-shaped C and a truth record', () => {
  for (const tier of TIERS) {
    const built = tierSource(tier);
    if (tier === 'R5') {
      // The GUI tier enters through WinMain, not main, and carries the
      // interaction truth measured on its compiled artifact (not asserted by
      // hand): four window messages, the button id, the timer and the wndproc.
      assert.match(built.source, /int WINAPI WinMain\(/);
      assert.match(built.source, /WndProc/);
      assert.match(built.source, /case WM_COMMAND:/);
      assert.match(built.source, /SetTimer/);
      assert.match(built.source, /\(HMENU\)0x65/);
      assert.deepEqual(built.interaction.messages, ['msg:0x1', 'msg:0x2', 'msg:0x111', 'msg:0x113']);
      assert.deepEqual(built.interaction.controls, ['ctl:0x65', 'timer:0x1']);
      assert.deepEqual(built.interaction.windows, ['win:class-register', 'win:create', 'win:wndproc=WndProc']);
      assert.deepEqual(built.interaction.resources, ['res:manifest:0x1']);
      const mutated = tierSource('R5', { mutate: true });
      assert.doesNotMatch(mutated.source, /WM_COMMAND/, 'the R5 mutation removes the whole WM_COMMAND branch');
      assert.deepEqual(mutated.interaction, built.interaction, 'the truth stays the target truth; only the draft changes');
    } else {
      assert.match(built.source, /int main\(void\)/);
    }
    assert.ok(Array.isArray(built.literals));
    assert.ok(Array.isArray(built.apiNames));
    if (tier === 'R4') assert.equal(built.sealed, true);
  }
  const mutated = tierSource('R0', { mutate: true });
  assert.match(mutated.source, /MessageBoxA/);
  assert.match(mutated.source, /fabricated\.example\.test/);
  assert.deepEqual(mutated.literals, tierSource('R0').literals);
});

test('a mechanical baseline draft can never declare convergence', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'f'.repeat(64), targetSize: 10, budget: 2 });
  recordIteration(state, { build: { ok: true }, compare: fakeCompare({ overall: 1 }), draftKind: 'baseline' });
  assert.equal(state.status, 'running');
  recordIteration(state, { build: { ok: true }, compare: fakeCompare({ overall: 1 }), draftKind: 'baseline' });
  assert.equal(state.status, 'budget-exhausted');
});

test('the artifact store keeps a loop state at one stable path per session', async () => {
  const base = await mkdtemp(join(tmpdir(), 'dsh-rea-state-'));
  try {
    const store = createArtifactStore({ root: base, base });
    const first = await store.statePath('reconstruct-abc.json');
    const written = await store.writeState('reconstruct-abc.json', '{"status":"running"}');
    assert.equal(first, written);
    const back = await store.read(first);
    assert.equal(back.text, '{"status":"running"}');
    const again = await store.writeState('reconstruct-abc.json', '{"status":"converged"}');
    assert.equal(again, first);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test('the loop tool starts, advances one draft and converges on a real compile', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-loop-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store });

    const started = await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });
    assert.match(started.text, /status=running/);

    const advanced = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false, behavior: true, interaction: true });
    assert.match(advanced.text, /status=converged/);
    assert.match(advanced.text, /overall 100\.0%|overall 99\./);
    // The T4 gate and render path run end-to-end through the loop tool.
    assert.match(advanced.text, /T4 100\.0%/);
    assert.match(advanced.text, /behaviour: outputs 100\.0%/);
    // The T5 flag threads through rea_reconstruct -> compareDraft -> compareBuilds;
    // with engine=false the tier is blocked honestly, and a blocked tier never
    // gates convergence.
    assert.match(advanced.text, /T5 blocked/);

    const status = await tool.execute({ action: 'status', target: specimen.truth.targetPath });
    assert.match(status.text, /1\. built/);
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.status, 'converged');
    // The winning draft is persisted so a later auto run can continue from it.
    assert.ok(persisted.lastDraftPath);
    assert.equal(await readFile(persisted.lastDraftPath, 'utf8'), specimen.truth.source);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('decoder candidates are ranked by the argument they write and the loop they run', () => {
  const ranked = rankDecoderCandidates([
    { name: 'reader', rva: '0x1000', size: 100, body: 'void f(longlong param_1) { while (*param_1) { param_1 = param_1 + 1; } }' },
    { name: 'writer_two', rva: '0x2000', size: 120, body: 'void f(longlong param_1, longlong param_2) { *(char *)param_2 = 1; for (i = 0; i < n; i = i + 1) { *(char *)(param_2 + i) = *(char *)(param_2 + i) ^ 0x5a; } }' },
    { name: 'writer_one', rva: '0x3000', size: 300, body: 'void f(longlong param_1) { *(char *)param_1 = 0; while (i < n) { param_1[i] = param_1[i] ^ key; } }' },
    { name: 'huge', rva: '0x4000', size: 5000, body: 'void f(longlong param_1) { *param_1 = 1; }' },
  ], { unresolvedBytes: 68 });
  assert.deepEqual(ranked.map((item) => item.name), ['writer_two', 'writer_one']);
  assert.equal(ranked[0].argIndex, 2, 'the written argument is param_2, not the default param_1');
  assert.equal(ranked[0].length, 68, 'the dump length follows the unresolved region');
  assert.ok(ranked[0].reasons.some((reason) => reason.includes('writes through argument 2')));
  assert.ok(ranked[0].score >= 0.9);
});

test('dynamic evidence reopens a spent loop instead of declaring it converged', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-dynamic-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store });

    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 1 });
    const empty = join(dir, 'empty.c');
    await writeFile(empty, 'int main(void) { return 0; }\n', 'utf8');
    const spent = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: empty, engine: false });
    assert.match(spent.text, /terminal: budget-exhausted/);

    const recovered = Buffer.from('recovered-config-value', 'utf8').toString('hex');
    const applied = await tool.execute({
      action: 'dynamic-apply', target: specimen.truth.targetPath, hex: recovered, rva: '0x1590',
    });
    assert.match(applied.text, /status=running/);
    assert.match(applied.text, /recovered-config-value/);
    assert.match(applied.text, /submit a draft/);

    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.status, 'running', 'evidence is not a verdict');
    assert.equal(persisted.iterations.length, 1, 'a dump is not an iteration');
    assert.equal(persisted.budget, 2, 'one extra iteration is granted for the draft that carries the values');
    assert.deepEqual(persisted.dynamic.strings, ['recovered-config-value']);
    assert.equal(persisted.dynamic.rva, '0x1590');

    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const closed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(closed.text, /status=converged/);
    const final = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(final.dynamic.strings[0], 'recovered-config-value', 'the trace stays in the record after convergence');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('upstream analyzers appear as alternate confirmations only when the host advertises them', () => {
  const comparison = fakeCompare({ overall: 0.5, missing: ['createfilea'], added: ['writeprocessmemory'], unmatched: ['https://x'] });
  const local = gapsFromComparison(comparison);
  assert.ok(local.every((gap) => gap.alternates === undefined), 'no upstream tool, no alternate path');

  const gaps = gapsFromComparison(comparison, { availableTools: new Set(['verify_reconstruction', 'evaluate_reconstruction_coverage']) });
  const byId = new Map(gaps.map((gap) => [gap.id, gap]));
  assert.deepEqual(byId.get('imports-missing').alternates, ['evaluate_reconstruction_coverage']);
  assert.deepEqual(byId.get('imports-added').alternates, ['evaluate_reconstruction_coverage']);
  assert.deepEqual(byId.get('literals-unmatched').alternates, ['verify_reconstruction']);
  // A blocked T2 cannot be settled by an upstream verifier: there is nothing to
  // verify against, so it stays local-only.
  assert.equal(byId.get('t2-blocked')?.alternates, undefined);
});

test('a runtime disagreement blocks convergence until a matching trace is recorded', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-runtime-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });

    const tracePath = join(dir, 'trace.json');
    const writeTrace = async (score) => writeFile(tracePath, JSON.stringify({
      targetPath: specimen.truth.targetPath,
      comparison: {
        status: 'ran',
        score,
        exit: { same: score === 1 },
        stdout: { score },
        stderr: { score: 1 },
        files: { score },
      },
    }, null, 2), 'utf8');

    await writeTrace(0.4);
    const applied = await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, trace: tracePath });
    assert.match(applied.text, /runtime evidence: 40\.0%/);
    assert.match(applied.text, /cannot converge/);

    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const blocked = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(blocked.text, /status=running/);
    assert.match(blocked.text, /disagrees, convergence blocked/);

    await writeTrace(1);
    await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, trace: tracePath });
    const closed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(closed.text, /status=converged/);
    assert.match(closed.text, /runtime: 100\.0%/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a trace recorded for a different build is stale and cannot gate convergence', () => {
  const base = { targetPath: 'C://x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 2 };
  const stale = createLoopState(base);
  stale.runtime = { score: 0.1, rebuiltSha256: 'old-build' };
  stale.lastBuildSha256 = 'new-build';
  recordIteration(stale, { build: { ok: true }, compare: fakeCompare({ overall: 1 }) });
  assert.equal(stale.status, 'converged', 'stale evidence is not evidence about this draft');

  const fresh = createLoopState(base);
  fresh.runtime = { score: 0.1, rebuiltSha256: 'same-build' };
  fresh.lastBuildSha256 = 'same-build';
  recordIteration(fresh, { build: { ok: true }, compare: fakeCompare({ overall: 1 }) });
  assert.equal(fresh.status, 'running', 'a fresh disagreement still blocks convergence');
});

test('the loop tool renders upstream alternates when the host advertises them', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-upstream-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R2', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({
      store,
      availableTools: () => new Set(['verify_reconstruction', 'evaluate_reconstruction_coverage']),
    });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 1 });
    const empty = join(dir, 'empty.c');
    await writeFile(empty, 'int main(void) { return 0; }\n', 'utf8');
    const answer = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: empty, engine: false });
    assert.match(answer.text, /gap \[T1-payload\] payload-missing/);
    assert.match(answer.text, /also: evaluate_reconstruction_coverage/);
    const brief = await tool.execute({ action: 'handoff', target: specimen.truth.targetPath });
    assert.match(brief.text, /# Reconstruction brief/);
    assert.match(brief.text, /## Open gaps/);
    assert.match(brief.text, /saved: .*reconstruction-brief\.md/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the handoff brief names the functions to rewrite and how to confirm them', () => {
  const state = createLoopState({ targetPath: 'C://x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 3 });
  recordIteration(state, {
    build: { ok: true },
    compare: fakeCompare({
      overall: 0.7,
      missing: ['createfilea'],
      mismatches: [{ name: 'FUN_180001000', rva: '0x1000', similarity: 0.55 }],
    }),
  });
  const brief = renderHandoff(state);
  assert.match(brief, /FUN_180001000 rva=0x1000 55\.0%/);
  assert.match(brief, /rea_decompile_address/);
  assert.match(brief, /## Open gaps/);
  assert.match(brief, /advance source=/);
  assert.match(brief, /the comparison decides/i);
});

test('a model-authored rewrite is applied to the last draft and measured as a draft', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-rewrite-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });

    const base = join(dir, 'base.c');
    await writeFile(base, 'int main(void) { return 0; }\n', 'utf8');
    const answer = await tool.execute({
      action: 'rewrite',
      target: specimen.truth.targetPath,
      source: base,
      engine: false,
      rewrites: [{ name: 'main', source: 'int main(void) { return 1; }' }],
    });
    assert.match(answer.text, /rewrite: applied main/);
    assert.match(answer.text, /1\. built/);

    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.iterations.length, 1);
    assert.match(await readFile(persisted.lastDraftPath, 'utf8'), /return 1;/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a draft=auto rollback retry keeps its marker in the persisted loop state', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-auto-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    // The repair engine is injected so the scenario is deterministic: round 1
    // scores 0.9, the batch replacement drops to 0.8, and the rollback retry
    // recovers with the `retry: true` marker. The rollback decision itself is
    // covered by test/autodraft.test.js; this test pins the tool path — the
    // marker must survive toAutoHistory, recordIteration and writeState.
    const autoRepairRounds = async ({ startText }) => ({
      best: {
        sourceText: startText,
        built: await compileC({ sourceText: startText, workDir: join(dir, 'fake-auto'), name: 'auto-fake' }),
        compare: fakeCompare({ overall: 0.9 }),
      },
      history: [
        { round: 1, overall: 0.9, replaced: ['FUN_180001000'], added: [] },
        { round: 1, overall: 0.8, replaced: ['FUN_180001000'], added: [], retry: true },
      ],
      firstFailure: null,
    });
    const tool = buildReconstructTool({ store, autoRepairRounds });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });

    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, draft: 'auto', engine: false, rounds: 2 });

    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    const auto = persisted.iterations[persisted.iterations.length - 1].auto;
    assert.equal(auto.startedFromSource, true);
    assert.equal(auto.rounds, 2, 'the batch round and the retry round are both on record');
    assert.equal(auto.history.length, 2);
    assert.equal(auto.history[0].retry, undefined, 'an ordinary round carries no retry key');
    assert.equal(auto.history[1].retry, true, 'the retry marker survives toAutoHistory + writeState');
    assert.match(await readFile(persisted.lastDraftPath, 'utf8'), /GetComputerNameA/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
