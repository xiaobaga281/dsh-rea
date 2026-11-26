import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createArtifactStore } from '../lib/infra/artifacts.js';
import { evidenceProducer, identifyFile } from '../lib/infra/evidence.js';
import { compareBuilds } from '../lib/restore/compare.js';
import { buildReadiness, compileC } from '../lib/restore/build.js';
import { ghidraLocalReadiness } from '../lib/restore/ghidra-local.js';
import { RECONSTRUCT_ACTIONS } from '../lib/restore/recon-actions.js';
import { createLoopState, evaluateConvergence, gapsFromComparison, migrateLoopState, rankDecoderCandidates, recordIteration, renderHandoff, CONVERGENCE, runtimeEvidenceFresh } from '../lib/restore/recon.js';
import { buildReconstructTool } from '../lib/surface/recon-tools.js';
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
      t2: {
        status: t2, score: t2 === 'ran' ? t2Score : null, reason: t2 === 'ran' ? null : 'Ghidra is not ready',
        scope: 'all-functions', coverage: 1, matched: 1, functions: 1, belowThreshold: t2Score < 0.9 ? 1 : 0,
        inventoryComplete: true, failed: 0, truncated: false, timeStopped: false, analysisTimedOut: false,
        ...(mismatches.length > 0 ? { mismatches } : {}),
      },
      t3: { status: unmatched.length > 0 ? 'ran' : 'ran', score: unmatched.length > 0 ? 0.5 : 1, unmatched },
    },
    weightsUsed: { t1: 0.55, t2: 0.3, t3: 0.15 },
  };
}

const measure = (state, options) => recordIteration(state, { build: { ok: true }, rebuiltSha256: 'measured-build', sourceSha: 'source-sha', ...options });

async function withInjectedT2(options) {
  const comparison = await compareBuilds({ ...options, engine: false });
  comparison.tiers.t2 = fakeCompare().tiers.t2;
  return comparison;
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
  assert.equal(state.budget.iterations, 20);
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
    assert.match(gap.executable.tool, /^rea_/);
    assert.ok(Array.isArray(gap.executable.requiredArgs));
    assert.ok(['read', 'write', 'compile', 'execute'].includes(gap.executable.policy));
    assert.equal(gap.executable.confirm, false);
    assert.equal(gap.executable.action, null);
    if (gap.id === 't2-blocked') {
      assert.equal(gap.executable.tool, 'rea_doctor');
      assert.match(gap.executable.blockedReason, /Ghidra is not ready/);
    } else {
      assert.equal(gap.executable.blockedReason, null);
    }
  }
});

test('a refuted hypothesis carries the reconstruct re-check action as structured metadata', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'e'.repeat(64), targetSize: 10, budget: 2 });
  state.hypotheses = [{ id: 'wrong-api', status: 'refuted', statement: 'it calls CreateFileA', detail: 'no matching call' }];
  recordIteration(state, { build: { ok: true }, rebuiltSha256: 'rebuilt', compare: fakeCompare({ overall: 0.8 }) });
  const gap = state.iterations.at(-1).gaps.find((item) => item.id === 'hypothesis-refuted');
  assert.equal(gap.executable.tool, 'rea_reconstruct');
  assert.equal(gap.executable.action, 'hypothesis-check');
  assert.deepEqual(gap.executable.requiredArgs, ['target', 'action', 'hypothesis']);
  assert.equal(gap.executable.policy, 'compile');
  assert.equal(gap.executable.blockedReason, null);
});

test('the reconstruct schema and runtime validation use the exported action enum', async () => {
  const tool = buildReconstructTool({ store: null });
  assert.deepEqual(tool.parameters.properties.action.enum, [...RECONSTRUCT_ACTIONS]);
  for (const action of ['unpack-apply', 'dump-apply']) assert.match(tool.parameters.properties.action.description, new RegExp(action));
  const refused = await tool.execute({ action: 'not-an-action', target: 'C:\\x.exe' });
  assert.match(refused.text, /unpack-apply/);
  assert.match(refused.text, /dump-apply/);
});

test('the loop converges only when the tiers agree, and an empty measurement blocks', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'b'.repeat(64), targetSize: 10, budget: 2 });
  measure(state, { compare: fakeCompare({ overall: CONVERGENCE }) });
  assert.equal(state.status, 'converged');

  const empty = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'c'.repeat(64), targetSize: 10, budget: 2 });
  recordIteration(empty, { build: { ok: true }, compare: { ...fakeCompare(), overall: null } });
  assert.equal(empty.status, 'blocked');
  assert.match(empty.reason, /compare-unmeasurable/);

  const weak = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'd'.repeat(64), targetSize: 10, budget: 1 });
  recordIteration(weak, { sourceSha: 'source-sha', build: { ok: true }, rebuiltSha256: 'measured-build', compare: fakeCompare({ overall: 0.97 }) });
  assert.equal(weak.status, 'budget-exhausted');
});

test('a spent budget cannot hide hard measurement failures or unmeasured runtime tiers', () => {
  const runtimeMissing = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 1 });
  const noRuntime = fakeCompare({ overall: 0.8 });
  noRuntime.tiers.t3 = { status: 'ran', score: null, unmatched: [] };
  measure(runtimeMissing, { compare: noRuntime });
  assert.equal(runtimeMissing.status, 'budget-exhausted');
  assert.ok(runtimeMissing.gate.failedGates.includes('t3-unmeasurable'));
  assert.equal(runtimeMissing.best, null);

  const hardBlocked = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'b'.repeat(64), targetSize: 10, budget: 1 });
  measure(hardBlocked, { compare: fakeCompare({ t2: 'blocked' }) });
  assert.equal(hardBlocked.status, 'blocked');
  assert.ok(hardBlocked.gate.failedGates.includes('t2-unmeasured'));
});

test('a successful build binds its measured artifact hash without a caller-supplied duplicate', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  const sha256 = 'f'.repeat(64);
  recordIteration(state, { sourceSha: 'source-sha', build: { ok: true, sha256 }, compare: fakeCompare({ overall: 1 }) });
  assert.equal(state.status, 'converged');
  assert.equal(state.best.rebuiltSha256, sha256);
  assert.equal(state.lastBuildSha256, sha256);
  assert.equal(state.iterations[0].build.sha256, sha256);

  const unbound = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  recordIteration(unbound, { build: { ok: true }, compare: fakeCompare({ overall: 1 }) });
  assert.equal(unbound.status, 'blocked');
  assert.ok(unbound.gate.failedGates.includes('rebuild-unbound'));
});

test('comparison failure and unbound source cannot replace accepted build evidence', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  state.lastBuildSha256 = 'accepted-build';
  state.lastDraftPath = 'accepted.c';
  state.best = { iteration: 1, overall: 0.95, gatePassed: true, sourceSha256: 'accepted-source', rebuiltSha256: 'accepted-build', draftPath: 'accepted.c' };
  recordIteration(state, { sourceSha: 'candidate-source', build: { ok: true, sha256: 'candidate-build' }, compare: null });
  assert.equal(state.lastBuildSha256, 'accepted-build');
  assert.equal(state.lastDraftPath, 'accepted.c');
  assert.equal(state.best.rebuiltSha256, 'accepted-build');

  const unbound = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  recordIteration(unbound, { build: { ok: true, sha256: 'candidate-build' }, compare: fakeCompare({ overall: 1 }) });
  assert.equal(unbound.status, 'blocked');
  assert.ok(unbound.gate.failedGates.includes('source-unbound'));
  assert.equal(unbound.best, null);
});

test('T2 is a hard gate: blocked, low, partial and entry-only measurements cannot converge', () => {
  const base = { targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 3 };
  for (const [label, t2] of [
    ['blocked', { status: 'blocked', score: null }],
    ['low', { score: 0.85 }],
    ['truncated', { truncated: true }],
    ['time-stopped', { timeStopped: true }],
    ['analysis-timeout', { analysisTimedOut: true }],
    ['decompile-failed', { failed: 1 }],
    ['entry-only', { scope: 'entry' }],
  ]) {
    const state = createLoopState(base);
    const compare = fakeCompare({ overall: 0.99 });
    Object.assign(compare.tiers.t2, t2);
    const gate = evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' });
    assert.equal(gate.passed, false, label);
    measure(state, { compare });
    assert.equal(state.status, label === 'low' ? 'running' : 'blocked', label);
    assert.equal(state.best, null, label);
  }
});

test('selected-function convergence requires every requested function and limits the claim', () => {
  const state = createLoopState({
    targetPath: 'C:\\x.exe', targetSha256: 'b'.repeat(64), targetSize: 10,
    scope: 'selected-functions', functionNames: ['main', 'decode'],
  });
  const compare = fakeCompare({ overall: 0.99 });
  Object.assign(compare.tiers.t2, { scope: 'selected-functions', matched: 2, functions: 2, coverage: 1, belowThreshold: 0 });
  const gate = evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' });
  assert.equal(gate.passed, true);
  assert.equal(gate.claimScope, 'selected-functions');
  compare.tiers.t2.matched = 1;
  assert.equal(evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' }).passed, false);
});

test('selected-function convergence allows failures outside the request only with complete selected coverage', () => {
  const state = createLoopState({
    targetPath: 'C:\\x.exe', targetSha256: 'e'.repeat(64), targetSize: 10,
    scope: 'selected-functions', functionNames: ['main', 'decode'],
  });
  const compare = fakeCompare({ overall: 0.99 });
  Object.assign(compare.tiers.t2, {
    scope: 'selected-functions', matched: 2, functions: 2, coverage: 1, belowThreshold: 0,
    inventoryComplete: false, inventoryEnumerationComplete: true, failed: 1, truncated: false,
    selectedCoverage: {
      complete: true, requested: 2,
      target: { complete: true, found: 2, decompiled: 2, missing: [], failed: [], ambiguous: [] },
      rebuilt: { complete: true, found: 2, decompiled: 2, missing: [], failed: [], ambiguous: [] },
      outsideScopeFailures: 1,
    },
  });
  const options = { build: { ok: true }, compare, rebuiltSha256: 'build' };
  assert.equal(evaluateConvergence(state, options).passed, true);
  compare.tiers.t2.inventoryComplete = true;
  assert.equal(evaluateConvergence(state, options).passed, false, 'complete inventory cannot also report a decompile failure');
  compare.tiers.t2.inventoryComplete = false;
  compare.tiers.t2.selectedCoverage.target.failed = ['decode'];
  compare.tiers.t2.selectedCoverage.target.complete = false;
  assert.equal(evaluateConvergence(state, options).passed, false);
  compare.tiers.t2.selectedCoverage.target.failed = [];
  compare.tiers.t2.selectedCoverage.target.complete = true;
  compare.tiers.t2.inventoryEnumerationComplete = false;
  assert.equal(evaluateConvergence(state, options).passed, false);
});

test('runtime evidence without both hashes is unbound, and stale evidence neither gates nor reopens', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'c'.repeat(64), targetSize: 10, convergenceScope: 'runtime' });
  const compare = fakeCompare({ overall: 0.99 });
  const options = { build: { ok: true }, compare, rebuiltSha256: 'new-build' };
  state.lastBuildSha256 = 'new-build';
  state.runtime = { score: 0.1, rebuiltSha256: 'old-build' };
  assert.equal(runtimeEvidenceFresh(state), false);
  assert.ok(evaluateConvergence(state, options).failedGates.includes('runtime-unbound-or-stale'));
  state.runtime = { score: 1 };
  assert.equal(runtimeEvidenceFresh(state), false);
  state.runtime = { score: 0.1, targetSha256: state.target.sha256, rebuiltSha256: 'new-build' };
  assert.equal(runtimeEvidenceFresh(state), true);
  assert.ok(evaluateConvergence(state, options).failedGates.includes('runtime-threshold'));
  state.runtime.score = 1;
  assert.equal(evaluateConvergence(state, options).passed, true);
  state.analysisTarget = { kind: 'unpacked', path: 'C:\\unpacked.exe', sha256: 'd'.repeat(64), derivedFromEvidenceId: 'ev-unpack' };
  assert.equal(runtimeEvidenceFresh(state), false, 'a trace for the packed target cannot gate its derived image');
  state.runtime.targetSha256 = state.analysisTarget.sha256;
  assert.equal(runtimeEvidenceFresh(state), true);
});

test('a low-scoring or baseline draft never replaces the accepted best', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'd'.repeat(64), targetSize: 10, budget: 5 });
  measure(state, { compare: fakeCompare({ overall: 0.99, t2Score: 0.85 }) });
  assert.equal(state.best, null);
  measure(state, { compare: fakeCompare({ overall: 0.99 }) });
  assert.equal(state.best.iteration, 2);
  measure(state, { compare: fakeCompare({ overall: 0.995, t2Score: 0.85 }) });
  assert.equal(state.best.iteration, 2);
  assert.equal(state.best.gatePassed, true);
});

test('T1 uses its measured structural score while empty import sets remain explicit', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  const compare = fakeCompare({ overall: 1 });
  compare.tiers.t1.imports = { recall: null, precision: null, missing: [], added: [] };
  const gate = evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' });
  assert.equal(gate.passed, true, 'section structure is measurable even when neither binary imports APIs');

  compare.tiers.t1.score = null;
  compare.tiers.t1.status = 'empty';
  assert.ok(evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' }).failedGates.includes('t1-unmeasured'));
  compare.tiers.t1.status = 'ran';
  assert.ok(evaluateConvergence(state, { build: { ok: true }, compare, rebuiltSha256: 'build' }).failedGates.includes('t1-unmeasurable'));
});

test('a null literal tier blocks, while sealed static unreachability takes precedence', () => {
  const ordinary = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10 });
  const noLiterals = fakeCompare({ overall: 1 });
  noLiterals.tiers.t3 = { status: 'ran', score: null, literals: 0, matched: [], unmatched: [] };
  measure(ordinary, { compare: noLiterals });
  assert.equal(ordinary.status, 'blocked');
  assert.ok(ordinary.gate.failedGates.includes('t3-unmeasurable'));

  const sealed = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, unresolvedRegions: 1, sealed: true });
  measure(sealed, { compare: noLiterals });
  assert.equal(sealed.status, 'unreachable');
  assert.match(sealed.reason, /dynamic plan/);
  assert.equal(sealed.best, null);
});

test('a spent budget with sealed regions and unmatched literals ends unreachable, not exhausted', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'e'.repeat(64), targetSize: 10, unresolvedRegions: 1, budget: 1 });
  measure(state, { compare: fakeCompare({ overall: 0.8, unmatched: ['secret'] }) });
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

test('an expired wall-clock budget prevents convergence even with perfect tiers', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 5, deadlineMs: 1_000 });
  state.budget.startedAt = '2000-01-01T00:00:00.000Z';
  measure(state, { compare: fakeCompare({ overall: 1 }) });
  assert.equal(state.status, 'budget-exhausted');
  assert.ok(state.gate.failedGates.includes('budget-deadline'));
  assert.equal(state.best, null);
});

test('a mechanical baseline draft can never declare convergence', () => {
  const state = createLoopState({ targetPath: 'C:\\x.exe', targetSha256: 'f'.repeat(64), targetSize: 10, budget: 2 });
  measure(state, { compare: fakeCompare({ overall: 1 }), draftKind: 'baseline' });
  assert.equal(state.status, 'running');
  measure(state, { compare: fakeCompare({ overall: 1 }), draftKind: 'baseline' });
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

test('a draft persistence failure cannot create a resumable iteration', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-draft-failure-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const baseStore = fakeStore(join(dir, 'state'));
    const store = {
      ...baseStore,
      async writeState(name, body) {
        if (name.startsWith('draft-')) throw new Error('disk full');
        return baseStore.writeState(name, body);
      },
    };
    const tool = buildReconstructTool({ store, compareBuilds: withInjectedT2 });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });
    const failed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(failed.text, /draft could not be persisted/);
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.iterations.length, 0);
    assert.equal(persisted.best, null);
    assert.equal(persisted.lastBuildSha256, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
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
    const tool = buildReconstructTool({ store, compareBuilds: withInjectedT2 });

    const started = await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });
    assert.match(started.text, /status=running/);

    const advanced = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false, behavior: true });
    assert.match(advanced.text, /status=converged/);
    assert.match(advanced.text, /overall 100\.0%|overall 99\./);
    assert.match(advanced.text, /T4 100\.0%/);
    assert.match(advanced.text, /behaviour: outputs 100\.0%/);

    const status = await tool.execute({ action: 'status', target: specimen.truth.targetPath });
    assert.match(status.text, /1\. built/);
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.status, 'converged');
    // The winning draft is persisted so a later auto run can continue from it.
    assert.ok(persisted.lastDraftPath);
    assert.equal(await readFile(persisted.lastDraftPath, 'utf8'), specimen.truth.source);

    const unmeasuredStore = fakeStore(join(dir, 'unmeasured-state'));
    const unmeasuredTool = buildReconstructTool({ store: unmeasuredStore });
    await unmeasuredTool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 1 });
    const blocked = await unmeasuredTool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(blocked.text, /terminal: blocked/);
    assert.match(blocked.text, /T2/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a rewrite resumes from the accepted best instead of a later discarded candidate', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-rewrite-base-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store, compareBuilds: withInjectedT2 });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 3 });
    const acceptedPath = join(dir, 'accepted.c');
    const discardedPath = join(dir, 'discarded.c');
    await writeFile(acceptedPath, specimen.truth.source, 'utf8');
    await writeFile(discardedPath, 'int main(void) { return 0; }\n', 'utf8');
    const accepted = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: acceptedPath, engine: false });
    assert.match(accepted.text, /status=converged/);
    const identity = await identifyFile(specimen.truth.targetPath);
    const statePath = await store.statePath(`reconstruct-${identity.sha256.slice(0, 12)}.json`);
    const state = JSON.parse(await readFile(statePath, 'utf8'));
    state.status = 'running';
    state.lastCandidateDraftPath = discardedPath;
    await writeFile(statePath, JSON.stringify(state, null, 2), 'utf8');
    const rewritten = await tool.execute({
      action: 'rewrite', target: specimen.truth.targetPath,
      rewrites: [{ name: 'main', source: 'int main(void) { return 0; }' }],
    });
    assert.match(rewritten.text, /base .*draft-[^\\]+-1\.c/);
    assert.doesNotMatch(rewritten.text, /base .*discarded\.c/);
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
    let observedDynamicTruth = null;
    const tool = buildReconstructTool({
      store,
      compareBuilds: async (options) => {
        observedDynamicTruth = options.dynamicEvidence;
        return withInjectedT2(options);
      },
    });

    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 1 });
    const empty = join(dir, 'empty.c');
    await writeFile(empty, 'int main(void) { return 0; }\n', 'utf8');
    const spent = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: empty, engine: false });
    assert.match(spent.text, /terminal: budget-exhausted/);

    const evidenceStore = createArtifactStore({ root: join(dir, 'evidence') });
    const targetIdentity = await identifyFile(specimen.truth.targetPath);
    const probeReceipt = async (value, rva) => {
      const hex = Buffer.from(value, 'utf8').toString('hex');
      const record = {
        target: specimen.truth.targetPath, targetSha256: targetIdentity.sha256,
        module: 'specimen.exe', rva, argIndex: 0, length: Buffer.byteLength(value), hex,
      };
      const saved = await evidenceStore.write('probe.json', JSON.stringify(record));
      const artifact = await identifyFile(saved);
      return evidenceStore.writeEvidence({
        type: 'probe', status: 'success', producer: evidenceProducer('rea_dynamic_probe', {
          policy: { allowSampleExecution: true }, confirm: true,
        }),
        targetSha256: targetIdentity.sha256, artifact,
        details: { module: record.module, rva, argIndex: 0, length: record.length, dumpSha256: artifact.sha256 },
      });
    };
    const raw = await tool.execute({
      action: 'dynamic-apply', target: specimen.truth.targetPath, hex: Buffer.from('bare').toString('hex'), rva: '0x1590',
    });
    assert.match(raw.text, /receipt rejected/);
    const firstReceipt = await probeReceipt('recovered-config-value', '0x1590');
    const beforeApply = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${createHash('sha256').update(await readFile(specimen.truth.targetPath)).digest('hex').slice(0, 12)}.json`), 'utf8'));
    for (const [input, pattern] of [
      [{ evidence: firstReceipt.receiptPath, rva: '0x1591' }, /RVA does not match/],
      [{ evidence: firstReceipt.receiptPath, rva: 'not-hex' }, /hexadecimal 64-bit address/],
      [{ evidence: firstReceipt.receiptPath, module: 'other.exe' }, /module does not match/],
    ]) {
      const refused = await tool.execute({ action: 'dynamic-apply', target: specimen.truth.targetPath, ...input });
      assert.match(refused.text, pattern);
      assert.deepEqual(JSON.parse(await readFile(join(dir, 'state', `reconstruct-${createHash('sha256').update(await readFile(specimen.truth.targetPath)).digest('hex').slice(0, 12)}.json`), 'utf8')), beforeApply);
    }
    const applied = await tool.execute({
      action: 'dynamic-apply', target: specimen.truth.targetPath, evidence: firstReceipt.receiptPath, rva: '0x1590',
    });
    assert.match(applied.text, /status=running/);
    assert.match(applied.text, /recovered-config-value/);
    assert.match(applied.text, /submit a draft/);

    const secondReceipt = await probeReceipt('earlier-config-value', '0x1580');
    await tool.execute({ action: 'dynamic-apply', target: specimen.truth.targetPath, evidence: secondReceipt.receiptPath, rva: '0x1580' });
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.status, 'running', 'evidence is not a verdict');
    assert.equal(persisted.iterations.length, 1, 'a dump is not an iteration');
    assert.equal(persisted.budget.iterations, 2, 'one extra iteration is granted for the draft that carries the values');
    assert.equal(persisted.dynamicHistory.length, 2);
    assert.deepEqual(persisted.dynamicHistory.map((item) => item.evidenceId), [firstReceipt.evidenceId, secondReceipt.evidenceId]);
    assert.deepEqual(persisted.dynamic.strings, ['earlier-config-value']);

    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const closed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(closed.text, /status=converged/);
    assert.ok(observedDynamicTruth.strings.includes('recovered-config-value'));
    assert.ok(observedDynamicTruth.strings.includes('earlier-config-value'));
    const final = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(final.dynamicHistory[0].strings[0], 'recovered-config-value', 'the trace stays in the record after convergence');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('dynamic planning records an explicit partial inventory without claiming complete coverage', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-dynamic-plan-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const targetIdentity = await identifyFile(specimen.truth.targetPath);
    const store = fakeStore(join(dir, 'state'));
    let observed;
    const tool = buildReconstructTool({
      store,
      ghidraReady: async () => ({ ready: true }),
      listFunctions: async (_path, options) => {
        observed = options;
        return {
          ok: false, code: 'inventory-partial', reason: 'injected analysis timeout',
          functions: [{ name: 'FUN_1000', rva: '0x1000', size: 64, body: 'void f(char *param_1) { for (int i=0;i<8;i++) param_1[i] ^= 0x5a; }' }],
          emitted: 1, total: 20, pages: 1, inventoryComplete: false, analysisTimedOut: true,
        };
      },
    });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2 });
    const result = await tool.execute({ action: 'dynamic-plan', target: specimen.truth.targetPath });
    assert.equal(observed.allowPartial, true);
    assert.match(result.text, /partial inventory/i);
    assert.match(result.text, /cannot establish whole-program coverage/i);
    const state = JSON.parse(await readFile(await store.statePath(`reconstruct-${targetIdentity.sha256.slice(0, 12)}.json`), 'utf8'));
    assert.equal(state.dynamicPlan.inventory.complete, false);
    assert.equal(state.dynamicPlan.inventory.emitted, 1);
    assert.equal(state.dynamicPlan.inventory.total, 20);
    assert.equal(state.dynamicPlan.candidates[0].name, 'FUN_1000');
    assert.equal(state.status, 'running');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('unpack and dump receipts switch the analysis target without inheriting old scores', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-derived-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const targetIdentity = await identifyFile(specimen.truth.targetPath);
    const store = fakeStore(join(dir, 'state'));
    const tool = buildReconstructTool({ store, compareBuilds: async () => fakeCompare({ overall: 1 }) });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 2, convergenceScope: 'runtime' });
    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const measured = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(measured.text, /status=running/);
    const sha = targetIdentity.sha256.slice(0, 12);
    const statePath = join(dir, 'state', `reconstruct-${sha}.json`);
    const before = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(before.iterations.length, 1);
    assert.ok(before.lastBuildSha256);
    before.dynamic = { targetSha256: targetIdentity.sha256, strings: ['packed-only-value'] };
    before.dynamicHistory = [before.dynamic];
    before.dynamicPlan = { candidates: [{ name: 'packed-decoder' }] };
    before.hypotheses = [{ id: 'packed-only-claim', status: 'verified' }];
    await writeFile(statePath, JSON.stringify(before, null, 2), 'utf8');
    const evidenceStore = createArtifactStore({ root: join(dir, 'evidence') });
    const derivedPath = join(dir, 'derived.exe');
    const derivedBytes = await readFile(specimen.truth.targetPath);
    await writeFile(derivedPath, derivedBytes);
    const derived = await identifyFile(derivedPath);
    const writeDerivedReceipt = (type, producer, targetSha256 = targetIdentity.sha256) => evidenceStore.writeEvidence({
      type, status: 'success',
      producer: producer.startsWith('rea_memory_dump')
        ? evidenceProducer(producer, { policy: { allowSampleExecution: true }, confirm: true })
        : evidenceProducer(producer),
      targetSha256, artifact: derived,
    });

    const wrongTarget = await writeDerivedReceipt('unpack', 'rea_unpack', 'f'.repeat(64));
    const rejected = await tool.execute({ action: 'unpack-apply', target: specimen.truth.targetPath, evidence: wrongTarget.receiptPath });
    assert.match(rejected.text, /different target/);
    assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), before, 'a wrong-target receipt cannot mutate state');

    const wrongProducer = await writeDerivedReceipt('unpack', 'rea_memory_dump');
    const wrongKind = await tool.execute({ action: 'unpack-apply', target: specimen.truth.targetPath, evidence: wrongProducer.receiptPath });
    assert.match(wrongKind.text, /expected a rea_unpack unpack receipt/);
    assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), before);

    const unpacked = await writeDerivedReceipt('unpack', 'rea_unpack');
    await writeFile(derivedPath, Buffer.concat([derivedBytes, Buffer.from('tampered')]));
    const tampered = await tool.execute({ action: 'unpack-apply', target: specimen.truth.targetPath, evidence: unpacked.receiptPath });
    assert.match(tampered.text, /artifact changed after capture/);
    assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), before);
    await writeFile(derivedPath, derivedBytes);

    const switched = await tool.execute({ action: 'unpack-apply', target: specimen.truth.targetPath, evidence: unpacked.receiptPath });
    assert.match(switched.text, /old inventory and comparison scores are invalid/);
    const unpackedState = JSON.parse(await readFile(statePath, 'utf8'));
    assert.deepEqual(unpackedState.target, before.target, 'the original target identity is permanent');
    assert.equal(unpackedState.analysisTarget.kind, 'unpacked');
    assert.equal(unpackedState.analysisTarget.sha256, derived.sha256);
    assert.equal(unpackedState.analysisTarget.derivedFromEvidenceId, unpacked.evidenceId);
    assert.equal(unpackedState.best, null);
    assert.equal(unpackedState.lastBuildSha256, null);
    assert.equal(unpackedState.lastDraftPath, null);
    assert.equal(unpackedState.lastCandidateDraftPath, null);
    assert.equal(unpackedState.runtime, null);
    assert.deepEqual(unpackedState.runtimeHistory, []);
    assert.equal(unpackedState.dynamic, null);
    assert.deepEqual(unpackedState.dynamicHistory, []);
    assert.equal(unpackedState.dynamicPlan, null);
    assert.deepEqual(unpackedState.hypotheses, [], 'packed-target hypotheses cannot verify the derived image');
    assert.equal(unpackedState.gate, null);
    assert.equal(unpackedState.intake.functions, 0);
    assert.equal(unpackedState.iterations.length, 1, 'history remains auditable but cannot gate the new target');

    const dumped = await writeDerivedReceipt('memory-dump', 'rea_memory_dump');
    await tool.execute({ action: 'dump-apply', target: specimen.truth.targetPath, evidence: dumped.receiptPath });
    const dumpedState = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(dumpedState.analysisTarget.kind, 'memory-image');
    assert.equal(dumpedState.analysisTarget.derivedFromEvidenceId, dumped.evidenceId);
    assert.deepEqual(dumpedState.target, before.target);
    assert.equal(dumpedState.iterations.length, 1);
    await writeFile(derivedPath, Buffer.concat([derivedBytes, Buffer.from('changed')]));
    const changed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(changed.text, /analysis target bytes changed after capture/);
    assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), dumpedState);
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
    const tool = buildReconstructTool({ store, compareBuilds: withInjectedT2 });
    await tool.execute({ action: 'start', target: specimen.truth.targetPath, budget: 3, convergenceScope: 'runtime' });

    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    const waiting = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(waiting.text, /status=running/);
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const initial = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.ok(initial.gate.failedGates.includes('runtime-unbound-or-stale'));
    const rebuiltPath = initial.iterations[0].build.outPath;
    assert.ok(rebuiltPath, 'the measured rebuild is retained for trace binding');

    const tracePath = join(dir, 'trace.json');
    const evidenceStore = createArtifactStore({ root: join(dir, 'evidence') });
    const targetIdentity = await identifyFile(specimen.truth.targetPath);
    const writeTrace = async (score, { receiptTargetSha256 = targetIdentity.sha256, rebuiltSha256 = initial.lastBuildSha256 } = {}) => {
      await writeFile(tracePath, JSON.stringify({
        targetPath: specimen.truth.targetPath,
        rebuiltPath,
        targetSha256: targetIdentity.sha256,
        rebuiltSha256: initial.lastBuildSha256,
        comparison: {
          status: 'ran',
          score,
          exit: { same: score === 1 },
          stdout: { score },
          stderr: { score: 1 },
          files: { score },
        },
      }, null, 2), 'utf8');
      const artifact = await identifyFile(tracePath);
      const receipt = await evidenceStore.writeEvidence({
        type: 'trace', status: 'success', producer: evidenceProducer('rea_trace_behavior', {
          policy: { allowSampleExecution: true }, confirm: true,
        }),
        targetSha256: receiptTargetSha256, artifact,
        binding: { rebuiltSha256 },
        details: { traceSha256: artifact.sha256 },
      });
      return receipt.receiptPath;
    };

    await writeTrace(0.4);
    const rawTrace = await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, trace: tracePath });
    assert.match(rawTrace.text, /receipt rejected/);
    const lowReceipt = await writeTrace(0.4);
    const applied = await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, evidence: lowReceipt });
    assert.match(applied.text, /runtime evidence: ev-[^,]+, 40\.0%/);
    const executedBytes = await readFile(rebuiltPath);
    await writeFile(rebuiltPath, targetBuffer);
    const pathReplaced = await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, evidence: lowReceipt });
    assert.match(pathReplaced.text, /runtime evidence: ev-[^,]+, 40\.0%/, 'the receipt binds executed bytes, not a mutable path');
    await writeFile(rebuiltPath, executedBytes);
    assert.match(applied.text, /cannot converge/);
    const statePath = join(dir, 'state', `reconstruct-${sha}.json`);
    const beforeStale = JSON.parse(await readFile(statePath, 'utf8'));
    const wrongTarget = await writeTrace(1, { receiptTargetSha256: 'f'.repeat(64) });
    const wrongBuild = await writeTrace(1, { rebuiltSha256: 'f'.repeat(64) });
    for (const [receiptPath, pattern] of [[wrongTarget, /different target/], [wrongBuild, /stale or unbound/]]) {
      const refused = await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, evidence: receiptPath });
      assert.match(refused.text, pattern);
      assert.deepEqual(JSON.parse(await readFile(statePath, 'utf8')), beforeStale, 'stale evidence neither gates nor reopens');
    }
    const low = await tool.execute({ action: 'status', target: specimen.truth.targetPath });
    assert.match(low.text, /runtime: 40\.0%/);
    assert.match(low.text, /disagrees, convergence blocked/);

    const highReceipt = await writeTrace(1);
    await tool.execute({ action: 'trace-apply', target: specimen.truth.targetPath, evidence: highReceipt });
    const closed = await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, engine: false });
    assert.match(closed.text, /status=converged/);
    assert.match(closed.text, /runtime: 100\.0%/);
    const final = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.notEqual(final.iterations[0].build.outPath, final.iterations[1].build.outPath);
    assert.equal(createHash('sha256').update(await readFile(initial.iterations[0].build.outPath)).digest('hex'), initial.lastBuildSha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fresh runtime counterevidence invalidates the accepted best and migration drops unaccepted v1 bests', () => {
  const base = { targetPath: 'C://x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 4 };
  const state = createLoopState(base);
  measure(state, { compare: fakeCompare({ overall: 0.99 }), rebuiltSha256: 'same-build', sourceSha: 'source' });
  assert.ok(state.best);
  state.runtime = { score: 0.4, targetSha256: base.targetSha256, rebuiltSha256: 'same-build' };
  state.lastBuildSha256 = 'same-build';
  measure(state, { compare: fakeCompare({ overall: 0.995 }), rebuiltSha256: 'same-build', sourceSha: 'replacement' });
  assert.equal(state.best, null, 'the refuted build stays rejected while runtime evidence disagrees');
  state.runtime.score = 1;
  measure(state, { compare: fakeCompare({ overall: 0.995 }), rebuiltSha256: 'same-build', sourceSha: 'replacement' });
  assert.equal(state.best.iteration, 3, 'a refuted best cannot block a valid replacement');
  assert.equal(state.reopenHistory.length, 1);
  assert.equal(state.reopenHistory[0].previousBest.rebuiltSha256, 'same-build');

  const legacy = {
    schemaVersion: 1, target: { path: 'x', sha256: 'a', size: 1 }, iterations: [], budget: 2,
    best: { iteration: 1, overall: 0.99, gatePassed: false, sourceSha256: 's', rebuiltSha256: 'b' },
  };
  assert.equal(migrateLoopState(legacy).best, null);
  const current = { ...createLoopState(base), best: { iteration: 1, overall: 1, gatePassed: false, sourceSha256: 's', rebuiltSha256: 'b' } };
  delete current.lastCandidateDraftPath;
  const migrated = migrateLoopState(current);
  assert.equal(migrated.best, null, 'v2 migration reapplies the accepted-best contract');
  assert.equal(migrated.lastCandidateDraftPath, null);
  assert.equal(current.lastCandidateDraftPath, undefined, 'migration does not mutate the input');
});

test('a trace recorded for a different build is stale and cannot gate convergence', () => {
  const base = { targetPath: 'C://x.exe', targetSha256: 'a'.repeat(64), targetSize: 10, budget: 2 };
  const stale = createLoopState(base);
  stale.runtime = { score: 0.1, targetSha256: base.targetSha256, rebuiltSha256: 'old-build' };
  stale.lastBuildSha256 = 'new-build';
  recordIteration(stale, { sourceSha: 'source-sha', build: { ok: true }, rebuiltSha256: 'new-build', compare: fakeCompare({ overall: 1 }) });
  assert.equal(stale.status, 'converged', 'stale evidence is not evidence about this draft');

  const fresh = createLoopState(base);
  fresh.runtime = { score: 0.1, targetSha256: base.targetSha256, rebuiltSha256: 'same-build' };
  fresh.lastBuildSha256 = 'same-build';
  recordIteration(fresh, { sourceSha: 'source-sha', build: { ok: true }, rebuiltSha256: 'same-build', compare: fakeCompare({ overall: 1 }) });
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
  measure(state, {
    compare: fakeCompare({
      overall: 0.7,
      missing: ['createfilea'],
      mismatches: [{
        name: 'FUN_180001000', rva: '0x1000', similarity: 0.55, reason: 'below the structural semantic threshold',
        dossier: {
          name: 'FUN_180001000', exportName: 'SealedValue', rva: '0x1000', size: 64,
          cfg: { blocks: 3, edges: 3, conditionals: 1, loops: 0, maxFanout: 2 },
          calls: { callees: [{ name: 'memcpy', rva: '0x2000' }], callers: [] },
          references: [{ fromRva: '0x1010', toRva: '0x3000', type: 'DATA', string: 'sealed' }],
          referencesTruncated: false,
          pseudocode: 'undefined4 SealedValue(void) { return DAT_180003000; }',
        },
      }],
    }),
  });
  const brief = renderHandoff(state);
  assert.match(brief, /FUN_180001000 rva=0x1000 55\.0%/);
  assert.match(brief, /rea_decompile_address/);
  assert.match(brief, /## Function dossiers/);
  assert.match(brief, /FUN_180001000 \/ SealedValue/);
  assert.match(brief, /memcpy@0x2000/);
  assert.match(brief, /0x1010→0x3000 DATA sealed/);
  assert.match(brief, /return DAT_180003000/);
  assert.match(brief, /not a recovered parameter-flow proof/);
  assert.equal(state.iterations[0].compare.t2.mismatches[0].dossier.exportName, 'SealedValue');
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
    assert.match(await readFile(persisted.iterations[0].draftPath, 'utf8'), /return 1;/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('selected auto drafts use only fully decompiled requested functions despite unrelated failures', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-selected-auto-'));
  try {
    const specimen = await generateSpecimen({ tier: 'R0', outDir: dir });
    assert.equal(specimen.ok, true, specimen.build?.reason);
    const store = fakeStore(join(dir, 'state'));
    let observed;
    const listFunctions = async (_path, options) => {
      observed = options;
      return {
        ok: false, code: 'decompile-failed', reason: '1 unrelated function failed', total: 2, emitted: 2,
        enumerationComplete: true, inventoryComplete: false, failed: 1, truncated: false,
        functions: [
          { name: 'broken', rva: '0x1000', size: 8, body: '(decompile failed)', decompiled: false, cfg: { blocks: 1, edges: 0 } },
          { name: 'wanted', rva: '0x1010', size: 8, body: 'void wanted(void) { return; }', decompiled: true, cfg: { blocks: 1, edges: 0 } },
        ],
      };
    };
    const autoRepairRounds = async ({ startText, baselineSource }) => {
      assert.match(baselineSource, /wanted/);
      assert.doesNotMatch(baselineSource, /broken/);
      return {
        best: {
          sourceText: startText,
          built: await compileC({ sourceText: startText, workDir: join(dir, 'auto'), name: 'selected' }),
          compare: fakeCompare({ overall: 0.99 }),
        },
        history: [], firstFailure: null,
      };
    };
    const tool = buildReconstructTool({ store, ghidraReady: async () => ({ ready: true }), listFunctions, autoRepairRounds });
    await tool.execute({
      action: 'start', target: specimen.truth.targetPath, budget: 2,
      scope: 'selected-functions', functionNames: ['wanted'],
    });
    const sourcePath = join(dir, 'draft.c');
    await writeFile(sourcePath, specimen.truth.source, 'utf8');
    await tool.execute({ action: 'advance', target: specimen.truth.targetPath, source: sourcePath, draft: 'auto', engine: false });
    assert.equal(observed.allowDecompileFailures, true);
    const targetBuffer = await readFile(specimen.truth.targetPath);
    const sha = createHash('sha256').update(targetBuffer).digest('hex').slice(0, 12);
    const persisted = JSON.parse(await readFile(join(dir, 'state', `reconstruct-${sha}.json`), 'utf8'));
    assert.equal(persisted.iterations.length, 1);
    assert.equal(persisted.iterations[0].draftKind, 'source');
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
    assert.match(await readFile(persisted.iterations.at(-1).draftPath, 'utf8'), /GetComputerNameA/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
