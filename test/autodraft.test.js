import assert from 'node:assert/strict';
import test from 'node:test';

import { applyRewrites, lowestSimilarityMismatch, repairDraft, runAutoRepairRounds, toAutoHistory } from '../lib/restore/autodraft.js';

const draftSource = [
  'int helper(int x) { return x + 1; }',
  'int target_fn(int x) { return x - 1; }',
  'int main(void) { return helper(1); }',
].join('\n');

const baselineSource = [
  'int helper(int x) { return x + 1; }',
  'int target_fn(int x) { if (x > 3) { return x * 2; } return 0; }',
  'int binding_fn(void) { return CreateFileA("a", 0, 0, 0, 0, 0, 0); }',
  'int main(void) { return helper(1); }',
].join('\n');

test('a mismatched function is replaced by its decompiled body, and an absent one is added', () => {
  const repaired = repairDraft({
    sourceText: draftSource,
    baselineSource,
    mismatches: ['target_fn', 'not_in_baseline'],
  });
  assert.equal(repaired.changed, true);
  assert.deepEqual(repaired.replaced, ['target_fn']);
  assert.deepEqual(repaired.skipped, ['not_in_baseline']);
  assert.match(repaired.sourceText, /if \(x > 3\) \{ return x \* 2; \}/);
  assert.doesNotMatch(repaired.sourceText, /return x - 1;/);
  assert.match(repaired.sourceText, /int helper\(int x\) \{ return x \+ 1; \}/, 'untouched functions stay');
});

test('a missing import pulls in the baseline function that binds it, once', () => {
  const repaired = repairDraft({
    sourceText: draftSource,
    baselineSource,
    missingImports: ['createfilea'],
  });
  assert.deepEqual(repaired.added, ['binding_fn']);
  assert.match(repaired.sourceText, /CreateFileA/);
  // A second call must not duplicate the definition.
  const again = repairDraft({ sourceText: repaired.sourceText, baselineSource, missingImports: ['createfilea'] });
  assert.equal(again.changed, false);
});

test('a draft with nothing to repair is returned unchanged', () => {
  const repaired = repairDraft({ sourceText: draftSource, baselineSource, mismatches: ['helper'] });
  // helper exists in both and would be replaced with an identical body; the
  // function still counts as a substitution, but the text stays valid C.
  assert.equal(repaired.changed, true);
  assert.match(repaired.sourceText, /int helper\(int x\) \{ return x \+ 1; \}/);
  const untouched = repairDraft({ sourceText: draftSource, baselineSource });
  assert.equal(untouched.changed, false);
  assert.equal(untouched.sourceText, draftSource);
});

test('replacement text is inserted literally, not as a regex pattern', () => {
  const repaired = repairDraft({
    sourceText: 'int f(void) { return 0; }\n',
    baselineSource: 'int f(void) { return 1; /* $& $1 literal */ }\n',
    mismatches: ['f'],
  });
  assert.match(repaired.sourceText, /\$& \$1 literal/);
});

test('model-authored bodies replace only the named functions and must define them', () => {
  const applied = applyRewrites({
    sourceText: draftSource,
    rewrites: [{ name: 'target_fn', source: 'int target_fn(int x) { return x * 3; }' }],
  });
  assert.equal(applied.changed, true);
  assert.deepEqual(applied.applied, ['target_fn']);
  assert.match(applied.sourceText, /return x \* 3;/);
  assert.doesNotMatch(applied.sourceText, /return x - 1;/);
  assert.match(applied.sourceText, /int helper\(int x\) \{ return x \+ 1; \}/, 'other functions are untouched');

  const appended = applyRewrites({
    sourceText: draftSource,
    rewrites: [{ name: 'extra_fn', source: 'int extra_fn(void) { return 7; }' }],
  });
  assert.deepEqual(appended.appended, ['extra_fn']);
  assert.match(appended.sourceText, /int extra_fn\(void\)/);

  assert.match(applyRewrites({ sourceText: draftSource, rewrites: [] }).error, /non-empty/);
  assert.match(applyRewrites({ sourceText: draftSource, rewrites: [{ name: 'bad-name', source: 'int bad(void){return 0;}' }] }).error, /invalid function name/);
  assert.match(applyRewrites({ sourceText: draftSource, rewrites: [{ name: 'target_fn', source: 'int other(void){return 0;}' }] }).error, /does not define target_fn/);
});

test('a replacement keeps exactly one declaration, never a doubled return type', () => {
  const repaired = repairDraft({
    sourceText: 'int f(void) { return 0; }\n',
    baselineSource: 'static int f(void) { return 1; }\n',
    mismatches: ['f'],
  });
  assert.equal(repaired.sourceText.trim(), 'static int f(void) { return 1; }');
  assert.doesNotMatch(repaired.sourceText, /int\s+int/);
});

// ---------------------------------------------------------------------------
// draft=auto batch rollback: the loop orchestrator and its serialization.
// The fake comparisons mirror test/recon.test.js fakeCompare's shape.
// ---------------------------------------------------------------------------

function fakeComparison(overall, mismatches = [], { t1Missing = [] } = {}) {
  return {
    overall,
    tiers: {
      t1: {
        status: 'ran',
        score: overall,
        imports: { recall: t1Missing.length === 0 ? 1 : 0.5, precision: 1, missing: t1Missing, added: [] },
        strings: { recall: 1 },
        sections: { jaccard: 1 },
      },
      t2: { status: 'ran', score: overall, mismatches },
      t3: { status: 'ran', score: 1, unmatched: [] },
    },
    weightsUsed: { t1: 0.55, t2: 0.3, t3: 0.15 },
  };
}

/** A measure() that replays a scripted list of outcomes and records the drafts it was asked to compile. */
function scriptedMeasure(script) {
  const calls = [];
  const measure = async (sourceText, label) => {
    calls.push({ sourceText, label });
    const step = script[calls.length - 1];
    if (!step) throw new Error(`unexpected measure call #${calls.length}`);
    if (step.fail) return { ok: false, built: { ok: false, code: 'compile-failed', reason: step.reason ?? 'compile failed' } };
    return { ok: true, built: { ok: true, marker: `build-${calls.length}` }, comparison: step.comparison };
  };
  return { measure, calls };
}

const rollDraft = [
  'int alpha(int x) { return x + 1; }',
  'int beta(int x) { return x - 1; }',
  'int main(void) { return alpha(1) + beta(2); }',
].join('\n');

const rollBaseline = [
  'int alpha(int x) { if (x > 3) { return x * 2; } return 0; }',
  'int beta(int x) { while (x > 0) { x = x - 3; } return x; }',
  'int gamma(int x) { return x * 5; }',
  'int delta(int x) { return x * 7; }',
  'int main(void) { return alpha(1) + beta(2); }',
].join('\n');

const notSettledBelow = (threshold) => (comparison) => typeof comparison.overall === 'number' && comparison.overall >= threshold;

test('lowestSimilarityMismatch picks the least-trusted function, or nobody', () => {
  assert.equal(lowestSimilarityMismatch(null), null);
  assert.equal(lowestSimilarityMismatch(undefined), null);
  assert.equal(lowestSimilarityMismatch([]), null);
  assert.equal(lowestSimilarityMismatch([{ name: 'A', similarity: 0.8 }, { name: 'B', similarity: 0.4 }]), 'B');
  assert.equal(lowestSimilarityMismatch([{ name: 'A', reason: 'blocked' }, { name: 'B', similarity: 0.4 }]), 'B', 'reason entries never win');
  assert.equal(lowestSimilarityMismatch([{ name: 'A', reason: 'x' }, { name: 'B', reason: 'y' }]), null, 'no numeric similarity, no pick');
  assert.equal(lowestSimilarityMismatch([{ name: 'A', similarity: 0.4 }, { name: 'B', similarity: 0.4 }]), 'A', 'ties keep the first');
});

test('toAutoHistory keeps the retry marker through serialization and omits it otherwise', () => {
  const history = [
    { round: 1, overall: 0.5, replaced: ['alpha'], added: [] },
    { round: 2, overall: 0.65, replaced: ['beta'], added: [], retry: true },
  ];
  const serialized = toAutoHistory(history);
  assert.deepEqual(serialized[0], { round: 1, overall: 0.5, replaced: ['alpha'], added: [] });
  assert.equal('retry' in serialized[0], false, 'ordinary rounds carry no retry key');
  assert.deepEqual(serialized[1], { round: 2, overall: 0.65, replaced: ['beta'], added: [], retry: true });
  assert.equal(JSON.parse(JSON.stringify(serialized))[1].retry, true, 'the state-file round trip keeps the marker');
});

test('a null-overall first round keeps the real build and never fakes a failure', async () => {
  const { measure, calls } = scriptedMeasure([{ comparison: fakeComparison(null) }]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 1,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.best, null, 'an unmeasurable comparison is not an accepted best');
  assert.equal(result.candidate.built.marker, 'build-1', 'the real built artifact is kept as the measured candidate');
  assert.equal(result.candidate.compare.overall, null);
  assert.equal(result.firstFailure, null, 'a successful compile must not become auto-failed');
  assert.equal(result.history.length, 1);
  assert.equal(calls.length, 1);
});

test('a numeric round after a null one wins on the original comparison and rolls nothing back', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(null, [{ name: 'alpha', similarity: 0.6 }]) },
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.7 }]) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.best.compare.overall, 0.5, '0.5 beats null via the original ?? -1 rule');
  assert.equal(result.history.length, 2);
  assert.equal(result.history.some((item) => item.retry), false, 'a null-overall round is not a score drop');
  assert.equal(calls.length, 2, 'no rollback compile after a null-overall round');
});

test('a lower-scoring batch round rolls back and retries only the lowest-similarity function', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.6, [{ name: 'alpha', similarity: 0.8 }, { name: 'beta', similarity: 0.4 }]) },
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.7 }]) },
    { comparison: fakeComparison(0.65, []) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.history.length, 3);
  assert.equal(result.history[2].retry, true);
  assert.equal(result.history[2].round, 2, 'the retry keeps its numeric round');
  assert.deepEqual(result.history[2].replaced, ['beta'], 'only the lowest-similarity function is retried');
  assert.equal(result.best.compare.overall, 0.65);
  assert.equal(result.history.length, 3, 'auto.rounds === history.length (retry round included)');
  assert.equal(calls.length, 3, 'r1 + r2 + one retry compile, bounded');
  assert.match(calls[1].sourceText, /if \(x > 3\)/, 'the dropped round had replaced alpha');
  assert.match(calls[1].sourceText, /while \(x > 0\)/, 'the dropped round had replaced beta');
  assert.match(calls[2].sourceText, /while \(x > 0\)/, 'the retry draft keeps the beta replacement');
  assert.doesNotMatch(calls[2].sourceText, /if \(x > 3\)/, 'the retry draft rolls alpha back');
  assert.equal(toAutoHistory(result.history)[2].retry, true, 'the marker survives serialization');
});

test('a retry that still scores below the best leaves the best draft in place', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.6, [{ name: 'alpha', similarity: 0.8 }, { name: 'beta', similarity: 0.4 }]) },
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.7 }]) },
    { comparison: fakeComparison(0.55, []) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.best.sourceText, rollDraft, 'the best draft is untouched');
  assert.equal(result.best.compare.overall, 0.6);
  assert.equal(result.history.length, 3);
  assert.equal(result.history[2].retry, true);
  assert.equal(calls.length, 3);
});

test('steady improvement never triggers the rollback', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.6 }]) },
    { comparison: fakeComparison(0.7, []) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.7),
  });
  assert.equal(result.history.length, 2);
  assert.equal(result.history.some((item) => item.retry), false);
  assert.equal(result.best.compare.overall, 0.7);
  assert.equal(calls.length, 2);
});

test('a tie keeps the earlier best, and a later drop rolls back to that best draft', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.9 }]) },
    { comparison: fakeComparison(0.5, [{ name: 'gamma', similarity: 0.3 }, { name: 'delta', similarity: 0.7 }]) },
    { comparison: fakeComparison(0.4, []) },
    { comparison: fakeComparison(0.45, []) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 3,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.best.sourceText, rollDraft, 'the tie never updated the best');
  assert.equal(result.best.compare.overall, 0.5);
  assert.equal(result.history.length, 4);
  assert.equal(result.history[3].retry, true);
  assert.equal(calls.length, 4);
  assert.match(calls[3].sourceText, /return x \* 5;/, 'the rollback target is the best draft plus only gamma, the lowest-similarity mismatch from the previous round');
  assert.doesNotMatch(calls[3].sourceText, /return x \* 7;/, 'delta is not part of the single-function retry');
  assert.doesNotMatch(calls[3].sourceText, /if \(x > 3\)/, 'alpha is not part of the single-function retry');
});

test('a retry target outside the baseline is skipped without a doomed compile', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.8 }, { name: 'ghost', similarity: 0.1 }]) },
    { comparison: fakeComparison(0.4, []) },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(calls.length, 2, 'no compile is spent on a function the baseline cannot provide');
  assert.equal(result.history.length, 2);
  assert.equal(result.history.some((item) => item.retry), false);
  assert.equal(result.best.compare.overall, 0.5);
});

test('a failed retry compile keeps the best draft and adds no history entry', async () => {
  const { measure, calls } = scriptedMeasure([
    { comparison: fakeComparison(0.5, [{ name: 'alpha', similarity: 0.4 }]) },
    { comparison: fakeComparison(0.4, []) },
    { fail: true, reason: 'gcc exploded' },
  ]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(calls.length, 3);
  assert.equal(result.history.length, 2, 'no overall n/a entry for the failed retry');
  assert.equal(result.best.compare.overall, 0.5);
  assert.equal(result.best.sourceText, rollDraft);
});

test('a first-round compile failure is recorded and no best is claimed', async () => {
  const { measure, calls } = scriptedMeasure([{ fail: true, reason: 'no compiler' }]);
  const result = await runAutoRepairRounds({
    startText: rollDraft,
    baselineSource: rollBaseline,
    rounds: 2,
    measure,
    isSettled: notSettledBelow(0.9),
  });
  assert.equal(result.best, null);
  assert.equal(result.history.length, 0);
  assert.notEqual(result.firstFailure, null, 'the caller records the failure instead of inventing auto-failed');
  assert.equal(result.firstFailure.ok, false);
  assert.equal(result.firstFailure.reason, 'no compiler');
  assert.equal(calls.length, 1);
});
