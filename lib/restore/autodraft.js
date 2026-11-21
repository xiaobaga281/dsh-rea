/**
 * Automatic draft repair: turn the comparison's gaps into a new draft.
 *
 * The loop's correction step used to be manual by design - a person or a model
 * reads the gap list and rewrites the source. This module closes the mechanical
 * part of that step without inventing anything:
 *
 *   - a function the T2 tier reports as mismatched is replaced by the same
 *     function's decompiled translation from the mechanical baseline;
 *   - a function that binds a missing import is pulled in from the baseline,
 *     because the import gap is evidence that the call path exists in the
 *     target and is absent from the draft.
 *
 * Nothing is written from the model's imagination and no target value is
 * copied into the source to make a tier pass. Every replacement is a body the
 * decompiler produced from the target itself, and the next comparison decides
 * whether the substitution helped. If the score does not improve, the caller
 * keeps the previous draft.
 *
 * @module dsh-rea/lib/autodraft
 */

import { extractFunctionBlocks, extractSourceFunctions } from './compare.js';

const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Repair one draft.
 *
 * `mismatches` is a list of function names (T2), `missingImports` a list of
 * lowercased API names (T1). Both come from the comparison, never from a
 * heuristic guess.
 */
export function repairDraft({
  sourceText, baselineSource, mismatches = [], missingImports = [], maxFunctions = 6, maxImports = 4,
} = {}) {
  // Whole blocks, not just bodies: the replacement carries its own return type.
  const draft = extractFunctionBlocks(sourceText ?? '');
  const baseline = extractFunctionBlocks(baselineSource ?? '');
  const replaced = [];
  const added = [];
  const skipped = [];
  let next = String(sourceText ?? '');

  const place = (name) => {
    const body = baseline.get(name);
    if (!body) {
      skipped.push(name);
      return false;
    }
    if (draft.has(name)) {
      // A function replacer keeps `$&`-like sequences in decompiled bodies from
      // being interpreted as replacement patterns.
      next = next.replace(draft.get(name), () => body);
      replaced.push(name);
    } else {
      next = `${next.trimEnd()}\n\n${body}\n`;
      added.push(name);
    }
    draft.set(name, body);
    return true;
  };

  for (const name of mismatches) {
    if (replaced.length + added.length >= maxFunctions) break;
    place(String(name));
  }

  for (const api of missingImports) {
    if (added.length >= maxFunctions) break;
    if (typeof api !== 'string' || api.length === 0) continue;
    let pulled = 0;
    for (const [name, body] of baseline) {
      if (pulled >= maxImports) break;
      if (draft.has(name)) continue;
      const call = new RegExp(`\\b${escapeRegExp(api)}\\s*\\(`, 'i');
      if (!call.test(body)) continue;
      next = `${next.trimEnd()}\n\n${body}\n`;
      draft.set(name, body);
      added.push(name);
      pulled += 1;
    }
  }

  return {
    sourceText: next,
    replaced,
    added,
    skipped,
    changed: replaced.length + added.length > 0,
  };
}

/**
 * The lowest-similarity function in a T2 mismatch list, or null.
 *
 * The rollback retry replaces exactly one function: the one the comparison
 * trusts least. Entries without a numeric similarity (reason placeholders)
 * never win, and a null/empty list yields null so the caller skips the retry
 * instead of guessing a name.
 */
export function lowestSimilarityMismatch(mismatches) {
  if (!Array.isArray(mismatches)) return null;
  let lowest = null;
  for (const item of mismatches) {
    if (!item || typeof item.similarity !== 'number') continue;
    if (lowest === null || item.similarity < lowest.similarity) lowest = item;
  }
  return lowest === null ? null : lowest.name;
}

/**
 * Serialize the auto-repair history for the loop state.
 *
 * The state file is the contract: a retry round keeps its `retry: true` marker
 * through serialization, and ordinary rounds carry no retry key at all. Any new
 * per-round field must go through here or it will be silently dropped from the
 * persisted state.
 */
export function toAutoHistory(history = []) {
  return history.map((item) => ({
    round: item.round,
    overall: item.overall,
    replaced: item.replaced,
    added: item.added,
    ...(item.retry ? { retry: true } : {}),
  }));
}

/**
 * Run the draft=auto repair rounds.
 *
 * Extracted from the loop tool so the rollback behaviour is testable without a
 * compiler. `measure(sourceText, label)` compiles and compares one draft and
 * returns `{ ok: true, built, comparison }` or `{ ok: false, built?, code,
 * reason }`; `isSettled(comparison)` decides whether the loop may stop early.
 *
 * Best-draft protection is the loop's original rule, verbatim: a round becomes
 * the best only when its overall score is strictly higher (`?? -1` comparison,
 * so a null overall neither wins nor fakes a failure). When a round scores
 * lower than the best so far, the loop rolls back to that best draft and
 * retries once with only the lowest-similarity mismatched function replaced:
 * at most one extra compile, never a second rollback, and a retry that does
 * not beat the best is never accepted.
 */
export async function runAutoRepairRounds({
  startText, baselineSource, rounds = 2, measure, isSettled = () => false,
} = {}) {
  const history = [];
  let current = startText;
  let best = null;
  let firstFailure = null;
  let rollbackUsed = false;
  let prevMismatches = null;
  for (let round = 1; round <= rounds; round += 1) {
    const outcome = await measure(current, String(round));
    if (!outcome?.ok) {
      // Same as the original loop: only the first failure (before any best
      // exists) becomes the recorded build result.
      if (!best) firstFailure = outcome?.built ?? outcome ?? { ok: false, code: 'compile-failed' };
      break;
    }
    const comparison = outcome.comparison;
    const entry = { round, overall: comparison.overall, replaced: [], added: [] };
    history.push(entry);
    if (!best || (comparison.overall ?? -1) > (best.compare.overall ?? -1)) {
      best = { sourceText: current, built: outcome.built, compare: comparison };
    }
    if (isSettled(comparison)) break;
    // Rollback decision, made against the previous round's mismatch list - the
    // one that produced this lower-scoring draft. The typeof guard keeps a null
    // overall from ever counting as a drop.
    const dropped = best && best.compare !== comparison
      && typeof comparison.overall === 'number'
      && (comparison.overall ?? -1) < (best.compare.overall ?? -1);
    const lowest = lowestSimilarityMismatch(prevMismatches);
    if (dropped && !rollbackUsed && lowest) {
      rollbackUsed = true;
      const retryRepair = repairDraft({
        sourceText: best.sourceText,
        baselineSource,
        mismatches: [lowest],
        missingImports: [],
      });
      // The retry target is not in the baseline: skip the doomed compile.
      if (!retryRepair.changed) break;
      const retry = await measure(retryRepair.sourceText, `${round}-retry`);
      // Compile failed: the best stays, and no history entry is pushed (an
      // overall n/a entry would read as a measured round).
      if (!retry?.ok) break;
      const retryEntry = {
        round, overall: retry.comparison.overall, replaced: retryRepair.replaced, added: retryRepair.added, retry: true,
      };
      history.push(retryEntry);
      if (!best || (retry.comparison.overall ?? -1) > (best.compare.overall ?? -1)) {
        best = { sourceText: retryRepair.sourceText, built: retry.built, compare: retry.comparison };
        // The retry won: continue from it. The next round re-measures the same
        // text once - a deterministic repeat, and the total stays within
        // rounds+1 comparisons.
        current = retryRepair.sourceText;
        prevMismatches = retry.comparison.tiers.t2?.mismatches ?? [];
        continue;
      }
      break; // the retry did not beat the best: keep the best draft
    }
    const repair = repairDraft({
      sourceText: current,
      baselineSource,
      mismatches: (comparison.tiers.t2?.mismatches ?? []).map((item) => item.name),
      missingImports: comparison.tiers.t1?.status === 'ran' ? comparison.tiers.t1.imports.missing : [],
    });
    entry.replaced = repair.replaced;
    entry.added = repair.added;
    if (!repair.changed) break;
    prevMismatches = comparison.tiers.t2?.mismatches ?? [];
    current = repair.sourceText;
  }
  return { best, history, firstFailure };
}

/**
 * Apply model-authored function bodies to an existing draft.
 *
 * This is the model-in-the-loop primitive: the host model reads the handoff
 * brief, writes only the functions that were wrong, and submits them here. The
 * function names are the contract; every body must define the function it
 * claims to define, and the merged draft still has to compile and score higher
 * before anything is accepted.
 */
export function applyRewrites({ sourceText, rewrites = [], maxRewrites = 8, maxChars = 65_536 } = {}) {
  const base = String(sourceText ?? '');
  if (base.trim().length === 0) return { error: 'the base draft is empty' };
  if (!Array.isArray(rewrites) || rewrites.length === 0) return { error: 'rewrites must be a non-empty array' };
  if (rewrites.length > maxRewrites) return { error: `at most ${maxRewrites} functions can be rewritten in one call` };
  const draft = extractFunctionBlocks(base);
  const applied = [];
  const appended = [];
  let next = base;
  for (const item of rewrites) {
    const name = String(item?.name ?? '').trim();
    const code = String(item?.source ?? '');
    if (!/^[A-Za-z_]\w*$/.test(name)) return { error: `invalid function name "${name}"` };
    if (code.length === 0 || code.length > maxChars) return { error: `the body for ${name} is empty or over ${maxChars} characters` };
    if (!extractSourceFunctions(code).has(name)) return { error: `the body for ${name} does not define ${name}` };
    if (draft.has(name)) {
      next = next.replace(draft.get(name), () => code);
      applied.push(name);
    } else {
      next = `${next.trimEnd()}\n\n${code}\n`;
      appended.push(name);
    }
    draft.set(name, code);
  }
  return { sourceText: next, applied, appended, changed: applied.length + appended.length > 0 };
}
