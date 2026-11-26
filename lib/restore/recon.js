/**
 * The reconstruction loop: evidence in, drafts out, terminal state always.
 *
 * A reverse engineer's loop is not a report - it is a sequence of falsifiable
 * attempts. Each iteration compiles a draft and compares it with the target;
 * the gaps are the next iteration's work list. This module owns the parts that
 * must not depend on the model's optimism:
 *
 *   - the budget, so the loop cannot run forever;
 *   - the convergence rule, measured on the comparison tiers, not on prose;
 *   - the terminal states, each with a product: converged, budget-exhausted,
 *     blocked, unreachable;
 *   - an empty measurement is a failure, not a 100% (the 1.8.10 gate lesson).
 *
 * The compiler and the comparison are separate modules; this one is pure so
 * the rules can be tested without building anything.
 *
 * @module dsh-rea-restore/lib/recon
 */

export const CONVERGENCE = 0.98;
const DEFAULT_BUDGET = 5;
const MAX_BUDGET = 20;

const pct = (value) => (typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : 'n/a');

export function createLoopState({
  targetPath, targetSha256, targetSize, unresolvedRegions = 0, sealed = false, budget = DEFAULT_BUDGET,
  scope = 'whole-program', functionNames = [], convergenceScope = 'static', deadlineMs = null,
} = {}) {
  const at = new Date().toISOString();
  const scopeKind = typeof scope === 'string' ? scope : scope?.kind;
  if (!['whole-program', 'selected-functions'].includes(scopeKind)) throw new Error('scope must be whole-program or selected-functions');
  if (!['static', 'runtime'].includes(convergenceScope)) throw new Error('convergenceScope must be static or runtime');
  const names = [...new Set((Array.isArray(functionNames) ? functionNames : []).map((name) => String(name)).filter(Boolean))];
  if (scopeKind === 'selected-functions' && names.length === 0) throw new Error('selected-functions scope requires at least one function name');
  const iterations = Math.max(1, Math.min(MAX_BUDGET, Number.isFinite(budget) ? Math.floor(budget) : DEFAULT_BUDGET));
  const duration = deadlineMs === null ? null : Math.max(1, Math.floor(Number(deadlineMs)));
  if (deadlineMs !== null && !Number.isFinite(duration)) throw new Error('deadlineMs must be a finite positive number');
  return {
    schemaVersion: 2,
    createdAt: at,
    updatedAt: at,
    startedAt: at,
    target: { path: targetPath, sha256: targetSha256, size: targetSize },
    analysisTarget: { kind: 'original', path: targetPath, sha256: targetSha256, derivedFromEvidenceId: null },
    scope: { kind: scopeKind, functionNames: names },
    convergenceScope,
    intake: {
      unresolvedRegions,
      sealed,
      note: unresolvedRegions > 0
        ? `${unresolvedRegions} high-entropy region(s) carry no recoverable key material; a draft can reproduce the decoder but not the sealed values`
        : null,
    },
    budget: { iterations, deadlineMs: duration, startedAt: at },
    iterations: [],
    best: null,
    lastCandidateDraftPath: null,
    status: 'running',
    reason: null,
    gate: null,
    evidenceRefs: [],
    reopenHistory: [],
  };
}

function acceptedBest(best) {
  return best?.gatePassed === true
    && Number.isFinite(best.overall) && best.overall >= CONVERGENCE
    && typeof best.sourceSha256 === 'string' && best.sourceSha256.length > 0
    && typeof best.rebuiltSha256 === 'string' && best.rebuiltSha256.length > 0
    ? best : null;
}

export function migrateLoopState(state) {
  if (![1, 2].includes(state?.schemaVersion) || !state?.target || !Array.isArray(state?.iterations)) {
    throw new Error('unsupported reconstruction state schema; start a new loop');
  }
  const startedAt = state.startedAt ?? state.createdAt ?? new Date().toISOString();
  return {
    ...state,
    schemaVersion: 2,
    startedAt,
    analysisTarget: state.analysisTarget ?? { kind: 'original', path: state.target.path, sha256: state.target.sha256, derivedFromEvidenceId: null },
    scope: state.scope ?? { kind: 'whole-program', functionNames: [] },
    convergenceScope: state.convergenceScope ?? 'static',
    budget: state.budget ?? { iterations: DEFAULT_BUDGET, deadlineMs: null, startedAt },
    gate: state.gate ?? null,
    evidenceRefs: state.evidenceRefs ?? [],
    reopenHistory: state.reopenHistory ?? [],
    lastCandidateDraftPath: state.lastCandidateDraftPath ?? null,
    best: acceptedBest(state.best),
  };
}

export function runtimeEvidenceFresh(state, rebuiltSha256 = state.lastBuildSha256) {
  const runtime = state.runtime;
  return Boolean(
    runtime
    && typeof runtime.targetSha256 === 'string'
    && runtime.targetSha256 === (state.analysisTarget?.sha256 ?? state.target?.sha256)
    && typeof runtime.rebuiltSha256 === 'string'
    && runtime.rebuiltSha256 === rebuiltSha256
    && rebuiltSha256 === state.lastBuildSha256,
  );
}

export function evaluateConvergence(state, {
  draftKind = 'source', build = null, compare = null, rebuiltSha256 = state.lastBuildSha256 ?? null, now = Date.now(),
} = {}) {
  const failedGates = [];
  const add = (gate) => failedGates.push(gate);
  if (draftKind !== 'source') add('source-draft-required');
  if (build?.ok !== true) add(build?.code === 'unavailable' ? 'build-unavailable' : 'build-failed');
  else if (typeof rebuiltSha256 !== 'string' || rebuiltSha256.length === 0) add('rebuild-unbound');
  if (!compare || !Number.isFinite(compare.overall)) add('compare-unmeasurable');
  else if (compare.overall < CONVERGENCE) add('overall-threshold');

  const t2 = compare?.tiers?.t2;
  if (t2?.status !== 'ran' || !Number.isFinite(t2.score)) add('t2-unmeasured');
  else {
    if (t2.score < 0.9) add('t2-threshold');
    if (!Number.isFinite(t2.functions) || t2.functions <= 0) add('t2-empty');
    if (t2.scope === 'entry' || !['all-functions', 'selected-functions'].includes(t2.scope)) add('t2-entry-or-unknown-scope');
    if (t2.truncated === true || t2.timeStopped === true || t2.analysisTimedOut === true) add('t2-partial');
    if (state.scope?.kind === 'whole-program') {
      if (t2.inventoryComplete !== true) add('t2-partial');
      if (Number.isFinite(t2.failed) && t2.failed > 0) add('t2-decompile-failed');
      if (t2.scope !== 'all-functions') add('whole-program-scope-mismatch');
    } else {
      const requested = state.scope.functionNames ?? [];
      const coverage = t2.selectedCoverage;
      const measuredSelection = coverage?.complete === true && coverage.requested === requested.length
        && ['target', 'rebuilt'].every((side) => {
          const item = coverage[side];
          return item?.complete === true && item.found === requested.length && item.decompiled === requested.length
            && item.missing?.length === 0 && item.failed?.length === 0 && item.ambiguous?.length === 0;
        });
      if (t2.scope !== 'selected-functions') add('selected-functions-scope-mismatch');
      const coverageBound = measuredSelection && t2.inventoryEnumerationComplete === true;
      if (coverage ? !coverageBound : t2.inventoryComplete !== true) add('selected-functions-inventory-incomplete');
      if (Number.isFinite(t2.failed) && t2.failed > 0 && (t2.inventoryComplete === true || !measuredSelection)) add('t2-decompile-failed');
      if (requested.length === 0 || t2.matched !== requested.length || t2.functions !== requested.length || t2.coverage !== 1) add('selected-functions-incomplete');
      if (t2.belowThreshold !== 0) add('selected-functions-below-threshold');
    }
  }

  const thresholdTier = (tier, name) => {
    if (tier?.status !== 'ran') {
      if (state.requestedTiers?.[name] === true) add(`${name}-unmeasured`);
      return;
    }
    if (!Number.isFinite(tier.score)) add(`${name}-unmeasurable`);
    else if (tier.score < 0.9) add(`${name}-threshold`);
  };
  thresholdTier(compare?.tiers?.payload, 'payload');
  thresholdTier(compare?.tiers?.t3, 't3');
  thresholdTier(compare?.tiers?.t4, 'behavior');
  thresholdTier(compare?.tiers?.t5, 'interaction');
  const t1 = compare?.tiers?.t1;
  if (t1?.status !== 'ran') add('t1-unmeasured');
  else if (!Number.isFinite(t1.score)) add('t1-unmeasurable');
  else {
    if (t1.score < 0.9) add('t1-threshold');
    if (t1.imports && !Number.isFinite(t1.imports.recall) && !Number.isFinite(t1.imports.precision)) {
      // A zero-import target is still measurable through its section structure;
      // the empty import sets stay visible instead of being called a perfect match.
    }
    if (Number.isFinite(t1.imports?.recall) && t1.imports.recall < 0.95) add('t1-recall-threshold');
    if (Number.isFinite(t1.imports?.precision) && t1.imports.precision < 0.9) add('t1-precision-threshold');
  }

  const freshRuntime = runtimeEvidenceFresh(state, rebuiltSha256);
  if (state.convergenceScope === 'runtime') {
    if (!freshRuntime) add('runtime-unbound-or-stale');
    else if (!Number.isFinite(state.runtime.score) || state.runtime.score < 0.9) add('runtime-threshold');
  } else if (freshRuntime && (!Number.isFinite(state.runtime.score) || state.runtime.score < 0.9)) {
    add('runtime-counterevidence');
  }
  if (state.budget?.deadlineMs !== null && state.budget?.deadlineMs !== undefined) {
    const deadline = Date.parse(state.budget.startedAt) + state.budget.deadlineMs;
    if (!Number.isFinite(deadline) || now >= deadline) add('budget-deadline');
  }
  return {
    passed: failedGates.length === 0,
    failedGates,
    claimScope: state.scope?.kind === 'selected-functions'
      ? `selected-functions${state.convergenceScope === 'runtime' ? '+runtime' : ''}`
      : `whole-program${state.convergenceScope === 'runtime' ? '+runtime' : ''}`,
  };
}

/**
 * Turn a comparison into ranked gaps. Every gap names what would settle it;
 * a gap with no confirmation path is a wish, not a work item.
 */
const UPSTREAM_ALTERNATES = {
  'functions-mismatched': ['verify_reconstruction'],
  'entry-pseudocode': ['verify_reconstruction'],
  'literals-unmatched': ['verify_reconstruction'],
  'imports-missing': ['evaluate_reconstruction_coverage'],
  'imports-added': ['evaluate_reconstruction_coverage'],
  'payload-missing': ['evaluate_reconstruction_coverage'],
  'payload-fabricated': ['evaluate_reconstruction_coverage'],
  'behavior-outputs-missing': ['evaluate_reconstruction_coverage'],
  'behavior-outputs-fabricated': ['evaluate_reconstruction_coverage'],
  'behavior-state-missing': ['evaluate_reconstruction_coverage'],
  'behavior-state-fabricated': ['evaluate_reconstruction_coverage'],
  'behavior-effects-missing': ['evaluate_reconstruction_coverage'],
  'behavior-effects-fabricated': ['evaluate_reconstruction_coverage'],
  'interaction-windows-missing': ['evaluate_reconstruction_coverage'],
  'interaction-windows-fabricated': ['evaluate_reconstruction_coverage'],
  'interaction-messages-missing': ['evaluate_reconstruction_coverage'],
  'interaction-messages-fabricated': ['evaluate_reconstruction_coverage'],
  'interaction-controls-missing': ['evaluate_reconstruction_coverage'],
  'interaction-controls-fabricated': ['evaluate_reconstruction_coverage'],
  'interaction-resources-missing': ['evaluate_reconstruction_coverage'],
  'interaction-resources-fabricated': ['evaluate_reconstruction_coverage'],
};

const readGap = (tool, requiredArgs = []) => Object.freeze({
  tool, action: null, requiredArgs, policy: 'read', confirm: false, blockedReason: null,
});
const compileGap = (tool, requiredArgs = []) => Object.freeze({
  tool, action: null, requiredArgs, policy: 'compile', confirm: false, blockedReason: null,
});

/** Every comparison gap names a registered first-party tool and its real inputs. */
export const GAP_EXECUTABLES = Object.freeze({
  'imports-missing': readGap('rea_triage', ['path']),
  'imports-added': readGap('rea_triage', ['path']),
  'functions-mismatched': readGap('rea_decompile_address', ['path', 'address']),
  'entry-pseudocode': readGap('rea_decompile_address', ['path', 'address']),
  't2-blocked': readGap('rea_doctor'),
  'literals-unmatched': readGap('rea_ioc_extract', ['path']),
  'payload-missing': readGap('rea_ioc_extract', ['path']),
  'payload-fabricated': readGap('rea_ioc_extract', ['path']),
  'behavior-outputs-missing': readGap('rea_decompile_address', ['path', 'address']),
  'behavior-outputs-fabricated': readGap('rea_ioc_extract', ['path']),
  'behavior-state-missing': readGap('rea_triage', ['path']),
  'behavior-state-fabricated': readGap('rea_ioc_extract', ['path']),
  'behavior-effects-missing': readGap('rea_triage', ['path']),
  'behavior-effects-fabricated': readGap('rea_ioc_extract', ['path']),
  'interaction-windows-missing': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-windows-fabricated': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-messages-missing': readGap('rea_decompile_address', ['path', 'address']),
  'interaction-messages-fabricated': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-controls-missing': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-controls-fabricated': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-resources-missing': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'interaction-resources-fabricated': compileGap('rea_compare_build', ['target', 'rebuilt', 'interaction']),
  'hypothesis-refuted': Object.freeze({
    tool: 'rea_reconstruct', action: 'hypothesis-check',
    requiredArgs: ['target', 'action', 'hypothesis'],
    policy: 'compile', confirm: false, blockedReason: null,
  }),
});

function gapExecutable(id, blockedReason = null) {
  const spec = GAP_EXECUTABLES[id];
  if (!spec) throw new Error(`gap "${id}" has no executable mapping`);
  return { ...spec, blockedReason: blockedReason ?? null };
}

export function gapsFromComparison(result, { availableTools = null } = {}) {
  const gaps = [];
  const t1 = result.tiers.t1;
  if (t1.status === 'ran') {
    const imports = t1.imports;
    if (imports.recall !== null && imports.recall < 0.95 && imports.missing.length > 0) {
      gaps.push({
        id: 'imports-missing', tier: 'T1',
        detail: `${imports.missing.length} target import(s) are absent from the rebuild: ${imports.missing.slice(0, 6).join(', ')}`,
        action: 'Restore the code path that binds these imports; if the loader resolves them by hash, restore that table instead',
        confirm: 'inspect_with_objdump on the import table',
      });
    }
    if (imports.precision !== null && imports.precision < 0.9 && imports.added.length > 0) {
      gaps.push({
        id: 'imports-added', tier: 'T1',
        detail: `the rebuild imports ${imports.added.length} name(s) the target does not: ${imports.added.slice(0, 6).join(', ')}`,
        action: 'Remove invented capabilities; a function with no target counterpart is fabricated evidence and is scored against',
        confirm: 'inspect_with_objdump on the rebuild',
      });
    }
  }
  const t2 = result.tiers.t2;
  if (t2.status === 'ran' && typeof t2.score === 'number' && t2.score < 0.9) {
    const mismatchList = (t2.mismatches ?? []).slice(0, 5)
      .map((item) => (item.reason ? `${item.name} (${item.reason})` : `${item.name} ${(item.similarity * 100).toFixed(0)}%`));
    const scope = t2.scope === 'all-functions'
      ? `function inventory similarity ${pct(t2.score)}${typeof t2.coverage === 'number' ? `, coverage ${pct(t2.coverage)}` : ''}`
      : `entry pseudocode similarity ${pct(t2.score)}`;
    gaps.push({
      id: t2.scope === 'all-functions' ? 'functions-mismatched' : 'entry-pseudocode', tier: 'T2',
      detail: `${scope}${mismatchList.length > 0 ? `; first mismatches: ${mismatchList.join(' | ')}` : ''}`,
      action: t2.scope === 'all-functions'
        ? 'Redraft the mismatched functions first, lowest similarity first; confirm each against its decompilation before changing anything else'
        : 'Compare the two entry decompilations side by side; the first differing basic block is the next function to redraft',
      confirm: 'rea_decompile_address on each mismatch RVA',
    });
  } else if (t2.status === 'blocked') {
    gaps.push({
      id: 't2-blocked', tier: 'T2', blocked: t2.reason,
      detail: `the function tier did not run: ${t2.reason}`,
      action: 'Repair or install the decompiler, or continue with T1/T3 and record the reduced coverage',
      confirm: null,
    });
  }
  const t3 = result.tiers.t3;
  if (t3.status === 'ran' && typeof t3.score === 'number' && t3.score < 1 && t3.unmatched.length > 0) {
    gaps.push({
      id: 'literals-unmatched', tier: 'T3',
      detail: `source literals not observed in the target: ${t3.unmatched.slice(0, 6).join(' | ')}`,
      action: 'Decode the target region that should hold each literal; a literal the target cannot contain is a fabrication, not a gap',
      confirm: 'rea_ioc_extract with detail=true',
    });
  }
  const payload = result.tiers.payload ?? null;
  if (payload?.status === 'ran') {
    if (payload.score !== null && payload.score < 0.9) {
      gaps.push({
        id: 'payload-missing', tier: 'T1-payload',
        detail: `payload indicators coverage ${pct(payload.indicators.recall)}, precision ${pct(payload.indicators.precision)}; missing: ${(payload.indicators.missing ?? []).slice(0, 6).join(' | ')}`,
        action: 'Recover the missing indicators from the target: plaintext ones belong in the source; encoded ones need the decode channels before they can appear in a draft',
        confirm: 'rea_ioc_extract with detail=true, then the decode plan from rea_triage',
      });
    }
    if (payload.indicators.precision !== null && payload.indicators.precision < 0.9 && (payload.indicators.added ?? []).length > 0) {
      gaps.push({
        id: 'payload-fabricated', tier: 'T1-payload',
        detail: `the rebuild carries ${payload.indicators.added.length} indicator(s) the target does not: ${payload.indicators.added.slice(0, 6).join(' | ')}`,
        action: 'Remove invented indicators; a value with no target counterpart is fabricated evidence and is scored against',
        confirm: 'rea_ioc_extract on the target to check each value',
      });
    }
  }
  const t4 = result.tiers.t4 ?? null;
  if (t4?.status === 'ran') {
    const dimensions = [
      ['outputs', 'output literals', 'rea_decompile_address on the call site that prints each message'],
      ['state', 'state names', 'rea_triage with strings enabled, then match each name against the target'],
      ['effects', 'side-effect families', 'inspect_with_objdump on the import table'],
    ];
    for (const [key, label, confirm] of dimensions) {
      const dimension = t4[key];
      if (!dimension) continue;
      if (dimension.recall !== null && dimension.recall < 0.9 && dimension.missing.length > 0) {
        gaps.push({
          id: `behavior-${key}-missing`, tier: 'T4',
          detail: `${label} in the target but not in the rebuild: ${dimension.missing.slice(0, 6).join(' | ')}`,
          action: `Restore the code path that produces these ${label}; behaviour that vanished is a missing branch, not a formatting difference`,
          confirm,
        });
      }
      if (dimension.precision !== null && dimension.precision < 0.9 && dimension.added.length > 0) {
        gaps.push({
          id: `behavior-${key}-fabricated`, tier: 'T4',
          detail: `the rebuild declares ${dimension.added.length} ${label} the target does not: ${dimension.added.slice(0, 6).join(' | ')}`,
          action: 'Remove the invented behaviour; an effect or message with no target counterpart is fabricated evidence and is scored against',
          confirm: 'rea_ioc_extract on the target to check each value',
        });
      }
    }
  }
  const t5 = result.tiers.t5 ?? null;
  if (t5?.status === 'ran') {
    const dimensions = [
      ['windows', 'window/dialog facts', 'rea_compare_build with interaction=true'],
      ['messages', 'window messages', 'rea_decompile_address on the window procedure'],
      ['controls', 'control/timer ids', 'rea_compare_build with interaction=true'],
      ['resources', 'resource ids', 'rea_compare_build with interaction=true'],
    ];
    for (const [key, label, confirm] of dimensions) {
      const dimension = t5[key];
      if (!dimension) continue;
      if (dimension.recall !== null && dimension.recall < 0.9 && dimension.missing.length > 0) {
        gaps.push({
          id: `interaction-${key}-missing`, tier: 'T5',
          detail: `${label} in the target but not in the rebuild: ${dimension.missing.slice(0, 6).join(' | ')}`,
          action: `Restore the code path that declares these ${label}; a dropped message handler or control id is a missing branch, not a formatting difference`,
          confirm,
        });
      }
      if (dimension.precision !== null && dimension.precision < 0.9 && dimension.added.length > 0) {
        gaps.push({
          id: `interaction-${key}-fabricated`, tier: 'T5',
          detail: `the rebuild declares ${dimension.added.length} ${label} the target does not: ${dimension.added.slice(0, 6).join(' | ')}`,
          action: 'Remove the invented interaction surface; a window, message or control id with no target counterpart is fabricated evidence and is scored against',
          confirm: 'rea_compare_build with interaction=true on the target itself',
        });
      }
    }
  }
  // Upstream analyzers are only named when the host actually advertises them;
  // a confirm path into a tool that is not registered is advice nobody can
  // follow. The local path stays first.
  for (const gap of gaps) gap.executable = gapExecutable(gap.id, gap.blocked);
  // Upstream analyzers are only named when the host actually advertises them;
  // a confirm path into a tool that is not registered is advice nobody can
  // follow. The local path stays first.
  if (availableTools && typeof availableTools.has === 'function') {
    for (const gap of gaps) {
      const alternates = (UPSTREAM_ALTERNATES[gap.id] ?? []).filter((tool) => availableTools.has(tool));
      if (alternates.length > 0) gap.alternates = alternates;
    }
  }
  return gaps;
}

function slim(result) {
  const t1 = result.tiers.t1;
  const payload = result.tiers.payload ?? { status: 'empty', score: null, strings: {} };
  return {
    overall: result.overall,
    t1: {
      status: t1.status,
      score: t1.score,
      importsRecall: t1.status === 'ran' ? t1.imports.recall : null,
      importsPrecision: t1.status === 'ran' ? t1.imports.precision : null,
      sectionsJaccard: t1.status === 'ran' ? t1.sections.jaccard : null,
    },
    payload: {
      status: payload.status,
      score: payload.score,
      indicatorsRecall: payload.status === 'ran' ? payload.indicators.recall : null,
      indicatorsPrecision: payload.status === 'ran' ? payload.indicators.precision : null,
      missing: payload.status === 'ran' ? (payload.indicators.missing ?? []).slice(0, 10) : [],
      added: payload.status === 'ran' ? (payload.indicators.added ?? []).slice(0, 10) : [],
    },
    t2: {
      status: result.tiers.t2.status,
      score: result.tiers.t2.score,
      reason: result.tiers.t2.reason,
      scope: result.tiers.t2.scope ?? null,
      coverage: result.tiers.t2.coverage ?? null,
      matched: result.tiers.t2.matched ?? null,
      functions: result.tiers.t2.functions ?? null,
      belowThreshold: result.tiers.t2.belowThreshold ?? null,
      inventoryComplete: result.tiers.t2.inventoryComplete ?? null,
      failed: result.tiers.t2.failed ?? null,
      truncated: result.tiers.t2.truncated ?? null,
      timeStopped: result.tiers.t2.timeStopped ?? null,
      analysisTimedOut: result.tiers.t2.analysisTimedOut ?? null,
      pageSize: result.tiers.t2.pageSize ?? null,
      pages: result.tiers.t2.pages ?? null,
      // Double report: the undeducted window average and the denominator the
      // deduction removed functions from, so the loop's own record shows both.
      scoreAll: result.tiers.t2.scoreAll ?? null,
      denominator: result.tiers.t2.denominator ?? null,
      deductedTotal: result.tiers.t2.deductedTotal ?? null,
      mismatches: (result.tiers.t2.mismatches ?? []).slice(0, 12).map((item) => ({
        name: item.name,
        rva: item.rva ?? null,
        similarity: item.similarity ?? null,
        reason: item.reason ?? null,
        dossier: item.dossier ?? null,
      })),
    },
    t3: { status: result.tiers.t3.status, score: result.tiers.t3.score, unmatched: result.tiers.t3.unmatched ?? [] },
    t4: {
      status: result.tiers.t4?.status ?? 'skipped',
      score: result.tiers.t4?.score ?? null,
      outputs: result.tiers.t4?.outputs?.score ?? null,
      state: result.tiers.t4?.state?.score ?? null,
      effects: result.tiers.t4?.effects?.score ?? null,
    },
    t5: {
      status: result.tiers.t5?.status ?? 'skipped',
      score: result.tiers.t5?.score ?? null,
      windows: result.tiers.t5?.windows?.score ?? null,
      messages: result.tiers.t5?.messages?.score ?? null,
      controls: result.tiers.t5?.controls?.score ?? null,
      resources: result.tiers.t5?.resources?.score ?? null,
      inventoryComplete: result.tiers.t5?.inventoryComplete ?? null,
      inventoryTruncated: result.tiers.t5?.inventoryTruncated ?? null,
      failed: result.tiers.t5?.failed ?? null,
      pages: result.tiers.t5?.pages ?? null,
    },
    weightsUsed: result.weightsUsed,
  };
}

/**
 * Append one iteration and decide the state's exit.
 *
 * Convergence requires the measured tiers to agree: an overall number alone can
 * hide a missing import set (structural) behind a perfect literal score.
 */
export function recordIteration(state, { sourceSha, sourceChars, build, compare, draftKind = 'source', availableTools = null, rebuiltSha256 = build?.sha256 ?? null } = {}) {
  const at = new Date().toISOString();
  const boundRebuildSha256 = rebuiltSha256 ?? null;
  const gaps = compare ? gapsFromComparison(compare, { availableTools }) : [];
  // A hypothesis the target's own evidence refuted stays a live gap: it flows
  // into every later iteration until the claim is dropped or restated, so a
  // refuted attribution cannot quietly survive in the report.
  for (const hypothesis of state.hypotheses ?? []) {
    if (hypothesis?.status !== 'refuted') continue;
    gaps.push({
      id: 'hypothesis-refuted',
      tier: 'T4',
      detail: `hypothesis "${hypothesis.id}" was refuted by the target's own evidence: ${hypothesis.detail ?? hypothesis.statement}`,
      action: 'Drop the refuted claim or restate it with evidence the listing actually supports, then re-check it',
      confirm: 'rea_reconstruct action=hypothesis-check',
      executable: gapExecutable('hypothesis-refuted'),
    });
  }
  const iteration = {
    index: state.iterations.length + 1,
    at,
    draftKind,
    sourceSha: sourceSha ?? null,
    sourceChars: sourceChars ?? null,
    build: build
      ? { ok: build.ok, code: build.code, compiler: build.compiler ?? null, elapsedMs: build.elapsedMs ?? null, reason: build.reason ?? null, outPath: build.outPath ?? null, sha256: build.sha256 ?? null, size: build.size ?? null }
      : null,
    compare: compare ? slim(compare) : null,
    analysisTargetSha256: state.analysisTarget?.sha256 ?? state.target.sha256,
    gaps,
  };
  state.iterations.push(iteration);
  state.updatedAt = at;
  if (state.status !== 'running') {
    state.status = 'running';
    state.reason = null;
  }

  const overall = compare?.overall ?? null;
  if (build?.ok === true && Number.isFinite(overall) && typeof boundRebuildSha256 === 'string' && boundRebuildSha256.length > 0) {
    state.lastBuildSha256 = boundRebuildSha256;
  }
  const gate = evaluateConvergence(state, { draftKind, build, compare, rebuiltSha256: boundRebuildSha256 });
  if (gate.passed && (typeof sourceSha !== 'string' || sourceSha.length === 0)) {
    gate.passed = false;
    gate.failedGates.push('source-unbound');
  }
  iteration.gate = gate;
  state.gate = gate;
  if (gate.failedGates.includes('runtime-counterevidence')
    && state.best?.rebuiltSha256 === state.runtime?.rebuiltSha256) {
    state.reopenHistory.push({
      at, iteration: iteration.index, reason: 'runtime-counterevidence',
      previousBest: state.best,
    });
    state.reopenHistory = state.reopenHistory.slice(-20);
    state.best = null;
  }
  if (gate.passed && (state.best === null || overall > state.best.overall)) {
    state.best = {
      iteration: iteration.index,
      overall,
      gatePassed: true,
      sourceSha256: sourceSha,
      rebuiltSha256: boundRebuildSha256,
      draftPath: null,
      comparisonRef: `iteration:${iteration.index}`,
    };
  }
  if (gate.passed) {
    state.status = 'converged';
    state.reason = null;
    return state;
  }
  const staticUnreachable = state.intake.unresolvedRegions > 0 && !state.dynamic
    && ((compare?.tiers?.t3?.unmatched ?? []).length > 0 || state.intake.sealed);
  const coreMeasurementBlocked = gate.failedGates.some((name) => [
    'build-unavailable', 'rebuild-unbound', 'source-unbound', 'compare-unmeasurable', 't2-unmeasured', 't2-empty',
    't2-entry-or-unknown-scope', 't2-partial', 't2-decompile-failed',
    'whole-program-scope-mismatch', 'selected-functions-scope-mismatch', 'selected-functions-inventory-incomplete', 'selected-functions-incomplete',
  ].includes(name));
  if (staticUnreachable && !coreMeasurementBlocked) {
    state.status = 'unreachable';
    state.reason = 'the remaining gap needs values that never exist in the file: hand the sealed region to the dynamic plan';
    return state;
  }
  if (coreMeasurementBlocked) {
    state.status = 'blocked';
    state.reason = `convergence gate blocked: ${gate.failedGates.join(', ')}`;
    return state;
  }
  const measurementBlocked = gate.failedGates.some((name) => [
    't1-unmeasured', 't1-unmeasurable', 't3-unmeasured', 't3-unmeasurable',
    'behavior-unmeasured', 'interaction-unmeasured',
  ].includes(name));
  const budget = state.budget?.iterations ?? state.budget;
  const budgetSpent = gate.failedGates.includes('budget-deadline') || state.iterations.length >= budget;
  if (budgetSpent) {
    const t3Unmatched = (compare?.tiers?.t3?.unmatched ?? []).length;
    if (state.intake.unresolvedRegions > 0 && !state.dynamic && (t3Unmatched > 0 || state.intake.sealed)) {
      state.status = 'unreachable';
      state.reason = 'the remaining gap needs values that never exist in the file: hand the sealed region to the dynamic plan';
    } else {
      state.status = 'budget-exhausted';
      state.reason = gate.failedGates.includes('budget-deadline')
        ? 'the wall-clock budget is spent; the residual gaps are the report'
        : `the budget of ${budget} iteration(s) is spent; the residual gaps are the report`;
    }
    return state;
  }
  if (measurementBlocked) {
    state.status = 'blocked';
    state.reason = `convergence gate blocked: ${gate.failedGates.join(', ')}`;
    return state;
  }
  return state;
}

/**
 * Rank functions as decoder candidates for the dynamic probe.
 *
 * The heuristic is deliberately simple and explainable: a decoder writes
 * through a pointer argument, usually inside a loop, and is small enough that
 * hooking one function covers the whole decode. It proposes; the analyst (or
 * the policy gate) decides.
 */
export function rankDecoderCandidates(functions, { unresolvedBytes = null } = {}) {
  const candidates = [];
  const length = Number.isFinite(unresolvedBytes) && unresolvedBytes > 0
    ? Math.min(4096, unresolvedBytes)
    : 256;
  // The write has to be on the left of an assignment and has to name an
  // argument: `*(byte *)param_2 = ...`, `*param_2 = ...`, `param_2[i] = ...`.
  const writePattern = /(?:\*\s*\(\s*[A-Za-z_][\w ]*\*\s*\)\s*param_(\d)|\*param_(\d)|param_(\d)\s*\[[^\]]*\])\s*(?:=|\+=|\|=|\^=|<<=|>>=)/;
  for (const fn of functions ?? []) {
    if (!fn?.body || typeof fn.body !== 'string' || fn.body.length < 12) continue;
    if (Number.isFinite(fn.size) && fn.size > 1_200) continue;
    const write = fn.body.match(writePattern);
    const writesArg = write !== null;
    const argIndex = write
      ? Number(write[1] ?? write[2] ?? write[3] ?? 0)
      : 0;
    const readsArg = /param_\d\s*(?:\+|\[|\)|\*)/.test(fn.body);
    const loop = /\b(?:while|for)\b/.test(fn.body);
    // A byte transform is a write plus xor/shift work; a loop counter's `i += 1`
    // is not, so compound arithmetic alone is not enough.
    const transform = writesArg && (/\^=|<<=|>>=/.test(fn.body) || /\^\s*(?:0x[0-9a-f]+|\w+)/i.test(fn.body));
    let score = 0;
    const reasons = [];
    if (writesArg) { score += 0.5; reasons.push(`writes through argument ${argIndex}`); }
    if (transform) { score += 0.15; reasons.push('transforms bytes in place'); }
    if (loop) { score += 0.2; reasons.push('contains a loop'); }
    if (readsArg) { score += 0.05; reasons.push('reads an argument buffer'); }
    if (Number.isFinite(fn.size) && fn.size >= 20 && fn.size <= 600) { score += 0.1; reasons.push(`size ${fn.size} bytes`); }
    // A loop that only reads is too weak a signal to propose to an operator who
    // is about to execute the sample; a write or an in-place transform is not.
    if (!writesArg && !transform) continue;
    candidates.push({
      name: fn.name,
      rva: fn.rva,
      size: fn.size ?? null,
      score: Number(Math.min(1, score).toFixed(2)),
      reasons,
      argIndex: Number.isFinite(argIndex) ? Math.max(0, Math.min(7, argIndex)) : 0,
      length,
    });
  }
  return candidates.sort((a, b) => b.score - a.score || (a.size ?? 0) - (b.size ?? 0)).slice(0, 8);
}

/**
 * The handoff brief: everything a person or a model needs to write the next
 * draft, in one document. The loop cannot understand code, so the point where
 * understanding is required is made explicit and portable instead of implicit.
 */
export function renderHandoff(state) {
  const iteration = [...state.iterations].reverse().find((item) => item.compare
    && (item.analysisTargetSha256 ?? state.target.sha256) === (state.analysisTarget?.sha256 ?? state.target.sha256));
  if (!iteration) return null;
  const compare = iteration.compare;
  const lines = [
    `# Reconstruction brief — ${state.target.path}`,
    '',
    `- target sha256: ${state.target.sha256}`,
    `- analysis target: ${state.analysisTarget?.kind ?? 'original'} ${state.analysisTarget?.path ?? state.target.path} sha256=${state.analysisTarget?.sha256 ?? state.target.sha256}`,
    `- status: ${state.status}${state.reason ? ` (${state.reason})` : ''}`,
    `- overall: ${pct(compare.overall)}`,
    `- draft: ${iteration.draftPath ?? state.lastDraftPath ?? '(not persisted)'}`,
    '',
    '## Tier scores',
    '',
    `- T1 structure: ${pct(compare.t1?.score)}`,
    `- payload: ${compare.payload?.status === 'ran' ? pct(compare.payload.score) : compare.payload?.status ?? 'n/a'}`,
    `- T2 functions: ${compare.t2?.status === 'ran' ? pct(compare.t2.score) : compare.t2?.status ?? 'n/a'}`,
    ...(compare.t2?.scoreAll !== null && compare.t2?.scoreAll !== undefined
      ? [`  - undeducted (scoreAll): ${pct(compare.t2.scoreAll)}; denominator ${compare.t2.denominator?.before ?? 'n/a'} → ${compare.t2.denominator?.after ?? 'n/a'} (${compare.t2.deductedTotal ?? 0} toolchain functions deducted)`]
      : []),
    `- T3 literals: ${compare.t3?.status === 'ran' ? pct(compare.t3.score) : compare.t3?.status ?? 'n/a'}`,
    `- T4 behaviour: ${compare.t4?.status === 'ran' ? pct(compare.t4.score) : compare.t4?.status ?? 'n/a'}`,
    `- T5 interaction: ${compare.t5?.status === 'ran' ? pct(compare.t5.score) : compare.t5?.status ?? 'n/a'}`,
    ...(state.runtime ? [`- runtime trace: ${pct(state.runtime.score)}${state.runtime.score < 0.9 ? ' (disagrees)' : ''}`] : []),
    '',
    '## Open gaps',
    '',
  ];
  if (iteration.gaps.length === 0) lines.push('(none recorded for this iteration)');
  for (const gap of iteration.gaps) {
    lines.push(`- [${gap.tier}] ${gap.id}: ${gap.detail}`);
    lines.push(`  - next: ${gap.action}`);
    if (gap.confirm) lines.push(`  - confirm: ${gap.confirm}`);
    if (gap.alternates?.length) lines.push(`  - also: ${gap.alternates.join(', ')}`);
  }
  const hypotheses = state.hypotheses ?? [];
  if (hypotheses.length > 0) {
    lines.push('', '## Semantic hypotheses', '');
    for (const hypothesis of hypotheses) {
      const status = hypothesis.status ?? 'recorded';
      lines.push(`- [${status}] ${hypothesis.id}: ${hypothesis.statement}`);
      if (hypothesis.detail) lines.push(`  - check: ${hypothesis.detail}`);
      if (status === 'refuted') lines.push('  - next: drop or restate this claim; it is carried as a hypothesis-refuted gap');
      if (status === 'verified') lines.push('  - note: verified through the named channel only - the boundary recorded with the check still applies');
    }
  }
  const mismatches = compare.t2?.mismatches ?? [];
  lines.push('', '## Functions to rewrite', '');
  if (mismatches.length === 0) {
    lines.push('(no function-level mismatch recorded; T2 may be blocked or the inventory below threshold)');
  } else {
    for (const item of mismatches) {
      const similarity = typeof item.similarity === 'number' ? ` ${pct(item.similarity)}` : ` ${item.reason ?? ''}`;
      const rva = item.rva ? ` rva=${item.rva}` : '';
      lines.push(`- ${item.name}${rva}${similarity}${item.rva ? ` — decompile: rea_decompile_address({ target: "${state.analysisTarget?.path ?? state.target.path}", address: "${item.rva}" })` : ''}`);
    }
  }
  const dossiers = mismatches.filter((item) => item.dossier).slice(0, 12);
  if (dossiers.length > 0) {
    lines.push('', '## Function dossiers', '');
    for (const item of dossiers) {
      const dossier = item.dossier;
      const names = [dossier.name, dossier.exportName, item.name].filter(Boolean);
      const relatedHypotheses = hypotheses.filter((hypothesis) => names.includes(hypothesis.functionName));
      const relatedGaps = iteration.gaps.filter((gap) => gap.tier === 'T2');
      lines.push(`### ${dossier.name}${dossier.exportName ? ` / ${dossier.exportName}` : ''}`, '');
      lines.push(`- identity: ${dossier.name} | export: ${dossier.exportName ?? 'none'} | RVA: ${dossier.rva ?? 'n/a'} | size: ${dossier.size ?? 'n/a'}`);
      lines.push(`- CFG: ${JSON.stringify(dossier.cfg ?? null)}`);
      lines.push(`- callees: ${(dossier.calls?.callees ?? []).map((fn) => `${fn.name}@${fn.rva}`).join(', ') || 'none measured'}${dossier.calls?.calleesLimited ? ' (bounded)' : ''}`);
      lines.push(`- callers: ${(dossier.calls?.callers ?? []).map((fn) => `${fn.name}@${fn.rva}`).join(', ') || 'none measured'}${dossier.calls?.callersLimited ? ' (bounded)' : ''}`);
      lines.push(`- references: ${dossier.references.map((ref) => `${ref.fromRva}→${ref.toRva} ${ref.type}${ref.string ? ` ${ref.string}` : ''}`).join(', ') || 'none measured'}${dossier.referencesTruncated ? ' (bounded)' : ''}`);
      lines.push(`- current hypothesis: ${relatedHypotheses.length > 0 ? relatedHypotheses.map((hypothesis) => `${hypothesis.id} [${hypothesis.status ?? 'recorded'}] ${hypothesis.statement}`).join('; ') : 'none recorded'}`);
      lines.push(`- gap: ${item.reason ?? `similarity ${pct(item.similarity)}`}${relatedGaps[0]?.detail ? `; ${relatedGaps[0].detail}` : ''}`);
      lines.push(`- next: ${relatedGaps[0]?.action ?? 'rewrite this function, then recompile and rerun the same scoped comparison'}`);
      lines.push('', '```c', dossier.pseudocode || '(no pseudocode)', '```', '');
    }
    lines.push('Call targets and bounded references are evidence for review; they are not a recovered parameter-flow proof.', '');
  }
  lines.push(
    '',
    '## How to continue',
    '',
    '1. Rewrite only the functions listed above; leave the rest of the draft untouched.',
    '2. Submit it with `rea_reconstruct action=advance source=<file> behavior=true engine=true`.',
    '3. If a runtime trace exists, re-run `rea_trace_behavior` and `action=trace-apply`; the old trace is stale once the build changes.',
    '4. The comparison decides. A rewrite that lowers the score is not accepted as convergence.',
  );
  return lines.join('\n');
}

export function renderLoop(state) {
  const lines = [
    `Reconstruction loop — ${state.target.path}`,
    `sha256=${state.target.sha256.slice(0, 16)}… size=${state.target.size} budget=${state.budget?.iterations ?? state.budget} status=${state.status}`,
    ...(state.analysisTarget && state.analysisTarget.sha256 !== state.target.sha256
      ? [`analysis target: ${state.analysisTarget.kind} ${state.analysisTarget.path} sha256=${state.analysisTarget.sha256}`] : []),
    `scope: ${state.scope?.kind ?? 'whole-program'}${state.scope?.functionNames?.length ? ` (${state.scope.functionNames.join(', ')})` : ''}; convergence: ${state.convergenceScope ?? 'static'}`,
  ];
  if (state.intake.note) lines.push(`intake: ${state.intake.note}`);
  if (state.dynamic) {
    lines.push(`dynamic: ${state.dynamic.bytes} bytes dumped${state.dynamic.rva ? ` at ${state.dynamic.rva}` : ''}; ${state.dynamic.strings.length} string(s), ${state.dynamic.iocs.length} indicator(s) recovered`);
  }
  if (state.dynamicPlan?.candidates?.length) {
    lines.push(`dynamic plan: ${state.dynamicPlan.candidates.length} candidate(s) — ${state.dynamicPlan.candidates.slice(0, 4).map((item) => `${item.name}@${item.rva}`).join(', ')}`);
  }
  if (state.runtime) {
    const fresh = runtimeEvidenceFresh(state);
    const unbound = !fresh && (!state.runtime.targetSha256 || !state.runtime.rebuiltSha256);
    const verdict = unbound ? ' — unbound, cannot gate convergence' : !fresh ? ' — stale, recorded for a different build' : (typeof state.runtime.score === 'number' && state.runtime.score < 0.9 ? ' — disagrees, convergence blocked' : '');
    lines.push(`runtime: ${pct(state.runtime.score)}${verdict} (exit ${state.runtime.exitSame ? 'same' : 'different'}, stdout ${pct(state.runtime.stdout)}, files ${pct(state.runtime.files)})`);
  }
  if (state.hypotheses?.length) {
    const counts = {};
    for (const hypothesis of state.hypotheses) counts[hypothesis.status ?? 'recorded'] = (counts[hypothesis.status ?? 'recorded'] ?? 0) + 1;
    lines.push(`hypotheses: ${state.hypotheses.length} (${Object.entries(counts).map(([status, count]) => `${status} ${count}`).join(', ')})`);
    for (const hypothesis of state.hypotheses.filter((item) => item.status === 'refuted').slice(0, 4)) {
      lines.push(`  refuted: ${hypothesis.id} — ${hypothesis.detail ?? hypothesis.statement}`);
    }
  }
  if (state.intake.verdict) {
    const entry = state.intake.entryRva === null || state.intake.entryRva === undefined
      ? 'entry n/a'
      : `entry 0x${(state.intake.entryRva >>> 0).toString(16)}`;
    lines.push(`inventory: ${state.intake.verdict} · ${state.intake.imports ?? 0} imports · ${state.intake.strings ?? 0} strings · ${entry} · build ${state.intake.build ?? 'unknown'}`);
  }
  lines.push('');
  for (const iteration of state.iterations) {
    const build = iteration.build?.ok === true ? `built with ${iteration.build.compiler ?? 'compiler'}` : `build ${iteration.build?.code ?? 'n/a'}${iteration.build?.reason ? `: ${iteration.build.reason}` : ''}`;
    lines.push(`${iteration.index}. ${build} | overall ${pct(iteration.compare?.overall)} | T1 ${pct(iteration.compare?.t1?.score)} P ${iteration.compare?.payload?.status === 'ran' ? pct(iteration.compare.payload.score) : iteration.compare?.payload?.status ?? 'n/a'} T2 ${iteration.compare?.t2?.status === 'ran' ? pct(iteration.compare.t2.score) : iteration.compare?.t2?.status ?? 'n/a'} T3 ${iteration.compare?.t3?.status === 'ran' ? pct(iteration.compare.t3.score) : iteration.compare?.t3?.status ?? 'n/a'} T4 ${iteration.compare?.t4?.status === 'ran' ? pct(iteration.compare.t4.score) : iteration.compare?.t4?.status ?? 'n/a'} T5 ${iteration.compare?.t5?.status === 'ran' ? pct(iteration.compare.t5.score) : iteration.compare?.t5?.status ?? 'n/a'}${iteration.draftKind === 'baseline' ? ' | draft: baseline (floor, cannot converge)' : ''}`);
    if (iteration.compare?.t4?.status === 'ran') {
      lines.push(`   behaviour: outputs ${pct(iteration.compare.t4.outputs)} · state ${pct(iteration.compare.t4.state)} · effects ${pct(iteration.compare.t4.effects)}`);
    }
    if (iteration.compare?.t5?.status === 'ran') {
      lines.push(`   interaction: windows ${pct(iteration.compare.t5.windows)} · messages ${pct(iteration.compare.t5.messages)} · controls ${pct(iteration.compare.t5.controls)} · resources ${pct(iteration.compare.t5.resources)}`);
    }
    if (iteration.baseline) {
      lines.push(`   baseline draft: ${iteration.baseline.translated} translated, ${iteration.baseline.stubbed} stubbed, ${iteration.baseline.omitted} runtime-provided (${iteration.baseline.rounds} compile round(s))`);
    }
    if (iteration.auto) {
      const rounds = iteration.auto.history
        .map((item) => `r${item.round} ${pct(item.overall)}${item.replaced.length > 0 ? ` (replaced ${item.replaced.slice(0, 4).join(', ')}${item.replaced.length > 4 ? '…' : ''})` : ''}${item.retry ? ' single-function retry' : ''}`)
        .join(' → ');
      lines.push(`   auto draft: ${iteration.auto.rounds} round(s), started from ${iteration.auto.startedFromSource ? 'the analyst source' : 'the mechanical baseline'} — ${rounds}`);
    }
    if (iteration.floorNote) lines.push(`   ${iteration.floorNote}`);
    for (const gap of iteration.gaps) {
      lines.push(`   gap [${gap.tier}] ${gap.id}: ${gap.detail}${gap.blocked ? ` (blocked: ${gap.blocked})` : ''}`);
      lines.push(`     next: ${gap.action}${gap.confirm ? ` | confirm: ${gap.confirm}` : ''}${gap.alternates?.length ? ` | also: ${gap.alternates.join(', ')}` : ''}`);
    }
  }
  if (state.iterations.length === 0) lines.push('(no iterations yet: submit a draft source with action=advance)');
  lines.push('');
  if (state.status === 'running') {
    const budget = state.budget?.iterations ?? state.budget;
    lines.push(`next: submit a draft source (absolute path) with action=advance; ${budget - state.iterations.length} of ${budget} iterations remain.`);
    if (state.lastDraftPath) {
      lines.push(`auto resume: draft=auto without source continues from the last best draft (${state.lastDraftPath})`);
    }
  } else {
    lines.push(`terminal: ${state.status}${state.reason ? ` — ${state.reason}` : ''}`);
  }
  return lines.join('\n');
}
