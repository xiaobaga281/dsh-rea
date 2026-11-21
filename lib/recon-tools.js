/**
 * The reconstruction loop's comparison tool.
 *
 * One tool, one question: does the rebuilt binary match the target, tier by
 * tier, and where exactly does it not. The build itself is a separate step
 * (`compileC` in lib/build.js) because a tool that both compiles and compares
 * would hide which of the two failed.
 *
 * Read-only with respect to the samples: both files are read, the source is
 * read, and nothing is executed. The JSON report is written to the artifact
 * store for reuse across sessions.
 *
 * @module dsh-rea/lib/recon-tools
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';

import { buildReadiness, compileC } from './build.js';
import { applyRewrites, runAutoRepairRounds, toAutoHistory } from './autodraft.js';
import { buildBaseline, synthesizeDraft } from './baseline.js';
import { checkSemanticHypothesis, compareBuilds, floorFromSkeleton, measureToolchainFloor } from './compare.js';
import { decompileWithGhidra, ghidraLocalReadiness, listFunctionsWithGhidra } from './ghidra-local.js';
import { parsePEImports, extractIocs } from './intel.js';
import { createLoopState, CONVERGENCE, rankDecoderCandidates, recordIteration, renderHandoff, renderLoop } from './recon.js';
import { readPeLayout } from './structure.js';
import { extractDeepStrings } from './strings.js';
import { extractStrings, triageBuffer } from './triage.js';
import { markUntrusted, withRedactedOutput } from './tools.js';

const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const pct = (value) => (typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : 'n/a');

function render(result) {
  const lines = [
    `Rebuild comparison — ${result.target.path} ↔ ${result.rebuilt.path}`,
    `target: ${result.target.size} B sha256=${result.target.sha256.slice(0, 16)}… format=${result.target.format}`,
    `rebuilt: ${result.rebuilt.size} B sha256=${result.rebuilt.sha256.slice(0, 16)}… format=${result.rebuilt.format}`,
    '',
  ];
  const t1 = result.tiers.t1;
  if (t1.status === 'ran') {
    const imports = t1.imports;
    lines.push(`T1 structure: ${pct(t1.score)} (weight ${result.weightsUsed.t1 ?? 0})`);
    lines.push(`  imports: recall ${pct(imports.recall)} precision ${pct(imports.precision)} (target ${imports.targetSize}, rebuilt ${imports.rebuiltSize})`);
    if (imports.missing.length > 0) lines.push(`  missing imports: ${imports.missing.slice(0, 8).join(', ')}${imports.missing.length > 8 ? ' …' : ''}`);
    if (imports.added.length > 0) lines.push(`  rebuilt-only imports: ${imports.added.slice(0, 8).join(', ')}${imports.added.length > 8 ? ' …' : ''}`);
    lines.push(`  sections: Jaccard ${pct(t1.sections.jaccard)}`);
  } else {
    lines.push('T1 structure: empty — no imports or sections to compare');
  }
  const payload = result.tiers.payload;
  if (payload?.status === 'ran') {
    const indicators = payload.indicators;
    lines.push(`Payload: ${pct(payload.score)} (weight ${result.weightsUsed.payload ?? 0}) — indicators and canaries after the toolchain floor`);
    lines.push(`  recall ${pct(indicators.recall)} precision ${pct(indicators.precision)} (target ${indicators.targetSize} indicators, rebuilt ${indicators.rebuiltSize})`);
    if (indicators.missing.length > 0) lines.push(`  missing: ${indicators.missing.slice(0, 6).join(' | ')}${indicators.missing.length > 6 ? ' …' : ''}`);
    if (indicators.added.length > 0) lines.push(`  rebuilt-only: ${indicators.added.slice(0, 6).join(' | ')}${indicators.added.length > 6 ? ' …' : ''}`);
  } else {
    lines.push('Payload: empty — no indicators survived the toolchain floor (encoded or absent)');
  }
  const t2 = result.tiers.t2;
  if (t2.status === 'ran') {
    lines.push(`T2 functions: ${pct(t2.score)} (weight ${result.weightsUsed.t2 ?? 0})`);
    // Double report: the deducted score above, the raw window average here, so
    // the effect of the toolchain deduction is always visible in the text too.
    if (t2.scoreAll !== undefined && t2.scoreAll !== null) {
      lines.push(`  undeducted (scoreAll): ${pct(t2.scoreAll)}; denominator ${t2.denominator?.before ?? 'n/a'} → ${t2.denominator?.after ?? 'n/a'}`
        + ` (${t2.deductedTotal ?? 0} deducted${t2.nameOnlyTotal ? `, ${t2.nameOnlyTotal} name-only audited, not deducted` : ''})`);
      if (t2.deducted?.length) {
        lines.push(`  deducted: ${t2.deducted.slice(0, 6).map((item) => `${item.name} [${item.matchedBy}]`).join(', ')}${t2.deductedTotal > 6 ? ' …' : ''}`);
      }
      if (t2.nameOnlyAudit?.length) {
        lines.push(`  name-only (kept in denominator): ${t2.nameOnlyAudit.slice(0, 6).map((item) => item.name).join(', ')}${t2.nameOnlyTotal > 6 ? ' …' : ''}`);
      }
    }
    if (t2.scope === 'all-functions') {
      const bound = t2.truncated ? ` (${t2.analysisTimedOut ? 'analysis hit the 180-second ceiling; ' : ''}inventory truncated at the function cap)` : '';
      lines.push(`  ${t2.matched}/${t2.functions} functions matched, coverage ${pct(t2.coverage)}${bound}`);
      if (t2.mismatches?.length) {
        lines.push(`  first mismatches: ${t2.mismatches.slice(0, 4).map((item) => (item.reason ? `${item.name} (${item.reason})` : `${item.name} ${pct(item.similarity)}`)).join(' | ')}`);
      }
    } else {
      lines.push(`  entry-function scope: ${pct(t2.score)} similarity${t2.fallbackReason ? `; inventory unavailable: ${t2.fallbackReason}` : ''}`);
    }
  } else {
    lines.push(`T2 functions: blocked — ${t2.reason}`);
  }
  const t3 = result.tiers.t3;
  if (t3.status === 'ran') {
    lines.push(`T3 source literals: ${pct(t3.score)} (weight ${result.weightsUsed.t3 ?? 0}) — ${t3.matched.length}/${t3.literals} found in the target's strings`);
    if (t3.unmatched.length > 0) {
      lines.push(`  not observed in the target: ${t3.unmatched.slice(0, 8).join(' | ')}${t3.unmatched.length > 8 ? ' …' : ''}`);
      lines.push('  (a literal can be absent from sampled strings and still be encoded or optimised away; this is a gap to explain, not proof of fabrication)');
    }
  } else {
    lines.push(`T3 source literals: skipped — ${t3.reason}`);
  }
  const t4 = result.tiers.t4;
  if (t4?.status === 'ran') {
    lines.push(`T4 behaviour: ${pct(t4.score)} (weight ${result.weightsUsed.t4 ?? 0}) — declared output, state and side effects`);
    const dimension = (label, value) => lines.push(`  ${label}: ${pct(value?.score)} (recall ${pct(value?.recall)} precision ${pct(value?.precision)}; target ${value?.targetSize}, rebuilt ${value?.rebuiltSize})`);
    dimension('outputs', t4.outputs);
    dimension('state', t4.state);
    dimension('effects', t4.effects);
    for (const [key, label] of [['outputs', 'outputs'], ['state', 'state'], ['effects', 'effects']]) {
      const missing = t4[key]?.missing ?? [];
      const added = t4[key]?.added ?? [];
      if (missing.length > 0) lines.push(`  ${label} missing: ${missing.slice(0, 6).join(' | ')}${missing.length > 6 ? ' …' : ''}`);
      if (added.length > 0) lines.push(`  ${label} rebuilt-only: ${added.slice(0, 6).join(' | ')}${added.length > 6 ? ' …' : ''}`);
    }
  } else if (t4) {
    lines.push(`T4 behaviour: skipped — ${t4.reason}`);
  }
  const t5 = result.tiers.t5;
  if (t5?.status === 'ran') {
    lines.push(`T5 interaction: ${pct(t5.score)} (weight ${result.weightsUsed.t5 ?? 0}) — window procedures, messages, control ids and resources`);
    const dimension = (label, value) => lines.push(`  ${label}: ${pct(value?.score)} (recall ${pct(value?.recall)} precision ${pct(value?.precision)}; target ${value?.targetSize}, rebuilt ${value?.rebuiltSize})`);
    dimension('windows', t5.windows);
    dimension('messages', t5.messages);
    dimension('controls', t5.controls);
    dimension('resources', t5.resources);
    for (const [key, label] of [['windows', 'windows'], ['messages', 'messages'], ['controls', 'controls'], ['resources', 'resources']]) {
      const missing = t5[key]?.missing ?? [];
      const added = t5[key]?.added ?? [];
      if (missing.length > 0) lines.push(`  ${label} missing: ${missing.slice(0, 6).join(' | ')}${missing.length > 6 ? ' …' : ''}`);
      if (added.length > 0) lines.push(`  ${label} rebuilt-only: ${added.slice(0, 6).join(' | ')}${added.length > 6 ? ' …' : ''}`);
    }
    if (t5.note) lines.push(`  note: ${t5.note}`);
  } else if (t5) {
    lines.push(`T5 interaction: ${t5.status} — ${t5.reason}`);
  }
  lines.push('');
  lines.push(`overall: ${pct(result.overall)}${result.overall === null ? ' — no tier produced a score, which is a failure, not a pass' : ''}`);
  lines.push('limits:');
  for (const limit of result.limitations) lines.push(`- ${limit}`);
  return lines.join('\n');
}

export function buildCompareBuildTool({ maxBytes = 64 * 1024 * 1024, store } = {}) {
  const tool = {
    name: 'rea_compare_build',
    description: 'Compare a rebuilt binary with the target it was reconstructed from. Tier T1 checks imports (recall and precision) and section layout; the payload tier compares IoC-shaped indicators after the toolchain floor; T2 decompiles the function inventory on both sides and reports pseudocode and CFG similarity; T3 checks the string constants declared in the reconstructed source against the target; T4 (opt-in, behavior=true) compares the declared behaviour surface - output literals, state names and side-effect families - on recall and precision; T5 (opt-in, interaction=true, needs the engine inventory) compares the GUI interaction surface - window procedures, message constants, control/timer ids and resource ids - on recall and precision. Read-only: both binaries are read, never executed. Use after compiling a reconstruction, and treat "overall" as a gap list, not a verdict.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        target: { type: 'string', description: 'Absolute path of the original sample.' },
        rebuilt: { type: 'string', description: 'Absolute path of the binary compiled from the reconstructed source.' },
        source: { type: 'string', description: 'Optional absolute path of the reconstructed source; enables the T3 literal tier.' },
        engine: { type: 'boolean', description: 'Set false to skip the Ghidra tier and stay fully local.' },
        behavior: { type: 'boolean', description: 'Score the opt-in T4 behaviour tier: output literals, state names and side-effect families, each on recall and precision. Renormalises the weights when enabled.' },
        interaction: { type: 'boolean', description: 'Score the opt-in T5 interaction tier: window procedures, message constants, control/timer ids and .rsrc resource ids, each on recall and precision. Needs the engine function inventory (engine=false blocks it) and renormalises the weights when enabled.' },
        functions: { type: 'number', description: 'Function inventory cap for T2, 1-200. Defaults to 48.' },
        functionNames: { type: 'array', items: { type: 'string' }, description: 'Restrict T2 to these function names (matched by name, not layout) - use for function-level restoration reviews.' },
        metric: { type: 'string', enum: ['mixed', 'cfg', 'semantic', 'text'], description: 'T2 similarity metric. semantic is the right choice for cross-compiler restoration reviews; cfg assumes similar code generation; mixed is the loop default.' },
        threshold: { type: 'number', description: 'Per-function match threshold for the review gate, 0-1. Defaults to 0.9; a function below it is listed as a mismatch.' },
        deductFunctions: { type: 'boolean', description: 'Deduct toolchain-injected target functions from the T2 denominator, matched against a measured same-toolchain empty-program floor (name+RVA, name+body-hash or body-hash; name-only hits are audited, not deducted). t2.score becomes the deducted average, t2.scoreAll keeps the raw average. No effect when functionNames is set.' },
      },
      required: ['target', 'rebuilt'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no comparison)' }]; },
    },
    async execute(args) {
      for (const key of ['target', 'rebuilt']) {
        if (!isAbsolute(String(args?.[key] ?? ''))) return { text: `rea_compare_build: ${key} must be an absolute path` };
      }
      if (args?.source !== undefined && !isAbsolute(String(args.source))) {
        return { text: 'rea_compare_build: source must be an absolute path when supplied' };
      }
      let sourceText = null;
      if (typeof args?.source === 'string') {
        try {
          const buffer = await readFile(args.source);
          if (buffer.length > MAX_SOURCE_BYTES) return { text: `rea_compare_build: source exceeds the ${MAX_SOURCE_BYTES}-byte read cap` };
          sourceText = buffer.toString('utf8');
        } catch (error) {
          return { text: `rea_compare_build: cannot read source (${error?.message ?? error})` };
        }
      }
      let result;
      let floorNote = 'runtime floor: not applied';
      let runtimeFloor = null;
      // One floor build serves both floors; the function inventory is only
      // requested when deduction is on, so the default path never pays for it.
      const wantDeduct = args?.deductFunctions === true;
      let functionFloor = null;
      if (store?.statePath) {
        const readiness = await buildReadiness();
        if (readiness.ready) {
          const sessionDir = dirname(await store.statePath('floor'));
          const measured = await measureToolchainFloor({ workDir: join(sessionDir, 'toolchain-floor'), listFunctions: wantDeduct });
          if (measured.reason === null) {
            runtimeFloor = measured.floor;
            floorNote = `runtime floor: measured (${measured.floor.imports.size} imports, ${measured.floor.strings.size} strings excluded)`;
            if (wantDeduct) {
              if (measured.functionFloor) {
                functionFloor = measured.functionFloor;
                floorNote += `; function floor: ${measured.functionFloor.names.size} names, ${measured.functionFloor.bodyHashes.size} bodies`;
              } else {
                floorNote += `; function floor not applied (${measured.functionFloorReason ?? 'not measured'})`;
              }
            }
          } else {
            floorNote = `runtime floor: not applied (${measured.reason})`;
          }
        } else {
          floorNote = `runtime floor: not applied (${readiness.reason})`;
        }
      } else if (wantDeduct) {
        floorNote = 'runtime floor: not applied (no artifact store; function deduction needs the measured floor)';
      }
      try {
        result = await compareBuilds({
          targetPath: args.target,
          rebuiltPath: args.rebuilt,
          sourceText,
          engine: args?.engine !== false,
          maxBytes,
          runtimeFloor,
          maxFunctions: Number.isFinite(args?.functions) ? Math.max(1, Math.min(200, Math.floor(args.functions))) : 48,
          functionFilter: Array.isArray(args?.functionNames) && args.functionNames.length > 0
            ? args.functionNames.map((name) => String(name))
            : null,
          functionMetric: ['mixed', 'cfg', 'semantic', 'text'].includes(args?.metric) ? args.metric : 'mixed',
          functionThreshold: Number.isFinite(args?.threshold) ? Math.max(0, Math.min(1, args.threshold)) : 0.9,
          behavior: args?.behavior === true,
          deductFunctions: wantDeduct,
          functionFloor,
          interaction: args?.interaction === true,
        });
      } catch (error) {
        return { text: `rea_compare_build: ${error?.message ?? error}` };
      }
      const text = `${render(result)}\n${floorNote}`;
      if (store?.write) {
        try {
          const saved = await store.write('rebuild-comparison.json', JSON.stringify(result, null, 2));
          return { text: `${text}\n\nfull JSON: ${saved}` };
        } catch (error) {
          return { text: `${text}\n\nfull JSON: not saved (${error?.message ?? error})` };
        }
      }
      return { text };
    },
    isConcurrencySafe: () => true,
  };
  // The comparison names both input paths; redact host identity from the
  // rendered text and keep the disk JSON as the local record.
  return withRedactedOutput(tool);
}

const loopStateName = (sha256) => `reconstruct-${sha256.slice(0, 12)}.json`;

/**
 * The loop tool: start on a target, advance one draft at a time.
 *
 * State is a deterministic sidecar in this session, so "start in one call,
 * advance in the next" does not depend on the model remembering a path. The
 * budget and the terminal rules live in `lib/recon.js`; this tool supplies the
 * build and the comparison and refuses to skip either.
 */
export function buildReconstructTool({ maxBytes = 64 * 1024 * 1024, store, availableTools = null, autoRepairRounds = null } = {}) {
  const tool = {
    name: 'rea_reconstruct',
    description: 'Drive the reconstruction loop against one target. action=start records the target, its unresolved regions and the iteration budget; action=advance compiles one draft source, compares it with the target on the T1/T2/T3 tiers (plus opt-in T4 behaviour and opt-in T5 interaction), records the gaps and decides the terminal state (converged, budget-exhausted, blocked, unreachable); action=status renders the current state; action=handoff writes a portable brief (gaps, mismatched functions with RVAs, next steps) for the person or model that has to rewrite the code, and includeCode=true embeds their pseudocode; action=rewrite applies model-authored function bodies to the last best draft and measures them like any other draft; action=dynamic-plan ranks decoder candidates for the opt-in Frida probe; action=dynamic-apply records a probe dump as extra target truth, reopens a terminal loop and lets the next draft be confirmed by the comparison instead of asserting convergence; action=trace-apply records a rea_trace_behavior comparison and blocks convergence while the executed rebuild still behaves differently; action=hypothesis-record stores a semantic hypothesis (a statement plus grep-able decompilation evidence and a checkable prediction) in the loop state; action=hypothesis-check runs the recorded or supplied hypothesis against the target\'s own evidence (import table, deep strings, constant bytes, decompiled bodies) and returns verified, unverified or refuted - a refuted hypothesis becomes a hypothesis-refuted gap in the next iteration. The target is only read; the draft is compiled, never executed. A draft is a hypothesis: the comparison is what decides.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['start', 'advance', 'status', 'handoff', 'rewrite', 'dynamic-plan', 'dynamic-apply', 'trace-apply', 'hypothesis-record', 'hypothesis-check'], description: 'start, advance, status, handoff, rewrite, dynamic-plan, dynamic-apply, trace-apply, hypothesis-record or hypothesis-check.' },
        target: { type: 'string', description: 'Absolute path of the target binary; required for every action.' },
        source: { type: 'string', description: 'Absolute path of the draft source; required for draft=source.' },
        draft: { type: 'string', enum: ['source', 'baseline', 'auto'], description: 'source publishes the draft at `source`; baseline decompiles the target and compiles the mechanical translation (needs Ghidra); auto starts from `source`, or from the last best draft when no source is given (the mechanical baseline when there is none yet), and replaces mismatched functions with their decompiled translations, keeping only rounds that score higher. When a round scores lower than the best so far, the loop rolls back to that best draft and retries once with only the lowest-similarity function replaced. Defaults to source.' },
        rounds: { type: 'number', description: 'For draft=auto: maximum repair rounds, 1-5. Defaults to 2. Each round compiles and compares; when a round scores lower than the best so far, the loop rolls back to the best draft and retries once with only the lowest-similarity function replaced, so the worst case is rounds+1 comparisons.' },
        budget: { type: 'number', description: 'Iteration budget for action=start, 1-20. Defaults to 5.' },
        engine: { type: 'boolean', description: 'Set false to skip the Ghidra tier during advance.' },
        functions: { type: 'number', description: 'Function inventory cap for T2 and baseline drafts, 1-200. Defaults to 48.' },
        hex: { type: 'string', description: 'For action=dynamic-apply: the hex dump returned by rea_dynamic_probe.' },
        probe: { type: 'string', description: 'For action=dynamic-apply: absolute path of the JSON saved by rea_dynamic_probe; used when the text preview truncated the dump.' },
        behavior: { type: 'boolean', description: 'Score the T4 behaviour tier (outputs, state, side effects) as part of the comparison. Off by default; enabling it renormalises the weights.' },
        interaction: { type: 'boolean', description: 'Score the T5 interaction tier (window procedures, messages, control/timer ids, resources) as part of the comparison. Needs the engine inventory (engine=false blocks it). Off by default; enabling it renormalises the weights.' },
        deductFunctions: { type: 'boolean', description: 'Deduct toolchain-injected target functions from the T2 denominator against the measured empty-program floor. t2.score becomes the deducted average, t2.scoreAll keeps the raw average. Off by default.' },
        rva: { type: 'string', description: 'For action=dynamic-apply: the hooked RVA that produced the dump, for the record.' },
        trace: { type: 'string', description: 'For action=trace-apply: absolute path of the JSON written by rea_trace_behavior.' },
        hypothesis: {
          type: 'object',
          additionalProperties: false,
          description: 'For action=hypothesis-record / hypothesis-check: one semantic hypothesis. statement is the one-line attribution claim; evidence lists quotes that must appear in the target\'s own decompilation; prediction is the checkable claim (kind: string-literal | constant-at-rva | import-used | calls-target).',
          properties: {
            id: { type: 'string', description: 'Stable identifier; re-recording the same id replaces the earlier entry.' },
            statement: { type: 'string', description: 'One-sentence semantic judgement, e.g. "FUN_180009820 converts a double through the constant at DAT_18029bd28".' },
            functionName: { type: 'string', description: 'Function-level hypothesis: the function the claim is about. Presence of functionName or rva makes the hypothesis function-level.' },
            rva: { type: 'string', description: 'Function-level hypothesis: the function RVA, e.g. 0x9820.' },
            evidence: {
              type: 'array',
              description: 'Quotes that must be findable in the target\'s decompilation; every quote must hit or the hypothesis is rejected.',
              items: {
                type: 'object', additionalProperties: false,
                properties: {
                  channel: { type: 'string', description: 'Evidence channel, e.g. ghidra-decompile.' },
                  rva: { type: 'string', description: 'RVA of the function the quote is taken from.' },
                  quote: { type: 'string', description: 'Verbatim fragment of the decompiled body.' },
                },
                required: ['quote'],
              },
            },
            prediction: {
              type: 'object', additionalProperties: false,
              description: 'The checkable prediction. constant-at-rva takes the address in rva and the expected little-endian hex bytes in value.',
              properties: {
                kind: { type: 'string', enum: ['string-literal', 'constant-at-rva', 'import-used', 'calls-target'] },
                value: { type: 'string', description: 'API name, literal, callee name, or expected hex bytes.' },
                rva: { type: 'string', description: 'For constant-at-rva: the address to read (VA or RVA).' },
              },
              required: ['kind', 'value'],
            },
          },
          required: ['id', 'statement', 'prediction'],
        },
        hypothesisId: { type: 'string', description: 'For action=hypothesis-check: re-check a recorded hypothesis by id instead of passing hypothesis again.' },
        includeCode: { type: 'boolean', description: 'For action=handoff: include decompiled pseudocode for up to three mismatched functions. Off by default because the first decompile can trigger a full analysis.' },
        rewrites: {
          type: 'array',
          description: 'For action=rewrite: model-authored function bodies to apply to the last best draft. Each item names one function; only those bodies change.',
          items: {
            type: 'object', additionalProperties: false,
            properties: { name: { type: 'string' }, source: { type: 'string' } },
            required: ['name', 'source'],
          },
        },
      },
      required: ['action', 'target'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no loop state)' }]; },
    },
    async execute(args) {
      if (!['start', 'advance', 'status', 'handoff', 'rewrite', 'dynamic-plan', 'dynamic-apply', 'trace-apply', 'hypothesis-record', 'hypothesis-check'].includes(args?.action)) {
        return { text: 'rea_reconstruct: action must be start, advance, status, handoff, rewrite, dynamic-plan, dynamic-apply, trace-apply, hypothesis-record or hypothesis-check' };
      }
      if (!isAbsolute(String(args?.target ?? ''))) return { text: 'rea_reconstruct: target must be an absolute path' };
      if (!store?.writeState || !store?.statePath) return { text: 'rea_reconstruct: no artifact store is available in this session' };
      let buffer;
      try {
        buffer = await readFile(args.target);
      } catch (error) {
        return { text: `rea_reconstruct: cannot read target (${error?.message ?? error})` };
      }
      if (buffer.length > maxBytes) return { text: `rea_reconstruct: target exceeds the ${maxBytes}-byte read cap` };
      const sha256 = createHash('sha256').update(buffer).digest('hex');
      const name = loopStateName(sha256);
      const stateFile = await store.statePath(name);

      if (args.action === 'start') {
        const report = triageBuffer(buffer, { name: 'target' });
        const layout = readPeLayout(buffer);
        const imports = parsePEImports(buffer);
        const readiness = await buildReadiness();
        const state = createLoopState({
          targetPath: args.target,
          targetSha256: sha256,
          targetSize: buffer.length,
          unresolvedRegions: report.unresolved?.length ?? 0,
          budget: args.budget,
        });
        state.intake = {
          ...state.intake,
          verdict: report.verdict,
          format: report.format,
          entryRva: layout?.entryRva ?? null,
          imports: imports?.apiFlat?.length ?? 0,
          strings: report.strings?.count ?? null,
          unresolvedBytes: (report.unresolved ?? []).reduce((sum, region) => sum + Math.max(0, (region.end ?? 0) - (region.start ?? 0)), 0),
          build: readiness.ready
            ? `${readiness.compiler} ${readiness.version ?? ''}`.trim()
            : `blocked: ${readiness.reason}`,
        };
        await store.writeState(name, JSON.stringify(state, null, 2));
        return { text: `${renderLoop(state)}\n\nstate: ${stateFile}` };
      }

      let state;
      try {
        state = JSON.parse(await readFile(stateFile, 'utf8'));
      } catch {
        return { text: 'rea_reconstruct: no loop state exists for this target; call action=start first' };
      }
      if (args.action === 'status') return { text: renderLoop(state) };

      if (args.action === 'hypothesis-record' || args.action === 'hypothesis-check') {
        let hypothesis = args?.hypothesis;
        if (args.action === 'hypothesis-check' && !hypothesis && args?.hypothesisId) {
          hypothesis = (state.hypotheses ?? []).find((item) => item?.id === args.hypothesisId);
          if (!hypothesis) return { text: `rea_reconstruct: no recorded hypothesis with id "${args.hypothesisId}"` };
        }
        if (!hypothesis || typeof hypothesis !== 'object' || !hypothesis.id || !hypothesis.prediction?.kind) {
          return { text: 'rea_reconstruct: hypothesis requires id, statement and prediction{kind, value}' };
        }
        if (args.action === 'hypothesis-record') {
          // A record stores the claim and its grep-able evidence; it asserts
          // nothing. Only action=hypothesis-check can move the status.
          const entry = {
            id: String(hypothesis.id),
            statement: String(hypothesis.statement ?? ''),
            level: hypothesis.functionName || hypothesis.rva ? 'function' : 'binary',
            functionName: hypothesis.functionName ?? null,
            rva: hypothesis.rva ?? null,
            evidence: Array.isArray(hypothesis.evidence) ? hypothesis.evidence : [],
            prediction: hypothesis.prediction,
            status: 'recorded',
            detail: null,
            recordedAt: new Date().toISOString(),
          };
          state.hypotheses = [...(state.hypotheses ?? []).filter((item) => item?.id !== entry.id), entry];
          await store.writeState(name, JSON.stringify(state, null, 2));
          return { text: `${renderLoop(state)}\n\nrecorded hypothesis "${entry.id}" (${entry.level}-level, status recorded); run action=hypothesis-check (or hypothesisId=${entry.id}) to verify it` };
        }
        // hypothesis-check: build the measured channels and decide.
        const layout = readPeLayout(buffer);
        const imports = parsePEImports(buffer);
        const strings = extractDeepStrings(buffer, { minLength: 4, maxStrings: 4_000 });
        let functions = null;
        let functionsNote = 'no Ghidra inventory (engine unavailable or list failed); calls-target and function-scoped checks stay unverified';
        const engineReady = await ghidraLocalReadiness();
        if (engineReady.ready) {
          const listed = await listFunctionsWithGhidra(args.target, { maxFunctions: 200, timeoutMs: 300_000 });
          if (listed.ok) {
            functions = listed.functions;
            functionsNote = `Ghidra inventory: ${listed.emitted} function(s)${listed.truncated ? ' (truncated at the cap)' : ''}`;
          }
        }
        const result = checkSemanticHypothesis(buffer, { layout, imports, strings, functions }, hypothesis);
        const previous = (state.hypotheses ?? []).find((item) => item?.id === result.id);
        const entry = {
          id: result.id,
          statement: result.statement,
          level: result.level,
          functionName: hypothesis.functionName ?? null,
          rva: hypothesis.rva ?? null,
          evidence: Array.isArray(hypothesis.evidence) ? hypothesis.evidence : [],
          prediction: hypothesis.prediction,
          recordedAt: previous?.recordedAt ?? new Date().toISOString(),
          status: result.status,
          detail: result.detail,
          result,
          checkedAt: result.checkedAt,
        };
        state.hypotheses = [...(state.hypotheses ?? []).filter((item) => item?.id !== result.id), entry];
        await store.writeState(name, JSON.stringify(state, null, 2));
        const lines = [
          renderLoop(state),
          '',
          functionsNote,
          `hypothesis "${result.id}" [${result.level}] -> ${result.status}`,
          `detail: ${result.detail}`,
          `boundary: ${result.boundary}`,
        ];
        if (result.status === 'refuted') lines.push('this hypothesis is carried as a hypothesis-refuted gap from the next iteration on');
        if (result.status === 'verified') lines.push('verified through the named channel only; the same-channel/blind-spot notes above still apply');
        return { text: lines.join('\n') };
      }

      if (args.action === 'handoff') {
        let brief = renderHandoff(state);
        if (brief === null) return { text: 'rea_reconstruct: no iteration is recorded yet; advance a draft before asking for a handoff brief' };
        if (args?.includeCode === true) {
          const last = [...state.iterations].reverse().find((item) => item.compare);
          const mismatches = (last?.compare?.t2?.mismatches ?? []).filter((item) => item.rva).slice(0, 3);
          if (mismatches.length > 0) {
            const ready = await ghidraLocalReadiness();
            if (!ready.ready) {
              brief += `\n\n## Decompiled targets\n\n(Ghidra unavailable: ${ready.reason})`;
            } else {
              const blocks = [];
              for (const item of mismatches) {
                const code = await decompileWithGhidra(args.target, { rva: item.rva, timeoutMs: 120_000 });
                blocks.push(code.ok
                  ? `### ${item.name} (${item.rva})\n\n\`\`\`c\n${code.code}\n\`\`\``
                  : `### ${item.name} (${item.rva})\n\n(decompile failed: ${code.reason ?? code.code})`);
              }
              brief += `\n\n## Decompiled targets\n\n${blocks.join('\n\n')}`;
            }
          }
        }
        if (typeof store.write === 'function') {
          try {
            const saved = await store.write('reconstruction-brief.md', brief);
            return { text: `${brief}\n\nsaved: ${saved}` };
          } catch (error) {
            return { text: `${brief}\n\nnot saved (${error?.message ?? error})` };
          }
        }
        return { text: brief };
      }
      const maxFunctions = Number.isFinite(args?.functions) ? Math.max(1, Math.min(200, Math.floor(args.functions))) : 48;
      const readDraftSource = async (path = args?.source) => {
        if (!isAbsolute(String(path ?? ''))) return { error: 'rea_reconstruct: source must be an absolute path for this draft' };
        try {
          const sourceBuffer = await readFile(path);
          if (sourceBuffer.length > MAX_SOURCE_BYTES) return { error: `rea_reconstruct: source exceeds the ${MAX_SOURCE_BYTES}-byte read cap` };
          return { text: sourceBuffer.toString('utf8') };
        } catch (error) {
          return { error: `rea_reconstruct: cannot read source (${error?.message ?? error})` };
        }
      };


      if (args.action === 'dynamic-plan') {
        const engineReady = await ghidraLocalReadiness();
        if (!engineReady.ready) return { text: `rea_reconstruct: dynamic planning needs Ghidra (${engineReady.reason})` };
        const listed = await listFunctionsWithGhidra(args.target, { maxFunctions, timeoutMs: 300_000 });
        if (!listed.ok) return { text: `rea_reconstruct: inventory failed (${listed.reason ?? listed.code})` };
        const candidates = rankDecoderCandidates(listed.functions, { unresolvedBytes: state.intake.unresolvedBytes ?? null });
        state.dynamicPlan = { at: new Date().toISOString(), candidates };
        await store.writeState(name, JSON.stringify(state, null, 2));
        const lines = [
          renderLoop(state),
          '',
          candidates.length === 0
            ? 'dynamic plan: no decoder-like candidate in this inventory; raise the function cap or inspect by hand'
            : `dynamic plan: ${candidates.length} candidate(s) - run rea_dynamic_probe (allowSampleExecution + confirm), then submit the hex with action=dynamic-apply`,
          ...candidates.map((item) => `- ${item.name} RVA ${item.rva} score ${item.score} arg ${item.argIndex} length ${item.length} — ${item.reasons.join('; ')}`),
        ];
        return { text: lines.join('\n') };
      }

      if (args.action === 'dynamic-apply') {
        let hex = String(args?.hex ?? '');
        if (hex.length === 0 && typeof args?.probe === 'string') {
          if (!isAbsolute(args.probe)) return { text: 'rea_reconstruct: probe must be an absolute path' };
          try {
            const record = JSON.parse(await readFile(args.probe, 'utf8'));
            hex = String(record?.hex ?? '');
          } catch (error) {
            return { text: `rea_reconstruct: cannot read the probe record (${error?.message ?? error})` };
          }
        }
        if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0 || hex.length > 131_072) {
          return { text: 'rea_reconstruct: hex must be an even-length hex dump of at most 64 KiB (or point probe at the saved JSON)' };
        }
        const bytes = Buffer.from(hex, 'hex');
        const extracted = extractStrings(bytes, { minLength: 4, maxStrings: 100 }).map((item) => item.value);
        const iocs = [...new Set(extractIocs(extracted.map((value) => ({ value }))).map((item) => item.value))];
        state.dynamic = {
          at: new Date().toISOString(),
          rva: args.rva ?? null,
          bytes: bytes.length,
          strings: extracted.slice(0, 20),
          iocs: iocs.slice(0, 20),
        };
        state.dynamicHistory = [...(state.dynamicHistory ?? []), state.dynamic];
        // Evidence is not a verdict. A dump proves the values exist; it does not
        // prove the source reproduces them, so the loop reopens and the next
        // draft has to be confirmed by the comparison like any other.
        const wasTerminal = state.status !== 'running';
        if (wasTerminal) {
          if (state.iterations.length >= state.budget) {
            state.budget = Math.min(20, state.budget + 1);
            state.budgetNotes = [...(state.budgetNotes ?? []), `+1 iteration for the draft that carries the ${state.dynamic.rva ?? 'unknown'} dump`];
          }
          state.status = 'running';
          state.reason = null;
          state.reopened = (state.reopened ?? 0) + 1;
        }
        await store.writeState(name, JSON.stringify(state, null, 2));
        const wrapped = extracted.slice(0, 8).map((value) => markUntrusted('dynamic-buffer', value, { maxChars: 120 })).join(' | ');
        const nextStep = wasTerminal
          ? `the loop is running again (${state.budget - state.iterations.length} of ${state.budget} iteration(s) left): submit a draft that carries these values so T3 and payload can confirm them`
          : 'recorded as extra target truth for the next draft; the loop status is unchanged';
        return {
          text: [
            renderLoop(state),
            '',
            `dynamic evidence: ${bytes.length} bytes, ${extracted.length} strings, ${iocs.length} indicators`,
            wrapped ? `recovered: ${wrapped}` : 'recovered: no printable strings in the dump',
            nextStep,
          ].join('\n'),
        };
      }

      if (args.action === 'trace-apply') {
        if (!isAbsolute(String(args?.trace ?? ''))) return { text: 'rea_reconstruct: trace must be an absolute path' };
        let record;
        try {
          record = JSON.parse(await readFile(args.trace, 'utf8'));
        } catch (error) {
          return { text: `rea_reconstruct: cannot read the trace record (${error?.message ?? error})` };
        }
        const comparison = record?.comparison;
        if (!comparison || comparison.status !== 'ran' || typeof comparison.score !== 'number') {
          return { text: 'rea_reconstruct: the trace record has no measurable comparison; run rea_trace_behavior first' };
        }
        const samePath = (left, right) => {
          const a = resolve(String(left ?? ''));
          const b = resolve(String(right ?? ''));
          return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
        };
        if (!samePath(record.targetPath, state.target.path)) {
          return { text: 'rea_reconstruct: this trace was recorded against a different target' };
        }
        let rebuiltSha256 = null;
        try {
          const rebuiltBuffer = await readFile(String(record.rebuiltPath ?? ''));
          rebuiltSha256 = createHash('sha256').update(rebuiltBuffer).digest('hex');
        } catch {
          // The build may have been cleaned up; the score is still recorded, but
          // it cannot be tied to a draft and will not gate convergence.
        }
        state.runtime = {
          at: new Date().toISOString(),
          score: comparison.score,
          rebuiltSha256,
          exitSame: comparison.exit?.same ?? null,
          stdout: comparison.stdout?.score ?? null,
          stderr: comparison.stderr?.score ?? null,
          files: comparison.files?.score ?? null,
          path: args.trace,
        };
        state.runtimeHistory = [...(state.runtimeHistory ?? []), state.runtime];
        // A runtime disagreement is evidence against the static verdict. If the
        // loop already converged, it reopens; it never keeps a converged badge
        // that the execution contradicts.
        if (state.status === 'converged' && comparison.score < 0.9) {
          if (state.iterations.length >= state.budget) {
            state.budget = Math.min(20, state.budget + 1);
            state.budgetNotes = [...(state.budgetNotes ?? []), '+1 iteration for the runtime disagreement'];
          }
          state.status = 'running';
          state.reason = null;
          state.reopened = (state.reopened ?? 0) + 1;
        }
        await store.writeState(name, JSON.stringify(state, null, 2));
        return {
          text: [
            renderLoop(state),
            '',
            `runtime evidence: ${(comparison.score * 100).toFixed(1)}% (exit ${comparison.exit?.same ? 'same' : 'different'}, stdout ${pct(comparison.stdout?.score)}, stderr ${pct(comparison.stderr?.score)}, files ${pct(comparison.files?.score)})`,
            comparison.score < 0.9
              ? 'the runtime trace disagrees with the static tiers: the loop cannot converge on this evidence; fix the behaviour and trace again'
              : 'the runtime trace agrees with the static tiers; it is recorded as a confirmation, not as a replacement for them',
          ].join('\n'),
        };
      }

      if (args.action === 'rewrite') {
        if (state.status !== 'running') {
          return { text: `rea_reconstruct: the loop is already ${state.status}${state.reason ? ` (${state.reason})` : ''}; start a new loop to keep going` };
        }
        const basePath = typeof args?.source === 'string' && args.source.length > 0 ? args.source : state.lastDraftPath;
        if (typeof basePath !== 'string' || basePath.length === 0) {
          return { text: 'rea_reconstruct: no base draft; advance one first or pass source=<absolute path>' };
        }
        const base = await readDraftSource(basePath);
        if (base.error) return { text: base.error };
        const merged = applyRewrites({ sourceText: base.text, rewrites: args?.rewrites });
        if (merged.error) return { text: `rea_reconstruct: ${merged.error}` };
        const iteration = state.iterations.length + 1;
        const mergedPath = await store.writeState(`rewrite-${sha256.slice(0, 12)}-${iteration}.c`, merged.sourceText);
        const outcome = await this.execute({ ...args, action: 'advance', draft: 'source', source: mergedPath });
        return {
          text: [
            outcome.text,
            '',
            `rewrite: applied ${merged.applied.length > 0 ? merged.applied.join(', ') : 'none'}; appended ${merged.appended.length > 0 ? merged.appended.join(', ') : 'none'}; base ${basePath}`,
          ].join('\n'),
        };
      }

      if (state.status !== 'running') {
        return { text: `rea_reconstruct: the loop is already ${state.status}${state.reason ? ` (${state.reason})` : ''}; start a new loop to keep going` };
      }
      // draft=auto starts from the analyst's source (or the mechanical baseline
      // when none is supplied), then uses the comparison's own gaps to replace
      // mismatched functions with their decompiled counterparts. The best round
      // wins; a repair that lowers the score is never recorded.
      const requested = args?.draft === 'baseline' ? 'baseline' : args?.draft === 'auto' ? 'auto' : 'source';
      const iteration = state.iterations.length + 1;
      const workDir = join(dirname(stateFile), `work-${sha256.slice(0, 12)}`);
      const dynamicEvidence = state.dynamic
        ? { strings: state.dynamic.strings ?? [], iocs: state.dynamic.iocs ?? [] }
        : null;
      let sourceText = null;
      let built = null;
      let baseline = null;
      let baselineInventory = null;
      let floorNote = null;
      let auto = null;
      let compare = null;

      // One memoised empty-program build serves the import/string floor and,
      // when deduction is on, the function floor. The function floor comes only
      // from the empty program: the stub floor built from the target's own
      // inventory carries the target's function names, and deducting on those
      // would eat user functions.
      const wantDeduct = args?.deductFunctions === true;
      let measuredFloorMemo = null;
      const measureFloorOnce = async () => {
        if (measuredFloorMemo === null) {
          measuredFloorMemo = await measureToolchainFloor({
            workDir: join(dirname(stateFile), 'toolchain-floor'),
            listFunctions: wantDeduct,
          });
        }
        return measuredFloorMemo;
      };
      let functionFloor = null;
      if (wantDeduct) {
        const measured = await measureFloorOnce();
        if (measured.functionFloor) functionFloor = measured.functionFloor;
        else floorNote = `function floor not applied: ${measured.functionFloorReason ?? measured.reason ?? 'not measured'}`;
      }

      const runtimeFloorFor = async (stubInventory) => {
        let runtimeFloor = null;
        // A baseline-derived draft gets the stricter floor: the same inventory
        // compiled with every function stubbed.
        if (stubInventory) {
          const stubDraft = synthesizeDraft(stubInventory.functions, {
            stubbed: new Set(stubInventory.functions.map((item) => item.name)),
          });
          const stubBuild = await compileC({ sourceText: stubDraft.source, workDir, name: `stub-floor-${iteration}` });
          if (stubBuild.ok) {
            runtimeFloor = floorFromSkeleton(await readFile(stubBuild.outPath));
          } else {
            floorNote = `stub floor not applied: ${stubBuild.reason}`;
          }
        }
        if (runtimeFloor === null) {
          const measured = await measureFloorOnce();
          if (measured.reason === null) runtimeFloor = measured.floor;
          else floorNote = floorNote ? `${floorNote}; toolchain floor not applied: ${measured.reason}` : `runtime floor not applied: ${measured.reason}`;
        }
        return runtimeFloor;
      };

      const compareDraft = (text, compiled, floor) => compareBuilds({
        targetPath: args.target,
        rebuiltPath: compiled.outPath,
        sourceText: text,
        engine: args?.engine !== false,
        maxBytes,
        runtimeFloor: floor,
        maxFunctions,
        behavior: args?.behavior === true,
        interaction: args?.interaction === true,
        // Toolchain-function deduction: the deducted t2.score drives the loop,
        // t2.scoreAll keeps the raw average on record.
        deductFunctions: wantDeduct,
        functionFloor,
        // Evidence recovered by the opt-in probe is target truth even though it
        // never appears in the file; the comparison must know it or a correct
        // draft containing a runtime key reads as fabrication.
        dynamicEvidence,
      });

      const settled = (result) => {
        if (!result || typeof result.overall !== 'number') return true;
        if (result.overall < CONVERGENCE) return false;
        const t1 = result.tiers.t1;
        const t3 = result.tiers.t3;
        const payload = result.tiers.payload;
        const behavior = result.tiers.t4;
        const interaction = result.tiers.t5;
        const structuralOk = t1.status !== 'ran'
          || ((t1.imports.recall === null || t1.imports.recall >= 0.95)
            && (t1.imports.precision === null || t1.imports.precision >= 0.9));
        const literalOk = t3.status !== 'ran' || t3.score === null || t3.score >= 0.9;
        const payloadOk = !payload || payload.status !== 'ran' || payload.score === null || payload.score >= 0.9;
        const behaviorOk = !behavior || behavior.status !== 'ran' || behavior.score === null || behavior.score >= 0.9;
        const interactionOk = !interaction || interaction.status !== 'ran' || interaction.score === null || interaction.score >= 0.9;
        return structuralOk && literalOk && payloadOk && behaviorOk && interactionOk;
      };

      if (requested === 'auto') {
        const engineReady = await ghidraLocalReadiness();
        if (!engineReady.ready) {
          built = { ok: false, code: 'unavailable', reason: engineReady.reason ?? 'Ghidra is not ready for an automatic draft' };
        } else {
          const listed = await listFunctionsWithGhidra(args.target, { maxFunctions, timeoutMs: 300_000 });
          if (!listed.ok) {
            built = { ok: false, code: 'inventory-failed', reason: listed.reason ?? listed.code };
          } else {
            baselineInventory = listed;
            state.intake.functions = listed.total;
            state.intake.functionSample = listed.emitted;
            baseline = await buildBaseline({ functions: listed.functions, workDir, name: `baseline-${iteration}` });
            if (!baseline.ok) {
              built = { ...(baseline.built ?? {}), ok: false, code: 'baseline-failed', reason: baseline.reason };
            } else {
              // Resume from the last best draft when no source is supplied: the
              // analyst can come back a day later and keep repairing instead of
              // restarting from the mechanical baseline.
              const resumePath = typeof args?.source === 'string' && args.source.length > 0
                ? args.source
                : (typeof state.lastDraftPath === 'string' ? state.lastDraftPath : null);
              const startedFromSource = resumePath !== null;
              const start = startedFromSource ? await readDraftSource(resumePath) : { text: baseline.sourceText };
              if (start.error) return { text: start.error };
              const rounds = Number.isFinite(args?.rounds) ? Math.max(1, Math.min(5, Math.floor(args.rounds))) : 2;
              const floor = await runtimeFloorFor(listed);
              const measure = async (source, label) => {
                const compiled = await compileC({ sourceText: source, workDir, name: `auto-${iteration}-${label}` });
                if (!compiled.ok) return { ok: false, built: compiled };
                let comparison;
                try {
                  comparison = await compareDraft(source, compiled, floor);
                } catch (error) {
                  return { ok: false, built: { ...compiled, ok: false, code: 'compare-error', reason: error?.message ?? String(error) } };
                }
                return { ok: true, built: compiled, comparison };
              };
              // `autoRepairRounds` is a test seam: the real rollback engine is
              // runAutoRepairRounds, and an injected replacement lets a test
              // drive the tool path with a deterministic round history.
              const { best, history, firstFailure } = await (autoRepairRounds ?? runAutoRepairRounds)({
                startText: start.text,
                baselineSource: baseline.sourceText,
                rounds,
                measure,
                isSettled: settled,
              });
              if (!best) {
                if (!built) built = firstFailure ?? { ok: false, code: 'auto-failed', reason: 'no automatic round compiled' };
              } else {
                sourceText = best.sourceText;
                built = best.built;
                compare = best.compare;
                auto = {
                  startedFromSource,
                  rounds: history.length,
                  history: toAutoHistory(history),
                };
              }
            }
          }
        }
      } else if (requested === 'source') {
        const read = await readDraftSource();
        if (read.error) return { text: read.error };
        sourceText = read.text;
        built = await compileC({ sourceText, workDir, name: `draft-${iteration}` });
      } else {
        const engineReady = await ghidraLocalReadiness();
        if (!engineReady.ready) {
          built = { ok: false, code: 'unavailable', reason: engineReady.reason ?? 'Ghidra is not ready for a baseline draft' };
        } else {
          const listed = await listFunctionsWithGhidra(args.target, { maxFunctions, timeoutMs: 300_000 });
          if (!listed.ok) {
            built = { ok: false, code: 'inventory-failed', reason: listed.reason ?? listed.code };
          } else {
            baselineInventory = listed;
            baseline = await buildBaseline({ functions: listed.functions, workDir, name: `baseline-${iteration}` });
            sourceText = baseline.sourceText;
            built = baseline.ok
              ? baseline.built
              : { ...(baseline.built ?? {}), ok: false, code: 'baseline-failed', reason: baseline.reason };
            state.intake.functions = listed.total;
            state.intake.functionSample = listed.emitted;
          }
        }
      }

      let buildRecord = built;
      if (compare === null && built?.ok && typeof sourceText === 'string') {
        const runtimeFloor = await runtimeFloorFor(baselineInventory);
        try {
          compare = await compareDraft(sourceText, built, runtimeFloor);
        } catch (error) {
          buildRecord = { ...built, ok: false, code: 'compare-error', reason: error?.message ?? String(error) };
        }
      }
      let buildSha256 = null;
      if (buildRecord?.ok && buildRecord.outPath) {
        try {
          buildSha256 = createHash('sha256').update(await readFile(buildRecord.outPath)).digest('hex');
        } catch {
          buildSha256 = null;
        }
      }
      state.lastBuildSha256 = buildSha256;
      const draftKind = requested === 'auto'
        ? (auto?.startedFromSource ? 'source' : 'baseline')
        : requested;
      recordIteration(state, {
        sourceSha: typeof sourceText === 'string' ? createHash('sha256').update(sourceText).digest('hex') : null,
        sourceChars: typeof sourceText === 'string' ? sourceText.length : null,
        build: buildRecord,
        compare,
        draftKind,
        availableTools: typeof availableTools === 'function' ? availableTools() : availableTools,
      });
      if (baseline) {
        state.iterations[state.iterations.length - 1].baseline = {
          translated: baseline.translated.length,
          stubbed: baseline.stubbed.length,
          omitted: baseline.omitted.length,
          rounds: baseline.rounds,
          degraded: baseline.degraded === true,
        };
      }
      if (auto) state.iterations[state.iterations.length - 1].auto = auto;
      if (floorNote) state.iterations[state.iterations.length - 1].floorNote = floorNote;
      // Persist the draft that produced this iteration so a later call can
      // continue from it (draft=auto without source) instead of starting over.
      if (typeof sourceText === 'string' && sourceText.length > 0) {
        try {
          const draftPath = await store.writeState(`draft-${sha256.slice(0, 12)}-${iteration}.c`, sourceText);
          state.lastDraftPath = draftPath;
          state.iterations[state.iterations.length - 1].draftPath = draftPath;
        } catch {
          // A read-only state directory must not fail the measurement.
        }
      }
      await store.writeState(name, JSON.stringify(state, null, 2));
      return { text: `${renderLoop(state)}\n\nstate: ${stateFile}` };
    },
    isConcurrencySafe: () => false,
  };
  // The loop state names the target, drafts and state sidecar paths; redact
  // host identity from the rendered text. The state JSON on disk keeps the
  // real paths: it is a local file, and resume depends on them.
  return withRedactedOutput(tool);
}
