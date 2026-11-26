/**
 * Review selected rebuilt functions against their target decompilation and
 * append one identity-bound record per run; manifest mode applies the same
 * review logic across pinned cases.
 *
 * @module dsh-rea-restore/scripts/recon/restore
 */
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { appendFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildReadiness, compileC } from '../../lib/restore/build.js';
import { checkSemanticHypothesis, compareBuilds } from '../../lib/restore/compare.js';
import { ghidraLocalReadiness, listFunctionsWithGhidra, selectedInventoryCoverage } from '../../lib/restore/ghidra-local.js';
import { parsePEImports } from '../../lib/static/intel.js';
import { extractDeepStrings } from '../../lib/static/strings.js';
import { readPeLayout } from '../../lib/static/structure.js';

const SHA256 = /^[a-f0-9]{64}$/i;
const METRICS = ['mixed', 'cfg', 'semantic', 'text'];
const ENGINE_EXECUTION_CODES = new Set(['unavailable', 'timeout', 'analysis-timeout', 'no-answer', 'inventory-page-limit']);

export class RestoreUsageError extends Error {}
export class RestoreDataError extends RestoreUsageError {}

function requireText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new RestoreUsageError(`${label} must be a non-empty string`);
  return value.trim();
}

function requireInteger(value, label, minimum = 0) {
  if (!Number.isInteger(value) || value < minimum) throw new RestoreUsageError(`${label} must be an integer >= ${minimum}`);
  return value;
}

function requireSha(value, label) {
  const text = requireText(value, label);
  if (!SHA256.test(text)) throw new RestoreUsageError(`${label} must be a SHA-256 hex digest`);
  return text.toLowerCase();
}

function normalizeScope(scope, functions) {
  if (!['whole-program', 'selected-functions'].includes(scope)) {
    throw new RestoreUsageError('scope must be whole-program or selected-functions');
  }
  if (!Array.isArray(functions) || functions.some((name) => typeof name !== 'string' || name.trim() === '')) {
    throw new RestoreUsageError('functions must be an array of non-empty names');
  }
  const names = [...new Set(functions.map((name) => name.trim()))];
  if (names.length !== functions.length) throw new RestoreUsageError('functions must not contain duplicates');
  if (scope === 'selected-functions' && names.length === 0) throw new RestoreUsageError('selected-functions needs at least one function');
  if (scope === 'whole-program' && names.length !== 0) throw new RestoreUsageError('whole-program must leave functions empty');
  return { kind: scope, functionNames: names };
}

function parseRestoreManifest(manifest) {
  if (!manifest || manifest.schemaVersion !== 1 || manifest.kind !== 'restore-gates') {
    throw new RestoreUsageError('manifest must use schemaVersion 1 and kind restore-gates');
  }
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw new RestoreUsageError('manifest files must not be empty');
  const ids = new Set();
  return manifest.files.map((item, index) => {
    const label = `files[${index}]`;
    const name = requireText(item?.name, `${label}.name`);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || ids.has(name)) throw new RestoreUsageError(`${label}.name must be unique and filesystem-safe`);
    ids.add(name);
    const scope = normalizeScope(item.scope, item.functions);
    if (!METRICS.includes(item.metric)) throw new RestoreUsageError(`${label}.metric is unsupported`);
    if (typeof item.threshold !== 'number' || !Number.isFinite(item.threshold) || item.threshold < 0 || item.threshold > 1) {
      throw new RestoreUsageError(`${label}.threshold must be a finite number from 0 to 1`);
    }
    const pageSize = item.pageSize === undefined ? 200 : requireInteger(item.pageSize, `${label}.pageSize`, 1);
    if (pageSize > 200) throw new RestoreUsageError(`${label}.pageSize must not exceed 200`);
    if (!item.expected || typeof item.expected !== 'object') throw new RestoreUsageError(`${label}.expected is required`);
    const expected = {
      functions: requireInteger(item.expected.functions, `${label}.expected.functions`, 1),
      matched: requireInteger(item.expected.matched, `${label}.expected.matched`, 0),
      belowThreshold: requireInteger(item.expected.belowThreshold, `${label}.expected.belowThreshold`, 0),
    };
    if (expected.matched + expected.belowThreshold !== expected.functions) {
      throw new RestoreUsageError(`${label}.expected matched + belowThreshold must equal functions`);
    }
    if (expected.belowThreshold !== 0 || expected.matched !== expected.functions) {
      throw new RestoreUsageError(`${label}.expected must describe a passing gate with every function matched and none below threshold`);
    }
    if (scope.kind === 'selected-functions' && expected.functions !== scope.functionNames.length) {
      throw new RestoreUsageError(`${label}.expected.functions must equal the requested function count`);
    }
    return {
      name,
      target: requireText(item.target, `${label}.target`),
      draft: requireText(item.draft, `${label}.draft`),
      bytes: requireInteger(item.bytes, `${label}.bytes`, 1),
      sha256: requireSha(item.sha256, `${label}.sha256`),
      draftSha256: requireSha(item.draftSha256, `${label}.draftSha256`),
      project: requireText(item.project, `${label}.project`),
      license: requireText(item.license, `${label}.license`),
      provenance: requireText(item.provenance, `${label}.provenance`),
      scope,
      metric: item.metric,
      threshold: item.threshold,
      pageSize,
      expected,
      hypotheses: item.hypotheses === undefined ? null : requireText(item.hypotheses, `${label}.hypotheses`),
    };
  });
}

export function validateRestoreManifest(manifest) {
  try {
    return parseRestoreManifest(manifest);
  } catch (error) {
    if (error instanceof RestoreDataError) throw error;
    throw new RestoreDataError(error?.message ?? String(error));
  }
}

export function evaluateRestoreResult({ scope, requested, expected, threshold, t2, inventory }) {
  const failures = [];
  if (t2?.status !== 'ran') failures.push(`T2 did not run (${t2?.status ?? 'missing'})`);
  if (typeof t2?.score !== 'number' || !Number.isFinite(t2.score)) failures.push('T2 score is not finite');
  else if (t2.score < threshold) failures.push(`T2 score ${t2.score} is below ${threshold}`);
  const expectedScope = scope === 'selected-functions' ? 'selected-functions' : 'all-functions';
  if (t2?.scope !== expectedScope) failures.push(`T2 scope is ${t2?.scope ?? 'missing'}, expected ${expectedScope}`);
  if (t2?.truncated === true || t2?.timeStopped === true || t2?.analysisTimedOut === true) failures.push('T2 inventory is truncated, stopped or timed out');
  if (!Number.isFinite(t2?.failed) || t2.failed < 0) failures.push('T2 decompile failure count is missing or invalid');
  const targetEnumerated = inventory?.inventoryComplete === true || inventory?.enumerationComplete === true;
  if (scope === 'whole-program') {
    if (t2?.inventoryComplete !== true || t2?.failed !== 0 || inventory?.inventoryComplete !== true || inventory?.truncated === true || inventory?.timeStopped === true || inventory?.analysisTimedOut === true || inventory?.failed !== 0) {
      failures.push('inventory is incomplete, truncated, stopped, timed out or failed');
    }
  } else {
    const coverage = t2?.selectedCoverage;
    const measuredSelection = coverage?.complete === true && coverage.requested === requested.length
      && ['target', 'rebuilt'].every((side) => {
        const item = coverage[side];
        return item?.complete === true && item.found === requested.length && item.decompiled === requested.length
          && item.missing?.length === 0 && item.failed?.length === 0 && item.ambiguous?.length === 0
          && (item.sourceFallback?.length ?? 0) === 0;
      });
    if (!targetEnumerated || !Number.isFinite(inventory?.failed) || inventory.failed < 0 || inventory?.truncated === true || inventory?.timeStopped === true || inventory?.analysisTimedOut === true) {
      failures.push('target inventory enumeration is incomplete, truncated, stopped or timed out');
    }
    const coverageBound = measuredSelection && t2?.inventoryEnumerationComplete === true;
    if (coverage ? !coverageBound : (t2?.inventoryComplete !== true || inventory?.failed > 0)) failures.push('selected-function decompilation coverage is incomplete');
    if (t2?.failed > 0 && t2?.inventoryComplete === true) failures.push('T2 claims a complete inventory despite decompile failures');
  }
  if (t2?.coverage !== 1) failures.push('T2 coverage is not complete');
  if (t2?.belowThreshold !== 0 || expected.belowThreshold !== 0) failures.push('a passing restore gate requires zero below-threshold functions');
  if (t2?.functions !== expected.functions) failures.push(`T2 functions ${t2?.functions ?? 'missing'} != expected ${expected.functions}`);
  if (t2?.matched !== expected.matched) failures.push(`T2 matched ${t2?.matched ?? 'missing'} != expected ${expected.matched}`);
  if (t2?.belowThreshold !== expected.belowThreshold) failures.push(`T2 belowThreshold ${t2?.belowThreshold ?? 'missing'} != expected ${expected.belowThreshold}`);
  if (scope === 'selected-functions' && requested.length !== expected.functions) failures.push('requested function count changed');
  return { passed: failures.length === 0, failures };
}

async function checkHypotheses(target, context, hypothesesPath) {
  if (!hypothesesPath) return null;
  const hypotheses = JSON.parse(await readFile(hypothesesPath, 'utf8'));
  if (!Array.isArray(hypotheses) || hypotheses.length === 0) throw new Error('the hypotheses file must hold a non-empty JSON array');
  return hypotheses.map((hypothesis) => {
    const check = checkSemanticHypothesis(target, context, hypothesis);
    const { boundary, ...rest } = check;
    return rest;
  });
}

export async function runRestoreReview(spec, {
  outDir, recordPath, hypothesesPath = null,
  readyBuild = buildReadiness, listFunctions = listFunctionsWithGhidra, build = compileC, compare = compareBuilds,
}) {
  const targetPath = spec.target;
  const draftPath = spec.draft;
  const names = spec.scope.functionNames;
  const scope = spec.scope.kind;
  let sourceBuffer;
  let targetBuffer;
  try {
    sourceBuffer = await readFile(draftPath);
    targetBuffer = await readFile(targetPath);
  } catch (error) {
    throw new RestoreDataError(`target or draft is unreadable: ${error?.message ?? error}`);
  }
  const sourceText = sourceBuffer.toString('utf8');
  const sourceSha256 = createHash('sha256').update(sourceBuffer).digest('hex');
  const targetSha256 = createHash('sha256').update(targetBuffer).digest('hex');
  const bindingErrors = [];
  if (spec.sha256 !== undefined && targetSha256 !== spec.sha256) bindingErrors.push('target SHA does not match the manifest');
  if (spec.bytes !== undefined && targetBuffer.length !== spec.bytes) bindingErrors.push('target size does not match the manifest');
  if (spec.draftSha256 !== undefined && sourceSha256 !== spec.draftSha256) bindingErrors.push('draft SHA does not match the manifest');
  if (bindingErrors.length > 0) {
    const record = {
      recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
      ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256,
      targetSize: targetBuffer.length, draftPath, sourceSha256, scope,
      requested: names, expected: spec.expected ?? null, bindingErrors, exit: 1,
    };
    return { record, exitCode: 1, consoleLines: bindingErrors.map((error) => `ERROR ${error}`) };
  }

  const builder = await readyBuild();
  if (!builder.ready) {
    const reason = builder.reason ?? 'gcc is not ready';
    return {
      record: {
        recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
        ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256,
        targetSize: targetBuffer.length, draftPath, sourceSha256, scope, requested: names,
        expected: spec.expected ?? null, result: { status: 'blocked', reason }, exit: 2,
      },
      exitCode: 2,
      consoleLines: [`build prerequisite unavailable: ${reason}`],
    };
  }

  const listed = await listFunctions(targetPath, {
    maxFunctions: spec.pageSize, timeoutMs: 300_000, allowDecompileFailures: scope === 'selected-functions',
  });
  const targetCoverage = scope === 'selected-functions' ? selectedInventoryCoverage(listed, names) : null;
  if (!listed.ok && !(scope === 'selected-functions' && listed.enumerationComplete === true)) {
    const exitCode = ENGINE_EXECUTION_CODES.has(listed.code) ? 2 : 1;
    return {
      record: {
        recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
        ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256,
        targetSize: targetBuffer.length, draftPath, sourceSha256, scope, requested: names,
        inventory: {
          total: listed.total ?? null, emitted: listed.emitted ?? null, inventoryComplete: false,
          enumerationComplete: listed.enumerationComplete === true, failed: listed.failed ?? null,
          truncated: listed.truncated === true, timeStopped: listed.timeStopped === true,
          analysisTimedOut: listed.analysisTimedOut === true,
        },
        result: { status: 'blocked', reason: listed.reason ?? listed.code }, exit: exitCode,
      },
      exitCode,
      consoleLines: [`inventory failed: ${listed.reason ?? listed.code}`],
    };
  }
  const selected = scope === 'selected-functions'
    ? listed.functions.filter((item) => names.includes(item.name) || (item.exportName !== undefined && names.includes(item.exportName)))
    : listed.functions;
  const missing = names.filter((name) => !selected.some((item) => item.name === name || item.exportName === name));
  const requested = scope === 'selected-functions' ? names : selected.map((item) => item.name);
  const expected = spec.expected ?? {
    functions: scope === 'selected-functions' ? names.length : listed.total,
    matched: scope === 'selected-functions' ? names.length : listed.total,
    belowThreshold: 0,
  };
  const consoleLines = [
    `target: ${targetPath} — ${listed.total} functions, ${listed.emitted} emitted across ${listed.pages ?? 1} page(s)`,
    `scope: ${scope}${scope === 'selected-functions' ? ` (${names.join(', ')})` : ''}`,
  ];
  if (scope === 'selected-functions' && listed.failed > 0) {
    consoleLines.push(`full inventory decompilation failures: ${listed.failed}; requested functions decompiled: ${targetCoverage.decompiled}/${targetCoverage.requested}`);
  }
  if (missing.length > 0 || targetCoverage?.complete === false) {
    if (missing.length > 0) consoleLines.push(`not in the inventory: ${missing.join(', ')}`);
    if (targetCoverage?.failed.length > 0) consoleLines.push(`decompilation failed: ${targetCoverage.failed.join(', ')}`);
    if (targetCoverage?.ambiguous.length > 0) consoleLines.push(`ambiguous identity: ${targetCoverage.ambiguous.join(', ')}`);
    const reason = [
      missing.length > 0 ? `missing functions: ${missing.join(', ')}` : null,
      targetCoverage?.failed.length > 0 ? `decompile failed: ${targetCoverage.failed.join(', ')}` : null,
      targetCoverage?.ambiguous.length > 0 ? `ambiguous identity: ${targetCoverage.ambiguous.join(', ')}` : null,
    ].filter(Boolean).join('; ');
    const record = {
      recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
      ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256,
      targetSize: targetBuffer.length, draftPath, sourceSha256, scope, requested: names,
      expected, inventory: {
        total: listed.total, emitted: listed.emitted, truncated: listed.truncated === true,
        inventoryComplete: listed.inventoryComplete === true, enumerationComplete: listed.enumerationComplete === true,
        failed: listed.failed ?? 0, pages: listed.pages ?? 1, cached: listed.fromCache === true,
        timeStopped: listed.timeStopped === true, analysisTimedOut: listed.analysisTimedOut === true,
        selectedCoverage: targetCoverage,
      },
      result: { status: 'blocked', reason }, exit: 1,
    };
    return { record, exitCode: 1, consoleLines };
  }
  for (const item of selected.slice(0, 40)) {
    consoleLines.push(`--- ${item.name}${item.exportName ? `/${item.exportName}` : ''} rva=${item.rva} size=${item.size} cfg=${JSON.stringify(item.cfg)}`);
    consoleLines.push(`calls: callees ${JSON.stringify(item.calls?.callees ?? [])}; callers ${JSON.stringify(item.calls?.callers ?? [])}`);
    consoleLines.push(`references: ${JSON.stringify(item.references ?? [])}${item.referencesTruncated ? ' (bounded)' : ''}`);
    consoleLines.push(item.body.slice(0, 2_000));
  }

  await mkdir(outDir, { recursive: true });
  const workDir = await mkdtemp(join(outDir, 'run-'));
  const built = await build({ sourceText, workDir, name: 'restored', extraArgs: ['-fno-stack-protector'] });
  if (!built.ok) {
    const exitCode = ENGINE_EXECUTION_CODES.has(built.code) ? 2 : 1;
    const record = {
      schemaVersion: 2, recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
      ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256,
      targetSize: targetBuffer.length, draftPath, sourceSha256, rebuiltSha256: null,
      scope, metric: spec.metric, threshold: spec.threshold, requested: names,
      expected, result: { status: 'blocked', reason: `draft did not compile: ${built.reason}`, code: built.code ?? null },
      gateFailures: [`draft did not compile: ${built.reason}`], exit: exitCode,
    };
    return { record, exitCode, consoleLines: [...consoleLines, `draft did not compile: ${built.reason}`] };
  }
  const rebuiltSha256 = String(built.sha256 ?? '').toLowerCase();
  let builtBuffer;
  try {
    builtBuffer = await readFile(built.outPath);
  } catch (error) {
    throw new RestoreDataError(`rebuilt artifact is unreadable: ${error?.message ?? error}`);
  }
  if (!SHA256.test(rebuiltSha256) || createHash('sha256').update(builtBuffer).digest('hex') !== rebuiltSha256) {
    const failure = 'rebuilt SHA does not match the build result';
    return {
      exitCode: 1,
      consoleLines: [...consoleLines, `FAIL ${failure}`],
      record: {
        schemaVersion: 2, recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
        ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256, targetSize: targetBuffer.length,
        draftPath, sourceSha256, rebuiltPath: built.outPath, rebuiltSha256: rebuiltSha256 || null, compiler: built.compiler ?? null,
        scope, metric: spec.metric, threshold: spec.threshold, requested: names, expected,
        result: { status: 'blocked', reason: failure }, gateFailures: [failure], exit: 1,
      },
    };
  }
  let result;
  try {
    result = await compare({
      targetPath, rebuiltPath: built.outPath, sourceText, engine: true, maxFunctions: spec.pageSize,
      functionFilter: scope === 'selected-functions' ? names : null,
      functionMetric: spec.metric, functionThreshold: spec.threshold, timeoutMs: 300_000,
    });
  } catch (error) {
    return {
      exitCode: 2,
      consoleLines: [...consoleLines, `comparison could not run: ${error?.message ?? error}`],
      record: {
        schemaVersion: 2, recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
        ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256, targetSize: targetBuffer.length,
        draftPath, sourceSha256, rebuiltPath: built.outPath,
        rebuiltSha256, compiler: built.compiler ?? null,
        scope, metric: spec.metric, threshold: spec.threshold, requested: names, expected,
        result: { status: 'blocked', reason: error?.message ?? String(error) }, exit: 2,
      },
    };
  }
  const t2 = result.tiers.t2;
  const evaluation = evaluateRestoreResult({ scope, requested, expected, threshold: spec.threshold, t2, inventory: listed });
  let afterTargetSha256 = null;
  let afterSourceSha256 = null;
  try {
    const afterTargetBuffer = await readFile(targetPath);
    const afterSourceBuffer = await readFile(draftPath);
    afterTargetSha256 = createHash('sha256').update(afterTargetBuffer).digest('hex');
    afterSourceSha256 = createHash('sha256').update(afterSourceBuffer).digest('hex');
  } catch (error) {
    evaluation.failures.push(`target or draft became unreadable during the review: ${error?.message ?? error}`);
    evaluation.passed = false;
  }
  if (afterTargetSha256 !== targetSha256 || afterSourceSha256 !== sourceSha256) {
    evaluation.failures.push('target or draft changed during the review');
    evaluation.passed = false;
  }
  try {
    const afterRebuiltSha256 = createHash('sha256').update(await readFile(built.outPath)).digest('hex');
    if (afterRebuiltSha256 !== rebuiltSha256) {
      evaluation.failures.push('rebuilt binary changed during the review');
      evaluation.passed = false;
    }
  } catch (error) {
    evaluation.failures.push(`rebuilt binary became unreadable during the review: ${error?.message ?? error}`);
    evaluation.passed = false;
  }
  consoleLines.push('', `T2 (${spec.metric}, threshold ${(spec.threshold * 100).toFixed(0)}%): ${t2.status}${typeof t2.score === 'number' ? ` ${(t2.score * 100).toFixed(1)}%` : ''}`
    + `${typeof t2.functions === 'number' ? ` — ${t2.matched}/${t2.functions} functions` : ''}`
    + `${typeof t2.coverage === 'number' ? `, coverage ${(t2.coverage * 100).toFixed(1)}%` : ''}`
    + `${typeof t2.belowThreshold === 'number' ? `, below threshold ${t2.belowThreshold}` : ''}`);
  if (t2.status !== 'ran') consoleLines.push(`reason: ${t2.reason}`);
  for (const mismatch of t2.mismatches ?? []) {
    if (mismatch.reason) { consoleLines.push(`- ${mismatch.name}: ${mismatch.reason}`); continue; }
    const parts = [`${(mismatch.similarity * 100).toFixed(1)}%`];
    if (mismatch.semanticSimilarity !== null) {
      const c = mismatch.semanticComponents ?? {};
      const percent = (value) => typeof value === 'number' ? `${(value * 100).toFixed(0)}%` : 'n/a';
      parts.push(`semantic ${(mismatch.semanticSimilarity * 100).toFixed(1)}% (constants ${percent(c.constants)} / operators ${percent(c.operators)} / keywords ${percent(c.keywords)} / calls ${percent(c.calls)})`);
    }
    if (mismatch.cfgSimilarity !== null) parts.push(`cfg ${(mismatch.cfgSimilarity * 100).toFixed(1)}%`);
    consoleLines.push(`- ${mismatch.name}: ${parts.join(' | ')}`);
  }

  let hypothesisResults = null;
  let hypothesisError = null;
  if (hypothesesPath) {
    try {
      const context = {
        layout: readPeLayout(targetBuffer), imports: parsePEImports(targetBuffer),
        strings: extractDeepStrings(targetBuffer, { minLength: 4, maxStrings: 4_000 }), functions: listed.functions,
      };
      hypothesisResults = await checkHypotheses(targetBuffer, context, hypothesesPath);
      for (const check of hypothesisResults) {
        consoleLines.push(`hypothesis "${check.id}" [${check.level}] -> ${check.status}`);
        consoleLines.push(`  claim: ${check.statement}`);
        consoleLines.push(`  ${check.detail}`);
        if (check.status !== 'verified') {
          consoleLines.push('  (recorded - hypothesis outcomes do not change the T2 verdict)');
        }
      }
    } catch (error) {
      hypothesisError = error?.message ?? String(error);
      evaluation.failures.push(`hypotheses could not be checked (${hypothesisError})`);
      evaluation.passed = false;
      consoleLines.push(`hypotheses could not be checked (${hypothesisError})`);
    }
  }
  const exitCode = evaluation.passed ? 0 : ENGINE_EXECUTION_CODES.has(t2.code) ? 2 : 1;
  for (const failure of evaluation.failures) consoleLines.push(`FAIL ${failure}`);
  const record = {
    schemaVersion: 2, recordedAt: new Date().toISOString(), mode: spec.expected ? 'manifest' : 'single-target',
    ...(spec.name ? { caseId: spec.name } : {}), target: targetPath, targetSha256, targetSize: targetBuffer.length,
    draftPath, sourceSha256, rebuiltPath: built.outPath, rebuiltSha256, compiler: built.compiler ?? null,
    scope, metric: spec.metric, threshold: spec.threshold, maxFunctions: spec.pageSize,
    pageSize: listed.pageSize ?? spec.pageSize, requested: names,
    ...(spec.project ? { project: spec.project, license: spec.license, provenance: spec.provenance } : {}),
    expected,
    inventory: {
      total: listed.total, emitted: listed.emitted, truncated: listed.truncated === true,
      inventoryComplete: listed.inventoryComplete === true, enumerationComplete: listed.enumerationComplete === true,
      failed: listed.failed ?? 0, selectedCoverage: targetCoverage,
      pages: listed.pages ?? 1, cached: listed.fromCache === true,
      timeStopped: listed.timeStopped === true, analysisTimedOut: listed.analysisTimedOut === true,
    },
    result: {
      status: t2.status, reason: t2.reason ?? null,
      ...(t2.code ? { code: t2.code } : {}),
      score: typeof t2.score === 'number' ? Number(t2.score.toFixed(4)) : null,
      matched: typeof t2.matched === 'number' ? t2.matched : null,
      functions: typeof t2.functions === 'number' ? t2.functions : null,
      coverage: typeof t2.coverage === 'number' ? Number(t2.coverage.toFixed(4)) : null,
      belowThreshold: t2.belowThreshold ?? null,
      inventoryComplete: t2.inventoryComplete === true,
      inventoryEnumerationComplete: t2.inventoryEnumerationComplete === true,
      failed: t2.failed ?? null, truncated: t2.truncated === true,
      timeStopped: t2.timeStopped === true, analysisTimedOut: t2.analysisTimedOut === true,
      selectedCoverage: t2.selectedCoverage ?? null,
    },
    gateFailures: evaluation.failures,
    mismatches: (t2.mismatches ?? []).slice(0, 20).map((mismatch) => ({
      name: mismatch.name, similarity: typeof mismatch.similarity === 'number' ? mismatch.similarity : null,
      reason: mismatch.reason ?? null,
    })),
    ...(hypothesisResults ? { hypotheses: hypothesisResults } : {}),
    ...(hypothesisError ? { hypothesesError: hypothesisError } : {}), exit: exitCode,
  };
  return { record, exitCode, consoleLines };
}

export async function appendGateRecord(recordPath, record) {
  if (recordPath === 'none') return null;
  await mkdir(dirname(resolve(recordPath)), { recursive: true });
  await appendFile(recordPath, `${JSON.stringify(record)}\n`, 'utf8');
  return recordPath;
}

function valueOf(args, flag, fallback = null) {
  const index = args.indexOf(flag);
  return index !== -1 && index + 1 < args.length ? args[index + 1] : fallback;
}

export function parseSingleSpec(args) {
  const target = args[0];
  if (typeof target !== 'string' || target.startsWith('--')) throw new RestoreUsageError('a target path is required');
  const scope = valueOf(args, '--scope', 'selected-functions');
  const names = String(valueOf(args, '--functions', '')).split(',').map((name) => name.trim()).filter(Boolean);
  const normalized = normalizeScope(scope, names);
  const draft = valueOf(args, '--draft');
  if (typeof draft !== 'string' || draft === '') throw new RestoreUsageError('a --draft file is required');
  const metric = valueOf(args, '--metric', 'semantic');
  if (!METRICS.includes(metric)) throw new RestoreUsageError(`--metric must be one of ${METRICS.join(', ')}`);
  const rawThreshold = valueOf(args, '--threshold', '0.9');
  const threshold = Number(rawThreshold);
  if (rawThreshold.trim() === '' || !Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
    throw new RestoreUsageError('--threshold must be a finite number from 0 to 1');
  }
  const pageSize = Number(valueOf(args, '--page-size', valueOf(args, '--max-functions', '200')));
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 200) throw new RestoreUsageError('--page-size must be an integer from 1 to 200');
  return {
    target, draft, scope: normalized, metric, threshold, pageSize,
    outDir: resolve(valueOf(args, '--out', join('dist', 'restore', basename(target).replace(/\.[^.]+$/, '')))),
    recordPath: valueOf(args, '--record', join('dist', 'restore-gates.jsonl')),
    hypothesesPath: valueOf(args, '--hypotheses'),
  };
}

export async function runManifest(manifestPath, args) {
  const absoluteManifest = resolve(manifestPath);
  let manifestBuffer;
  try {
    manifestBuffer = await readFile(absoluteManifest);
  } catch (error) {
    throw new RestoreDataError(`manifest is unreadable: ${error?.message ?? error}`);
  }
  const manifestSha256 = createHash('sha256').update(manifestBuffer).digest('hex');
  let cases;
  try {
    cases = validateRestoreManifest(JSON.parse(manifestBuffer.toString('utf8')));
  } catch (error) {
    throw new RestoreDataError(`invalid manifest: ${error?.message ?? error}`);
  }
  const base = dirname(absoluteManifest);
  const resolveFromManifest = (path) => isAbsolute(path) ? path : resolve(base, path);
  cases = cases.map((item) => ({
    ...item, target: resolveFromManifest(item.target), draft: resolveFromManifest(item.draft),
    hypothesesPath: item.hypotheses ? resolveFromManifest(item.hypotheses) : null,
  }));
  for (const item of cases) {
    for (const [label, path] of [['target', item.target], ['draft', item.draft]]) {
      if (!existsSync(path)) throw new RestoreDataError(`${item.name}: ${label} does not exist: ${path}`);
    }
    if (item.hypothesesPath && !existsSync(item.hypothesesPath)) throw new RestoreDataError(`${item.name}: hypotheses file does not exist: ${item.hypothesesPath}`);
  }
  const readiness = await ghidraLocalReadiness();
  if (!readiness.ready) throw new RestoreUsageError(`function-level review needs Ghidra (${readiness.reason})`);
  const outDir = resolve(valueOf(args, '--out', join('dist', 'restore-manifest')));
  const recordPath = valueOf(args, '--record', join('dist', 'restore-gates.jsonl'));
  const results = [];
  for (const item of cases) {
    console.log(`\n=== ${item.name} ===`);
    let review;
    try {
      review = await runRestoreReview(item, {
        outDir: join(outDir, item.name), recordPath, hypothesesPath: item.hypothesesPath,
      });
    } catch (error) {
      const exitCode = error instanceof RestoreDataError ? 1 : 2;
      review = {
        exitCode,
        consoleLines: [`review could not run: ${error?.message ?? error}`],
        record: {
          schemaVersion: 2, recordedAt: new Date().toISOString(), mode: 'manifest', caseId: item.name,
          target: item.target, draftPath: item.draft, scope: item.scope.kind, requested: item.scope.functionNames,
          expected: item.expected, result: { status: 'blocked', reason: error?.message ?? String(error) }, exit: exitCode,
        },
      };
    }
    let exitCode = review.exitCode;
    let recordWriteError = null;
    try {
      const written = await appendGateRecord(recordPath, review.record);
      if (written) review.consoleLines.push(`gate record appended -> ${written}`);
    } catch (error) {
      recordWriteError = error?.message ?? String(error);
      exitCode = 1;
      review.record.exit = 1;
      review.consoleLines.push(`ERROR gate record could not be written (${recordWriteError})`);
    }
    console.log(`\n=== ${item.name} ===`);
    for (const line of review.consoleLines) console.log(line);
    results.push({ name: item.name, exit: exitCode, recordWriteError, record: review.record });
  }
  const exit = results.some((item) => item.exit === 2) ? 2 : results.some((item) => item.exit !== 0) ? 1 : 0;
  const report = {
    schemaVersion: 1, mode: 'release-gate', generatedAt: new Date().toISOString(),
    manifestPath: absoluteManifest, manifestSha256, passed: exit === 0, exit,
    cases: results.map(({ recordWriteError, ...item }) => item),
  };
  await mkdir(outDir, { recursive: true });
  const reportPath = join(outDir, 'restore-manifest.json');
  try {
    await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  } catch (error) {
    console.error(`manifest report could not be written (${error?.message ?? error})`);
    return 1;
  }
  console.log(`\nmanifest ${results.filter((item) => item.exit === 0).length}/${results.length} passed; exit ${exit}`);
  console.log(`json ${reportPath}`);
  return exit;
}

async function main() {
  const args = process.argv.slice(2);
  try {
    if (args.includes('--manifest')) {
      const manifestPath = valueOf(args, '--manifest');
      if (!manifestPath || manifestPath.startsWith('--')) throw new RestoreUsageError('--manifest needs a file path');
      return await runManifest(manifestPath, args);
    }
    const spec = parseSingleSpec(args);
    if (!existsSync(spec.target) || !existsSync(spec.draft)) throw new RestoreDataError('target or draft does not exist');
    if (spec.hypothesesPath && !existsSync(spec.hypothesesPath)) throw new RestoreDataError(`hypotheses file does not exist: ${spec.hypothesesPath}`);
    const readiness = await ghidraLocalReadiness();
    if (!readiness.ready) throw new RestoreUsageError(`function-level review needs Ghidra (${readiness.reason}); no downgrade to text-only scoring`);
    const review = await runRestoreReview(spec, { outDir: spec.outDir, recordPath: spec.recordPath, hypothesesPath: spec.hypothesesPath });
    for (const line of review.consoleLines) console.log(line);
    let exitCode = review.exitCode;
    try {
      const written = await appendGateRecord(spec.recordPath, review.record);
      if (written) console.log(`gate record appended -> ${written}`);
    } catch (error) {
      console.error(`gate record could not be written (${error?.message ?? error})`);
      review.record.exit = 1;
      exitCode = 1;
    }
    return exitCode;
  } catch (error) {
    console.error(error instanceof RestoreUsageError ? error.message : `review could not run: ${error?.message ?? error}`);
    return error instanceof RestoreDataError ? 1 : 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exit(await main());
}
