/**
 * Function-level restoration review against a real target.
 *
 * Usage:
 *   node scripts/recon-restore.mjs <target> --functions FUN_a,FUN_b --draft <file.c>
 *        [--max-functions 200] [--metric semantic|cfg|mixed|text] [--threshold 0.9] [--out <dir>]
 *        [--record <path|none>] [--hypotheses <file.json>]
 *
 * Every completed review appends one machine-readable JSON line to
 * dist/restore-gates.jsonl (override with --record <path>, disable with
 * --record none), so gate results can be checked against structured records
 * instead of extracting numbers from this text output.
 *
 * Prints the target pseudocode for the requested functions so a draft can be
 * written against it, compiles the draft, and compares ONLY those functions by
 * name. T2 must run, because CFG shape is the cross-compiler signal; without
 * Ghidra the review is refused rather than downgraded to a text guess.
 *
 * Exit codes: 0 all requested functions matched; 1 a function is missing or
 * below the review floor; 2 the review could not run.
 */
import { existsSync } from 'node:fs';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

import { compileC } from '../lib/build.js';
import { checkSemanticHypothesis, compareBuilds } from '../lib/compare.js';
import { ghidraLocalReadiness, listFunctionsWithGhidra } from '../lib/ghidra-local.js';
import { parsePEImports } from '../lib/intel.js';
import { extractDeepStrings } from '../lib/strings.js';
import { readPeLayout } from '../lib/structure.js';

const args = process.argv.slice(2);
const target = args[0];
if (typeof target !== 'string' || target.startsWith('--')) {
  console.error('usage: node scripts/recon-restore.mjs <target> --functions NAME[,NAME] --draft <file.c> [--max-functions 200] [--metric cfg]');
  process.exit(2);
}
const valueOf = (flag, fallback = null) => {
  const index = args.indexOf(flag);
  return index !== -1 && index + 1 < args.length ? args[index + 1] : fallback;
};
const names = String(valueOf('--functions', '')).split(',').map((name) => name.trim()).filter(Boolean);
const draftPath = valueOf('--draft');
const maxFunctions = Math.max(1, Math.min(200, Number.parseInt(valueOf('--max-functions', '200'), 10) || 200));
const metric = ['mixed', 'cfg', 'semantic', 'text'].includes(valueOf('--metric', 'semantic')) ? valueOf('--metric', 'semantic') : 'semantic';
const threshold = Math.max(0, Math.min(1, Number.parseFloat(valueOf('--threshold', '0.9')) || 0.9));
if (names.length === 0 || typeof draftPath !== 'string') {
  console.error('a --functions list and a --draft file are required');
  process.exit(2);
}
if (!existsSync(target) || !existsSync(draftPath)) {
  console.error('target or draft does not exist');
  process.exit(2);
}
const outDir = resolve(valueOf('--out', join('dist', 'restore', basename(target).replace(/\.[^.]+$/, ''))));
const recordPath = valueOf('--record', join('dist', 'restore-gates.jsonl'));
const hypothesesPath = valueOf('--hypotheses');

const readiness = await ghidraLocalReadiness();
if (!readiness.ready) {
  console.error(`function-level review needs Ghidra (${readiness.reason}); no downgrade to text-only scoring`);
  process.exit(2);
}
const listed = await listFunctionsWithGhidra(target, { maxFunctions, timeoutMs: 300_000 });
if (!listed.ok) {
  console.error(`inventory failed: ${listed.reason ?? listed.code}`);
  process.exit(2);
}
const selected = listed.functions.filter((item) => names.includes(item.name) || (item.exportName !== undefined && names.includes(item.exportName)));
const missing = names.filter((name) => !selected.some((item) => item.name === name || item.exportName === name));
console.log(`target: ${target} — ${listed.total} functions, ${listed.emitted} emitted${listed.truncated ? ' (cap)' : ''}${listed.analysisTimedOut ? ' (analysis timed out at the ceiling)' : ''}`);
if (missing.length > 0) {
  console.error(`not in the inventory: ${missing.join(', ')}`);
  console.error(`available: ${listed.functions.map((item) => item.name).slice(0, 40).join(', ')}${listed.functions.length > 40 ? ' …' : ''}`);
  process.exit(2);
}
for (const item of selected) {
  console.log(`--- ${item.name} rva=${item.rva} size=${item.size} cfg=${JSON.stringify(item.cfg)}`);
  console.log(item.body.slice(0, 2_000));
}
const sourceText = await readFile(draftPath, 'utf8');
await mkdir(outDir, { recursive: true });
const built = await compileC({
  sourceText,
  workDir: outDir,
  name: 'restored',
  // A review build should not add instrumentation the target does not carry:
  // stack-protector branches change the CFG and score as a mismatch.
  extraArgs: ['-fno-stack-protector'],
});
if (!built.ok) {
  console.error(`draft did not compile: ${built.reason}`);
  process.exit(1);
}
const result = await compareBuilds({
  targetPath: target,
  rebuiltPath: built.outPath,
  sourceText,
  engine: true,
  maxFunctions,
  functionFilter: names,
  functionMetric: metric,
  functionThreshold: threshold,
  timeoutMs: 300_000,
});
const t2 = result.tiers.t2;
console.log('');
console.log(`T2 (${metric}, threshold ${(threshold * 100).toFixed(0)}%): ${t2.status}${typeof t2.score === 'number' ? ` ${(t2.score * 100).toFixed(1)}%` : ''}`
  + `${typeof t2.functions === 'number' ? ` — ${t2.matched}/${t2.functions} functions` : ''}`
  + `${typeof t2.coverage === 'number' ? `, coverage ${(t2.coverage * 100).toFixed(1)}%` : ''}`
  + `${typeof t2.belowThreshold === 'number' ? `, below threshold ${t2.belowThreshold}` : ''}`);
if (t2.status !== 'ran') console.log(`reason: ${t2.reason}`);
for (const mismatch of t2.mismatches ?? []) {
  if (mismatch.reason) {
    console.log(`- ${mismatch.name}: ${mismatch.reason}`);
    continue;
  }
  const parts = [`${(mismatch.similarity * 100).toFixed(1)}%`];
  if (mismatch.semanticSimilarity !== null) {
    const c = mismatch.semanticComponents;
    parts.push(`semantic ${(mismatch.semanticSimilarity * 100).toFixed(1)}% (constants ${(c.constants * 100).toFixed(0)} / operators ${(c.operators * 100).toFixed(0)} / keywords ${(c.keywords * 100).toFixed(0)} / calls ${c.calls === null ? 'n/a' : `${(c.calls * 100).toFixed(0)}%`})`);
  }
  if (mismatch.cfgSimilarity !== null) parts.push(`cfg ${(mismatch.cfgSimilarity * 100).toFixed(1)}%`);
  console.log(`- ${mismatch.name}: ${parts.join(' | ')}`);
}
const exitCode = t2.status === 'ran' && t2.matched === names.length && (t2.belowThreshold ?? 0) === 0 ? 0 : 1;
// Optional attribution surface: check semantic hypotheses against the target's
// own evidence. Additive output - a refuted hypothesis is recorded and shown,
// it never flips the function-review exit code.
let hypothesisResults = null;
if (hypothesesPath) {
  try {
    const hypotheses = JSON.parse(await readFile(hypothesesPath, 'utf8'));
    if (!Array.isArray(hypotheses)) throw new Error('the hypotheses file must hold a JSON array');
    const targetBuffer = await readFile(target);
    const context = {
      layout: readPeLayout(targetBuffer),
      imports: parsePEImports(targetBuffer),
      strings: extractDeepStrings(targetBuffer, { minLength: 4, maxStrings: 4_000 }),
      functions: listed.functions,
    };
    hypothesisResults = hypotheses.map((hypothesis) => checkSemanticHypothesis(targetBuffer, context, hypothesis));
    console.log('');
    for (const check of hypothesisResults) {
      console.log(`hypothesis "${check.id}" [${check.level}] -> ${check.status}`);
      console.log(`  claim: ${check.statement}`);
      console.log(`  ${check.detail}`);
      if (check.status !== 'verified') console.log('  (not verified - an unverified or refuted hypothesis is not a pass)');
    }
  } catch (error) {
    console.error(`hypotheses could not be checked (${error?.message ?? error})`);
  }
}
if (recordPath !== 'none') {
  // One JSON line per review, so a validator can align gate numbers against
  // structured records instead of scraping this text output. The target field
  // keeps the exact path string handed to the gate, because the inventory
  // cache keys on that string verbatim. An unwritable record never changes the
  // verdict: the review itself already ran and printed.
  try {
    await mkdir(dirname(resolve(recordPath)), { recursive: true });
    const record = {
      recordedAt: new Date().toISOString(),
      target,
      metric,
      threshold,
      maxFunctions,
      requested: names,
      inventory: {
        total: listed.total,
        emitted: listed.emitted,
        truncated: listed.truncated === true,
        cached: listed.fromCache === true,
        timeStopped: listed.timeStopped === true,
        analysisTimedOut: listed.analysisTimedOut === true,
      },
      result: {
        status: t2.status,
        score: typeof t2.score === 'number' ? Number(t2.score.toFixed(4)) : null,
        matched: typeof t2.matched === 'number' ? t2.matched : null,
        functions: typeof t2.functions === 'number' ? t2.functions : null,
        coverage: typeof t2.coverage === 'number' ? Number(t2.coverage.toFixed(4)) : null,
        belowThreshold: t2.belowThreshold ?? 0,
      },
      mismatches: (t2.mismatches ?? []).slice(0, 20).map((mismatch) => ({
        name: mismatch.name,
        similarity: typeof mismatch.similarity === 'number' ? mismatch.similarity : null,
        reason: mismatch.reason ?? null,
      })),
      ...(hypothesisResults ? { hypotheses: hypothesisResults.map(({ boundary, ...rest }) => rest) } : {}),
      exit: exitCode,
    };
    await appendFile(recordPath, `${JSON.stringify(record)}\n`, 'utf8');
    console.log(`gate record appended -> ${recordPath}`);
  } catch (error) {
    console.error(`gate record could not be written (${error?.message ?? error})`);
  }
}
process.exit(exitCode);
