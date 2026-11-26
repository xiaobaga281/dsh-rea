/**
 * Summarize the function-level restoration gates across all targets.
 *
 * The gate (scripts/recon/restore.mjs) appends one machine-readable record per
 * run to dist/restore-gates.jsonl; this read-only pass turns that stream into
 * the per-target view the report needs: the latest positive and negative
 * control per target×metric, each run's score, and how many iterations the
 * closed loop took to converge. Nothing here executes samples or engines.
 *
 * The `corpus-adv` counter is the routine "real-sample convergence" number:
 * every gate run against a real adversarial corpus lands in the same stream,
 * so the rate is always one command away instead of buried in prose.
 *
 * Run: node scripts/gates/adv-gates-summary.mjs [record-path]
 *
 * Exit codes: 0 summary printed; 2 the record file is missing.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const recordPath = process.argv[2] ?? join('dist', 'restore-gates.jsonl');
if (!existsSync(recordPath)) {
  console.error(`adv-gates-summary: no gate record file: ${recordPath}`);
  process.exit(2);
}

const records = readFileSync(recordPath, 'utf8')
  .split(/\r?\n/)
  .filter((line) => line.trim().length > 0)
  .map((line) => JSON.parse(line));

/** Group records by target + metric/threshold; keep arrival order. */
const groups = new Map();
for (const record of records) {
  const key = `${record.target} [${record.metric}/${record.threshold}]`;
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(record);
}

console.log(`restoration gates: ${records.length} runs, ${groups.size} target×metric groups (latest per group; runs = loop iterations)`);
let adversarialRuns = 0;
let adversarialPassed = 0;
for (const [key, runs] of [...groups.entries()].sort()) {
  const latest = runs[runs.length - 1];
  const result = latest.result ?? {};
  const verdict = latest.exit === 0 ? 'PASS' : 'FAIL';
  if (String(latest.target).includes('corpus-adv')) {
    adversarialRuns += runs.length;
    if (latest.exit === 0 && latest.metric !== 'text') adversarialPassed += 1;
  }
  const matched = result.matched !== undefined ? `${result.matched}/${result.functions}` : '?';
  const score = typeof result.score === 'number' ? result.score.toFixed(3) : '?';
  const below = result.belowThreshold !== undefined ? result.belowThreshold : '-';
  console.log(`  ${verdict}  ${key}  score=${score} matched=${matched} below=${below} exit=${latest.exit} runs=${runs.length}`);
}
console.log(`corpus-adv (real adversarial) runs: ${adversarialRuns}, latest positive gates passed: ${adversarialPassed}`);
