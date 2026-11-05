/**
 * Two-persona duel.
 *
 *   Defender: rebuild the target harder each generation (scripts/duel/defender.mjs)
 *   Attacker: analyse it with the shipped tools (scripts/duel/attacker.mjs)
 *   Scorer:   scripts/duel/score.mjs (pure, unit-tested)
 *
 * The control generation D0 stores everything in plaintext, so the attacker's
 * own D0 result defines the reachable ceiling *and* the benign noise baseline.
 * Every later generation is scored against that ceiling, which keeps the ground
 * truth honest without a hand-maintained expectation list.
 *
 * Run: npm run duel [-- --out dist/duel --label 1.8.4]
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { buildGeneration, GENERATION_IDS } from './duel/defender.mjs';
import { attack, loadTools } from './duel/attacker.mjs';
import { scoreAll } from './duel/score.mjs';

const out = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : join('dist', 'duel');
const label = process.argv.includes('--label') ? process.argv[process.argv.indexOf('--label') + 1] : 'run';
const generations = process.argv.includes('--only')
  ? process.argv[process.argv.indexOf('--only') + 1].split(',')
  : GENERATION_IDS;

mkdirSync(out, { recursive: true });

const tools = await loadTools();
const rows = [];

for (const id of generations) {
  const built = buildGeneration(id);
  const file = resolve(out, `${id}.exe`);
  writeFileSync(file, built.buffer);
  const result = await attack(tools, file);
  rows.push({
    id,
    note: built.note,
    bytes: built.buffer.length,
    decoys: built.decoys,
    decoyIocs: built.decoyIocs,
    decoyApis: built.decoyApis,
    unrecoverable: built.unrecoverable,
    sealed: built.sealed ?? [],
    ...result,
  });
}

const { ceiling, baselineNoise, scored, mean, weakest, honestyFailures, noisePeak, precisionFloor } = scoreAll(rows);

const report = {
  schemaVersion: 2,
  label,
  generatedAt: new Date().toISOString(),
  toolVersion: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version,
  ceiling,
  baselineNoise,
  generations: scored,
  mean,
  weakest,
  honestyFailures,
  noisePeak,
  precisionFloor,
};

writeFileSync(join(out, 'duel.json'), `${JSON.stringify(report, null, 2)}\n`);

// ------------------------------------------------------------------ console --

const pad = (value, width) => String(value).padEnd(width);
const pct = (value) => `${(value * 100).toFixed(1)}%`;

console.log(`duel [${label}] v${report.toolVersion}`);
console.log(`ceiling from D0: ${ceiling.endpoints.length} endpoints, ${ceiling.iocText.length} indicators, `
  + `${ceiling.tracking.length} tracking families, ${ceiling.anti.length} anti markers, ${ceiling.watermarks.length} watermarks`
  + ` | noise baseline ${baselineNoise}`);
console.log('');
for (const row of scored) {
  if (row.id === 'D0') continue;
  console.log(`D${row.id.slice(1)}  defender: ${row.note}`);
  console.log(`    endpoints ${row.got.endpoints.length}/${row.reachable.endpoints.length}  `
    + `indicators ${row.got.iocText.length}/${row.reachable.iocText.length}  `
    + `tracking ${row.got.tracking.length}/${row.reachable.tracking.length}  `
    + `anti ${row.got.anti.length}/${row.reachable.anti.length}  `
    + `watermark ${row.got.watermarks.length}/${row.reachable.watermarks.length}  `
    + `| noise ${row.noise}${row.extraNoise ? ` (+${row.extraNoise} over baseline)` : ''}${row.sealed?.length ? `  sealed ${row.sealed.length}` : ''}`
    + `${row.decoyIocs ? `  bait: ${row.decoyIocs} IoCs / ${row.decoyApis} APIs` : ''}`);
  console.log(`    api ${row.got.api.length}/${row.reachable.api.length}  `
    + `behaviour ${row.got.behavior.length}/${row.reachable.behavior.length}  `
    + `plan ${row.unrecoverable ? (row.planOk ? 'yes' : 'NO') : 'n/a'}`
    + `  verify ${row.probe ? (row.probe.tier === 'local' ? `local:${row.probe.verdict ?? '?'}` : (row.probe.ok && row.probe.name ? row.probe.name : 'FAILED')) : 'n/a'}`
    + `  precision ${pct(row.precision)}`);
  const misses = Object.entries(row.missing).filter(([, list]) => list.length > 0)
    .map(([key, list]) => `${key}: ${list.slice(0, 3).join(' | ')}`);
  if (misses.length > 0) console.log(`    blind spots: ${misses.join('  ;;  ')}`);
  if (row.honesty !== null) console.log(`    honesty (reports the unopenable region): ${row.honesty ? 'yes' : 'NO'}`);
  console.log(`    score ${pct(row.overall)}`);
  console.log('');
}
console.log(`${pad('gen', 5)}${pad('endpoint', 10)}${pad('indicator', 11)}${pad('tracking', 10)}${pad('anti', 7)}${pad('wm', 6)}${pad('api', 7)}${pad('behav', 8)}${pad('plan', 6)}${pad('verify', 8)}${pad('prec', 7)}${pad('noise', 7)}score`);
for (const row of scored) {
  console.log(`${pad(row.id, 5)}${pad(`${row.got.endpoints.length}/${row.reachable?.endpoints.length ?? ceiling.endpoints.length}`, 10)}`
    + `${pad(`${row.got.iocText.length}/${row.reachable?.iocText.length ?? ceiling.iocText.length}`, 11)}`
    + `${pad(`${row.got.tracking.length}/${row.reachable?.tracking.length ?? ceiling.tracking.length}`, 10)}`
    + `${pad(`${row.got.anti.length}/${row.reachable?.anti.length ?? ceiling.anti.length}`, 7)}`
    + `${pad(`${row.got.watermarks.length}/${row.reachable?.watermarks.length ?? ceiling.watermarks.length}`, 6)}`
    + `${pad(`${row.got.api.length}/${row.reachable?.api.length ?? ceiling.api.length}`, 7)}`
    + `${pad(`${row.got.behavior.length}/${row.reachable?.behavior.length ?? ceiling.behavior.length}`, 8)}`
    + `${pad(row.unrecoverable ? (row.planOk ? 'yes' : 'NO') : '-', 6)}`
    + `${pad(row.probe ? (row.probe.tier === 'local' ? (row.probe.ok ? 'local' : 'NO') : (row.probe.ok && row.probe.name ? 'yes' : 'NO')) : '-', 8)}`
    + `${pad(pct(row.precision), 7)}`
    + `${pad(row.noise, 7)}${pct(row.overall)}`);
}
console.log(`mean ${pct(mean)}  weakest ${weakest}  precision floor ${pct(precisionFloor)}  honesty failures: ${honestyFailures.join(', ') || 'none'}`);
console.log("json " + join(out, 'duel.json'));

// The plugin registers a web server and keeps handles open; a CLI run must not
// hang waiting for them.
await new Promise((resolve) => setTimeout(resolve, 50));
process.exit(0);
