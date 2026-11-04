/**
 * Two-persona duel.
 *
 *   Defender: rebuild the target harder each generation (scripts/duel/defender.mjs)
 *   Attacker: analyse it with the shipped tools (scripts/duel/attacker.mjs)
 *
 * The control generation D0 stores everything in plaintext, so the attacker's
 * own D0 result defines the reachable ceiling. Every later generation is scored
 * against that ceiling, which keeps the ground truth honest without a
 * hand-maintained expectation list.
 *
 * Run: npm run duel [-- --out dist/duel --label 1.7.0]
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { buildGeneration, GENERATION_IDS } from './duel/defender.mjs';
import { attack, loadTools } from './duel/attacker.mjs';

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
    unrecoverable: built.unrecoverable,
    ...result,
  });
}

const control = rows.find((row) => row.id === 'D0');
if (!control) throw new Error('D0 control missing: it defines the ceiling for every other generation');

const ceiling = {
  endpoints: control.endpoints,
  iocText: control.iocText,
  tracking: control.trackingIds,
  anti: control.antiTechniques,
  watermarks: control.watermarks,
  // The analyst-level dimensions also take their ceiling from D0: whatever the
  // plaintext control exposes is the reachable set, not a hand-written list.
  api: control.apiHits,
  behavior: control.behaviorHits,
};

// Rebalanced for the L3 question. String recall still leads, because a report
// that cannot name the endpoint is not a report; but structure, behaviour and
// the next experiment now carry 43% between them, which is the difference
// between a technician and an analyst.
const WEIGHTS = {
  endpoints: 0.15, iocText: 0.15, tracking: 0.10, anti: 0.12, watermarks: 0.05,
  api: 0.15, behavior: 0.15, plan: 0.13,
};

const ratio = (hit, total) => (total === 0 ? 1 : Number((hit / total).toFixed(3)));
const scoreRow = (row) => {
  const got = {
    endpoints: row.endpoints.filter((value) => ceiling.endpoints.includes(value)),
    iocText: row.iocText.filter((value) => ceiling.iocText.includes(value)),
    tracking: row.trackingIds.filter((value) => ceiling.tracking.includes(value)),
    anti: row.antiTechniques.filter((value) => ceiling.anti.includes(value)),
    watermarks: row.watermarks.filter((value) => ceiling.watermarks.includes(value)),
    api: row.apiHits.filter((value) => ceiling.api.includes(value)),
    behavior: row.behaviorHits.filter((value) => ceiling.behavior.includes(value)),
  };
  const recall = {
    endpoints: ratio(got.endpoints.length, ceiling.endpoints.length),
    iocText: ratio(got.iocText.length, ceiling.iocText.length),
    tracking: ratio(got.tracking.length, ceiling.tracking.length),
    anti: ratio(got.anti.length, ceiling.anti.length),
    watermarks: ratio(got.watermarks.length, ceiling.watermarks.length),
    // A dimension with nothing in the control is not "fully covered" - it is
    // unmeasurable, and counting it as 1.0 would quietly inflate every row.
    api: ceiling.api.length === 0 ? null : ratio(got.api.length, ceiling.api.length),
    behavior: ceiling.behavior.length === 0 ? null : ratio(got.behavior.length, ceiling.behavior.length),
    plan: row.unrecoverable ? (row.planOk ? 1 : 0) : null,
  };
  // `plan` only means something when something is actually sealed; for the
  // open generations its weight is redistributed instead of scored as a free 1.
  let weighted = 0;
  let total = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const value = recall[key];
    if (value === null) continue;
    weighted += value * weight;
    total += weight;
  }
  const overall = Number((weighted / total).toFixed(4));
  const missing = {
    endpoints: ceiling.endpoints.filter((value) => !got.endpoints.includes(value)),
    iocText: ceiling.iocText.filter((value) => !got.iocText.includes(value)),
    tracking: ceiling.tracking.filter((value) => !got.tracking.includes(value)),
    anti: ceiling.anti.filter((value) => !got.anti.includes(value)),
    watermarks: ceiling.watermarks.filter((value) => !got.watermarks.includes(value)),
    api: ceiling.api.filter((value) => !got.api.includes(value)),
    behavior: ceiling.behavior.filter((value) => !got.behavior.includes(value)),
  };
  // A target that cannot be opened statically must be reported as such; silence
  // is a worse answer than "this region needs a dynamic trace".
  const honesty = row.unrecoverable ? row.unresolved : null;
  return {
    ...row, got, recall, overall,
    missing,
    honesty,
    noise: row.noise.length,
  };
};

const scored = rows.map((row) => (row.id === 'D0' ? {
  ...row,
  got: { endpoints: row.endpoints, iocText: row.iocText, tracking: row.trackingIds, anti: row.antiTechniques, watermarks: row.watermarks, api: row.apiHits, behavior: row.behaviorHits },
  recall: { endpoints: 1, iocText: 1, tracking: 1, anti: 1, watermarks: 1, api: 1, behavior: 1, plan: null },
  overall: 1,
  missing: { endpoints: [], iocText: [], tracking: [], anti: [], watermarks: [], api: [], behavior: [] },
  honesty: null,
  noise: row.noise.length,
} : scoreRow(row)));

const attackable = scored.filter((row) => row.id !== 'D0');
const mean = attackable.length === 0 ? 0 : Number((attackable.reduce((sum, row) => sum + row.overall, 0) / attackable.length).toFixed(4));

const report = {
  schemaVersion: 1,
  label,
  generatedAt: new Date().toISOString(),
  toolVersion: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version,
  ceiling,
  generations: scored,
  mean,
  weakest: null,
  honestyFailures: scored.filter((row) => row.honesty === false).map((row) => row.id),
  noisePeak: Math.max(...scored.map((row) => row.noise)),
};
report.weakest = attackable.length > 0
  ? attackable.reduce((worst, row) => (row.overall < worst.overall ? row : worst), attackable[0]).id
  : null;

writeFileSync(join(out, 'duel.json'), `${JSON.stringify(report, null, 2)}\n`);

// ------------------------------------------------------------------ console --

const pad = (value, width) => String(value).padEnd(width);
const pct = (value) => `${(value * 100).toFixed(1)}%`;

console.log(`duel [${label}] v${report.toolVersion}`);
console.log(`ceiling from D0: ${ceiling.endpoints.length} endpoints, ${ceiling.iocText.length} indicators, `
  + `${ceiling.tracking.length} tracking families, ${ceiling.anti.length} anti markers, ${ceiling.watermarks.length} watermarks`);
console.log('');
for (const row of scored) {
  if (row.id === 'D0') continue;
  console.log(`D${row.id.slice(1)}  defender: ${row.note}`);
  console.log(`    endpoints ${row.got.endpoints.length}/${ceiling.endpoints.length}  `
    + `indicators ${row.got.iocText.length}/${ceiling.iocText.length}  `
    + `tracking ${row.got.tracking.length}/${ceiling.tracking.length}  `
    + `anti ${row.got.anti.length}/${ceiling.anti.length}  `
    + `watermark ${row.got.watermarks.length}/${ceiling.watermarks.length}  `
    + `| noise ${row.noise}`);
  console.log(`    api ${row.got.api.length}/${ceiling.api.length}  `
    + `behaviour ${row.got.behavior.length}/${ceiling.behavior.length}  `
    + `plan ${row.unrecoverable ? (row.planOk ? 'yes' : 'NO') : 'n/a'}`);
  const misses = Object.entries(row.missing).filter(([, list]) => list.length > 0)
    .map(([key, list]) => `${key}: ${list.slice(0, 3).join(' | ')}`);
  if (misses.length > 0) console.log(`    blind spots: ${misses.join('  ;;  ')}`);
  if (row.honesty !== null) console.log(`    honesty (reports the unopenable region): ${row.honesty ? 'yes' : 'NO'}`);
  console.log(`    score ${pct(row.overall)}`);
  console.log('');
}
console.log(`${pad('gen', 5)}${pad('endpoint', 10)}${pad('indicator', 11)}${pad('tracking', 10)}${pad('anti', 7)}${pad('wm', 6)}${pad('api', 7)}${pad('behav', 8)}${pad('plan', 6)}${pad('noise', 7)}score`);
for (const row of scored) {
  console.log(`${pad(row.id, 5)}${pad(`${row.got.endpoints.length}/${ceiling.endpoints.length}`, 10)}`
    + `${pad(`${row.got.iocText.length}/${ceiling.iocText.length}`, 11)}`
    + `${pad(`${row.got.tracking.length}/${ceiling.tracking.length}`, 10)}`
    + `${pad(`${row.got.anti.length}/${ceiling.anti.length}`, 7)}`
    + `${pad(`${row.got.watermarks.length}/${ceiling.watermarks.length}`, 6)}`
    + `${pad(`${row.got.api.length}/${ceiling.api.length}`, 7)}`
    + `${pad(`${row.got.behavior.length}/${ceiling.behavior.length}`, 8)}`
    + `${pad(row.unrecoverable ? (row.planOk ? 'yes' : 'NO') : '-', 6)}`
    + `${pad(row.noise, 7)}${pct(row.overall)}`);
}
console.log(`mean ${pct(mean)}  weakest ${report.weakest}  honesty failures: ${report.honestyFailures.join(', ') || 'none'}`);
console.log("json " + join(out, 'duel.json'));

// The plugin registers a web server and keeps handles open; a CLI run must not
// hang waiting for them.
await new Promise((resolve) => setTimeout(resolve, 50));
process.exit(0);
