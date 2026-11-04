/**
 * Real-world capability scan.
 *
 * Runs the shipped tools over the downloaded corpus and records what an analyst
 * would actually see: how long a scan takes per megabyte, how many indicators
 * appear, whether the tracking/anti-analysis heuristics stay quiet on software
 * that does not phone home, and whether anything crashes on a real PE.
 *
 * The corpus is deleted afterwards; scan.json keeps the numbers and the hashes
 * so the run can be repeated with the same files.
 *
 *   node scripts/corpus-scan.mjs [--out dist/corpus/scan.json]
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { loadTools } from './duel/attacker.mjs';

const out = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : join('dist', 'corpus', 'scan.json');
const manifestPath = join('dist', 'corpus', 'manifest.json');
if (!existsSync(manifestPath)) throw new Error('run node scripts/fetch-corpus.mjs first');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

const tools = await loadTools();
const textOf = (result) => (typeof result?.text === 'string' ? result.text : '');

const call = async (name, args) => {
  const tool = tools.get(name);
  if (!tool?.execute) return { text: '', ms: 0, error: 'missing' };
  const started = process.hrtime.bigint();
  try {
    const text = textOf(await tool.execute(args));
    return { text, ms: Number(process.hrtime.bigint() - started) / 1e6 };
  } catch (error) {
    return { text: '', ms: Number(process.hrtime.bigint() - started) / 1e6, error: error.message };
  }
};

const firstMatch = (text, re) => (text.match(re) ?? [])[1] ?? null;

const rows = [];
for (const file of manifest.files) {
  const path = join('dist', 'corpus', file.name);
  if (!existsSync(path)) { console.log(`skip ${file.name} (missing)`); continue; }

  const ioc = await call('rea_ioc_extract', { path, detail: true });
  const tracking = await call('rea_tracking_surface', { path });
  const anti = await call('rea_anti_analysis', { path });
  const exposure = await call('rea_analyst_exposure', { path });

  const mb = file.bytes / (1024 * 1024);
  const totalMs = ioc.ms + tracking.ms + anti.ms + exposure.ms;
  const savedMatch = ioc.text.match(/full JSON:\s*(.+)\s*$/m);
  let saved = null;
  if (savedMatch) {
    try { saved = JSON.parse(readFileSync(savedMatch[1].trim(), 'utf8')); } catch { saved = null; }
  }
  const byType = {};
  for (const item of saved?.iocs ?? []) byType[item.type] = (byType[item.type] ?? 0) + 1;

  rows.push({
    name: file.name,
    project: file.project,
    bytes: file.bytes,
    sha256: file.sha256,
    ms: { ioc: Math.round(ioc.ms), tracking: Math.round(tracking.ms), anti: Math.round(anti.ms), exposure: Math.round(exposure.ms), total: Math.round(totalMs) },
    msPerMb: Number((totalMs / Math.max(mb, 0.01)).toFixed(0)),
    errors: [ioc, tracking, anti, exposure].filter((item) => item.error).map((item) => item.error),
    strings: Number(firstMatch(ioc.text, /strings sampled: (\d+)/) ?? 0),
    channels: firstMatch(ioc.text, /strings sampled: \d+ \(([^)]*)\)/) ?? '',
    indicators: Number(firstMatch(ioc.text, /indicators: (\d+)/) ?? 0),
    byType,
    trackingLevel: firstMatch(tracking.text, /level: (\w+)/) ?? 'unknown',
    trackingCategories: firstMatch(tracking.text, /categories: (.+)/) ?? '',
    antiTechniques: Number(firstMatch(anti.text, /techniques: (\d+)/) ?? 0),
    exposureLevel: firstMatch(exposure.text, /level: (\w+)/) ?? 'unknown',
    unresolved: /unresolved encrypted region/.test(ioc.text),
    sampleIndicators: (saved?.iocs ?? []).slice(0, 12).map((item) => `${item.type}:${item.value}`),
  });
  console.log(`${file.name.padEnd(14)}${String(file.bytes).padStart(9)} B  ${String(Math.round(totalMs)).padStart(5)} ms  `
    + `strings ${String(rows.at(-1).strings).padStart(5)}  iocs ${String(rows.at(-1).indicators).padStart(3)}  `
    + `tracking ${rows.at(-1).trackingLevel.padEnd(7)} anti ${String(rows.at(-1).antiTechniques).padStart(2)}`
    + `${rows.at(-1).errors.length ? `  ERROR ${rows.at(-1).errors.join(';')}` : ''}`);
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  toolVersion: JSON.parse(readFileSync('package.json', 'utf8')).version,
  corpus: manifest.files.map(({ name, sha256, bytes, project, license }) => ({ name, sha256, bytes, project, license })),
  rows,
  summary: {
    files: rows.length,
    errors: rows.filter((row) => row.errors.length > 0).length,
    meanMsPerMb: Math.round(rows.reduce((sum, row) => sum + row.msPerMb, 0) / Math.max(rows.length, 1)),
    slowest: rows.reduce((worst, row) => (row.msPerMb > worst.msPerMb ? row : worst), rows[0] ?? { name: null }).name,
    highTrackingOnBenign: rows.filter((row) => ['high', 'critical'].includes(row.trackingLevel)).map((row) => row.name),
    unresolvedFlags: rows.filter((row) => row.unresolved).map((row) => row.name),
  },
};
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
console.log(`\nfiles ${report.summary.files}  errors ${report.summary.errors}  mean ${report.summary.meanMsPerMb} ms/MB  slowest ${report.summary.slowest}`);
console.log(`high tracking on benign: ${report.summary.highTrackingOnBenign.join(', ') || 'none'}`);
console.log(`unresolved flags: ${report.summary.unresolvedFlags.join(', ') || 'none'}`);
console.log(`json ${out}`);

await new Promise((resolve) => setTimeout(resolve, 50));
process.exit(0);
