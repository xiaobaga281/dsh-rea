/**
 * End-to-end capability dry-run: build test samples, assemble the real plugin
 * against a fake host (which still starts the real REA child), run the local
 * analysis tools over them, and score the findings against a known expectation
 * list. This is the measurement that decides whether the intel layer needs
 * strengthening.
 *
 * Run: npm run demo
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
const OUT = join(tmpdir(), 'rea-samples');

const { apply } = await import(new URL('index.js', ROOT).href);
const {
  antiAnalysisMatrix, capabilityProfile, extractIocs, parsePEImports,
  summarizeIocs, trackingSurface,
} = await import(new URL('lib/intel.js', ROOT).href);
const { extractStrings, xorProbe, triageBuffer } = await import(new URL('lib/triage.js', ROOT).href);
const { extractDeepStrings, channelSummary } = await import(new URL('lib/strings.js', ROOT).href);

if (!existsSync(join(OUT, 'tracked_app.exe'))) {
  await import(new URL('scripts/make-sample.mjs', ROOT).href);
}
const expectations = JSON.parse(readFileSync(join(OUT, 'expectations.json'), 'utf8'));

function makeHost() {
  const tools = [];
  const ctx = {
    logger: { info: () => {}, warn: () => {}, error: () => {} },
    tools: { register(definition) { tools.push(definition); return () => {}; } },
    webServer: { register() { return () => {}; } },
    effect(fn) { fn(); return () => {}; },
  };
  return { ctx, tools };
}

const host = makeHost();
await apply(host.ctx, { catalogProbe: false });
const call = async (name, args) => {
  const tool = host.tools.find((item) => item.name === name);
  if (!tool) return `(missing tool ${name})`;
  try {
    const result = await tool.execute(args ?? {});
    return String(result?.text ?? result?.report ?? JSON.stringify(result));
  } catch (error) {
    return `(error: ${error?.message ?? error})`;
  }
};

const score = (label, expected, present) => {
  const hit = expected.filter((item) => present.has(item));
  const missed = expected.filter((item) => !present.has(item));
  console.log(`  ${label.padEnd(16)} ${hit.length}/${expected.length}  ${hit.length === expected.length ? 'OK' : `missed: ${missed.join(', ')}`}`);
  return { label, hit: hit.length, total: expected.length, missed };
};

console.log(`Capability dry-run (${host.tools.length} tools registered)\n`);
const results = [];

// ---- Core-function measurement over the tracked binary ----
const bytes = readFileSync(join(OUT, 'tracked_app.exe'));
const legacyStrings = extractStrings(bytes, { minLength: 5, maxStrings: 4_000 });
const strings = extractDeepStrings(bytes, { minLength: 5, maxStrings: 4_000 });
const imports = parsePEImports(bytes);
const iocs = extractIocs(strings);
const tracking = trackingSurface(strings, imports);
const anti = antiAnalysisMatrix(strings, imports, null);
const profile = capabilityProfile({ imports, strings, tracking });
const xor = xorProbe(bytes, { sampleBytes: 64 * 1024, limit: 8 });
const triage = triageBuffer(bytes, { name: 'tracked_app.exe' });

const haystack = strings.map((item) => item.value).join('\n').toLowerCase();
const legacyHaystack = legacyStrings.map((item) => item.value).join('\n').toLowerCase();
console.log('== static parse ==');
console.log(`  PE imports        ${imports?.dlls.length ?? 0} DLLs / ${imports?.apiFlat.length ?? 0} APIs`);
console.log(`  strings           legacy ${legacyStrings.length} -> deep ${strings.length} (${Object.entries(channelSummary(strings)).map(([k, v]) => `${k}=${v}`).join(', ')})`);
console.log(`  hidden recovered  legacy ${expectations.hidden.filter((item) => legacyHaystack.includes(item.toLowerCase())).length}/${expectations.hidden.length} -> deep ${expectations.hidden.filter((item) => haystack.includes(item.toLowerCase())).length}/${expectations.hidden.length}`);
const iocSummary = summarizeIocs(iocs);
console.log(`  IoC               ${iocSummary.total} (confirmed ${JSON.stringify(iocSummary.confirmedByType)}, ${iocSummary.derived} recovered)`);
console.log(`  triage verdict    ${triage.verdict} (${triage.confidence})`);
console.log(`  xor probe         ${xor.length} candidate keys`);
console.log('\n== expectation coverage (core functions) ==');
results.push(score('tracking', expectations.tracking, new Set(tracking.findings.map((item) => item.id))));
results.push(score('anti-analysis', expectations.anti, new Set(anti.techniques.map((item) => item.id))));
results.push(score('ioc types', expectations.iocTypes, new Set(iocs.map((item) => item.type))));
results.push(score('imports', expectations.imports, new Set(imports?.apiFlat ?? [])));
results.push(score('capabilities', expectations.capabilities, new Set(profile.capabilities.map((item) => item.id))));
results.push(score('hidden strings', expectations.hidden, new Set([...expectations.hidden].filter((item) => haystack.includes(item.toLowerCase())))));

// ---- Tool-level end-to-end check ----
console.log('\n== tool output (tracked_app.exe) ==');
const toolChecks = [
  ['rea_triage', { path: join(OUT, 'tracked_app.exe'), detail: false }, ['imports:', 'capability hints:', 'indicators:']],
  ['rea_ioc_extract', { path: join(OUT, 'tracked_app.exe') }, ['telemetry.tracked-app.example', 'untrusted-ioc', 'T1055']],
  ['rea_tracking_surface', { path: join(OUT, 'tracked_app.exe') }, ['Tracking and fingerprinting surface', 'Analytics / telemetry SDK']],
  ['rea_anti_analysis', { path: join(OUT, 'tracked_app.exe') }, ['Anti-analysis technique matrix', 'Debugger presence APIs']],
  ['rea_analyst_exposure', { path: join(OUT, 'tracked_app.exe') }, ['Account / login identity', '0.0.0.0 telemetry.tracked-app.example', 'preflight checklist']],
];
for (const [name, args, needles] of toolChecks) {
  const output = await call(name, args);
  const found = needles.filter((needle) => output.includes(needle));
  console.log(`  ${name.padEnd(24)} ${found.length}/${needles.length} ${output.startsWith('(') ? output : ''}`);
  results.push({ label: `tool:${name}`, hit: found.length, total: needles.length, missed: needles.filter((n) => !found.includes(n)) });
}

console.log('\n== false-positive control (clean_app.exe) ==');
const cleanBytes = readFileSync(join(OUT, 'clean_app.exe'));
const cleanStrings = extractDeepStrings(cleanBytes, { minLength: 5, maxStrings: 4_000 });
const cleanTracking = trackingSurface(cleanStrings, parsePEImports(cleanBytes));
const cleanAnti = antiAnalysisMatrix(cleanStrings, parsePEImports(cleanBytes), null);
console.log(`  tracking findings ${cleanTracking.findings.length} (level ${cleanTracking.level}) | anti-analysis ${cleanAnti.techniques.length} | deep strings ${cleanStrings.length}`);

console.log('\n== source-level twin (tracked_app.js) ==');
const jsTracking = await call('rea_tracking_surface', { path: join(OUT, 'tracked_app.js') });
console.log(`  tracking surface output ${jsTracking.length} chars | ${jsTracking.split('\n')[2] ?? ''}`);

const exposureOutput = await call('rea_analyst_exposure', { path: join(OUT, 'tracked_app.exe') });
console.log('\n== anti-tracking (analyst exposure) ==');
results.push(score('exposure', expectations.exposure, new Set(expectations.exposure.filter((item) => exposureOutput.includes(item)))));

const report = {
  generatedAt: new Date().toISOString(),
  tools: host.tools.length,
  coverage: results,
  cleanControl: { tracking: cleanTracking.findings.length, anti: cleanAnti.techniques.length },
  xorKeys: xor.map((item) => item.key),
};
const dist = join(ROOT_PATH, 'dist');
mkdirSync(dist, { recursive: true });
writeFileSync(join(dist, 'capability-demo.json'), `${JSON.stringify(report, null, 2)}\n`);
const totalHit = results.reduce((sum, item) => sum + item.hit, 0);
const totalAll = results.reduce((sum, item) => sum + item.total, 0);
console.log(`\noverall ${totalHit}/${totalAll} (${Math.round((totalHit / totalAll) * 100)}%) -> dist/capability-demo.json`);
process.exit(0);
