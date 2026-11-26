import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

import { buildGeneration } from '../scripts/duel/defender.mjs';
import { readPeLayout, parseTlsCallbacks, findCodePointerTables, classifyCodePointerTables, structuralAnomalies, structureProfile, parsePeExports } from '../lib/static/structure.js';
import { javaRequirement } from '../lib/infra/engines.js';
import { assessBehavior, planNextSteps } from '../lib/static/plan.js';
import { triageBuffer } from '../lib/static/triage.js';
import { HASH_ALGORITHMS, buildHashIndex, recoverHashedApis } from '../lib/static/api-hash.js';

const D0 = buildGeneration('D0').buffer;
const D6 = buildGeneration('D6').buffer;
const D8 = buildGeneration('D8').buffer;

test('D0 keeps a real import directory; D6 strips it', () => {
  assert.equal(structureProfile(D0).importsPresent, true);
  assert.equal(structureProfile(D6).importsPresent, false);
});

test('TLS callback and dispatch table are found in the structural generation', () => {
  const layout = readPeLayout(D6);
  const tls = parseTlsCallbacks(D6, layout);
  assert.equal(tls.present, true);
  assert.equal(tls.callbacks.length, 1);
  assert.match(tls.callbacks[0].section, /^\.text$/);

  const tables = findCodePointerTables(D6, layout);
  assert.equal(tables.length, 1);
  assert.ok(tables[0].entries >= 16);
  assert.equal(classifyCodePointerTables(tables).dispatchTables.length, 1);
});

test('ROR13 hashes resolve for D6 and salted hashes stay unresolved in D8', () => {
  const six = structureProfile(D6);
  assert.ok(six.hashedApis.count >= 7);
  assert.ok(six.hashedApis.algorithms.includes('ror13'));

  const eight = structureProfile(D8);
  assert.equal(eight.hashedApis.count, 0);
  assert.equal(eight.importsPresent, false);
});

test('the parameterised family does not turn a salted table into names', () => {
  const index = buildHashIndex();
  assert.ok(index.size > 100);
  const salted = buildGeneration('D8');
  const recovered = recoverHashedApis(salted.buffer, { index });
  assert.equal(recovered.apis.length, 0);
});

test('behaviour attribution separates import-table evidence from hash evidence', () => {
  const imported = assessBehavior({
    imports: { apiFlat: ['VirtualAllocEx', 'WriteProcessMemory', 'GetVolumeInformationA'] },
    strings: [{ value: 'HKLM\\SOFTWARE\\OrbitApp\\InstallId' }],
    iocs: [{ type: 'url', value: 'https://telemetry.orbit-app.example/v1/collect' }],
  });
  const ids = imported.findings.map((item) => item.id);
  assert.ok(ids.includes('injection'));
  assert.ok(ids.includes('device-identifier'));
  assert.ok(ids.includes('persistence'));
  assert.match(imported.summary, /reports to a remote endpoint|collects stable device identifiers/);

  const hashed = assessBehavior({ imports: { apiFlat: [] }, hashed: [{ api: 'CryptEncrypt' }] });
  const crypto = hashed.findings.find((item) => item.id === 'crypto');
  assert.equal(crypto.source, 'api-hash');
  assert.equal(crypto.confidence, 'low');
});

test('a sealed region produces one concrete experiment, with the REA call that confirms it', () => {
  const strings = [{ value: 'cfg=rc4;key=derive(GetVolumeInformationA.serial);' }];
  const plan = planNextSteps({
    structure: { sections: [{ name: '.rdata', virtualAddress: 0x1000, virtualSize: 0x2000, rawSize: 0x2000 }], tls: { present: false, callbacks: [] }, dispatchTables: [] },
    unresolved: [{ start: 0x1600, end: 0x1800, rva: 0x1600 }],
    strings,
  });
  assert.equal(plan.length, 1);
  assert.match(plan[0].action, /GetVolumeInformationA/);
  assert.match(plan[0].action, /decrypt/i);
  assert.match(plan[0].confirm, /load_frida_script|start_gdb_session/);
});

test('without a sealed region the plan still names a confirmation path', () => {
  const plan = planNextSteps({
    structure: { sections: [], tls: { present: false, callbacks: [] }, dispatchTables: [], importsPresent: true },
    unresolved: [],
    strings: [],
    behavior: { findings: [] },
    entry: 0x1000,
  });
  assert.equal(plan.length, 1);
  assert.ok(plan[0].confirm.length > 0);
});

test('hash algorithms are deterministic across runs', () => {
  assert.equal(HASH_ALGORITHMS.ror13('GetVolumeInformationA'), HASH_ALGORITHMS.ror13('GetVolumeInformationA'));
  assert.notEqual(HASH_ALGORITHMS.ror13('GetVolumeInformationA'), HASH_ALGORITHMS.ror13('GetVolumeInformationW'));
});

test('a switch-heavy binary is not accused of control-flow flattening', () => {
  // Measured on 7-Zip's 7zr.exe: 33 code-pointer tables, every one of them a
  // compiler switch table. The count is the only offline discriminator, because
  // a switch table and a CFF dispatch table have identical static shape.
  const many = Array.from({ length: 33 }, (_, index) => ({ section: '.rdata', rva: 0x1000 + index * 0x40, at: index * 0x40, entries: 15 }));
  const verdict = classifyCodePointerTables(many);
  assert.deepEqual(verdict.dispatchTables, []);
  assert.match(verdict.note, /switch tables/);

  const one = [{ section: '.rdata', rva: 0x2000, at: 0x2000, entries: 24 }];
  const single = classifyCodePointerTables(one);
  assert.equal(single.dispatchTables.length, 1);
  assert.equal(single.dispatchTables[0].confidence, 'low');
});

test('uninitialised data does not count as a structural anomaly, executable growth does', () => {
  const base = { imageBase: 0x400000, entryRva: 0x1000, dataDirs: [] };
  const bss = structuralAnomalies({
    ...base,
    sections: [{ name: '.data', virtualAddress: 0x1000, virtualSize: 0x8000, rawPointer: 0x600, rawSize: 0x200, executable: false, writable: true }],
  }, { importsPresent: true });
  assert.deepEqual(bss, []);

  const stub = structuralAnomalies({
    ...base,
    sections: [{ name: '.text', virtualAddress: 0x1000, virtualSize: 0x40000, rawPointer: 0x400, rawSize: 0x400, executable: true, writable: false }],
  }, { importsPresent: true });
  assert.equal(stub.length, 1);
  assert.match(stub[0], /self-unpacking/);
});

test('an experiment says so when the tool it names cannot run', () => {
  // 1.8.0 shipped confirm strings like "confirm with: batch_decompile" on hosts
  // with no Ghidra, which reads as an instruction but is not one. The provider
  // tag is what makes the seam visible.
  const offline = {
    live: 0,
    total: 3,
    providers: {
      frida: { ready: false, reason: 'frida not on PATH' },
      ghidra: { ready: false, reason: 'Ghidra not installed' },
      rizin: { ready: true, reason: null },
    },
  };
  const plan = planNextSteps({
    structure: { sections: [], tls: { present: false, callbacks: [] }, dispatchTables: [], importsPresent: false },
    unresolved: [{ label: 'sealed-config', offset: 0x600, length: 1024, rva: 0x1000 }],
    strings: ['cfg=derive(GetVolumeInformationA)'],
    behavior: { findings: [] },
    hashed: [],
    entry: 0x1000,
    providers: offline,
  });
  const step = plan.find((item) => item.provider);
  assert.ok(step, 'no provider tag was attached');
  assert.equal(step.provider.ready, false);
  assert.match(step.confirm, /load_frida_script/);

  const withoutProbe = planNextSteps({
    structure: { sections: [], tls: { present: false, callbacks: [] }, dispatchTables: [], importsPresent: false },
    unresolved: [{ label: 'sealed-config', offset: 0x600, length: 1024, rva: 0x1000 }],
    strings: ['cfg=derive(GetVolumeInformationA)'],
    behavior: { findings: [] }, hashed: [], entry: 0x1000,
  });
  assert.equal(withoutProbe.find((item) => item.provider), undefined, 'a probe that was never supplied must not be invented');
});

test('triage carries the engine snapshot into its report', () => {
  const providers = { live: 1, total: 2, note: null, providers: { frida: { ready: true, reason: null }, ghidra: { ready: false, reason: 'Ghidra not installed' } } };
  const report = triageBuffer(buildGeneration('D6').buffer, { name: 'D6.exe', providers });
  assert.equal(report.providers.live, 1);
  assert.equal(report.providers.total, 2);
  assert.equal(report.providers.ready.ghidra.ready, false);
  const tagged = report.plan.filter((step) => step.provider);
  assert.ok(tagged.length > 0);
  assert.ok(tagged.every((step) => ['frida', 'ghidra', 'rizin'].includes(step.provider.key)));
});

test('without a probe the report admits it did not check', () => {
  const report = triageBuffer(buildGeneration('D0').buffer, { name: 'D0.exe' });
  assert.equal(report.providers, null);
});

test('a JDK that exists but is too old is not a ready engine', () => {
  // 1.8.1 shipped "jdk ok (17.0.8)" beside "ghidra missing" and every decompile
  // died in Ghidra's launcher with "JDK 21+ could not be found". The status was
  // literally true and practically a lie.
  const old = javaRequirement({ available: true, major: 17, version: '17.0.8' });
  assert.equal(old.sufficient, false);
  assert.match(old.note, /older than JDK 21/);

  const ok = javaRequirement({ available: true, major: 21, version: '21.0.13' });
  assert.equal(ok.sufficient, true);
  assert.equal(ok.note, null);

  // Unknown version is not evidence of sufficiency or an age measurement.
  const unknown = javaRequirement({ available: true, major: null });
  assert.equal(unknown.sufficient, false);
  assert.match(unknown.note, /could not be determined/);
  assert.doesNotMatch(unknown.note, /too old|older than/);
  assert.equal(javaRequirement({ available: false }).note, null);
});

test('the report states the image base so a probe address can be computed', () => {
  const report = triageBuffer(buildGeneration('D6').buffer, { name: 'D6.exe' });
  assert.equal(report.structure.imageBase, 0x400000);
  const step = report.plan.find((item) => item.probe);
  assert.ok(step, 'no machine-readable probe was emitted');
  assert.equal(step.probe.tool, 'inspect_address_context');
  assert.ok(Number.isInteger(step.probe.rva));
});


test('parsePeExports reads the real corpus export table (skip when the corpus is absent)', (t) => {
  const corpus = new URL('../dist/corpus/sqlite3.dll', import.meta.url);
  let bytes;
  try {
    bytes = readFileSync(corpus);
  } catch {
    t.skip('dist/corpus/sqlite3.dll not present (fetch-corpus not run)');
    return;
  }
  const parsed = parsePeExports(bytes);
  assert.equal(parsed.count, 361);
  assert.equal(parsed.exports.length, 361);
  // sqlite3_version is a data export pointing at the version string; its RVA
  // is exercised by the parse validation in docs/reconstruction-plan.md §13.
  const step = parsed.exports.find((entry) => entry.name === 'sqlite3_step');
  assert.ok(step, 'sqlite3_step missing from the export table');
  assert.equal(step.forwarded, false);
  assert.ok(step.rva > 0x1000, `sqlite3_step rva sanity: ${step.rva}`);
  for (const entry of parsed.exports.slice(0, 50)) {
    assert.ok(entry.name.length > 0);
  }
});

test('parsePeExports degrades on non-PE input instead of throwing', () => {
  assert.deepEqual(parsePeExports(Buffer.from('not a pe'), {}), { exports: [], count: 0 });
  assert.deepEqual(parsePeExports(Buffer.alloc(0)), { exports: [], count: 0 });
});
