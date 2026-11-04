import assert from 'node:assert/strict';
import test from 'node:test';

import { buildGeneration } from '../scripts/duel/defender.mjs';
import { readPeLayout, parseTlsCallbacks, findCodePointerTables, classifyCodePointerTables, structuralAnomalies, structureProfile } from '../lib/structure.js';
import { assessBehavior, planNextSteps } from '../lib/plan.js';
import { HASH_ALGORITHMS, buildHashIndex, recoverHashedApis } from '../lib/api-hash.js';

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
