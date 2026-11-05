/**
 * D8 was the duel's "information is unreachable" generation: a salted hash
 * table whose salt sat inside a DEFLATE+XOR container. Both halves were
 * reachable - the container named its own key, and the decrypted config named
 * the salt - but the tool never applied either, so it reported "algorithm
 * unknown" next to a table it could have opened.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { HASH_ALGORITHMS, buildHashIndex, recoverHashedApis } from '../lib/api-hash.js';
import { structureProfile } from '../lib/structure.js';
import { extractDeepStrings } from '../lib/strings.js';
import { triageBuffer } from '../lib/triage.js';
import { planNextSteps } from '../lib/plan.js';
import { buildGeneration } from '../scripts/duel/defender.mjs';

/** The per-build constant D8 hides inside its sealed config. */
const SALT = 0x5d3a91c7;

const d8 = buildGeneration('D8').buffer;

test('a container header names its own XOR key, and it is applied', () => {
  const strings = extractDeepStrings(d8, {});
  const salt = strings.find((item) => /salt=0x[0-9a-f]+/i.test(String(item.value)));
  assert.ok(salt, 'the config line was not recovered');
  assert.match(String(salt.value), new RegExp(`salt=0x${SALT.toString(16)}`, 'i'));
  // The key came from the header, not from crib-dragging: the channel records it.
  assert.match(String(salt.encoding), /declared-key/);
});

test('the config header survives truncation of the hidden-string list', () => {
  const report = triageBuffer(d8, { providers: null });
  const values = (report.hiddenStrings ?? []).map((item) => String(item.value));
  assert.ok(values.some((value) => /salt=0x/i.test(value)), 'the load-bearing line must not be the one dropped');
});

test('an unsalted index cannot see a salted table', () => {
  const hash = HASH_ALGORITHMS['mul31-xor-2f']('IsDebuggerPresent');
  const salted = (hash ^ SALT) >>> 0;
  assert.equal(buildHashIndex().has(salted), false);
});

test('a salted index resolves the same table', () => {
  const hash = HASH_ALGORITHMS['mul31-xor-2f']('IsDebuggerPresent');
  const salted = (hash ^ SALT) >>> 0;
  const bucket = buildHashIndex({ salt: SALT }).get(salted);
  assert.ok(bucket, 'salted index missed the entry');
  assert.equal(bucket[0].api, 'IsDebuggerPresent');
  assert.match(bucket[0].algorithm, /\+salt$/);
});

test('structureProfile finds nothing without the salt and ten names with it', () => {
  const blind = structureProfile(d8);
  assert.equal(blind.hashedApis.count, 0);
  assert.equal(blind.hashedApis.salt, null);

  const opened = structureProfile(d8, { salt: SALT });
  assert.equal(opened.hashedApis.count, 10);
  assert.equal(opened.hashedApis.salt, SALT);
  assert.deepEqual(opened.hashedApis.algorithms, ['mul31-xor-2f+salt']);
  assert.ok(opened.hashedApis.items.some((item) => item.api === 'IsDebuggerPresent'));
});

test('triage reads the declared salt and names the APIs it opens', () => {
  const report = triageBuffer(d8, { providers: null });
  assert.equal(report.imports?.apiCount, 10, 'all ten hash entries should resolve');
  assert.ok(report.imports?.highSignal?.includes('IsDebuggerPresent'));
  // The behaviour layer is what carries the names into the report a reader
  // sees, so check the claims rather than only the count.
  const findings = (report.behavior?.findings ?? []).map((item) => item.id);
  assert.ok(findings.includes('injection'), `findings: ${findings.join(', ')}`);
  assert.ok(findings.includes('crypto'), `findings: ${findings.join(', ')}`);
  // All six behaviour classes depend on names that only exist after the hash
  // table is opened, so full coverage is the end-to-end proof.
  for (const id of ['device-identifier', 'telemetry', 'persistence', 'anti-debug', 'injection', 'crypto']) {
    assert.ok(findings.includes(id), `missing behaviour ${id}`);
  }
});

test('without a salt the extraction is unchanged', () => {
  const d6 = buildGeneration('D6').buffer;
  const profile = structureProfile(d6);
  assert.equal(profile.hashedApis.count, 10);
  assert.equal(profile.hashedApis.salt, null);
  assert.deepEqual(profile.hashedApis.algorithms, ['ror13']);
});

test('recoverHashedApis ignores a zero salt instead of doubling the index', () => {
  // salt 0 would XOR every hash with itself and match every table twice.
  const blind = recoverHashedApis(d8, { salt: 0 });
  assert.equal(blind.apis.length, 0);
});

test('the plan names the salt instead of pretending the algorithm was obvious', () => {
  const plan = planNextSteps({
    structure: {
      importsPresent: false,
      tls: { present: false, callbacks: [] },
      dispatchTables: [],
      hashedApis: { count: 10, algorithms: ['mul31-xor-2f+salt'], salt: SALT, truncated: false },
    },
    unresolved: [],
    hashed: Array.from({ length: 10 }, (_, index) => ({ api: `api${index}`, algorithm: 'mul31-xor-2f+salt' })),
  });
  const step = plan.find((entry) => entry.priority === 4);
  assert.ok(step);
  assert.match(step.action, /mul31-xor-2f with salt 0x5d3a91c7/);
  assert.doesNotMatch(step.action, /\+salt/);
  assert.match(step.why, /hands over its own salt/);
});
