/**
 * Regressions from the D9 (decoy) duel round.
 *
 * D9 planted a plaintext decoy C2 config and a second CRC32 hash table. Three
 * claims the product made about it were wrong, and none of them was a recall
 * problem - the old score could not see any of this.
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { extractIocs, plausibleEmail } from '../lib/intel.js';
import { buildIocExtractTool } from '../lib/intel-tools.js';
import { describeStructure } from '../lib/analysis-tools.js';
import { planNextSteps } from '../lib/plan.js';
import { buildGeneration, GENERATION_IDS } from '../scripts/duel/defender.mjs';

// ----------------------------------------------------------- false positives --

test('a recognised TLD and a lowercase domain make a plausible address', () => {
  assert.equal(plausibleEmail('analytics@orbit-app.example'), true);
  assert.equal(plausibleEmail('buildbot@nightly.example'), true);
  assert.equal(plausibleEmail('admin@tracker.example'), true);
});

test('byte accidents from high-entropy regions are not emails', () => {
  // These three appeared as "email" IoCs on every duel generation before 1.8.4.
  for (const noise of ['J@nC.NDH', 'ID@qo.HIplXO', 'bido@ihl.xml', 'nltc@ri-p.xml']) {
    assert.equal(plausibleEmail(noise), false, noise);
  }
});

test('extractIocs drops the noise and keeps the real address', () => {
  const items = [
    { value: 'J@nC.NDH sdk junk', offset: 10, encoding: 'ascii' },
    { value: 'analytics@orbit-app.example', offset: 40, encoding: 'b64custom>zlib>ascii', derived: true },
  ];
  const iocs = extractIocs(items);
  assert.equal(iocs.some((item) => item.value === 'J@nC.NDH'), false);
  assert.equal(iocs.some((item) => item.value === 'analytics@orbit-app.example'), true);
});

test('an address with no @ or no dot is refused', () => {
  assert.equal(plausibleEmail('not-an-address'), false);
  assert.equal(plausibleEmail('@example.com'), false);
});

// ------------------------------------------------------------------- wording --

test('the IoC report no longer calls plaintext bytes "confirmed"', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ioc-wording-'));
  const sample = join(dir, 'sample.bin');
  await writeFile(sample, ['https://cdn.metrics-edge.example/v2/ping', 'https://update-check.example.net/health'].join('\n'));
  try {
    const out = await buildIocExtractTool({ store: { write: async () => join(dir, 'out.json') } })
      .execute({ path: sample, detail: true });
    assert.doesNotMatch(out.text, /\(\d+ confirmed/);
    assert.match(out.text, /\(\d+ observed in plaintext/);
    assert.match(out.text, /— unverified/);
    assert.match(out.text, /Plaintext visibility is not confirmation/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const structure = (algorithms) => ({
  imageBase: 0x400000,
  entryRva: 0x9100,
  importsPresent: false,
  tls: { present: true, callbacks: [{ rva: 0x9800 }] },
  dispatchTables: [],
  hashedApis: { count: algorithms.length === 1 ? 10 : 19, algorithms, truncated: false },
});

test('one algorithm is reported as one unverified table', () => {
  const line = describeStructure(structure(['ror13']));
  assert.match(line, /10 API hashes resolved \(ror13\) - resolved, unverified/);
});

test('mixed algorithms are labelled as separate or decoy tables', () => {
  const line = describeStructure(structure(['ror13', 'crc32']));
  assert.match(line, /19 API hashes resolved \(ror13\/crc32\)/);
  assert.match(line, /mixed algorithms: likely separate or decoy tables/);
});

test('a plan over mixed algorithms stops claiming one algorithm fits them all', () => {
  const plan = planNextSteps({
    structure: { ...structure(['ror13', 'crc32']), hashedApis: { count: 19, algorithms: ['ror13', 'crc32'], truncated: false } },
    unresolved: [],
    hashed: Array.from({ length: 9 }, (_, index) => ({ api: `api${index}`, algorithm: 'ror13' })),
  });
  const step = plan.find((entry) => entry.priority === 4);
  assert.ok(step);
  assert.doesNotMatch(step.action, /fits those/);
  assert.match(step.action, /Separate the 9 recovered hash names by algorithm/);
  assert.match(step.action, /decoy tables/);
  assert.match(step.expect, /two address-contiguous groups/);
});

test('a single-algorithm plan keeps its original actionable wording', () => {
  const plan = planNextSteps({
    structure: structure(['ror13']),
    unresolved: [],
    hashed: Array.from({ length: 9 }, (_, index) => ({ api: `api${index}`, algorithm: 'ror13' })),
  });
  const step = plan.find((entry) => entry.priority === 4);
  assert.match(step.action, /ror13 fits those/);
});

// -------------------------------------------------------------- the fixture --

test('D9 exists, builds, and declares its decoys and sealed literals', () => {
  assert.ok(GENERATION_IDS.includes('D9'));
  const built = buildGeneration('D9');
  assert.ok(built.buffer.length > 1000);
  assert.equal(built.decoyIocs, 12);
  assert.equal(built.decoyApis, 10);
  assert.equal(built.unrecoverable, true);
  assert.equal(built.sealed.length, 4);
});
