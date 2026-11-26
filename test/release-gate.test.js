import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { RELEASE_STEPS } from '../scripts/release/release-gate.mjs';

test('the release gate runs checks before producing or describing an artifact', () => {
  assert.deepEqual(RELEASE_STEPS.map((step) => step.label), [
    'default suite',
    'behaviour ladder',
    'engine ladder',
    'real restore suite',
    'static corpus gate',
    'real corpus inventory',
    'host matrix',
    'structure check',
    'pack',
    'manifest',
  ]);
  const packed = RELEASE_STEPS.findIndex((step) => step.label === 'pack');
  const manifest = RELEASE_STEPS.findIndex((step) => step.label === 'manifest');
  const host = RELEASE_STEPS.findIndex((step) => step.label === 'host matrix');
  assert.ok(host > 0 && host < packed, 'host matrix must pass before packaging');
  assert.equal(manifest, RELEASE_STEPS.length - 1, 'manifest is always last');
});

test('the installed scripts expose the same fixed entry point', () => {
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'package.json'), 'utf8'));
  assert.equal(pkg.scripts['release-gate'], 'node scripts/release/release-gate.mjs');
});