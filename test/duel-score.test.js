/**
 * The scorer used to be inline in a CLI script, which meant its rules could
 * only be observed by running a 90-second duel. It is a module now; these tests
 * pin the parts that are easy to break silently.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BASE_WEIGHTS, NOISE_SCALE, NOISE_TOLERANCE, PRECISION_WEIGHT, WEIGHTS,
  buildCeiling, precisionOf, scoreAll, scoreRow,
} from '../scripts/duel/score.mjs';

const list = (...values) => values;

const control = {
  id: 'D0',
  endpoints: list('a', 'b'),
  iocText: list('ioc1', 'ioc2'),
  trackingIds: list('t1'),
  antiTechniques: list('anti1'),
  watermarks: list('wm'),
  apiHits: list('api1', 'api2'),
  behaviorHits: list('beh1'),
  noise: list('benign1', 'benign2', 'benign3'),
  sealed: [],
};

/** A row that finds everything reachable and says nothing extra. */
const perfect = (overrides = {}) => ({
  id: 'D1',
  endpoints: [...control.endpoints],
  iocText: [...control.iocText],
  trackingIds: [...control.trackingIds],
  antiTechniques: [...control.antiTechniques],
  watermarks: [...control.watermarks],
  apiHits: [...control.apiHits],
  behaviorHits: [...control.behaviorHits],
  noise: [...control.noise],
  sealed: [],
  probe: null,
  planOk: true,
  unresolved: true,
  unrecoverable: false,
  ...overrides,
});

test('the ten weights still add up to exactly one', () => {
  const total = Object.values(WEIGHTS).reduce((sum, weight) => sum + weight, 0);
  assert.ok(Math.abs(total - 1) < 1e-9, `weights sum to ${total}`);
  assert.equal(WEIGHTS.precision, PRECISION_WEIGHT);
  for (const [key, weight] of Object.entries(BASE_WEIGHTS)) {
    assert.ok(Math.abs(WEIGHTS[key] - weight * (1 - PRECISION_WEIGHT)) < 1e-9);
  }
});

test('precision ignores the control baseline and a small fluctuation', () => {
  assert.equal(precisionOf(3, 3), 1);
  assert.equal(precisionOf(3 + NOISE_TOLERANCE, 3), 1);
  assert.equal(precisionOf(3 + NOISE_TOLERANCE - 1, 3), 1);
});

test('precision halves when extra candidates reach the scale', () => {
  const baseline = 3;
  const extra = NOISE_SCALE;
  const value = precisionOf(baseline + NOISE_TOLERANCE + extra, baseline);
  assert.equal(value, 0.5);
});

test('precision is monotonic and never negative', () => {
  assert.ok(precisionOf(20, 3) < precisionOf(14, 3));
  assert.ok(precisionOf(1000, 3) > 0);
  assert.equal(precisionOf(0, 30), 1);
});

test('adding precision does not move a generation that scores 100% already', () => {
  // This is the whole point of scaling the other nine weights: a new
  // dimension must not quietly rewrite the historical series.
  const ceiling = buildCeiling(control);
  const row = scoreRow(perfect(), ceiling, { baselineNoise: control.noise.length });
  assert.equal(row.precision, 1);
  assert.equal(row.overall, 1);
});

test('extra noise lowers the score, and the amount is the precision formula', () => {
  const ceiling = buildCeiling(control);
  const clean = scoreRow(perfect(), ceiling, { baselineNoise: control.noise.length });
  const noisy = scoreRow(perfect({ noise: list(...control.noise, ...Array.from({ length: 10 }, (_, i) => `decoy${i}`)) }),
    ceiling, { baselineNoise: control.noise.length });
  assert.equal(noisy.extraNoise, 10 - NOISE_TOLERANCE);
  assert.equal(noisy.precision, precisionOf(13, 3));
  assert.ok(noisy.overall < clean.overall);
  // Capability recall is unchanged: precision is a separate dimension, not a
  // silent tax on the endpoint count.
  assert.equal(noisy.recall.endpoints, clean.recall.endpoints);
});

test('a sealed literal leaves the reachable ceiling instead of counting as a miss', () => {
  const ceiling = buildCeiling(control);
  const row = scoreRow(perfect({
    endpoints: ['a'],
    sealed: ['b'],
  }), ceiling, { baselineNoise: control.noise.length });
  assert.deepEqual(row.reachable.endpoints, ['a']);
  assert.equal(row.recall.endpoints, 1);
  assert.deepEqual(row.missing.endpoints, []);
});

test('a generation that seals its only watermark has no measurable wm dimension', () => {
  const ceiling = buildCeiling(control);
  const row = scoreRow(perfect({ watermarks: [], sealed: ['wm'] }), ceiling, { baselineNoise: control.noise.length });
  assert.equal(row.recall.watermarks, null);
  assert.equal(row.overall, 1, 'null redistributes the weight, it does not score zero');
});

test('a failed probe scores 0, a report that stopped claiming one is unmeasurable', () => {
  const ceiling = buildCeiling(control);
  const failed = scoreRow(perfect({ probe: { ok: false, name: null }, unrecoverable: true }), ceiling,
    { baselineNoise: control.noise.length });
  assert.equal(failed.recall.verify, 0);
  const withdrawn = scoreRow(perfect({ probe: null, unrecoverable: true }), ceiling,
    { baselineNoise: control.noise.length });
  assert.equal(withdrawn.recall.verify, null);
  assert.ok(withdrawn.overall > failed.overall);
});

test('a missing D0 is refused rather than scoring against an empty ceiling', () => {
  assert.throws(() => scoreAll([perfect()]), /D0 control missing/);
});

test('scoreAll reports the weakest generation, honesty failures and precision floor', () => {
  const rows = [
    control,
    perfect({ id: 'D1' }),
    perfect({ id: 'D2', noise: list(...control.noise, ...Array.from({ length: 24 }, (_, i) => `decoy${i}`)) }),
    perfect({ id: 'D3', unrecoverable: true, unresolved: false }),
  ];
  const result = scoreAll(rows);
  assert.equal(result.baselineNoise, 3);
  assert.equal(result.weakest, 'D2', 'precision is a scored dimension; honesty is a separate reported signal');
  assert.deepEqual(result.honestyFailures, ['D3']);
  assert.ok(result.precisionFloor < 0.5);
  assert.equal(result.scored[0].overall, 1);
  // Honesty does not silently enter the weighted score: it is reported beside
  // it, so a dishonest answer cannot be averaged away by eight perfect rows.
  assert.equal(result.scored[3].overall, 1);
});
