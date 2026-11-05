/**
 * The duel's scoring rules, kept free of filesystem and console work so the
 * rules themselves can be tested instead of inferred from a table printed by a
 * CLI run.
 *
 * Two ideas make the score honest:
 *
 *   - the control generation D0 defines the ceiling (what the analyser can
 *     reach at all) and the noise baseline (how much benign chatter it produces
 *     on an easy sample). Neither is a hand-maintained expected-result list;
 *   - the defender declares which literals it sealed behind a runtime-derived
 *     key. Those are removed from that generation's reachable ceiling instead
 *     of being charged to recall *and* to honesty.
 *
 * @module dsh-rea/scripts/duel/score
 */

/**
 * Nine capability dimensions. String recall still leads, because a report that
 * cannot name the endpoint is not a report; structure, behaviour and the next
 * experiment carry the rest.
 */
export const BASE_WEIGHTS = {
  endpoints: 0.13, iocText: 0.13, tracking: 0.10, anti: 0.10, watermarks: 0.04,
  api: 0.14, behavior: 0.14, plan: 0.10, verify: 0.12,
};

/**
 * Precision is a tenth dimension, not a multiplier bolted onto the total.
 * Scaling the other nine by (1 - W) means a generation with no extra noise
 * scores exactly what it scored before precision existed, so adding this
 * dimension cannot quietly rewrite the historical series.
 */
export const PRECISION_WEIGHT = 0.12;
export const WEIGHTS = Object.freeze({
  ...Object.fromEntries(Object.entries(BASE_WEIGHTS).map(([key, weight]) => [key, weight * (1 - PRECISION_WEIGHT)])),
  precision: PRECISION_WEIGHT,
});

/**
 * The control fluctuates by a couple of benign fragments, and a decoded
 * channel legitimately adds one or two more (a URL also yields its host, an
 * email its domain). Three keeps the historical series stable when a genuine
 * false-positive filter lowers D0's baseline by one - without it, D2 was
 * charged 1.1% for an improvement made to the extractor, not for anything it
 * reported.
 */
export const NOISE_TOLERANCE = 3;
/** Extra candidates needed to halve precision. Larger = more forgiving. */
export const NOISE_SCALE = 8;

const ratio = (hit, total) => (total === 0 ? 1 : Number((hit / total).toFixed(3)));

/**
 * Extra IoC candidates over the control baseline, with a small tolerance.
 *
 * A decoy that a defender puts in the file is not a hallucination - the tool
 * correctly extracted a string that is there. It is still a *wrong lead*: an
 * analyst who reports twelve planted C2 endpoints as findings has not done the
 * job. Precision charges the failure to discriminate, not the extraction.
 */
export function precisionOf(noiseCount, baselineNoise) {
  const extra = Math.max(0, noiseCount - baselineNoise - NOISE_TOLERANCE);
  return Number((1 / (1 + extra / NOISE_SCALE)).toFixed(3));
}

export function buildCeiling(control) {
  return {
    endpoints: control.endpoints,
    iocText: control.iocText,
    tracking: control.trackingIds,
    anti: control.antiTechniques,
    watermarks: control.watermarks,
    // The analyst-level dimensions take their ceiling from D0 too: whatever
    // the plaintext control exposes is the reachable set, not a written list.
    api: control.apiHits,
    behavior: control.behaviorHits,
  };
}

export function scoreRow(row, ceiling, { baselineNoise = 0 } = {}) {
  const sealed = new Set(row.sealed ?? []);
  const reachable = {
    endpoints: ceiling.endpoints.filter((value) => !sealed.has(value)),
    iocText: ceiling.iocText.filter((value) => !sealed.has(value)),
    tracking: ceiling.tracking.filter((value) => !sealed.has(value)),
    anti: ceiling.anti.filter((value) => !sealed.has(value)),
    watermarks: ceiling.watermarks.filter((value) => !sealed.has(value)),
    api: ceiling.api.filter((value) => !sealed.has(value)),
    behavior: ceiling.behavior.filter((value) => !sealed.has(value)),
  };
  const got = {
    endpoints: row.endpoints.filter((value) => reachable.endpoints.includes(value)),
    iocText: row.iocText.filter((value) => reachable.iocText.includes(value)),
    tracking: row.trackingIds.filter((value) => reachable.tracking.includes(value)),
    anti: row.antiTechniques.filter((value) => reachable.anti.includes(value)),
    watermarks: row.watermarks.filter((value) => reachable.watermarks.includes(value)),
    api: row.apiHits.filter((value) => reachable.api.includes(value)),
    behavior: row.behaviorHits.filter((value) => reachable.behavior.includes(value)),
  };
  const noiseCount = Array.isArray(row.noise) ? row.noise.length : Number(row.noise ?? 0);
  const extraNoise = Math.max(0, noiseCount - baselineNoise - NOISE_TOLERANCE);
  const precision = precisionOf(noiseCount, baselineNoise);
  const recall = {
    endpoints: ratio(got.endpoints.length, reachable.endpoints.length),
    iocText: ratio(got.iocText.length, reachable.iocText.length),
    tracking: ratio(got.tracking.length, reachable.tracking.length),
    anti: ratio(got.anti.length, reachable.anti.length),
    // A generation that sealed the only watermark has no measurable
    // attribution dimension; null redistributes its weight.
    watermarks: reachable.watermarks.length === 0 ? null : ratio(got.watermarks.length, reachable.watermarks.length),
    api: reachable.api.length === 0 ? null : ratio(got.api.length, reachable.api.length),
    behavior: reachable.behavior.length === 0 ? null : ratio(got.behavior.length, reachable.behavior.length),
    plan: row.unrecoverable ? (row.planOk ? 1 : 0) : null,
    // The only dimension decided outside the recipe: was the address the plan
    // named actually the kind of thing the plan said it was.
    //
    // Two tiers. An engine run has to resolve a name, because that is what the
    // engine adds over reading the file. A local structural probe cannot name
    // anything, so it is scored on the verdict it does produce - and a plan
    // that points at .rdata while claiming code still fails it.
    verify: (() => {
      if (!row.probe) return null;
      if (!row.probe.ok) return 0;
      if (row.probe.tier === 'local') return 1;
      return row.probe.name ? 1 : 0;
    })(),
    precision,
  };
  let weighted = 0;
  let total = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const value = recall[key];
    if (value === null) continue;
    weighted += value * weight;
    total += weight;
  }
  const overall = Number((weighted / total).toFixed(4));
  const missing = Object.fromEntries(Object.entries(reachable).map(([key, values]) => [
    key, values.filter((value) => !got[key].includes(value)),
  ]));
  const honesty = row.unrecoverable ? row.unresolved : null;
  return {
    ...row, got, recall, overall, missing, reachable,
    precision, extraNoise,
    honesty,
    noise: noiseCount,
  };
}

/** Score every row; D0 defines the ceiling and is the 100% reference. */
export function scoreAll(rows) {
  const control = rows.find((row) => row.id === 'D0');
  if (!control) throw new Error('D0 control missing: it defines the ceiling for every other generation');
  const ceiling = buildCeiling(control);
  const baselineNoise = Array.isArray(control.noise) ? control.noise.length : Number(control.noise ?? 0);
  const scored = rows.map((row) => (row.id === 'D0' ? {
    ...row,
    got: {
      endpoints: row.endpoints, iocText: row.iocText, tracking: row.trackingIds,
      anti: row.antiTechniques, watermarks: row.watermarks, api: row.apiHits, behavior: row.behaviorHits,
    },
    recall: {
      endpoints: 1, iocText: 1, tracking: 1, anti: 1, watermarks: 1,
      api: 1, behavior: 1, plan: null, verify: null, precision: 1,
    },
    overall: 1,
    missing: Object.fromEntries(Object.keys(ceiling).map((key) => [key, []])),
    precision: 1,
    extraNoise: 0,
    honesty: null,
    noise: baselineNoise,
  } : scoreRow(row, ceiling, { baselineNoise })));

  const attackable = scored.filter((row) => row.id !== 'D0');
  const mean = attackable.length === 0 ? 0
    : Number((attackable.reduce((sum, row) => sum + row.overall, 0) / attackable.length).toFixed(4));
  return {
    ceiling,
    baselineNoise,
    scored,
    mean,
    weakest: attackable.length === 0 ? null
      : attackable.reduce((worst, row) => (row.overall < worst.overall ? row : worst), attackable[0]).id,
    honestyFailures: scored.filter((row) => row.honesty === false).map((row) => row.id),
    noisePeak: Math.max(...scored.map((row) => row.noise)),
    precisionFloor: Math.min(...scored.map((row) => row.precision)),
  };
}
