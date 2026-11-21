/**
 * Reconstruction loop report: R0–R5.
 *
 * For each tier:
 *   ceiling   rebuild the truth source, compile it, compare with the target.
 *             This is the score of a perfect reconstruction, and proves the
 *             scorer can say 1.0 without an empty denominator.
 *   mutation  compile a sibling source with one literal and one API changed.
 *             The score must drop and the gaps must name what changed; a
 *             scorer that stays green here measures nothing.
 *   loop      run the state machine with the truth draft. R0–R5 must converge;
 *             R4 additionally must report that its sealed values are not in
 *             the file, and the sealed plaintext must not appear in the target.
 *   hash      R3 additionally checks that the API-hash table recovers the truth
 *             names through the existing local channel.
 *   interaction R5 with --interaction: the window/message/control/resource
 *             surface must score 1.0 on the truth rebuild and drop on the
 *             WM_COMMAND-less mutant (needs the engine inventory; the target
 *             list is a cache hit).
 *
 * Run: npm run recon [-- --out dist/recon] [-- --engine] [-- --behavior]
 *                     [-- --interaction] [-- --baseline] [-- --only R0,...]
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { recoverHashedApis } from '../lib/static/api-hash.js';
import { buildReadiness, compileC } from '../lib/restore/build.js';
import { buildBaseline, synthesizeDraft } from '../lib/restore/baseline.js';
import { compareBuilds, floorFromSkeleton, functionFloorFromInventory, measureToolchainFloor, unionFunctionFloors } from '../lib/restore/compare.js';
import { decompileWithGhidra, ghidraLocalReadiness, listFunctionsWithGhidra } from '../lib/restore/ghidra-local.js';
import { parsePEImports } from '../lib/static/intel.js';
import { createLoopState, recordIteration } from '../lib/restore/recon.js';
import { readPeLayout } from '../lib/static/structure.js';
import { extractStrings, triageBuffer } from '../lib/static/triage.js';
import { TIERS, generateSpecimen } from './recon/specimen.mjs';

const out = resolve(process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : join('dist', 'recon'));
mkdirSync(out, { recursive: true });
// The ladder is local by default: a full run that waits on ten cold Ghidra
// imports is not a measurement loop anyone will re-run. `--engine` adds the
// T2 tier; without it the report states T2 was skipped, never that it passed.
const useEngine = process.argv.includes('--engine');
const wantBaseline = process.argv.includes('--baseline');
// T4 is opt-in everywhere else because it re-reads the same bytes as T1 and
// payload; the ladder makes it explicit with a flag so the default table stays
// comparable with the numbers in the plan document.
const useBehavior = process.argv.includes('--behavior');
// T5 is opt-in the same way and additionally reuses the T2 engine inventory:
// without --engine the interaction tier reports blocked for every tier, which
// is stated up front rather than discovered per row.
const useInteraction = process.argv.includes('--interaction');
if (useInteraction && !useEngine) {
  console.log('note: --interaction reuses the engine function inventory; without --engine the interaction tier reports blocked (pass --engine to score it)');
}
const functionsAt = process.argv.indexOf('--functions');
const functionsCap = functionsAt !== -1
  ? Math.max(1, Math.min(200, Number.parseInt(process.argv[functionsAt + 1] ?? '48', 10) || 48))
  : 48;
// T2 denominator deduction: remove toolchain-injected target functions (matched
// against a measured same-toolchain floor) from the average, and report the
// undeducted average alongside as scoreAll. Off by default; the raw ladder
// numbers stay comparable with the plan document.
const deductFunctions = process.argv.includes('--deduct-functions');

const pct = (value) => (typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : 'n/a');

// Real-sample review: no truth source exists, so function-level restoration is
// not scored here. What is measurable is recorded, and the absence of a score
// is stated rather than turned into a number.
const corpusAt = process.argv.indexOf('--corpus');
if (corpusAt !== -1) {
  const directory = resolve(process.argv[corpusAt + 1] ?? join('dist', 'corpus'));
  const entries = (await readdir(directory).catch(() => [])).filter((name) => /\.(?:exe|dll)$/i.test(name)).slice(0, 10);
  if (entries.length === 0) {
    console.error(`recon --corpus: no .exe/.dll files under ${directory}; run npm run fetch-corpus first`);
    process.exit(2);
  }
  const engine = await ghidraLocalReadiness();
  const builder = await buildReadiness();
  const floorBuild = builder.ready
    ? await measureToolchainFloor({ workDir: join(out, 'corpus-floor'), listFunctions: deductFunctions })
    : { floor: null, reason: builder.reason };
  const corpusFloor = floorBuild.floor ?? null;
  const rows = [];
  for (const name of entries) {
    const path = join(directory, name);
    const info = await stat(path).catch(() => null);
    if (!info?.isFile()) continue;
    const buffer = await readFile(path);
    const triage = triageBuffer(buffer, { name });
    const layout = readPeLayout(buffer);
    const imports = parsePEImports(buffer);
    let inventory = null;
    let listed = null;
    if (engine.ready && layout && layout.entryRva !== 0) {
      listed = await listFunctionsWithGhidra(path, { maxFunctions: functionsCap, timeoutMs: 300_000 });
      if (listed.ok) {
        inventory = {
          ok: true,
          scope: 'all-functions',
          functions: listed.emitted,
          total: listed.total,
          failed: listed.failed,
          truncated: listed.truncated,
          timeStopped: listed.timeStopped,
          analysisTimedOut: listed.analysisTimedOut === true,
        };
      } else {
        const decompiled = await decompileWithGhidra(path, { rva: layout.entryRva, timeoutMs: 300_000 });
        inventory = decompiled.ok
          ? { ok: true, scope: 'entry', function: decompiled.function ?? null, lines: decompiled.code.split(/\r?\n/).length, fallbackReason: listed.reason ?? listed.code }
          : { ok: false, reason: decompiled.reason ?? decompiled.code };
      }
    }
    let baseline = null;
    if (wantBaseline && triage.verdict === 'likely-packed-or-protected') {
      // The decompiled functions of a packed target are the stub, not the
      // application. A source baseline on them would measure the packer.
      baseline = { ok: false, reason: 'triage says packed/protected; unpack before a source baseline' };
    }
    if (wantBaseline && triage.verdict !== 'likely-packed-or-protected' && listed?.ok) {
      // Per-target floor: the same inventory with every function stubbed. The
      // global empty-program floor misses strings the stubs themselves carry.
      let fileFloor = corpusFloor;
      const stubDraft = synthesizeDraft(listed.functions, { stubbed: new Set(listed.functions.map((item) => item.name)) });
      const stubBuild = await compileC({ sourceText: stubDraft.source, workDir: join(out, 'corpus-floor', name), name: 'stub-floor' });
      if (stubBuild.ok) fileFloor = floorFromSkeleton(await readFile(stubBuild.outPath));
      const built = await buildBaseline({
        functions: listed.functions,
        workDir: join(out, 'corpus-baseline', name.replace(/[^A-Za-z0-9._-]/g, '_')),
        name: 'baseline',
      });
      if (!built.ok) {
        baseline = { ok: false, reason: built.reason };
      } else {
        try {
          const comparison = await compareBuilds({
            targetPath: path,
            rebuiltPath: built.built.outPath,
            sourceText: built.sourceText,
            engine: useEngine,
            maxFunctions: functionsCap,
            runtimeFloor: fileFloor,
            deductFunctions,
            functionFloor: floorBuild.functionFloor ?? null,
          });
          baseline = {
            ok: true,
            translated: built.translated.length,
            stubbed: built.stubbed.length,
            omitted: built.omitted.length,
            screened: built.screened,
            degraded: built.degraded === true,
            overall: comparison.overall,
            t1: comparison.tiers.t1.score,
            payload: comparison.tiers.payload.score,
            payloadStatus: comparison.tiers.payload.status,
            payloadMissing: comparison.tiers.payload.status === 'ran'
              ? comparison.tiers.payload.indicators.missing.slice(0, 5)
              : [],
            t2: comparison.tiers.t2.status,
            t2Score: comparison.tiers.t2.score,
            t2ScoreAll: comparison.tiers.t2.scoreAll ?? null,
            t2Denominator: comparison.tiers.t2.denominator ?? null,
            t2Deducted: comparison.tiers.t2.deductedTotal ?? null,
          };
        } catch (error) {
          baseline = { ok: false, reason: `comparison failed: ${error?.message ?? error}` };
        }
      }
    }
    const state = createLoopState({
      targetPath: path,
      targetSha256: triage.file.sha256,
      targetSize: buffer.length,
      unresolvedRegions: triage.unresolved.length,
      budget: 1,
    });
    rows.push({
      name,
      size: buffer.length,
      verdict: triage.verdict,
      imports: imports?.apiFlat?.length ?? 0,
      strings: extractStrings(buffer, { minLength: 6, maxStrings: 4_000 }).length,
      unresolved: triage.unresolved.length,
      inventory,
      baseline,
      restoration: baseline === null
        ? 'not scored: no truth source for a real binary; the loop needs a source to compare against'
        : baseline.ok
          ? 'function-level baseline measured: reproduction against the target, not proof of the original source'
          : `baseline unavailable: ${baseline.reason}`,
      intake: state.intake.note,
    });
  }
  writeFileSync(join(out, 'recon-corpus.json'), `${JSON.stringify({ generatedAt: new Date().toISOString(), engine, builder, floor: floorBuild.reason, rows }, null, 2)}\n`);
  console.log(`real-sample review (${entries.length} file(s), engine ${engine.ready ? 'ready' : `blocked: ${engine.reason}`}, builder ${builder.ready ? builder.compiler : `blocked: ${builder.reason}`})`);
  for (const row of rows) {
    const inventory = row.inventory === null
      ? 'n/a'
      : row.inventory.ok === false
        ? `failed (${row.inventory.reason})`
        : row.inventory.scope === 'all-functions'
          ? `${row.inventory.functions}/${row.inventory.total} functions${row.inventory.truncated || row.inventory.timeStopped ? ' (bounded)' : ''}`
          : `entry only (${row.inventory.lines} lines; inventory: ${row.inventory.fallbackReason})`;
    console.log(`${row.name}: ${row.verdict} imports=${row.imports} strings=${row.strings} unresolved=${row.unresolved} inventory=${inventory}`);
    if (row.baseline !== null) {
      console.log(row.baseline.ok
        ? `  baseline: overall ${pct(row.baseline.overall)} | ${row.baseline.translated} translated, ${row.baseline.stubbed} stubbed, ${row.baseline.omitted} runtime${row.baseline.screened ? `, screened ${row.baseline.screened.kept}/${row.baseline.screened.kept + row.baseline.screened.failed}` : ''}${row.baseline.degraded ? ', degraded to a compiled floor' : ''} | T1 ${pct(row.baseline.t1)} P ${pct(row.baseline.payload)} T2 ${row.baseline.t2}${row.baseline.payloadStatus === 'ran' && row.baseline.payloadMissing.length ? ` | payload missing: ${row.baseline.payloadMissing.join(' | ')}` : ''}`
        : `  baseline: failed (${row.baseline.reason})`);
    }
  }
  console.log('function-level restoration: not scored - a real binary has no truth source; scores require the R-ladder or a known source');
  console.log(`json ${join(out, 'recon-corpus.json')}`);
  process.exit(0);
}

const readiness = await buildReadiness();
if (!readiness.ready) {
  console.error(`recon: no build engine available (${readiness.reason}); the loop's build step cannot run`);
  process.exit(2);
}
console.log(`build engine: ${readiness.compiler} ${readiness.version ?? ''} (${readiness.path})`);

// What any build from this toolchain carries for free. Subtracting it is what
// keeps a CRT-heavy rebuild from scoring 99% without recovering anything.
const measuredFloor = await measureToolchainFloor({ workDir: join(out, 'toolchain-floor'), listFunctions: deductFunctions });
if (measuredFloor.reason !== null) {
  console.error(`recon: the toolchain floor could not be measured (${measuredFloor.reason}); scores would be inflated`);
  process.exit(2);
}
const runtimeFloor = measuredFloor.floor;
console.log(`toolchain floor: ${runtimeFloor.imports.size} imports, ${runtimeFloor.strings.size} strings excluded`);
let functionFloorNote = 'function floor: off (pass --deduct-functions)';
if (deductFunctions) {
  functionFloorNote = measuredFloor.functionFloor
    ? `function floor: ${measuredFloor.functionFloor.names.size} names, ${measuredFloor.functionFloor.rvas.size} rvas, ${measuredFloor.functionFloor.bodyHashes.size} body hashes (empty-program build)`
    : `function floor: UNAVAILABLE (${measuredFloor.functionFloorReason ?? 'not measured'}); T2 runs undeducted`;
  console.log(functionFloorNote);
}

const only = process.argv.includes('--only')
  ? process.argv[process.argv.indexOf('--only') + 1].split(',').map((tier) => tier.trim()).filter(Boolean)
  : null;
const selectedTiers = only === null ? TIERS : TIERS.filter((tier) => only.includes(tier));
if (selectedTiers.length === 0) {
  console.error(`recon: --only matched no tier (known: ${TIERS.join(', ')})`);
  process.exit(2);
}
const rows = [];
const failures = [];

for (const tier of selectedTiers) {
  const row = { tier };
  const truthSpec = await generateSpecimen({ tier, outDir: out, mutate: false });
  if (!truthSpec.ok) {
    failures.push(`${tier}: target build failed (${truthSpec.build.reason})`);
    rows.push({ ...row, ok: false, error: truthSpec.build.reason });
    continue;
  }
  const targetPath = truthSpec.truth.targetPath;
  const targetBuffer = await readFile(targetPath);
  const report = triageBuffer(targetBuffer, { name: `${tier}.exe` });

  // Per-target floor: compile the same inventory with every function stubbed.
  // Its imports/strings are what this pipeline produces with zero
  // reconstruction, which is a stricter floor than an empty program's CRT.
  let tierFloor = runtimeFloor;
  let baselineInventory = null;
  // The function floor starts from the empty program; the stub pipeline adds
  // whatever CRT this inventory's translation units pull in. The stubs
  // themselves are renamed with a prefix so the floor never carries the
  // target's own function names - deducting on those would eat user functions.
  let tierFunctionFloor = measuredFloor.functionFloor;
  if (wantBaseline) {
    baselineInventory = await listFunctionsWithGhidra(targetPath, { maxFunctions: functionsCap, timeoutMs: 300_000 });
    if (!baselineInventory.ok) {
      failures.push(`${tier}: baseline inventory failed (${baselineInventory.reason ?? baselineInventory.code})`);
    } else {
      const stubDraft = synthesizeDraft(baselineInventory.functions, {
        stubbed: new Set(baselineInventory.functions.map((item) => item.name)),
        stubPrefix: deductFunctions ? 'dsh_stub_' : '',
      });
      const stubBuild = await compileC({ sourceText: stubDraft.source, workDir: join(out, tier), name: `${tier}-stub-floor` });
      if (stubBuild.ok) {
        tierFloor = floorFromSkeleton(await readFile(stubBuild.outPath));
        if (deductFunctions) {
          const stubListed = await listFunctionsWithGhidra(stubBuild.outPath, { maxFunctions: 200, timeoutMs: 300_000 });
          if (stubListed.ok) {
            tierFunctionFloor = unionFunctionFloors(tierFunctionFloor, functionFloorFromInventory(stubListed.functions));
          } else {
            failures.push(`${tier}: the stub-floor function inventory failed (${stubListed.reason ?? stubListed.code})`);
          }
        }
      } else {
        failures.push(`${tier}: the stub-only floor did not compile (${stubBuild.reason})`);
      }
    }
  }
  if (deductFunctions && tierFunctionFloor === null) {
    console.log(`${tier}: function floor unavailable - T2 runs undeducted for this tier`);
  }

  const rebuild = await compileC({
    sourceText: truthSpec.truth.source,
    workDir: join(out, tier),
    name: `${tier}-rebuild`,
    // The build recipe is part of the reconstruction: a strip flag changes the
    // symbol names the decompiler prints, and comparing a stripped target with
    // an unstripped rebuild would measure the flag, not the source.
    extraArgs: truthSpec.truth.extraArgs,
  });
  if (!rebuild.ok) {
    failures.push(`${tier}: truth rebuild failed (${rebuild.reason})`);
    rows.push({ ...row, ok: false, error: rebuild.reason });
    continue;
  }
  const ceiling = await compareBuilds({
    targetPath,
    rebuiltPath: rebuild.outPath,
    sourceText: truthSpec.truth.source,
    engine: useEngine,
    timeoutMs: 300_000,
    runtimeFloor: tierFloor,
    maxFunctions: functionsCap,
    behavior: useBehavior,
    interaction: useInteraction,
    deductFunctions,
    functionFloor: tierFunctionFloor,
  });
  if (ceiling.overall === null) failures.push(`${tier}: the ceiling produced no measurable tier`);
  else if (ceiling.overall < 0.95) failures.push(`${tier}: the truth rebuild scored only ${pct(ceiling.overall)} - scorer or build is unstable`);

  // Payload check: plaintext truth literals must be present in the truth
  // rebuild and absent from the baseline rebuild. Encoded tiers keep their
  // literals as bytes in both binaries, so plaintext presence is not applicable.
  const plaintextTier = tier === 'R0' || tier === 'R3';
  const rebuiltStrings = extractStrings(await readFile(rebuild.outPath), { minLength: 6, maxStrings: 4_000 }).map((item) => item.value);
  const payloadHits = (text) => truthSpec.truth.literals.filter((literal) => text.some((value) => value.includes(literal))).length;
  if (plaintextTier) {
    const ceilingHits = payloadHits(rebuiltStrings);
    row.ceilingPayload = { recovered: ceilingHits, total: truthSpec.truth.literals.length };
    // The comparison's payload tier covers strings the target still carries;
    // the truth check below is stricter: every plaintext literal must be in the
    // truth rebuild, or the scorer itself is measuring the wrong thing.
    if (ceilingHits < truthSpec.truth.literals.length) {
      failures.push(`${tier}: the truth rebuild is missing ${truthSpec.truth.literals.length - ceilingHits} plaintext literal(s)`);
    }
  }
  row.ceilingScore = ceiling.overall;

  const mutated = await generateSpecimen({ tier, outDir: out, mutate: true });
  const mutation = mutated.ok
    ? await compareBuilds({
      targetPath,
      rebuiltPath: mutated.truth.targetPath,
      sourceText: mutated.truth.source,
      // The interaction tier needs an inventory on both sides: the target list
      // is a cache hit, so --interaction only adds one fresh analysis (the
      // mutated build). Without it the R5 negative control degrades to the
      // overall number and cannot name the missing message handler.
      engine: useEngine || useInteraction,
      maxFunctions: functionsCap,
      timeoutMs: 300_000,
      runtimeFloor: tierFloor,
      interaction: useInteraction,
    })
    : null;
  if (mutation === null) failures.push(`${tier}: mutated specimen did not build`);
  else {
    const mutationInteraction = mutation.tiers.t5 ?? null;
    const gapSignals = [
      ...(mutation.tiers.t1.status === 'ran' ? mutation.tiers.t1.imports.missing : []),
      ...(mutation.tiers.t1.status === 'ran' ? mutation.tiers.t1.imports.added : []),
      ...(mutation.tiers.t3.status === 'ran' ? mutation.tiers.t3.unmatched : []),
      ...(mutationInteraction?.status === 'ran'
        ? ['windows', 'messages', 'controls', 'resources'].flatMap((key) => [
          ...(mutationInteraction[key]?.missing ?? []),
          ...(mutationInteraction[key]?.added ?? []),
        ])
        : []),
    ];
    if (mutation.overall >= ceiling.overall && gapSignals.length === 0) {
      failures.push(`${tier}: the mutated rebuild scored ${pct(mutation.overall)} - a mutation the scorer cannot see`);
    }
    row.mutationGaps = gapSignals.slice(0, 4);
  }

  const state = createLoopState({
    targetPath,
    targetSha256: report.file.sha256,
    targetSize: targetBuffer.length,
    unresolvedRegions: report.unresolved.length,
    budget: 3,
  });
  recordIteration(state, {
    sourceSha: createHash('sha256').update(truthSpec.truth.source).digest('hex'),
    sourceChars: truthSpec.truth.source.length,
    build: rebuild,
    compare: ceiling,
  });
  if (state.status !== 'converged') failures.push(`${tier}: the loop with the truth draft ended ${state.status} (${state.reason ?? 'no reason'})`);

  // Mechanical baseline: decompile, translate, compile, compare. No model is
  // involved anywhere in this column. The inventory is bounded to the first 12
  // functions in address order: the translation repair loop handles user code,
  // and runtime bodies beyond that mostly reduce to stubs while making the
  // compiler struggle with Ghidra's type names.
  if (wantBaseline && baselineInventory?.ok) {
    const baselineBuild = await buildBaseline({ functions: baselineInventory.functions, workDir: join(out, tier), name: `${tier}-baseline` });
    if (!baselineBuild.ok) {
      failures.push(`${tier}: the mechanical baseline did not compile (${baselineBuild.reason})`);
    } else {
      const baselineCompare = await compareBuilds({
        targetPath,
        rebuiltPath: baselineBuild.built.outPath,
        sourceText: baselineBuild.sourceText,
        engine: useEngine,
        runtimeFloor: tierFloor,
        maxFunctions: functionsCap,
        deductFunctions,
        functionFloor: tierFunctionFloor,
      });
      row.baseline = baselineCompare.overall;
      row.baselineDetail = {
        translated: baselineBuild.translated.length,
        stubbed: baselineBuild.stubbed.length,
        omitted: baselineBuild.omitted.length,
        screened: baselineBuild.screened,
        rounds: baselineBuild.rounds,
        t1: baselineCompare.tiers.t1.score,
        payload: baselineCompare.tiers.payload?.score ?? null,
        t2: baselineCompare.tiers.t2.status,
        t2Score: baselineCompare.tiers.t2.score ?? null,
        t2ScoreAll: baselineCompare.tiers.t2.scoreAll ?? null,
        t2Denominator: baselineCompare.tiers.t2.denominator ?? null,
        t2Deducted: baselineCompare.tiers.t2.deductedTotal ?? null,
        t3: baselineCompare.tiers.t3.status,
      };
      if (plaintextTier) {
        const baselineStrings = extractStrings(await readFile(baselineBuild.built.outPath), { minLength: 6, maxStrings: 4_000 }).map((item) => item.value);
        row.baselinePayload = { recovered: payloadHits(baselineStrings), total: truthSpec.truth.literals.length };
        if (row.baselinePayload.recovered >= truthSpec.truth.literals.length) {
          failures.push(`${tier}: the mechanical baseline recovered every plaintext literal - the baseline is not mechanical or the literals leaked`);
        }
      }
      row.baselineScore = baselineCompare.overall;
    }
  }

  let hashRecall = null;
  if (tier === 'R3') {
    const recovered = recoverHashedApis(targetBuffer);
    const names = new Set(recovered.apis.map((item) => item.api));
    hashRecall = truthSpec.truth.apiNames.filter((name) => names.has(name)).length / truthSpec.truth.apiNames.length;
    if (hashRecall < 1) failures.push(`R3: API-hash recall ${pct(hashRecall)} - the table is not recoverable through the local channel`);
  }

  let sealedLeak = null;
  let unresolved = report.unresolved.length;
  if (tier === 'R4') {
    const strings = extractStrings(targetBuffer, { minLength: 6, maxStrings: 4_000 }).map((item) => item.value);
    sealedLeak = truthSpec.truth.sealedValues.some((value) => strings.some((text) => text.includes(value)));
    if (sealedLeak) failures.push('R4: a sealed plaintext value appears in the target - the specimen does not seal anything');
    if (unresolved === 0) failures.push('R4: the sealed region did not register as unresolved - the honesty check tested nothing');
  }

  // R5's interaction assertions run only when the tier was actually measured;
  // an unmeasured opt-in tier is skipped with a note, never counted as a zero.
  if (tier === 'R5' && useInteraction) {
    const interactionTier = ceiling.tiers.t5;
    if (interactionTier.status !== 'ran' || interactionTier.score !== 1) {
      failures.push(`R5: the interaction ceiling did not score 1.0 (${interactionTier.status} ${pct(interactionTier.score)})`);
    }
    const mutatedInteraction = mutation?.tiers?.t5 ?? null;
    if (mutatedInteraction === null || mutatedInteraction.status !== 'ran' || !(mutatedInteraction.messages.recall < 1)) {
      failures.push(`R5: the mutated rebuild kept the full message surface (messages recall ${pct(mutatedInteraction?.messages?.recall)}) - a mutation the interaction scorer cannot see`);
    }
  } else if (tier === 'R5') {
    console.log('R5: interaction assertions skipped - pass --interaction (with --engine) to measure the T5 tier');
  }

  rows.push({
    ...row,
    ok: true,
    targetBytes: targetBuffer.length,
    targetSha256: report.file.sha256,
    sealed: truthSpec.truth.sealed,
    unresolved,
    ceiling: ceiling.overall,
    ceilingTiers: { t1: ceiling.tiers.t1.score, t2: ceiling.tiers.t2.status, t3: ceiling.tiers.t3.score, t4: ceiling.tiers.t4.status === 'ran' ? ceiling.tiers.t4.score : null, t5: ceiling.tiers.t5.status === 'ran' ? ceiling.tiers.t5.score : null },
    ceilingT2: {
      score: ceiling.tiers.t2.score ?? null,
      scoreAll: ceiling.tiers.t2.scoreAll ?? null,
      denominator: ceiling.tiers.t2.denominator ?? null,
      deducted: ceiling.tiers.t2.deductedTotal ?? null,
      nameOnly: ceiling.tiers.t2.nameOnlyTotal ?? null,
    },
    ceilingBehavior: ceiling.tiers.t4.status === 'ran'
      ? { outputs: ceiling.tiers.t4.outputs.score, state: ceiling.tiers.t4.state.score, effects: ceiling.tiers.t4.effects.score }
      : null,
    ceilingInteraction: ceiling.tiers.t5.status === 'ran'
      ? {
        windows: ceiling.tiers.t5.windows.score,
        messages: ceiling.tiers.t5.messages.score,
        controls: ceiling.tiers.t5.controls.score,
        resources: ceiling.tiers.t5.resources.score,
      }
      : null,
    mutation: mutation?.overall ?? null,
    loopStatus: state.status,
    hashRecall,
    sealedLeak,
  });
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  engine: { compiler: readiness.compiler, version: readiness.version, source: readiness.source },
  rows,
  failures,
};
writeFileSync(join(out, 'recon.json'), `${JSON.stringify(report, null, 2)}\n`);

console.log('');
console.log(`${'tier'.padEnd(5)}${'ceiling'.padEnd(9)}${'baseline'.padEnd(10)}${'mutation'.padEnd(10)}${'loop'.padEnd(17)}${'hash'.padEnd(7)}${'unresolved'.padEnd(11)}sealed leak`);
for (const row of rows) {
  if (!row.ok) {
    console.log(`${row.tier.padEnd(5)}BUILD FAILED: ${row.error}`);
    continue;
  }
  console.log(`${row.tier.padEnd(5)}${pct(row.ceilingScore).padEnd(9)}${pct(row.baselineScore).padEnd(10)}${pct(row.mutation).padEnd(10)}${row.loopStatus.padEnd(17)}${pct(row.hashRecall).padEnd(7)}${String(row.unresolved).padEnd(11)}${row.sealed ? (row.sealedLeak ? 'YES (failure)' : 'none') : '-'}`);
}
if (useBehavior) {
  for (const row of rows) {
    if (!row.ok || !row.ceilingBehavior) continue;
    console.log(`  ${row.tier} behaviour: outputs ${pct(row.ceilingBehavior.outputs)} state ${pct(row.ceilingBehavior.state)} effects ${pct(row.ceilingBehavior.effects)}`);
  }
}
if (useInteraction) {
  for (const row of rows) {
    if (!row.ok || !row.ceilingInteraction) continue;
    console.log(`  ${row.tier} interaction: windows ${pct(row.ceilingInteraction.windows)} messages ${pct(row.ceilingInteraction.messages)} controls ${pct(row.ceilingInteraction.controls)} resources ${pct(row.ceilingInteraction.resources)}`);
  }
}
if (deductFunctions) {
  for (const row of rows) {
    if (!row.ok) continue;
    const c = row.ceilingT2;
    if (c?.denominator) {
      console.log(`${row.tier} T2 deducted: ${pct(c.score)} (raw scoreAll ${pct(c.scoreAll)}), denominator ${c.denominator.before}→${c.denominator.after}, ${c.deducted ?? 0} deducted, ${c.nameOnly ?? 0} name-only audited`);
    }
    const b = row.baselineDetail;
    if (b?.t2Denominator) {
      console.log(`${row.tier} baseline T2 deducted: ${pct(b.t2Score)} (raw scoreAll ${pct(b.t2ScoreAll)}), denominator ${b.t2Denominator.before}→${b.t2Denominator.after}, ${b.t2Deducted ?? 0} deducted`);
    }
  }
}
for (const row of rows) {
  if (!row.baselineDetail) continue;
  const detail = row.baselineDetail;
  const screened = detail.screened ? `, screened ${detail.screened.kept}/${detail.screened.kept + detail.screened.failed}` : '';
  console.log(`${row.tier} baseline: ${detail.translated} translated, ${detail.stubbed} stubbed, ${detail.omitted} runtime-provided${screened}, ${detail.rounds} round(s) | T1 ${pct(detail.t1)} P ${pct(detail.payload)} T2 ${detail.t2} T3 ${detail.t3}`);
}
for (const row of rows) {
  if (!row.ceilingPayload) continue;
  const baseline = row.baselinePayload ? `, baseline ${row.baselinePayload.recovered}/${row.baselinePayload.total}` : '';
  console.log(`${row.tier} payload literals: truth rebuild ${row.ceilingPayload.recovered}/${row.ceilingPayload.total}${baseline}`);
}
if (rows.some((row) => row.ceilingPayload)) {
  console.log('payload literals are a truth check on the specimen (ceiling must recover all; baseline must recover none); the scored payload tier covers target-visible strings only.');
}
if (failures.length > 0) {
  console.log('');
  for (const failure of failures) console.log(`FAIL ${failure}`);
}
console.log(`\njson ${join(out, 'recon.json')}`);
process.exit(failures.length === 0 ? 0 : 1);
