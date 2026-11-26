import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildProcessFailure, buildReadiness, compileC } from '../lib/restore/build.js';
import { buildInteractionTier, cfgSimilarity, classifyAgainstFunctionFloor, compareBuilds, floorFromSkeleton, functionFloorFromInventory, matchFunctionLists, measureToolchainFloor, normalizePseudocode, pseudocodeSimilarity, scoreFunctionLists, semanticSimilarity, sourceLiterals, splitByFunctionFloor, unionFunctionFloors } from '../lib/restore/compare.js';
import { ghidraLocalReadiness, parseFunctionList } from '../lib/restore/ghidra-local.js';
import { buildCompareBuildTool } from '../lib/surface/recon-tools.js';
import { generateSpecimen } from '../scripts/recon/specimen.mjs';

/** A minimal valid PE32 whose import table and strings are configurable. */
function samplePE({ dll = 'KERNEL32.dll', apis = ['CreateFileA'], strings = [], encoded = [] } = {}) {
  const b = Buffer.alloc(0x800);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(1, 0x86);
  b.writeUInt16LE(0xe0, 0x94);
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt32LE(0x1000, opt + 16);
  b.writeUInt32LE(16, opt + 92);
  const dd = opt + 96;
  b.writeUInt32LE(0x1000, dd + 8);
  b.writeUInt32LE(0x100, dd + 12);
  const section = opt + 0xe0;
  b.write('.rdata\0\0', section, 'latin1');
  b.writeUInt32LE(0x600, section + 8);
  b.writeUInt32LE(0x1000, section + 12);
  b.writeUInt32LE(0x600, section + 16);
  b.writeUInt32LE(0x200, section + 20);
  // Descriptor at RVA 0x1000 -> file 0x200.
  b.writeUInt32LE(0x1040, 0x200);
  b.writeUInt32LE(0x1080, 0x20c);
  b.writeUInt32LE(0x1040, 0x210);
  // Thunk array at RVA 0x1040 -> file 0x240; names at RVA 0x1060+.
  let nameRva = 0x10a0;
  apis.forEach((api, index) => {
    b.writeUInt32LE(nameRva, 0x240 + index * 4);
    nameRva += 2 + Buffer.byteLength(api) + 1;
  });
  b.write(dll, 0x280, 'latin1');
  let nameAt = 0x2a0;
  for (const api of apis) {
    b.writeUInt16LE(0, nameAt);
    b.write(api, nameAt + 2, 'latin1');
    nameAt += 2 + Buffer.byteLength(api) + 1;
  }
  let stringAt = 0x400;
  for (const value of strings) {
    b.write(`${value}\0`, stringAt, 'latin1');
    stringAt += Buffer.byteLength(value) + 1;
  }
  let encodedAt = 0x680;
  for (const buffer of encoded) {
    b.write(buffer.toString('latin1'), encodedAt, 'latin1');
    encodedAt += buffer.length + 1;
  }
  return b;
}

async function inTemp(prefix, fn) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('an identical rebuild scores 1.0 on structure and is not an empty pass', async () => {
  const bytes = samplePE({ strings: ['https://c2.example/gate.php', 'FirebaseAnalytics'] });
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, bytes);
    await writeFile(rebuilt, bytes);
    const result = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    assert.equal(result.tiers.t1.status, 'ran');
    assert.equal(result.tiers.t1.score, 1);
    assert.equal(result.overall, 1);
    assert.equal(result.tiers.t2.status, 'blocked');
    assert.equal(result.tiers.t3.status, 'skipped');
  });
});

test('a different import set lowers recall and names what is missing', async () => {
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, samplePE({ apis: ['CreateFileA', 'IsDebuggerPresent'], strings: ['https://c2.example/gate.php'] }));
    await writeFile(rebuilt, samplePE({ apis: ['CreateFileA'], strings: ['https://c2.example/gate.php'] }));
    const result = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    const imports = result.tiers.t1.imports;
    assert.ok(imports.recall < 1);
    assert.equal(imports.precision, 1);
    assert.deepEqual(imports.missing, ['isdebuggerpresent']);
    assert.ok(result.overall < 1);
  });
});

test('source literals are matched against the target and unmatched ones are kept visible', async () => {
  const source = 'const char *a = "https://c2.example/gate.php";\nconst char *b = "never-present-token";\nprintf("%d\\n", 1);';
  const literals = sourceLiterals(source);
  assert.ok(literals.has('https://c2.example/gate.php'));
  assert.ok(![...literals].some((value) => value === '%d\\n'));
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, samplePE({ strings: ['https://c2.example/gate.php'] }));
    await writeFile(rebuilt, samplePE({ strings: ['https://c2.example/gate.php'] }));
    const result = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, sourceText: source, engine: false });
    assert.equal(result.tiers.t3.status, 'ran');
    assert.equal(result.tiers.t3.literals, 2);
    assert.deepEqual(result.tiers.t3.matched, ['https://c2.example/gate.php']);
    assert.deepEqual(result.tiers.t3.unmatched, ['never-present-token']);
    assert.equal(result.tiers.t3.score, 0.5);
  });
});

test('a comparison with nothing measurable is null, never a synthetic 100%', async () => {
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.bin');
    const rebuilt = join(dir, 'rebuilt.bin');
    await writeFile(target, Buffer.alloc(0));
    await writeFile(rebuilt, Buffer.alloc(0));
    const result = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    assert.equal(result.tiers.t1.status, 'empty');
    assert.equal(result.overall, null);
    const tool = buildCompareBuildTool({});
    const answer = await tool.execute({ target, rebuilt: rebuilt, engine: false });
    assert.match(answer.text, /failure, not a pass/);
  });
});

test('pseudocode similarity normalises addresses, constants and decompiler temporaries', () => {
  const left = 'undefined8 entry(void) { uVar1 = *(int *)(0x140001000 + 8); return uVar1; }';
  const right = 'undefined8 entry(void) { uVar7 = *(int *)(0x140002000 + 8); return uVar7; }';
  const normalized = normalizePseudocode(left);
  assert.match(normalized, /var/);
  assert.doesNotMatch(normalized, /0x140001000/);
  const similar = pseudocodeSimilarity(left, right);
  assert.ok(similar.similarity > 0.8);
  assert.equal(pseudocodeSimilarity('', 'anything'), null);
});

test('semantic similarity compares structural constants across compilers', () => {
  const msvc = 'undefined8 FUN(longlong a, longlong b) { if (*(short *)(a + 0x20) != *(short *)(b + 0x20)) return 1; if (*(int *)(b + 0x11c) != 0) *(uint *)(b + 200) = *(uint *)(b + 200) & 0xfffffffd | 1; return helper(); }';
  const mingw = 'unsigned long long FUN(long long a, long long b) { if (*(unsigned short *)(a + 32) != *(unsigned short *)(b + 32)) return 1; if (*(int *)(b + 0x11c) != 0) *(unsigned int *)(b + 200) = (*(unsigned int *)(b + 200) & 0xfffffffd) | 1; return helper(); }';
  const same = semanticSimilarity(msvc, mingw);
  assert.ok(same.similarity > 0.8, `expected a strong match, got ${same.similarity}`);
  const other = semanticSimilarity(msvc, 'int other(void) { while (1) { return 3; } }');
  assert.ok(other.similarity < same.similarity);
});

test('CFG shape separates a stub from the original control flow', () => {
  const original = { blocks: 5, edges: 6, conditionals: 2, loops: 1, maxFanout: 2 };
  assert.equal(cfgSimilarity(original, { ...original }), 1);
  const stub = { blocks: 1, edges: 0, conditionals: 0, loops: 0, maxFanout: 0 };
  const shaped = cfgSimilarity(original, stub);
  assert.ok(shaped < 0.6);
  assert.equal(cfgSimilarity(null, original), null);
  assert.equal(cfgSimilarity(original, undefined), null);
});

test('function inventories are matched by RVA, and a dropped function scores zero', () => {
  const target = [
    { name: 'entry', rva: '0x1000', body: 'alpha beta gamma delta epsilon zeta' },
    { name: 'decoder', rva: '0x1100', body: 'eta theta iota kappa lambda mu' },
  ];
  const rebuilt = [
    { name: 'FUN_140001000', rva: '0x1000', body: 'alpha beta gamma delta epsilon zeta' },
  ];
  const pairs = matchFunctionLists(target, rebuilt);
  assert.equal(pairs.length, 2);
  assert.equal(pairs[1].rebuilt, null);
  const scored = scoreFunctionLists(target, rebuilt);
  assert.equal(scored.pairs, 2);
  assert.equal(scored.matched, 1);
  assert.equal(scored.coverage, 0.5);
  assert.equal(scored.score, 0.5);
  assert.deepEqual(scored.mismatches.map((item) => item.name), ['decoder']);
});

test('a rebuild whose layout drifted is matched by function name', () => {
  const target = [{ name: 'decoder', rva: '0x1000', body: 'alpha beta gamma delta' }];
  const rebuilt = [{ name: 'decoder', rva: '0x2000', body: 'alpha beta gamma delta' }];
  const scored = scoreFunctionLists(target, rebuilt);
  assert.equal(scored.matched, 1);
  assert.equal(scored.score, 1);
});

test('the Ghidra list parser separates metadata, bodies and the done marker', () => {
  const text = [
    '11:22:33 INFO  ProbeAddress.java> LIST {"total":2,"emitted":2,"truncated":false}',
    '11:22:33 INFO  ProbeAddress.java> FUNCTION {"name":"entry","entry":"140001000","rva":"0x1000","size":12}',
    'undefined8 entry(void)',
    '{',
    '  return 0;',
    '}',
    'FUNCTION_END',
    'FUNCTION {"name":"helper","entry":"140001100","rva":"0x1100","size":8}',
    '(decompile failed)',
    'FUNCTION_END',
    'LIST_DONE {"ok":true,"total":2,"emitted":2,"failed":1,"truncated":false}',
  ].join('\n');
  const parsed = parseFunctionList(text);
  assert.equal(parsed.header.total, 2);
  assert.equal(parsed.done.failed, 1);
  assert.equal(parsed.functions.length, 2);
  assert.match(parsed.functions[0].body, /return 0/);
  assert.equal(parsed.functions[1].name, 'helper');
});

test('the toolchain floor is subtracted from both sides, so shared runtime is not recovery', async () => {
  const skeleton = samplePE({ apis: ['CreateFileA'], strings: ['compiler-runtime-string'] });
  const floor = floorFromSkeleton(skeleton);
  assert.ok(floor.imports.has('createfilea'));
  assert.ok(floor.strings.has('compiler-runtime-string'));
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, samplePE({ apis: ['CreateFileA'], strings: ['compiler-runtime-string', 'https://payload.example.test/beacon'] }));
    await writeFile(rebuilt, samplePE({ apis: ['CreateFileA'], strings: ['compiler-runtime-string'] }));
    const withFloor = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false, runtimeFloor: floor });
    assert.equal(withFloor.tiers.payload.status, 'ran');
    assert.ok(withFloor.tiers.payload.indicators.targetSize >= 1);
    assert.ok(withFloor.tiers.payload.indicators.missing.some((value) => value.includes('payload.example.test')));
    assert.ok(withFloor.tiers.payload.score < 1);
  });
});

test('encoded payload is scored through the decode channels', async () => {
  const url = 'https://encoded.example.test/gate';
  const encoded = Buffer.from([...Buffer.from(url, 'latin1')].map((byte) => byte ^ 0x5a));
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    const stripped = join(dir, 'stripped.exe');
    await writeFile(target, samplePE({ encoded: [encoded] }));
    await writeFile(rebuilt, samplePE({ encoded: [encoded] }));
    await writeFile(stripped, samplePE());
    const withPayload = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    assert.equal(withPayload.tiers.payload.status, 'ran');
    assert.equal(withPayload.tiers.payload.indicators.recall, 1);
    const withoutPayload = await compareBuilds({ targetPath: target, rebuiltPath: stripped, engine: false });
    assert.ok(withoutPayload.tiers.payload.indicators.missing.some((value) => value.includes('encoded.example.test')));
  });
});

test('the build step reports unavailable or compiles a trivial program', async () => {
  const readiness = await buildReadiness();
  await inTemp('dsh-rea-build-', async (dir) => {
    const outcome = await compileC({
      sourceText: 'int main(void) { return 0; }\n',
      workDir: join(dir, 'work'),
      name: 'probe',
    });
    if (readiness.ready) {
      assert.equal(outcome.ok, true, outcome.reason);
      assert.ok(outcome.outPath.endsWith('probe.exe'));
      const firstBuild = await readFile(outcome.outPath);
      assert.equal(outcome.sha256, createHash('sha256').update(firstBuild).digest('hex'));
      const floor = await measureToolchainFloor({ workDir: join(dir, 'floor') });
      assert.equal(floor.reason, null);
      assert.ok(floor.floor.imports.size > 0);
      assert.ok(floor.floor.strings.size > 0);
      const repeated = await compileC({ sourceText: 'int main(void) { return 0; }\n', workDir: join(dir, 'work'), name: 'probe' });
      assert.equal(repeated.ok, true, repeated.reason);
      assert.deepEqual(await readFile(repeated.outPath), firstBuild, 'runtime evidence stays bound when the same draft is rebuilt');
    } else {
      assert.equal(outcome.code, 'unavailable');
      assert.ok(outcome.reason.length > 0);
    }
    const badWorkDir = await compileC({ sourceText: 'int main(void) { return 0; }', workDir: 'relative/path' });
    assert.equal(badWorkDir.code, 'bad-workdir');
  });
});

test('a compiler that cannot launch is unavailable rather than a source failure', () => {
  const failure = buildProcessFailure({ code: -1, error: Object.assign(new Error('spawn EACCES'), { code: 'EACCES' }) });
  assert.equal(failure.ok, false);
  assert.equal(failure.code, 'unavailable');
  assert.match(failure.reason, /could not start.*EACCES/);
  assert.equal(buildProcessFailure({ code: 1, stderr: 'source error' }).code, 'compile-error');
  assert.equal(buildProcessFailure({ code: null, timedOut: true }).code, 'timeout');
});

test('the behaviour tier is opt-in and an identical rebuild scores 1.0 on it', async () => {
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    const bytes = samplePE({
      apis: ['CreateFileA', 'RegSetValueExA', 'MessageBoxA'],
      strings: ['Cannot open config file.', 'HKCU\\Software\\rea\\state'],
    });
    await writeFile(target, bytes);
    await writeFile(rebuilt, bytes);

    const skipped = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    assert.equal(skipped.tiers.t4.status, 'skipped');
    assert.equal(skipped.weightsUsed.t4, undefined);

    const scored = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false, behavior: true });
    assert.equal(scored.tiers.t4.status, 'ran');
    assert.equal(scored.tiers.t4.score, 1);
    assert.equal(scored.tiers.t4.outputs.recall, 1);
    assert.equal(scored.tiers.t4.effects.recall, 1);
    assert.ok(scored.weightsUsed.t4 > 0);
    assert.ok(scored.limitations.some((line) => line.includes('declared behaviour surface')));
  });
});

test('the behaviour tier names a dropped message and an invented capability', async () => {
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, samplePE({ apis: ['CreateFileA', 'MessageBoxA'], strings: ['Cannot open config file.'] }));
    await writeFile(rebuilt, samplePE({ apis: ['CreateFileA', 'WinHttpOpen'], strings: [] }));
    const result = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false, behavior: true });
    assert.ok(result.tiers.t4.score < 1);
    assert.ok(result.tiers.t4.outputs.missing.includes('Cannot open config file.'));
    assert.ok(result.tiers.t4.effects.added.includes('network:open'));
    assert.ok(result.tiers.t4.effects.missing.includes('ui:call'));
  });
});

test('dynamic evidence joins the target truth so a runtime-only value is not scored as fabrication', async () => {
  const url = 'https://telemetry.example.test/v1/collect';
  const source = `const char *endpoint = "${url}";\n`;
  await inTemp('dsh-rea-compare-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    // The target derives the endpoint at run time, so it holds no static copy;
    // the rebuild carries it because the source is correct.
    await writeFile(target, samplePE({ apis: ['CreateFileA'], strings: [] }));
    await writeFile(rebuilt, samplePE({ apis: ['CreateFileA'], strings: [url] }));

    const staticOnly = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, sourceText: source, engine: false });
    assert.ok(staticOnly.tiers.payload.indicators.precision === 0);
    assert.equal(staticOnly.tiers.t3.score, 0);

    const withTrace = await compareBuilds({
      targetPath: target, rebuiltPath: rebuilt, sourceText: source, engine: false,
      dynamicEvidence: { strings: [url], iocs: [url] },
    });
    assert.equal(withTrace.tiers.payload.indicators.precision, 1);
    assert.equal(withTrace.tiers.payload.indicators.recall, 1);
    assert.equal(withTrace.tiers.t3.score, 1);
    assert.equal(withTrace.dynamicEvidence.strings, 1);
    assert.ok(withTrace.limitations.some((line) => line.includes('exist at run time')));
  });
});

test('a compiled rebuild that drops a file write and its message loses behaviour recall', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  await inTemp('dsh-rea-behaviour-', async (dir) => {
    const withBehaviour = [
      '#include <windows.h>',
      'int main(void) {',
      '  HANDLE h = CreateFileA("rea-state.dat", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);',
      '  if (h == INVALID_HANDLE_VALUE) MessageBoxA(0, "Cannot open config file.", "rea", 0);',
      '  else CloseHandle(h);',
      '  return 0;',
      '}',
    ].join('\n');
    const without = [
      '#include <stdio.h>',
      'int main(void) { printf("ok\\n"); return 0; }',
    ].join('\n');
    const a = await compileC({ sourceText: withBehaviour, workDir: join(dir, 'a'), name: 'a' });
    const b = await compileC({ sourceText: without, workDir: join(dir, 'b'), name: 'b' });
    assert.equal(a.ok, true, a.reason);
    assert.equal(b.ok, true, b.reason);
    // Without the toolchain floor both sides share the CRT's own messages and
    // effects, and the tier would score the runtime instead of the code.
    const measured = await measureToolchainFloor({ workDir: join(dir, 'floor') });
    assert.equal(measured.reason, null);
    const result = await compareBuilds({
      targetPath: a.outPath, rebuiltPath: b.outPath, engine: false, behavior: true,
      runtimeFloor: measured.floor,
    });
    assert.equal(result.tiers.t4.status, 'ran');
    assert.ok(result.tiers.t4.score < 0.9);
    assert.ok(result.tiers.t4.effects.missing.includes('file:create'), 'the file write is missing from the rebuild');
    assert.ok(result.tiers.t4.outputs.missing.some((value) => value.includes('Cannot open config file')), 'the failure message is missing');
  });
});

// ---------------------------------------------------------------------------
// T2 denominator deduction: the function-level toolchain floor.
// ---------------------------------------------------------------------------

test('the function floor never deducts main or decompiler-generated names by name', () => {
  const floor = functionFloorFromInventory([
    { name: '__tmainCRTStartup', rva: '0x1000', body: 'void __tmainCRTStartup(void) { int x = 1; while (x) { x = 0; } }' },
    { name: 'main', rva: '0x1600', body: 'int main(void) { return 0; }' },
    { name: 'FUN_140001000', rva: '0x1400', body: 'undefined8 FUN_140001000(void) { return 0; }' },
  ]);
  assert.ok(floor.names.has('__tmainCRTStartup'));
  assert.ok(!floor.names.has('main'), 'main is never a floor name');
  assert.ok(!floor.names.has('FUN_140001000'), 'FUN_* is never a floor name');
  // Their bodies still count: a body hash is measured evidence, not a name.
  assert.ok([...floor.bodyHashes.keys()].length === 3);
  assert.ok(floor.rvas.has('0x1000'));
  assert.ok(!floor.rvas.has('0x1600'));
});

test('deduction requires measured evidence: name-only hits are audited, not deducted', () => {
  const floor = functionFloorFromInventory([
    { name: '__tmainCRTStartup', rva: '0x1000', body: 'void __tmainCRTStartup(void) { int x = 1; while (x) { x = 0; } }' },
    { name: 'FUN_140001000', rva: '0x1400', body: 'undefined8 FUN_140001000(void) { return 0; }' },
  ]);
  const target = [
    // name + RVA both match the floor: the strongest class.
    { name: '__tmainCRTStartup', rva: '0x1000', body: 'void __tmainCRTStartup(void) { int x = 2; while (x) { x = 0; } }' },
    // same body as a floor function but a FUN_ name the floor excludes: only
    // the body hash can catch it (the R0-style unnamed CRT thunk case).
    { name: 'FUN_140001000', rva: '0x9999', body: 'undefined8 FUN_140001000(void) { return 0; }' },
    // name survives, body differs: audit only, stays in the denominator.
    { name: '__tmainCRTStartup', rva: '0x7777', body: 'void __tmainCRTStartup(void) { while (1) { break; } }' },
    // a user function: never matched.
    { name: 'mix', rva: '0x2000', body: 'int mix(int a, int b) { return a + b; }' },
  ];
  assert.equal(classifyAgainstFunctionFloor(target[0], floor), 'name+rva');
  assert.equal(classifyAgainstFunctionFloor(target[1], floor), 'body-hash');
  assert.equal(classifyAgainstFunctionFloor(target[2], floor), 'name-only');
  assert.equal(classifyAgainstFunctionFloor(target[3], floor), null);
  const split = splitByFunctionFloor(target, floor);
  assert.deepEqual(split.deducted.map((item) => item.name), ['__tmainCRTStartup', 'FUN_140001000']);
  assert.deepEqual(split.deducted.map((item) => item.matchedBy), ['name+rva', 'body-hash']);
  assert.deepEqual(split.nameOnly.map((item) => item.name), ['__tmainCRTStartup']);
  assert.deepEqual(split.kept.map((item) => item.name), ['__tmainCRTStartup', 'mix']);
  assert.equal(split.kept.length, 2, 'name-only hits stay in the denominator');
});

test('floors union across sources and survive a JSON round trip', () => {
  const empty = functionFloorFromInventory([
    { name: '__tmainCRTStartup', rva: '0x1000', body: 'void __tmainCRTStartup(void) { return; }' },
  ]);
  const stub = functionFloorFromInventory([
    { name: '_gnu_exception_handler', rva: '0x2000', body: 'long _gnu_exception_handler(void) { return 0; }' },
  ]);
  const union = unionFunctionFloors(empty, stub);
  assert.ok(union.names.has('__tmainCRTStartup'));
  assert.ok(union.names.has('_gnu_exception_handler'));
  // A floor that crossed JSON lost its Sets/Maps; the union must still accept it.
  const jsonFloor = JSON.parse(JSON.stringify({ names: ['memcpy'], rvas: ['0x3000'], bodyHashes: { deadbeef: 'memcpy' } }));
  const merged = unionFunctionFloors(union, jsonFloor);
  assert.ok(merged.names.has('memcpy'));
  assert.ok(merged.bodyHashes.has('deadbeef'));
  assert.equal(unionFunctionFloors(null, empty).names.size, 1);
});

test('a deducted window still counts a missing counterpart as zero', () => {
  // The "no counterpart scores zero" rule is unchanged inside the deducted
  // denominator: dropping the only counterpart of a kept function must average
  // that zero in, not drop the pair.
  const floor = functionFloorFromInventory([
    { name: 'crt_func', rva: '0x1000', body: 'void crt_func(void) { int x = 1; x = x + 1; }' },
  ]);
  const target = [
    { name: 'crt_func', rva: '0x1000', body: 'void crt_func(void) { int x = 1; x = x + 1; }' },
    { name: 'decoder', rva: '0x2000', body: 'alpha beta gamma delta epsilon zeta eta' },
  ];
  const rebuilt = [
    { name: 'crt_func', rva: '0x1000', body: 'void crt_func(void) { int x = 1; x = x + 1; }' },
  ];
  const split = splitByFunctionFloor(target, floor);
  assert.equal(split.kept.length, 1);
  const scored = scoreFunctionLists(split.kept, rebuilt, { metric: 'text', matchBy: 'rva' });
  assert.equal(scored.pairs, 1);
  assert.equal(scored.matched, 0);
  assert.equal(scored.score, 0, 'the kept function with no counterpart still scores zero');
  assert.deepEqual(scored.mismatches.map((item) => item.name), ['decoder']);
});

test('deductFunctions is opt-in: the default comparison keeps the raw window', async (t) => {
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  await inTemp('dsh-rea-deduct-', async (dir) => {
    const source = [
      '#include <stdio.h>',
      'static int mix(int a, int b) { int s = 0; for (int i = 0; i < 4; i += 1) { s += a * i + b; } return s; }',
      'int main(void) { printf("%d\\n", mix(3, 4)); return 0; }',
    ].join('\n');
    const target = await compileC({ sourceText: source, workDir: join(dir, 't'), name: 'target' });
    const rebuilt = await compileC({ sourceText: source, workDir: join(dir, 'r'), name: 'rebuilt' });
    assert.equal(target.ok, true, target.reason);
    assert.equal(rebuilt.ok, true, rebuilt.reason);

    const raw = await compareBuilds({ targetPath: target.outPath, rebuiltPath: rebuilt.outPath, engine: true, maxFunctions: 48, timeoutMs: 300_000 });
    assert.equal(raw.tiers.t2.status, 'ran');
    assert.equal(raw.tiers.t2.scoreAll, undefined, 'no scoreAll without the deduction flag');
    assert.equal(raw.tiers.t2.denominator, undefined);
    assert.ok(raw.limitations[0].includes('no counterpart scores zero'), 'the undeducted limitation text is unchanged');

    const measured = await measureToolchainFloor({ workDir: join(dir, 'floor'), listFunctions: true });
    assert.equal(measured.reason, null);
    assert.ok(measured.functionFloor, `function floor measured (${measured.functionFloorReason})`);
    assert.ok(measured.functionFloor.names.size > 0, 'the empty program carries named CRT functions');

    const deducted = await compareBuilds({
      targetPath: target.outPath, rebuiltPath: rebuilt.outPath, engine: true, maxFunctions: 48,
      timeoutMs: 300_000, deductFunctions: true, functionFloor: measured.functionFloor,
    });
    assert.equal(deducted.tiers.t2.status, 'ran');
    const { denominator, deducted: removed, score, scoreAll } = deducted.tiers.t2;
    assert.ok(denominator.before > denominator.after, `CRT functions leave the denominator (${denominator.before} → ${denominator.after})`);
    assert.ok(removed.length > 0, 'the deducted list is on record');
    assert.equal(typeof score, 'number');
    assert.equal(typeof scoreAll, 'number');
    assert.ok(!removed.some((item) => item.name === 'mix' || item.name === 'main'), 'user functions stay in the denominator');
    assert.ok(deducted.limitations[0].includes('deducted average'), 'the limitation text explains the deduction');
    // Same-toolchain rebuild: every kept function still matches, so both
    // averages stay at 1.0 and only the denominator moves.
    assert.equal(score, 1);
    assert.equal(scoreAll, 1);

    // A named-function review is never deducted, even when asked.
    const named = await compareBuilds({
      targetPath: target.outPath, rebuiltPath: rebuilt.outPath, engine: true, maxFunctions: 48,
      timeoutMs: 300_000, deductFunctions: true, functionFloor: measured.functionFloor,
      functionFilter: ['mix'],
    });
    assert.equal(named.tiers.t2.status, 'ran');
    assert.equal(named.tiers.t2.denominator, undefined, 'functionFilter wins over deduction');
    assert.equal(named.tiers.t2.functions, 1);
  });
});

test('measureToolchainFloor without listFunctions keeps its old shape', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  await inTemp('dsh-rea-floor-', async (dir) => {
    const measured = await measureToolchainFloor({ workDir: join(dir, 'floor') });
    assert.equal(measured.reason, null);
    assert.equal(measured.functionFloor, null, 'no function floor unless asked for');
    assert.ok(measured.floor.imports.size > 0);
  });
});

// ---------------------------------------------------------------------------
// T5 interaction tier: opt-in, engine-inventory-dependent, symmetric.
// ---------------------------------------------------------------------------

test('the interaction tier is opt-in: skipped by default, blocked without the engine inventory', async () => {
  await inTemp('dsh-rea-interact-', async (dir) => {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    const bytes = samplePE({ apis: ['CreateFileA', 'MessageBoxA'], strings: ['https://c2.example/gate.php'] });
    await writeFile(target, bytes);
    await writeFile(rebuilt, bytes);

    const skipped = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false });
    assert.equal(skipped.tiers.t5.status, 'skipped');
    assert.equal(skipped.tiers.t5.score, null);
    assert.equal(skipped.weightsUsed.t5, undefined, 'the default ladder has no t5 weight');
    assert.ok(skipped.limitations.every((line) => !line.includes('T5')), 'no interaction limitations when the tier did not run');

    const blocked = await compareBuilds({ targetPath: target, rebuiltPath: rebuilt, engine: false, interaction: true });
    assert.equal(blocked.tiers.t5.status, 'blocked', 'explicit blocked, never a silent zero');
    assert.equal(blocked.tiers.t5.score, null);
    assert.match(blocked.tiers.t5.reason, /engine function inventory/);
    assert.equal(blocked.weightsUsed.t5, undefined, 'a blocked tier does not enter the weighted average');
    assert.equal(blocked.overall, skipped.overall, 'the overall number is unchanged without the tier');
    assert.deepEqual(blocked.weightsUsed, skipped.weightsUsed);
  });
});

test('the interaction tier scores a GUI rebuild at 1.0 and names a dropped message handler', async (t) => {
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-t5-'));
  try {
    const target = await generateSpecimen({ tier: 'R5', outDir: dir, mutate: false });
    assert.equal(target.ok, true, target.build?.reason);
    const rebuilt = await compileC({ sourceText: target.truth.source, workDir: join(dir, 'rebuild'), name: 'r5-rebuild', extraArgs: target.truth.extraArgs });
    assert.equal(rebuilt.ok, true, rebuilt.reason);

    const ceiling = await compareBuilds({
      targetPath: target.truth.targetPath, rebuiltPath: rebuilt.outPath, sourceText: target.truth.source,
      engine: true, timeoutMs: 300_000, maxFunctions: 48, interaction: true,
    });
    assert.equal(ceiling.tiers.t5.status, 'ran');
    assert.equal(ceiling.tiers.t5.score, 1, 'a faithful rebuild keeps the whole interaction surface');
    assert.equal(ceiling.tiers.t5.windows.recall, 1);
    assert.equal(ceiling.tiers.t5.messages.recall, 1);
    assert.equal(ceiling.tiers.t5.controls.recall, 1);
    assert.equal(ceiling.overall, 1);
    assert.ok(ceiling.weightsUsed.t5 > 0, 'the ran tier enters the renormalised weights');
    assert.ok(ceiling.weightsUsed.t4 === undefined, 'the untouched opt-in tier stays out');
    assert.ok(ceiling.limitations.some((line) => line.includes('user32/kernel32')), 'the interaction limitations are on record');

    const mutant = await generateSpecimen({ tier: 'R5', outDir: dir, mutate: true });
    assert.equal(mutant.ok, true, mutant.build?.reason);
    const mutation = await compareBuilds({
      targetPath: target.truth.targetPath, rebuiltPath: mutant.truth.targetPath, sourceText: mutant.truth.source,
      engine: true, timeoutMs: 300_000, maxFunctions: 48, interaction: true,
    });
    assert.equal(mutation.tiers.t5.status, 'ran');
    assert.ok(mutation.tiers.t5.score < 1, 'a dropped message handler lowers the interaction score');
    assert.equal(mutation.tiers.t5.messages.recall, 0.75, 'three of four message handlers survive the mutation');
    assert.deepEqual(mutation.tiers.t5.messages.missing, ['msg:0x111'], 'WM_COMMAND is the named gap');
    assert.equal(mutation.tiers.t5.controls.recall, 1, 'the button id survives via its hmenu');
    assert.ok(mutation.overall < ceiling.overall);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// T5 tier-status rules: skipped / blocked / empty / truncated, decided on
// measured facts. The truncated-without-facts -> blocked rule exists so a cut
// off window procedure can never be reported as "no interaction surface".
// ---------------------------------------------------------------------------

const tierLists = {
  full: { ok: true, functions: [{ name: 'WndProc', rva: '0x1760', body: 'undefined8 WndProc(longlong p1, uint p2) { if (p2 == 1) { return 0; } return 0; }' }], truncated: false },
  truncated: { ok: true, functions: [{ name: 'FUN_140001000', rva: '0x1000', body: 'undefined8 FUN_140001000(void) { return 0; }' }], truncated: true },
};

function tierSide({ imports = [], functions = [], withLayout = false } = {}) {
  return {
    buffer: Buffer.alloc(0x20),
    layout: withLayout ? { plus: true, imageBase: 0x140000000, entryRva: 0x1000, dataDirs: [], sections: [] } : null,
    imports: { apiFlat: imports },
    functions,
  };
}

test('the interaction tier status rules cover every branch on measured facts', () => {
  const windowImports = ['RegisterClassExW', 'CreateWindowExW'];

  assert.equal(buildInteractionTier({}).status, 'skipped', 'off is the default');
  const noEngine = buildInteractionTier({ enabled: true, engine: false });
  assert.equal(noEngine.status, 'blocked');
  assert.match(noEngine.reason, /engine function inventory/);
  const noLists = buildInteractionTier({ enabled: true, engine: true, target: tierSide(), rebuilt: tierSide() });
  assert.equal(noLists.status, 'blocked');
  assert.match(noLists.reason, /engine function inventory/);

  // The verifier-flagged rule, now executed: a truncated inventory that
  // surfaced zero target facts is blocked with score null, never a scored 0.
  const blocked = buildInteractionTier({
    enabled: true, engine: true,
    targetList: tierLists.truncated, rebuiltList: tierLists.truncated,
    target: tierSide(), rebuilt: tierSide(),
  });
  assert.equal(blocked.status, 'blocked');
  assert.equal(blocked.score, null);
  assert.equal(blocked.inventoryTruncated, true);
  assert.match(blocked.reason, /truncated inventory surfaced no interaction facts/);

  // Truncated but the target still shows facts (import-level at least): the
  // tier runs on what is visible and says the inventory was truncated.
  const ran = buildInteractionTier({
    enabled: true, engine: true,
    targetList: tierLists.truncated, rebuiltList: tierLists.truncated,
    target: tierSide({ imports: windowImports }), rebuilt: tierSide({ imports: windowImports }),
  });
  assert.equal(ran.status, 'ran');
  assert.equal(ran.inventoryTruncated, true);
  assert.match(ran.note, /truncated/);
  assert.equal(ran.windows.recall, 1);

  // Not truncated and nothing on either side: honest empty, not blocked, not 1.0.
  const empty = buildInteractionTier({
    enabled: true, engine: true,
    targetList: tierLists.full, rebuiltList: tierLists.full,
    target: tierSide(), rebuilt: tierSide(),
  });
  assert.equal(empty.status, 'empty');
  assert.equal(empty.score, null);
  assert.equal(empty.inventoryTruncated, false);

  // Full inventory with a real window procedure: ran, no truncation note.
  const clean = buildInteractionTier({
    enabled: true, engine: true,
    targetList: tierLists.full, rebuiltList: tierLists.full,
    target: tierSide({ imports: windowImports }), rebuilt: tierSide({ imports: windowImports }),
  });
  assert.equal(clean.status, 'ran');
  assert.equal(clean.inventoryTruncated, false);
  assert.equal(clean.note, undefined);
});

/** Zero the .rsrc data-directory pointer: a PE that genuinely carries no resources. */
function zeroResourceDirectory(bytes) {
  const buffer = Buffer.from(bytes);
  const pe = buffer.readUInt32LE(0x3c);
  const plus = buffer.readUInt16LE(pe + 24) === 0x20b;
  const directoryAt = pe + 24 + (plus ? 112 : 96);
  buffer.writeUInt32LE(0, directoryAt + 2 * 8);
  buffer.writeUInt32LE(0, directoryAt + 2 * 8 + 4);
  return buffer;
}

test('a one-function page size still aggregates the complete engine inventory', async (t) => {
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const ghidra = await ghidraLocalReadiness();
  if (!ghidra.ready) {
    t.skip(`no Ghidra (${ghidra.reason})`);
    return;
  }
  await inTemp('dsh-rea-t5-pages-', async (dir) => {
    const spec = await generateSpecimen({ tier: 'R5', outDir: dir, mutate: false });
    assert.equal(spec.ok, true, spec.build?.reason);
    const compared = await compareBuilds({
      targetPath: spec.truth.targetPath, rebuiltPath: spec.truth.targetPath,
      engine: true, interaction: true, maxFunctions: 1, timeoutMs: 300_000,
    });
    assert.equal(compared.tiers.t2.inventoryComplete, true, JSON.stringify(compared.tiers.t2));
    assert.equal(compared.tiers.t2.truncated, false);
    assert.ok(compared.tiers.t2.pages > 1, 'page size is not an inventory cap');
    assert.equal(compared.tiers.t5.status, 'ran');
    assert.equal(compared.tiers.t5.inventoryComplete, true);
    assert.equal(compared.tiers.t5.inventoryTruncated, false);
    assert.equal(compared.tiers.t5.score, 1);
  });
});
