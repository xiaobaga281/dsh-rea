/**
 * W3: .NET/managed metadata manifest tests.
 *
 * Two positive corpora, both local and read-only, zero external traffic:
 *   1. a deterministic minimal IL fixture (test/fixtures/managed/mini.il)
 *      assembled at test time with the system ilasm.exe - the output is only
 *      ever parsed as bytes, never executed;
 *   2. the system's own System.Data.dll (a real ~3.5 MB mixed-mode corpus).
 *
 * Negatives: a native PE without a CLR directory, a CLR directory aimed at
 * non-BSJB bytes, a CLR header outside the mapped image, non-PE bytes, and the
 * system's native where.exe.
 *
 * The CLR-header layout regression is pinned here: ECMA-335 sizes
 * IMAGE_COR20_HEADER at 64 bytes with StrongNameSignature at +24, but both
 * measured corpora carry cb=72 and the strong-name RVA/size at +32/+36 (the
 * signature ends exactly at the metadata root). If the offset is ever "fixed"
 * back to +24, the System.Data assertions below fail.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import { parseManaged } from '../lib/managed.js';
import { readPeLayout, rvaToOffset, structureProfile } from '../lib/structure.js';
import { triageBuffer } from '../lib/triage.js';

const windir = process.env.WINDIR ?? 'C:\\Windows';
const frameworkDirs = [
  join(windir, 'Microsoft.NET', 'Framework64', 'v4.0.30319'),
  join(windir, 'Microsoft.NET', 'Framework', 'v4.0.30319'),
];
const findTool = (name) => frameworkDirs.map((dir) => join(dir, name)).find((path) => existsSync(path)) ?? null;
const ilasmPath = findTool('ilasm.exe');
const systemDataPath = findTool('System.Data.dll');
const whereExePath = join(windir, 'System32', 'where.exe');
const ILASM_SKIP = ilasmPath ? false : 'ilasm.exe not found on this host (no .NET Framework)';
const SYSTEM_DATA_SKIP = systemDataPath ? false : 'System.Data.dll not found on this host';
const mscorlibPath = findTool('mscorlib.dll');
const MSCORLIB_SKIP = mscorlibPath ? false : 'mscorlib.dll not found on this host';

/** Smallest PE the structural readers accept; extended with a CLR directory. */
function miniPe({ text = Buffer.alloc(0), clr = false, clrRva = 0x1000 } = {}) {
  const textSize = Math.max(text.length, 0x200);
  const bytes = Buffer.alloc(0x200 + textSize);
  bytes.write('MZ', 0, 'latin1');
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'latin1');
  bytes.writeUInt16LE(1, 0x46);
  bytes.writeUInt16LE(0xf0, 0x54);
  bytes.writeUInt16LE(0x20b, 0x58);
  bytes.writeBigUInt64LE(0x400000n, 0x58 + 24);
  bytes.writeUInt32LE(16, 0x58 + 108); // NumberOfRvaAndSizes
  if (clr) {
    bytes.writeUInt32LE(clrRva, 0x58 + 112 + 14 * 8);
    bytes.writeUInt32LE(72, 0x58 + 112 + 14 * 8 + 4);
  }
  const table = 0x58 + 0xf0;
  bytes.write('.text', table, 'latin1');
  bytes.writeUInt32LE(textSize, table + 8);
  bytes.writeUInt32LE(0x1000, table + 12);
  bytes.writeUInt32LE(textSize, table + 16);
  bytes.writeUInt32LE(0x200, table + 20);
  bytes.writeUInt32LE(0x60000020, table + 36);
  text.copy(bytes, 0x200);
  return bytes;
}

/** A CLR header at rva 0x1000 whose metadata RVA points at non-BSJB bytes. */
function miniPeWithGarbageMetadata() {
  const text = Buffer.alloc(0x400);
  text.writeUInt32LE(72, 0); // cb
  text.writeUInt16LE(2, 4); // runtime major
  text.writeUInt16LE(5, 6); // runtime minor
  text.writeUInt32LE(0x1200, 8); // metadata RVA -> rva 0x1200 = file offset 0x400
  text.writeUInt32LE(0x100, 12); // metadata size
  text.write('NOPE', 0x200, 'latin1'); // not BSJB
  return miniPe({ text, clr: true });
}

let fixtureCache = null;
async function assembledFixture() {
  if (fixtureCache) return fixtureCache;
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-managed-'));
  try {
    const out = join(dir, 'mini.exe');
    const source = join(dir, 'mini.il');
    await writeFile(source, await readFile(join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'managed', 'mini.il')));
    const run = spawnSync(ilasmPath, ['/nologo', `/out=${out}`, source], { encoding: 'utf8' });
    assert.equal(run.status, 0, `ilasm failed: ${(run.stderr || run.stdout || '').slice(0, 300)}`);
    assert.ok(existsSync(out), 'ilasm produced no output');
    const bytes = await readFile(out);
    const layout = readPeLayout(bytes);
    assert.ok(layout, 'ilasm output is not a parseable PE');
    const manifest = parseManaged(bytes, layout);
    assert.ok(manifest?.metadata, 'ilasm output did not parse as a managed manifest');
    fixtureCache = { dir, bytes, layout, manifest };
    return fixtureCache;
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}
after(async () => {
  if (fixtureCache) await rm(fixtureCache.dir, { recursive: true, force: true });
  if (ehFixtureCache) await rm(ehFixtureCache.dir, { recursive: true, force: true });
});

/** Second fixture: a method with .try/.catch/.finally for the CIL EH parser. */
let ehFixtureCache = null;
async function assembledEhFixture() {
  if (ehFixtureCache) return ehFixtureCache;
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-managed-eh-'));
  try {
    const out = join(dir, 'eh.exe');
    const source = join(dir, 'eh.il');
    await writeFile(source, await readFile(join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'managed', 'eh.il')));
    const run = spawnSync(ilasmPath, ['/nologo', `/out=${out}`, source], { encoding: 'utf8' });
    assert.equal(run.status, 0, `ilasm failed: ${(run.stderr || run.stdout || '').slice(0, 300)}`);
    assert.ok(existsSync(out), 'ilasm produced no output for eh.il');
    const bytes = await readFile(out);
    const layout = readPeLayout(bytes);
    assert.ok(layout, 'eh.il output is not a parseable PE');
    const manifest = parseManaged(bytes, layout);
    assert.ok(manifest?.metadata, 'eh.il output did not parse as a managed manifest');
    ehFixtureCache = { dir, bytes, layout, manifest };
    return ehFixtureCache;
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}

test('the ilasm fixture parses into a complete manifest', { skip: ILASM_SKIP }, async () => {
  const { manifest } = await assembledFixture();
  assert.equal(manifest.managed, true);
  assert.equal(manifest.present, true);
  assert.equal(manifest.assemblyName, 'mini');
  assert.equal(manifest.assembly.version, '1.0.0.0');
  assert.equal(manifest.moduleName, 'mini.exe');
  assert.equal(manifest.metadata.version, 'v4.0.30319');
  assert.equal(manifest.typeDefTotal, 3);
  assert.equal(manifest.methodDefTotal, 3);
  assert.deepEqual(manifest.types.map((type) => type.name), ['<Module>', 'Program', 'Helper']);
  assert.deepEqual(manifest.types.find((type) => type.name === 'Program').methods.map((method) => method.name), ['Main']);
  assert.deepEqual(manifest.types.find((type) => type.name === 'Helper').methods.map((method) => method.name), ['.ctor', 'GetSeed']);
  assert.deepEqual(manifest.tableRows, {
    Module: 1, TypeRef: 1, TypeDef: 3, Field: 1,
    MethodDef: 3, MemberRef: 1, Assembly: 1, AssemblyRef: 1,
  });
});

test('the fixture #US heap carries the marker string', { skip: ILASM_SKIP }, async () => {
  const { manifest } = await assembledFixture();
  assert.ok(
    manifest.metadata.usStrings.some((value) => value.includes('dsh-rea managed fixture')),
    `#US strings: ${JSON.stringify(manifest.metadata.usStrings)}`,
  );
});

test('CLR header layout regression: the unsigned fixture has zeros at both +24 and +32', { skip: ILASM_SKIP }, async () => {
  const { bytes, layout, manifest } = await assembledFixture();
  const headerAt = rvaToOffset(layout, manifest.rva);
  assert.equal(bytes.readUInt32LE(headerAt + 24), 0);
  assert.equal(bytes.readUInt32LE(headerAt + 28), 0);
  assert.equal(bytes.readUInt32LE(headerAt + 32), 0);
  assert.equal(bytes.readUInt32LE(headerAt + 36), 0);
  assert.deepEqual(manifest.strongName, { rva: 0, size: 0 });
});

test('caps bound the fixture manifest independently', { skip: ILASM_SKIP }, async () => {
  const { bytes, layout } = await assembledFixture();
  const typeCapped = parseManaged(bytes, layout, { typeCap: 2 });
  assert.equal(typeCapped.types.length, 2);
  assert.equal(typeCapped.typeDefTotal, 3);
  assert.equal(typeCapped.typesTruncated, true);
  assert.equal(typeCapped.caps.typeCap, 2);
  const methodCapped = parseManaged(bytes, layout, { methodCapPerType: 1 });
  const helper = methodCapped.types.find((type) => type.name === 'Helper');
  assert.equal(helper.methodCount, 2);
  assert.equal(helper.methods.length, 1);
  assert.equal(methodCapped.methodsTruncated, true);
});

test('System.Data.dll parses to the expected manifest within budget', { skip: SYSTEM_DATA_SKIP }, () => {
  const bytes = readFileSync(systemDataPath);
  const layout = readPeLayout(bytes);
  const started = performance.now();
  const manifest = parseManaged(bytes, layout);
  const elapsed = performance.now() - started;
  assert.ok(manifest, 'no manifest parsed');
  assert.equal(manifest.assemblyName, 'System.Data');
  assert.equal(manifest.assembly.version, '4.0.0.0');
  assert.equal(manifest.moduleName, 'System.Data.dll');
  assert.equal(manifest.metadata.version, 'v4.0.30319');
  assert.ok(manifest.typeDefTotal >= 1000, `typeDefTotal ${manifest.typeDefTotal}`);
  assert.ok(manifest.methodDefTotal >= 10000, `methodDefTotal ${manifest.methodDefTotal}`);
  assert.ok(manifest.resourceTotal >= 16, `resourceTotal ${manifest.resourceTotal}`);
  assert.equal(manifest.resources.length, 16);
  assert.equal(manifest.resourcesTruncated, true);
  assert.ok(elapsed < 100, `parse took ${elapsed} ms`);
  // Strong-name signature at the measured +32 slot: 256 bytes ending exactly
  // at the metadata root. Reading +24 instead (the canonical layout) breaks
  // both assertions - that is the regression this test pins.
  assert.equal(manifest.strongName.size, 256);
  assert.equal(manifest.strongName.rva + manifest.strongName.size, manifest.header.metadataRva);
  const names = manifest.types.flatMap((type) => type.methods.map((method) => method.name));
  assert.ok(names.includes('Dispose'), 'Dispose missing from the capped listing');
});

test('System.Data with the caps released lists every type, method and resource', { skip: SYSTEM_DATA_SKIP }, () => {
  const bytes = readFileSync(systemDataPath);
  const manifest = parseManaged(bytes, readPeLayout(bytes), { typeCap: 4096, methodCapPerType: 4096, resourceCap: 64 });
  assert.equal(manifest.types.length, manifest.typeDefTotal);
  assert.equal(manifest.resources.length, manifest.resourceTotal);
  assert.equal(manifest.typesTruncated, false);
  assert.equal(manifest.methodsTruncated, false);
  const names = manifest.types.flatMap((type) => type.methods.map((method) => method.name));
  assert.ok(names.includes('Fill'), 'Fill missing with caps released');
  assert.ok(names.includes('Open'), 'Open missing with caps released');
});

test('structureProfile exposes the manifest on the managed field', { skip: SYSTEM_DATA_SKIP }, () => {
  const profile = structureProfile(readFileSync(systemDataPath));
  assert.equal(profile.managed.present, true);
  assert.equal(profile.managed.managed, true);
  assert.equal(profile.managed.assemblyName, 'System.Data');
  assert.ok(profile.managed.typeDefTotal >= 1000);
  assert.ok(Array.isArray(profile.managed.types));
});

test('a native PE reports no managed manifest at all', () => {
  const native = miniPe();
  assert.equal(parseManaged(native, readPeLayout(native)), null);
  assert.deepEqual(structureProfile(native).managed, { present: false, rva: 0, size: 0 });
  assert.equal(parseManaged(Buffer.from('not a pe'), null), null);
});

test('a CLR directory aimed at non-BSJB bytes degrades with a note, not a throw', () => {
  const bytes = miniPeWithGarbageMetadata();
  const manifest = parseManaged(bytes, readPeLayout(bytes));
  assert.ok(manifest, 'manifest missing');
  assert.equal(manifest.present, true);
  assert.equal(manifest.metadata, null);
  assert.match(manifest.note, /BSJB/);
  const profile = structureProfile(bytes);
  assert.equal(profile.managed.present, true);
  assert.equal(profile.managed.metadata, null);
});

test('a CLR header outside the mapped image degrades with a note', () => {
  const bytes = miniPe({ clr: true, clrRva: 0x9000 });
  const manifest = parseManaged(bytes, readPeLayout(bytes));
  assert.equal(manifest.header, null);
  assert.match(manifest.note, /outside the mapped image/);
});

test('triage exposes the manifest and adapts its .NET guidance to the advertised tools', { skip: ILASM_SKIP }, async () => {
  const { bytes } = await assembledFixture();
  const report = triageBuffer(bytes, { name: 'mini.exe' });
  assert.equal(report.structure.managed.present, true);
  assert.equal(report.structure.managed.assemblyName, 'mini');
  assert.ok(report.nextSteps.some((step) => /\.NET|CLR/.test(step)), 'no .NET guidance');

  const withUpstream = triageBuffer(bytes, {
    name: 'mini.exe',
    availableTools: new Set(['inspect_managed_artifact', 'inspect_managed_members']),
  });
  assert.ok(withUpstream.nextSteps.some((step) => step.includes('inspect_managed_artifact')), 'upstream guidance missing');

  const withoutUpstream = triageBuffer(bytes, { name: 'mini.exe', availableTools: new Set() });
  assert.ok(withoutUpstream.nextSteps.some((step) => step.includes('structure.managed')), 'local-manifest guidance missing');
  assert.ok(!withoutUpstream.nextSteps.some((step) => step.includes('inspect_managed_artifact')), 'guidance still names unavailable tools');
});

test('the system native where.exe has no managed manifest', { skip: existsSync(whereExePath) ? false : 'where.exe not found' }, () => {
  const bytes = readFileSync(whereExePath);
  assert.equal(parseManaged(bytes, readPeLayout(bytes)), null);
  assert.equal(structureProfile(bytes).managed.present, false);
});

test('the ilasm fixture disassembles to CIL with resolved tokens', { skip: ILASM_SKIP }, async () => {
  const { bytes, layout } = await assembledFixture();
  const { cil } = parseManaged(bytes, layout, { cil: true });
  assert.ok(cil, 'no cil section');
  assert.equal(cil.methods.length, 3);
  assert.equal(cil.truncated, undefined);
  const main = cil.methods.find((method) => method.name === 'Main');
  assert.equal(main.entrypoint, true);
  // Measured: ilasm emits a FAT header for the entrypoint method even at
  // maxstack 1 with no locals, while the other two methods stay tiny.
  assert.equal(main.header, 'fat');
  assert.equal(cil.methods.find((method) => method.name === '.ctor').header, 'tiny');
  assert.deepEqual(main.instructions.map((insn) => insn.n), ['ldstr', 'pop', 'ret']);
  assert.deepEqual(main.strings, ['dsh-rea managed fixture']);
  const ctor = cil.methods.find((method) => method.name === '.ctor');
  assert.ok(ctor.apis.includes('System.Object::.ctor'), JSON.stringify(ctor.apis));
  const getSeed = cil.methods.find((method) => method.name === 'GetSeed');
  assert.deepEqual(getSeed.fields, ['Helper::seed']);
  assert.deepEqual(cil.pinvoke, []);
  assert.equal(cil.pinvokeTotal, 0);
  // The instruction stream must land exactly on the body end: the strongest
  // guard that operand sizes (the opcode table) are right.
  for (const method of cil.methods) {
    assert.equal(method.unknownOpcodes, undefined, `${method.name} hit an unknown opcode`);
    const last = method.instructions[method.instructions.length - 1];
    assert.ok(last.o < method.codeBytes, `${method.name} overruns its body`);
  }
});

test('the exception-handling fixture yields real EH clauses from ilasm', { skip: ILASM_SKIP }, async () => {
  const { bytes, layout } = await assembledEhFixture();
  const { cil } = parseManaged(bytes, layout, { cil: true });
  const main = cil.methods.find((method) => method.name === 'Main');
  assert.ok(main, 'Main missing from the EH fixture');
  assert.equal(main.unknownOpcodes, undefined);
  const clauses = main.eh ?? [];
  assert.equal(clauses.length, 2, `expected catch + finally, got ${JSON.stringify(clauses)}`);
  assert.deepEqual(clauses.map((clause) => clause.kind).sort(), ['catch', 'finally']);
  for (const clause of clauses) {
    assert.ok(clause.tryOffset + clause.tryLength <= main.codeBytes, `try range outside body: ${JSON.stringify(clause)}`);
    assert.ok(clause.handlerOffset + clause.handlerLength <= main.codeBytes, `handler outside body: ${JSON.stringify(clause)}`);
  }
  const catchClause = clauses.find((clause) => clause.kind === 'catch');
  assert.equal(catchClause.classToken >>> 24, 0x01, 'catch class token should be a TypeRef');
  const names = main.instructions.map((insn) => insn.n);
  for (const expected of ['leave.s', 'endfinally', 'ret']) {
    assert.ok(names.includes(expected), `${expected} missing from the EH fixture listing`);
  }
});

test('a large managed corpus decodes without unknown opcodes and is capped', { skip: SYSTEM_DATA_SKIP }, () => {
  const bytes = readFileSync(systemDataPath);
  const { cil } = parseManaged(bytes, readPeLayout(bytes), { cil: true, cilMethodCap: 8 });
  assert.equal(cil.methods.length, 8);
  assert.equal(cil.truncated, true);
  for (const method of cil.methods) {
    assert.equal(method.unknownOpcodes, undefined, `${method.type}::${method.name} hit an unknown opcode`);
    if (method.instructionsTruncated) continue;
    const last = method.instructions[method.instructions.length - 1];
    assert.ok(last.o < method.codeBytes, `overrun in ${method.type}::${method.name}`);
  }
});

test('mscorlib resolves its P/Invoke surface through ImplMap', { skip: MSCORLIB_SKIP }, () => {
  const bytes = readFileSync(mscorlibPath);
  const { cil } = parseManaged(bytes, readPeLayout(bytes), { cil: true, cilMethodCap: 4 });
  assert.ok(cil.pinvokeTotal > 0, 'no P/Invoke entries found in mscorlib');
  assert.ok(
    cil.pinvoke.some((entry) => /kernel32|api-ms|ucrtbase/i.test(entry.dll)),
    JSON.stringify(cil.pinvoke.slice(0, 4)),
  );
  assert.equal(cil.pinvoke.length <= cil.caps.pinvokeCap, true);
});
