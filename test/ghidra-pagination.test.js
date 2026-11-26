import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  aggregateFunctionPages,
  hasEngineAnswer,
  hasUsableProject,
  inventoryCachePath,
  parseFunctionList,
  projectNameForContent,
  projectStatePath,
  rememberActiveProjectName,
  selectProjectName,
  shouldRecoverProject,
  selectedInventoryCoverage,
  sha256File,
} from '../lib/restore/ghidra-local.js';

function page(cursor, pageSize, total, names, overrides = {}) {
  const functions = names.map((name, index) => ({
    name,
    rva: `0x${(0x1000 + (cursor + index) * 0x10).toString(16)}`,
    size: 12,
    cfg: { blocks: 1, edges: 0, conditionals: 0, loops: 0, maxFanout: 0 },
    calls: { callees: [], callers: [] },
    references: [],
    body: `void ${name}(void) { return; }`,
  }));
  const emitted = functions.length;
  const nextCursor = cursor + emitted < total ? cursor + emitted : null;
  return {
    header: { total, cursor, pageSize, emitted },
    done: {
      ok: true, total, cursor, pageSize, emitted, failed: 0, nextCursor,
      inventoryComplete: nextCursor === null, timeStopped: false, budgetMs: 180000,
      ...overrides,
    },
    functions,
  };
}

test('stable pages aggregate beyond 200 functions without calling a boundary truncated', () => {
  const names = Array.from({ length: 205 }, (_, index) => `FUN_${index}`);
  const result = aggregateFunctionPages([
    page(0, 200, 205, names.slice(0, 200)),
    page(200, 200, 205, names.slice(200)),
  ]);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.total, 205);
  assert.equal(result.emitted, 205);
  assert.equal(result.functions.length, 205);
  assert.equal(result.truncated, false);
  assert.equal(result.inventoryComplete, true);
  assert.equal(result.pages, 2);
  const prefix = aggregateFunctionPages([page(0, 200, 205, names.slice(0, 200))]);
  assert.equal(prefix.ok, true, prefix.reason);
  assert.equal(prefix.inventoryComplete, false);
  assert.equal(prefix.truncated, false, 'a normal page boundary is not truncation');
});

test('selected-function inventory can traverse unrelated decompile failures without claiming full decompilation', () => {
  const first = page(0, 2, 4, ['broken', 'wanted']);
  first.done.failed = 1;
  first.done.inventoryComplete = false;
  first.done.truncated = true;
  first.functions[0].body = '(decompile failed)';
  first.functions[0].decompiled = false;
  const second = page(2, 2, 4, ['later', 'other']);
  const strict = aggregateFunctionPages([first, second]);
  assert.equal(strict.ok, false);
  assert.match(strict.reason, /decompilation/i);
  const selected = aggregateFunctionPages([first, second], { allowDecompileFailures: true });
  assert.equal(selected.ok, false);
  assert.equal(selected.code, 'decompile-failed');
  assert.equal(selected.enumerationComplete, true);
  assert.equal(selected.inventoryComplete, false);
  assert.equal(selected.truncated, false);
  assert.equal(selected.failed, 1);
  assert.equal(selected.functions.length, 4);
  const coverage = selectedInventoryCoverage(selected, ['wanted', 'later']);
  assert.equal(coverage.complete, true, JSON.stringify(coverage));
  assert.equal(coverage.found, 2);
  assert.equal(coverage.decompiled, 2);
  assert.equal(selectedInventoryCoverage(selected, ['broken']).complete, false);
  const sourceFallback = selectedInventoryCoverage(selected, ['broken'], { sourceFunctions: new Set(['broken']) });
  assert.equal(sourceFallback.complete, false, 'source text cannot stand in for rebuilt decompilation');
  assert.equal(sourceFallback.decompiled, 0);
  assert.deepEqual(sourceFallback.sourceFallback, ['broken']);
  assert.deepEqual(sourceFallback.failed, []);
  assert.equal(selectedInventoryCoverage(selected, ['absent']).complete, false);
  assert.equal(selectedInventoryCoverage({ ...selected, enumerationComplete: false }, ['wanted']).complete, false);
  assert.equal(selectedInventoryCoverage({ ...selected, timeStopped: true }, ['wanted']).complete, false);
  assert.equal(
    aggregateFunctionPages([first, second], { allowDecompileFailures: true }).functions[0].decompiled,
    false,
  );
});

test('empty complete inventory stays complete but supplies no function evidence', () => {
  const result = aggregateFunctionPages([page(0, 48, 0, [])]);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.total, 0);
  assert.equal(result.emitted, 0);
  assert.equal(result.inventoryComplete, true);
  assert.deepEqual(result.functions, []);
});

test('duplicate, missing, looping and inconsistent pages are explicit failures', () => {
  const first = page(0, 2, 5, ['a', 'b']);
  const second = page(2, 2, 5, ['c', 'd']);
  const last = page(4, 2, 5, ['e']);
  const cases = [
    [[first, first], /duplicate function page/i],
    [[first, last], /missing function page/i],
    [[{ ...first, done: { ...first.done, nextCursor: 0 } }, second], /cursor loop/i],
    [[first, { ...second, done: { ...second.done, total: 6 } }], /total mismatch/i],
    [[first, { ...second, header: null }], /LIST or LIST_DONE/i],
    [[{ ...first, done: { ...first.done, failed: 1, inventoryComplete: false } }], /decompilation/i],
    [[{ ...first, done: { ...first.done, timeStopped: true, inventoryComplete: false } }], /decompile deadline|time stopped/i],
  ];
  for (const [pages, pattern] of cases) {
    const result = aggregateFunctionPages(pages);
    assert.equal(result.ok, false);
    assert.equal(result.inventoryComplete, false);
    assert.match(result.reason, pattern);
  }
});

test('identity deduplication merges aliases but cannot inflate complete coverage', () => {
  const first = page(0, 1, 2, ['FUN_1000']);
  first.functions[0].exportName = 'exported_alias';
  const alias = page(1, 1, 2, ['renamed_1000']);
  alias.functions[0] = { ...alias.functions[0], rva: first.functions[0].rva, exportName: 'exported_alias' };
  const result = aggregateFunctionPages([first, alias]);
  assert.equal(result.ok, false);
  assert.equal(result.deduplicated, 1);
  assert.equal(result.functions.length, 1);
  assert.equal(result.functions[0].name, 'FUN_1000');
  assert.equal(result.functions[0].exportName, 'exported_alias');
  assert.match(result.reason, /identity/i);
});

test('the same name at different RVAs remains two distinct functions', () => {
  const result = aggregateFunctionPages([
    page(0, 1, 2, ['repeated_name']),
    page(1, 1, 2, ['repeated_name']),
  ]);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.functions.length, 2);
  assert.equal(result.inventoryComplete, true);
});

test('the parser retains bounded call and reference evidence with pseudocode', () => {
  const metadata = {
    name: 'FUN_1000', exportName: 'decode', rva: '0x1000', size: 42,
    cfg: { blocks: 2, edges: 2, conditionals: 1, loops: 0, maxFanout: 1 },
    calls: { callees: [{ name: 'helper', rva: '0x2000' }], callers: [] },
    references: [{ fromRva: '0x1004', toRva: '0x3000', type: 'DATA', string: 'key' }],
  };
  const parsed = parseFunctionList([
    `LIST {"total":1,"cursor":0,"pageSize":48,"emitted":1}`,
    `FUNCTION ${JSON.stringify(metadata)}`,
    'undefined8 decode(void) { return helper("key"); }',
    'FUNCTION_END',
    'LIST_DONE {"ok":true,"total":1,"cursor":0,"pageSize":48,"emitted":1,"failed":0,"nextCursor":null,"inventoryComplete":true,"timeStopped":false}',
  ].join('\n'));
  assert.equal(parsed.functions[0].calls.callees[0].name, 'helper');
  assert.equal(parsed.functions[0].references[0].string, 'key');
  assert.match(parsed.functions[0].body, /return helper/);
  assert.equal(parsed.done.inventoryComplete, true);
  const failed = parseFunctionList([
    'LIST {"total":1,"cursor":0,"pageSize":48,"emitted":1}',
    'FUNCTION {"name":"broken","rva":"0x1000"}',
    '(decompile failed)',
    'FUNCTION_END',
    'LIST_DONE {"ok":true,"total":1,"cursor":0,"pageSize":48,"emitted":1,"failed":1,"nextCursor":null,"inventoryComplete":false,"timeStopped":false}',
  ].join('\n'));
  assert.equal(failed.functions[0].decompiled, false);
});

test('engine answer detection distinguishes list pages from probe responses', () => {
  const listed = '12:00:00 INFO  ProbeAddress.java> LIST_DONE {"ok":true,"total":1,"inventoryComplete":true}\nproject lock released';
  assert.equal(hasEngineAnswer(listed, 'list'), true, 'a valid list page must not trigger project recovery');
  assert.equal(hasEngineAnswer('project lock released', 'list'), false);
  assert.equal(hasEngineAnswer('12:00:00 INFO  ProbeAddress.java> PROBE {"ok":true}', 'probe'), true);
  assert.equal(hasEngineAnswer('LIST_DONE {"ok":true}', 'probe'), false);
  assert.equal(shouldRecoverProject('INFO project is locked by another process', 'list'), true, 'stdout lock failures must recover too');
  assert.equal(shouldRecoverProject('INFO project is locked by another process', 'probe'), true);
  assert.equal(shouldRecoverProject('ERROR No program files found within specified project folder: /', 'list'), true, 'an interrupted import can leave an empty project');
  assert.equal(shouldRecoverProject('ERROR Project data directory not found: /broken.rep/data', 'list'), true, 'an interrupted save can leave a project without its data directory');
  assert.equal(shouldRecoverProject('ERROR Project marker file not found: /broken.gpr', 'list'), true, 'an interrupted save can leave a missing project marker');
  assert.equal(shouldRecoverProject('ERROR Project marker file not found: /broken.gpr', 'probe'), true);
  assert.equal(shouldRecoverProject('ERROR Project data directory not found: /broken.rep/data', 'probe'), true);
  assert.equal(shouldRecoverProject('ERROR ghidra.util.exception.ClosedException: File is closed', 'list'), true, 'a closed project database must be bypassed');
  assert.equal(shouldRecoverProject('ERROR Import failed for file: /target.exe', 'probe'), true, 'an import failure must not poison later probes');
  assert.equal(shouldRecoverProject(listed, 'list'), false, 'a valid page never triggers recovery');
  assert.equal(shouldRecoverProject('the script produced no answer', 'list'), false, 'unrelated failures are not permission to rebuild the project');
});

test('project usability requires both the marker and saved program data', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-project-state-'));
  try {
    assert.equal(hasUsableProject(dir, 'sample'), false);
    await writeFile(join(dir, 'sample.gpr'), '');
    assert.equal(hasUsableProject(dir, 'sample'), false);
    await mkdir(join(dir, 'sample.rep', 'idata'), { recursive: true });
    assert.equal(hasUsableProject(dir, 'sample'), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a recovered Ghidra project remains selected across inventory pages', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-rea-project-recovery-'));
  const projectDir = join(root, 'projects');
  const sha = 'a'.repeat(64);
  const base = projectNameForContent(sha);
  const recovered = `${base}-recovered`;
  try {
    await mkdir(join(projectDir, `${base}.rep`, 'idata'), { recursive: true });
    await writeFile(join(projectDir, `${base}.gpr`), '');
    await mkdir(join(projectDir, `${recovered}.rep`, 'idata'), { recursive: true });
    await writeFile(join(projectDir, `${recovered}.gpr`), '');
    await rememberActiveProjectName(root, projectDir, sha, recovered);
    assert.equal(await selectProjectName(projectDir, sha, root), recovered);
    assert.equal(await selectProjectName(projectDir, sha, root), recovered);

    const statePath = projectStatePath(sha, root);
    await writeFile(statePath, JSON.stringify({ targetSha256: sha, scriptVersion: 5, projectName: '../escape' }));
    assert.equal(await selectProjectName(projectDir, sha, root), base);
    await writeFile(statePath, JSON.stringify({ targetSha256: 'b'.repeat(64), scriptVersion: 5, projectName: recovered }));
    assert.equal(await selectProjectName(projectDir, sha, root), base);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cache and project identity depend on content, not path, size or mtime', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-cache-id-'));
  try {
    const first = join(dir, 'first.bin');
    const second = join(dir, 'second.bin');
    const changed = join(dir, 'changed.bin');
    const fixed = new Date('2020-01-01T00:00:00.000Z');
    await writeFile(first, Buffer.from('same target bytes'));
    await writeFile(second, Buffer.from('same target bytes'));
    await writeFile(changed, Buffer.from('diff target bytes'));
    await utimes(first, fixed, fixed);
    await utimes(second, fixed, fixed);
    await utimes(changed, fixed, fixed);
    assert.equal((await readFile(first)).length, (await readFile(changed)).length);
    assert.equal((await utimes(first, fixed, fixed)), undefined);

    const firstSha = await sha256File(first);
    const secondSha = await sha256File(second);
    const changedSha = await sha256File(changed);
    assert.equal(firstSha, secondSha);
    assert.notEqual(firstSha, changedSha);
    assert.equal(projectNameForContent(firstSha), projectNameForContent(secondSha));
    assert.notEqual(projectNameForContent(firstSha), projectNameForContent(changedSha));
    assert.equal(inventoryCachePath(firstSha, { pageSize: 48 }, dir), inventoryCachePath(secondSha, { pageSize: 48 }, dir));
    assert.notEqual(inventoryCachePath(firstSha, { pageSize: 48 }, dir), inventoryCachePath(changedSha, { pageSize: 48 }, dir));
    assert.notEqual(inventoryCachePath(firstSha, { pageSize: 48 }, dir), inventoryCachePath(firstSha, { pageSize: 200 }, dir));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
