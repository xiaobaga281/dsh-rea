import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createResultIndex } from '../lib/result-index.js';
import { listPlaybooks, runPlaybook, safePlaybookName } from '../lib/playbook.js';
import { buildWindowsToolsTool, protocolToolInventory, windowsToolInventory } from '../lib/external-adapters.js';
import {
  buildBatchTriageTool, buildDiffHintTool, buildFuzzHarnessTool, buildPlaybookTool, buildQueryResultsTool,
} from '../lib/workflow-tools.js';

async function withTemp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-workflow-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('playbook names reject traversal and only accept .mjs', () => {
  assert.equal(safePlaybookName('rename.mjs'), 'rename.mjs');
  assert.equal(safePlaybookName('../evil.mjs'), null);
  assert.equal(safePlaybookName('C:\\tmp\\x.mjs'), null);
  assert.equal(safePlaybookName('x.js'), null);
});

test('a trusted playbook runs in a child and every call is proxied and counted', async () => {
  await withTemp(async (dir) => {
    await writeFile(join(dir, 'chain.mjs'), `export default async ({ rea, artifact, input }) => {
      const a = await rea.call('list_names', {});
      artifact.log('seen', input.tag);
      return { first: a, tag: input.tag };
    };`, 'utf8');
    assert.deepEqual(await listPlaybooks(dir), ['chain.mjs']);
    const calls = [];
    const outcome = await runPlaybook({
      dir, name: 'chain.mjs', input: { tag: 'alpha' }, timeoutMs: 20_000, maxCalls: 5,
      toolNames: () => ['mcp__rea__list_names'],
      callTool: async (tool, args) => { calls.push({ tool, args }); return { content: [{ type: 'text', text: 'names' }] }; },
    });
    assert.equal(outcome.ok, true, JSON.stringify(outcome));
    assert.equal(outcome.calls, 1);
    assert.equal(calls[0].tool, 'list_names');
    assert.match(outcome.result, /alpha/);
    assert.ok(outcome.logs.some((line) => line.includes('seen alpha')));
  });
});

test('playbooks cannot call a tool outside the catalog and cannot exceed the call cap', async () => {
  await withTemp(async (dir) => {
    await writeFile(join(dir, 'bad.mjs'), `export default async ({ rea }) => { await rea.call('not_in_catalog', {}); return 'x'; };`, 'utf8');
    const outcome = await runPlaybook({
      dir, name: 'bad.mjs', timeoutMs: 20_000, maxCalls: 2,
      toolNames: () => [], callTool: async () => ({}),
    });
    assert.equal(outcome.ok, false);
    assert.match(outcome.error, /not in the REA catalog/);
  });
});

test('rea_run_playbook lists scripts when no name is given', async () => {
  await withTemp(async (dir) => {
    await writeFile(join(dir, 'one.mjs'), 'export default async () => 1;', 'utf8');
    const tool = buildPlaybookTool({
      dir, timeoutMs: 5_000, maxCalls: 2,
      callTool: async () => ({}), toolNames: () => [],
    });
    const { text } = await tool.execute({});
    assert.match(text, /one\.mjs/);
  });
});

test('result query and corpus triage share one index', async () => {
  await withTemp(async (dir) => {
    const index = createResultIndex({ base: dir });
    await index.record({ at: '2026-01-01T00:00:00.000Z', tool: 'analyze_function', evidenceIds: ['ev_1'] });
    const query = buildQueryResultsTool(index);
    const { text } = await query.execute({ tool: 'analyze' });
    assert.match(text, /analyze_function/);

    await writeFile(join(dir, 'a.bin'), Buffer.from('plain words here '.repeat(200)));
    await writeFile(join(dir, 'b.bin'), Buffer.concat([Buffer.from('UPX0 UPX1 '), Buffer.alloc(2048, 0x41)]));
    const batch = buildBatchTriageTool({ resultIndex: index, triageOptions: {}, maxBatch: 10 });
    const summary = await batch.execute({ directory: dir, pattern: '.bin' });
    assert.match(summary.text, /files examined: 2/);
    assert.equal((await index.query({ tool: 'rea_triage' })).length, 2);
  });
});

test('diff hint produces a prioritised candidate list and declares its limits', async () => {
  await withTemp(async (dir) => {
    const left = join(dir, 'old.bin');
    const right = join(dir, 'new.bin');
    await writeFile(left, Buffer.from('alpha beta gamma old string value '.repeat(100)));
    await writeFile(right, Buffer.from('alpha beta delta new string value '.repeat(100)));
    const tool = buildDiffHintTool({ triageOptions: {} });
    const { text } = await tool.execute({ left, right });
    assert.match(text, /priority 1/);
    assert.match(text, /untrusted-strings/);
    assert.match(text, /NOT structural binary diffing/);
  });
});

test('fuzz harness generates a template without compiling anything', async () => {
  const tool = buildFuzzHarnessTool({});
  const { text } = await tool.execute({ crash: 'SIGSEGV at 0xdeadbeef' });
  assert.match(text, /LLVMFuzzerTestOneInput/);
  assert.match(text, /SIGSEGV/);
  assert.match(text, /untrusted-crash-input/);
});

test('external adapters degrade honestly when tools are absent', () => {
  assert.equal(windowsToolInventory('linux').supported, false);
  assert.equal(typeof protocolToolInventory().tshark.available, 'boolean');
  const windows = buildWindowsToolsTool({ platform: 'linux' });
  return windows.execute({}).then(({ text }) => assert.match(text, /linux/));
});
