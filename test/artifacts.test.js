import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { DESTRUCTIVE_TOOLS, MUTATING_TOOLS, createArtifactStore } from '../lib/artifacts.js';

async function withStore(options, run) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-rea-artifacts-'));
  try {
    await run(createArtifactStore({ root, ...options }), root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('a result inside the budget is returned untouched', async () => {
  await withStore({ maxChars: 100 }, async (store) => {
    assert.equal(await store.maybeSpill('binary_session', 'x'.repeat(100)), undefined);
  });
});

test('an oversized result is written to disk and replaced by a head plus a handle', async () => {
  await withStore({ maxChars: 100, headChars: 20 }, async (store, root) => {
    const text = 'A'.repeat(500);
    const replacement = await store.maybeSpill('binary_session', text);
    assert.ok(replacement.includes(root), 'the replacement names the artifact path');
    assert.ok(replacement.startsWith('A'.repeat(20)));
    assert.ok(replacement.includes('480 more characters omitted'));
    const path = replacement.match(/Full output: (.+)$/m)[1];
    assert.ok(existsSync(path));
    assert.equal(await readFile(path, 'utf8'), text);
  });
});

test('pages are bounded and report what is left', async () => {
  await withStore({ maxChars: 10 }, async (store) => {
    const replacement = await store.maybeSpill('t', 'B'.repeat(300));
    const path = replacement.match(/Full output: (.+)$/m)[1];
    const first = await store.read(path, 0, 100);
    assert.equal(first.returned, 100);
    assert.equal(first.total, 300);
    assert.equal(first.remaining, 200);
    assert.equal(first.nextOffset, 100);
    const last = await store.read(path, 200, 1000);
    assert.equal(last.remaining, 0);
    assert.equal(last.nextOffset, null);
  });
});

test('the artifact reader refuses paths outside its own directory', async () => {
  await withStore({ maxChars: 10 }, async (store) => {
    await assert.rejects(store.read(join(tmpdir(), 'elsewhere.txt')), /only reads files under/);
    await assert.rejects(store.read('/etc/passwd'), /only reads files under/);
  });
});

test('the audit trail records one JSON line per call', async () => {
  await withStore({}, async (store, root) => {
    await store.audit({ tool: 'set_comment', args: ['address'] });
    await store.audit({ tool: 'push_adb_file', args: ['device_path'] });
    const lines = (await readFile(join(root, 'audit.jsonl'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0]);
    assert.equal(first.tool, 'set_comment');
    assert.ok(typeof first.at === 'string');
  });
});

test('destructive tools are a subset of the audited ones', () => {
  for (const tool of DESTRUCTIVE_TOOLS) {
    assert.ok(MUTATING_TOOLS.has(tool), `${tool} should also be audited`);
  }
  assert.ok(DESTRUCTIVE_TOOLS.has('uninstall_adb_package'));
  assert.equal(DESTRUCTIVE_TOOLS.has('set_comment'), false);
});
