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

// --- 1.3.0: fail-closed classification, session scope, retention ----------

test('a tool added by a future REA release is audited by default, not silently ignored', async () => {
  const { classifyTool } = await import('../lib/artifacts.js');
  const unknown = classifyTool('deploy_remote_payload', { description: 'Sends a payload to the target.' });
  assert.equal(unknown.mutating, true);
  assert.equal(unknown.inferred, true);
  assert.equal(classifyTool('list_strings').mutating, false);
  assert.equal(classifyTool('inspect_macho', { description: 'Read-only inspection.' }).mutating, false);
});

test('destructive device verbs are inferred from the name, not a hardcoded list', async () => {
  const { classifyTool } = await import('../lib/artifacts.js');
  assert.equal(classifyTool('uninstall_adb_package').destructive, true);
  assert.equal(classifyTool('delete_device_file').destructive, true);
  assert.equal(classifyTool('push_adb_file').destructive, true);
  assert.equal(classifyTool('set_comment').destructive, false);
  assert.equal(classifyTool('record_unknown').destructive, false);
});

test('an explicit read-only declaration overrides a write-looking verb', async () => {
  const { classifyTool } = await import('../lib/artifacts.js');
  assert.equal(classifyTool('set_view_mode', { description: 'Read-only. Does not change any state.' }).mutating, false);
});

test('session scope rejects paths outside the allowed roots and allows those inside', async () => {
  const { pathOutsideScope } = await import('../lib/artifacts.js');
  const roots = [join(tmpdir(), 'allowed')];
  assert.equal(pathOutsideScope({ path: join(tmpdir(), 'allowed', 'a.exe') }, roots), null);
  assert.equal(pathOutsideScope({ path: join(tmpdir(), 'elsewhere', 'a.exe') }, roots).key, 'path');
  assert.equal(pathOutsideScope({ path: 'C:/Windows/system32/cmd.exe' }, roots).key, 'path');
  assert.equal(pathOutsideScope({ path: '/anything' }, []), null);
  assert.equal(pathOutsideScope({}, roots), null);
});

test('sensitive mode never writes the full result to disk', async () => {
  await withStore({ maxChars: 20, headChars: 10, sensitive: true }, async (store, root) => {
    const replacement = await store.maybeSpill('binary_session', 'S'.repeat(500));
    assert.match(replacement, /NOT written to disk/);
    assert.match(replacement, /cannot be paged/);
  });
});

test('sensitive mode writes no artifact file at all', async () => {
  const { readdir } = await import('node:fs/promises');
  await withStore({ maxChars: 20, headChars: 10, sensitive: true }, async (store, root) => {
    await store.maybeSpill('binary_session', 'S'.repeat(500));
    assert.deepEqual(await readdir(root), []);
  });
});

test('purge removes only expired plugin session directories', async () => {
  const { mkdtemp: mkd, mkdir: mk, writeFile: wf, utimes, readdir: rd, rm: rmAll } = await import('node:fs/promises');
  const base = await mkd(join(tmpdir(), 'dsh-rea-purge-'));
  try {
    const current = join(base, '2026-11-03T00-00-00-000Z-1000');
    const old = join(base, '2026-10-01T00-00-00-000Z-1001');
    const stray = join(base, 'keep-me');
    for (const dir of [current, old, stray]) {
      await mk(dir, { recursive: true });
      await wf(join(dir, 'out.txt'), 'x'.repeat(100));
    }
    const past = new Date('2026-10-01T00:00:00Z').getTime();
    await utimes(old, new Date(past), new Date(past));
    const store = createArtifactStore({ root: current, base, retentionDays: 7 });
    const result = await store.purge({ now: new Date('2026-11-03T00:00:00Z').getTime() });
    assert.equal(result.removedDirs, 1);
    assert.ok(result.freedBytes >= 100);
    const remaining = await rd(base);
    assert.ok(remaining.includes('keep-me'), 'a non-plugin directory is never touched');
    assert.ok(remaining.includes('2026-11-03T00-00-00-000Z-1000'), 'the current session is kept');
  } finally {
    await rmAll(base, { recursive: true, force: true });
  }
});

test('write() stores a named report inside the session directory', async () => {
  await withStore({}, async (store, root) => {
    const path = await store.write('report.md', '# report');
    assert.ok(path.startsWith(root));
    assert.equal(await readFile(path, 'utf8'), '# report');
  });
});
