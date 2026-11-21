import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { unpackReadiness } from '../lib/dynamic/unpack.js';
import { buildUnpackTool } from '../lib/surface/unpack-tools.js';

test('unpack readiness reports a path or a precise reason', () => {
  const readiness = unpackReadiness();
  assert.equal(typeof readiness.ready, 'boolean');
  if (readiness.ready) assert.ok(readiness.path);
  else assert.match(readiness.reason, /UPX not found/);
});

test('the unpack tool validates paths and refuses to clobber without force', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-unpack-'));
  try {
    const source = join(dir, 'sample.exe');
    const output = join(dir, 'out.exe');
    await writeFile(source, 'not packed');
    await writeFile(output, 'existing');
    const tool = buildUnpackTool({});
    assert.match((await tool.execute({ source: 'relative.exe', output })).text, /source must be an absolute path/);
    assert.match((await tool.execute({ source: join(dir, 'missing.exe'), output })).text, /source does not exist/);
    assert.match((await tool.execute({ source, output })).text, /output already exists/);
    assert.ok(existsSync(output));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});