import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import { detectGccAt, gccSpec, unpackGcc } from '../lib/infra/engines.js';

function tarHeader(name, size) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write('0000644\0', 100, 8);
  header.write('0000000\0', 108, 8);
  header.write('0000000\0', 116, 8);
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12);
  header.write('00000000000\0', 136, 12);
  header.write('        ', 148, 8);
  header.write('0', 156, 1);
  header.write('ustar\0', 257, 6);
  header.write('00', 263, 2);
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8);
  return header;
}

function tarGz(files) {
  const parts = [];
  for (const [name, content] of Object.entries(files)) {
    const body = Buffer.from(content, 'utf8');
    parts.push(tarHeader(name, body.length), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

test('the WinLibs unpack path is verified without the 276 MB download', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-gcc-'));
  try {
    const archive = join(dir, 'winlibs-test.tgz');
    await writeFile(archive, tarGz({ 'mingw64/bin/gcc.exe': 'fake compiler for layout verification' }));
    const root = join(dir, 'gcc');
    const found = await unpackGcc(archive, root);
    assert.ok(found.endsWith(join('mingw64', 'bin', 'gcc.exe')));
    assert.ok(existsSync(found));
    assert.equal(detectGccAt(root).ready, true);
    assert.equal(detectGccAt(join(dir, 'empty')).ready, false);

    const bad = join(dir, 'bad.tgz');
    await writeFile(bad, 'not an archive');
    await assert.rejects(() => unpackGcc(bad, join(dir, 'bad-root')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the WinLibs pin is fixed and platform-gated', () => {
  const spec = gccSpec('win32', 'x64');
  assert.equal(spec.kind, 'gcc');
  assert.match(spec.release.url, /brechtsanders\/winlibs_mingw\/releases\/download/);
  assert.match(spec.release.sha256, /^[0-9a-f]{64}$/);
  assert.equal(gccSpec('linux', 'x64'), null);
  assert.equal(gccSpec('win32', 'arm64'), null);
});
