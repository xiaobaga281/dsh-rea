import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { UPDATE_STATE, installUpdate } from '../lib/update.js';

const writePackage = async (dir, version, marker) => {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'dsh-rea', version }, null, 2));
  await writeFile(join(dir, 'index.js'), `export const marker = ${JSON.stringify(marker)};\n`);
};

/** Build a package tarball shaped like `npm pack` output (a `package/` root). */
const packInto = (workdir, stageName, name) => {
  // Relative paths plus cwd: GNU tar reads the colon in "C:\..." as a remote host.
  execFileSync('tar', ['-czf', name, '-C', stageName, 'package'], { cwd: workdir });
  return join(workdir, name);
};

/** One local mirror only: the built-in list would try the public proxies. */
const LOCAL_MIRROR = [{ id: 'local', label: 'local', prefix: '' }];

async function serveFile(path) {
  const body = await readFile(path);
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/gzip', 'content-length': body.length });
    response.end(body);
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}/asset.tgz`, close: () => new Promise((done) => server.close(done)) };
}

test('installs a newer package over the current tree and keeps a backup', async () => {
  const workdir = await mkdtemp(join(tmpdir(), 'dsh-rea-install-'));
  let close;
  try {
    const target = join(workdir, 'plugin');
    await writePackage(target, '1.0.0', 'old');

    await writePackage(join(workdir, 'stage', 'package'), '2.0.0', 'new');
    const archive = packInto(workdir, 'stage', 'dsh-rea-2.0.0.tgz');
    const digest = createHash('sha256').update(await readFile(archive)).digest('hex');
    const server = await serveFile(archive);
    close = server.close;

    UPDATE_STATE.current = '1.0.0';
    UPDATE_STATE.latest = '2.0.0';
    UPDATE_STATE.asset = { name: 'dsh-rea-2.0.0.tgz', size: 0, url: server.url, sha256: digest };
    UPDATE_STATE.mirrors = LOCAL_MIRROR;

    const state = await installUpdate(null, { target });
    assert.equal(state.phase, 'restart-required', state.error ?? '');
    assert.equal(state.restartRequired, true);

    const manifest = JSON.parse(await readFile(join(target, 'package.json'), 'utf8'));
    assert.equal(manifest.version, '2.0.0');
    assert.match(await readFile(join(target, 'index.js'), 'utf8'), /"new"/);

    const backups = (await readdir(workdir)).filter((name) => name.startsWith('plugin.bak-'));
    assert.equal(backups.length, 1);
    const previous = JSON.parse(await readFile(join(workdir, backups[0], 'package.json'), 'utf8'));
    assert.equal(previous.version, '1.0.0');
  } finally {
    if (close) await close();
    await rm(workdir, { recursive: true, force: true });
  }
});

test('a checksum mismatch leaves the installed version untouched', async () => {
  const workdir = await mkdtemp(join(tmpdir(), 'dsh-rea-bad-'));
  let close;
  try {
    const target = join(workdir, 'plugin');
    await writePackage(target, '1.0.0', 'old');
    await writePackage(join(workdir, 'stage', 'package'), '2.0.0', 'new');
    const archive = packInto(workdir, 'stage', 'dsh-rea-2.0.0.tgz');
    const server = await serveFile(archive);
    close = server.close;

    UPDATE_STATE.current = '1.0.0';
    UPDATE_STATE.latest = '2.0.0';
    UPDATE_STATE.asset = { name: 'dsh-rea-2.0.0.tgz', size: 0, url: server.url, sha256: 'f'.repeat(64) };
    UPDATE_STATE.mirrors = LOCAL_MIRROR;

    const state = await installUpdate(null, { target });
    assert.equal(state.phase, 'error');
    assert.match(state.error, /checksum mismatch|every update mirror failed/);
    const manifest = JSON.parse(await readFile(join(target, 'package.json'), 'utf8'));
    assert.equal(manifest.version, '1.0.0');
    assert.equal(existsSync(join(workdir, 'plugin.bak-1')), false);
  } finally {
    if (close) await close();
    await rm(workdir, { recursive: true, force: true });
  }
});

test('an archive whose version does not match the feed is refused', async () => {
  const workdir = await mkdtemp(join(tmpdir(), 'dsh-rea-mismatch-'));
  let close;
  try {
    const target = join(workdir, 'plugin');
    await writePackage(target, '1.0.0', 'old');
    await writePackage(join(workdir, 'stage', 'package'), '1.5.0', 'new');
    const archive = packInto(workdir, 'stage', 'dsh-rea-2.0.0.tgz');
    const digest = createHash('sha256').update(await readFile(archive)).digest('hex');
    const server = await serveFile(archive);
    close = server.close;

    UPDATE_STATE.current = '1.0.0';
    UPDATE_STATE.latest = '2.0.0';
    UPDATE_STATE.asset = { name: 'dsh-rea-2.0.0.tgz', size: 0, url: server.url, sha256: digest };
    UPDATE_STATE.mirrors = LOCAL_MIRROR;

    const state = await installUpdate(null, { target });
    assert.equal(state.phase, 'error');
    assert.match(state.error, /contains 1\.5\.0/);
    const manifest = JSON.parse(await readFile(join(target, 'package.json'), 'utf8'));
    assert.equal(manifest.version, '1.0.0');
  } finally {
    if (close) await close();
    await rm(workdir, { recursive: true, force: true });
  }
});

test('an install without a published digest is refused outright', async () => {
  const workdir = await mkdtemp(join(tmpdir(), 'dsh-rea-nodigest-'));
  try {
    const target = join(workdir, 'plugin');
    await writePackage(target, '1.0.0', 'old');
    UPDATE_STATE.current = '1.0.0';
    UPDATE_STATE.latest = '2.0.0';
    UPDATE_STATE.asset = { name: 'dsh-rea-2.0.0.tgz', size: 0, url: 'http://127.0.0.1:9/never.tgz', sha256: null };
    const state = await installUpdate(null, { target });
    assert.equal(state.phase, 'error');
    assert.match(state.error, /no SHA-256/);
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
});
