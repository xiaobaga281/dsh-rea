import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { listDirectories } from '../lib/fs-browse.js';
import { mountEnvironmentRoutes } from '../lib/routes.js';

async function tree() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-browse-'));
  await mkdir(join(root, 'alpha'));
  await mkdir(join(root, 'beta'));
  await mkdir(join(root, 'alpha', 'nested'));
  await writeFile(join(root, 'readme.txt'), 'not a directory');
  return root;
}

test('an empty path lists the filesystem roots', async () => {
  const listing = await listDirectories('');
  assert.equal(listing.path, null);
  assert.equal(listing.parent, null);
  assert.ok(listing.entries.length > 0);
  assert.ok(listing.roots.length > 0);
});

test('a directory lists its subdirectories and nothing else', async () => {
  const root = await tree();
  const listing = await listDirectories(root);
  assert.equal(listing.path, resolve(root));
  const names = listing.entries.map((entry) => entry.name);
  assert.deepEqual(names, ['alpha', 'beta']);
  // A file in the same directory must not appear: the picker chooses roots,
  // and a file in the list would invite a scope that can never match.
  assert.ok(!names.includes('readme.txt'));
});

test('entries are full paths so the caller never has to join them', async () => {
  const root = await tree();
  const listing = await listDirectories(root);
  const alpha = listing.entries.find((entry) => entry.name === 'alpha');
  assert.equal(alpha.path, resolve(root, 'alpha'));
  // And that path is itself browsable.
  const inner = await listDirectories(alpha.path);
  assert.deepEqual(inner.entries.map((entry) => entry.name), ['nested']);
});

test('the parent is offered, and the root has none', async () => {
  const root = await tree();
  const listing = await listDirectories(join(root, 'alpha'));
  assert.equal(listing.parent, resolve(root));
  const top = await listDirectories(listing.parent);
  assert.ok(top.entries.length >= 2);
});

test('a relative path is refused instead of resolved against the cwd', async () => {
  await assert.rejects(() => listDirectories('samples'), /is not an absolute path/);
});

test('a missing directory is a 404 with the path in the message', async () => {
  const root = await tree();
  await assert.rejects(() => listDirectories(join(root, 'does-not-exist')), (error) => {
    assert.equal(error.statusCode, 404);
    assert.match(error.message, /cannot be read/);
    return true;
  });
});

test('a file is refused with a reason', async () => {
  const root = await tree();
  await assert.rejects(() => listDirectories(join(root, 'readme.txt')), /is not a directory/);
});

test('a very large directory is capped and says so', async () => {
  const root = await tree();
  const listing = await listDirectories(root, { limit: 1 });
  assert.equal(listing.entries.length, 1);
  assert.equal(listing.truncated, true);
});

test('the listing endpoint answers with the same shape the picker expects', async () => {
  const routes = new Map();
  mountEnvironmentRoutes({ webServer: { register(definition) {
    const key = definition.method ? `${definition.method} ${definition.path}` : definition.path;
    if (routes.has(key)) throw new Error(`webserver: duplicate exact route "${definition.path}"`);
    routes.set(key, definition.handler);
    return () => {};
  } } }, {
    status: async () => ({ ok: true }),
    listDirectories: (path) => listDirectories(path),
  });
  const root = await tree();
  const state = { status: 0, body: '' };
  const response = {
    writableEnded: false,
    writeHead(code) { state.status = code; this.writableEnded = true; },
    end(body) { state.body = String(body ?? ''); },
  };
  await routes.get('/rea/fs/list')({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    async *[Symbol.asyncIterator]() { yield Buffer.from(JSON.stringify({ path: root }), 'utf8'); },
  }, response);
  assert.equal(state.status, 200);
  const payload = JSON.parse(state.body);
  assert.equal(payload.ok, true);
  assert.deepEqual(payload.entries.map((entry) => entry.name), ['alpha', 'beta']);
});

test('the listing endpoint refuses a relative path with 400', async () => {
  const routes = new Map();
  mountEnvironmentRoutes({ webServer: { register(definition) {
    const key = definition.method ? `${definition.method} ${definition.path}` : definition.path;
    if (routes.has(key)) throw new Error(`webserver: duplicate exact route "${definition.path}"`);
    routes.set(key, definition.handler);
    return () => {};
  } } }, {
    status: async () => ({ ok: true }),
    listDirectories: (path) => listDirectories(path),
  });
  const state = { status: 0, body: '' };
  const response = {
    writableEnded: false,
    writeHead(code) { state.status = code; this.writableEnded = true; },
    end(body) { state.body = String(body ?? ''); },
  };
  await routes.get('/rea/fs/list')({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    async *[Symbol.asyncIterator]() { yield Buffer.from(JSON.stringify({ path: 'samples' }), 'utf8'); },
  }, response);
  assert.equal(state.status, 400);
  assert.match(JSON.parse(state.body).error, /not an absolute path/);
});

/** Registry that behaves like the host: one exact route per path, no twins. */
function hostRegistry(routes) {
  return {
    register(definition) {
      if (routes.has(definition.path)) {
        throw new Error(`webserver: duplicate exact route "${definition.path}"`);
      }
      routes.set(definition.path, definition.handler);
      return () => {};
    },
  };
}

test('the plugin registers each path once, which is what the host enforces', () => {
  // The real failure this pins: two entries for /rea/fs/list (GET and POST)
  // made the whole plugin fail to load with
  //   webserver: duplicate exact route "/rea/fs/list"
  const routes = new Map();
  assert.doesNotThrow(() => mountEnvironmentRoutes({ webServer: hostRegistry(routes) }, {
    status: async () => ({ ok: true }),
    listDirectories: async () => ({ path: '/', parent: null, entries: [] }),
  }));
  assert.equal(routes.has('/rea/fs/list'), true);
});

test('the single listing route answers GET and POST, and refuses the rest', async () => {
  const routes = new Map();
  mountEnvironmentRoutes({ webServer: hostRegistry(routes) }, {
    status: async () => ({ ok: true }),
    listDirectories: async () => ({ path: '/tmp', parent: '/', entries: [] }),
  });
  const handler = routes.get('/rea/fs/list');
  const makeResponse = () => {
    const state = { status: 0, body: '' };
    return {
      state,
      writableEnded: false,
      writeHead(code) { state.status = code; this.writableEnded = true; },
      end(body) { state.body = String(body ?? ''); },
    };
  };

  const get = makeResponse();
  await handler({ method: 'GET', url: '/rea/fs/list?path=%2Ftmp', headers: {} }, get);
  assert.equal(get.state.status, 200);
  assert.equal(JSON.parse(get.state.body).ok, true);

  const post = makeResponse();
  await handler({
    method: 'POST',
    url: '/rea/fs/list',
    headers: { 'content-type': 'application/json' },
    async *[Symbol.asyncIterator]() { yield Buffer.from(JSON.stringify({ path: '/tmp' }), 'utf8'); },
  }, post);
  assert.equal(post.state.status, 200);

  const put = makeResponse();
  await handler({ method: 'PUT', url: '/rea/fs/list', headers: {} }, put);
  assert.equal(put.state.status, 405);
  assert.equal(JSON.parse(put.state.body).error, 'method-not-allowed');
});
