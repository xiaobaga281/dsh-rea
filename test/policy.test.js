import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  applyPolicyPatch, describePolicy, normalizePolicyPatch, readPolicyOverrides, writePolicyOverrides,
} from '../lib/policy-store.js';
import { resolveConfig } from '../lib/config.js';
import { mountEnvironmentRoutes } from '../lib/routes.js';

const scratch = async () => mkdtemp(join(tmpdir(), 'dsh-policy-'));

test('the panel can turn device mutations on and off', () => {
  const { patch } = normalizePolicyPatch({ allowDeviceMutations: true });
  assert.deepEqual(patch, { allowDeviceMutations: true });
  const off = normalizePolicyPatch({ allowDeviceMutations: false });
  assert.deepEqual(off.patch, { allowDeviceMutations: false });
});

test('a non-boolean switch value is refused rather than coerced', () => {
  // "false" is a string that `Boolean()` would call true; refusing it is the
  // difference between a safety switch and a decoration.
  assert.throws(() => normalizePolicyPatch({ allowDeviceMutations: 'false' }), /must be true or false/);
  assert.throws(() => normalizePolicyPatch({ sensitiveArtifacts: 1 }), /must be true or false/);
});

test('a relative target root is refused with the offending entry', () => {
  assert.throws(() => normalizePolicyPatch({ allowedTargets: ['samples'] }), /"samples" is not an absolute path/);
});

test('target roots accept text and arrays, trim, drop blanks and dedupe', () => {
  const fromText = normalizePolicyPatch({ allowedTargets: '  C:\\samples \n\n D:\\lab \nC:\\samples\n' });
  assert.deepEqual(fromText.patch.allowedTargets, ['C:\\samples', 'D:\\lab']);
  const empty = normalizePolicyPatch({ allowedTargets: '   \n' });
  assert.deepEqual(empty.patch.allowedTargets, []);
});

test('retention is bounded and integral', () => {
  assert.equal(normalizePolicyPatch({ artifactRetentionDays: 30 }).patch.artifactRetentionDays, 30);
  assert.throws(() => normalizePolicyPatch({ artifactRetentionDays: 0 }), /between 1 and 365/);
  assert.throws(() => normalizePolicyPatch({ artifactRetentionDays: 400 }), /between 1 and 365/);
  assert.throws(() => normalizePolicyPatch({ artifactRetentionDays: 1.5 }), /whole number/);
});

test('an unknown egress policy is refused', () => {
  assert.throws(() => normalizePolicyPatch({ networkEgressPolicy: 'block' }), /must be one of allow, warn, deny/);
  assert.equal(normalizePolicyPatch({ networkEgressPolicy: 'deny' }).patch.networkEgressPolicy, 'deny');
});

test('an unknown field is refused instead of silently dropped', () => {
  // A typo in the panel that "saves successfully" is worse than an error: the
  // person believes a restriction is in place.
  assert.throws(() => normalizePolicyPatch({ allowDeviceMutation: true }), /unknown policy field: allowDeviceMutation/);
});

test('reset returns the defaults and cannot be mixed with other fields', () => {
  const { reset, patch } = normalizePolicyPatch({ reset: true });
  assert.equal(reset, true);
  assert.deepEqual(patch.allowedTargets, []);
  assert.equal(patch.allowDeviceMutations, false);
  assert.equal(patch.networkEgressPolicy, 'warn');
  assert.throws(() => normalizePolicyPatch({ reset: true, allowDeviceMutations: true }), /cannot be combined/);
});

test('a saved policy round-trips through the file', async () => {
  const dir = await scratch();
  const file = join(dir, 'policy.json');
  await writePolicyOverrides({ networkEgressPolicy: 'deny', artifactRetentionDays: 3 }, { file });
  const read = await readPolicyOverrides(file);
  assert.equal(read.error, null);
  assert.equal(read.values.networkEgressPolicy, 'deny');
  assert.equal(read.values.artifactRetentionDays, 3);
  assert.match(read.updatedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('a missing file is not an error', async () => {
  const dir = await scratch();
  const read = await readPolicyOverrides(join(dir, 'absent.json'));
  assert.deepEqual(read.values, {});
  assert.equal(read.error, null);
});

test('a corrupt file is reported and ignored, not fatal', async () => {
  const dir = await scratch();
  const file = join(dir, 'policy.json');
  await writeFile(file, '{ not json', 'utf8');
  const read = await readPolicyOverrides(file);
  assert.deepEqual(read.values, {});
  assert.match(read.error, /not valid JSON/);
});

test('a file whose values no longer validate falls back to the row', async () => {
  const dir = await scratch();
  const file = join(dir, 'policy.json');
  await writeFile(file, JSON.stringify({ values: { artifactRetentionDays: 9999 } }), 'utf8');
  const read = await readPolicyOverrides(file);
  assert.deepEqual(read.values, {});
  assert.match(read.error, /between 1 and 365/);
});

test('the write is atomic enough that no half file is left behind', async () => {
  const dir = await scratch();
  const file = join(dir, 'policy.json');
  await writePolicyOverrides({ sensitiveArtifacts: true }, { file });
  const text = await readFile(file, 'utf8');
  assert.doesNotThrow(() => JSON.parse(text));
  assert.match(text, /"schemaVersion": 1/);
});

test('the panel override beats the config row', () => {
  const row = { allowDeviceMutations: true, artifactRetentionDays: 30, networkEgressPolicy: 'allow' };
  const config = resolveConfig(row, { allowDeviceMutations: false, networkEgressPolicy: 'deny' });
  assert.equal(config.allowDeviceMutations, false);
  assert.equal(config.networkEgressPolicy, 'deny');
  // Not in the override: the row still decides.
  assert.equal(config.artifactRetentionDays, 30);
});

test('an override cannot reach fields outside the five', () => {
  // The override file is editable by hand; `enabled: false` there would take
  // the plugin down without the panel ever showing a switch for it.
  const config = resolveConfig({ enabled: true }, { enabled: false, toolCallTimeoutMs: 1, allowDeviceMutations: true });
  assert.equal(config.enabled, true);
  assert.notEqual(config.toolCallTimeoutMs, 1);
  assert.equal(config.allowDeviceMutations, true);
});

test('a patch applies in place so the guard sees it on the next call', () => {
  const config = resolveConfig({}, null);
  const identity = config;
  applyPolicyPatch(config, { networkEgressPolicy: 'deny', allowedTargets: ['C:\\lab'] });
  assert.equal(config, identity);
  assert.equal(identity.networkEgressPolicy, 'deny');
  assert.deepEqual(identity.allowedTargets, ['C:\\lab']);
  // The copy is defensive: mutating the patch must not reach into the config.
  assert.deepEqual(describePolicy(config).allowedTargets, ['C:\\lab']);
});

function fakeServer() {
  const routes = new Map();
  return {
    routes,
    webServer: {
      register(definition) {
        routes.set(`${definition.method} ${definition.path}`, definition.handler);
        return () => routes.delete(definition.path);
      },
    },
  };
}

function fakeResponse() {
  const state = { status: 0, body: '', ended: false };
  return {
    state,
    writableEnded: false,
    writeHead(status) { state.status = status; this.writableEnded = true; },
    end(body) { state.body = String(body ?? ''); this.writableEnded = true; state.ended = true; },
  };
}

function jsonRequest(body) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    async *[Symbol.asyncIterator]() { yield Buffer.from(JSON.stringify(body), 'utf8'); },
  };
}

test('POST /rea/policy applies the change and returns the new posture', async () => {
  const server = fakeServer();
  const applied = [];
  mountEnvironmentRoutes({ webServer: server.webServer }, {
    status: async () => ({ ok: true, policy: { values: structuredClone(applied.at(-1) ?? {}) } }),
    applyPolicy: async (body) => {
      const { patch } = normalizePolicyPatch(body);
      applied.push(patch);
      return { changed: true };
    },
  });
  const handler = server.routes.get('POST /rea/policy');
  assert.equal(typeof handler, 'function');
  const response = fakeResponse();
  await handler(jsonRequest({ networkEgressPolicy: 'deny', artifactRetentionDays: 14 }), response);
  assert.equal(response.state.status, 200);
  const payload = JSON.parse(response.state.body);
  assert.equal(payload.changed, true);
  assert.equal(payload.restarted, false);
  assert.deepEqual(applied, [{ networkEgressPolicy: 'deny', artifactRetentionDays: 14 }]);
});

test('POST /rea/policy reports a refused value with a 400 and a reason', async () => {
  const server = fakeServer();
  mountEnvironmentRoutes({ webServer: server.webServer }, {
    status: async () => ({ ok: true }),
    applyPolicy: async (body) => {
      normalizePolicyPatch(body);
      return { changed: true };
    },
  });
  const response = fakeResponse();
  await server.routes.get('POST /rea/policy')(jsonRequest({ allowedTargets: ['relative'] }), response);
  assert.equal(response.state.status, 400);
  assert.match(JSON.parse(response.state.body).error, /not an absolute path/);
});

test('a policy write never restarts the analysis child', async () => {
  // Restarting would kill a running decompile for a checkbox. The route must
  // say so explicitly, because the panel shows the flag.
  const server = fakeServer();
  let restarted = 0;
  const original = mountEnvironmentRoutes;
  original({ webServer: server.webServer }, {
    status: async () => ({ ok: true }),
    applyPolicy: async () => ({ changed: true }),
    restart: async () => { restarted += 1; return true; },
  });
  const response = fakeResponse();
  await server.routes.get('POST /rea/policy')(jsonRequest({ sensitiveArtifacts: true }), response);
  assert.equal(JSON.parse(response.state.body).restarted, false);
  assert.equal(restarted, 0);
});
