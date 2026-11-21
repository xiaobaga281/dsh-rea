/**
 * Developer-invisibility regression: the plugin's own outbound channels and
 * the localized-mode gate.
 *
 * Every request is verified against INTERCEPTED built-ins - `node:http`,
 * `node:https` and `node:tls` are patched with t.mock.method, so the suite
 * never opens a real socket. The patches go on the built-in module objects,
 * not on lib/download.js's ESM exports: ESM bindings are live views that
 * cannot be swapped, while the functions download.js looks up
 * (`http.get`, `https.request`, `tls.connect`) are mutable properties of the
 * built-in exports objects.
 *
 * The fixture objects implement exactly the surface download.js touches
 * (request side: setTimeout / on / once / end / destroy; response side:
 * statusCode / headers / resume / setEncoding / setTimeout / on / pipe) and
 * nothing more - a real socket is never constructed.
 *
 * Declared blind spot (do not remove): the REA child process and the Ghidra
 * JVM are separate OS processes; a socket mock in THIS process cannot see
 * their traffic, so these tests assert the plugin's own four declared download
 * channels only. The plugin-owned analysis tools are covered by the
 * zero-calls test below because they run in this process.
 */
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir, homedir, hostname, userInfo } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

import { buildExportReportTool, buildTriageTool } from '../lib/surface/analysis-tools.js';
import { createArtifactStore } from '../lib/infra/artifacts.js';
import { downloadFile, fetchText, stripProxyUserInfo } from '../lib/infra/download.js';
import { ENGINE_ENV_OVERRIDES, GHIDRA_RELEASE, detectGhidra, installExternalTool, installGhidra } from '../lib/infra/engines.js';
import { PLUGIN_ROOT } from '../lib/infra/paths.js';
import { describePolicy, normalizePolicyPatch, POLICY_DEFAULTS, POLICY_KEYS } from '../lib/infra/policy-store.js';
import { resolveConfig } from '../lib/infra/config.js';
import { checkForUpdate, installUpdate } from '../lib/infra/update.js';

/* ── interception layer ─────────────────────────────────────────────────── */

/** Fake IncomingMessage with the exact surface download.js touches. */
function fakeResponse({ status = 200, headers = {}, body = '' } = {}) {
  const listeners = new Map();
  const attach = (map, event, handler) => {
    if (!map.has(event)) map.set(event, []);
    map.get(event).push(handler);
    return response;
  };
  const emit = (event, ...args) => {
    for (const handler of [...(listeners.get(event) ?? [])]) handler(...args);
  };
  const response = {
    statusCode: status,
    headers,
    resume() {},
    destroy() {},
    setEncoding() {},
    setTimeout() {},
    on(event, handler) { return attach(listeners, event, handler); },
    once(event, handler) { return attach(listeners, event, handler); },
    // Only what response.pipe(output) needs: hand chunks to dest, then end it.
    pipe(dest) {
      this.on('data', (chunk) => dest.write(chunk));
      this.on('end', () => dest.end());
      return dest;
    },
    // Scheduled by the mock AFTER the caller attached its listeners.
    __deliver() {
      setTimeout(() => {
        if (body.length > 0) emit('data', Buffer.from(body));
        emit('end');
      }, 0);
    },
  };
  return response;
}

/** Fake ClientRequest with the exact surface download.js touches. */
function fakeRequest() {
  const listeners = new Map();
  const attach = (event, handler) => {
    if (!listeners.has(event)) listeners.set(event, []);
    listeners.get(event).push(handler);
    return request;
  };
  const emit = (event, ...args) => {
    for (const handler of [...(listeners.get(event) ?? [])]) handler(...args);
  };
  const request = {
    setTimeout() { return request; },
    on: attach,
    once: attach,
    end() {},
    destroy() {},
    __emit: emit,
  };
  return request;
}

const later = (fn) => { setTimeout(fn, 0); };

/**
 * Patch every network primitive lib/download.js can reach, and neutralise the
 * proxy environment unless the test asks for one. Restores the environment in
 * the `finally`; the t.mock patches restore themselves when the test ends.
 */
function installMocks(t, { proxy = '', body = 'ok', status = 200 } = {}) {
  const calls = [];
  const proxyEnvNames = ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'];
  const savedEnv = Object.fromEntries(proxyEnvNames.map((name) => [name, process.env[name]]));
  for (const name of proxyEnvNames) delete process.env[name];
  if (proxy) process.env.HTTPS_PROXY = proxy;

  const direct = (proto) => (parsed, options, callback) => {
    calls.push({ kind: 'direct', proto, url: String(parsed.href ?? parsed), headers: { ...options.headers } });
    const response = fakeResponse({ status, headers: { 'content-type': 'application/json', 'content-length': String(body.length) }, body });
    later(() => callback(response));
    later(() => response.__deliver());
    return fakeRequest();
  };
  t.mock.method(http, 'get', direct('http:'));
  t.mock.method(https, 'get', direct('https:'));
  t.mock.method(http, 'request', (options) => {
    const request = fakeRequest();
    if (options.method === 'CONNECT') {
      calls.push({ kind: 'connect', host: options.host, port: options.port, headers: { ...options.headers } });
      later(() => request.__emit('connect', { statusCode: 200, headers: {} }, { destroy() {}, on() {}, once() {} }));
      return request;
    }
    calls.push({ kind: 'inner-http', host: options.host, headers: { ...options.headers } });
    const response = fakeResponse({ status, headers: {}, body });
    later(() => request.__emit('response', response));
    later(() => response.__deliver());
    return request;
  });
  t.mock.method(https, 'request', (options) => {
    const request = fakeRequest();
    calls.push({ kind: 'inner', host: options.host, headers: { ...options.headers } });
    const response = fakeResponse({ status, headers: {}, body });
    later(() => request.__emit('response', response));
    later(() => response.__deliver());
    return request;
  });
  t.mock.method(tls, 'connect', (options, callback) => {
    calls.push({ kind: 'tls', servername: options.servername });
    const secure = { once() {}, destroy() {} };
    later(() => callback(secure));
    return secure;
  });

  return {
    calls,
    done() {
      for (const [name, value] of Object.entries(savedEnv)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    },
  };
}

/** The three identity strings this host would leak if a header were dynamic. */
const CANARIES = [hostname(), userInfo().username, homedir()];

function assertNoIdentity(headers) {
  const values = Object.values(headers).map((value) => String(value)).join('\n');
  for (const canary of CANARIES) {
    assert.ok(canary.length === 0 || !values.includes(canary), `a request header names this host (${canary}): ${values}`);
  }
  assert.ok(!('authorization' in headers), 'no authorization header may be sent');
  assert.ok(!('cookie' in headers), 'no cookie header may be sent');
}

/* ── 1. request headers carry no user identity ─────────────────────────── */

test('fetchText sends only user-agent "dsh-rea" and accept, with nothing that names this host', async (t) => {
  const mocks = installMocks(t);
  try {
    const text = await fetchText('https://update.example.test/manifest.json');
    assert.equal(text, 'ok');
    const direct = mocks.calls.filter((call) => call.kind === 'direct');
    assert.equal(direct.length, 1);
    const headers = direct[0].headers;
    // Literal equality: the UA is a compile-time constant, so a version, a
    // platform string or a hostname would fail this comparison.
    assert.equal(headers['user-agent'], 'dsh-rea');
    assert.deepEqual(Object.keys(headers).sort(), ['accept', 'user-agent']);
    assert.equal(headers.accept, 'application/json, text/plain, */*');
    assertNoIdentity(headers);
  } finally { mocks.done(); }
});

test('downloadFile sends the same minimal header set on the large-file path', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-localized-'));
  const mocks = installMocks(t, { body: 'ok' });
  try {
    const target = join(dir, 'artifact.zip');
    const result = await downloadFile('http://mirror.example.test/big.zip', target);
    assert.deepEqual(result, { bytes: 2, total: 2 });
    const direct = mocks.calls.filter((call) => call.kind === 'direct');
    assert.equal(direct.length, 1);
    const headers = direct[0].headers;
    assert.equal(headers['user-agent'], 'dsh-rea');
    assert.deepEqual(Object.keys(headers).sort(), ['accept', 'user-agent']);
    assert.equal(headers.accept, '*/*');
    assertNoIdentity(headers);
  } finally {
    mocks.done();
    await rm(dir, { recursive: true, force: true });
  }
});

/* ── 2. proxy credentials: CONNECT only, never error text ──────────────── */

test('proxy credentials ride the CONNECT hop to the configured proxy only', async (t) => {
  const mocks = installMocks(t, { proxy: 'http://canary-proxy-user:canary-proxy-pass@127.0.0.1:9' });
  try {
    const text = await fetchText('https://update.example.test/manifest.json');
    assert.equal(text, 'ok');
    const tunnels = mocks.calls.filter((call) => call.kind === 'connect');
    const inner = mocks.calls.filter((call) => call.kind === 'inner' || call.kind === 'inner-http');
    assert.equal(tunnels.length, 1);
    assert.equal(inner.length, 1);
    // Credentials go to the proxy the person configured - that is the point of
    // the CONNECT hop - and nowhere else.
    const authorization = tunnels[0].headers['proxy-authorization'];
    assert.match(String(authorization), /^Basic /);
    assert.equal(Buffer.from(String(authorization).slice(6), 'base64').toString(), 'canary-proxy-user:canary-proxy-pass');
    assert.equal(tunnels[0].headers.host, 'update.example.test:443');
    assertNoIdentity({ ...tunnels[0].headers });
    // The tunneled request itself must not carry the proxy credentials.
    assert.ok(!('proxy-authorization' in inner[0].headers));
    assert.equal(inner[0].headers['user-agent'], 'dsh-rea');
    assert.deepEqual(Object.keys(inner[0].headers).sort(), ['accept', 'user-agent']);
    assertNoIdentity(inner[0].headers);
  } finally { mocks.done(); }
});

test('an invalid proxy string never leaks its credentials into the error text', async (t) => {
  // The proxy URL is echoed into a failure message that reaches the panel and
  // the Host log; redact.js has no rule for userinfo, so the only guard is the
  // strip in lib/download.js. Before that fix this test failed.
  const mocks = installMocks(t, { proxy: 'http://canary-proxy-user:canary-proxy-pass@exa mple.invalid:9' });
  try {
    await assert.rejects(
      () => fetchText('https://update.example.test/manifest.json'),
      (error) => {
        assert.match(error.message, /invalid proxy URL/);
        assert.ok(!error.message.includes('canary-proxy-pass'), 'the proxy password must never reach error text');
        assert.ok(!error.message.includes('canary-proxy-user'), 'the proxy username must never reach error text');
        return true;
      },
    );
    assert.equal(mocks.calls.length, 0, 'a malformed proxy must fail before any connection');
  } finally { mocks.done(); }
});

test('stripProxyUserInfo drops userinfo and keeps everything else', () => {
  assert.equal(stripProxyUserInfo('http://user:pass@host:8118'), 'http://host:8118');
  assert.equal(stripProxyUserInfo('user:pass@host'), 'host');
  assert.equal(stripProxyUserInfo('http://host:8080'), 'http://host:8080');
  assert.equal(stripProxyUserInfo('http://user@host'), 'http://host');
});

/* ── 3. localizedMode: the plugin's own downloads are refused locally ──── */

test('localizedMode refuses the update check and install without a single connection', async (t) => {
  const mocks = installMocks(t, { body: JSON.stringify({ tag_name: 'v1.11.0', body: '', assets: [] }) });
  try {
    // Twice on purpose: the gate sits before the shared-promise cache, so the
    // refusal must never be cached and the second call must refuse too.
    const first = await checkForUpdate(null, { current: '1.10.0', localizedMode: true });
    assert.equal(first.phase, 'error');
    assert.match(first.error, /localizedMode/i);
    const second = await checkForUpdate(null, { current: '1.10.0', localizedMode: true });
    assert.equal(second.phase, 'error');
    const installState = await installUpdate(null, { localizedMode: true });
    assert.equal(installState.phase, 'error');
    assert.match(installState.error, /localizedMode/i);
    assert.equal(mocks.calls.length, 0, 'localized mode must not touch the network');
    // The refusals must not poison the shared state: a real check afterwards
    // still performs its request (and is not short-circuited by a cached
    // error).
    const real = await checkForUpdate(null, { current: '1.10.0' });
    assert.equal(real.phase, 'idle');
    assert.equal(real.hasUpdate, true);
    assert.equal(mocks.calls.length, 1);
    const headers = mocks.calls[0].headers;
    assert.equal(headers['user-agent'], 'dsh-rea');
    assertNoIdentity(headers);
  } finally { mocks.done(); }
});

test('localizedMode refuses a new engine download with offline guidance', async (t) => {
  const mocks = installMocks(t);
  try {
    await assert.rejects(
      () => installExternalTool('jadx', null, { localizedMode: true }),
      (error) => {
        assert.match(error.message, /localizedMode/);
        assert.match(error.message, /absolute path/i);
        return true;
      },
    );
    assert.equal(mocks.calls.length, 0);
  } finally { mocks.done(); }
});

test('localizedMode refuses the Ghidra download when nothing is cached', async (t) => {
  // The gate fires only when a download would be needed; a host with an
  // installed Ghidra or a verified cached archive keeps using it. This repo's
  // dev box keeps a real Ghidra under .tools and ENGINE_ENV_OVERRIDES points
  // at it, so the installed-root input is temporarily withheld: the test
  // points GHIDRA_INSTALL_DIR at an empty directory and removes the saved
  // override, leaving no cached path that could satisfy the install.
  const savedOverride = ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR;
  const savedEnv = process.env.GHIDRA_INSTALL_DIR;
  const emptyDir = await mkdtemp(join(tmpdir(), 'dsh-rea-no-ghidra-'));
  delete ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR;
  process.env.GHIDRA_INSTALL_DIR = emptyDir;
  // Mirror of lib/paths.js: GHIDRA_ARCHIVE = ENGINE_ROOT/ghidra-<version>.zip,
  // ENGINE_ROOT = join(DSH_HOME, 'rea-engines').
  const cachedArchive = join(homedir(), '.dsh', 'rea-engines', `ghidra-${GHIDRA_RELEASE.version}.zip`);
  const mocks = installMocks(t);
  try {
    const detected = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
    if (detected.available || existsSync(cachedArchive)) {
      return t.skip('no host configuration made Ghidra unresolvable; the refusal branch needs a host without an installed/cached Ghidra');
    }
    await assert.rejects(
      () => installGhidra(null, { localizedMode: true }),
      (error) => {
        assert.match(error.message, /localizedMode/);
        assert.match(error.message, /GHIDRA_INSTALL_DIR|archive/i);
        return true;
      },
    );
    assert.equal(mocks.calls.length, 0);
  } finally {
    mocks.done();
    if (savedOverride === undefined) delete ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR;
    else ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR = savedOverride;
    if (savedEnv === undefined) delete process.env.GHIDRA_INSTALL_DIR;
    else process.env.GHIDRA_INSTALL_DIR = savedEnv;
    await rm(emptyDir, { recursive: true, force: true });
  }
});

/* ── 4. analysis operations are local: zero outbound calls ─────────────── */

test('own analysis tools complete without any network call', async (t) => {
  const mocks = installMocks(t);
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-localized-analysis-'));
  try {
    // A real file from the repository fixtures: rea_triage reads bytes only.
    const fixture = join(PLUGIN_ROOT, 'test', 'fixtures', 'sqlite3-restored.c');
    assert.equal(existsSync(fixture), true, 'the fixture used for the zero-outbound run must exist');
    const { report } = await buildTriageTool({}).execute({ path: fixture });
    assert.match(report, /REA static triage/);

    const store = createArtifactStore({ root: dir });
    const exporter = buildExportReportTool({ client: null, store, toolVersion: 'test' });
    const exported = await exporter.execute({
      bundle: {
        target: '/samples/a.exe',
        evidence: [{ id: 'E1', observation: 'decodes a blob', limitation: 'static only', kind: 'decompiler-inference' }],
        unknowns: [{ id: 'U1', question: 'Is it C2?', severity: 'high', required_authority_level: 'dynamic-trace' }],
      },
    });
    assert.match(exported.text, /Evidence bundle exported/);
    assert.equal(mocks.calls.length, 0, 'own analysis tools must not open a connection');
  } finally {
    mocks.done();
    await rm(dir, { recursive: true, force: true });
  }
});

/* ── 5. the policy surface carries localizedMode ───────────────────────── */

test('localizedMode is the tenth panel-editable policy key with the same fail-closed validation', () => {
  assert.equal(POLICY_KEYS.length, 10);
  assert.ok(POLICY_KEYS.includes('localizedMode'));
  assert.equal(POLICY_DEFAULTS.localizedMode, false);
  assert.equal(normalizePolicyPatch({ localizedMode: true }).patch.localizedMode, true);
  assert.equal(normalizePolicyPatch({ localizedMode: false }).patch.localizedMode, false);
  assert.throws(() => normalizePolicyPatch({ localizedMode: 'on' }), /localizedMode must be true or false/);
  assert.throws(() => normalizePolicyPatch({ localizedmode: true }), /unknown policy field: localizedmode/);
});

test('localizedMode flows through resolveConfig with panel-beats-row precedence', () => {
  assert.equal(resolveConfig({}, null).localizedMode, false);
  assert.equal(resolveConfig({ localizedMode: true }, null).localizedMode, true);
  // The panel override wins over the config row, like every other policy key.
  assert.equal(resolveConfig({ localizedMode: true }, { localizedMode: false }).localizedMode, false);
  assert.equal(resolveConfig({ localizedMode: false }, { localizedMode: true }).localizedMode, true);
  const described = describePolicy(resolveConfig({ localizedMode: true }, null));
  assert.equal(described.localizedMode, true);
});
