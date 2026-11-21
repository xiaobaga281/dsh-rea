/**
 * Smoke-layer purity gate (W1 test layering, 2026-11-20).
 *
 * `npm run test:smoke` is the pure-JS fast-feedback layer: the test files it
 * lists must never compile a fixture (gcc), never touch Frida / dynamic
 * readiness, never spawn a child process, and never open a real socket.
 * This test reads the smoke manifest out of package.json and re-checks every
 * listed file's source against that contract, so a future test that needs
 * gcc/Frida/subprocesses/sockets cannot silently drift into the smoke layer,
 * and the manifest cannot silently drop files either. localized-mode.test.js
 * is the one whitelisted exception: its node:http/https/tls imports are
 * t.mock.method stubs (asserted below), not real network objects.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..');

// The reviewed smoke layer (43 files). The 12 live/heavy files stay out on
// purpose (gcc fixtures, Frida helpers, subprocess-driven gates): baseline,
// build-compare, dynamic, install, memdump, observe, recon, restore, sandbox,
// semantic-hypothesis, trace, unpack.
const SMOKE_FILES = [
  'analysis-tools', 'android', 'artifacts', 'autodraft', 'behavior',
  'capability-hardening', 'cil', 'config', 'detection-surface', 'duel-score',
  'engine-health', 'export', 'framer', 'fs-browse', 'gcc-install',
  'hardening-150', 'import-sources', 'installer', 'intel', 'interaction',
  'ladder-160', 'localized-mode', 'naming', 'panel', 'policy',
  'precision-hardening', 'probe', 'red-team-regressions', 'redact',
  'registry', 'result-index', 'routes', 'salted-hash', 'schema-cache',
  'senior-identity', 'strings', 'structure-audit', 'structure', 'tools',
  'triage', 'update', 'work-root', 'workflow',
];

const HEAVY_FILES = [
  'baseline', 'build-compare', 'dynamic', 'install', 'memdump', 'observe',
  'recon', 'restore', 'sandbox', 'semantic-hypothesis', 'trace', 'unpack',
];

const FORBIDDEN_PATTERNS = [
  { pattern: /from\s+'node:child_process'|require\(['"]child_process['"]\)/, why: 'spawns subprocesses' },
  { pattern: /from\s+'node:net'/, why: 'opens raw sockets' },
  { pattern: /\b(compileC|buildReadiness|dynamicReadiness|ghidraLocalReadiness|unpackReadiness)\b/, why: 'needs gcc or Frida readiness' },
  { pattern: /\.listen\(/, why: 'listens on a real socket' },
];

test('the test:smoke manifest lists exactly the reviewed pure-JS layer', async () => {
  const pkg = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'));
  const listed = (pkg.scripts['test:smoke'] ?? '')
    .split(/\s+/)
    .filter((part) => part.startsWith('test/'))
    .map((part) => part.replace(/^test\//, '').replace(/\.test\.js$/, ''));
  assert.deepEqual(listed.sort(), [...SMOKE_FILES].sort(),
    'package.json test:smoke and the reviewed smoke list must stay in sync');
  for (const heavy of HEAVY_FILES) {
    assert.ok(!listed.includes(heavy), `live/heavy test ${heavy} must not join the smoke layer`);
  }
  assert.equal(pkg.scripts.test, 'node --test --test-concurrency=2', 'the full-suite script must stay untouched');
});

test('every smoke file stays pure JS: no gcc, no Frida, no subprocess, no real socket', async () => {
  for (const name of SMOKE_FILES) {
    const source = await readFile(join(ROOT, 'test', `${name}.test.js`), 'utf8');
    for (const { pattern, why } of FORBIDDEN_PATTERNS) {
      assert.ok(!pattern.test(source), `${name}.test.js is not smoke-pure: it ${why}`);
    }
    if (/from\s+'node:(http|https|tls)'/.test(source)) {
      assert.equal(name, 'localized-mode', `only localized-mode may import http/https/tls (mocked), not ${name}`);
      assert.match(source, /t\.mock\./, 'localized-mode must stub http/https/tls with t.mock, not use them for real');
    }
  }
});
