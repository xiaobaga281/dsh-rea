import assert from 'node:assert/strict';
import test from 'node:test';

import { DEFAULT_MIRRORS, compareVersions, digestFromNotes, resolveInstallTarget } from '../lib/update.js';

test('orders releases numerically, not lexically', () => {
  assert.equal(compareVersions('1.2.0', '1.1.0'), 1);
  assert.equal(compareVersions('1.10.0', '1.9.0'), 1);
  assert.equal(compareVersions('1.1.0', '1.2.0'), -1);
  assert.equal(compareVersions('2.0.0', '1.99.99'), 1);
});

test('treats a leading v and a missing patch as equal', () => {
  assert.equal(compareVersions('v1.2.0', '1.2.0'), 0);
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
});

test('a prerelease sorts below its release', () => {
  assert.equal(compareVersions('1.2.0-beta.1', '1.2.0'), -1);
  assert.equal(compareVersions('1.2.0', '1.2.0-beta.1'), 1);
});

test('reads the digest the release notes publish', () => {
  const digest = 'a'.repeat(64);
  assert.equal(digestFromNotes(`sha256: ${digest}`), digest);
  assert.equal(digestFromNotes(`SHA256: ${digest}`), digest);
  assert.equal(digestFromNotes('no digest here'), null);
  assert.equal(digestFromNotes(''), null);
});

test('falls back to the official mirror first and keeps several in reserve', () => {
  assert.equal(DEFAULT_MIRRORS[0].prefix, '');
  assert.ok(DEFAULT_MIRRORS.length >= 4);
  assert.ok(DEFAULT_MIRRORS.every((mirror) => typeof mirror.label === 'string' && mirror.label.length > 0));
});

test('a real install target is returned unchanged', () => {
  const target = resolveInstallTarget(process.cwd());
  assert.equal(target, process.cwd());
});

test('a missing target still resolves to something usable', () => {
  const missing = resolveInstallTarget('C:/definitely/not/here/dsh-rea');
  assert.equal(typeof missing, 'string');
  assert.ok(missing.length > 0);
});
