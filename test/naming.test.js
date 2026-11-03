import assert from 'node:assert/strict';
import test from 'node:test';

import { MAX_PUBLIC_NAME_LENGTH, publicToolName } from '../lib/tools.js';

test('prefixes a plain REA tool name', () => {
  assert.equal(publicToolName('binary_session'), 'mcp__rea__binary_session');
});

test('replaces characters the function-name contract forbids and hashes the result', () => {
  const name = publicToolName('apk.inspect/target');
  assert.match(name, /^mcp__rea__apk_inspect_target_[0-9a-f]{12}$/);
  assert.ok(name.length <= MAX_PUBLIC_NAME_LENGTH);
});

test('leaves a name of exactly the maximum length alone', () => {
  const raw = 'x'.repeat(MAX_PUBLIC_NAME_LENGTH - 'mcp__rea__'.length);
  const name = publicToolName(raw);
  assert.equal(name.length, MAX_PUBLIC_NAME_LENGTH);
  assert.equal(name, `mcp__rea__${raw}`);
});

test('hashes a name that would exceed the maximum, and stays within it', () => {
  const name = publicToolName('y'.repeat(80));
  assert.ok(name.length <= MAX_PUBLIC_NAME_LENGTH, `${name} is ${name.length} characters`);
  assert.match(name, /_[0-9a-f]{12}$/);
});

test('is deterministic and distinguishes names that differ only at the end', () => {
  const long = 'z'.repeat(70);
  assert.equal(publicToolName(`${long}a`), publicToolName(`${long}a`));
  assert.notEqual(publicToolName(`${long}a`), publicToolName(`${long}b`));
});

test('two raw names never collapse onto one public name', () => {
  const raws = ['a.b', 'a_b', 'a/b', 'a b', 'apk.inspect', 'apk_inspect'];
  const names = new Set(raws.map((raw) => publicToolName(raw)));
  assert.equal(names.size, raws.length);
});
