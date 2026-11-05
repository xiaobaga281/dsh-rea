import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { explainWorkRoot, rejectReason, resolveWorkRoot, resetWorkRoot } from '../lib/work-root.js';

test('a path with a dot-prefixed element is refused, because Ghidra refuses it', () => {
  // This is not a style rule. Ghidra aborts the whole launch with
  // "Path element starting with '.' is not permitted", so a project directory
  // under ~/.dsh cannot be used no matter how writable it is.
  assert.match(rejectReason('C:/Users/x/.dsh/rea-engines/ghidra-projects'), /starts with "\."/);
  assert.equal(rejectReason('C:/Users/x/dsh-rea/ghidra-projects'), null);
  // A dot inside a name is fine; only a leading dot is not.
  assert.equal(rejectReason('C:/Users/x/dsh.rea/work'), null);
});

test('a path with a space is refused, because _JAVA_OPTIONS is split on whitespace', () => {
  assert.match(rejectReason('C:/Program Files/dsh/ghidra-work'), /space/);
});

test('the chosen root satisfies both rules and exists after resolution', () => {
  resetWorkRoot();
  const root = resolveWorkRoot();
  assert.ok(root, 'this host has at least one usable directory');
  assert.equal(rejectReason(root), null);
  for (const name of ['projects', 'scripts', 'tmp', 'cache', 'settings']) {
    assert.ok(existsSync(join(root, name)), `${name} should be created`);
  }
});

test('a rejected candidate says which rule it broke, not just "unusable"', () => {
  const explained = explainWorkRoot({ DSH_REA_GHIDRA_WORK: 'C:/Users/x/.hidden/work' });
  const first = explained[0];
  assert.equal(first.usable, false);
  assert.match(first.reason, /starts with "\."/);
  // The remaining candidates are still listed, so the reader can see that the
  // environment variable was tried and rejected rather than ignored.
  assert.ok(explained.length >= 2);
});

test('an explicit environment override wins when it is usable', () => {
  resetWorkRoot();
  const root = resolveWorkRoot();
  const explained = explainWorkRoot({ DSH_REA_GHIDRA_WORK: root });
  assert.equal(explained[0].path.toLowerCase(), root.toLowerCase());
  assert.equal(explained[0].usable, true);
});
