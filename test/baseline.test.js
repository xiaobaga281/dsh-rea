import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildBaseline, normalizeBody, parseSignature, synthesizeDraft } from '../lib/restore/baseline.js';
import { buildReadiness } from '../lib/restore/build.js';

test('normalizeBody maps the Ghidra type vocabulary and drops calling conventions', () => {
  const body = `int __cdecl main(void)

{
  undefined8 local_10;
  uchar local_58 [72];
  typeMismatch((ubsan_rt_TypeMismatchData *)&PTR_DAT_1400bd010,
               (ubsan_rt_ValueHandle__opaque_0 *)0x0);
  return 0;
}`;
  const normalized = normalizeBody(body);
  assert.doesNotMatch(normalized, /__cdecl/);
  assert.doesNotMatch(normalized, /undefined8/);
  assert.match(normalized, /unsigned long long local_10/);
  assert.match(normalized, /unsigned char local_58/);
  assert.doesNotMatch(normalized, /typeMismatch/);
  assert.match(normalized, /\(\(void\)0\)/);
});

test('parseSignature reads the return type, name and parameters', () => {
  const parsed = parseSignature('int __cdecl main(void)\n\n{\n  return 0;\n}');
  assert.equal(parsed.name, 'main');
  assert.equal(parsed.returnType, 'int');
  assert.equal(parsed.signature, 'int main(void);');
  assert.equal(parseSignature('not a function'), null);
});

test('synthesizeDraft omits runtime functions, stubs named ones and declares helpers', () => {
  const functions = [
    { name: 'main', body: 'int main(void) { fastMemset(buf,0,4); return helper(1); }' },
    { name: '__dyn_tls_init', body: 'int __dyn_tls_init(void) { return 0; }' },
    { name: 'helper', body: 'int helper(int x) { return x + 1; }' },
  ];
  const draft = synthesizeDraft(functions, { stubbed: new Set(['helper']) });
  assert.deepEqual(draft.translated, ['main']);
  assert.deepEqual(draft.omitted, ['__dyn_tls_init']);
  assert.ok(draft.stubbed.includes('helper'));
  assert.match(draft.source, /long fastMemset\(\);/);
  assert.match(draft.source, /long helper\(\) \{ return 0; \}/);
  assert.doesNotMatch(draft.source, /__dyn_tls_init\(void\) \{ return 0; \}/);
});

test('duplicate function names collapse to one definition', () => {
  const draft = synthesizeDraft([
    { name: 'dup', body: 'int dup(void) { return 1; }' },
    { name: 'dup', body: 'int dup(void) { return 2; }' },
  ]);
  assert.deepEqual(draft.translated, ['dup']);
  assert.ok(draft.omitted.includes('dup'));
  // One prototype plus one definition is correct; two definitions are not.
  assert.equal((draft.source.match(/int dup\(void\) \{/g) ?? []).length, 1);
});

test('buildBaseline stubs the function the compiler rejects and keeps the rest', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-baseline-'));
  try {
    const result = await buildBaseline({
      functions: [
        { name: 'good', body: 'int good(void) { return 7; }' },
        { name: 'broken', body: 'int broken(void) { this is not C; }' },
      ],
      workDir: dir,
      name: 'baseline-test',
      maxRounds: 6,
    });
    assert.equal(result.ok, true, result.reason);
    assert.deepEqual(result.translated, ['good']);
    assert.deepEqual(result.stubbed, ['broken']);
    assert.match(result.sourceText, /long broken\(\) \{ return 0; \}/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('stubPrefix renames stub definitions and prototypes so a floor carries no target names', () => {
  const functions = [
    { name: 'main', body: 'int main(void) { return helper(1); }' },
    { name: 'helper', body: 'int helper(int x) { return x + 1; }' },
    { name: 'target_fn', body: 'int target_fn(void) { return 2; }' },
  ];
  const draft = synthesizeDraft(functions, { stubbed: new Set(['helper', 'target_fn']), stubPrefix: 'dsh_stub_' });
  assert.match(draft.source, /long dsh_stub_helper\(\) \{ return 0; \}/);
  assert.match(draft.source, /long dsh_stub_target_fn\(\) \{ return 0; \}/);
  assert.doesNotMatch(draft.source, /long helper\(\) \{ return 0; \}/);
  assert.doesNotMatch(draft.source, /long target_fn\(\) \{ return 0; \}/);
  assert.match(draft.source, /long dsh_stub_helper\(\);/);
  // main was not stubbed, so its real body survives verbatim; there is no
  // renamed stub for it either.
  assert.match(draft.source, /int main\(void\) \{ return helper\(1\); \}/);
  assert.doesNotMatch(draft.source, /dsh_stub_main/);
  assert.equal((draft.source.match(/long dsh_stub_helper\(\);/g) ?? []).length, 1, 'no duplicate prototypes for renamed stubs');
  // Without the prefix the behaviour is unchanged (default path).
  const plain = synthesizeDraft(functions, { stubbed: new Set(['helper', 'target_fn']) });
  assert.match(plain.source, /long helper\(\) \{ return 0; \}/);
  assert.doesNotMatch(plain.source, /dsh_stub_/);
});
