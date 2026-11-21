/**
 * Host-identity redaction: the machine name, the account name and the home
 * directory prefix must leave the render paths as placeholders, everything
 * else - including other people's paths inside a sample - survives verbatim.
 */
import assert from 'node:assert/strict';
import { hostname, homedir } from 'node:os';
import test from 'node:test';

import { createRedactor, redactSensitive, restoreSensitive, sharedRedactor } from '../lib/redact.js';
import { withRedactedOutput } from '../lib/tools.js';

// Hermetic identity: the assertions never depend on the real box. The
// hostname is spelled consistently because restore returns the canonical
// original (matching is case-insensitive, restoration is exact).
const lab = () => createRedactor({ hostname: 'desktop-abc123', username: 'alice', homePath: 'C:\\Users\\alice' });

test('hostname, account name and home prefix are replaced with placeholders', () => {
  const { redact } = lab();
  assert.equal(redact('dns:resolve desktop-abc123'), 'dns:resolve [HOSTNAME]');
  assert.equal(redact('dns:resolve DESKTOP-ABC123'), 'dns:resolve [HOSTNAME]');
  assert.equal(redact('gethostname returned DESKTOP-ABC123.corp.local'), 'gethostname returned [HOSTNAME].corp.local');
  assert.equal(redact('C:\\Users\\alice\\AppData\\Local\\x.dat'), '[USERPROFILE]\\AppData\\Local\\x.dat');
  assert.equal(redact('c:/users/alice/x.dat'), '[USERPROFILE]/x.dat');
  assert.equal(redact('run as alice (uid 1001)'), 'run as [USERNAME] (uid 1001)');
  // The home rule runs first, so the username inside a path is not double-hit.
  assert.equal(redact('C:\\Users\\alice'), '[USERPROFILE]');
});

test('other people\'s identities and ordinary content are not touched', () => {
  const { redact } = lab();
  const evidence = [
    'desktop-other',
    'mydesktop-abc123x',
    'C:\\Users\\otheruser\\payload.bin',
    'PDB path: C:\\Users\\builder\\x.pdb',
    'malice',
    'sha256 0xdeadbeef',
  ];
  for (const line of evidence) assert.equal(redact(line), line, line);
  // A hyphen is a token boundary (same as \b): a compound that contains the
  // whole token is redacted. This is the documented false-positive class -
  // rare, reversible in-session, and accepted in exchange for not leaking.
  assert.equal(redact('alice-in-wonderland'), '[USERNAME]-in-wonderland');
});

test('restore maps placeholders back, including inside nested arguments', () => {
  const { redact, restore } = lab();
  const original = {
    path: 'C:\\Users\\alice\\artifacts\\001-triage.txt',
    nested: { host: 'desktop-abc123', list: ['user=alice', 7, null] },
  };
  const redacted = redact(original);
  assert.equal(redacted.path, '[USERPROFILE]\\artifacts\\001-triage.txt');
  assert.equal(redacted.nested.host, '[HOSTNAME]');
  assert.equal(redacted.nested.list[0], 'user=[USERNAME]');
  // The input object is not mutated.
  assert.equal(original.path, 'C:\\Users\\alice\\artifacts\\001-triage.txt');
  assert.deepEqual(restore(redacted), original);
});

test('restore only rewrites real placeholders and tolerates unknown text', () => {
  const { restore } = lab();
  assert.equal(restore('[HOSTNAME] [USERNAME] [USERPROFILE]'), 'desktop-abc123 alice C:\\Users\\alice');
  // A sample string that happens to contain bracketed text is left alone
  // unless it is exactly one of the known placeholders.
  assert.equal(restore('[OTHER] [HOSTNAMEX]'), '[OTHER] [HOSTNAMEX]');
});

test('an empty host yields no rules and redaction is a no-op', () => {
  const bare = createRedactor({ hostname: '', username: '', homePath: '' });
  assert.equal(bare.enabled, false);
  assert.equal(bare.redact('desktop-abc123 C:\\Users\\alice'), 'desktop-abc123 C:\\Users\\alice');
});

test('the shared redactor uses the real host identity', () => {
  const real = hostname();
  const home = homedir();
  const out = redactSensitive(`session on ${real}, artifacts under ${home}`);
  assert.ok(!out.includes(real), 'real hostname must not survive in rendered text');
  assert.ok(out.includes('[HOSTNAME]'));
  assert.ok(out.includes('[USERPROFILE]'));
  // Round-trip through the shared session redactor.
  assert.equal(restoreSensitive(out), `session on ${real}, artifacts under ${home}`);
  assert.equal(sharedRedactor().enabled, true);
});

test('withRedactedOutput wraps both text and report fields and is idempotent', async () => {
  const real = hostname();
  const base = {
    execute: async () => ({ text: `target ${real}`, report: `${homedir()}\\x` }),
  };
  const once = withRedactedOutput(base);
  const first = await once.execute({});
  assert.ok(!first.text.includes(real));
  assert.ok(first.text.includes('[HOSTNAME]'));
  assert.ok(first.report.includes('[USERPROFILE]'));
  // Wrapping again changes nothing further.
  const twice = withRedactedOutput(once);
  const second = await twice.execute({});
  assert.equal(second.text, first.text);
  assert.equal(second.report, first.report);
});

test('withRedactedOutput leaves non-string results alone', async () => {
  const tool = withRedactedOutput({ execute: async () => undefined });
  assert.equal(await tool.execute({}), undefined);
});
