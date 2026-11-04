import assert from 'node:assert/strict';
import test from 'node:test';

import {
  candidateKeys, cribDragKeys, findHighEntropyRegions, joinStackFragments, rc4Keystream,
  recoverBlobs,
} from '../lib/crypto-recovery.js';
import { HASH_ALGORITHMS, recoverHashedApis, resolveImports } from '../lib/api-hash.js';
import { detectAttributionCanaries } from '../lib/intel.js';
import { extractDeepStrings, channelSummary } from '../lib/strings.js';

const xorRepeat = (text, key) => {
  const raw = Buffer.from(text, 'latin1');
  const out = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw[i] ^ key[i % key.length];
  return out;
};

const rc4 = (key, data) => {
  const stream = rc4Keystream(key, data.length);
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 1) out[i] = data[i] ^ stream[i];
  return out;
};

test('crib dragging recovers a repeating XOR key from a known prefix', () => {
  const key = Buffer.from([0x9e, 0x37, 0x79, 0xb4]);
  const buffer = Buffer.concat([
    Buffer.alloc(64, 0x41),
    xorRepeat('https://multi.example/collect\0FirebaseAnalytics\0', key),
    Buffer.alloc(64, 0x00),
  ]);
  const keys = cribDragKeys(buffer);
  assert.ok(keys.length > 0, 'no candidate key recovered');
  assert.equal(keys[0].key.toString('hex'), key.toString('hex'));
});

test('four-byte XOR strings are recovered and marked as derived', () => {
  const key = Buffer.from([0x9e, 0x37, 0x79, 0xb4]);
  const buffer = Buffer.concat([
    Buffer.alloc(32, 0xcc),
    xorRepeat('https://hidden.example/gate.php\0android_id\0', key),
    Buffer.alloc(32, 0xcc),
  ]);
  const strings = extractDeepStrings(buffer, { minLength: 5, maxStrings: 200 });
  const joined = strings.map((item) => item.value).join('\n');
  assert.match(joined, /hidden\.example/);
  assert.match(joined, /android_id/);
  assert.ok(strings.some((item) => item.encoding.startsWith('xor4') && item.derived));
  assert.equal(channelSummary(strings).xor >= 1, true);
});

test('RC4 config blob is decrypted with the key stored beside it', () => {
  const key = Buffer.from('LadderCfgKey2024!', 'latin1');
  const plaintext = Buffer.from(
    `https://c2.example/beacon\0IsDebuggerPresent\0rdtsc\0${'fingerprint-padding-'.repeat(40)}\0`,
    'latin1',
  );
  const buffer = Buffer.concat([
    Buffer.from('cfg=rc4;key=LadderCfgKey2024!;build=debug\0', 'latin1'),
    rc4(key, plaintext),
    Buffer.alloc(64, 0x90),
  ]);
  const regions = findHighEntropyRegions(buffer);
  assert.ok(regions.length > 0, 'no high-entropy region detected');
  const keys = candidateKeys(buffer, { regions });
  assert.ok(keys.some((item) => item.value === 'LadderCfgKey2024!'), 'key not offered as a candidate');
  const blobs = recoverBlobs(buffer, { regions, keys });
  assert.ok(blobs.length > 0, 'blob not recovered');
  assert.equal(blobs[0].mode, 'rc4');
  assert.match(blobs[0].data.toString('latin1'), /c2\.example/);

  const strings = extractDeepStrings(buffer, { minLength: 5, maxStrings: 300 });
  const joined = strings.map((item) => item.value).join('\n');
  assert.match(joined, /c2\.example/);
  assert.match(joined, /IsDebuggerPresent/);
  assert.ok(strings.some((item) => String(item.encoding).startsWith('rc4:')));
});

test('stack strings are reassembled from short immediates', () => {
  const parts = [
    { value: 'https:', offset: 100, encoding: 'ascii' },
    { value: '//tele', offset: 110, encoding: 'ascii' },
    { value: 'metry.', offset: 120, encoding: 'ascii' },
    { value: 'example', offset: 130, encoding: 'ascii' },
    { value: '/collect', offset: 140, encoding: 'ascii' },
  ];
  const joined = joinStackFragments(parts);
  assert.ok(joined.length > 0, 'no stack string reassembled');
  assert.match(joined[0].value, /https:\/\/telemetry\.example\/collect/);
});

test('reversed literals are recovered', () => {
  const reversed = [...'https://rev.example/path'].reverse().join('');
  const buffer = Buffer.concat([Buffer.alloc(32, 0x00), Buffer.from(`${reversed}\0`, 'latin1')]);
  const strings = extractDeepStrings(buffer, { minLength: 5, maxStrings: 200 });
  assert.ok(strings.some((item) => item.encoding === 'reversed' && /rev\.example/.test(item.value)));
});

test('API hashes resolve to names across algorithms', () => {
  const names = ['IsDebuggerPresent', 'VirtualAllocEx', 'GetComputerNameA'];
  const table = Buffer.alloc(names.length * 4);
  names.forEach((name, index) => table.writeUInt32LE(HASH_ALGORITHMS.ror13(name), index * 4));
  const buffer = Buffer.concat([Buffer.alloc(16, 0x00), table, Buffer.alloc(16, 0x00)]);
  const { apis } = recoverHashedApis(buffer);
  const resolved = apis.map((item) => item.api);
  for (const name of names) assert.ok(resolved.includes(name), `${name} not resolved`);
  assert.ok(apis.every((item) => item.algorithm === 'ror13'));

  const merged = resolveImports(buffer, {
    dlls: [{ name: 'KERNEL32.dll', functions: ['#1', '#2'] }],
    apiFlat: ['#1', '#2'], ordinals: 2, empty: false,
  });
  assert.equal(merged.hashed.length, 3);
  assert.ok(merged.apiFlat.includes('IsDebuggerPresent'));
});

test('a normal import table skips the hash scan entirely', () => {
  const imports = {
    dlls: [{ name: 'KERNEL32.dll', functions: Array.from({ length: 30 }, (_, i) => `Api${i}`) }],
    apiFlat: Array.from({ length: 30 }, (_, i) => `Api${i}`), ordinals: 0, empty: false,
  };
  const merged = resolveImports(Buffer.alloc(64), imports);
  assert.equal(merged, imports);
  assert.equal(merged.hashed, undefined);
});

test('per-build attribution canaries are detected and explained', () => {
  const strings = [
    { value: 'https://9c41ab77.probe.ladder-app.example/t.gif?b=ladder-7f3a9c2e41d8', offset: 10 },
    { value: 'canary=ladder-7f3a9c2e41d8', offset: 80 },
    { value: 'build=debug', offset: 120 },
  ];
  const result = detectAttributionCanaries(strings);
  assert.equal(result.level, 'high');
  const values = result.markers.map((item) => item.value);
  assert.ok(values.includes('ladder-7f3a9c2e41d8'));
  assert.ok(values.includes('9c41ab77'));
  assert.ok(!values.includes('debug'), 'a plain build label is not a per-copy token');
  assert.match(result.risk, /attributable|identifies/i);
  assert.ok(result.advice.length >= 2);
});

test('a sample without canaries is not reported as watermarked', () => {
  const result = detectAttributionCanaries([
    { value: 'https://telemetry.example/v1/collect' },
    { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
  ]);
  assert.equal(result.level, 'none');
  assert.match(result.risk, /Absence is not proof/i);
});
