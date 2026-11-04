import assert from 'node:assert/strict';
import test from 'node:test';

import { channelSummary, extractDeepStrings } from '../lib/strings.js';
import { analystExposure, extractIocs, resolveDynamicApis, trackingSurface } from '../lib/intel.js';
import { buildAnalystExposureTool } from '../lib/intel-tools.js';

const wide = (text, phase = 0) => {
  const out = Buffer.alloc(text.length * 2 + 2 + phase);
  for (let i = 0; i < text.length; i += 1) {
    out[phase + i * 2] = text.charCodeAt(i);
    out[phase + i * 2 + 1] = 0;
  }
  return out;
};
const xorWith = (text, key) => {
  const raw = Buffer.from(`${text}\0`, 'latin1');
  for (let i = 0; i < raw.length; i += 1) raw[i] ^= key;
  return raw;
};

test('deep strings recover odd-offset UTF-16LE, UTF-16BE, XOR and base64', () => {
  const parts = [
    Buffer.from('plain https://plain.example/a\0', 'latin1'),
    wide('https://even.example/beacon', 0),
    wide('https://odd.example/beacon', 1),
    Buffer.from([0, 0x41, 0, 0x42, 0, 0x43, 0, 0x44, 0, 0x45, 0, 0x46, 0, 0]), // UTF-16BE "ABCDEF"
    xorWith('https://hidden.example/gate.php', 0x5a),
    Buffer.from(`${Buffer.from('https://b64.example/path').toString('base64')}\0`, 'latin1'),
  ];
  const buffer = Buffer.concat(parts);
  const strings = extractDeepStrings(buffer, { minLength: 5, maxStrings: 500 });
  const joined = strings.map((item) => item.value).join('\n');
  assert.match(joined, /plain\.example/);
  assert.match(joined, /even\.example/);
  assert.match(joined, /odd\.example/);
  assert.match(joined, /hidden\.example/);
  assert.match(joined, /b64\.example/);
  assert.match(joined, /ABCDEF/); // UTF-16BE content (may be deduped by the LE phase)
  assert.ok(strings.some((item) => item.encoding.startsWith('xor-') && item.derived));
  assert.ok(strings.some((item) => item.encoding === 'base64' && item.derived));
  const channels = channelSummary(strings);
  assert.ok(channels.xor >= 1);
  assert.ok(channels.ascii >= 1);
});

test('XOR channel does not flood on high-entropy data', () => {
  let seed = 0x12345678;
  const noise = Buffer.alloc(32 * 1024);
  for (let i = 0; i < noise.length; i += 1) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    noise[i] = seed >>> 24;
  }
  const strings = extractDeepStrings(noise, { minLength: 5, maxStrings: 500 });
  const xorCount = strings.filter((item) => item.encoding.startsWith('xor-')).length;
  assert.ok(xorCount < 60, `XOR noise produced ${xorCount} strings`);
});

test('derived indicators are marked separately from confirmed ones', () => {
  const strings = [
    { value: 'https://confirmed.example/a', offset: 0, encoding: 'ascii' },
    { value: 'https://recovered.example/b', offset: 40, encoding: 'xor-0x5a', derived: true },
  ];
  const iocs = extractIocs(strings);
  assert.equal(iocs.find((item) => item.value.includes('confirmed')).derived, false);
  assert.equal(iocs.find((item) => item.value.includes('recovered')).derived, true);
});

test('dynamic API resolution is detected when a loader is imported', () => {
  const strings = [{ value: 'VirtualAllocEx', offset: 0 }, { value: 'WriteProcessMemory', offset: 20 }];
  assert.equal(resolveDynamicApis({ apiFlat: ['CreateFileA'] }, strings).length, 0);
  const resolved = resolveDynamicApis({ apiFlat: ['GetProcAddress', 'LoadLibraryA'] }, strings);
  assert.ok(resolved.includes('VirtualAllocEx'));
});

test('analyst exposure maps linkage chains and prints block rules as text only', () => {
  const strings = [
    { value: 'https://telemetry.tracked-app.example/v1/collect' },
    { value: 'OAuth openid user_id Authorization: Bearer x' },
    { value: 'FCM deviceToken Crashlytics installationId' },
    { value: 'X-Forwarded-For User-Agent: RTCPeerConnection' },
    { value: 'navigator.userAgent canvas.toDataURL' },
  ];
  const tracking = trackingSurface(strings, { apiFlat: ['GetProcAddress'] });
  const iocs = extractIocs(strings);
  const exposure = analystExposure({ tracking, iocs, imports: { apiFlat: ['GetProcAddress'] }, strings });
  assert.ok(['high', 'critical'].includes(exposure.level));
  assert.ok(exposure.chains.some((chain) => chain.identifier === 'Account / login identity'));
  assert.ok(exposure.chains.some((chain) => chain.identifier === 'Network egress identity'));
  assert.ok(exposure.blockRules.includes('0.0.0.0 telemetry.tracked-app.example'));
  assert.ok(exposure.preflight.length >= 6);
  assert.match(exposure.limitations, /never modifies system state/i);
  assert.ok(Array.isArray(exposure.recoveredEndpoints));
});

test('rea_analyst_exposure tool reports chains, endpoints and preflight', async () => {
  const fs = await import('node:fs/promises');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'rea-exposure-'));
  const sample = path.join(dir, 'app.bin');
  await fs.writeFile(sample, [
    'https://telemetry.tracked-app.example/v1/collect', 'OAuth user_id',
    'FCM deviceToken', 'X-Forwarded-For', 'navigator.userAgent',
    'FirebaseAnalytics', 'Crashlytics',
  ].join('\n'));
  try {
    const tool = buildAnalystExposureTool({});
    const result = await tool.execute({ path: sample });
    assert.match(result.text, /Account \/ login identity/);
    assert.match(result.text, /hosts-style block rules/);
    assert.match(result.text, /TEXT ONLY/);
    assert.match(result.text, /preflight checklist/);
    const endpointsOnly = await tool.execute({ path: sample, mode: 'endpoints' });
    assert.match(endpointsOnly.text, /0\.0\.0\.0 telemetry/);
    assert.ok(!endpointsOnly.text.includes('preflight checklist'));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
