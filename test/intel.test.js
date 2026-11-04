import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  antiAnalysisMatrix, capabilityProfile, detectLeaks, extractIocs,
  parsePEImports, sanitizeText, summarizeIocs, trackingSurface,
} from '../lib/intel.js';
import {
  buildAntiAnalysisTool, buildIocExtractTool, buildSanitizeReportTool,
  buildTrackingSurfaceTool,
} from '../lib/intel-tools.js';
import { buildDiffHintTool } from '../lib/workflow-tools.js';
import { triageBuffer } from '../lib/triage.js';
import { resolveConfig } from '../lib/config.js';

/** A minimal PE32 whose import table names two KERNEL32 functions. */
function syntheticPE() {
  const b = Buffer.alloc(0x600);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(1, 0x86);
  b.writeUInt16LE(0xe0, 0x94);
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt32LE(16, opt + 92);
  const dd = opt + 96;
  b.writeUInt32LE(0x1000, dd + 8);
  b.writeUInt32LE(0x40, dd + 12);
  const sec = opt + 0xe0;
  b.write('.rdata\0\0', sec, 'latin1');
  b.writeUInt32LE(0x400, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x400, sec + 16);
  b.writeUInt32LE(0x200, sec + 20);
  b.writeUInt32LE(0x1200, 0x200);
  b.writeUInt32LE(0x1100, 0x20c);
  b.writeUInt32LE(0x1200, 0x210);
  b.write('KERNEL32.dll\0', 0x300, 'latin1');
  b.writeUInt32LE(0x1300, 0x400);
  b.writeUInt32LE(0x1310, 0x404);
  b.write('CreateFileA\0', 0x502, 'latin1');
  b.write('IsDebuggerPresent\0', 0x512, 'latin1');
  b.write('https://c2.example/gate.php\0', 0x560, 'latin1');
  return b;
}

test('PE import table parsing resolves DLL names and imported functions', () => {
  const parsed = parsePEImports(syntheticPE());
  assert.equal(parsed.empty, false);
  assert.equal(parsed.dlls[0].name, 'KERNEL32.dll');
  assert.ok(parsed.dlls[0].functions.includes('CreateFileA'));
  assert.ok(parsed.dlls[0].functions.includes('IsDebuggerPresent'));
  assert.equal(parsed.ordinals, 0);
  assert.equal(parsePEImports(Buffer.from('not a pe')), null);
});

test('IoC extraction types and deduplication', () => {
  const strings = [
    { value: 'beacon https://evil-domain.com/gate.php and 8.8.8.8 admin@evil-domain.com', offset: 16, encoding: 'ascii' },
    { value: 'C:\\Windows\\System32\\svchost.exe', offset: 80, encoding: 'ascii' },
    { value: 'https://evil-domain.com/gate.php', offset: 120, encoding: 'ascii' },
  ];
  const iocs = extractIocs(strings);
  const types = new Set(iocs.map((item) => item.type));
  for (const type of ['url', 'ipv4', 'email', 'winpath', 'domain']) assert.ok(types.has(type), `missing ${type}`);
  assert.equal(iocs.filter((item) => item.type === 'url').length, 1);
  assert.equal(summarizeIocs(iocs).total, iocs.length);
});

test('tracking surface finds SDK, fingerprint, location and ad-id families', () => {
  const report = trackingSurface([
    'FirebaseAnalytics logEvent', 'navigator.userAgent', 'canvas.toDataURL',
    'getLastKnownLocation', 'AdvertisingIdClient', 'document.cookie',
  ], null);
  const ids = new Set(report.findings.map((item) => item.id));
  for (const id of ['analytics-sdk', 'browser-fingerprint', 'geo', 'ad-id', 'storage-tracking']) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  assert.notEqual(report.level, 'none');
  assert.equal(trackingSurface(['harmless string']).level, 'none');
});

test('anti-analysis matrix filters next tools to what the server advertises', () => {
  const report = antiAnalysisMatrix(
    ['IsDebuggerPresent', 'cpuid', 'VMware', 'frida', 'rdtsc'],
    null,
    new Set(['inspect_native_instruction', 'procedure_assembly']),
  );
  const ids = new Set(report.techniques.map((item) => item.id));
  for (const id of ['debugger-api', 'cpu-hypervisor', 'vm-artifacts', 'hook-detection', 'timing']) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  for (const item of report.techniques) {
    for (const tool of item.nextTools) {
      assert.ok(['inspect_native_instruction', 'procedure_assembly'].includes(tool));
    }
    assert.match(item.countermeasure, /\w/);
  }
  assert.match(report.limitations, /never evasion/i);
});

test('capability profile maps imported APIs to ATT&CK-style hints', () => {
  const profile = capabilityProfile({
    imports: { apiFlat: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'WinHttpConnect', 'HttpSendRequest'] },
    tracking: { level: 'high', findings: [{ label: 'Analytics SDK' }] },
  });
  const ids = new Set(profile.capabilities.map((item) => item.id));
  assert.ok(ids.has('T1055'));
  assert.ok(ids.has('T1071'));
  assert.ok(ids.has('T1537'));
  assert.equal(profile.capabilities.find((item) => item.id === 'T1055').confidence, 'medium');
});

test('report sanitisation removes analyst identifiers and secrets', () => {
  const tokens = { user: 'alice', home: 'C:\\Users\\alice', host: 'ALICE-PC' };
  const body = 'Analyst alice on ALICE-PC opened C:\\Users\\alice\\samples\\a.exe with Bearer abcdefghijklmnopqrstuvwxyz and 10.0.0.5.';
  const before = detectLeaks(body, tokens);
  assert.ok(before.some((item) => item.kind === 'analyst-username'));
  const clean = sanitizeText(body, tokens);
  assert.match(clean.text, /<ANALYST_USER>/);
  assert.match(clean.text, /<ANALYST_HOST>/);
  assert.match(clean.text, /REDACTED_BEARER_TOKEN/);
  assert.ok(!clean.text.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(clean.replacements.length >= 3);
  const after = detectLeaks(clean.text, tokens);
  assert.equal(after.filter((item) => item.kind.startsWith('analyst-')).length, 0);
});

test('triage now reports imports, indicators and capability hints', () => {
  const report = triageBuffer(syntheticPE(), { name: 'sample.exe' });
  assert.equal(report.imports.dllCount, 1);
  assert.ok(report.imports.highSignal.includes('IsDebuggerPresent'));
  assert.ok(report.iocSummary.total >= 1);
  assert.ok(Array.isArray(report.capabilityHints));
  assert.match(report.nextSteps.join(' '), /rea_ioc_extract/);
});

test('intel tools produce bounded, untrusted-marked output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rea-intel-'));
  const sample = join(dir, 'sample.bin');
  await writeFile(sample, [
    'https://tracker.example/collect', 'FirebaseAnalytics', 'navigator.userAgent',
    'IsDebuggerPresent', 'VMware', '8.8.8.8', 'admin@tracker.example',
  ].join('\n'));
  const store = { write: async () => join(dir, 'out.json') };
  try {
    const ioc = await buildIocExtractTool({ store }).execute({ path: sample });
    assert.match(ioc.text, /tracker\.example/);
    assert.match(ioc.text, /<untrusted-ioc>/);
    const track = await buildTrackingSurfaceTool({}).execute({ path: sample });
    assert.match(track.text, /Analytics \/ telemetry SDK/);
    assert.match(track.text, /rea_sanitize_report/);
    const anti = await buildAntiAnalysisTool({ triageOptions: { availableTools: new Set(['inspect_native_instruction']) } }).execute({ path: sample });
    assert.match(anti.text, /Debugger presence APIs/);
    assert.match(anti.text, /next tools:/);
    const sanitizer = buildSanitizeReportTool({
      store,
      env: { USERNAME: 'alice', USERPROFILE: 'C:\\Users\\alice', COMPUTERNAME: 'ALICE-PC' },
    });
    const checked = await sanitizer.execute({ text: 'alice on C:\\Users\\alice\\a.exe' });
    assert.match(checked.text, /analyst-username/);
    const cleaned = await sanitizer.execute({ text: 'alice on C:\\Users\\alice\\a.exe', mode: 'sanitize' });
    assert.match(cleaned.text, /<ANALYST_USER>/);
    assert.match(cleaned.text, /clean copy:/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('diff hint reports import deltas, new network indicators and block overlap', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rea-diff-'));
  const left = join(dir, 'old.bin');
  const right = join(dir, 'new.bin');
  await writeFile(left, 'https://api.example/v1 shared string VirtualProtect');
  await writeFile(right, 'https://api.example/v1 https://c2.example/gate shared string VirtualAllocEx WriteProcessMemory');
  try {
    const tool = buildDiffHintTool({ triageOptions: { maxBytes: 1024 * 1024 } });
    const result = await tool.execute({ left, right });
    assert.match(result.text, /block overlap/);
    assert.match(result.text, /new network indicators/);
    assert.match(result.text, /c2\.example/);
    assert.match(result.text, /new high-risk imported APIs/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('network egress policy is normalised and defaults to warn', () => {
  assert.equal(resolveConfig({}).networkEgressPolicy, 'warn');
  assert.equal(resolveConfig({ networkEgressPolicy: 'deny' }).networkEgressPolicy, 'deny');
  assert.equal(resolveConfig({ networkEgressPolicy: 'invalid' }).networkEgressPolicy, 'warn');
});
