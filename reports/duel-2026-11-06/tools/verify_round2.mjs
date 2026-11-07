/** Round-2 regression: embedded PE, opcode anti-analysis, new encodings/IOCs. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { extractDeepStrings } from '../../../lib/strings.js';
import { extractIocs } from '../../../lib/intel.js';
import { structureProfile } from '../../../lib/structure.js';
import { triageFile } from '../../../lib/triage.js';

const SPEC = join(process.env.TEMP ?? '.', 'rea-spec2');
const read = (name) => readFileSync(join(SPEC, name));
const ok = (flag) => (flag ? 'PASS' : 'FAIL');

// --- R1: embedded PE ---------------------------------------------------------
{
  const bytes = read('R1a-embedded-pe.exe');
  const profile = structureProfile(bytes);
  const embedded = profile.embeddedPes ?? [];
  console.log(`${ok(embedded.length === 1)} embedded PE count=${embedded.length} ` +
    `${embedded.map((e) => `0x${e.offset.toString(16)} ${e.bits}-bit ${e.sections}sec ~${e.size}B`).join('; ')}`);
  const report = await triageFile(join(SPEC, 'R1a-embedded-pe.exe'));
  const line = [...(report.formatAnomalies ?? []), ...(report.structure?.anomalies ?? [])]
    .find((item) => /embedded PE/.test(item)) ?? '(none)';
  console.log(`triage anomaly: ${line}`);
  console.log(`${ok(!!(report.structure?.embeddedPes ?? []).length)} triage structure carries embeddedPes=`
    + `${(report.structure?.embeddedPes ?? []).length}`);
  console.log(`${ok((report.plan ?? []).some((step) => /Carve .* bytes at file offset 0x18001/.test(step.action ?? '')))} plan step for carving`);
}

// --- R2: encodings + IOC types ----------------------------------------------
{
  const bytes = read('R2-encoding-zoo.exe');
  const strings = extractDeepStrings(bytes, { minLength: 5 });
  const iocs = extractIocs(strings);
  const has = (needle) => iocs.some((item) => String(item.value).toLowerCase().includes(needle.toLowerCase()));
  console.log(`${ok(has('http://spaced.example-corp.net/a'))} spaced hex URL`);
  console.log(`${ok(has('https://b32.example-corp.net/b'))} base32 URL`);
  console.log(`${ok(iocs.some((i) => i.type === 'jwt'))} JWT`);
  console.log(`${ok(iocs.some((i) => i.type === 'ssh-key'))} SSH private key`);
  console.log(`${ok(has('203.0.113.77'))} dword IPv4 (0x + decimal)`);
  const dword = iocs.filter((i) => i.encoding === 'dword').map((i) => i.value);
  console.log(`  dword values: ${dword.join(', ') || 'none'}`);
  const channels = new Set(strings.map((s) => String(s.encoding).split('>')[0]));
  console.log(`  channels: ${[...channels].sort().join(',')}`);
}

// --- R3: opcode-level anti-analysis -----------------------------------------
{
  const bytes = read('R3-opcode-antidebug.exe');
  const profile = structureProfile(bytes);
  const signals = profile.codeSignals ?? [];
  console.log(`${ok(signals.length >= 5)} code signals=${signals.length} ` +
    `[${[...new Set(signals.map((s) => s.name))].join(', ')}]`);
  const report = await triageFile(join(SPEC, 'R3-opcode-antidebug.exe'));
  console.log(`triage anti categories: ${(report.antiAnalysis?.categories ?? []).join(', ')}`);
  const peb = (report.antiAnalysis?.matches ?? []).find((m) => m.category === 'peb-flags');
  console.log(`  peb evidence: ${peb ? peb.markers.join(' | ') : 'none'}`);
}
