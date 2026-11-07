/** Round-3 measurements: decode chains, schemes, analyser cost, managed PE. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { extractDeepStrings, channelSummary } from '../../../lib/strings.js';
import { extractIocs } from '../../../lib/intel.js';
import { triageFile } from '../../../lib/triage.js';

const SPEC = join(process.env.TEMP ?? '.', 'rea-spec3');
const read = (name) => readFileSync(join(SPEC, name));

function iocsOf(bytes) {
  const strings = extractDeepStrings(bytes, { minLength: 5, maxStrings: 4000 });
  return { iocs: extractIocs(strings), channels: channelSummary(strings) };
}

const expect = (label, hit) => `${hit ? 'PASS' : 'FAIL'} ${label}`;

// --- decode chains -----------------------------------------------------------
{
  const { iocs, channels } = iocsOf(read('R3a-xor-utf16.exe'));
  const wide = iocs.some((i) => String(i.value).includes('wide.example-corp.net'));
  console.log(expect('XOR(UTF-16LE) URL', wide), JSON.stringify(channels));
  if (!wide) console.log('   iocs:', iocs.map((i) => `${i.type}:${i.value}`).slice(0, 8).join(' | '));
}
for (const [file, label] of [
  ['R3b-b64-deflate-xor.exe', 'base64(deflate(xor5a))'],
  ['R3c-hex-gzip-xor4.exe', 'hex(gzip(xor4))'],
]) {
  const { iocs, channels } = iocsOf(read(file));
  const hit = iocs.some((i) => String(i.value).includes('r3.example-corp.net'));
  console.log(expect(label, hit), JSON.stringify(channels));
  if (!hit) console.log('   iocs:', iocs.map((i) => `${i.type}:${i.value}`).slice(0, 8).join(' | '));
}

// --- scheme coverage ---------------------------------------------------------
{
  const { iocs } = iocsOf(read('R3d-schemes.exe'));
  const values = iocs.map((i) => `${i.type}:${i.value}`);
  console.log('schemes:', values.join(' | '));
  for (const [label, needle] of [
    ['ws://', 'ws://gate.example-corp.net/socket'],
    ['tcp://', 'tcp://45.77.12.9:4444'],
    ['host:port', '198.51.100.9:8080'],
    ['.shop domain', 'cdn.example-corp.shop'],
    ['ftp://', 'ftp://files.example-corp.net/drop'],
    ['UNC path', '\\\\fileserver\\share'],
  ]) {
    console.log(`  ${values.some((v) => v.includes(needle)) ? 'PASS' : 'FAIL'} ${label}`);
  }
}

// --- cost / boundedness ------------------------------------------------------
for (const file of ['R3e-mz-flood.exe', 'R3f-zlib-bomb.exe']) {
  const bytes = read(file);
  const started = Date.now();
  const report = await triageFile(join(SPEC, file));
  const elapsed = Date.now() - started;
  console.log(`${file}: ${elapsed} ms, verdict=${report.verdict}, size=${bytes.length}, strings=${report.strings?.count ?? '?'}`);
}

// --- managed (.NET) ----------------------------------------------------------
{
  const report = await triageFile(join(SPEC, 'R3g-managed.exe'));
  const blob = JSON.stringify(report);
  console.log(`managed: format=${report.format} verdict=${report.verdict} `
    + `mentionsManaged=${/managed|\.net|clr|cil/i.test(blob)} nextSteps=${(report.nextSteps ?? []).slice(0, 2).join(' || ').slice(0, 200)}`);
  const { iocs } = iocsOf(read('R3g-managed.exe'));
  console.log(`  managed iocs: ${iocs.map((i) => `${i.type}:${i.value}`).slice(0, 6).join(' | ')}`);
}
