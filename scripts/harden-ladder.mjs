/**
 * Hardening ladder: measure what the analyser actually recovers as a target
 * gets progressively better at hiding. Every tier carries the SAME ground
 * truth; only the encoding/protection changes. That makes recall comparable
 * across tiers instead of comparing apples to oranges.
 *
 *   L0  plaintext                         (control)
 *   L1  UTF-16LE at odd phase + 1-byte XOR (1.5.0 baseline target)
 *   L2  4-byte repeating XOR + length-prefixed records + nested base64
 *   L3  RC4 config blob with nearby ASCII key + stack strings + reversed string
 *   L4  L3 plus import-by-ordinal and an API-hash table (no API names at all)
 *   L5  L4 plus per-build attribution canaries (analyst-tracking layer)
 *
 * Run: npm run ladder [-- --out dist/harden-ladder.json --label before]
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

import { extractDeepStrings, channelSummary } from '../lib/strings.js';
import { resolveImports } from '../lib/api-hash.js';
import {
  antiAnalysisMatrix, analystExposure, capabilityProfile, extractIocs, parsePEImports,
  trackingSurface,
} from '../lib/intel.js';

// ---------------------------------------------------------------- encoders ---

const rc4 = (key, data) => {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = Buffer.alloc(data.length);
  let i = 0; j = 0;
  for (let n = 0; n < data.length; n += 1) {
    i = (i + 1) & 0xff; j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
};

const xorRepeat = (input, key) => {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, 'latin1');
  const out = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw[i] ^ key[i % key.length];
  return out;
};

const utf16 = (text) => {
  const out = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i += 1) out.writeUInt16LE(text.charCodeAt(i), i * 2);
  return out;
};

const b64 = (buffer) => Buffer.from(buffer.toString('base64'), 'latin1');

// -------------------------------------------------------------- ground truth --

const ENDPOINTS = [
  'https://telemetry.ladder-app.example/v1/collect',
  'https://api.ladder-app.example/device/register',
  'https://hidden-c2.ladder-app.example/gate.php',
  'https://backup.ladder-app.example/beacon',
  'https://canary.ladder-app.example/pixel.gif',
];
const HIDDEN = [ENDPOINTS[2], ENDPOINTS[3], ENDPOINTS[4]];

const MARKERS = [
  'FirebaseAnalytics', 'AppsFlyer', 'Crashlytics', 'utm_source=ladder', 'setUserIdentifier',
  'android_id', 'getSubscriberId', 'AdvertisingIdClient', 'getLastKnownLocation',
  'canvas.toDataURL', 'devicePixelRatio', 'navigator.hardwareConcurrency',
  'Intl.DateTimeFormat', 'X-Forwarded-For', 'RTCPeerConnection', 'deviceToken',
  'installation_id', 'document.cookie', 'OAuth', 'user_id',
];
const ANTI = [
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'rdtsc', 'QueryPerformanceCounter', 'cpuid', 'VMXh', 'VMware', 'VBox',
  'Sandboxie', 'frida', 'gum-js-loop', 'TlsCallback',
];
const IOC_TEXT = [
  '203.0.113.77', 'analytics@ladder-app.example',
  'HKLM\\SOFTWARE\\LadderApp\\InstallId',
  'C:\\build\\ladder\\Release\\ladder_app.pdb',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ladder/2.1',
  'update.ladder-app.example',
];
const IMPORTS = [
  { dll: 'KERNEL32.dll', apis: ['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread', 'GetComputerNameA', 'GetVolumeInformationA'] },
  { dll: 'WININET.dll', apis: ['InternetConnectA', 'HttpSendRequestA'] },
  { dll: 'ADVAPI32.dll', apis: ['RegSetValueExA', 'CryptEncrypt'] },
];

const EXPECTED_TRACKING = [
  'analytics-sdk', 'ad-id', 'device-fingerprint', 'browser-fingerprint', 'geo', 'identity-gen',
  'storage-tracking', 'network-id', 'attribution', 'account-linkage', 'push-token',
  'crash-identity', 'network-identity', 'locale-time',
];
const EXPECTED_ANTI = [
  'debugger-api', 'timing', 'cpu-hypervisor', 'vm-artifacts', 'sandbox-env',
  'hook-detection', 'tls-callback',
];
const EXPECTED_IOC = ['url', 'ipv4', 'email', 'registry', 'pdb', 'winpath', 'useragent', 'domain'];

const CONTENT = [...ENDPOINTS, ...MARKERS, ...ANTI, ...IOC_TEXT];
const UTF16_SUBSET = new Set([...ANTI, ENDPOINTS[3]]);
const XOR_SUBSET = new Set([ENDPOINTS[2], ENDPOINTS[4], 'installation_id']);

// ------------------------------------------------------------------- PE build --

const align = (value, to) => Math.ceil(value / to) * to;

function buildRdata({ mode, payload }) {
  const parts = [];
  let cursor = 0;
  const put = (buffer, padding = 0) => {
    const at = cursor;
    parts.push({ at, buffer });
    cursor = align(cursor + buffer.length + padding, 4);
    return at;
  };

  const descriptorsAt = put(Buffer.alloc(20 * (IMPORTS.length + 1)));
  const dllNameAt = [];
  for (const entry of IMPORTS) dllNameAt.push(put(Buffer.from(`${entry.dll}\0`, 'latin1'), 2));

  const thunkAt = [];
  const byNameAt = [];
  for (const entry of IMPORTS) {
    const thunk = Buffer.alloc(4 * (entry.apis.length + 1));
    const names = [];
    entry.apis.forEach((api, slot) => {
      if (mode === 'ordinal' || mode === 'hashed') {
        thunk.writeUInt32LE((0x80000000 + slot + 1) >>> 0, slot * 4);
      } else {
        thunk.writeUInt32LE(0, slot * 4); // patched below once RVAs are known
        names.push(api);
      }
    });
    thunkAt.push({ at: put(thunk), names, slotCount: entry.apis.length, entry });
  }
  // Import-by-name blocks (hint word + name). Their RVA depends on layout, so
  // they are written after the thunk arrays but patched into the thunks.
  for (const group of thunkAt) {
    if (mode === 'ordinal' || mode === 'hashed') continue;
    const patched = Buffer.alloc(4 * (group.slotCount + 1));
    group.names.forEach((api, slot) => {
      const at = put(Buffer.from(`\0\0${api}\0`, 'latin1'), 2);
      byNameAt.push(at);
      patched.writeUInt32LE(0x1000 + at, slot * 4);
    });
    parts.find((item) => item.at === group.at).buffer = patched;
  }

  // API-hash table (L4+): 4-byte ROR13 hashes, no names anywhere.
  let hashAt = -1;
  if (mode === 'hashed') {
    const names = IMPORTS.flatMap((entry) => entry.apis);
    const table = Buffer.alloc(names.length * 4);
    names.forEach((name, index) => table.writeUInt32LE(ror13(name), index * 4));
    hashAt = put(table);
  }

  const payloadAt = align(cursor, 16);
  parts.push({ at: payloadAt, buffer: payload });

  const size = align(payloadAt + payload.length, 0x10);
  const rdata = Buffer.alloc(size);
  for (const part of parts) part.buffer.copy(rdata, part.at);

  // Descriptors: original thunk, name RVA, first thunk.
  IMPORTS.forEach((entry, index) => {
    const at = descriptorsAt + index * 20;
    rdata.writeUInt32LE(0x1000 + thunkAt[index].at, at);
    rdata.writeUInt32LE(0x1000 + dllNameAt[index], at + 12);
    rdata.writeUInt32LE(0x1000 + thunkAt[index].at, at + 16);
  });
  return { rdata, payloadRva: 0x1000 + payloadAt, hashRva: hashAt >= 0 ? 0x1000 + hashAt : null };
}

function ror13(name) {
  let h = 0;
  for (const byte of Buffer.from(name, 'latin1')) {
    h = ((h >>> 13) | (h << 19)) >>> 0;
    h = (h + byte) >>> 0;
  }
  return h >>> 0;
}

function buildText(stackEndpoint) {
  const buffer = Buffer.alloc(0x2000);
  let seed = 0x5eed1234;
  for (let i = 0; i < buffer.length; i += 1) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    buffer[i] = seed >>> 24;
  }
  if (!stackEndpoint) return buffer;
  // Stack strings: short immediate chunks, each NUL-terminated, executed in
  // order and concatenated at runtime. Reassembly is left to the analyser.
  const chunks = [];
  for (let i = 0; i < stackEndpoint.length; i += 6) chunks.push(stackEndpoint.slice(i, i + 6));
  let at = 0x140;
  // Non-printable opcode-like padding between pushes: real compilers emit
  // `mov [ebp-4], imm32` and the surrounding bytes are never ASCII.
  const JUNK = [0xcc, 0x90, 0x00, 0xeb, 0x00];
  for (const chunk of chunks) {
    buffer.write(`${chunk}\0`, at, 'latin1');
    at += chunk.length + 1;
    for (const byte of JUNK) { buffer[at] = byte; at += 1; }
  }
  return buffer;
}

function buildPE({ rdata, text }) {
  const headers = 0x200;
  const rdataRaw = align(rdata.length, 0x200);
  const textRaw = align(text.length, 0x200);
  const rdataVa = 0x1000;
  const textVa = rdataVa + align(rdataRaw, 0x1000);
  const imageSize = textVa + align(textRaw, 0x1000);
  const total = headers + rdataRaw + textRaw;
  const file = Buffer.alloc(total);

  file.write('MZ', 0, 'latin1');
  file.writeUInt32LE(0x80, 0x3c);
  const pe = 0x80;
  file.write('PE\0\0', pe, 'latin1');
  const coff = pe + 4;
  file.writeUInt16LE(0x14c, coff);
  file.writeUInt16LE(2, coff + 2);
  file.writeUInt16LE(0xe0, coff + 16);
  file.writeUInt16LE(0x0102, coff + 18);
  const opt = coff + 20;
  file.writeUInt16LE(0x10b, opt);
  file.writeUInt32LE(textVa + 0x100, opt + 16);
  file.writeUInt32LE(0x400000, opt + 28);
  file.writeUInt32LE(0x1000, opt + 32);
  file.writeUInt32LE(0x200, opt + 36);
  file.writeUInt32LE(imageSize, opt + 56);
  file.writeUInt32LE(headers, opt + 60);
  file.writeUInt16LE(3, opt + 68);
  file.writeUInt32LE(16, opt + 92);
  file.writeUInt32LE(rdataVa, opt + 96 + 8);
  file.writeUInt32LE(0x40, opt + 96 + 12);

  const writeSection = (index, name, va, rawSize, rawPointer, characteristics) => {
    const at = opt + 0xe0 + index * 40;
    file.write(name.padEnd(8, '\0'), at, 'latin1');
    file.writeUInt32LE(rawSize, at + 8);
    file.writeUInt32LE(va, at + 12);
    file.writeUInt32LE(rawSize, at + 16);
    file.writeUInt32LE(rawPointer, at + 20);
    file.writeUInt32LE(characteristics, at + 36);
  };
  writeSection(0, '.rdata', rdataVa, rdataRaw, headers, 0x40000040);
  writeSection(1, '.text', textVa, textRaw, headers + rdataRaw, 0x60000020);

  rdata.copy(file, headers);
  text.copy(file, headers + rdataRaw);
  return file;
}

// ------------------------------------------------------------- tier contents --

const TIER_CONTENT = {};

TIER_CONTENT.L0 = Buffer.concat(CONTENT.map((text) => Buffer.from(`${text}\0`, 'latin1')));

TIER_CONTENT.L1 = (() => {
  const parts = [Buffer.from([0])]; // force odd phase for the wide block
  for (const text of CONTENT) {
    if (XOR_SUBSET.has(text)) parts.push(xorRepeat(`${text}\0`, [0x5a]));
    else if (UTF16_SUBSET.has(text)) parts.push(Buffer.concat([Buffer.from([0x41]), utf16(`${text}\0`)]));
    else parts.push(Buffer.from(`${text}\0`, 'latin1'));
  }
  return Buffer.concat(parts);
})();

const KEY4 = [0x9e, 0x37, 0x79, 0xb4];
const asRecord = (buffer) => {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(buffer.length);
  return Buffer.concat([prefix, buffer]);
};
TIER_CONTENT.L2 = (() => {
  // One continuous cipher stream: a repeating-key XOR over a config table. The
  // key phase is global, exactly like a real encrypted blob - per-record key
  // resets would be an artefact of the fixture, not of the target.
  const plain = Buffer.concat(CONTENT
    .filter((text) => text !== ENDPOINTS[3] && text !== ENDPOINTS[1])
    .map((text) => asRecord(Buffer.from(`${text}\0`, 'latin1'))));
  const nested = [ENDPOINTS[3], ENDPOINTS[1]]
    .map((text) => `b64:${b64(xorRepeat(`${text}\0`, KEY4)).toString('latin1')}\0`)
    .join('');
  return Buffer.concat([xorRepeat(plain, KEY4), Buffer.from(nested, 'latin1')]);
})();

const RC4_KEY = 'LadderCfgKey2024!';
const RC4_PLAINTEXT = Buffer.concat(CONTENT.map((text) => {
  if (text === ENDPOINTS[1]) return Buffer.from(`${[...text].reverse().join('')}\0`, 'latin1');
  return Buffer.from(`${text}\0`, 'latin1');
}));
TIER_CONTENT.L3 = Buffer.concat([
  Buffer.from(`cfg=rc4;key=${RC4_KEY};build=debug\0`, 'latin1'),
  rc4(Buffer.from(RC4_KEY, 'latin1'), RC4_PLAINTEXT),
]);
TIER_CONTENT.L4 = TIER_CONTENT.L3;
TIER_CONTENT.L5 = Buffer.concat([
  TIER_CONTENT.L3,
  Buffer.from(`canary=ladder-7f3a9c2e41d8;build=2026-11-04T20:41Z\0`, 'latin1'),
  Buffer.from('https://9c41ab77.probe.ladder-app.example/t.gif?b=ladder-7f3a9c2e41d8\0', 'latin1'),
]);

const CANARY = ['ladder-7f3a9c2e41d8', '9c41ab77'];

// ------------------------------------------------------------------- measure --

function scoreTier(name, buffer, legacy = false) {
  const imports = legacy ? parsePEImports(buffer) : resolveImports(buffer, parsePEImports(buffer));
  // --legacy reproduces the 1.5.0 pipeline exactly, so the before/after table
  // is measured with the same fixture instead of being quoted from memory.
  const strings = extractDeepStrings(buffer, legacy
    ? { minLength: 5, maxStrings: 4_000, keyedXor: false, blobs: false, stack: false, reversed: false }
    : { minLength: 5, maxStrings: 4_000 });
  const tracking = trackingSurface(strings, imports);
  const anti = antiAnalysisMatrix(strings, imports, null);
  const iocs = extractIocs(strings);
  const profile = capabilityProfile({ imports, strings, tracking });

  const trackingIds = new Set(tracking.findings.map((item) => item.id));
  const antiIds = new Set(anti.techniques.map((item) => item.id));
  const iocTypes = new Set(iocs.map((item) => item.type));
  const haystack = strings.map((item) => item.value).join('\n');

  const hit = (list, set) => list.filter((id) => set.has(id));
  const trackingHit = hit(EXPECTED_TRACKING, trackingIds);
  const antiHit = hit(EXPECTED_ANTI, antiIds);
  const iocHit = hit(EXPECTED_IOC, iocTypes);
  const hiddenHit = HIDDEN.filter((value) => haystack.includes(value));
  const importHit = imports ? imports.apiFlat.filter((api) => /IsDebuggerPresent|VirtualAllocEx|CreateRemoteThread|InternetConnect|RegSetValue|CryptEncrypt/i.test(api)) : [];
  const canaryHit = CANARY.filter((value) => haystack.includes(value));
  const exposure = analystExposure({ tracking, iocs, imports, strings });
  const attributed = CANARY.filter((value) => exposure.attribution.markers
    .some((marker) => marker.value.includes(value) || value.includes(marker.value)));

  const channels = channelSummary(strings);
  const recall = (got, total) => Number(((got / total) * 100).toFixed(1));
  const overall = Number((
    (trackingHit.length / EXPECTED_TRACKING.length * 0.3
      + antiHit.length / EXPECTED_ANTI.length * 0.25
      + iocHit.length / EXPECTED_IOC.length * 0.2
      + hiddenHit.length / HIDDEN.length * 0.25) * 100
  ).toFixed(1));

  return {
    tier: name,
    bytes: buffer.length,
    sha256: createHash('sha256').update(buffer).digest('hex').slice(0, 16),
    strings: strings.length,
    channels,
    tracking: { got: trackingHit.length, total: EXPECTED_TRACKING.length, recall: recall(trackingHit.length, EXPECTED_TRACKING.length), missing: EXPECTED_TRACKING.filter((id) => !trackingIds.has(id)) },
    anti: { got: antiHit.length, total: EXPECTED_ANTI.length, recall: recall(antiHit.length, EXPECTED_ANTI.length), missing: EXPECTED_ANTI.filter((id) => !antiIds.has(id)) },
    ioc: { got: iocHit.length, total: EXPECTED_IOC.length, recall: recall(iocHit.length, EXPECTED_IOC.length), missing: EXPECTED_IOC.filter((id) => !iocTypes.has(id)) },
    hidden: { got: hiddenHit.length, total: HIDDEN.length, recall: recall(hiddenHit.length, HIDDEN.length), missing: HIDDEN.filter((value) => !hiddenHit.includes(value)) },
    imports: {
      named: imports ? imports.apiFlat.filter((api) => !api.startsWith('#')).length - (imports.hashed?.length ?? 0) : 0,
      hashed: imports?.hashed?.length ?? 0,
      ordinals: imports?.ordinals ?? 0,
      matched: importHit.length,
    },
    capabilities: profile.capabilities.map((item) => item.id),
    canaries: { got: canaryHit.length, total: CANARY.length, values: canaryHit },
    attribution: {
      got: attributed.length, total: CANARY.length,
      recall: recall(attributed.length, CANARY.length),
      level: exposure.attribution.level,
      markers: exposure.attribution.markers.map((item) => item.value),
    },
    overall,
  };
}

// --------------------------------------------------------------------- main --

const out = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : join(tmpdir(), 'rea-ladder');
const label = process.argv.includes('--label') ? process.argv[process.argv.indexOf('--label') + 1] : 'run';
const legacy = process.argv.includes('--legacy');
mkdirSync(out, { recursive: true });
mkdirSync(dirname(out), { recursive: true });

const TIERS = Object.keys(TIER_CONTENT);
const rows = [];
for (const tier of TIERS) {
  const mode = tier === 'L4' || tier === 'L5' ? 'hashed' : 'named';
  const { rdata } = buildRdata({ mode, payload: TIER_CONTENT[tier] });
  const text = buildText(tier === 'L3' || tier === 'L4' || tier === 'L5' ? ENDPOINTS[0] : null);
  const buffer = buildPE({ rdata: rdata.subarray(0, align(rdata.length, 0x10)), text });
  writeFileSync(join(out, `${tier}.exe`), buffer);
  rows.push(scoreTier(tier, buffer, legacy));
}

const report = {
  schemaVersion: 1,
  label,
  generatedAt: new Date().toISOString(),
  toolVersion: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version,
  groundTruth: { tracking: EXPECTED_TRACKING, anti: EXPECTED_ANTI, ioc: EXPECTED_IOC, hidden: HIDDEN, canaries: CANARY },
  tiers: rows,
  mean: Number((rows.reduce((sum, row) => sum + row.overall, 0) / rows.length).toFixed(1)),
  weakest: rows.reduce((worst, row) => (row.overall < worst.overall ? row : worst), rows[0]).tier,
};
writeFileSync(join(out, 'ladder.json'), `${JSON.stringify(report, null, 2)}\n`);

const pad = (value, width) => String(value).padEnd(width);
console.log(`hardening ladder [${label}] v${report.toolVersion}`);
console.log(`${pad('tier', 6)}${pad('overall', 9)}${pad('tracking', 10)}${pad('anti', 8)}${pad('ioc', 7)}${pad('hidden', 8)}${pad('attr', 7)}imports`);
for (const row of rows) {
  console.log(
    `${pad(row.tier, 6)}${pad(`${row.overall}%`, 9)}${pad(`${row.tracking.got}/${row.tracking.total}`, 10)}`
    + `${pad(`${row.anti.got}/${row.anti.total}`, 8)}${pad(`${row.ioc.got}/${row.ioc.total}`, 7)}`
    + `${pad(`${row.hidden.got}/${row.hidden.total}`, 8)}${pad(`${row.attribution.got}/${row.attribution.total}`, 7)}`
    + `${row.imports.named} named / ${row.imports.hashed} hashed / ${row.imports.ordinals} ord`,
  );
}
console.log(`mean ${report.mean}%  weakest ${report.weakest}  json ${join(out, 'ladder.json')}`);
