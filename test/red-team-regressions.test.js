/**
 * Regressions from the red-team duel of 2026-11-06.
 *
 * Each case is a channel or an attribution rule that an independent attacker
 * used to get past the analyser: hex and JSON escapes hid a URL, gzip was read
 * as "an encrypted region", the string "TLS" invented a callback that the PE
 * header denies, a decoy URL became "the" endpoint, and a report sent to
 * sanitize kept its AWS keys.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import { channelSummary, extractDeepStrings } from '../lib/strings.js';
import { antiAnalysisMatrix, detectLeaks, extractIocs, sanitizeText } from '../lib/intel.js';
import { peTlsDirectory } from '../lib/containers.js';
import { assessBehavior } from '../lib/plan.js';
import { findEmbeddedPes, scanCodeSignals, structureProfile } from '../lib/structure.js';

const URL = 'https://cdn-sync.example-corp.net/v3/poll';
const values = (buffer) => extractDeepStrings(buffer, { minLength: 5 }).map((item) => item.value);

/** Smallest PE that the structural readers accept, for layout-level tests. */
function miniPe({ text = Buffer.alloc(0), clr = false } = {}) {
  const textSize = Math.max(text.length, 0x200);
  const bytes = Buffer.alloc(0x200 + textSize);
  bytes.write('MZ', 0, 'latin1');
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'latin1');
  bytes.writeUInt16LE(1, 0x46);
  bytes.writeUInt16LE(0xf0, 0x54);
  bytes.writeUInt16LE(0x20b, 0x58);
  bytes.writeBigUInt64LE(0x400000n, 0x58 + 24);
  bytes.writeUInt32LE(16, 0x58 + 108); // NumberOfRvaAndSizes
  if (clr) {
    bytes.writeUInt32LE(0x1000, 0x58 + 112 + 14 * 8);
    bytes.writeUInt32LE(72, 0x58 + 112 + 14 * 8 + 4);
  }
  const table = 0x58 + 0xf0;
  bytes.write('.text', table, 'latin1');
  bytes.writeUInt32LE(textSize, table + 8);
  bytes.writeUInt32LE(0x1000, table + 12);
  bytes.writeUInt32LE(textSize, table + 16);
  bytes.writeUInt32LE(0x200, table + 20);
  bytes.writeUInt32LE(0x60000020, table + 36);
  text.copy(bytes, 0x200);
  return bytes;
}
const iocValues = (buffer) => extractIocs(extractDeepStrings(buffer, { minLength: 5 })).map((item) => item.value);

test('hex-encoded payloads are decoded, not left as printable noise', () => {
  const buffer = Buffer.from(`cfg=${Buffer.from(`exec ${URL}`).toString('hex')}\n`, 'latin1');
  const found = extractDeepStrings(buffer, { minLength: 5 });
  assert.ok(found.some((item) => item.value.includes(URL)), 'decoded URL missing');
  assert.ok(channelSummary(found).hex >= 1);
});

test('JSON \\u escapes are decoded', () => {
  const escaped = [...URL].map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const buffer = Buffer.from(`{"c2":"${escaped}"}`, 'latin1');
  const found = extractDeepStrings(buffer, { minLength: 5 });
  assert.ok(found.some((item) => item.value.includes(URL)), 'escaped URL missing');
  assert.ok(channelSummary(found)['json-escape'] >= 1);
});

test('a gzip stream is opened instead of being called an encrypted region', () => {
  const buffer = gzipSync(Buffer.from(`{"c2":"${URL}"}`, 'latin1'));
  const report = {};
  const found = extractDeepStrings(buffer, { minLength: 5, report });
  assert.ok(found.some((item) => item.value.includes(URL)), 'gzip payload missing');
  assert.ok((report.containers ?? []).some((item) => item.kind.includes('gzip')));
});

test('IOC types cover the channels malware actually uses', () => {
  const strings = [
    { value: '7482916350:AAH-3xK9pQm2vTn7rLwZs4Yd8eB1cF6gH0jK', offset: 1 },
    { value: 'Global\\OBS-9f3c2a', offset: 2 },
    { value: '2606:4700:4700::1111', offset: 3 },
    { value: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', offset: 4 },
    { value: 'AKIAIOSFODNN7EXAMPLE', offset: 5 },
    { value: 'hxxp://evil[.]example[.]com/gate.php', offset: 6 },
  ];
  const iocs = extractIocs(strings);
  const byType = (type) => iocs.filter((item) => item.type === type).map((item) => item.value);
  assert.equal(byType('telegram')[0], '7482916350:AAH-3xK9pQm2vTn7rLwZs4Yd8eB1cF6gH0jK');
  assert.equal(byType('mutex')[0], 'Global\\OBS-9f3c2a');
  assert.equal(byType('ipv6')[0], '2606:4700:4700::1111');
  assert.equal(byType('bitcoin')[0], 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq');
  assert.equal(byType('aws-key')[0], 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(byType('url')[0], 'http://evil.example.com/gate.php');
});

test('a clock is not an IPv6 address', () => {
  const iocs = extractIocs([{ value: '12:34 and 2026:11:06', offset: 0 }]);
  assert.equal(iocs.filter((item) => item.type === 'ipv6').length, 0);
});

test('the word TLS does not invent a callback the header denies', () => {
  const strings = [{ value: 'TLS handshake failed; see .tls', offset: 0 }];
  const denied = antiAnalysisMatrix(strings, null, null, { tls: { present: true, callbacks: 0 } });
  assert.equal(denied.techniques.some((item) => item.id === 'tls-callback'), false);
  const accepted = antiAnalysisMatrix(strings, null, null, { tls: { present: true, callbacks: 1 } });
  assert.equal(accepted.techniques.some((item) => item.id === 'tls-callback'), true);
  // No PE at all: the string is still the only evidence there is.
  const unknown = antiAnalysisMatrix(strings, null, null, { tls: null });
  assert.equal(unknown.techniques.some((item) => item.id === 'tls-callback'), true);
});

test('peTlsDirectory counts callbacks instead of trusting the directory entry', () => {
  const bytes = Buffer.alloc(0x800);
  bytes.write('MZ', 0, 'latin1');
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'latin1');
  bytes.writeUInt16LE(1, 0x46); // NumberOfSections
  bytes.writeUInt16LE(0xf0, 0x54); // SizeOfOptionalHeader
  bytes.writeUInt16LE(0x20b, 0x58); // PE32+
  bytes.writeBigUInt64LE(0x400000n, 0x58 + 24);
  const directory = 0x58 + 112 + 9 * 8;
  // TLS directory points at RVA 0x1000 inside the .rdata section.
  bytes.writeUInt32LE(0x401000, directory);
  bytes.writeUInt32LE(40, directory + 4);
  const table = 0x58 + 0xf0;
  bytes.write('.rdata', table, 'latin1');
  bytes.writeUInt32LE(0x400, table + 8); // VirtualSize
  bytes.writeUInt32LE(0x1000, table + 12); // VirtualAddress
  bytes.writeUInt32LE(0x400, table + 16); // SizeOfRawData
  bytes.writeUInt32LE(0x180, table + 20); // PointerToRawData
  // IMAGE_TLS_DIRECTORY at RVA 0x1000 -> file offset 0x180; its
  // AddressOfCallbacks (offset 12) points at RVA 0x1040 -> file offset 0x1c0.
  bytes.writeUInt32LE(0x401040, 0x180 + 12);
  const empty = peTlsDirectory(bytes);
  assert.deepEqual({ present: empty.present, callbacks: empty.callbacks }, { present: true, callbacks: 0 });
  bytes.writeUInt32LE(0x401234, 0x1c0);
  const one = peTlsDirectory(bytes);
  assert.equal(one.callbacks, 1);
});

test('a decoy URL is not printed as "the" endpoint', () => {
  const behaviour = assessBehavior({
    imports: null,
    strings: [{ value: 'telemetry endpoint configured', offset: 0 }],
    iocs: [{ type: 'url', value: 'https://www.microsoft.com/security' }, { type: 'url', value: 'https://c2.example-corp.net/gate' }],
  });
  assert.match(behaviour.summary, /2 candidate endpoints, unverified/);
  assert.doesNotMatch(behaviour.summary, /microsoft\.com/);
});

test('sanitize removes AWS keys and Slack webhooks', () => {
  const text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
    + 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
    + 'SLACK-WEBHOOK-PLACEHOLDER\n';
  const env = { user: 'nobody', host: 'nohost', home: 'C:\\nowhere' };
  const kinds = detectLeaks(text, env).map((item) => item.kind).sort();
  assert.deepEqual(kinds, ['aws-access-key', 'aws-secret-key', 'slack-webhook']);
  const clean = sanitizeText(text, env).text;
  assert.equal(clean.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(clean.includes('hooks.slack.com'), false);
});

// ---------------------------------------------------------------- round 2 --

test('a complete PE appended to a carrier is found, with its offset and size', () => {
  const carrier = miniPe();
  const inner = miniPe({ text: Buffer.from('embedded payload text', 'latin1') });
  const combined = Buffer.concat([carrier, inner]);
  const found = findEmbeddedPes(combined);
  assert.equal(found.length, 1);
  assert.equal(found[0].offset, carrier.length);
  assert.equal(found[0].bits, 64);
  assert.equal(found[0].sections, 1);
  assert.ok(found[0].size >= 0x400);
});

test('opcode-level anti-analysis is read from executable code only', () => {
  const code = Buffer.from(`65488b042530000000${'0f31'}${'cd2d'}${'0fa2'}`, 'hex');
  const text = Buffer.concat([code, Buffer.alloc(0x200 - code.length)]);
  const signals = scanCodeSignals(miniPe({ text }));
  const families = new Set(signals.map((signal) => signal.family));
  assert.deepEqual([...families].sort(), ['cpu-hypervisor', 'debugger-trap', 'peb-flags', 'timing']);
  assert.ok(signals.every((signal) => signal.rva >= 0x1000 && signal.section === '.text'));
  // The same bytes in a non-executable part of the file are data, not code.
  const carrier = miniPe();
  const withData = Buffer.concat([carrier, Buffer.from('65488b0425300000000f31cd2d0fa2', 'hex')]);
  assert.equal(scanCodeSignals(withData).length, 0);
});

test('the anti-analysis matrix merges opcode evidence into the right family', () => {
  const report = antiAnalysisMatrix([], null, null, {
    codeSignals: [{ family: 'peb-flags', name: 'mov rax, gs:[0x30] (PEB)', rva: 0x1010 }],
  });
  const peb = report.techniques.find((item) => item.id === 'peb-flags');
  assert.ok(peb);
  assert.match(peb.evidence.join(' '), /0x1010/);
});

test('spaced hex and base32 payloads are opened', () => {
  const spaced = Buffer.from('68 74 74 70 3a 2f 2f 73 70 61 63 65 64 2e 65 78 61 6d 70 6c 65 2e 6f 72 67 2f 61', 'latin1');
  assert.ok(values(spaced).some((value) => value.includes('http://spaced.example.org/a')));
  const base32 = Buffer.from('NB2HI4DTHIXS6YRTGIXGK6DBNVYGYZJNMNXXE4BONZSXIL3C', 'latin1');
  assert.ok(values(base32).some((value) => value.includes('https://b32.example-corp.net/b')));
});

test('JWT, SSH keys and labelled dword addresses are typed', () => {
  const iocs = extractIocs([
    { value: 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', offset: 0 },
    { value: '-----BEGIN OPENSSH PRIVATE KEY-----', offset: 1 },
    { value: 'c2_ip=0xCB00714D', offset: 2 },
    { value: 'ip=3405803837', offset: 3 },
  ]);
  assert.equal(iocs.filter((item) => item.type === 'jwt').length, 1);
  assert.equal(iocs.filter((item) => item.type === 'ssh-key').length, 1);
  assert.deepEqual(iocs.filter((item) => item.type === 'ipv4').map((item) => item.value).sort(),
    ['203.0.113.61', '203.0.113.77']);
});

test('an unlabelled 32-bit constant is not turned into an endpoint', () => {
  const iocs = extractIocs([{ value: 'version=0x00401000 build=3405803837', offset: 0 }]);
  assert.equal(iocs.filter((item) => item.type === 'ipv4').length, 0);
});

// ---------------------------------------------------------------- round 3 --

test('XORed UTF-16LE text is recovered', () => {
  const wide = Buffer.from('https://wide.example-corp.net/beacon', 'utf16le');
  const scrambled = Buffer.from(wide.map((byte) => byte ^ 0x5a));
  const found = values(scrambled);
  assert.ok(found.some((value) => value.includes('https://wide.example-corp.net/beacon')),
    `got: ${found.slice(0, 4).join(' | ')}`);
});

test('hex(gzip(xor4(config))) is followed through all three layers', () => {
  // Same shape as the red-team specimen (the crib pass needs a config with a
  // URL anchor it can align on).
  const plain = Buffer.from(JSON.stringify({
    c2: 'https://chain.example-corp.net/api/collect',
    user: 'r3',
    build: 'stage-4',
  }), 'latin1');
  const key = Buffer.from([0x13, 0x37, 0xbe, 0xef]);
  const scrambled = Buffer.from(plain.map((byte, index) => byte ^ key[index % 4]));
  const encoded = Buffer.from(gzipSync(scrambled).toString('hex'), 'latin1');
  const found = values(encoded);
  assert.ok(found.some((value) => value.includes('https://chain.example-corp.net/api/collect')),
    `got: ${found.slice(0, 4).join(' | ')}`);
});

test('non-HTTP schemes, host:port and UNC paths are typed', () => {
  const iocs = extractIocs([{
    value: 'ws://gate.example-corp.net/socket tcp://45.77.12.9:4444 198.51.100.9:8080 \\\\fileserver\\share\\x.bin',
    offset: 0,
  }]);
  const types = iocs.map((item) => `${item.type}:${item.value}`);
  assert.ok(types.some((value) => value.startsWith('url:ws://')));
  assert.ok(types.some((value) => value.startsWith('url:tcp://')));
  assert.ok(types.some((value) => value === 'hostport:198.51.100.9:8080'));
  assert.ok(types.some((value) => value.startsWith('unc:')));
});

test('a managed assembly is labelled, not reported as native code', () => {
  const profile = structureProfile(miniPe({ clr: true }));
  assert.equal(profile.managed.present, true);
  assert.equal(structureProfile(miniPe()).managed.present, false);
});

test('repetitive decoded data does not explode the salvage regexes', () => {
  // 40 KB of "9." used to make the email rule backtrack for seconds; the bound
  // is what keeps an 8 MB "MZ" file at ~2 s instead of minutes.
  const started = Date.now();
  const found = values(Buffer.from('MZ'.repeat(20480)));
  const elapsed = Date.now() - started;
  assert.ok(found.length <= 4);
  assert.ok(elapsed < 10_000, `took ${elapsed} ms`);
});
