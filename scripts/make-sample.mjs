/**
 * Build reproducible test samples for a capability dry-run.
 *
 * No compiler is required: `tracked_app.exe` is a structurally valid PE32 with
 * a real IMAGE_IMPORT_DESCRIPTOR chain, mixed ASCII / UTF-16LE / single-byte
 * XOR strings and a high-entropy code section. `clean_app.exe` has the same
 * skeleton without tracking or anti-analysis markers (false-positive control).
 * `tracked_app.js` is a runnable, non-networking source-level version.
 *
 * Run: npm run make-sample [-- --out <dir>]
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const out = process.argv.includes('--out')
  ? process.argv[process.argv.indexOf('--out') + 1]
  : join(tmpdir(), 'rea-samples');
mkdirSync(out, { recursive: true });

const IMPORT_SETS = [
  { dll: 'KERNEL32.dll', apis: ['IsDebuggerPresent', 'GetComputerNameA', 'GetVolumeInformationA', 'GetTickCount', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'GetProcAddress', 'LoadLibraryA', 'OutputDebugStringA', 'QueryPerformanceCounter'] },
  { dll: 'WININET.dll', apis: ['InternetConnectA', 'HttpSendRequestA', 'InternetOpenA'] },
  { dll: 'ADVAPI32.dll', apis: ['RegSetValueExA', 'RegOpenKeyExA', 'CryptEncrypt'] },
];
const CLEAN_IMPORTS = [
  { dll: 'KERNEL32.dll', apis: ['CreateFileA', 'ReadFile', 'CloseHandle'] },
  { dll: 'USER32.dll', apis: ['MessageBoxA'] },
];

const ASCII_STRINGS = [
  'https://telemetry.tracked-app.example/v1/collect',
  'https://api.tracked-app.example/device/register',
  'api.telemetry-cdn.example', '203.0.113.42',
  'analytics@tracked-app.example',
  'FirebaseAnalytics', 'AppsFlyer', 'Sentry.io', 'Mixpanel',
  'navigator.userAgent', 'canvas.toDataURL', 'devicePixelRatio',
  'GetComputerNameA', 'GetVolumeInformationA', 'MachineGuid',
  'android_id', 'AdvertisingIdClient', 'getLastKnownLocation',
  'INSTALL_REFERRER', 'utm_source', 'document.cookie',
  'OAuth', 'openid', 'user_id', 'id_token', 'refresh_token',
  'FCM', 'FirebaseInstanceId', 'deviceToken', 'push_token',
  'installation_id', 'setUserIdentifier', 'app_instance_id', 'session_id',
  'X-Forwarded-For', 'User-Agent:', 'RTCPeerConnection', 'dns.google',
  'logEvent', 'sessionReplay', 'screen_view', 'clickstream',
  'navigator.language', 'timezone_offset', 'navigator.hardwareConcurrency',
  'SecureRandom', 'visitor_id', 'client_id=', 'java.util.UUID',
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'rdtsc', 'QueryPerformanceCounter', 'cpuid', 'VMXh', 'VMware', 'VBox',
  'Sandboxie', 'Cuckoo', 'GetCursorPos', 'frida', 'gum-js-loop',
  'HKLM\\SOFTWARE\\TrackedApp\\InstallId',
  'C:\\Users\\analyst\\AppData\\Local\\TrackedApp\\cache.db',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) tracked-app/3.2',
  'C:\\build\\tracked-app\\Release\\tracked_app.pdb',
  'Authorization: Bearer REDACTED_FOR_TEST',
];
const UTF16_STRINGS = [
  'https://backup-telemetry.tracked-app.example/beacon',
  'IDFA', 'GAID', 'WEBGL_debug_renderer_info', 'Intl.DateTimeFormat',
  'getSubscriberId', 'Crashlytics', 'Bugly', 'VBOX', 'QEMU',
];
const XOR_STRINGS = [
  'https://hidden-c2.tracked-app.example/gate.php',
  'umeng', 'Adjust.com', 'Xposed', 'Magisk', 'TlsCallback',
];
const CLEAN_STRINGS = [
  'TrackedApp clean build', 'https://docs.tracked-app.example/help',
  'C:\\build\\clean\\Release\\clean_app.pdb', '1.0.0',
];

const rvaToFile = (rva) => 0x200 + (rva - 0x1000);

function buildPE({ imports, ascii, utf16, xor, highEntropy }) {
  const size = 0x3400;
  const b = Buffer.alloc(size);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(2, 0x86); // two sections
  b.writeUInt16LE(0xe0, 0x94); // SizeOfOptionalHeader
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt); // PE32
  b.writeUInt32LE(16, opt + 92); // NumberOfRvaAndSizes
  const dd = opt + 96;
  b.writeUInt32LE(0x1000, dd + 8); // import directory RVA
  b.writeUInt32LE(0x80, dd + 12);
  const sec = opt + 0xe0;
  b.write('.rdata\0\0', sec, 'latin1');
  b.writeUInt32LE(0x2000, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x2000, sec + 16);
  b.writeUInt32LE(0x200, sec + 20);
  b.write('.text\0\0\0', sec + 40, 'latin1');
  b.writeUInt32LE(0x1000, sec + 48);
  b.writeUInt32LE(0x3000, sec + 52);
  b.writeUInt32LE(0x1000, sec + 56);
  b.writeUInt32LE(0x2200, sec + 60);

  // Import descriptors at RVA 0x1000, DLL names at 0x1100, thunks at 0x1200,
  // IMAGE_IMPORT_BY_NAME entries at 0x1400.
  let nameRva = 0x1100;
  let thunkRva = 0x1200;
  let byNameRva = 0x1400;
  imports.forEach((entry, index) => {
    const desc = 0x200 + index * 20;
    b.writeUInt32LE(thunkRva, desc);
    b.writeUInt32LE(nameRva, desc + 12);
    b.writeUInt32LE(thunkRva, desc + 16);
    b.write(`${entry.dll}\0`, rvaToFile(nameRva), 'latin1');
    entry.apis.forEach((api, slot) => {
      b.writeUInt32LE(byNameRva, rvaToFile(thunkRva) + slot * 4);
      const at = rvaToFile(byNameRva);
      b.writeUInt16LE(slot, at);
      b.write(`${api}\0`, at + 2, 'latin1');
      byNameRva += 4 + api.length;
      byNameRva += (4 - (byNameRva % 4)) % 4;
    });
    nameRva += entry.dll.length + 8;
    thunkRva += 0x80;
  });

  // Strings: plain ASCII, UTF-16LE, and single-byte XOR (key 0x5a).
  let cursor = 0xa00;
  const emit = (buffer) => {
    if (cursor + buffer.length > 0x2200) return;
    buffer.copy(b, cursor);
    cursor += buffer.length + 1;
  };
  for (const text of ascii) emit(Buffer.from(`${text}\0`, 'latin1'));
  for (const text of utf16) {
    // Real wide strings are NUL-terminated; keep that separator so consecutive
    // UTF-16 values are separate findings instead of one 300-char blob.
    const wide = Buffer.alloc(text.length * 2 + 2);
    for (let i = 0; i < text.length; i += 1) { wide[i * 2] = text.charCodeAt(i); wide[i * 2 + 1] = 0; }
    if (cursor + wide.length > 0x2200) continue;
    wide.copy(b, cursor);
    cursor += wide.length;
  }
  for (const text of xor) {
    const raw = Buffer.from(`${text}\0`, 'latin1');
    for (let i = 0; i < raw.length; i += 1) raw[i] ^= 0x5a;
    emit(raw);
  }
  if (highEntropy) {
    let seed = 0x12345678;
    for (let at = 0x2200; at < size; at += 1) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      b[at] = seed >>> 24;
    }
  } else {
    b.fill(0x41, 0x2200, 0x2400);
  }
  b.writeUInt32LE(0x4000, 0x98 + 56); // SizeOfImage covers .rdata + .text
  return b;
}

const tracked = buildPE({ imports: IMPORT_SETS, ascii: ASCII_STRINGS, utf16: UTF16_STRINGS, xor: XOR_STRINGS, highEntropy: true });
const clean = buildPE({ imports: CLEAN_IMPORTS, ascii: CLEAN_STRINGS, utf16: [], xor: [], highEntropy: false });
writeFileSync(join(out, 'tracked_app.exe'), tracked);
writeFileSync(join(out, 'clean_app.exe'), clean);

const jsSource = `// Runnable source-level twin of tracked_app.exe. Never connects anywhere.
'use strict';
const crypto = require('node:crypto');
const os = require('node:os');
function deviceFingerprint() {
  return {
    hostname: os.hostname(), platform: os.platform(), arch: os.arch(),
    cpus: os.cpus().length, totalmem: os.totalmem(), timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    userAgent: 'Mozilla/5.0 tracked-app/3.2', canvasHash: crypto.createHash('sha256').update('canvas').digest('hex'),
  };
}
function telemetryPayload() {
  return { event: 'app_open', installId: crypto.randomUUID(), advertisingId: 'GAID-placeholder', ...deviceFingerprint() };
}
function antiAnalysis() {
  const started = process.hrtime.bigint();
  if (process.env.NODE_OPTIONS && process.env.NODE_OPTIONS.includes('inspect')) return 'debugger-suspected';
  return (process.hrtime.bigint() - started) > 100000000n ? 'timing-anomaly' : 'ok';
}
const endpoints = ['https://telemetry.tracked-app.example/v1/collect', 'https://backup-telemetry.tracked-app.example/beacon'];
console.log(JSON.stringify({ payload: telemetryPayload(), anti: antiAnalysis(), endpoints, xorKey: 0x5a }, null, 2));
`;
writeFileSync(join(out, 'tracked_app.js'), jsSource);

const expectations = {
  tracking: ['analytics-sdk', 'ad-id', 'device-fingerprint', 'browser-fingerprint', 'geo', 'identity-gen', 'network-id', 'storage-tracking', 'attribution', 'account-linkage', 'push-token', 'crash-identity', 'network-identity', 'behaviour-telemetry', 'locale-time'],
  anti: ['debugger-api', 'timing', 'cpu-hypervisor', 'vm-artifacts', 'sandbox-env', 'hook-detection', 'tls-callback'],
  iocTypes: ['url', 'domain', 'ipv4', 'email', 'registry', 'pdb', 'winpath', 'useragent'],
  imports: ['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread', 'InternetConnectA', 'RegSetValueExA', 'CryptEncrypt'],
  capabilities: ['T1055', 'T1071', 'T1547', 'T1082'],
  hidden: ['hidden-c2.tracked-app.example', 'Adjust.com', 'Xposed', 'TlsCallback', 'backup-telemetry.tracked-app.example'],
  exposure: ['Account / login identity', 'Network egress identity', '0.0.0.0 telemetry.tracked-app.example', 'preflight checklist'],
};
writeFileSync(join(out, 'expectations.json'), `${JSON.stringify(expectations, null, 2)}\n`);
console.log(`samples written to ${out}`);
console.log(`  tracked_app.exe ${tracked.length} bytes | clean_app.exe ${clean.length} bytes | tracked_app.js`);
