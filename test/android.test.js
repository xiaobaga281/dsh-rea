import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readArchiveIndex, summarizeApk } from '../lib/android.js';
import { summarizeManifest } from '../lib/axml.js';
import { triageBuffer } from '../lib/triage.js';

/** Build a stored-only ZIP, which is all the index reader has to understand. */
function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBytes = Buffer.from(name, 'latin1');
    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    locals.push(local, data);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBytes.copy(central, 46);
    centrals.push(central);
    offset += local.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(directory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, eocd]);
}

const apk = () => buildZip([
  ['AndroidManifest.xml', Buffer.alloc(512, 0)],
  ['classes.dex', Buffer.alloc(2048, 0)],
  ['lib/arm64-v8a/libapp.so', Buffer.alloc(4096, 0)],
  ['lib/arm64-v8a/libcrypto.so', Buffer.alloc(1024, 0)],
  ['resources.arsc', Buffer.alloc(256, 0)],
  ['META-INF/CERT.RSA', Buffer.alloc(64, 0)],
  ['assets/config.json', Buffer.alloc(128, 0)],
]);

test('the index is read from the end, not the front', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-apk-'));
  const file = join(dir, 'sample.apk');
  await writeFile(file, apk());
  try {
    const index = await readArchiveIndex(file);
    assert.equal(index.ok, true);
    assert.equal(index.entries.length, 7);
    assert.ok(index.entries.some((entry) => entry.name === 'AndroidManifest.xml'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a file without an index is refused instead of guessed', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-apk-'));
  const file = join(dir, 'not-a-zip.bin');
  await writeFile(file, Buffer.alloc(4096, 0x41));
  try {
    const index = await readArchiveIndex(file);
    assert.equal(index.ok, false);
    assert.match(index.reason, /end-of-central-directory/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the summary counts what an Android analyst asks for first', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-apk-'));
  const file = join(dir, 'sample.apk');
  await writeFile(file, apk());
  try {
    const summary = summarizeApk(await readArchiveIndex(file), { name: 'sample.apk' });
    assert.equal(summary.dex.count, 1);
    assert.equal(summary.native.count, 2);
    assert.equal(summary.native.abis[0].abi, 'arm64-v8a');
    assert.equal(summary.native.abis[0].count, 2);
    assert.equal(summary.signature.v1, true);
    assert.equal(summary.manifest.name, 'AndroidManifest.xml');
    assert.equal(summary.assets.count, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const elements = (list) => ({ ok: true, elements: list, strings: [] });

test('manifest facts come from attributes, not from string matching', () => {
  const summary = summarizeManifest(elements([
    { name: 'manifest', attributes: { package: 'com.example.app', versionName: '1.2.3', versionCode: 12 } },
    { name: 'uses-sdk', attributes: { minSdkVersion: 26, targetSdkVersion: 34 } },
    { name: 'uses-permission', attributes: { name: 'android.permission.INTERNET' } },
    { name: 'uses-permission', attributes: { name: 'android.permission.CAMERA' } },
    { name: 'application', attributes: { allowBackup: true } },
    { name: 'activity', attributes: { name: '.MainActivity', exported: true } },
  ]));
  assert.equal(summary.package, 'com.example.app');
  assert.equal(summary.versionCode, 12);
  assert.equal(summary.minSdk, 26);
  assert.equal(summary.permissions.count, 2);
  assert.equal(summary.components.exported.length, 1);
  assert.equal(summary.flags.allowBackup, true);
  assert.equal(summary.flags.debuggable, false);
});

test('an archive is not judged as packed code', () => {
  // The end-to-end failure this pins: a 238 MB APK came back as
  // "possibly-obfuscated" with Windows PEB markers and an OEP instruction.
  const buffer = apk();
  const summary = summarizeApk({
    ok: true,
    entries: [
      { name: 'AndroidManifest.xml', compressedSize: 100, uncompressedSize: 512, method: 0 },
      { name: 'classes.dex', compressedSize: 500, uncompressedSize: 2048, method: 0 },
      { name: 'lib/arm64-v8a/libapp.so', compressedSize: 900, uncompressedSize: 4096, method: 0 },
    ],
    signedV2: true,
  }, { name: 'sample.apk' });
  const report = triageBuffer(buffer, { name: 'sample.apk', android: summary });
  assert.equal(report.format, 'apk');
  assert.equal(report.verdict, 'android-package');
  assert.deepEqual(report.antiAnalysis.categories, [], 'no PE anti-analysis markers on a ZIP');
  assert.ok(report.reasons.some((line) => /deflate output/.test(line)));
  assert.equal(report.plan[0].action.startsWith('Decode classes*.dex'), true);
  assert.ok(report.nextSteps[0].includes('Android package'));
  assert.ok(!report.nextSteps.some((line) => /locate the OEP/.test(line)));
});
