import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { CorpusDataError, scanCorpus } from '../scripts/corpus/scan.mjs';
import { verifyCorpusBuffer } from '../scripts/corpus/fetch.mjs';
import { redactSensitive } from '../lib/infra/redact.js';

const digest = (buffer) => createHash('sha256').update(buffer).digest('hex');

const fakeTools = (savedPath, overrides = {}) => new Map([
  ['rea_ioc_extract', { execute: async () => ({ text: `strings sampled: 2 (ascii)\nindicators: 1\nfull JSON: ${savedPath}` }) }],
  ['rea_tracking_surface', { execute: async () => ({ text: 'level: low\ncategories: none' }) }],
  ['rea_anti_analysis', { execute: async () => ({ text: 'techniques: 0' }) }],
  ['rea_analyst_exposure', { execute: async () => ({ text: 'level: low' }) }],
  ...Object.entries(overrides).map(([name, value]) => [name, { execute: value }]),
]);

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-corpus-gate-'));
  const buffer = Buffer.from('MZ synthetic corpus bytes');
  const target = join(dir, 'sample.exe');
  const savedPath = join(dir, 'ioc.json');
  const manifestPath = join(dir, 'manifest.json');
  await writeFile(target, buffer);
  await writeFile(savedPath, JSON.stringify({
    file: target, fileSize: buffer.length, size: buffer.length, sha256: digest(buffer), truncated: false,
    coverage: { complete: true, exhaustive: false, stringCount: 2, maxStrings: 4000, derivedWindows: 1, derivedScanBounded: false },
    iocs: [{ type: 'url', value: 'example.invalid' }],
  }));
  const manifest = {
    schemaVersion: 1,
    files: [{
      name: 'sample.exe', project: 'fixture', license: 'MIT', url: 'https://example.invalid/source',
      bytes: buffer.length, sha256: digest(buffer),
    }],
    totalBytes: buffer.length,
  };
  await writeFile(manifestPath, JSON.stringify(manifest));
  return { dir, buffer, target, savedPath, manifestPath, manifest };
}

test('recon corpus mode requires an explicit gate for manifests and rejects gate directories', async () => {
  const item = await fixture();
  try {
    const manifestWithoutGate = spawnSync(process.execPath, ['scripts/recon/run.mjs', '--corpus', item.manifestPath], { encoding: 'utf8' });
    assert.equal(manifestWithoutGate.status, 2);
    assert.match(manifestWithoutGate.stderr, /pass --gate explicitly/);
    const directoryWithGate = spawnSync(process.execPath, ['scripts/recon/run.mjs', '--corpus', item.dir, '--gate'], { encoding: 'utf8' });
    assert.equal(directoryWithGate.status, 2);
    assert.match(directoryWithGate.stderr, /not an inventory directory/);
    const empty = spawnSync(process.execPath, ['scripts/recon/run.mjs', '--corpus', join(item.dir, 'empty')], { encoding: 'utf8' });
    assert.equal(empty.status, 2);
    assert.match(empty.stderr, /no .exe\/.dll files/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('recon corpus mode rejects a matching directory instead of silently dropping its row', async () => {
  const item = await fixture();
  try {
    await mkdir(join(item.dir, 'fake.exe'));
    const run = spawnSync(process.execPath, ['scripts/recon/run.mjs', '--corpus', item.dir, '--out', join(item.dir, 'out')], { encoding: 'utf8' });
    assert.equal(run.status, 1);
    assert.match(`${run.stdout}\n${run.stderr}`, /fake\.exe is not a regular file/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus cache verification accepts only the pinned PE bytes', () => {
  const buffer = Buffer.from('MZ pinned bytes');
  const source = { bytes: buffer.length, sha256: digest(buffer) };
  assert.equal(verifyCorpusBuffer(source, buffer).ok, true);
  const changed = Buffer.from(buffer);
  changed[changed.length - 1] ^= 1;
  assert.match(verifyCorpusBuffer(source, changed).reason, /SHA-256/);
  assert.match(verifyCorpusBuffer(source, Buffer.concat([buffer, Buffer.from('x')])).reason, /size/);
  assert.match(verifyCorpusBuffer(source, Buffer.from('not a PE')).reason, /not a PE/);
});

test('corpus scan gate passes a fully measured and identity-bound fixture', async () => {
  const item = await fixture();
  try {
    const report = await scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), gate: true, writeReport: false });
    assert.equal(report.exit, 0, report.gate.dataErrors.join('; '));
    assert.equal(report.gate.passed, true);
    assert.equal(report.summary.files, 1);
    assert.equal(report.rows[0].indicators, 1);
    assert.equal(report.corpus[0].provenance, 'https://example.invalid/source');
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate asks for the complete IOC pass instead of accepting a default cap', async () => {
  const item = await fixture();
  try {
    let requested = null;
    const tools = fakeTools(item.savedPath, {
      rea_ioc_extract: async (args) => {
        requested = args;
        return { text: `strings sampled: 2 (ascii)\nindicators: 1\nfull JSON: ${item.savedPath}` };
      },
    });
    const report = await scanCorpus({ ...item, toolMap: tools, gate: true, writeReport: false });
    assert.equal(report.exit, 0, report.gate.dataErrors.join('; '));
    assert.equal(requested.maxStrings, 200_000);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate restores redacted artifact handles before reading saved JSON', async () => {
  const item = await fixture();
  try {
    const report = await scanCorpus({
      ...item, toolMap: fakeTools(redactSensitive(item.savedPath)), gate: true, writeReport: false,
    });
    assert.equal(report.exit, 0, report.gate.dataErrors.join('; '));
    assert.equal(report.rows[0].sampleIndicators[0], 'url:example.invalid');
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate rejects same-size tampering and never skips a missing file', async () => {
  const item = await fixture();
  try {
    const changed = Buffer.from(item.buffer);
    changed[changed.length - 1] ^= 1;
    await writeFile(item.target, changed);
    const tampered = await scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), gate: true, writeReport: false });
    assert.equal(tampered.exit, 1);
    assert.match(tampered.gate.dataErrors.join(' '), /SHA-256/);
    await rm(item.target);
    const missing = await scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), gate: true, writeReport: false });
    assert.equal(missing.exit, 1);
    assert.equal(missing.summary.files, 1);
    assert.match(missing.gate.dataErrors.join(' '), /identity unreadable/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate rejects target replacement during static analysis', async () => {
  const item = await fixture();
  try {
    const changed = Buffer.from(item.buffer);
    changed[changed.length - 1] ^= 1;
    const tools = fakeTools(item.savedPath, {
      rea_ioc_extract: async () => {
        await writeFile(item.target, changed);
        return { text: `strings sampled: 2 (ascii)\nindicators: 1\nfull JSON: ${item.savedPath}` };
      },
    });
    const report = await scanCorpus({ ...item, toolMap: tools, gate: true, writeReport: false });
    assert.equal(report.exit, 1);
    assert.match(report.gate.dataErrors.join(' '), /target changed during corpus analysis/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate binds saved IOC evidence to exact target bytes and reported count', async () => {
  const item = await fixture();
  try {
    for (const [mutate, expected] of [
      [(value) => { value.sha256 = 'f'.repeat(64); }, /saved IOC SHA-256/],
      [(value) => { value.file = join(item.dir, 'other.exe'); }, /saved IOC file/],
      [(value) => { value.truncated = true; }, /saved IOC analysis was truncated/],
      [(value) => { value.coverage.complete = false; }, /coverage metadata is missing or incomplete/],
      [(value) => { value.coverage.stringCount = 3; }, /saved IOC string count 3 != reported 2/],
    ]) {
      const value = JSON.parse(await readFile(item.savedPath, 'utf8'));
      mutate(value);
      await writeFile(item.savedPath, JSON.stringify(value));
      const report = await scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), gate: true, writeReport: false });
      assert.equal(report.exit, 1);
      assert.match(report.gate.dataErrors.join(' '), expected);
    }
    const value = JSON.parse(await readFile(item.savedPath, 'utf8'));
    value.truncated = false;
    value.coverage.complete = true;
    value.coverage.stringCount = 2;
    value.sha256 = digest(item.buffer);
    value.file = item.target;
    await writeFile(item.savedPath, JSON.stringify(value));
    const countTools = fakeTools(item.savedPath, {
      rea_ioc_extract: async () => ({ text: `strings sampled: 2 (ascii)\nindicators: 2\nfull JSON: ${item.savedPath}` }),
    });
    const report = await scanCorpus({ ...item, toolMap: countTools, gate: true, writeReport: false });
    assert.equal(report.exit, 1);
    assert.match(report.gate.dataErrors.join(' '), /saved IOC count 1 != reported 2/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan gate treats missing tools, markers and malformed saved JSON as data errors', async () => {
  const item = await fixture();
  try {
    await writeFile(item.savedPath, '{broken');
    const missingTool = fakeTools(item.savedPath, { rea_anti_analysis: () => { throw new Error('missing'); } });
    missingTool.delete('rea_tracking_surface');
    const report = await scanCorpus({ ...item, toolMap: missingTool, gate: true, writeReport: false });
    assert.equal(report.exit, 1);
    const errors = report.gate.dataErrors.join(' ');
    assert.match(errors, /missing tool/);
    assert.match(errors, /anti: missing/);
    assert.match(errors, /saved JSON unreadable/);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan classifies malformed manifests and report-write failures as data errors', async () => {
  const item = await fixture();
  const script = fileURLToPath(new URL('../scripts/corpus/scan.mjs', import.meta.url));
  try {
    await writeFile(item.manifestPath, '{');
    const malformed = spawnSync(process.execPath, [script, '--manifest', item.manifestPath], { encoding: 'utf8' });
    assert.equal(malformed.status, 1);
    assert.match(malformed.stderr, /manifest is unreadable or invalid/);
    for (const value of [{ schemaVersion: 99, files: [] }, { schemaVersion: 1, files: [null] }]) {
      await writeFile(item.manifestPath, JSON.stringify(value));
      const invalidStructure = spawnSync(process.execPath, [script, '--manifest', item.manifestPath], { encoding: 'utf8' });
      assert.equal(invalidStructure.status, 1);
      assert.match(invalidStructure.stderr, /corpus manifest/);
    }
    await writeFile(item.manifestPath, JSON.stringify(item.manifest));
    await assert.rejects(
      () => scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), out: item.dir }),
      (error) => error instanceof CorpusDataError && /report could not be written/.test(error.message),
    );
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});

test('corpus scan rejects empty manifests and missing provenance', async () => {
  const item = await fixture();
  try {
    await writeFile(item.manifestPath, JSON.stringify({ schemaVersion: 1, files: [], totalBytes: 0 }));
    await assert.rejects(() => scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), writeReport: false }), /at least one file/);
    await writeFile(item.manifestPath, JSON.stringify(item.manifest));
    delete item.manifest.files[0].license;
    await writeFile(item.manifestPath, JSON.stringify(item.manifest));
    const report = await scanCorpus({ ...item, toolMap: fakeTools(item.savedPath), gate: true, writeReport: false });
    assert.equal(report.exit, 1);
    assert.match(report.gate.dataErrors.join(' '), /license or source provenance/);
    assert.equal((await readFile(item.manifestPath, 'utf8')).includes('sample.exe'), true);
  } finally {
    await rm(item.dir, { recursive: true, force: true });
  }
});
