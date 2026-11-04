/**
 * Triage calibration report.
 *
 * IMPORTANT: the built-in corpus is synthetic. Its hit rate measures the
 * heuristic against its own assumptions, NOT real-world packer detection.
 * To get a publishable number, pass a labelled directory:
 *
 *   node scripts/triage-baseline.mjs --corpus /abs/path
 *   /abs/path/packed/*   protected or packed samples (positive)
 *   /abs/path/clean/*    ordinary binaries and installers (negative)
 *
 * Without --corpus the script still prints the synthetic matrix so regressions
 * in the heuristic are visible, but labels the number as synthetic.
 */
import { readdir, stat, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

import { triageBuffer, triageFile } from '../lib/triage.js';

function fakePE({ sectionName = '.text', virtualSize = 0x1000, rawSize = 0x1000 } = {}) {
  const bytes = Buffer.alloc(0x400);
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'latin1');
  const coff = 0x44;
  bytes.writeUInt16LE(1, coff + 2);
  bytes.writeUInt16LE(0xe0, coff + 16);
  const optional = coff + 20;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(0x1000, optional + 16);
  const table = optional + 0xe0;
  bytes.write(sectionName.slice(0, 8), table, 'latin1');
  bytes.writeUInt32LE(virtualSize, table + 8);
  bytes.writeUInt32LE(0x1000, table + 12);
  bytes.writeUInt32LE(rawSize, table + 16);
  bytes.writeUInt32LE(0x200, table + 20);
  return bytes;
}

const SYNTHETIC = [
  { label: 'packed', name: 'upx-section', bytes: fakePE({ sectionName: 'UPX0', virtualSize: 0x10000, rawSize: 0x100 }) },
  { label: 'packed', name: 'high-entropy', bytes: (() => {
    const b = Buffer.alloc(16 * 1024);
    for (let i = 0; i < b.length; i += 1) b[i] = (i * 251 + (i >> 3) * 7) & 0xff;
    return b;
  })() },
  { label: 'packed', name: 'vmp-signature', bytes: Buffer.concat([Buffer.from('.vmp0 VMProtect begin'), Buffer.alloc(2048, 0x41)]) },
  { label: 'clean', name: 'plain-pe', bytes: fakePE() },
  { label: 'clean', name: 'plain-text', bytes: Buffer.from('This is an ordinary readme with words and sentences. '.repeat(300)) },
  { label: 'clean', name: 'dex-header', bytes: Buffer.concat([Buffer.from('dex\n035\0'), Buffer.alloc(1024, 0x41)]) },
  { label: 'clean', name: 'wasm-header', bytes: Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), Buffer.alloc(1024, 0x41)]) },
];

function verdictOf(report) {
  return report.verdict === 'appears-unpacked' ? 'clean' : 'packed';
}

function matrix(rows) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  for (const row of rows) {
    if (row.label === 'packed' && row.predicted === 'packed') tp += 1;
    else if (row.label === 'clean' && row.predicted === 'packed') fp += 1;
    else if (row.label === 'clean' && row.predicted === 'clean') tn += 1;
    else fn += 1;
  }
  const total = rows.length || 1;
  return {
    tp, fp, tn, fn,
    detectionRate: Number(((tp + fn) > 0 ? tp / (tp + fn) : 0).toFixed(3)),
    falsePositiveRate: Number(((fp + tn) > 0 ? fp / (fp + tn) : 0).toFixed(3)),
    accuracy: Number(((tp + tn) / total).toFixed(3)),
  };
}

const args = process.argv.slice(2);
const corpusIndex = args.indexOf('--corpus');
const outIndex = args.indexOf('--out');
const corpus = corpusIndex >= 0 ? args[corpusIndex + 1] : null;
const out = outIndex >= 0 ? args[outIndex + 1] : null;

const syntheticRows = SYNTHETIC.map((sample) => {
  const report = triageBuffer(sample.bytes, { name: sample.name });
  return { name: sample.name, label: sample.label, predicted: verdictOf(report), confidence: report.confidence, format: report.format };
});

let corpusRows = [];
let corpusNote = 'No labelled corpus supplied (--corpus /abs/path).';
if (corpus) {
  if (!isAbsolute(corpus)) throw new Error('--corpus must be an absolute path');
  for (const [label, subdir] of [['packed', 'packed'], ['clean', 'clean']]) {
    let names = [];
    try { names = await readdir(join(corpus, subdir)); } catch { continue; }
    for (const name of names.slice(0, 200)) {
      const path = join(corpus, subdir, name);
      let info;
      try { info = await stat(path); } catch { continue; }
      if (!info.isFile()) continue;
      try {
        const report = await triageFile(path);
        corpusRows.push({ name, label, predicted: verdictOf(report), confidence: report.confidence, format: report.format });
      } catch (error) {
        corpusRows.push({ name, label, predicted: 'error', confidence: 0, format: error.message.slice(0, 60) });
      }
    }
  }
  corpusNote = corpusRows.length > 0
    ? `Labelled corpus: ${corpusRows.length} files from ${corpus}.`
    : `No readable files found under ${corpus}/packed and ${corpus}/clean.`;
}

const lines = [
  '# rea_triage calibration',
  '',
  `Generated: ${new Date().toISOString()}`,
  `Platform: ${process.platform} / node ${process.version}`,
  '',
  '## Synthetic regression set',
  '',
  ...syntheticRows.map((row) => `- ${row.name.padEnd(16)} label=${row.label.padEnd(6)} predicted=${row.predicted.padEnd(6)} confidence=${row.confidence} format=${row.format}`),
  '',
  `synthetic matrix: ${JSON.stringify(matrix(syntheticRows))}`,
  '',
  '> These numbers are NOT a real-world detection rate. The samples were constructed to exercise the heuristic itself.',
  '',
  '## Labelled corpus',
  '',
  corpusNote,
  ...(corpusRows.length > 0 ? [
    '',
    `corpus matrix: ${JSON.stringify(matrix(corpusRows))}`,
    '',
    'Acceptance target from the capability review: detection >= 0.70, false-positive rate <= 0.10.',
    'Installers and compressed resources are the main false-positive source; add them to `clean/` to measure it.',
  ] : []),
  '',
  '## Known blind spots',
  '',
  '- No code is executed, so custom/VM protectors without plaintext markers are missed.',
  '- Only single-byte XOR over the first 64 KB is probed; multi-byte, RC4 and AES configs are not.',
  '- Strings are sampled (120 max) and files are read to a 64 MB cap by default.',
  '- APK/DEX/WASM are identified as containers but their internals are not parsed here.',
];

const body = `${lines.join('\n')}\n`;
if (out) await writeFile(out, body, 'utf8');
console.log(body);
