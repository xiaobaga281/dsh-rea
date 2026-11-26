/**
 * Run the shipped static tools over the pinned corpus and record capability
 * measurements, identity binding and an optional release-gate verdict.
 *
 * @module dsh-rea-restore/scripts/corpus/scan
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { identifyFile } from '../../lib/infra/evidence.js';
import { restoreSensitive } from '../../lib/infra/redact.js';
import { loadTools } from '../duel/attacker.mjs';

const textOf = (result) => (typeof result?.text === 'string' ? result.text : '');
const firstMatch = (text, re) => (text.match(re) ?? [])[1] ?? null;
// The release gate fails a capped IOC pass. Ask for the tool's highest
// supported cap; a target that still reaches it is reported, not scored.
const CORPUS_MAX_STRINGS = 200_000;

export class CorpusDataError extends Error {}

export async function scanCorpus({
  manifestPath = join('dist', 'corpus', 'manifest.json'),
  corpusRoot = dirname(resolve(manifestPath)),
  toolMap = null,
  out = join('dist', 'corpus', 'scan.json'),
  gate = false,
  writeReport = true,
} = {}) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    throw new CorpusDataError(`corpus manifest is unreadable or invalid: ${error?.message ?? error}`);
  }
  const dataErrors = [];
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.files) || manifest.files.length === 0) {
    throw new CorpusDataError('corpus manifest must use schemaVersion 1 and contain at least one file');
  }
  if (manifest.files.some((file) => file === null || typeof file !== 'object' || Array.isArray(file))) {
    throw new CorpusDataError('corpus manifest file entries must be objects');
  }
  const names = new Set();
  for (const file of manifest.files) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(file.name ?? '') || names.has(file.name)) {
      dataErrors.push(`invalid or duplicate corpus name: ${file.name ?? 'missing'}`);
    }
    names.add(file.name);
    if (!Number.isInteger(file.bytes) || file.bytes < 1 || !/^[a-f0-9]{64}$/i.test(file.sha256 ?? '')) {
      dataErrors.push(`${file.name}: invalid size or SHA-256`);
    }
    if (typeof file.license !== 'string' || file.license.trim() === '' || typeof file.url !== 'string' || file.url.trim() === '') {
      dataErrors.push(`${file.name}: license or source provenance is missing`);
    }
  }
  const expectedBytes = manifest.files.reduce((sum, file) => sum + (Number.isInteger(file.bytes) ? file.bytes : 0), 0);
  if (manifest.totalBytes !== expectedBytes) dataErrors.push(`manifest totalBytes ${manifest.totalBytes} != ${expectedBytes}`);

  const tools = toolMap ?? await loadTools();
  const call = async (name, args) => {
    const tool = tools.get(name);
    if (!tool?.execute) return { text: '', ms: 0, error: 'missing tool' };
    const started = process.hrtime.bigint();
    try {
      const text = textOf(await tool.execute(args));
      return { text, ms: Number(process.hrtime.bigint() - started) / 1e6 };
    } catch (error) {
      return { text: '', ms: Number(process.hrtime.bigint() - started) / 1e6, error: error?.message ?? String(error) };
    }
  };

  const rows = [];
  for (const file of manifest.files) {
    const path = isAbsolute(file.name) ? file.name : join(corpusRoot, file.name);
    const errors = [];
    let identity = null;
    try {
      identity = await identifyFile(path);
      if (identity.size !== file.bytes) errors.push(`size ${identity.size} != manifest ${file.bytes}`);
      if (identity.sha256.toLowerCase() !== String(file.sha256).toLowerCase()) errors.push('SHA-256 does not match manifest');
    } catch (error) {
      errors.push(`identity unreadable: ${error?.message ?? error}`);
    }
    if (errors.length > 0) {
      rows.push({ name: file.name, project: file.project ?? null, bytes: file.bytes, sha256: file.sha256, errors, dataErrors: [...errors] });
      continue;
    }

    const ioc = await call('rea_ioc_extract', { path, detail: true, maxStrings: CORPUS_MAX_STRINGS });
    const tracking = await call('rea_tracking_surface', { path });
    const anti = await call('rea_anti_analysis', { path });
    const exposure = await call('rea_analyst_exposure', { path });
    try {
      const after = await identifyFile(path);
      if (after.size !== file.bytes || after.sha256.toLowerCase() !== String(file.sha256).toLowerCase()) {
        errors.push('target changed during corpus analysis');
      }
    } catch (error) {
      errors.push(`target identity unreadable after corpus analysis: ${error?.message ?? error}`);
    }
    for (const [label, item] of [['ioc', ioc], ['tracking', tracking], ['anti', anti], ['exposure', exposure]]) {
      if (item.error) errors.push(`${label}: ${item.error}`);
    }
    const markers = [
      ['ioc', ioc, /strings sampled:/], ['ioc', ioc, /indicators:/],
      ['tracking', tracking, /level:/], ['anti', anti, /techniques:/], ['exposure', exposure, /level:/],
    ];
    for (const [label, item, marker] of markers) {
      if (!item.error && !marker.test(item.text)) errors.push(`${label}: report marker missing`);
    }
    const savedMatch = ioc.text.match(/full JSON:\s*(.+)\s*$/m);
    let saved = null;
    if (!ioc.error) {
      if (!savedMatch) errors.push('ioc: full JSON path missing');
      else {
        try {
          const savedPath = restoreSensitive(savedMatch[1].trim());
          saved = JSON.parse(readFileSync(isAbsolute(savedPath) ? savedPath : resolve(savedPath), 'utf8'));
          if (!Array.isArray(saved.iocs)) errors.push('ioc: saved JSON has no iocs array');
          if (typeof saved.file !== 'string' || resolve(saved.file) !== resolve(path)) errors.push('ioc: saved IOC file does not match the target');
          if (saved.fileSize !== file.bytes || saved.size !== file.bytes) errors.push('ioc: saved IOC size does not match the target');
          if (typeof saved.sha256 !== 'string' || saved.sha256.toLowerCase() !== String(file.sha256).toLowerCase()) errors.push('ioc: saved IOC SHA-256 does not match the target');
          if (saved.truncated === true) errors.push('ioc: saved IOC analysis was truncated');
          if (saved.coverage?.complete !== true || saved.coverage?.exhaustive !== false) errors.push('ioc: saved IOC coverage metadata is missing or incomplete');
          const reportedStrings = Number(firstMatch(ioc.text, /strings sampled: (\d+)/) ?? Number.NaN);
          if (saved.coverage?.stringCount !== reportedStrings) errors.push(`ioc: saved IOC string count ${saved.coverage?.stringCount ?? 'missing'} != reported ${reportedStrings}`);
          const reportedIndicators = Number(firstMatch(ioc.text, /indicators: (\d+)/) ?? Number.NaN);
          if (saved.iocs.length !== reportedIndicators) errors.push(`ioc: saved IOC count ${saved.iocs.length} != reported ${reportedIndicators}`);
        } catch (error) {
          errors.push(`ioc: saved JSON unreadable (${error?.message ?? error})`);
        }
      }
    }
    const byType = {};
    for (const item of saved?.iocs ?? []) byType[item.type] = (byType[item.type] ?? 0) + 1;
    const mb = file.bytes / (1024 * 1024);
    const totalMs = ioc.ms + tracking.ms + anti.ms + exposure.ms;
    rows.push({
      name: file.name, project: file.project, bytes: file.bytes, sha256: file.sha256,
      ms: { ioc: Math.round(ioc.ms), tracking: Math.round(tracking.ms), anti: Math.round(anti.ms), exposure: Math.round(exposure.ms), total: Math.round(totalMs) },
      msPerMb: Number((totalMs / Math.max(mb, 0.01)).toFixed(0)),
      errors,
      dataErrors: [...errors],
      strings: Number(firstMatch(ioc.text, /strings sampled: (\d+)/) ?? 0),
      iocCoverage: saved?.coverage ?? null,
      channels: firstMatch(ioc.text, /strings sampled: \d+ \(([^)]*)\)/) ?? '',
      indicators: Number(firstMatch(ioc.text, /indicators: (\d+)/) ?? 0),
      byType,
      trackingLevel: firstMatch(tracking.text, /level: (\w+)/) ?? 'unknown',
      trackingCategories: firstMatch(tracking.text, /categories: (.+)/) ?? '',
      antiTechniques: Number(firstMatch(anti.text, /techniques: (\d+)/) ?? 0),
      exposureLevel: firstMatch(exposure.text, /level: (\w+)/) ?? 'unknown',
      unresolved: /unresolved encrypted region/.test(ioc.text),
      sampleIndicators: (saved?.iocs ?? []).slice(0, 12).map((item) => `${item.type}:${item.value}`),
    });
  }
  const allDataErrors = [
    ...dataErrors,
    ...rows.flatMap((row) => (row.dataErrors ?? []).map((error) => `${row.name}: ${error}`)),
  ];
  const report = {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    toolVersion: JSON.parse(readFileSync('package.json', 'utf8')).version,
    mode: gate ? 'release-gate' : 'capability-report',
    corpus: manifest.files.map(({ name, sha256, bytes, project, license, url }) => ({ name, sha256, bytes, project, license, provenance: url })),
    rows,
    gate: { requested: gate, passed: allDataErrors.length === 0, dataErrors: allDataErrors },
    summary: {
      files: rows.length,
      errors: rows.filter((row) => row.errors.length > 0).length,
      dataErrors: allDataErrors.length,
      meanMsPerMb: Math.round(rows.reduce((sum, row) => sum + (row.msPerMb ?? 0), 0) / Math.max(rows.length, 1)),
      slowest: rows.filter((row) => typeof row.msPerMb === 'number').reduce((worst, row) => (!worst || row.msPerMb > worst.msPerMb ? row : worst), null)?.name ?? null,
      highTrackingOnBenign: rows.filter((row) => ['high', 'critical'].includes(row.trackingLevel)).map((row) => row.name),
      unresolvedFlags: rows.filter((row) => row.unresolved).map((row) => row.name),
    },
  };
  if (writeReport) {
    try {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
    } catch (error) {
      throw new CorpusDataError(`corpus report could not be written: ${error?.message ?? error}`);
    }
  }
  return { ...report, exit: allDataErrors.length === 0 ? 0 : 1 };
}

async function main() {
  const args = process.argv.slice(2);
  const valueOf = (flag, fallback) => {
    const index = args.indexOf(flag);
    return index === -1 ? fallback : args[index + 1];
  };
  try {
    const report = await scanCorpus({
      manifestPath: valueOf('--manifest', join('dist', 'corpus', 'manifest.json')),
      out: valueOf('--out', join('dist', 'corpus', 'scan.json')),
      gate: args.includes('--gate'),
    });
    console.log(`\nfiles ${report.summary.files}  errors ${report.summary.errors}  data errors ${report.summary.dataErrors}  mean ${report.summary.meanMsPerMb} ms/MB  slowest ${report.summary.slowest}`);
    console.log(`high tracking on benign: ${report.summary.highTrackingOnBenign.join(', ') || 'none'}`);
    console.log(`unresolved flags: ${report.summary.unresolvedFlags.join(', ') || 'none'}`);
    for (const error of report.gate.dataErrors) console.log(`FAIL ${error}`);
    console.log(`json ${resolve(valueOf('--out', join('dist', 'corpus', 'scan.json')))}`);
    return report.exit;
  } catch (error) {
    console.error(`corpus scan could not run: ${error?.message ?? error}`);
    return error instanceof CorpusDataError ? 1 : 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exit(await main());
}
