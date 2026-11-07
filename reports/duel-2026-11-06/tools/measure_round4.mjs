/** Round-4 measurements: provenance facts + the correlation tool. */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { triageFile } from '../../../lib/triage.js';
import { buildCorrelateSamplesTool } from '../../../lib/analysis-tools.js';
import { recoverCodeView, richHeader, imphashFromImports, entryAnomalies } from '../../../lib/identity.js';
import { parsePEImports } from '../../../lib/intel.js';
import { readPeLayout } from '../../../lib/structure.js';

const CANDIDATES = [
  join(process.env.TEMP ?? '.', 'rea-spec4'),
  join(process.env.USERPROFILE ?? '.', 'AppData', 'Local', 'Temp', 'rea-spec4'),
];
const SPEC = CANDIDATES.find((dir) => existsSync(dir)) ?? CANDIDATES[0];
const p = (name) => join(SPEC, name);
const ok = (flag) => (flag ? 'PASS' : 'FAIL');

// --- baseline: a clean signed Microsoft binary -------------------------------
{
  const report = await triageFile('C:\\Windows\\System32\\whoami.exe');
  const id = report.identity;
  console.log('whoami baseline:');
  console.log(`  imphash=${id.imphash} (${ok(!!id.imphash)})`);
  console.log(`  codeView=${JSON.stringify(id.codeView.map((c) => ({ guid: c.guid, age: c.age, path: c.path })))}`);
  console.log(`  rich=${id.rich === null ? 'null (' + ok(id.rich === null) + ')' : JSON.stringify(id.rich)}`);
  console.log(`  entryIssues=${id.entryIssues.length} (${ok(id.entryIssues.length === 0)}) timestamp=${id.timestamp?.iso}`);
}

// --- R4b: planted CodeView + decoy -------------------------------------------
{
  const report = await triageFile(p('R4b-codeview.exe'));
  const planted = report.identity.codeView.find((c) => c.path === 'C:\\build\\drop4\\Release\\drop4.pdb');
  console.log(`R4b planted record: ${ok(!!planted)} ${JSON.stringify(planted ?? null)}`);
  // mixed-endian check: bytes d4e3f2a1 b5c9 4d8e aa37f1e2d3c4b5a6
  const want = 'a1f2e3d4-c9b5-8e4d-aa37f1e2d3c4b5a6';
  console.log(`  guid formatted: ${planted?.guid === want ? 'PASS' : `FAIL got ${planted?.guid} want ${want}`}`);
  const junk = report.identity.codeView.some((c) => /not-a-pdb/.test(c.path));
  console.log(`  decoy rejected: ${ok(!junk)}`);
}

// --- R4c: real-shaped Rich header --------------------------------------------
{
  const report = await triageFile(p('R4c-rich.exe'));
  const rich = report.identity.rich;
  console.log(`R4c rich: ${ok(rich)} ${JSON.stringify(rich?.entries ?? null)} key=${rich?.key} at=0x${rich?.at?.toString(16)}`);
}

// --- R4d: entry past raw data --------------------------------------------------
{
  const report = await triageFile(p('R4d-entry-gap.exe'));
  const issues = report.identity.entryIssues;
  console.log(`R4d entry issues: ${ok(issues.some((t) => /past the raw data/.test(t)))} -> ${issues.join(' | ') || 'none'}`);
}

// --- correlation tool ----------------------------------------------------------
{
  const tool = buildCorrelateSamplesTool({ maxBytes: 32 * 1024 * 1024, limit: 20, store: null });
  const result = await tool.execute({ directory: SPEC });
  const text = result.text;
  console.log('\n=== rea_correlate_samples ===');
  console.log(text.split('\n').slice(0, 40).join('\n'));
  const clusterFor = (label) => {
    const head = text.split('\n').find((line) => line.startsWith(label));
    return head;
  };
  for (const [label, want] of [
    ['imphash families', /R4a1.*R4a2/],
    ['CodeView PDB GUID', /R4e1-family\.exe, R4e2-family\.exe|R4e2-family\.exe, R4e1-family\.exe/],
    ['PDB build paths', /drop4/],
  ]) {
    const line = clusterFor(label);
    console.log(`\n${ok(line && want.test(text.slice(text.indexOf(line))))} ${label}: ${line ?? 'MISSING'}`);
  }
}
