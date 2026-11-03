import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildExportReportTool, buildPurgeArtifactsTool, buildTriageTool } from '../lib/analysis-tools.js';
import { createArtifactStore } from '../lib/artifacts.js';

const BUNDLE = {
  target: '/samples/a.exe',
  evidence: [{ id: 'E1', observation: 'decodes a blob', limitation: 'static only', kind: 'decompiler-inference' }],
  unknowns: [{ id: 'U1', question: 'Is it C2?', severity: 'high', required_authority_level: 'dynamic-trace' }],
};

async function withStore(run) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-rea-extra-'));
  try {
    await run(createArtifactStore({ root }), root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('rea_triage refuses a relative path before touching the filesystem', async () => {
  const tool = buildTriageTool({});
  await assert.rejects(tool.execute({ path: 'relative.exe' }), /absolute/i);
});

test('rea_triage reports a verdict and next steps for a real file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-triage-tool-'));
  try {
    const path = join(dir, 'sample.bin');
    const bytes = Buffer.alloc(4096);
    bytes.write('UPX0', 100, 'latin1');
    bytes.write('VMProtect', 200, 'latin1');
    await writeFile(path, bytes);
    const { report } = await buildTriageTool({}).execute({ path });
    assert.match(report, /REA static triage/);
    assert.match(report, /verdict: likely-packed-or-protected/);
    assert.match(report, /UPX/);
    assert.match(report, /next steps:/);
    assert.match(report, /Heuristic only|heuristic/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rea_triage detail mode includes the section list', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-triage-detail-'));
  try {
    const path = join(dir, 'plain.bin');
    await writeFile(path, Buffer.from('just some text and nothing else'));
    const { report } = await buildTriageTool({}).execute({ path, detail: true });
    assert.match(report, /strings:/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rea_export_report writes Markdown and SARIF from an inline bundle', async () => {
  await withStore(async (store, root) => {
    const tool = buildExportReportTool({ store, toolVersion: '1.3.0' });
    const { text } = await tool.execute({ bundle: BUNDLE });
    assert.match(text, /Markdown:/);
    assert.match(text, /SARIF 2\.1\.0:/);
    assert.match(text, /inference, not source code/i);
    const files = await readdir(root);
    assert.equal(files.length, 2);
    const markdown = await readFile(join(root, files.find((name) => name.endsWith('.md'))), 'utf8');
    assert.match(markdown, /Is it C2/);
    const sarif = JSON.parse(await readFile(join(root, files.find((name) => name.endsWith('.sarif'))), 'utf8'));
    assert.equal(sarif.runs[0].results[0].level, 'error');
  });
});

test('rea_export_report honours the format selector', async () => {
  await withStore(async (store, root) => {
    const tool = buildExportReportTool({ store });
    await tool.execute({ bundle: BUNDLE, format: 'sarif' });
    assert.equal((await readdir(root)).length, 1);
  });
});

test('rea_export_report reads a bundle from disk', async () => {
  await withStore(async (store, root) => {
    const path = join(root, 'bundle.json');
    await writeFile(path, JSON.stringify(BUNDLE));
    const { text } = await buildExportReportTool({ store }).execute({ path });
    assert.match(text, /Markdown:/);
  });
});

test('rea_export_report fetches the bundle from REA when nothing is supplied', async () => {
  await withStore(async (store) => {
    const client = { callTool: async (name) => {
      assert.equal(name, 'export_evidence_bundle');
      return { content: [{ type: 'text', text: JSON.stringify({ result: BUNDLE }) }] };
    } };
    const { text } = await buildExportReportTool({ client, store }).execute({});
    assert.match(text, /Markdown:/);
  });
});

test('rea_export_report explains itself when REA returns non-JSON', async () => {
  await withStore(async (store) => {
    const client = { callTool: async () => ({ content: [{ type: 'text', text: 'not json' }] }) };
    await assert.rejects(buildExportReportTool({ client, store }).execute({}), /not JSON/);
  });
});

test('rea_purge_artifacts reports what it removed without deleting the current session', async () => {
  await withStore(async (store, root) => {
    await store.write('keep.txt', 'still here');
    const { text } = await buildPurgeArtifactsTool(store).execute({});
    assert.match(text, /Artifact purge/);
    assert.match(text, /left untouched/i);
    assert.equal(existsSync(join(root, '001-keep.txt')), true);
  });
});
