import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeBundle, renderReports, toMarkdown, toSarif } from '../lib/export.js';

const BUNDLE = {
  target: '/samples/a.exe',
  generated_at: '2026-11-03T00:00:00Z',
  revision: 7,
  coverage: { functions_examined: 12, functions_total: 300, percent: 4 },
  evidence: [
    { id: 'E1', observation: 'sub_401000 XOR-decodes a blob', limitation: 'static only; no runtime trace', confidence: 0.7, kind: 'decompiler-inference', address: '0x401000' },
    { id: 'E2', observation: 'imports WinInet', limitation: 'not stated', kind: 'import-table' },
  ],
  unknowns: [
    { id: 'U1', question: 'Is the decoded blob a C2 config?', severity: 'high', required_authority_level: 'dynamic-trace', status: 'open' },
    { id: 'U2', question: 'Which packer is this?', severity: 'low', status: 'resolved' },
  ],
};

test('normalization tolerates the nested result shape and alternate field names', () => {
  const nested = normalizeBundle({ result: { records: [{ observation: 'x', limitations: 'y' }], residual_unknowns: [{ description: 'q', priority: 'medium' }] } });
  assert.equal(nested.evidence.length, 1);
  assert.equal(nested.evidence[0].limitation, 'y');
  assert.equal(nested.unknowns.length, 1);
  assert.equal(nested.unknowns[0].severity, 'medium');
});

test('a JSON string bundle is accepted', () => {
  assert.equal(normalizeBundle(JSON.stringify(BUNDLE)).evidence.length, 2);
});

test('an empty or malformed bundle does not crash the export', () => {
  const empty = normalizeBundle(null);
  assert.equal(empty.evidence.length, 0);
  assert.equal(empty.unknowns.length, 0);
  assert.match(toMarkdown('not json'), /No Evidence records/);
});

test('Markdown includes the target, evidence, limits, unknowns and the inference boundary', () => {
  const markdown = toMarkdown(BUNDLE, { generatedAt: 'fixed' });
  assert.match(markdown, /# REA reconstruction report/);
  assert.match(markdown, /\/samples\/a\.exe/);
  assert.match(markdown, /E1/);
  assert.match(markdown, /static only; no runtime trace/);
  assert.match(markdown, /inferred/);
  assert.match(markdown, /Is the decoded blob a C2 config/);
  assert.match(markdown, /dynamic-trace/);
  assert.match(markdown, /inference, not source code/i);
  assert.match(markdown, /percent: 4/);
  assert.match(markdown, /1 of 2 Evidence records are marked as inferred/);
});

test('pipe characters in observations are escaped so the table stays valid', () => {
  const markdown = toMarkdown({ evidence: [{ id: 'E|1', observation: 'a | b | c' }] });
  assert.match(markdown, /a \\\| b \\\| c/);
});

test('SARIF is valid 2.1.0 with one result per unknown and evidence as rules', () => {
  const sarif = toSarif(BUNDLE, { toolVersion: '1.3.0' });
  assert.equal(sarif.version, '2.1.0');
  assert.match(sarif.$schema, /sarif-2\.1\.0/);
  assert.equal(sarif.runs[0].tool.driver.version, '1.3.0');
  assert.equal(sarif.runs[0].results.length, 2);
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[1].level, 'note');
  assert.equal(sarif.runs[0].tool.driver.rules.filter((rule) => rule.properties?.['dsh-rea/evidence-id']).length, 2);
  assert.match(sarif.runs[0].results[0].message.text, /dynamic-trace/);
  assert.equal(sarif.runs[0].properties['dsh-rea/evidence-count'], 2);
});

test('renderReports produces both artifacts with a trailing newline', () => {
  const { markdown, sarif } = renderReports(BUNDLE);
  assert.ok(markdown.length > 200);
  assert.ok(sarif.endsWith('\n'));
  assert.doesNotThrow(() => JSON.parse(sarif));
});
