import assert from 'node:assert/strict';
import test from 'node:test';

import { buildCatalogTool, buildTool, RESULT_GUIDANCE, textOf } from '../lib/tools.js';

function catalogOf(entries) {
  return { entries: () => entries };
}

test('the catalog names tools exactly, without asking for a second prefix', async () => {
  const tool = buildCatalogTool(catalogOf([
    { name: 'mcp__rea__binary_session', description: 'Open a binary.' },
    { name: 'mcp__rea__apk_manifest', description: 'Read an APK manifest.' },
  ]));
  const { text } = await tool.execute({});
  assert.match(text, /mcp__rea__binary_session/);
  assert.match(text, /mcp__rea__apk_manifest/);
  assert.doesNotMatch(text, /mcp__rea__<name>/);
});

test('listing without a query returns every tool and no description noise', async () => {
  const entries = Array.from({ length: 60 }, (_unused, index) => ({ name: `mcp__rea__tool_${index}`, description: 'd'.repeat(300) }));
  const { text } = await buildCatalogTool(catalogOf(entries)).execute({});
  const lines = text.split('\n');
  assert.equal(lines.length, 61);
  assert.ok(text.length < 4000, `listing is ${text.length} characters`);
});

test('a query filters by name and description and clips long descriptions', async () => {
  const tool = buildCatalogTool(catalogOf([
    { name: 'mcp__rea__apk_manifest', description: 'Read the AndroidManifest of an APK package.' },
    { name: 'mcp__rea__binary_session', description: 'Open a native binary.' },
  ]));
  const { text } = await tool.execute({ query: 'android' });
  assert.match(text, /apk_manifest/);
  assert.doesNotMatch(text, /binary_session/);
});

test('a broad query is truncated with an explicit count', async () => {
  const entries = Array.from({ length: 50 }, (_unused, index) => ({ name: `mcp__rea__packet_${index}`, description: 'packet tool' }));
  const { text } = await buildCatalogTool(catalogOf(entries)).execute({ query: 'packet' });
  assert.match(text, /… 10 more; narrow the query/);
  assert.equal(text.split('\n').length, 42);
});

test('an empty catalog explains itself instead of returning nothing', async () => {
  const { text } = await buildCatalogTool(catalogOf([])).execute({});
  assert.match(text, /empty/);
});

test('text blocks are joined and non-text blocks are named rather than dropped', () => {
  const text = textOf([
    { type: 'text', text: 'one' },
    { type: 'text', text: 'two' },
    { type: 'image', mimeType: 'image/png' },
    { type: 'resource', resource: { uri: 'file:///a', text: 'embedded body' } },
    { type: 'resource', resource: { uri: 'file:///b', blob: 'AAAA' } },
  ]);
  assert.match(text, /^one\ntwo/);
  assert.match(text, /image result not forwarded: image.png/);
  assert.match(text, /embedded body/);
  assert.match(text, /embedded binary resource: file:\/\/\/b/);
});

test('a tool definition carries the server schema and can defer its advertisement', () => {
  const client = { callTool: async () => ({ content: [] }) };
  const parameters = { type: 'object', properties: { target: { type: 'string' } } };
  const tool = buildTool(client, { name: 'apk_manifest', description: 'Read it.', inputSchema: parameters }, true);
  assert.equal(tool.name, 'mcp__rea__apk_manifest');
  assert.equal(tool.parameters, parameters);
  assert.equal(tool.deferLoading, true);
  assert.equal(buildTool(client, { name: 'plain' }, false).deferLoading, undefined);
});

test('execute forwards the abort signal and returns the flattened text', async () => {
  const seen = [];
  const client = {
    async callTool(name, args, signal) {
      seen.push({ name, args, signal });
      return { content: [{ type: 'text', text: 'result' }] };
    },
  };
  const signal = { aborted: false };
  const value = await buildTool(client, { name: 'ping' }, false).execute({ a: 1 }, { signal });
  assert.equal(value.text, 'result');
  assert.equal(seen[0].name, 'ping');
  assert.deepEqual(seen[0].args, { a: 1 });
  assert.equal(seen[0].signal, signal);
});

test('an isError result is raised so the model sees the failure', async () => {
  const client = { callTool: async () => ({ isError: true, content: [{ type: 'text', text: 'no target' }] }) };
  await assert.rejects(buildTool(client, { name: 'ping' }).execute({}, {}), /no target/);
});

test('the result guidance names the real tool identifiers', () => {
  assert.match(RESULT_GUIDANCE, /mcp__rea__inspect_analysis_view/);
  assert.match(RESULT_GUIDANCE, /mcp__rea__export_evidence_bundle/);
  assert.ok(RESULT_GUIDANCE.length < 400, `guidance is ${RESULT_GUIDANCE.length} characters`);
});
