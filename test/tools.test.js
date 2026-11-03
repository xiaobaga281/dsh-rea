import assert from 'node:assert/strict';
import test from 'node:test';

import { buildCatalogTool, buildStatusTool, buildTool, RESULT_GUIDANCE, textOf } from '../lib/tools.js';

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

test('a tool name returns that tool\'s input schema, prefixed or not', async () => {
  const tool = buildCatalogTool(catalogOf([{
    name: 'mcp__rea__capture_process_scenario',
    description: 'Run one command under a PTY.',
    parameters: { type: 'object', required: ['executable'], properties: { executable: { type: 'string' } } },
  }]));
  const plain = await tool.execute({ tool: 'capture_process_scenario' });
  assert.match(plain.text, /Input schema/);
  assert.match(plain.text, /"executable"/);
  const prefixed = await tool.execute({ tool: 'mcp__rea__capture_process_scenario' });
  assert.equal(prefixed.text, plain.text);
});

test('an unknown tool name is answered, not thrown', async () => {
  const tool = buildCatalogTool(catalogOf([{ name: 'mcp__rea__a', description: 'a' }]));
  const { text } = await tool.execute({ tool: 'nope' });
  assert.match(text, /No REA tool named nope/);
});

test('a guard refusal short-circuits before the child is called', async () => {
  let called = false;
  const client = { callTool: async () => { called = true; return { content: [] }; } };
  const tool = buildTool(client, { name: 'uninstall_adb_package' }, false, { guard: () => 'blocked by policy' });
  await assert.rejects(tool.execute({}, {}), /blocked by policy/);
  assert.equal(called, false);
});

test('a spill replaces the tool output with the handle', async () => {
  const client = { callTool: async () => ({ content: [{ type: 'text', text: 'x'.repeat(500) }] }) };
  const tool = buildTool(client, { name: 'big' }, false, { spill: async (name, text) => `SPILLED ${name} ${text.length}` });
  const value = await tool.execute({}, {});
  assert.equal(value.text, 'SPILLED big 500');
});

test('rea_status says what is missing instead of failing on an empty session', async () => {
  const client = { callTool: async () => ({ content: [{ type: 'text', text: JSON.stringify({ result: { open: false } }) }] }) };
  const tool = buildStatusTool({
    client,
    version: '1.2.0',
    engines: async () => ({
      runtime: { unpacked: true },
      java: { fullJdk: false },
      ghidra: { ready: false },
      external: {},
    }),
  });
  const { report } = await tool.execute({}, {});
  assert.match(report, /dsh-rea 1\.2\.0/);
  assert.match(report, /runtime: unpacked/);
  assert.match(report, /target: none/);
  assert.match(report, /open_binary/);
  assert.match(report, /blocked: .*Ghidra/);
});
