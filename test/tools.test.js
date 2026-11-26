import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { OWN_TOOL_AUDIT } from '../index.js';
import { buildCatalogTool, buildStatusTool, buildTool, createConnectionBinding, createConnectionSupervisor, guidanceFor, RESULT_GUIDANCE, textOf } from '../lib/surface/tools.js';

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
  assert.match(text, /\[image result saved as evidence/);
  assert.match(text, /embedded body/);
  assert.match(text, /binary resource saved as evidence: file:\/\/\/b/);
});

test('a tool definition carries the server schema and can defer its advertisement', () => {
  const client = { callTool: async () => ({ content: [] }) };
  const parameters = { type: 'object', properties: { target: { type: 'string' } } };
  const annotations = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };
  const outputSchema = { type: 'object', properties: { evidence_id: { type: 'string' } } };
  const tool = buildTool(client, {
    name: 'apk_manifest', description: 'Read it.', inputSchema: parameters, annotations, outputSchema,
  }, true);
  assert.equal(tool.name, 'mcp__rea__apk_manifest');
  assert.equal(tool.parameters, parameters);
  assert.deepEqual(tool.annotations, annotations);
  assert.equal(tool.output.schema, outputSchema);
  assert.equal(tool.deferLoading, true);
  const plain = buildTool(client, { name: 'plain' }, false);
  assert.equal(plain.deferLoading, undefined);
  assert.equal(plain.annotations, undefined);
  assert.deepEqual(plain.output.schema, {
    type: 'object', additionalProperties: false,
    properties: { text: { type: 'string' } }, required: ['text'],
  });
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

test('a connection replacement prepares first and rejects stale generations', async () => {
  const binding = createConnectionBinding();
  await assert.rejects(binding.callTool('ping'), /not connected/);
  const alpha = { callTool: async () => ({ content: [{ type: 'text', text: 'alpha result' }] }) };
  await binding.replace(alpha);
  assert.equal((await binding.callTool('ping')).content[0].text, 'alpha result');
  const stale = binding.snapshot();
  const bravo = { callTool: async () => ({ content: [{ type: 'text', text: 'bravo result' }] }) };
  assert.equal((await binding.replace(bravo, async (next) => next)).previous, alpha);
  assert.throws(() => binding.assertCurrent(stale), /stale client generation/);
  assert.equal((await binding.callTool('ping')).content[0].text, 'bravo result');
  const current = binding.snapshot();
  await assert.rejects(binding.replace({}, async () => { throw new Error('catalog failed'); }), /catalog failed/);
  assert.equal(binding.client, bravo);
  assert.deepEqual(binding.snapshot(), current);
});

test('every owned tool has an explicit read, write, compile or execute audit class', () => {
  assert.equal(Object.keys(OWN_TOOL_AUDIT).length, 30);
  for (const [name, kind] of Object.entries(OWN_TOOL_AUDIT)) {
    assert.ok(['read', 'write', 'compile', 'execute'].includes(kind), `${name} has invalid audit class ${kind}`);
  }
  assert.equal(OWN_TOOL_AUDIT.rea_reconstruct, 'compile');
  assert.equal(OWN_TOOL_AUDIT.rea_compare_build, 'compile');
  assert.equal(OWN_TOOL_AUDIT.rea_unpack, 'write');
  assert.equal(OWN_TOOL_AUDIT.rea_dynamic_probe, 'execute');
  assert.equal(OWN_TOOL_AUDIT.rea_trace_behavior, 'execute');
  assert.equal(OWN_TOOL_AUDIT.rea_memory_dump, 'execute');
});

test('a registered tool follows a replaced client provider', async () => {
  const calls = [];
  let current = { callTool: async (name) => { calls.push(`a:${name}`); return { content: [{ type: 'text', text: 'alpha' }] }; } };
  const tool = buildTool((...args) => current.callTool(...args), { name: 'ping' }, false);
  assert.equal((await tool.execute({})).text, 'alpha');
  current = { callTool: async (name) => { calls.push(`b:${name}`); return { content: [{ type: 'text', text: 'bravo' }] }; } };
  assert.equal((await tool.execute({})).text, 'bravo');
  current = { callTool: async () => { throw new Error('not connected'); } };
  await assert.rejects(tool.execute({}), /not connected/);
  assert.deepEqual(calls, ['a:ping', 'b:ping']);
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fakeClient(label, ready = Promise.resolve()) {
  const child = new EventEmitter();
  return {
    label,
    ready,
    child,
    disposeCalls: 0,
    async dispose() { this.disposeCalls += 1; },
    async callTool() { return { content: [{ type: 'text', text: label }] }; },
  };
}

function supervisorHarness(options = {}) {
  const connection = createConnectionBinding();
  const alpha = fakeClient('alpha');
  const commits = [];
  const events = [];
  const spawned = [];
  const supervisor = createConnectionSupervisor(connection, {
    spawn: () => {
      const next = fakeClient(`next-${spawned.length}`);
      spawned.push(next);
      return next;
    },
    prepare: async (client) => ({ label: client.label }),
    commit: (client, prepared) => commits.push({ client, prepared }),
    report: (message, level) => events.push({ message, level }),
    retryDelayMs: 1,
    maxAttempts: 2,
    ...options,
  });
  return { connection, alpha, commits, events, spawned, supervisor };
}

test('concurrent restarts spawn once and keep the old client until the new catalog is ready', async () => {
  const gate = deferred();
  const bravo = fakeClient('bravo');
  const spawned = [];
  const { connection, alpha, commits, supervisor } = supervisorHarness({
    spawn: () => { spawned.push(bravo); return bravo; },
    prepare: async (client) => {
      if (client === bravo) await gate.promise;
      return { label: client.label };
    },
  });
  await connection.replace(alpha);
  supervisor.supervise(alpha);
  const first = supervisor.restart('test');
  const second = supervisor.restart('test');
  assert.equal(first, second);
  assert.equal(spawned.length, 1);
  assert.equal(connection.client, alpha);
  assert.equal(alpha.disposeCalls, 0);
  gate.resolve();
  assert.equal(await first, true);
  assert.equal(connection.client, bravo);
  assert.equal(alpha.disposeCalls, 1);
  assert.equal(bravo.supervised, true);
  assert.deepEqual(commits.map(({ client }) => client), [bravo]);
  supervisor.dispose();
});

test('a failed handshake or catalog commit retains the old client and disposes the candidate', async () => {
  for (const failure of ['ready', 'commit']) {
    const bravo = fakeClient('bravo', failure === 'ready' ? Promise.reject(new Error('handshake failed')) : Promise.resolve());
    const { connection, alpha, supervisor } = supervisorHarness({
      spawn: () => bravo,
      commit: () => { throw new Error('catalog failed'); },
    });
    await connection.replace(alpha);
    await assert.rejects(supervisor.restart('test'), failure === 'ready' ? /handshake failed/ : /catalog failed/);
    assert.equal(connection.client, alpha);
    assert.equal(alpha.disposeCalls, 0);
    assert.equal(bravo.disposeCalls, 1);
    assert.equal((await connection.callTool('ping')).content[0].text, 'alpha');
    supervisor.dispose();
  }
});

test('a partial catalog commit fails the restart instead of reporting success', async () => {
  const bravo = fakeClient('bravo');
  const { connection, alpha, events, supervisor } = supervisorHarness({
    spawn: () => bravo,
    commit: () => ({ added: 2, updated: 0, removed: 0, failed: 1, size: 2 }),
  });
  await connection.replace(alpha);
  await assert.rejects(supervisor.restart('test'), /1 tool registration\(s\) failed/);
  assert.equal(connection.client, alpha);
  assert.equal(alpha.disposeCalls, 0);
  assert.equal(bravo.disposeCalls, 1);
  assert.equal(events.some((event) => /restarted/.test(event.message)), false);
  supervisor.dispose();
});

test('a late exit from a replaced client cannot schedule a reconnect', async () => {
  const candidates = [];
  const { connection, alpha, supervisor } = supervisorHarness({
    spawn: () => {
      const next = fakeClient(`replacement-${candidates.length}`);
      candidates.push(next);
      return next;
    },
  });
  await connection.replace(alpha);
  supervisor.supervise(alpha);
  await supervisor.restart('test');
  const active = candidates[0];
  assert.equal(active.supervised, true);
  alpha.child.emit('exit');
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(candidates.length, 1);
  active.child.emit('exit');
  active.child.emit('exit');
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(candidates.length, 2);
  assert.equal(connection.client, candidates[1]);
  supervisor.dispose();
});

test('reconnect failures stop after the configured attempt budget', async () => {
  let stopped;
  const finish = new Promise((resolve) => { stopped = resolve; });
  let spawned = 0;
  const { connection, alpha, events, supervisor } = supervisorHarness({
    spawn: () => {
      spawned += 1;
      return fakeClient(`broken-${spawned}`, Promise.reject(new Error('cannot start')));
    },
    report: (message, level) => {
      events.push({ message, level });
      if (level === 'error') stopped();
    },
  });
  await connection.replace(alpha);
  supervisor.supervise(alpha);
  alpha.child.emit('exit');
  await finish;
  assert.equal(spawned, 2);
  assert.match(events.at(-1).message, /reconnect stopped/);
  assert.equal(connection.client, alpha);
  supervisor.dispose();
});

test('disposal during restart clears the provider and cleans up both clients once', async () => {
  const gate = deferred();
  const bravo = fakeClient('bravo');
  const { connection, alpha, supervisor } = supervisorHarness({
    spawn: () => bravo,
    prepare: async (client) => {
      if (client === bravo) await gate.promise;
      return { label: client.label };
    },
  });
  await connection.replace(alpha);
  supervisor.supervise(alpha);
  const restarting = supervisor.restart('test');
  supervisor.dispose();
  gate.resolve();
  await assert.rejects(restarting, /disposed during restart/);
  assert.equal(connection.client, undefined);
  assert.equal(alpha.disposeCalls, 1);
  assert.equal(bravo.disposeCalls, 1);
  await assert.rejects(connection.callTool('ping'), /not connected/);
});

test('a late initial sync cannot commit over a replacement or after disposal', async () => {
  const gate = deferred();
  const bravo = fakeClient('bravo');
  const { connection, alpha, commits, supervisor } = supervisorHarness({
    prepare: async (client) => {
      if (client === alpha) await gate.promise;
      return { label: client.label };
    },
  });
  await connection.replace(alpha);
  const syncing = supervisor.sync();
  await connection.replace(bravo);
  gate.resolve();
  await assert.rejects(syncing, /stale client generation/);
  assert.equal(commits.length, 0);
  const secondGate = deferred();
  const secondConnection = createConnectionBinding();
  const charlie = fakeClient('charlie');
  await secondConnection.replace(charlie);
  const second = createConnectionSupervisor(secondConnection, {
    spawn: () => fakeClient('unused'),
    prepare: () => secondGate.promise,
    commit: () => { throw new Error('must not commit'); },
  });
  const pending = second.sync();
  second.dispose();
  secondGate.resolve({});
  await assert.rejects(pending, /disposed/);
  supervisor.dispose();
  second.dispose();
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
  assert.match(report, /dsh-rea-restore 1\.2\.0/);
  assert.match(report, /runtime: unpacked/);
  assert.match(report, /target: none/);
  assert.match(report, /open_binary/);
  assert.match(report, /blocked: .*Ghidra/);
});

// --- 1.3.0: tiered result guidance ----------------------------------------

test('a decompiler result is explicitly labelled as inference, not source', () => {
  assert.match(guidanceFor('procedure_pseudo_code'), /inference, not source code/i);
  assert.match(guidanceFor('batch_decompile'), /inference/i);
  assert.doesNotMatch(guidanceFor('list_strings'), /inference/i);
});

test('a state-changing tool is marked as audited', () => {
  assert.match(guidanceFor('set_comment'), /recorded in the audit trail/i);
  assert.match(guidanceFor('install_adb_package'), /audit trail/i);
  assert.equal(guidanceFor('inspect_macho'), '');
});

test('the rendered result carries the tiered caveat exactly once', () => {
  const client = { callTool: async () => ({ content: [] }) };
  const tool = buildTool(client, { name: 'procedure_pseudo_code', description: 'Decompiled C.' }, false);
  const blocks = tool.output.render({}, { text: 'int main(){}' });
  assert.match(blocks[0].text, /inference, not source code/);
  assert.equal(blocks[0].text.match(/inference, not source code/g).length, 1);
  assert.match(blocks[0].text, /RESULT_GUIDANCE|Evidence ID/);
});

test('the guard receives the schema entry so new tools can be classified', async () => {
  const seen = [];
  const client = { callTool: async () => ({ content: [{ type: 'text', text: 'ok' }] }) };
  const entry = { name: 'future_write_tool', description: 'Writes state.' };
  const tool = buildTool(client, entry, false, {
    guard: (name, _args, schemaEntry) => { seen.push(schemaEntry?.description); return undefined; },
  });
  await tool.execute({}, {});
  assert.deepEqual(seen, ['Writes state.']);
});
