import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createArtifactStore } from '../lib/infra/artifacts.js';
import { evidenceProducer, identifyFile, readEvidenceRecord, writeEvidenceRecord } from '../lib/infra/evidence.js';
import { buildDynamicProbeTool } from '../lib/surface/dynamic-tools.js';
import { buildMemoryDumpTool } from '../lib/surface/memdump-tools.js';
import { buildTraceBehaviorTool } from '../lib/surface/trace-tools.js';
import { buildUnpackTool } from '../lib/surface/unpack-tools.js';

const targetSha256 = 'a'.repeat(64);

test('evidence receipts bind successful bytes and reject changed artifacts', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-evidence-'));
  try {
    const artifactPath = join(dir, 'probe.json');
    await writeFile(artifactPath, '{"hex":"41424343"}\n', 'utf8');
    const artifact = await identifyFile(artifactPath);
    const store = createArtifactStore({ root: join(dir, 'artifacts') });
    const receipt = await store.writeEvidence({
      type: 'probe', status: 'success', producer: evidenceProducer('rea_dynamic_probe', {
        policy: { allowSampleExecution: true }, confirm: true,
      }),
      targetSha256, artifact,
      details: { module: 'sample.exe', rva: '0x1000', argIndex: 0, length: 4, dumpSha256: artifact.sha256 },
    });
    assert.match(receipt.receiptPath, /evidence-probe\.json$/);
    const loaded = await readEvidenceRecord(receipt.receiptPath);
    assert.equal(loaded.evidenceId, receipt.evidenceId);
    assert.equal(loaded.artifact.sha256, artifact.sha256);
    await writeFile(artifactPath, '{"hex":"41424344"}\n', 'utf8');
    await assert.rejects(readEvidenceRecord(receipt.receiptPath), /artifact changed after capture/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('execution receipts require both policy and per-call confirmation', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-evidence-policy-'));
  try {
    const artifactPath = join(dir, 'trace.json');
    await writeFile(artifactPath, '{}\n', 'utf8');
    const artifact = await identifyFile(artifactPath);
    for (const [producer, pattern] of [
      [evidenceProducer('rea_trace_behavior', { policy: { allowSampleExecution: true } }), /policy and per-call confirmation/],
      [evidenceProducer('rea_memory_dump', { confirm: true }), /policy and per-call confirmation/],
      [evidenceProducer('rea_dynamic_probe', { policy: { allowSampleExecution: false }, confirm: true }), /policy and per-call confirmation/],
      [evidenceProducer('rea_memory_dump', { policy: { allowSampleExecution: true, sandbox: true }, confirm: true }), /sandbox evidence requires/],
    ]) {
      await assert.rejects(writeEvidenceRecord({
        type: 'trace', status: 'success', producer, targetSha256, artifact,
      }), pattern);
    }
    const receiptPath = join(dir, 'forged.json');
    const forged = {
      schemaVersion: 1, evidenceId: 'ev-forged', type: 'trace', status: 'success',
      producer: evidenceProducer('rea_trace_behavior', { policy: { allowSampleExecution: true }, confirm: false }),
      targetSha256, artifact,
    };
    await writeFile(receiptPath, JSON.stringify(forged), 'utf8');
    await assert.rejects(readEvidenceRecord(receiptPath), /lacks policy or confirmation/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('producer receipt failures preserve diagnostics but never advertise applicable evidence', async (t) => {
  const cases = [
    {
      name: 'probe', diagnostic: 'dynamic-probe.json',
      create: ({ dir, target, store }) => buildDynamicProbeTool({
        config: { allowSampleExecution: true }, store,
        readiness: async () => ({ ready: true, command: 'python', args: [], version: 'test' }),
        runProbe: async () => ({ ok: true, module: 'sample.exe', ascii: 'ABCD', hex: '41424344', count: 1 }),
      }).execute({ target, breakRva: '0x1000', confirm: true }),
    },
    {
      name: 'memory-dump', diagnostic: 'memory-dump.json',
      create: async ({ dir, target, store }) => {
        const output = join(dir, 'image.exe');
        return buildMemoryDumpTool({
          config: { allowSampleExecution: true }, store,
          readiness: async () => ({ ready: true, command: 'python', args: [], version: 'test' }),
          dump: async ({ output: path }) => {
            await writeFile(path, 'MZ');
            return { ok: true, bytes: 2, sections: ['.text'], entryRva: 0, imports: 0, strings: 0, oepSignal: null, entryWatch: 'off' };
          },
        }).execute({ target, output, confirm: true });
      },
    },
    {
      name: 'trace', diagnostic: 'behaviour-trace.json',
      create: async ({ dir, target, store }) => {
        const rebuilt = join(dir, 'rebuilt.exe');
        await writeFile(rebuilt, 'MZ');
        const trace = { ok: true, exitCode: 0, timedOut: false, durationMs: 1, stdout: '', stderr: '', files: [], sandbox: { enabled: false } };
        return buildTraceBehaviorTool({
          config: { allowSampleExecution: true }, store,
          run: async () => trace,
        }).execute({ target, rebuilt, confirm: true });
      },
    },
    {
      name: 'unpack', diagnostic: 'unpack.json',
      create: async ({ dir, target, store }) => {
        const output = join(dir, 'unpacked.exe');
        return buildUnpackTool({
          store,
          readiness: () => ({ ready: true }),
          unpack: async ({ output: path }) => {
            await writeFile(path, 'MZ');
            return { ok: true, output: path, version: 'test', tool: 'upx', elapsedMs: 1 };
          },
        }).execute({ source: target, output });
      },
    },
  ];
  for (const item of cases) {
    await t.test(item.name, async () => {
      const dir = await mkdtemp(join(tmpdir(), `dsh-rea-${item.name}-receipt-failure-`));
      try {
        const target = join(dir, 'target.exe');
        await writeFile(target, 'MZ');
        const store = createArtifactStore({ root: join(dir, 'artifacts') });
        const writes = [];
        const write = store.write.bind(store);
        store.write = async (name, body) => { writes.push(name); return write(name, body); };
        store.writeEvidence = async () => { throw new Error('receipt disk full'); };
        const result = await item.create({ dir, target, store });
        assert.match(result.text, /receipt: not saved/);
        assert.match(result.text, /cannot be applied/);
        assert.doesNotMatch(result.text, /evidenceId:/);
        assert.ok(writes.includes(item.diagnostic), `diagnostic ${item.diagnostic} was not persisted`);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  }
});

test('a receipt cannot be written for missing or mismatched artifact bytes', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-evidence-bytes-'));
  try {
    const artifactPath = join(dir, 'unpacked.exe');
    await writeFile(artifactPath, 'MZ');
    const artifact = await identifyFile(artifactPath);
    const base = { type: 'unpack', status: 'success', producer: evidenceProducer('rea_unpack'), targetSha256 };
    await assert.rejects(writeEvidenceRecord({ ...base, artifact: { ...artifact, path: join(dir, 'missing.exe') } }), /ENOENT|no such file/i);
    await assert.rejects(writeEvidenceRecord({ ...base, artifact: { ...artifact, sha256: 'f'.repeat(64) } }), /identity does not match/);
    await assert.rejects(writeEvidenceRecord({ ...base, artifact: { ...artifact, size: artifact.size + 1 } }), /identity does not match/);
    await assert.rejects(writeEvidenceRecord({ ...base, status: 'failed', artifact }), /only successful evidence/);
    const receipt = await writeEvidenceRecord({ ...base, artifact });
    assert.equal(receipt.status, 'success');
    assert.equal(receipt.artifact.sha256, artifact.sha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
