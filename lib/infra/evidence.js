/**
 * Evidence identity and receipt primitives: content hashes, producer policy
 * tags and the SHA-bound records dynamic/unpack/dump/trace application trusts.
 *
 * @module dsh-rea-restore/lib/infra/evidence
 */
import { createHash } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

const SHA256 = /^[a-f0-9]{64}$/i;
const TYPES = new Set(['inventory', 'probe', 'unpack', 'memory-dump', 'trace']);
const EXECUTION_TOOLS = new Set(['rea_dynamic_probe', 'rea_memory_dump', 'rea_trace_behavior']);

export async function identifyFile(path) {
  const handle = await open(path, 'r');
  const hash = createHash('sha256');
  let size = 0;
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      hash.update(chunk.subarray(0, bytesRead));
    }
  } finally {
    await handle.close();
  }
  return { path, sha256: hash.digest('hex'), size };
}

export function evidenceProducer(tool, extra = {}) {
  return { ...extra, tool, version: 'evidence-v1' };
}

export async function writeEvidenceRecord(input) {
  const type = String(input?.type ?? '');
  if (!TYPES.has(type)) throw new Error('unsupported evidence type');
  if (input.status !== 'success') throw new Error('only successful evidence can be applied');
  if (!SHA256.test(String(input.targetSha256 ?? ''))) throw new Error('evidence target SHA is required');
  if (!isAbsolute(String(input.artifact?.path ?? ''))) throw new Error('evidence artifact path must be absolute');
  const artifact = await identifyFile(input.artifact.path);
  if (artifact.sha256 !== String(input.artifact.sha256).toLowerCase() || artifact.size !== input.artifact.size) {
    throw new Error('evidence artifact identity does not match its bytes');
  }
  const producer = input.producer;
  if (!producer || typeof producer.tool !== 'string' || typeof producer.version !== 'string') throw new Error('evidence producer is required');
  if (EXECUTION_TOOLS.has(producer.tool)
    && (producer.policy?.allowSampleExecution !== true || producer.confirm !== true)) {
    throw new Error('execution evidence requires policy and per-call confirmation');
  }
  if (producer.policy?.sandbox === true && producer.policy.sandboxSampleExecution !== true) {
    throw new Error('sandbox evidence requires its own opt-in policy');
  }
  const receipt = {
    schemaVersion: 1,
    evidenceId: `ev-${Date.now()}-${createHash('sha256').update(`${type}:${artifact.sha256}:${Math.random()}`).digest('hex').slice(0, 12)}`,
    type,
    status: 'success',
    createdAt: new Date().toISOString(),
    producer,
    targetSha256: input.targetSha256.toLowerCase(),
    artifact,
    binding: input.binding ?? {},
    coverage: input.coverage ?? {},
    limitations: Array.isArray(input.limitations) ? input.limitations.map(String) : [],
    details: input.details ?? {},
  };
  return receipt;
}

export async function readEvidenceRecord(path) {
  if (!isAbsolute(String(path ?? ''))) throw new Error('evidence receipt path must be absolute');
  const receipt = JSON.parse(await readFile(path, 'utf8'));
  if (receipt.schemaVersion !== 1 || !TYPES.has(receipt.type) || receipt.status !== 'success') throw new Error('invalid evidence receipt');
  if (!SHA256.test(String(receipt.targetSha256 ?? '')) || typeof receipt.evidenceId !== 'string' || !receipt.evidenceId
    || typeof receipt.producer?.tool !== 'string' || !receipt.producer.tool
    || typeof receipt.producer?.version !== 'string' || !receipt.producer.version
    || !isAbsolute(String(receipt.artifact?.path ?? ''))) {
    throw new Error('incomplete evidence receipt');
  }
  if (EXECUTION_TOOLS.has(receipt.producer.tool)
    && (receipt.producer.policy?.allowSampleExecution !== true || receipt.producer.confirm !== true)) {
    throw new Error('execution receipt lacks policy or confirmation');
  }
  if (receipt.producer.policy?.sandbox === true && receipt.producer.policy.sandboxSampleExecution !== true) {
    throw new Error('sandbox receipt lacks its own opt-in policy');
  }
  const artifact = await identifyFile(receipt.artifact?.path ?? '');
  if (artifact.sha256 !== String(receipt.artifact.sha256).toLowerCase() || artifact.size !== receipt.artifact.size) {
    throw new Error('evidence artifact changed after capture');
  }
  return { ...receipt, receiptPath: path };
}
