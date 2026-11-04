import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createResultIndex, snapshotMeta } from '../lib/result-index.js';

const RESULT = {
  structuredContent: {
    result: {
      evidence: [
        { evidence_id: 'ev_aaa', observation: 'one' },
        { evidence_id: 'ev_bbb', observation: 'two' },
      ],
      confidence: 0.42,
      coverage: { functions: 12, strings: 40 },
      provider: { id: 'ghidra' },
      predicate_type: 'function-analysis',
    },
  },
  content: [{ type: 'text', text: '{"unrelated":true}' }],
};

test('snapshotMeta keeps the machine-readable anchors that text flattening loses', () => {
  const meta = snapshotMeta('analyze_function', RESULT, '{"unrelated":true}');
  assert.equal(meta.tool, 'analyze_function');
  assert.equal(meta.hasStructured, true);
  assert.deepEqual(meta.evidenceIds, ['ev_aaa', 'ev_bbb']);
  assert.equal(meta.confidence, 0.42);
  assert.deepEqual(meta.coverageKeys, ['functions', 'strings']);
  assert.equal(meta.provider, 'ghidra');
  assert.equal(meta.resultKind, 'function-analysis');
});

test('snapshotMeta falls back to a JSON text envelope and tolerates junk', () => {
  const meta = snapshotMeta('x', { content: [] }, '{"evidence":[{"id":"E1"}],"coverage":{"a":1}}');
  assert.deepEqual(meta.evidenceIds, ['E1']);
  const junk = snapshotMeta('x', {}, 'not json at all');
  assert.equal(junk.hasStructured, false);
  assert.equal(junk.evidenceCount, 0);
});

test('the index is append-only, cross-session and filterable', async () => {
  const base = await mkdtemp(join(tmpdir(), 'dsh-rea-index-'));
  try {
    const index = createResultIndex({ base });
    assert.deepEqual(await index.query({}), []);
    await index.record({ at: '2026-01-01T00:00:00.000Z', tool: 'analyze_function', confidence: 0.9, evidenceIds: ['ev_old'] });
    await index.record({ at: '2026-02-01T00:00:00.000Z', tool: 'batch_decompile', confidence: 0.2, evidenceIds: ['ev_new'] });
    await index.record({ at: '2026-03-01T00:00:00.000Z', tool: 'analyze_function', confidence: 0.8, evidenceIds: ['ev_new'] });

    assert.equal((await index.query({})).length, 3);
    assert.equal((await index.query({ tool: 'analyze' })).length, 2);
    assert.equal((await index.query({ minConfidence: 0.5 })).length, 2);
    assert.equal((await index.query({ since: '2026-02-15T00:00:00.000Z' })).length, 1);
    assert.equal((await index.query({ evidenceId: 'ev_new' })).length, 2);
    assert.equal((await index.query({ keyword: 'batch' }))[0].tool, 'batch_decompile');
    assert.equal((await index.query({ limit: 1 })).length, 1);
    assert.equal((await index.query({}))[0].at, '2026-03-01T00:00:00.000Z');

    const text = await readFile(index.file, 'utf8');
    assert.equal(text.trim().split('\n').length, 3);
    assert.equal(await createResultIndex({ base }).query({}).then((rows) => rows.length), 3);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
