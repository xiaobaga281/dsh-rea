import test from 'node:test';
import assert from 'node:assert/strict';

import { annotationSummary, createSchemaCache, schemaAt, schemaOutline } from '../lib/schema-cache.js';

const FULL_TOOL = {
  name: 'compare_functions',
  description: 'Compare two Evidence sets',
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true, idempotentHint: true },
  inputSchema: {
    type: 'object',
    properties: {
      left: {
        type: 'object',
        properties: {
          evidence_id: { type: 'string', pattern: '^ev_[a-f0-9]{64}$', description: 'Stable Evidence ID' },
          subject: { type: 'object', properties: { format: { type: 'string', enum: ['hopper', 'ghidra'] } } },
        },
        required: ['evidence_id'],
      },
      right: { type: 'object', properties: { evidence_id: { type: 'string' } } },
    },
    required: ['left', 'right'],
    $defs: { __schema0: { type: 'string' } },
  },
  outputSchema: { type: 'object', properties: { conclusions: { type: 'array', items: { type: 'string' } } } },
};

test('schemaOutline shows nested field counts without dumping the whole schema', () => {
  const outline = schemaOutline(FULL_TOOL.inputSchema);
  assert.deepEqual(outline.required, ['left', 'right']);
  assert.equal(outline.fields.left.type, 'object');
  assert.equal(outline.fields.left.nestedFields, 2);
  assert.equal(outline.definitions, 1);
});

test('schemaAt navigates properties, $defs and array items', () => {
  assert.equal(schemaAt(FULL_TOOL.inputSchema, 'left.evidence_id').pattern, '^ev_[a-f0-9]{64}$');
  assert.deepEqual(schemaAt(FULL_TOOL.inputSchema, 'left.subject.format.enum'), ['hopper', 'ghidra']);
  assert.equal(schemaAt(FULL_TOOL.inputSchema, '$defs.__schema0').type, 'string');
  assert.equal(schemaAt(FULL_TOOL.inputSchema, 'does.not.exist'), null);
  assert.equal(schemaAt(FULL_TOOL.outputSchema, 'conclusions.items').type, 'string');
});

test('annotationSummary keeps only the four actionable hints', () => {
  assert.deepEqual(annotationSummary(FULL_TOOL.annotations), {
    readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true,
  });
  assert.equal(annotationSummary(null), null);
});

test('the cache serves compact outlines by default and expands one path at a time', () => {
  const cache = createSchemaCache();
  cache.prime([{ name: 'compare_functions', inputSchema: { type: 'object', properties: { left: { type: 'object' }, right: { type: 'object' } } } }]);
  const before = cache.describe('compare_functions');
  assert.match(before, /compact/);
  assert.match(before, /Input schema \(compact profile\)/);

  cache.primeFull([FULL_TOOL]);
  assert.equal(cache.fullCount, 1);
  assert.ok(cache.memoryBytes > 0);
  const outline = cache.describe('mcp__rea__compare_functions');
  assert.match(outline, /full \(complete upstream definitions cached\)/);
  assert.match(outline, /nestedFields/);
  assert.match(outline, /openWorldHint/);
  const expanded = cache.describe('compare_functions', { path: 'left.evidence_id' });
  assert.match(expanded, /ev_\[a-f0-9\]/);
  assert.doesNotMatch(expanded, /truncated/);
  assert.match(cache.describe('compare_functions', { path: 'nope' }), /No field at path/);
});

test('output schema is opt-in and a failed probe degrades instead of throwing', () => {
  const cache = createSchemaCache();
  cache.prime([{ name: 'x', inputSchema: {} }]);
  assert.match(cache.describe('x', { includeOutput: true }), /not available/);
  cache.markProbeFailed('ECONNRESET');
  assert.match(cache.status, /unavailable/);
  assert.match(cache.describe('x'), /compact/);
  assert.equal(cache.describe('missing'), null);
});
