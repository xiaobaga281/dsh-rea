import assert from 'node:assert/strict';
import test from 'node:test';

import { dynamicReadiness } from '../lib/dynamic/dynamic.js';
import { buildDynamicProbeTool } from '../lib/surface/dynamic-tools.js';

test('the dynamic probe refuses without the policy flag, before touching the target', async () => {
  const tool = buildDynamicProbeTool({ config: { allowSampleExecution: false } });
  const result = await tool.execute({ target: 'C:\\nonexistent.exe', breakRva: '0x1000', confirm: true });
  assert.match(result.text, /sample execution is disabled/);
});

test('the dynamic probe refuses without per-call confirmation', async () => {
  const tool = buildDynamicProbeTool({ config: { allowSampleExecution: true } });
  const result = await tool.execute({ target: 'C:\\nonexistent.exe', breakRva: '0x1000' });
  assert.match(result.text, /confirm must be true/);
});

test('the dynamic probe validates the RVA shape', async () => {
  const tool = buildDynamicProbeTool({ config: { allowSampleExecution: true } });
  const result = await tool.execute({ target: 'C:\\nonexistent.exe', breakRva: 'not-an-rva', confirm: true });
  assert.match(result.text, /breakRva must be a hex RVA/);
});

test('dynamic readiness reports whether Python + Frida can run a probe', async () => {
  const readiness = await dynamicReadiness();
  assert.equal(typeof readiness.ready, 'boolean');
  if (readiness.ready) assert.equal(typeof readiness.version, 'string');
  else assert.ok(typeof readiness.reason === 'string' && readiness.reason.length > 0);
});
