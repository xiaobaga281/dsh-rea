import assert from 'node:assert/strict';
import test from 'node:test';

import { childEnvironment, resolveConfig } from '../lib/config.js';
import { DEFAULT_MAX_BUFFER_BYTES, DEFAULT_TOOL_CALL_TIMEOUT_MS, REA_MIN_MAX_RESPONSE_BYTES } from '../lib/mcp-client.js';

test('defaults match the documented configuration table', () => {
  const config = resolveConfig({});
  assert.equal(config.schemaProfile, 'compact');
  assert.equal(config.outputSchemaProfile, 'off');
  assert.equal(config.toolCallTimeoutMs, DEFAULT_TOOL_CALL_TIMEOUT_MS);
  assert.equal(config.maxBufferBytes, DEFAULT_MAX_BUFFER_BYTES);
  assert.equal(config.deferCatalog, true);
  assert.equal(config.enabled, true);
});

test('an out-of-range profile falls back to the default instead of reaching the child', () => {
  const config = resolveConfig({ schemaProfile: 'everything', outputSchemaProfile: 'compact' });
  assert.equal(config.schemaProfile, 'compact');
  assert.equal(config.outputSchemaProfile, 'off');
});

test('maxBufferBytes below REA\'s floor is raised, never passed through', () => {
  assert.equal(resolveConfig({ maxBufferBytes: 1024 }).maxBufferBytes, DEFAULT_MAX_BUFFER_BYTES);
  const raised = REA_MIN_MAX_RESPONSE_BYTES + 4096;
  assert.equal(resolveConfig({ maxBufferBytes: raised }).maxBufferBytes, raised);
});

test('a non-positive timeout is replaced rather than disabling the guard', () => {
  assert.equal(resolveConfig({ toolCallTimeoutMs: 0 }).toolCallTimeoutMs, DEFAULT_TOOL_CALL_TIMEOUT_MS);
  assert.equal(resolveConfig({ toolCallTimeoutMs: -5 }).toolCallTimeoutMs, DEFAULT_TOOL_CALL_TIMEOUT_MS);
  assert.equal(resolveConfig({ toolCallTimeoutMs: 1500 }).toolCallTimeoutMs, 1500);
});

test('deferCatalog and enabled are opt-out flags', () => {
  assert.equal(resolveConfig({ deferCatalog: false }).deferCatalog, false);
  assert.equal(resolveConfig({ enabled: false }).enabled, false);
});

test('the child environment carries REA settings and withholds unrelated secrets', () => {
  const config = resolveConfig({});
  config.reaVersion = '6.7.0';
  const base = {
    PATH: '/usr/bin',
    HOME: '/home/person',
    OPENAI_API_KEY: 'sk-should-not-be-visible',
    GITHUB_TOKEN: 'ghp-should-not-be-visible',
    JAVA_HOME: '/opt/jdk-21',
    REA_ANALYSIS_PROVIDER: 'ghidra',
  };
  const env = childEnvironment(config, base);
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(env.REA_MCP_INPUT_SCHEMA_PROFILE, 'compact');
  assert.equal(env.REA_MCP_OUTPUT_SCHEMA_PROFILE, 'off');
  assert.equal(env.REA_PACKAGE_VERSION, '6.7.0');
  // JAVA_HOME may also come from a saved engine path on the machine running the
  // tests, so only its presence is asserted here.
  assert.ok(typeof env.JAVA_HOME === 'string' && env.JAVA_HOME.length > 0);
  assert.equal(env.REA_ANALYSIS_PROVIDER, 'ghidra');
  assert.equal(env.OPENAI_API_KEY, undefined);
  assert.equal(env.GITHUB_TOKEN, undefined);
});

test('1.3.0 policy defaults are conservative and opt-in', () => {
  const config = resolveConfig({});
  assert.deepEqual(config.allowedTargets, []);
  assert.equal(config.allowDeviceMutations, false);
  assert.equal(config.sensitiveArtifacts, false);
  assert.equal(config.artifactRetentionDays, 7);
  assert.equal(config.maxBackups, 2);
  assert.equal(config.pinnedSha256, null);
  assert.equal(config.triageMaxBytes, 64 * 1024 * 1024);
});

test('a malformed pinned digest is ignored instead of pinning garbage', () => {
  assert.equal(resolveConfig({ pinnedSha256: 'not-a-digest' }).pinnedSha256, null);
  assert.equal(resolveConfig({ pinnedSha256: 'A'.repeat(64) }).pinnedSha256, 'a'.repeat(64));
});

test('retention and backup counts are clamped to usable ranges', () => {
  assert.equal(resolveConfig({ artifactRetentionDays: 0 }).artifactRetentionDays, 1);
  assert.equal(resolveConfig({ artifactRetentionDays: 9999 }).artifactRetentionDays, 365);
  assert.equal(resolveConfig({ maxBackups: 99 }).maxBackups, 10);
});

test('allowedTargets only keeps non-empty strings', () => {
  assert.deepEqual(resolveConfig({ allowedTargets: ['/samples', '', 42] }).allowedTargets, ['/samples']);
});
