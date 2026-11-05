import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyEngineFailure, clearEngineHealth, engineHealth, providerFromError, recordEngineFailure, resetEngineHealth,
} from '../lib/engine-health.js';
import { planNextSteps } from '../lib/plan.js';

test('a JVM that cannot create its scratch directory is named as such', () => {
  // The real message is 1.5 KB of Java stack trace; the report needs the cause.
  const reason = 'Exception in thread "main" java.io.IOException: Failed to create directory: C:\\Users\\x\\AppData\\Local\\Temp\\rea-ghidra-abc\\tmp\\x-ghidra';
  const classified = classifyEngineFailure(reason);
  assert.equal(classified.code, 'jvm-scratch-denied');
  assert.match(classified.reason, /私有运行目录/);
  // It must not blame the installation: this one happens with a correct JDK 21
  // and a correct Ghidra 12.
  assert.doesNotMatch(classified.reason, /版本过低|too old/);
});

test('a missing JDK is a different code with different advice', () => {
  const classified = classifyEngineFailure('JDK 21+ (64-bit) could not be found and must be manually chosen!');
  assert.equal(classified.code, 'jdk');
  assert.match(classified.reason, /JDK 21\+/);
});

test('an unsupported native runtime is recognised', () => {
  assert.equal(classifyEngineFailure('{"code":"ERR_REA_WINDOWS_NATIVE"}').code, 'native-unsupported');
});

test('an unknown failure is shortened but not invented', () => {
  const classified = classifyEngineFailure(`something odd happened ${'x'.repeat(400)}`);
  assert.equal(classified.code, 'unknown');
  assert.ok(classified.reason.length <= 160);
});

test('recording twice keeps the first timestamp and counts both', () => {
  resetEngineHealth();
  const first = recordEngineFailure('ghidra', 'Failed to create directory: a', { now: new Date('2026-01-01T00:00:00Z') });
  const second = recordEngineFailure('ghidra', 'Failed to create directory: b', { now: new Date('2026-01-01T00:05:00Z') });
  assert.equal(second.count, 2);
  assert.equal(second.at, first.at);
  assert.equal(second.lastAt, '2026-01-01T00:05:00.000Z');
  assert.equal(engineHealth('ghidra').count, 2);
  clearEngineHealth('ghidra');
  assert.equal(engineHealth('ghidra'), null);
});

test('an error without a provider id is not attributed to one', () => {
  assert.equal(providerFromError('some tool failed'), null);
  assert.equal(providerFromError('{"details":{"provider_id":"ghidra"}}'), 'ghidra');
  assert.equal(providerFromError('"provider_id": "JADX"'), 'jadx');
});

test('an unavailable engine drops the probe instead of promising it', () => {
  const plan = planNextSteps({
    structure: {
      tls: { present: true, callbacks: [{ rva: 0x1800, section: '.text' }] },
      hashedApis: null,
      importsPresent: true,
      dispatchTables: [],
    },
    unresolved: [],
    providers: {
      providers: {
        ghidra: { ready: false, reason: 'Ghidra 的 JVM 无法创建临时目录（上游 Windows 限制）' },
      },
    },
  });
  const step = plan.find((entry) => entry.action.includes('TLS callback'));
  assert.ok(step, 'the experiment is still planned');
  assert.equal(step.probe, undefined, 'a probe against a dead engine is a false claim');
  assert.match(step.blocked, /私有运行目录|临时目录/);
  assert.equal(step.provider.ready, false);
});

test('a ready engine keeps the probe', () => {
  const plan = planNextSteps({
    structure: {
      tls: { present: true, callbacks: [{ rva: 0x1800, section: '.text' }] },
      hashedApis: null,
      importsPresent: true,
      dispatchTables: [],
    },
    unresolved: [],
    providers: { providers: { ghidra: { ready: true, reason: null } } },
  });
  const step = plan.find((entry) => entry.action.includes('TLS callback'));
  assert.deepEqual(step.probe, { tool: 'inspect_address_context', rva: 0x1800, expectName: 'tls_callback' });
  assert.equal(step.blocked, undefined);
});

test('a provider the plan does not name is not added', () => {
  const plan = planNextSteps({
    structure: { tls: { present: true, callbacks: [{ rva: 0x1800, section: '.text' }] }, hashedApis: null, importsPresent: true, dispatchTables: [] },
    providers: { providers: { jadx: { ready: true } } },
  });
  const step = plan.find((entry) => entry.action.includes('TLS callback'));
  assert.equal(step.provider, undefined);
  assert.ok(step.probe, 'no readiness claim means no reason to drop the probe');
});
