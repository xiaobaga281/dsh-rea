import assert from 'node:assert/strict';
import test from 'node:test';

import {
  behaviorLimitations,
  classifyApi,
  compareBehaviorContracts,
  contractFrom,
  operationOf,
} from '../lib/behavior.js';

test('imports classify into a family and an operation, and CRT noise classifies as nothing', () => {
  assert.deepEqual(classifyApi('CreateFileA'), { family: 'file', operation: 'create', token: 'file:create' });
  assert.deepEqual(classifyApi('RegSetValueExA'), { family: 'registry', operation: 'set', token: 'registry:set' });
  assert.deepEqual(classifyApi('WinHttpOpen'), { family: 'network', operation: 'open', token: 'network:open' });
  // Process injection outranks the memory family: the side effect is a remote
  // write, not an allocation.
  assert.equal(classifyApi('WriteProcessMemory').family, 'process');
  assert.equal(classifyApi('_memcpy'), null);
  assert.equal(classifyApi('__stdio_common_vfprintf'), null);
  assert.equal(operationOf('CreateProcessW'), 'create');
});

test('a contract separates output literals, state names and effect families, and subtracts the floor', () => {
  const contract = contractFrom({
    imports: ['CreateFileA', 'RegSetValueExA', 'MessageBoxA', '_memcpy'],
    strings: [
      'Cannot open config file.',
      'usage: rea [-v] <path>',
      'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Global\\rea-mutex-1',
      'C:\\ProgramData\\rea\\state.dat',
      'REA_CONFIG_PATH',
      'https://c2.example.test/gate.php',
      'compiler boilerplate string',
    ],
    floorStrings: new Set(['compiler boilerplate string']),
  });
  assert.deepEqual([...contract.effects].sort(), ['file:create', 'registry:set', 'ui:call']);
  assert.ok(contract.outputs.has('Cannot open config file.'));
  assert.ok(contract.outputs.has('usage: rea [-v] <path>'));
  assert.ok(!contract.outputs.has('https://c2.example.test/gate.php'), 'a URL is payload, not output');
  assert.ok(contract.state.has('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'));
  assert.ok(contract.state.has('Global\\rea-mutex-1'));
  assert.ok(contract.state.has('C:\\ProgramData\\rea\\state.dat'));
  assert.ok(contract.state.has('REA_CONFIG_PATH'));
  assert.ok(!contract.outputs.has('compiler boilerplate string'), 'floor vocabulary is not behaviour');
});

test('an identical contract scores 1.0, a dropped message lowers recall and an invented effect lowers precision', () => {
  const target = contractFrom({
    imports: ['CreateFileA', 'MessageBoxA'],
    strings: ['Cannot open config file.', 'HKCU\\Software\\rea'],
  });
  const same = compareBehaviorContracts(target, target);
  assert.equal(same.status, 'ran');
  assert.equal(same.score, 1);

  const dropped = contractFrom({ imports: ['CreateFileA'], strings: [] });
  const lower = compareBehaviorContracts(target, dropped);
  assert.ok(lower.score < 1);
  assert.equal(lower.outputs.recall, 0);
  assert.ok(lower.effects.missing.includes('ui:call'));

  const invented = contractFrom({
    imports: ['CreateFileA', 'MessageBoxA', 'WinHttpOpen'],
    strings: ['Cannot open config file.', 'HKCU\\Software\\rea', 'Unexpected failure.'],
  });
  const fabricated = compareBehaviorContracts(target, invented);
  assert.ok(fabricated.effects.precision < 1);
  assert.ok(fabricated.outputs.precision < 1);
  assert.ok(fabricated.effects.added.includes('network:open'));
});

test('an empty comparison is empty, and a one-sided dimension is scored on the side that exists', () => {
  const empty = compareBehaviorContracts(contractFrom({}), contractFrom({}));
  assert.equal(empty.status, 'empty');
  assert.equal(empty.score, null);

  const target = contractFrom({ strings: ['HKCU\\Software\\rea'] });
  const rebuilt = contractFrom({});
  const oneSided = compareBehaviorContracts(target, rebuilt);
  // No effects on either side: that dimension is not applicable. State has a
  // target denominator and zero recall, so the tier is a measured failure.
  assert.equal(oneSided.effects.score, null);
  assert.equal(oneSided.state.score, 0);
  assert.equal(oneSided.status, 'ran');
  assert.ok(behaviorLimitations().length >= 3);
});
