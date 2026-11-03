import assert from 'node:assert/strict';
import test from 'node:test';

import { createToolRegistry } from '../lib/registry.js';

const definition = (name, description = `${name} description`) => ({
  name,
  description,
  parameters: { type: 'object', properties: {} },
});

function harness() {
  const registered = [];
  const disposed = [];
  const errors = [];
  const registry = createToolRegistry((tool) => {
    registered.push(tool.name);
    return () => disposed.push(tool.name);
  }, { onError: (message) => errors.push(message) });
  return { registry, registered, disposed, errors };
}

test('registers every definition on the first sync', () => {
  const { registry, registered } = harness();
  const result = registry.apply([definition('a'), definition('b')]);
  assert.deepEqual(registered, ['a', 'b']);
  assert.equal(result.added, 2);
  assert.equal(result.size, 2);
});

test('a second identical sync registers nothing', () => {
  const { registry, registered } = harness();
  registry.apply([definition('a'), definition('b')]);
  const result = registry.apply([definition('a'), definition('b')]);
  assert.equal(registered.length, 2);
  assert.equal(result.added, 0);
  assert.equal(result.updated, 0);
});

test('a changed schema is re-registered once', () => {
  const { registry, registered, disposed } = harness();
  registry.apply([definition('a')]);
  const result = registry.apply([{ ...definition('a'), description: 'changed' }]);
  assert.equal(result.updated, 1);
  assert.deepEqual(registered, ['a', 'a']);
  assert.deepEqual(disposed, ['a']);
});

test('a tool the server dropped is disposed', () => {
  const { registry, disposed } = harness();
  registry.apply([definition('a'), definition('b')]);
  const result = registry.apply([definition('a')]);
  assert.equal(result.removed, 1);
  assert.deepEqual(disposed, ['b']);
  assert.deepEqual(registry.names(), ['a']);
});

test('one failing registration does not take the other tools with it', () => {
  const errors = [];
  const registry = createToolRegistry((tool) => {
    if (tool.name === 'bad') throw new Error('schema rejected');
    return () => {};
  }, { onError: (message) => errors.push(message) });
  const result = registry.apply([definition('good1'), definition('bad'), definition('good2')]);
  assert.equal(result.failed, 1);
  assert.equal(result.size, 2);
  assert.deepEqual(registry.names(), ['good1', 'good2']);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /bad/);
});

test('a failed update falls back to the previous definition', () => {
  const live = new Map();
  const registry = createToolRegistry((tool) => {
    if (tool.description === 'changed') throw new Error('no');
    live.set(tool.name, tool);
    return () => live.delete(tool.name);
  });
  registry.apply([definition('a'), definition('b')]);
  registry.apply([definition('a'), { ...definition('b'), description: 'changed' }, definition('c')]);
  assert.deepEqual(registry.names(), ['a', 'b', 'c']);
  assert.equal(live.get('b').description, 'b description');
  assert.equal(live.get('c').description, 'c description');
});

test('disposeAll clears everything', () => {
  const { registry, disposed } = harness();
  registry.apply([definition('a'), definition('b')]);
  registry.disposeAll();
  assert.equal(registry.size, 0);
  assert.deepEqual(disposed.sort(), ['a', 'b']);
});
