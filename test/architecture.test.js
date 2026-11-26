/**
 * Architecture enforcement: the lib/ tree is layered, and the layering is a
 * contract, not a convention. Every module lives in exactly one layer
 * directory, imports stay inside the allowed dependency directions, and the
 * non-surface layers are cycle-free. A new module that ignores the layering
 * fails this test instead of silently eroding the structure.
 *
 * Pure source reading - no engine, no network. Smoke-layer safe.
 *
 * @module dsh-rea/test/architecture
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { parseModuleEdges } from '../scripts/gates/module-graph.mjs';
import { structurePaths } from '../scripts/gates/update-code-structure.mjs';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..');
const LIB = join(ROOT, 'lib');
const LAYERS = ['infra', 'static', 'dynamic', 'restore', 'surface'];

/** Dependency directions: a layer may import itself plus the layers listed. */
const ALLOWED = {
  infra: ['infra'],
  static: ['infra', 'static'],
  dynamic: ['infra', 'static', 'dynamic'],
  restore: ['infra', 'static', 'restore'],
  surface: ['infra', 'static', 'dynamic', 'restore', 'surface'],
};

function libFiles(dir) {
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) found.push(...libFiles(full));
    else if (name.endsWith('.js') || name.endsWith('.mjs')) found.push(full);
  }
  return found;
}

const allFiles = libFiles(LIB);
const relOf = (full) => full.slice(LIB.length + 1).replace(/\\/g, '/');
const layerOf = (rel) => rel.split('/')[0];
const specifiersOf = (source) => parseModuleEdges(source).edges.filter((specifier) => specifier.startsWith('.'));

test('the generated structure list contains each entry exactly once', () => {
  const paths = structurePaths(ROOT).map((file) => file.slice(ROOT.length + 1).replace(/\\/g, '/'));
  assert.equal(new Set(paths).size, paths.length);
  assert.equal(paths.filter((path) => path.startsWith('scripts/duel/')).length, 5);
});

test('every lib module lives in exactly one layer directory', () => {
  const strays = readdirSync(LIB).filter((name) => !LAYERS.includes(name));
  assert.deepEqual(strays, [], `stray entries at lib root: ${strays.join(', ')}`);
  for (const rel of allFiles.map(relOf)) {
    assert.ok(LAYERS.includes(layerOf(rel)), `module outside the layers: ${rel}`);
  }
  assert.ok(allFiles.length >= 60, `module count dropped unexpectedly: ${allFiles.length}`);
});

test('imports stay inside the allowed dependency directions', () => {
  const violations = [];
  for (const full of allFiles) {
    const rel = relOf(full);
    const layer = layerOf(rel);
    const src = readFileSync(full, 'utf8');
    for (const specifier of specifiersOf(src)) {
      const targetAbs = join(LIB, rel.split('/').slice(0, -1).join('/'), specifier);
      const targetRel = relOf(targetAbs);
      const targetLayer = targetRel.split('/')[0];
      if (!LAYERS.includes(targetLayer)) {
        violations.push(`${rel} -> non-layer target ${specifier}`);
        continue;
      }
      if (!ALLOWED[layer].includes(targetLayer)) {
        violations.push(`${rel} -> ${targetRel} (${layer} may not import ${targetLayer})`);
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('the non-surface layers are cycle-free', () => {
  const graph = new Map();
  for (const full of allFiles) {
    const rel = relOf(full);
    if (layerOf(rel) === 'surface') continue; // UI wiring may be interdependent
    const src = readFileSync(full, 'utf8');
    const targets = [];
    for (const specifier of specifiersOf(src)) {
      const targetAbs = join(LIB, rel.split('/').slice(0, -1).join('/'), specifier);
      const targetRel = relOf(targetAbs);
      if (layerOf(targetRel) !== 'surface') targets.push(targetRel);
    }
    graph.set(rel, targets);
  }
  // Iterative depth-first search with a colour map; report one cycle.
  const state = new Map();
  let cycle = null;
  const visit = (node, stack) => {
    if (cycle) return;
    state.set(node, 'open');
    stack.push(node);
    for (const next of graph.get(node) ?? []) {
      if (!graph.has(next)) continue;
      if (state.get(next) === 'open') { cycle = [...stack.slice(stack.indexOf(next)), next]; return; }
      if (!state.has(next)) visit(next, stack);
    }
    stack.pop();
    state.set(node, 'done');
  };
  for (const node of graph.keys()) {
    if (!state.has(node)) visit(node, []);
  }
  assert.equal(cycle, null, `import cycle detected: ${(cycle ?? []).join(' -> ')}`);
});
