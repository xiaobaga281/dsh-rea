import assert from 'node:assert/strict';
import test from 'node:test';

import { parseModuleEdges } from '../scripts/gates/module-graph.mjs';
import { moduleReachability } from '../scripts/gates/update-code-structure.mjs';

test('module edges cover static, side-effect, dynamic and import.meta URL forms', () => {
  const source = [
    "import a from './a.js';",
    "import './side.js';",
    "import { b } from \"./b.js\";",
    "export { c } from './c.js';",
    "const d = await import('./d.js');",
    "const worker = new URL('./worker.mjs', import.meta.url);",
  ].join('\n');
  const parsed = parseModuleEdges(source);
  assert.deepEqual(parsed.edges, [
    './a.js', './side.js', './b.js', './c.js', './d.js', './worker.mjs',
  ]);
  assert.deepEqual(parsed.unresolved, []);
});

test('non-literal dynamic imports are reported and ordinary URLs are not module edges', () => {
  const source = [
    'const module = await import(scriptUrl);',
    'const other = await import(pathToFileURL(candidate).href);',
    'const page = new URL(window.location.href);',
  ].join('\n');
  const parsed = parseModuleEdges(source);
  assert.deepEqual(parsed.edges, []);
  assert.deepEqual(parsed.unresolved, ['scriptUrl', 'pathToFileURL(candidate']);
});

test('the real module graph has no duplicate or dead lib entry', () => {
  const graph = moduleReachability();
  assert.deepEqual(graph.unreachable, []);
  assert.ok(graph.total >= 65);
  for (const unresolved of graph.unresolved) assert.match(unresolved, /^.+: import\(.+\)$/);
});