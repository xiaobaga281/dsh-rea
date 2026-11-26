/**
 * Generate the README "代码结构" block from the modules themselves.
 *
 * Handwritten structure lists drift: the 1.4.0 review found the README claiming
 * a tool count that the code no longer produced, and this block had already
 * lost identity/intel/structure/plan/probe/ghidra-local by 1.9.0. The block is
 * now generated from each file's module header and checked by host-matrix, so
 * adding a module without documenting it (or documenting one that no longer
 * exists) fails the gate instead of aging silently.
 *
 * Also exposes the module reachability walk used by that gate.
 *
 * Run: node scripts/gates/update-code-structure.mjs [--check]
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseModuleEdges } from './module-graph.mjs';

export const BEGIN = '<!-- code-structure:begin -->';
export const END = '<!-- code-structure:end -->';

const ROOT = dirname(fileURLToPath(import.meta.url));

/** First sentence of the file's leading JSDoc block, minus the @module line. */
export function summarize(source) {
  const match = /^\s*\/\*\*([\s\S]*?)\*\//.exec(source);
  if (!match) return '(no module header)';
  const body = match[1]
    .split('\n')
    .map((line) => line.replace(/^\s*\*\s?/, '').trimEnd())
    .filter((line) => !/^\s*@module\b/.test(line))
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (body.length === 0) return '(no module header)';
  const sentence = /^(.*?[.!?。！？])(?:\s|$)/.exec(body)?.[1] ?? body;
  return sentence.length > 220 ? `${sentence.slice(0, 217)}...` : sentence;
}

function listFiles(dir, pattern) {
  // Recursive: lib is layered into subdirectories (infra/static/dynamic/
  // restore/surface), and every module in them is part of the documented
  // structure block.
  if (!existsSync(dir)) return [];
  const found = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const full = join(current, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (pattern.test(name)) found.push(full);
    }
  };
  walk(dir);
  return found;
}

/** Every file the block documents, in a stable and unique order. */
export function structurePaths(root = join(ROOT, '..', '..')) {
  const files = [
    join(root, 'index.js'),
    join(root, 'client.js'),
    ...listFiles(join(root, 'lib'), /\.(?:js|mjs)$/),
    ...listFiles(join(root, 'scripts'), /\.mjs$/),
  ].filter((file) => existsSync(file));
  const unique = [...new Set(files)];
  if (unique.length !== files.length) {
    throw new Error('structure entries contain duplicate paths');
  }
  return unique;
}

/** Every entry the block documents, in a stable order. */
export function structureEntries(root = join(ROOT, '..', '..')) {
  return structurePaths(root).map((file) => {
    const name = file.slice(root.length + 1).replace(/\\/g, '/');
    return `- ${name}: ${summarize(readFileSync(file, 'utf8'))}`;
  });
}

export function generateBlock(root = join(ROOT, '..', '..')) {
  return [BEGIN, '```', ...structureEntries(root), '```', END].join('\n');
}

/** Returns { ok, reason } for the README's generated block. */
export function readmeStructureStatus(readmePath) {
  let readme;
  try { readme = readFileSync(readmePath, 'utf8'); } catch (error) { return { ok: false, reason: `cannot read README.md: ${error.message}` }; }
  const begin = readme.indexOf(BEGIN);
  const end = readme.indexOf(END);
  if (begin < 0 || end < begin) return { ok: false, reason: 'README has no code-structure markers' };
  const actual = readme.slice(begin, end + END.length);
  const expected = generateBlock(dirname(readmePath));
  return actual === expected
    ? { ok: true, reason: null }
    : { ok: false, reason: 'README code-structure block is stale; run npm run structure' };
}

/**
 * Which lib modules cannot be reached from the plugin entry points.
 *
 * Dynamic children are edges too: playbook-worker.mjs is forked through a
 * `new URL('./playbook-worker.mjs', import.meta.url)` expression, not imported,
 * and a walker that only understands `import` would call the live worker dead.
 */
export function moduleReachability(root = join(ROOT, '..', '..')) {
  const libDir = join(root, 'lib');
  const canon = (file) => file.replace(/\\/g, '/');
  const files = [
    join(root, 'index.js'), join(root, 'client.js'),
    ...listFiles(libDir, /\.(?:js|mjs)$/),
  ].filter((file) => existsSync(file)).map(canon);
  const fileSet = new Set(files);
  const edges = new Map();
  const unresolved = [];
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    const dir = posix.dirname(file);
    const parsed = parseModuleEdges(source);
    for (const expression of parsed.unresolved) {
      unresolved.push(`${file.slice(canon(root).length + 1)}: import(${expression})`);
    }
    const targets = parsed.edges
      .filter((specifier) => specifier.startsWith('.'))
      .map((specifier) => posix.normalize(`${dir}/${specifier}`));
    edges.set(file, targets.filter((target) => fileSet.has(target)));
  }
  const reachable = new Set();
  const walk = (file) => {
    if (reachable.has(file)) return;
    reachable.add(file);
    for (const target of edges.get(file) ?? []) walk(target);
  };
  walk(canon(join(root, 'index.js')));
  walk(canon(join(root, 'client.js')));
  const libPrefix = `${canon(libDir)}/`;
  const unreachable = files
    .filter((file) => file.startsWith(libPrefix) && !reachable.has(file))
    .map((file) => file.slice(canon(root).length + 1));
  return {
    unreachable,
    unresolved,
    total: files.filter((file) => file.startsWith(libPrefix)).length,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const readmePath = join(ROOT, '..', '..', 'README.md');
  const check = process.argv.includes('--check');
  if (check) {
    const status = readmeStructureStatus(readmePath);
    console.log(status.ok ? 'code structure: current' : `code structure: ${status.reason}`);
    process.exit(status.ok ? 0 : 1);
  }
  const readme = readFileSync(readmePath, 'utf8');
  const begin = readme.indexOf(BEGIN);
  const end = readme.indexOf(END);
  if (begin < 0 || end < begin) {
    console.error('README has no code-structure markers; add them around the section first.');
    process.exit(1);
  }
  const next = readme.slice(0, begin) + generateBlock(join(ROOT, '..', '..')) + readme.slice(end + END.length);
  writeFileSync(readmePath, next);
  console.log(`code structure: updated ${structureEntries(join(ROOT, '..', '..')).length} entries`);
}
