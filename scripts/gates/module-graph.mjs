/**
 * Narrow ES-module edge parser shared by the structure generator and the
 * architecture gate. It understands the forms this repository actually uses:
 * static imports/exports, side-effect imports, literal dynamic imports and
 * `new URL(..., import.meta.url)`. Non-literal dynamic imports are reported
 * instead of silently vanishing from reachability.
 *
 * @module dsh-rea-restore/scripts/gates/module-graph
 */

const STATIC_FROM = /\b(?:import|export)\s+(?:[^'";]*?\s+from\s*)?(['"])([^'"]+)\1/g;
const DYNAMIC_LITERAL = /\bimport\s*\(\s*(['"`])([^'"`$\n]+)\1\s*\)/g;
const META_URL = /\bnew\s+URL\s*\(\s*(['"`])(\.[^'"`$\n]+)\1\s*,\s*import\.meta\.url\s*\)/g;
const DYNAMIC_EXPRESSION = /\bimport\s*\(\s*([^)\n]{1,200})\s*\)/g;

const snippet = (value) => String(value).replace(/\s+/g, ' ').trim();

/**
 * @param {string} source
 * @returns {{edges: string[], unresolved: string[]}}
 */
export function parseModuleEdges(source) {
  const text = String(source ?? '');
  const edges = [];
  const unresolved = [];
  const seen = new Set();
  const add = (specifier) => {
    if (!seen.has(specifier)) {
      seen.add(specifier);
      edges.push(specifier);
    }
  };
  for (const match of text.matchAll(STATIC_FROM)) add(match[2]);
  for (const match of text.matchAll(DYNAMIC_LITERAL)) add(match[2]);
  for (const match of text.matchAll(META_URL)) add(match[2]);

  const literalSpans = [...text.matchAll(DYNAMIC_LITERAL)].map((match) => match[0]);
  let remaining = text;
  for (const literal of literalSpans) remaining = remaining.replace(literal, '');
  for (const match of remaining.matchAll(DYNAMIC_EXPRESSION)) {
    const expression = snippet(match[1]);
    if (expression.length > 0 && !unresolved.includes(expression)) unresolved.push(expression);
  }
  return { edges, unresolved };
}