/**
 * Full-schema cache and progressive disclosure for REA's deferred catalog.
 *
 * The live child advertises a compact input schema (84 KB across 207 tools)
 * because the full one is 652 KB and the biggest single tool is 165 KB. Both
 * are far too large to hand to a model, but neither is too large to keep in
 * host memory. This module therefore:
 *
 *   - optionally probes a short-lived second child configured with the FULL
 *     input/output schema profiles and caches every entry there;
 *   - serves a compact *outline* by default and expands one JSON path at a
 *     time, so a 13-parameter tool can be understood in a few small calls;
 *   - exposes output schemas and safety annotations on demand.
 *
 * A probe failure is a degraded mode, never an activation failure: the compact
 * schema the live child already supplied stays usable.
 *
 * @module dsh-rea/lib/schema-cache
 */

const OUTLINE_LIMIT = 12_000;

function bounded(value, limit = OUTLINE_LIMIT) {
  const json = JSON.stringify(value, null, 2);
  if (json.length <= limit) return json;
  return `${json.slice(0, limit)}\n… (truncated at ${limit} characters; use a narrower "path" or "includeOutput" to expand a sub-tree)`;
}

/** Navigate a dotted JSON path through the usual JSON-Schema combinators. */
export function schemaAt(schema, dottedPath) {
  let node = schema;
  const parts = String(dottedPath ?? '').split('.').filter(Boolean);
  for (const part of parts) {
    if (!node || typeof node !== 'object') return null;
    if (node.properties?.[part] !== undefined) { node = node.properties[part]; continue; }
    if (node.$defs?.[part] !== undefined) { node = node.$defs[part]; continue; }
    if (/^\d+$/.test(part) && Array.isArray(node.anyOf)) { node = node.anyOf[Number(part)]; continue; }
    if (/^\d+$/.test(part) && Array.isArray(node.oneOf)) { node = node.oneOf[Number(part)]; continue; }
    if (part === 'items' && node.items !== undefined) { node = node.items; continue; }
    if (Object.prototype.hasOwnProperty.call(node, part)) { node = node[part]; continue; }
    return null;
  }
  return node ?? null;
}

/** A shallow, cheap outline: property names, types, required flags, child counts. */
export function schemaOutline(schema) {
  if (!schema || typeof schema !== 'object') return { type: 'unknown' };
  const properties = schema.properties ?? {};
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  const fields = {};
  for (const [name, value] of Object.entries(properties)) {
    const child = value && typeof value === 'object' ? value : {};
    const type = Array.isArray(child.type) ? child.type.join('|') : (child.type ?? (child.anyOf ? 'anyOf' : child.oneOf ? 'oneOf' : 'any'));
    const nested = child.properties ? Object.keys(child.properties).length
      : child.items?.properties ? Object.keys(child.items.properties).length : 0;
    fields[name] = {
      type,
      ...(required.has(name) ? { required: true } : {}),
      ...(nested > 0 ? { nestedFields: nested } : {}),
      ...(typeof child.description === 'string' ? { hint: child.description.slice(0, 120) } : {}),
    };
  }
  return {
    type: schema.type ?? 'object',
    required: [...required],
    fields,
    ...(schema.$defs ? { definitions: Object.keys(schema.$defs).length } : {}),
    additionalProperties: schema.additionalProperties ?? undefined,
  };
}

/** Safety annotations, condensed to what a caller can act on. */
export function annotationSummary(annotations) {
  if (!annotations || typeof annotations !== 'object') return null;
  return {
    readOnlyHint: annotations.readOnlyHint ?? null,
    destructiveHint: annotations.destructiveHint ?? null,
    idempotentHint: annotations.idempotentHint ?? null,
    openWorldHint: annotations.openWorldHint ?? null,
  };
}

/**
 * In-memory index over one `tools/list` result, plus an optional second,
 * full-profile result. Names are accepted with or without the public prefix.
 */
export function createSchemaCache() {
  const compactEntries = new Map();
  const fullEntries = new Map();
  let probeState = 'not-run';

  const normalize = (name) => String(name ?? '').replace(/^mcp__rea__/, '');

  return {
    /** Entries from the live (compact) child. Always available. */
    prime(entries) {
      for (const entry of Array.isArray(entries) ? entries : []) {
        if (typeof entry?.name === 'string') compactEntries.set(entry.name, entry);
      }
      return compactEntries.size;
    },

    /** Entries from the full-profile probe. Replaces any previous probe. */
    primeFull(entries) {
      for (const entry of Array.isArray(entries) ? entries : []) {
        if (typeof entry?.name === 'string') fullEntries.set(entry.name, entry);
      }
      probeState = fullEntries.size > 0 ? 'ready' : 'empty';
      return fullEntries.size;
    },

    markProbeFailed(reason) {
      probeState = `unavailable: ${String(reason).slice(0, 120)}`;
    },

    get status() { return probeState; },
    get compactCount() { return compactEntries.size; },
    get fullCount() { return fullEntries.size; },
    get memoryBytes() {
      let total = 0;
      for (const entry of fullEntries.values()) total += Buffer.byteLength(JSON.stringify(entry));
      return total;
    },

    entry(name) {
      const key = normalize(name);
      return fullEntries.get(key) ?? compactEntries.get(key) ?? null;
    },

    hasFull(name) { return fullEntries.has(normalize(name)); },

    /**
     * Describe one tool. `path` expands a sub-tree (e.g. "left.evidence_id");
     * `includeOutput` returns the full output schema instead of the input one.
     */
    describe(name, { path, includeOutput = false, includeAnnotations = true } = {}) {
      const key = normalize(name);
      const compact = compactEntries.get(key);
      const full = fullEntries.get(key);
      if (!compact && !full) return null;
      const source = full ?? compact;
      const lines = [
        key,
        `catalog profile: ${full ? 'full (complete upstream definitions cached)' : `compact (full probe ${probeState})`}`,
      ];
      if (includeAnnotations) {
        const annotations = annotationSummary(source.annotations ?? compact?.annotations);
        if (annotations) lines.push(`annotations: ${JSON.stringify(annotations)}`);
      }
      if (includeOutput) {
        const output = source.outputSchema ?? full?.outputSchema;
        if (!output) {
          lines.push('Output schema: not available. Enable catalogProbe (default) and check rea_doctor.');
        } else {
          const node = path ? schemaAt(output, path) : output;
          lines.push(path ? `Output schema at "${path}":` : 'Output schema (use "path" to expand one field):');
          lines.push(node === null ? `No output field at path "${path}".` : bounded(path ? node : schemaOutline(output)));
        }
        return lines.join('\n');
      }
      const input = source.inputSchema ?? compact?.inputSchema ?? {};
      if (path) {
        const node = schemaAt(input, path) ?? schemaAt(full?.inputSchema ?? {}, path);
        lines.push(`Input schema at "${path}":`);
        lines.push(node === null
          ? `No field at path "${path}". Top-level fields: ${Object.keys(input.properties ?? {}).join(', ') || '(none)'}`
          : bounded(node));
      } else if (full) {
        lines.push('Input schema outline (use "path" to expand a field):');
        lines.push(bounded(schemaOutline(input)));
      } else {
        lines.push('Input schema (compact profile):');
        lines.push(bounded(input));
      }
      return lines.join('\n');
    },
  };
}

/**
 * Fetch the complete catalog with a short-lived child. The probe uses the same
 * runtime entrypoint and narrowed environment as the live child; only the two
 * schema-profile variables differ. It never blocks activation.
 */
export async function probeFullCatalog({ ReaMcpClient, childEnvironment, config, entry, cwd, version, log = () => {} }) {
  const probeConfig = {
    ...config,
    schemaProfile: 'full',
    outputSchemaProfile: 'full',
  };
  const client = new ReaMcpClient({
    command: process.execPath,
    args: [entry, 'mcp'],
    env: childEnvironment(probeConfig, process.env),
    cwd,
    version,
    initializeTimeoutMs: 60_000,
    log,
  });
  try {
    await client.ready;
    return await client.listTools();
  } finally {
    try { await client.dispose(); } catch {}
  }
}
