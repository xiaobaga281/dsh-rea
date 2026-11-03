/**
 * The tool surface: one bridge per REA tool, plus the two tools this plugin
 * owns (`rea_catalog` and `rea_doctor`).
 *
 * Tools are plain objects rather than `defineTool` from `@deepseek-ai/dsh-tools`:
 * a profile bundle is resolved against the profile's `node_modules`, where that
 * shipped package is not present, so importing it would fail at activation.
 *
 * @module dsh-rea/lib/tools
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

import { childEnvironment } from './config.js';

/** DeepSeek function-name contract: at most 64 characters, only [A-Za-z0-9_-]. */
export const MAX_PUBLIC_NAME_LENGTH = 64;
const INVALID_NAME_CHARS = /[^A-Za-z0-9_-]/g;
const HASH_LENGTH = 12;

/** Deterministic public name for one REA tool: `mcp__rea__<raw>`, or a hashed lossy form. */
export function publicToolName(rawName) {
  const joined = `mcp__rea__${rawName}`;
  const normalized = joined.replace(INVALID_NAME_CHARS, '_');
  if (normalized === joined && normalized.length <= MAX_PUBLIC_NAME_LENGTH) return normalized;
  const hash = createHash('sha256').update(`rea\0${rawName}`).digest('hex').slice(0, HASH_LENGTH);
  return `${normalized.slice(0, MAX_PUBLIC_NAME_LENGTH - HASH_LENGTH - 1)}_${hash}`;
}

/**
 * Appended to every REA tool result.
 *
 * REA returns Evidence records, and a truncated or resource-constrained result
 * must be paged or exported rather than re-requested. Kept to two sentences:
 * it is paid on every single call, so the earlier five-line version was a
 * measurable tax on a long analysis.
 */
export const RESULT_GUIDANCE = [
  'Cite the Evidence ID and its stated coverage limits; never present a static-analysis detail as observed execution.',
  'If a result is truncated, page it with mcp__rea__inspect_analysis_view or export it with mcp__rea__export_evidence_bundle instead of repeating the call.',
].join(' ');

/** Flatten an MCP content array into the text the model reads. */
export function textOf(content) {
  const parts = [];
  for (const block of Array.isArray(content) ? content : []) {
    if (block?.type === 'text') {
      parts.push(block.text ?? '');
    } else if (block?.type === 'image') {
      parts.push(`[image result not forwarded: ${block.mimeType ?? 'unknown type'}; ask REA for the text view of this finding]`);
    } else if (block?.type === 'audio') {
      parts.push(`[audio result unsupported: ${block.mimeType ?? 'unknown type'}]`);
    } else if (block?.type === 'resource_link') {
      parts.push(`Resource link: ${block.name} (${block.uri})`);
    } else if (block?.type === 'resource') {
      // An embedded resource usually carries its content inline; dropping it
      // silently lost whole artifacts (a manifest, a decompiled file) when the
      // server chose that shape.
      const resource = block.resource;
      if (typeof resource?.text === 'string') parts.push(resource.text);
      else if (resource?.blob !== undefined) parts.push(`[embedded binary resource: ${resource?.uri ?? 'unknown uri'}, ${resource?.mimeType ?? 'unknown type'}; ask REA for the text view]`);
      else parts.push(`[embedded resource without text: ${resource?.uri ?? 'unknown uri'}]`);
    } else {
      parts.push('[unsupported MCP content block]');
    }
  }
  return parts.join('\n');
}

/**
 * Turn one `tools/list` entry into a Harness tool definition.
 *
 * The input schema is the server's own, so the model sees exactly what REA
 * documents and a schema change on the server is picked up on the next sync.
 * A structured-content-only result is serialized to text rather than shown
 * empty, and an `isError` result is raised so the model sees the failure.
 */
export function buildTool(client, entry, deferred) {
  const rawName = String(entry.name);
  return {
    name: publicToolName(rawName),
    description: typeof entry.description === 'string' ? entry.description : rawName,
    parameters: entry.inputSchema ?? { type: 'object', additionalProperties: false, properties: {} },
    ...(deferred === true ? { deferLoading: true } : {}),
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { text: { type: 'string' } }, required: ['text'],
      },
      render(_args, value) {
        const body = typeof value?.text === 'string' && value.text.length > 0 ? value.text : '(REA returned no content)';
        return [{ type: 'text', text: `${body}\n\n---\n${RESULT_GUIDANCE}` }];
      },
    },
    async execute(args, exec) {
      const result = await client.callTool(rawName, args, exec?.signal);
      if (result?.isError === true) throw new Error(textOf(result.content) || 'REA reported an error without a message');
      const text = textOf(result?.content);
      if (text.length === 0 && result?.structuredContent !== undefined) {
        try { return { text: JSON.stringify(result.structuredContent, null, 2) }; } catch { /* fall through */ }
      }
      return { text };
    },
    // Analysis is CPU- and disk-heavy; one at a time keeps REA's sessions sane.
    isConcurrencySafe: () => false,
  };
}

/** Collapse a description to one bounded line for the catalog listing. */
function clip(text, limit) {
  const flat = String(text ?? '').replace(/\s+/g, ' ').trim();
  return flat.length <= limit ? flat : `${flat.slice(0, limit - 1)}…`;
}

/**
 * Discovery tool for the deferred catalog.
 *
 * With `deferCatalog` on (the default) the 207 REA tool schemas are held out of
 * the request payload, so the model cannot read them off the tool list. This
 * tool is the small, always-advertised index it searches instead.
 *
 * No argument lists every tool name, which is roughly 6 KB; a keyword adds a
 * one-line description per hit. The names in the output are *already* the exact
 * `mcp__rea__*` identifiers to call - the earlier wording told the model to
 * prefix them again, which would have produced `mcp__rea__mcp__rea__foo`.
 */
export function buildCatalogTool(catalog) {
  return {
    name: 'rea_catalog',
    description: 'List or search REA\'s reverse-engineering tools by keyword. Use this to find the exact mcp__rea__* tool name before calling one, since REA\'s full catalog is deferred to keep it out of context. No argument lists every tool name; a keyword filters by name and description.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'Keyword to match against tool names and descriptions. Omit to list every tool name.' },
      },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { text: { type: 'string' } }, required: ['text'],
      },
      render(_args, value) {
        return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(empty catalog)' }];
      },
    },
    async execute(args) {
      const query = typeof args?.query === 'string' ? args.query.trim().toLowerCase() : '';
      const entries = catalog.entries();
      if (entries.length === 0) return { text: 'The REA tool catalog is empty: the MCP server has not listed any tools yet. Check rea_doctor.' };
      if (query.length === 0) {
        const head = `REA tool catalog (${entries.length} tools). Each name below is the exact tool to call; pass a query to see descriptions.`;
        return { text: [head, ...entries.map((entry) => `- ${entry.name}`)].join('\n') };
      }
      const matches = entries.filter((entry) => entry.name.toLowerCase().includes(query)
        || entry.description.toLowerCase().includes(query));
      const head = `REA tools matching "${query}" (${matches.length} of ${entries.length}). Names are exact:`;
      const lines = matches.slice(0, 40).map((entry) => `- ${entry.name}: ${clip(entry.description, 140)}`);
      if (matches.length > 40) lines.push(`- … ${matches.length - 40} more; narrow the query`);
      return { text: [head, ...lines].join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/**
 * One read-only readiness tool: REA's own doctor, run as a one-shot child.
 *
 * This is the only place the plugin starts a second REA process, and it is
 * bounded: killed on timeout, killed on abort, and its output capped.
 */
export function buildDoctorTool({ config, entry, translate = (_key, fallback) => fallback }) {
  return {
    name: 'rea_doctor',
    description: translate(
      'tool.rea_doctor',
      'Run REA\'s own readiness check and report it as JSON: whether the REA MCP child starts, its server state, and which analysis engines (Ghidra, Hopper, IDA, JADX, Kuna, Apktool) are available or missing. Read-only; never opens a target.',
    ),
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { report: { type: 'string' } }, required: ['report'],
      },
      render(_args, value) {
        return [{ type: 'text', text: typeof value?.report === 'string' ? value.report : '(no report)' }];
      },
    },
    async execute(_args, exec) {
      if (entry === undefined) return { report: 'The rea-agents runtime could not be resolved: the archive is missing or failed to unpack.' };
      const signal = exec?.signal;
      if (signal?.aborted) throw Object.assign(new Error('the doctor run was canceled'), { name: 'AbortError' });
      const child = spawn(process.execPath, [entry, 'mcp', 'doctor', '--json'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: childEnvironment(config, process.env),
      });
      let stdout = '';
      let stderr = '';
      const BUDGET = 1024 * 1024;
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk) => { if (stdout.length < BUDGET) stdout += chunk; });
      child.stderr.on('data', (chunk) => { if (stderr.length < BUDGET) stderr += chunk; });
      const kill = () => { try { child.kill('SIGKILL'); } catch {} };
      const onAbort = () => kill();
      signal?.addEventListener?.('abort', onAbort, { once: true });
      const code = await new Promise((resolveExit) => {
        const timer = setTimeout(() => { kill(); resolveExit(null); }, 120_000);
        timer.unref?.();
        child.once('exit', (exitCode) => { clearTimeout(timer); resolveExit(exitCode); });
        child.once('error', () => { clearTimeout(timer); resolveExit(-1); });
      });
      signal?.removeEventListener?.('abort', onAbort);
      if (signal?.aborted) throw Object.assign(new Error('the doctor run was canceled'), { name: 'AbortError' });
      const body = stdout.trim();
      if (body.length > 0) return { report: body };
      return { report: `rea mcp doctor produced no report (exit ${code ?? 'timed out'})${stderr.trim() ? `\nstderr:\n${stderr.trim()}` : ''}` };
    },
    isConcurrencySafe: () => true,
  };
}
