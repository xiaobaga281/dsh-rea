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
 *
 * `guard` can refuse a call before it reaches the child (destructive device
 * operations), and `spill` can replace an oversized result with a head plus a
 * handle on disk. Both are optional so the bridge stays testable on its own.
 */
export function buildTool(client, entry, deferred, { spill, guard } = {}) {
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
      const refusal = guard?.(rawName, args);
      if (typeof refusal === 'string' && refusal.length > 0) throw new Error(refusal);
      const result = await client.callTool(rawName, args, exec?.signal);
      if (result?.isError === true) throw new Error(textOf(result.content) || 'REA reported an error without a message');
      let text = textOf(result?.content);
      if (text.length === 0 && result?.structuredContent !== undefined) {
        try { text = JSON.stringify(result.structuredContent, null, 2); } catch { /* fall through */ }
      }
      const spilled = await spill?.(rawName, text);
      return { text: typeof spilled === 'string' ? spilled : text };
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
    description: 'List or search REA\'s reverse-engineering tools by keyword, or get one tool\'s input schema. Use this before calling an mcp__rea__* tool, since REA\'s full catalog is deferred to keep it out of context. No argument lists every tool name; a keyword filters by name and description; tool="<name>" returns that tool\'s exact parameters.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'Keyword to match against tool names and descriptions. Omit to list every tool name.' },
        tool: { type: 'string', description: 'Exact tool name, with or without the mcp__rea__ prefix. Returns its full input schema.' },
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
      const requested = typeof args?.tool === 'string' ? args.tool.trim() : '';
      const entries = catalog.entries();
      if (entries.length === 0) return { text: 'The REA tool catalog is empty: the MCP server has not listed any tools yet. Check rea_doctor.' };

      // Deferred loading hides the schema, not just the description. A tool with
      // thirteen parameters cannot be called correctly from its name alone, so
      // one exact name returns that tool's full input schema on demand.
      if (requested.length > 0) {
        const wanted = requested.startsWith('mcp__rea__') ? requested : `mcp__rea__${requested}`;
        const entry = entries.find((item) => item.name === wanted || item.name === requested);
        if (entry === undefined) {
          return { text: `No REA tool named ${requested}. Call rea_catalog with no arguments to list every name.` };
        }
        const schema = JSON.stringify(entry.parameters ?? { type: 'object', properties: {} }, null, 2);
        const bounded = schema.length > 8000 ? `${schema.slice(0, 8000)}\n… (schema truncated at 8000 characters)` : schema;
        return {
          text: [
            entry.name,
            clip(entry.description, 500),
            '',
            'Input schema:',
            bounded,
          ].join('\n'),
        };
      }

      if (query.length === 0) {
        const head = `REA tool catalog (${entries.length} tools). Each name below is the exact tool to call; pass a query to see descriptions, or tool="<name>" to see one schema.`;
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

/**
 * One-screen readiness report.
 *
 * 55 of REA's 207 tools take no required argument and operate on "the current
 * document"; on a headless provider they fail with "no target" until something
 * is open. Checking that in one cheap call is far better than discovering it
 * through a failed analysis, so this tool states the target, the provider and
 * the engine inventory up front.
 */
export function buildStatusTool({ client, engines, version }) {
  return {
    name: 'rea_status',
    description: 'Report the current REA session in one screen: whether a target is open, which provider is bound, which analysis engines are installed, and what is therefore possible right now. Read-only. Call this before a long analysis, or when a tool reports "no target".',
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { report: { type: 'string' } }, required: ['report'] },
      render(_args, value) {
        return [{ type: 'text', text: typeof value?.report === 'string' ? value.report : '(no report)' }];
      },
    },
    async execute(_args, exec) {
      const lines = [`dsh-rea ${version ?? 'unknown'}`];
      let environment;
      try {
        environment = await engines?.();
      } catch {}

      if (environment) {
        const java = environment.java ?? {};
        const ghidra = environment.ghidra ?? {};
        const external = environment.external ?? {};
        const mark = (ok) => (ok ? 'ok' : 'missing');
        lines.push(`runtime: ${environment.runtime?.unpacked ? 'unpacked' : 'not ready'}`);
        lines.push(`engines: jdk ${mark(java.fullJdk)}${java.version ? ` (${java.version})` : ''} | ghidra ${mark(ghidra.ready)}${ghidra.version ? ` (${ghidra.version})` : ''} | jadx ${mark(external.jadx)} | apktool ${mark(external.apktool)} | wabt ${mark(external.wabt)} | rizin ${mark(external.rizin)}`);
      }

      let session;
      try {
        const result = await client.callTool('binary_session', {}, exec?.signal);
        session = { ok: result?.isError !== true, text: textOf(result?.content) };
      } catch (error) {
        session = { ok: false, text: error.message };
      }

      if (!session.ok) {
        lines.push(`session: unavailable (${clip(session.text, 200)})`);
        lines.push('next: the REA child is not answering; run rea_doctor.');
        return { report: lines.join('\n') };
      }

      let open;
      let provider;
      let target;
      let providers = [];
      try {
        const core = JSON.parse(session.text).result ?? JSON.parse(session.text);
        open = core.open;
        provider = core.provider?.id ?? core.provider?.name ?? core.provider;
        target = core.target?.path ?? core.target?.name ?? core.target;
        if (Array.isArray(core.capabilities)) {
          providers = core.capabilities
            .map((capability) => capability?.provider?.id ?? capability?.provider?.name ?? capability?.id)
            .filter((name) => typeof name === 'string');
        }
      } catch {
        lines.push(`session: ${clip(session.text, 400)}`);
      }

      if (open === false) {
        lines.push('target: none — call open_binary({"path": "/absolute/path"}) before any analysis tool');
      } else if (open === true) {
        lines.push(`target: ${typeof target === 'string' ? target : target ? clip(JSON.stringify(target), 200) : 'open'}`);
      }
      if (provider) lines.push(`provider: ${typeof provider === 'string' ? provider : clip(JSON.stringify(provider), 120)}`);
      if (providers.length > 0) lines.push(`providers: ${providers.slice(0, 8).join(', ')}`);

      const external = environment?.external ?? {};
      const blocked = [];
      if (!external.jadx) blocked.push('android decompilation (needs JADX)');
      if (!external.apktool) blocked.push('android resources (needs Apktool)');
      if (!external.wabt) blocked.push('wasm validation (needs WABT)');
      if (!environment?.ghidra?.ready) blocked.push('native function analysis (needs Ghidra + full JDK)');
      if (blocked.length > 0) lines.push(`blocked: ${blocked.join('; ')}`);

      return { report: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Page through a result that was spilled to disk instead of kept in context. */
export function buildReadArtifactTool(store) {
  return {
    name: 'rea_read_artifact',
    description: 'Read a bounded page of a large REA result that was written to disk instead of returned inline. Use the path reported by the truncated result; page with offset until remaining is 0.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Absolute path of the spilled artifact, as reported by the truncated result.' },
        offset: { type: 'number', description: 'Character offset to start at. Defaults to 0.' },
        limit: { type: 'number', description: 'Characters to return, at most 64000. Defaults to 12000.' },
      },
      required: ['path'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) {
        return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(empty)' }];
      },
    },
    async execute(args) {
      const page = await store.read(args?.path, args?.offset, args?.limit);
      const tail = page.remaining > 0
        ? `\n\n[characters ${page.offset}-${page.offset + page.returned} of ${page.total}; ${page.remaining} remaining, next offset ${page.nextOffset}]`
        : `\n\n[characters ${page.offset}-${page.offset + page.returned} of ${page.total}; end of artifact]`;
      return { text: `${page.text}${tail}` };
    },
    isConcurrencySafe: () => true,
  };
}
