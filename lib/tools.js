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

import { classifyTool } from './artifacts.js';
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

/**
 * Two extra sentences are worth paying on exactly the results where the model
 * is most likely to overclaim. A decompiler's pseudo-C is an *inference*, not
 * source code, and a state-changing call should be visibly recorded so a later
 * turn does not describe the change as an observation. Everything else keeps
 * the two-sentence default; the guidance is appended to every single result.
 */
const INFERENCE_GUIDANCE = 'Decompiler/reconstruction output is an inference, not source code; verify it against disassembly before treating it as fact.';
const MUTATION_GUIDANCE = 'This call changed REA state and was recorded in the audit trail.';
const INFERENCE_TOOL = /(?:pseudo|decompil|reconstruct|infer|disassembl|hypothes|estimate|guess|^analyze_function$|^batch_decompile$)/i;
const MUTATING_TOOL = /^(?:set_|unset_|annotate_|push_|install_|uninstall_|stop_|start_|load_|unload_|resume_|goto_|import_|record_|update_|capture_|delete_|remove_|kill_|write_|apply_|create_|pull_|collect_|recover_|export_|extract_|decode_)/i;

/** Pick the extra caveat a tool's result needs, or `''` for the default. */
export function guidanceFor(name, entry = {}) {
  const raw = String(name ?? '');
  if (INFERENCE_TOOL.test(raw) || INFERENCE_TOOL.test(String(entry?.description ?? '').slice(0, 200))) {
    return INFERENCE_GUIDANCE;
  }
  return MUTATING_TOOL.test(raw) ? MUTATION_GUIDANCE : '';
}

/** Flatten an MCP content array into the text the model reads. */
export function textOf(content) {
  return flattenContent(content).text;
}

/**
 * Flatten a content array while preserving non-text evidence.
 *
 * REA's screenshot and UI tools return image blocks; embedded resources can
 * carry binary blobs. The old bridge replaced both with a one-line placeholder,
 * which made 18 visual tools effectively unusable and destroyed the original
 * evidence. `onBinary` is given a chance to persist each block and return a
 * short replacement line; without it the behaviour stays read-only and textual.
 */
export function flattenContent(content) {
  const parts = [];
  const binaries = [];
  for (const block of Array.isArray(content) ? content : []) {
    if (block?.type === 'text') {
      parts.push(block.text ?? '');
    } else if (block?.type === 'image') {
      const record = { kind: 'image', mimeType: block.mimeType ?? 'application/octet-stream', data: block.data ?? null };
      binaries.push(record);
      parts.push(`[image result saved as evidence; see the artifact paths below]`);
    } else if (block?.type === 'audio') {
      parts.push(`[audio result unsupported: ${block.mimeType ?? 'unknown type'}]`);
    } else if (block?.type === 'resource_link') {
      parts.push(`Resource link: ${block.name} (${block.uri})`);
    } else if (block?.type === 'resource') {
      const resource = block.resource;
      if (typeof resource?.text === 'string') {
        parts.push(resource.text);
      } else if (resource?.blob !== undefined) {
        const record = {
          kind: 'resource', mimeType: resource.mimeType ?? 'application/octet-stream',
          uri: resource.uri ?? 'unknown', data: resource.blob,
        };
        binaries.push(record);
        parts.push(`[binary resource saved as evidence: ${record.uri}]`);
      } else {
        parts.push(`[embedded resource without text: ${resource?.uri ?? 'unknown uri'}]`);
      }
    } else {
      parts.push('[unsupported MCP content block]');
    }
  }
  return { text: parts.join('\n'), binaries };
}

/**
 * Sample-derived strings and decompiler output are attacker-controlled data.
 * They are wrapped, escaped and truncated so an embedded instruction cannot be
 * mistaken for a conversation directive.
 */
export function markUntrusted(label, text, { maxChars = 4_000 } = {}) {
  const flat = String(text ?? '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '\ufffd')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\r?\n/g, ' \\n ')
    .slice(0, maxChars);
  return `<untrusted-${label}> ${flat}${String(text ?? '').length > maxChars ? ' …[truncated]' : ''} </untrusted-${label}>`;
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
export function buildTool(client, entry, deferred, { spill, guard, metadata, binary } = {}) {
  const rawName = String(entry.name);
  // Computed once at registration, not per call: the extra caveat is a property
  // of the tool, and an inference tool must never be described as source code.
  const caveat = guidanceFor(rawName, entry);
  const guidance = caveat.length > 0 ? `${caveat} ${RESULT_GUIDANCE}` : RESULT_GUIDANCE;
  // Only read-only tools may run concurrently. The 1.3.1 bridge serialised all
  // 207 tools, which made any batch workflow queue behind itself.
  const readOnly = classifyTool(rawName, entry).mutating === false;
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
        return [{ type: 'text', text: `${body}\n\n---\n${guidance}` }];
      },
    },
    async execute(args, exec) {
      // The schema entry reaches the guard so an upstream tool added after this
      // plugin shipped can still be classified from its name and description.
      const refusal = guard?.(rawName, args, entry);
      if (typeof refusal === 'string' && refusal.length > 0) throw new Error(refusal);
      const result = await client.callTool(rawName, args, exec?.signal);
      if (result?.isError === true) throw new Error(textOf(result.content) || 'REA reported an error without a message');
      const flattened = flattenContent(result?.content);
      let text = flattened.text;
      if (text.length === 0 && result?.structuredContent !== undefined) {
        try { text = JSON.stringify(result.structuredContent, null, 2); } catch { /* fall through */ }
      }
      if (flattened.binaries.length > 0 && typeof binary === 'function') {
        const saved = [];
        for (const record of flattened.binaries.slice(0, 8)) {
          const outcome = await binary(rawName, record);
          if (typeof outcome?.path === 'string') saved.push(`${outcome.path} (${outcome.bytes ?? 0} bytes)`);
        }
        text += saved.length > 0
          ? `\n\n[non-text evidence saved: ${saved.join('; ')}. Images and binary resources are kept out of the conversation; review them out-of-band.]`
          : '\n\n[non-text evidence was returned but could not be saved; check the artifact directory permissions.]';
      }
      // Keep the machine-readable anchors even though the model only sees text.
      void metadata?.(rawName, result, text);
      const spilled = await spill?.(rawName, text);
      return { text: typeof spilled === 'string' ? spilled : text };
    },
    // State-changing tools stay serialised; read-only tools can be batched.
    isConcurrencySafe: () => readOnly,
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
export function buildCatalogTool(catalog, cache = null) {
  return {
    name: 'rea_catalog',
    description: 'List or search REA\'s reverse-engineering tools by keyword, or inspect one tool\'s schema. Before calling an mcp__rea__* tool use tool="<name>" to see its parameters. Complex schemas are large: pass path="<dotted field>" to expand one field at a time, or includeOutput=true for the output schema. No argument lists every tool name.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'Keyword to match against tool names and descriptions. Omit to list every tool name.' },
        tool: { type: 'string', description: 'Exact tool name, with or without the mcp__rea__ prefix.' },
        path: { type: 'string', description: 'Dotted JSON path inside the input/output schema, e.g. "left.evidence_id" or "properties.0". Expands one sub-tree instead of truncating a 165 KB schema.' },
        includeOutput: { type: 'boolean', description: 'Return the tool\'s output schema (and its sub-tree at "path") instead of the input schema. Requires the full catalog probe.' },
        includeAnnotations: { type: 'boolean', description: 'Include upstream safety annotations. Defaults to true.' },
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
        if (cache) {
          const described = cache.describe(requested, {
            path: typeof args?.path === 'string' ? args.path : undefined,
            includeOutput: args?.includeOutput === true,
            includeAnnotations: args?.includeAnnotations !== false,
          });
          if (described) {
            return { text: [clip(entry.description, 500), '', described].join('\n') };
          }
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
