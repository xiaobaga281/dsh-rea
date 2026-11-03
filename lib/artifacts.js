/**
 * Artifact spill, change-control policy and audit trail.
 *
 * A single REA call can return tens of kilobytes - `binary_session` is about
 * 73 KB on a real target - and everything a tool returns is paid again on every
 * later turn of the conversation. Past a budget the text is written to disk and
 * the model gets a head plus a handle, which it can page with
 * `rea_read_artifact`.
 *
 * The same module owns two safety decisions:
 *
 *  - *classification*: which tool calls change state. An upstream release can
 *    add a tool that was not in the hardcoded 1.2.0 list, so the list is now a
 *    set of known exceptions on top of a fail-closed rule: anything not clearly
 *    read-only is treated as mutating and audited, and anything that removes or
 *    overwrites something on a device is refused unless explicitly allowed.
 *  - *retention*: spilled results are full decompiler output and can contain
 *    secrets from a sample. They are not immortal. Session directories expire,
 *    total size is capped, and `sensitiveArtifacts` keeps only a head in context
 *    without writing the full text to disk at all.
 *
 * @module dsh-rea/lib/artifacts
 */

import { appendFile, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';

const SESSION_ID = `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`;
/** Only session directories this plugin created are ever eligible for purging. */
const SESSION_DIR_PATTERN = /^\d{4}-\d{2}-\d{2}T[\d-]+Z?-\d+$/;

/** Everything this process writes lives under one session directory. */
export function sessionArtifactRoot(base) {
  return join(base, SESSION_ID);
}

function safeSegment(value) {
  return String(value ?? 'artifact').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
}

/**
 * @param {{
 *   root: string,
 *   base?: string,
 *   maxChars?: number,
 *   headChars?: number,
 *   retentionDays?: number,
 *   maxBytes?: number,
 *   sensitive?: boolean,
 * }} options
 */
export function createArtifactStore({
  root,
  base,
  maxChars = 24_000,
  headChars = 2_000,
  retentionDays = 7,
  maxBytes = 256 * 1024 * 1024,
  sensitive = false,
}) {
  let sequence = 0;
  const resolvedRoot = resolve(root);
  const resolvedBase = resolve(base ?? dirname(resolvedRoot));

  const inside = (path) => {
    const absolute = resolve(path);
    return absolute === resolvedRoot || absolute.startsWith(`${resolvedRoot}${sep}`);
  };

  const store = {
    root: resolvedRoot,
    base: resolvedBase,
    sensitive,

    /**
     * Write an oversized result and return the replacement text, or `undefined`
     * when the result fits and should be returned as-is.
     *
     * In sensitive mode the full body is never persisted: the model gets only a
     * bounded head and a note that paging is unavailable. This is deliberately a
     * lossy mode - it trades convenience for "the sample never lands on disk".
     */
    async maybeSpill(toolName, text) {
      if (typeof text !== 'string' || text.length <= maxChars) return undefined;
      const head = text.slice(0, Math.min(headChars, maxChars));
      const omitted = text.length - head.length;
      if (sensitive) {
        return [
          head,
          '',
          `[... ${omitted} more characters withheld; sensitiveArtifacts is on, so the full result was NOT written to disk and cannot be paged.]`,
          'To page this result, disable sensitiveArtifacts (it will be written under the artifact directory instead).',
        ].join('\n');
      }
      await mkdir(resolvedRoot, { recursive: true });
      sequence += 1;
      const name = `${String(sequence).padStart(3, '0')}-${safeSegment(toolName)}.txt`;
      const path = join(resolvedRoot, name);
      await writeFile(path, text, 'utf8');
      return [
        head,
        '',
        `[... ${omitted} more characters omitted. Full output: ${path}`,
        `Page it with rea_read_artifact({"path": ${JSON.stringify(path)}, "offset": ${head.length}}) rather than repeating the call.]`,
      ].join('\n');
    },

    /** Bounded read-back for a spilled artifact; paths outside the store are refused. */
    async read(path, offset = 0, limit = 12_000) {
      if (typeof path !== 'string' || path.length === 0) throw new Error('path is required');
      if (!inside(path)) throw new Error('rea_read_artifact only reads files under the artifact directory');
      const start = Number.isFinite(offset) && offset > 0 ? Math.floor(offset) : 0;
      const size = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 64_000) : 12_000;
      const body = await readFile(path, 'utf8');
      const slice = body.slice(start, start + size);
      const remaining = Math.max(0, body.length - (start + slice.length));
      return { text: slice, offset: start, returned: slice.length, total: body.length, remaining, nextOffset: remaining > 0 ? start + slice.length : null };
    },

    /** Write one report/export into this session and return its absolute path. */
    async write(name, body) {
      await mkdir(resolvedRoot, { recursive: true });
      sequence += 1;
      const path = join(resolvedRoot, `${String(sequence).padStart(3, '0')}-${safeSegment(name)}`);
      await writeFile(path, body, 'utf8');
      return path;
    },

    /** Append one JSON line to the audit trail; failures never break a tool call. */
    async audit(record) {
      try {
        await mkdir(resolvedRoot, { recursive: true });
        await appendFile(join(resolvedRoot, 'audit.jsonl'), `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`, 'utf8');
      } catch {}
    },

    /**
     * Expire old session directories and enforce a total size cap.
     *
     * Only directories matching this plugin's own session-id shape are touched;
     * a stray folder in `~/.dsh/rea-artifacts` is never deleted. The current
     * session is always kept. Returns a small summary for the sidebar/tool.
     */
    async purge({ olderThanDays = retentionDays, capBytes = maxBytes, now = Date.now() } = {}) {
      let entries;
      try {
        entries = await readdir(resolvedBase, { withFileTypes: true });
      } catch {
        return { removedDirs: 0, freedBytes: 0, keptBytes: 0, skipped: 'base-unreadable' };
      }
      const candidates = [];
      for (const entry of entries) {
        if (!entry.isDirectory() || !SESSION_DIR_PATTERN.test(entry.name)) continue;
        const path = join(resolvedBase, entry.name);
        if (path === resolvedRoot) continue;
        try {
          const info = await stat(path);
          let bytes = 0;
          for (const file of await readdir(path)) {
            try { bytes += (await stat(join(path, file))).size; } catch {}
          }
          candidates.push({ path, mtime: info.mtimeMs, bytes });
        } catch {}
      }
      const cutoff = now - Math.max(0, olderThanDays) * 24 * 60 * 60 * 1000;
      const doomed = new Set(candidates.filter((item) => item.mtime < cutoff).map((item) => item.path));
      let keptBytes = candidates.reduce((sum, item) => sum + item.bytes, 0);
      if (keptBytes > capBytes) {
        for (const item of [...candidates].sort((a, b) => a.mtime - b.mtime)) {
          if (keptBytes <= capBytes) break;
          if (doomed.has(item.path)) continue;
          doomed.add(item.path);
          keptBytes -= item.bytes;
        }
      }
      let removedDirs = 0;
      let freedBytes = 0;
      for (const item of candidates) {
        if (!doomed.has(item.path)) continue;
        try {
          await rm(item.path, { recursive: true, force: true });
          removedDirs += 1;
          freedBytes += item.bytes;
        } catch {}
      }
      return { removedDirs, freedBytes, keptBytes: Math.max(0, keptBytes), retentionDays: olderThanDays, capBytes };
    },
  };
  return store;
}

/* ------------------------------------------------------------------------- *
 * Change-control classification
 * ------------------------------------------------------------------------- */

/**
 * Every first token REA 6.7.0 actually advertises (61 of them). A *new* token
 * in a later release is the fail-closed case: it is audited by default, because
 * a tool we have never seen should not be assumed read-only. A known token,
 * however, is classified by what it does - `procedure_pseudo_code` and
 * `current_address` are read-only even though their first token is a noun.
 */
const KNOWN_FIRST_TOKENS = new Set([
  'inspect', 'list', 'compare', 'trace', 'procedure', 'capture', 'set', 'get',
  'observe', 'start', 'read', 'search', 'analyze', 'project', 'close', 'resolve',
  'current', 'decode', 'verify', 'address', 'find', 'binary', 'extract', 'import',
  'gdb', 'rizin', 'open', 'pull', 'export', 'build', 'annotate', 'comment', 'goto',
  'inline', 'next', 'prev', 'unset', 'xrefs', 'batch', 'demangle', 'execute',
  'load', 'resume', 'unload', 'frida', 'instrument', 'cutter', 'decompile',
  'recover', 'push', 'collect', 'install', 'uninstall', 'stop', 'identify',
  'discover', 'reconcile', 'evaluate', 'correlate', 'record', 'update',
]);

/**
 * Verbs that change the target, a device, a debugger session or the workspace.
 * Deliberately includes `instrument` and `execute` (Frida injection / arbitrary
 * Rizin commands), which the old hardcoded list missed. Ambiguous tokens such
 * as `decode` and `build` are NOT here: their specific tools are audited via
 * `MUTATING_TOOLS` instead of condemning every verb match.
 */
const WRITE_VERBS = new Set([
  'set', 'unset', 'annotate', 'goto', 'capture', 'start', 'close', 'load',
  'unload', 'resume', 'import', 'record', 'update', 'push', 'collect',
  'install', 'uninstall', 'stop', 'pull', 'export', 'extract', 'execute',
  'instrument', 'open', 'recover', 'delete', 'remove', 'kill', 'wipe',
  'overwrite', 'write', 'apply', 'create', 'clear', 'reset', 'rename', 'move',
  'pause', 'detach', 'attach', 'inject', 'patch', 'modify', 'force', 'erase',
  'unlink', 'deploy', 'send', 'post', 'submit', 'grant', 'revoke', 'sign',
]);

/**
 * Verbs that remove or overwrite something on an attached device or target.
 * Combined with a device-ish noun, these are refused without an explicit opt-in.
 */
const DESTRUCTIVE_VERBS = new Set([
  'uninstall', 'remove', 'delete', 'kill', 'wipe', 'overwrite', 'push',
  'install', 'force_stop', 'stop', 'clear', 'reset', 'erase', 'unlink',
]);
const DEVICE_NOUNS = /(?:adb|device|package|app|process|file|firmware|artifact|target|binary|session)/i;

/** Known exceptions where the verb alone would misclassify. */
const KNOWN_READ_ONLY = new Set([
  'binary_session', 'list_documents', 'inspect_analysis_view',
  'compare_functions', 'verify_reconstruction', 'evaluate_reconstruction_coverage',
  'trace_native_values', 'search_strings', 'list_strings',
]);

/** Backwards-compatible: the 1.2.0 hardcoded lists remain as known baselines. */
export const MUTATING_TOOLS = new Set([
  'set_address_name', 'set_addresses_names', 'set_bookmark', 'set_comment', 'set_inline_comment',
  'unset_bookmark', 'annotate_native_function', 'import_managed_reconstruction',
  'record_unknown', 'update_unknown', 'import_evidence_bundle',
  'start_frida_session', 'load_frida_script', 'unload_frida_script', 'resume_frida_session',
  'start_gdb_session', 'start_rizin_debug_session',
  'start_adb_app', 'start_adb_activity', 'stop_adb_app',
  'push_adb_file', 'install_adb_package', 'uninstall_adb_package',
  'capture_native_ui_scenario', 'capture_browser_scenario', 'capture_electron_scenario',
  'capture_process_scenario', 'capture_web_screenshot', 'capture_adb_screen',
  'decode_android_resources', 'extract_artifact', 'extract_firmware',
  'export_evidence_bundle', 'export_web_scripts', 'pull_adb_file', 'pull_adb_package',
  'collect_adb_bugreport', 'recover_javascript_sources',
]);

/** The four operations that are refused by default even when auditing is on. */
export const DESTRUCTIVE_TOOLS = new Set([
  'uninstall_adb_package', 'install_adb_package', 'push_adb_file', 'stop_adb_app',
]);

/**
 * Classify one tool call into a policy decision.
 *
 * @param {string} name raw REA tool name
 * @param {{ description?: string }} [entry] the schema entry, when available
 * @returns {{ mutating: boolean, destructive: boolean, inferred: boolean, verb: string }}
 */
export function classifyTool(name, entry = {}) {
  const raw = String(name ?? '');
  const verb = raw.split('_')[0].toLowerCase();
  if (DESTRUCTIVE_TOOLS.has(raw)) return { mutating: true, destructive: true, inferred: false, verb };
  const description = String(entry?.description ?? '');
  const declaresMutation = /device-mutating|mutates the device|changes the (?:target|device|state)|writes? (?:to|the)|modifies the/i.test(description);
  const declaresReadOnly = /\bread-only\b|\bdoes not (?:change|modify|write)\b/i.test(description);
  const knownToken = KNOWN_FIRST_TOKENS.has(verb) || KNOWN_READ_ONLY.has(raw);
  // Fail closed on vocabulary we have never seen; classify known vocabulary by
  // its verb. A false "mutating" costs one JSONL line, a false "read-only"
  // costs the audit record entirely, so an unknown token is always audited.
  const mutating = declaresReadOnly ? false
    : (WRITE_VERBS.has(verb) || declaresMutation || MUTATING_TOOLS.has(raw) || !knownToken);
  const inferred = !MUTATING_TOOLS.has(raw) && !DESTRUCTIVE_TOOLS.has(raw);
  const destructive = DESTRUCTIVE_VERBS.has(verb) && DEVICE_NOUNS.test(raw);
  return { mutating, destructive, inferred, verb };
}

/**
 * Session-level authorization: when the row names allowed target roots, any
 * absolute path argument outside them is refused. An empty list means "no
 * restriction", which is the default so existing setups are unchanged.
 */
export function pathOutsideScope(args, allowedTargets) {
  if (!Array.isArray(allowedTargets) || allowedTargets.length === 0) return null;
  const roots = allowedTargets.filter((entry) => typeof entry === 'string' && isAbsolute(entry)).map((entry) => resolve(entry));
  if (roots.length === 0) return null;
  const PATH_KEYS = new Set(['path', 'file', 'file_path', 'filepath', 'target', 'target_path', 'source', 'input', 'output', 'directory', 'dir', 'apk', 'binary', 'artifact', 'url']);
  for (const [key, value] of Object.entries(args ?? {})) {
    if (!PATH_KEYS.has(key.toLowerCase()) || typeof value !== 'string' || !isAbsolute(value)) continue;
    const candidate = resolve(value);
    const allowed = roots.some((root) => candidate === root || candidate.startsWith(`${root}${sep}`));
    if (!allowed) return { key, path: value };
  }
  return null;
}
