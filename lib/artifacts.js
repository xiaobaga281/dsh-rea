/**
 * Artifact spill and audit trail.
 *
 * A single REA call can return tens of kilobytes - `binary_session` is about
 * 73 KB on a real target - and everything a tool returns is paid again on every
 * later turn of the conversation. Past a budget the text is written to disk and
 * the model gets a head plus a handle, which it can page with
 * `rea_read_artifact`. The same directory holds the audit trail for tool calls
 * that change state, so "what did the agent do to the target" is answerable
 * afterwards.
 *
 * @module dsh-rea/lib/artifacts
 */

import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

const SESSION_ID = `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`;

/** Everything this process writes lives under one session directory. */
export function sessionArtifactRoot(base) {
  return join(base, SESSION_ID);
}

function safeSegment(value) {
  return String(value ?? 'artifact').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
}

/**
 * @param {{ root: string, maxChars?: number, headChars?: number }} options
 */
export function createArtifactStore({ root, maxChars = 24_000, headChars = 2_000 }) {
  let sequence = 0;
  const resolvedRoot = resolve(root);

  const inside = (path) => {
    const absolute = resolve(path);
    return absolute === resolvedRoot || absolute.startsWith(`${resolvedRoot}${sep}`);
  };

  return {
    root: resolvedRoot,

    /**
     * Write an oversized result and return the replacement text, or `undefined`
     * when the result fits and should be returned as-is.
     */
    async maybeSpill(toolName, text) {
      if (typeof text !== 'string' || text.length <= maxChars) return undefined;
      await mkdir(resolvedRoot, { recursive: true });
      sequence += 1;
      const name = `${String(sequence).padStart(3, '0')}-${safeSegment(toolName)}.txt`;
      const path = join(resolvedRoot, name);
      await writeFile(path, text, 'utf8');
      const head = text.slice(0, Math.min(headChars, maxChars));
      const omitted = text.length - head.length;
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
      const text = await readFile(path, 'utf8');
      const slice = text.slice(start, start + size);
      const remaining = Math.max(0, text.length - (start + slice.length));
      return { text: slice, offset: start, returned: slice.length, total: text.length, remaining, nextOffset: remaining > 0 ? start + slice.length : null };
    },

    /** Append one JSON line to the audit trail; failures never break a tool call. */
    async audit(record) {
      try {
        await mkdir(resolvedRoot, { recursive: true });
        await appendFile(join(resolvedRoot, 'audit.jsonl'), `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`, 'utf8');
      } catch {}
    },
  };
}

/**
 * Tool names that change the analysed target, its device, or a debugger session.
 *
 * These are audited. The subset in `DESTRUCTIVE_TOOLS` removes or overwrites
 * something on a device and additionally needs explicit opt-in.
 */
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

/** Removes or overwrites something on a device; requires `allowDeviceMutations`. */
export const DESTRUCTIVE_TOOLS = new Set([
  'uninstall_adb_package', 'install_adb_package', 'push_adb_file', 'stop_adb_app',
]);
