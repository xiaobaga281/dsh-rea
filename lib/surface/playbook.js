/**
 * Trusted playbook runner.
 *
 * A playbook turns a long chain of model round-trips into one deterministic
 * script: `rea.call("batch_decompile", {...})`, filter, rename, export. That
 * is a large win, but it is also arbitrary code execution. The boundary here
 * is explicit and deliberately conservative:
 *
 *   - scripts are *files* in a user-owned directory, never inline code from a
 *     conversation. Installing one is an explicit act of trust;
 *   - they run in a child process (not `node:vm`, which is not a sandbox) with
 *     a narrowed environment and no inherited CLI flags;
 *   - every `rea.call` is proxied back to the parent, which applies the same
 *     guard/audit as a normal tool call, enforces a tool whitelist, a call cap
 *     and a wall-clock timeout;
 *   - output is bounded before it reaches the model.
 *
 * This is isolation for accidents and runaway scripts, NOT a security sandbox
 * against a malicious script. Say so in the tool description.
 *
 * @module dsh-rea/lib/playbook
 */

import { fork } from 'node:child_process';
import { readFile, readdir, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const WORKER = fileURLToPath(new URL('./playbook-worker.mjs', import.meta.url));
const MAX_OUTPUT_CHARS = 12_000;

/** One segment, no traversal, .mjs only. */
export function safePlaybookName(name) {
  return typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.mjs$/.test(name) && !name.includes('..')
    ? name : null;
}

export async function listPlaybooks(dir) {
  try {
    const entries = await readdir(dir);
    return entries.filter((name) => safePlaybookName(name) !== null).sort();
  } catch {
    return [];
  }
}

function bounded(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? 'null';
  return text.length > MAX_OUTPUT_CHARS ? `${text.slice(0, MAX_OUTPUT_CHARS)}\n… [truncated]` : text;
}

/**
 * Run one playbook file. `callTool` is the parent's guarded REA caller;
 * `toolNames` supplies the whitelist of tools the child may ask for.
 */
export async function runPlaybook({
  dir,
  name,
  input = {},
  timeoutMs = 120_000,
  maxCalls = 200,
  callTool,
  toolNames = () => [],
  env = {},
}) {
  const safe = safePlaybookName(name);
  if (!safe) throw new Error('playbook name must be a simple .mjs file name in the playbook directory');
  const scriptPath = join(resolve(dir), safe);
  const info = await stat(scriptPath).catch(() => null);
  if (!info?.isFile()) {
    const available = await listPlaybooks(dir);
    throw new Error(`playbook "${safe}" not found in ${dir}. Available: ${available.length > 0 ? available.join(', ') : '(none)'}. Create a .mjs file there to install one.`);
  }
  await readFile(scriptPath, 'utf8');

  const allowed = new Set(toolNames().map((tool) => String(tool).replace(/^mcp__rea__/, '')));
  const started = Date.now();
  const logs = [];
  let calls = 0;
  let settled = false;

  return new Promise((resolvePromise, rejectPromise) => {
    const child = fork(WORKER, [pathToFileURL(scriptPath).href, JSON.stringify(input ?? {})], {
      cwd: resolve(dir),
      env: { PATH: env.PATH ?? process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '', TEMP: process.env.TEMP ?? '', TMP: process.env.TMP ?? '', ELECTRON_RUN_AS_NODE: '1' },
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      execArgv: [],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk) => { if (stderr.length < 8_000) stderr += chunk; });

    let timer;
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch {}
      const fallback = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} complete(); }, 1_500);
      fallback.unref?.();
      const complete = () => {
        clearTimeout(fallback);
        if (error) rejectPromise(error);
        else resolvePromise({ ...value, logs, calls, durationMs: Date.now() - started });
      };
      // Wait for the process to actually release its cwd on Windows before the
      // caller (often a temporary directory) tries to clean it up.
      if (child.exitCode !== null || child.signalCode !== null) complete();
      else child.once('exit', complete);
    };

    timer = setTimeout(() => finish(null, new Error(`playbook timed out after ${timeoutMs} ms`)), timeoutMs);
    timer.unref?.();

    child.on('error', (error) => finish(null, error));
    child.on('exit', (code) => {
      if (!settled) finish(null, new Error(`playbook worker exited before reporting a result (code ${code})${stderr ? `: ${stderr.slice(0, 300)}` : ''}`));
    });

    child.on('message', async (message) => {
      if (settled || !message || typeof message !== 'object') return;
      if (message.type === 'log') {
        if (logs.length < 100) logs.push(String(message.text ?? '').slice(0, 500));
        return;
      }
      if (message.type === 'call') {
        const reply = (ok, value, error) => {
          try { child.send({ type: 'result', id: message.id, ok, value, error }); } catch {}
        };
        if (calls >= maxCalls) return reply(false, null, `playbook exceeded the ${maxCalls}-call limit`);
        const raw = String(message.tool ?? '');
        if (!allowed.has(raw)) return reply(false, null, `tool "${raw}" is not in the REA catalog`);
        calls += 1;
        try {
          const result = await callTool(raw, message.args ?? {});
          const serialised = JSON.stringify(result ?? null);
          if (serialised !== undefined && serialised.length > 512_000) {
            return reply(false, null, 'tool result exceeded the 512 KB playbook transfer cap; use rea_export_report instead');
          }
          reply(true, result ?? null, null);
        } catch (error) {
          reply(false, null, error?.message ?? String(error));
        }
        return;
      }
      if (message.type === 'done') {
        finish({ ok: true, result: bounded(message.result ?? null) }, null);
        return;
      }
      if (message.type === 'failed') {
        finish({ ok: false, result: null, error: String(message.error ?? 'playbook failed') }, null);
      }
    });
  });
}
