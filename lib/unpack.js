/**
 * Static unpacking with UPX.
 *
 * Unpacking is a file transformation, not execution: `upx -d` rewrites the
 * packed image into an ordinary PE. The tool is optional and honest about it -
 * a target packed by something else, or not packed at all, gets a precise
 * refusal instead of a silent copy.
 *
 * The binary is not shipped: install UPX and put it on PATH, or drop it at
 * `.tools/upx/upx.exe` beside the plugin.
 *
 * @module dsh-rea/lib/unpack
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { PLUGIN_ROOT } from './paths.js';

const MANAGED = join(PLUGIN_ROOT, '.tools', 'upx', process.platform === 'win32' ? 'upx.exe' : 'upx');
const MAX_OUTPUT = 256 * 1024;

/** Whether a UPX binary can be found. Never runs it against a sample. */
export function unpackReadiness() {
  if (existsSync(MANAGED)) return { ready: true, path: MANAGED, source: 'managed', reason: null };
  const probe = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['upx'], {
    encoding: 'utf8', timeout: 8_000, windowsHide: true, maxBuffer: 64 * 1024,
  });
  const first = `${probe.stdout ?? ''}`.trim().split('\n')[0]?.trim() ?? '';
  const ready = probe.error === undefined && probe.status === 0 && first.length > 0;
  return {
    ready,
    path: ready ? first : null,
    source: ready ? 'path' : null,
    reason: ready ? null : 'UPX not found; install it and put it on PATH, or place upx at .tools/upx',
  };
}

function run(command, args, { timeoutMs = 120_000, signal } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const append = (buffer, isError) => {
      const text = buffer.toString('utf8');
      if (isError) stderr = (stderr + text).slice(-MAX_OUTPUT);
      else stdout = (stdout + text).slice(-MAX_OUTPUT);
    };
    child.stdout.on('data', (chunk) => append(chunk, false));
    child.stderr.on('data', (chunk) => append(chunk, true));
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* best effort */ }
    }, Math.max(5_000, timeoutMs));
    const onAbort = () => { try { child.kill('SIGKILL'); } catch { /* gone */ } };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.on('error', (error) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolvePromise({ code: -1, stdout, stderr, timedOut, error });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolvePromise({ code: code ?? -1, stdout, stderr, timedOut });
    });
  });
}

// One unpack at a time: output paths and UPX's temporary files are not
// designed for concurrent runs against the same source.
let queue = Promise.resolve();
function serialize(task) {
  const next = queue.then(task, task);
  queue = next.then(() => {}, () => {});
  return next;
}

export async function unpackWithUpx({ source, output, timeoutMs = 120_000, signal } = {}) {
  const readiness = unpackReadiness();
  if (!readiness.ready) return { ok: false, code: 'unavailable', reason: readiness.reason };
  return serialize(async () => {
    const started = Date.now();
    const result = await run(readiness.path, ['-d', source, '-o', output], { timeoutMs, signal });
    const elapsedMs = Date.now() - started;
    const text = `${result.stdout}\n${result.stderr}`;
    if (result.timedOut) return { ok: false, code: 'timeout', reason: `UPX did not finish within ${timeoutMs} ms`, elapsedMs };
    if (result.code !== 0) {
      const reason = /NotPackedException|not packed by UPX/i.test(text)
        ? 'the target is not packed by UPX (another packer or not packed at all)'
        : (text.split(/\r?\n/).filter(Boolean).slice(-3).join(' | ') || `UPX exited with ${result.code}`);
      return { ok: false, code: 'not-unpackable', reason, elapsedMs };
    }
    return { ok: true, code: 'unpacked', output, elapsedMs, tool: readiness.path };
  });
}