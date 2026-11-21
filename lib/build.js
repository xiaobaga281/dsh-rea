/**
 * Compile a reconstructed source with the plugin's own gcc.
 *
 * The reconstruction loop's third step is a build: without it, "the source was
 * restored" is a claim with no artefact behind it. This module drives a
 * compiler the plugin prepares itself (see `detectGcc` in engines.js), inside
 * a directory the caller owns, with a wall-clock cap and a serial queue - the
 * same runner shape as `ghidra-local.js`.
 *
 * It never executes the produced binary. The target sample is not compiled,
 * not run and not modified; only source text handed to this module is built.
 *
 * @module dsh-rea/lib/build
 */

import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

import { detectGcc } from './engines.js';

const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const MAX_OUTPUT = 512 * 1024;
const DEFAULT_TIMEOUT_MS = 180_000;

/** Whether a build can actually run here, and with which gcc. */
export async function buildReadiness() {
  return detectGcc();
}

function run(command, args, { cwd, env, timeoutMs, signal } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
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
      // gcc spawns cc1/as/ld as children; killing the driver alone leaves them
      // writing into the work directory the next attempt wants.
      try {
        spawn(process.platform === 'win32' ? 'taskkill' : 'kill', process.platform === 'win32'
          ? ['/pid', String(child.pid), '/t', '/f']
          : ['-TERM', String(child.pid)], { windowsHide: true, stdio: 'ignore' });
      } catch { /* the timeout result is what matters */ }
      child.kill('SIGKILL');
    }, Math.max(5_000, timeoutMs ?? DEFAULT_TIMEOUT_MS));
    const onAbort = () => { try { child.kill('SIGKILL'); } catch { /* already gone */ } };
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

// One build at a time: two gcc runs in the same work directory would overwrite
// each other's .o files, and the loop is sequential by construction anyway.
let buildQueue = Promise.resolve();
function serialize(task) {
  const next = buildQueue.then(task, task);
  buildQueue = next.then(() => {}, () => {});
  return next;
}

/**
 * Compile one C source into a PE.
 *
 * Returns `unavailable` with the probe's reason when no compiler is installed -
 * the caller must report that as blocked, not as a failed reconstruction.
 */
export async function compileC({ sourceText, workDir, name = 'reconstruction', extraArgs = [], timeoutMs, signal } = {}) {
  if (typeof sourceText !== 'string' || sourceText.trim().length === 0) {
    return { ok: false, code: 'empty-source', reason: 'source text is empty' };
  }
  if (Buffer.byteLength(sourceText) > MAX_SOURCE_BYTES) {
    return { ok: false, code: 'too-large', reason: `source exceeds the ${MAX_SOURCE_BYTES}-byte build cap` };
  }
  if (!isAbsolute(workDir ?? '')) {
    return { ok: false, code: 'bad-workdir', reason: 'workDir must be an absolute path' };
  }
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(name)) {
    return { ok: false, code: 'bad-name', reason: 'name must be a simple file stem ([A-Za-z0-9_-], at most 40)' };
  }
  const gcc = await detectGcc();
  if (!gcc.ready) {
    return { ok: false, code: 'unavailable', reason: gcc.reason ?? 'gcc is not ready' };
  }

  return serialize(async () => {
    await mkdir(workDir, { recursive: true });
    const sourcePath = join(workDir, `${name}.c`);
    const outPath = join(workDir, `${name}.exe`);
    await writeFile(sourcePath, sourceText, 'utf8');
    // zig cc needs the explicit gnu target: the host-native default is the MSVC
    // target, and this machine has no MSVC. The caches are shared across builds
    // on purpose: a per-workdir cache recompiles zig's own runtime every time,
    // which turned a one-second compile into a minute-long one.
    //
    // Arguments use bare file names with cwd=workDir: GNU ld on Windows mangles
    // non-ASCII absolute paths (a repo under 新建文件夹 fails with a mojibake
    // output path), and cwd is already the directory we own.
    const sourceArg = `${name}.c`;
    const outputArg = `${name}.exe`;
    const args = gcc.compiler === 'zig'
      ? ['cc', '-target', 'x86_64-windows-gnu', '-std=c11', '-O0', '-o', outputArg, sourceArg, ...extraArgs.filter((item) => typeof item === 'string')]
      : ['-std=c11', '-O0', '-o', outputArg, sourceArg, ...extraArgs.filter((item) => typeof item === 'string')];
    const zigCache = gcc.source === 'managed' && gcc.compiler === 'zig'
      ? join(dirname(dirname(gcc.path)), 'cache')
      : join(tmpdir(), 'dsh-rea-zig-cache');
    const env = gcc.compiler === 'zig'
      ? { ...process.env, ZIG_GLOBAL_CACHE_DIR: zigCache, ZIG_LOCAL_CACHE_DIR: join(zigCache, 'local') }
      : process.env;
    const started = Date.now();
    const result = await run(gcc.path, args, { cwd: workDir, env, timeoutMs, signal });
    const elapsedMs = Date.now() - started;
    if (result.timedOut) {
      return { ok: false, code: 'timeout', reason: `the compiler did not finish within ${timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`, elapsedMs };
    }
    if (result.code !== 0) {
      const diagnostic = [result.stderr, result.stdout].filter(Boolean).join('\n');
      const detail = diagnostic.split(/\r?\n/).filter(Boolean).slice(-6).join(' | ');
      return {
        ok: false,
        code: 'compile-error',
        reason: detail || `the compiler exited with ${result.code}`,
        stderr: result.stderr.slice(-16_000),
        elapsedMs,
      };
    }
    return {
      ok: true,
      code: 'built',
      compiler: gcc.compiler,
      gcc: gcc.path,
      sourcePath,
      outPath,
      elapsedMs,
      warnings: result.stderr.trim().length > 0 ? result.stderr.trim().split(/\r?\n/).slice(0, 8) : [],
    };
  });
}
