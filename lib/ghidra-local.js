/**
 * A first-party Ghidra runner.
 *
 * REA ships its own Ghidra integration, but on Windows it builds a private
 * runtime with a DACL the child JVM cannot write into, so the engine dies before
 * it reads a byte: temp, then cache, then config, then the log file, then the
 * project directory that `-projectPath` pins inside the same runtime. That last
 * one cannot be moved by any system property - the path is chosen by REA.
 *
 * This module does not patch an installed third-party bundle. It runs Ghidra
 * directly from the same installation, in a project directory this plugin owns,
 * with the JVM's per-user directories redirected the same way. The result is an
 * engine that can answer "what is at this address" on hosts where the wrapped
 * provider cannot start.
 *
 * @module dsh-rea/lib/ghidra-local
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { detectGhidra, ENGINE_ENV_OVERRIDES } from './engines.js';
import { PLUGIN_ROOT } from './paths.js';
import { resolveWorkRoot } from './work-root.js';

/** Scripts are copied out of the bundle so Ghidra never writes into it. */
const SCRIPT_DIR = join(PLUGIN_ROOT, 'scripts', 'ghidra');
const SCRIPT_NAME = 'ProbeAddress.java';
const LOG4J_NAME = 'log4j-headless.xml';
const DEFAULT_TIMEOUT_MS = 240_000;

/** True when this host can run Ghidra under our own control. */
export { resolveWorkRoot } from './work-root.js';

export async function ghidraLocalReadiness(env = process.env) {
  const ghidra = await detectGhidra({ ...env, ...ENGINE_ENV_OVERRIDES });
  if (!ghidra.available) return { ready: false, reason: 'Ghidra not installed', path: null };
  if (!ghidra.ready) {
    return {
      ready: false,
      reason: ghidra.java?.sufficientForGhidra === false
        ? `JDK ${ghidra.java.version ?? 'unknown'} is too old`
        : 'Ghidra installed but no usable JDK',
      path: ghidra.path,
    };
  }
  const root = resolveWorkRoot(env);
  if (!root) {
    return {
      ready: false,
      reason: 'no writable project directory whose path is free of dot-prefixed elements and spaces',
      path: ghidra.path,
    };
  }
  return { ready: true, reason: null, path: ghidra.path, work: root, version: ghidra.version };
}

function stageScripts(root) {
  const target = join(root, 'scripts');
  for (const name of [SCRIPT_NAME, LOG4J_NAME]) {
    try {
      copyFileSync(join(SCRIPT_DIR, name), join(target, name));
    } catch (error) {
      throw new Error(`cannot stage ${name}: ${error?.message ?? error}`);
    }
  }
  return target;
}

/**
 * Environment for the child JVM only.
 *
 * `_JAVA_OPTIONS` is the one channel Ghidra's launcher honours without editing
 * its `launch.properties`, which an upgrade would overwrite. It applies to this
 * child alone; the parent process and REA's own children are untouched.
 */
function childEnv(ghidra, root) {
  const options = [
    `-Dapplication.tempdir=${join(root, 'tmp')}`,
    `-Dapplication.cachedir=${join(root, 'cache')}`,
    `-Dapplication.settingsdir=${join(root, 'settings')}`,
    `-Djava.io.tmpdir=${join(root, 'tmp')}`,
    `-Dlog4j.configurationFile=${join(root, 'scripts', LOG4J_NAME)}`,
  ];
  return {
    ...process.env,
    JAVA_HOME: ghidra.java?.home ?? process.env.JAVA_HOME,
    GHIDRA_INSTALL_DIR: ghidra.path,
    _JAVA_OPTIONS: options.join(' '),
  };
}

const MAX_OUTPUT = 4 * 1024 * 1024;

function run(command, args, { env, timeoutMs, signal } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
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
      // cmd.exe owns the JVM as a grandchild; killing the shell alone leaves it
      // running and the next attempt collides with the project lock.
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

/** One project per file version, so a second probe skips the analysis. */
function projectFor(binaryPath) {
  let stamp = '';
  try {
    const stat = statSync(binaryPath);
    stamp = `${binaryPath}:${stat.size}:${stat.mtimeMs}`;
  } catch {
    stamp = binaryPath;
  }
  return `p${createHash('sha256').update(stamp).digest('hex').slice(0, 16)}`;
}

const findProbe = (text) => {
  const line = text.split(/\r?\n/).find((entry) => entry.includes('PROBE {'));
  if (!line) return null;
  const start = line.indexOf('PROBE {');
  try {
    return JSON.parse(line.slice(start + 6).trim());
  } catch {
    return null;
  }
};

/**
 * Strip Ghidra's log decoration from script output.
 *
 * Headless routes `println` through log4j, so every line the script emits
 * arrives as `12:33:24 INFO  ProbeAddress.java> ...`. Only the first line of a
 * multi-line block gets the prefix, so removing whole lines would delete
 * pseudocode; the prefix has to be stripped in place.
 */
const LOG_PREFIX = /^\d{2}:\d{2}:\d{2}\s+(?:TRACE|DEBUG|INFO|WARN|ERROR)\s+ProbeAddress\.java>\s?/;
const stripLogPrefix = (line) => line.replace(LOG_PREFIX, '');

const findDecompiled = (text) => {
  const begin = text.indexOf('DECOMPILE_BEGIN');
  const end = text.indexOf('DECOMPILE_END');
  if (begin < 0 || end < begin) return null;
  const firstBreak = text.indexOf('\n', begin);
  if (firstBreak < 0) return null;
  return text.slice(firstBreak + 1, end)
    .split(/\r?\n/)
    .map(stripLogPrefix)
    .filter((line) => !/^(?:TRACE|DEBUG|INFO|WARN|ERROR)\s+ProbeAddress\.java>\s*$/.test(line))
    .join('\n')
    .replace(/^\s*\n+/, '')
    .replace(/\s+$/u, '');
};

async function invoke(binaryPath, scriptArgs, { timeoutMs, signal } = {}) {
  const readiness = await ghidraLocalReadiness();
  if (!readiness.ready) return { ok: false, code: 'unavailable', reason: readiness.reason };
  const ghidra = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  const root = readiness.work;
  let scripts;
  try {
    scripts = stageScripts(root);
  } catch (error) {
    return { ok: false, code: 'unavailable', reason: String(error?.message ?? error) };
  }
  const headless = join(readiness.path, 'support', process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless');
  if (!existsSync(headless)) {
    return { ok: false, code: 'unavailable', reason: 'analyzeHeadless is missing from the install' };
  }

  const projectDir = join(root, 'projects');
  const name = projectFor(binaryPath);
  const tail = ['-scriptPath', scripts, '-postScript', SCRIPT_NAME, ...scriptArgs];
  const env = childEnv(ghidra, root);
  const command = process.platform === 'win32' ? (process.env.ComSpec || 'cmd.exe') : headless;
  const wrap = (rest) => (process.platform === 'win32' ? ['/d', '/s', '/c', headless, ...rest] : rest);

  const started = Date.now();
  let usedCache = existsSync(join(projectDir, `${name}.gpr`));
  // `-process` takes an *optional* program name; passing the project name there
  // makes Ghidra look for a program with that name and abort. With no argument
  // it processes the single program the project holds.
  let result = await run(command, wrap([projectDir, name, ...(usedCache
    ? ['-process', '-noanalysis']
    : ['-import', binaryPath]), ...tail]), { env, timeoutMs, signal });

  // A project left locked by a killed run poisons every later probe; the
  // cheapest recovery is to drop it and analyze once more from the file.
  if (usedCache && !findProbe(result.stdout + result.stderr) && /lock|in use|Unable to open project/i.test(result.stderr)) {
    try { rmSync(join(projectDir, `${name}.gpr`), { recursive: true, force: true }); } catch { /* best effort */ }
    try { rmSync(join(projectDir, `${name}.rep`), { recursive: true, force: true }); } catch { /* best effort */ }
    usedCache = false;
    result = await run(command, wrap([projectDir, name, '-import', binaryPath, ...tail]), { env, timeoutMs, signal });
  }

  const text = `${result.stdout}\n${result.stderr}`;
  return {
    ...result,
    text,
    elapsedMs: Date.now() - started,
    cached: usedCache,
    probe: findProbe(text),
    decompiled: findDecompiled(text),
  };
}

/**
 * Ask the engine what is at one address.
 *
 * `rva` is relative to the image base: a hardened sample may change the
 * preferred base at load time, and the RVA survives that.
 */
export async function probeWithGhidra(binaryPath, { rva, kind = 'code', timeoutMs, signal } = {}) {
  const run_ = await invoke(binaryPath, [`0x${Number(rva).toString(16)}`, 'probe', kind], { timeoutMs, signal });
  if (run_.code === 'unavailable' || run_.ok === false) return run_;
  if (run_.timedOut) return { ok: false, code: 'timeout', reason: `Ghidra did not finish within ${timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`, elapsedMs: run_.elapsedMs };
  if (!run_.probe) {
    return {
      ok: false,
      code: 'no-answer',
      reason: (run_.stderr || run_.stdout || '').split(/\r?\n/).filter(Boolean).slice(-3).join(' | ') || 'the script produced no answer',
      elapsedMs: run_.elapsedMs,
    };
  }
  if (run_.probe.ok !== true) {
    return { ok: false, code: run_.probe.error ?? 'no-answer', reason: run_.probe.error ?? 'the script reported an error', elapsedMs: run_.elapsedMs };
  }
  return {
    ok: true,
    engine: 'ghidra-local',
    elapsedMs: run_.elapsedMs,
    cached: run_.cached,
    ...run_.probe,
    // The name a reader wants is whichever the symbol table has: a TLS callback
    // is a symbol before it is a function.
    name: run_.probe.symbol || run_.probe.function || run_.probe.pointerFunction || run_.probe.pointerSymbol || null,
  };
}

/** Decompile the function at or containing one address. */
export async function decompileWithGhidra(binaryPath, { rva, timeoutMs, signal } = {}) {
  const outcome = await invoke(binaryPath, [`0x${Number(rva).toString(16)}`, 'decompile'], { timeoutMs, signal });
  if (outcome.code === 'unavailable' || outcome.ok === false) return outcome;
  if (outcome.timedOut) return { ok: false, code: 'timeout', reason: 'Ghidra did not finish', elapsedMs: outcome.elapsedMs };
  if (!outcome.probe || outcome.probe.ok !== true) {
    return {
      ok: false,
      code: outcome.probe?.error ?? 'no-answer',
      reason: outcome.probe?.error ?? 'the script produced no answer',
      elapsedMs: outcome.elapsedMs,
    };
  }
  return {
    ok: true,
    engine: 'ghidra-local',
    function: outcome.probe.function,
    entry: outcome.probe.entry,
    code: outcome.decompiled ?? '',
    elapsedMs: outcome.elapsedMs,
    cached: outcome.cached,
  };
}
