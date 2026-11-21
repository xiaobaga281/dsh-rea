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
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { cpus } from 'node:os';
import { dirname, join } from 'node:path';
import { detectGhidra, ENGINE_ENV_OVERRIDES } from './engines.js';
import { PLUGIN_ROOT } from './paths.js';
import { parsePeExports, readPeLayout, rvaToOffset } from './structure.js';
import { resolveWorkRoot } from './work-root.js';

/** Scripts are copied out of the bundle so Ghidra never writes into it. */
const SCRIPT_DIR = join(PLUGIN_ROOT, 'scripts', 'ghidra');
/** Bump when ProbeAddress.java changes: Ghidra caches compiled classes by path. */
const SCRIPT_VERSION = 3;
const SCRIPT_NAME = 'ProbeAddress.java';
const LOG4J_NAME = 'log4j-headless.xml';
const DEFAULT_TIMEOUT_MS = 240_000;
// Analysis is the dominant cost on a cold import. Ghidra parallelises its
// analyzers; the default is conservative, so give it the machine's cores
// (bounded) and a per-file ceiling. A timed-out analysis still runs the
// postScript on what was found, and the timeout is reported, never hidden.
const MAX_CPU = Math.max(1, Math.min(8, (cpus().length || 2) - 1));
const ANALYSIS_TIMEOUT_SECONDS = 180;

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
  const target = join(root, 'scripts', `v${SCRIPT_VERSION}`);
  mkdirSync(target, { recursive: true });
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

async function invokeOnce(binaryPath, scriptArgs, { timeoutMs, signal } = {}) {
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
  const analysisFlags = ['-max-cpu', String(MAX_CPU), '-analysisTimeoutPerFile', String(ANALYSIS_TIMEOUT_SECONDS)];
  let result = await run(command, wrap([projectDir, name, ...(usedCache
    ? ['-process', '-noanalysis', '-max-cpu', String(MAX_CPU)]
    : ['-import', binaryPath, ...analysisFlags]), ...tail]), { env, timeoutMs, signal });

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
    analysisTimedOut: /analysis (?:has )?timed out|analysis timeout|Timed out (?:while )?analyzing/i.test(text),
    probe: findProbe(text),
    decompiled: findDecompiled(text),
  };
}

// Ghidra's headless launcher takes an exclusive lock on the project directory
// it opens. Two analyses of different files still collide, because they share
// that directory - and a failed launch reads as "the engine cannot run", which
// is indistinguishable from an install problem. Serialise every engine call
// here rather than trusting the host to schedule the tools one at a time.
let engineQueue = Promise.resolve();
function serialize(task) {
  const next = engineQueue.then(task, task);
  engineQueue = next.then(() => {}, () => {});
  return next;
}

function invoke(binaryPath, scriptArgs, options) {
  return serialize(() => invokeOnce(binaryPath, scriptArgs, options));
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

/**
 * Parse the `list` pass: per-function metadata plus its pseudocode body.
 *
 * Every line goes through the same decoration stripper the decompile path uses,
 * because headless routes println through log4j and only the first line of a
 * multi-line block carries the prefix.
 */
export function parseFunctionList(text) {
  const lines = String(text ?? '').split(/\r?\n/).map(stripLogPrefix);
  const functions = [];
  let header = null;
  let done = null;
  let current = null;
  for (const line of lines) {
    if (line.startsWith('FUNCTION {')) {
      try {
        current = { ...JSON.parse(line.slice('FUNCTION '.length)), body: [] };
      } catch {
        current = null;
      }
      continue;
    }
    if (line === 'FUNCTION_END') {
      if (current) functions.push({ ...current, body: current.body.join('\n') });
      current = null;
      continue;
    }
    if (line.startsWith('LIST_DONE {')) {
      try { done = JSON.parse(line.slice('LIST_DONE '.length)); } catch { done = null; }
      continue;
    }
    if (line.startsWith('LIST {')) {
      try { header = JSON.parse(line.slice('LIST '.length)); } catch { header = null; }
      continue;
    }
    if (current) current.body.push(line);
  }
  return { header, done, functions };
}

/**
 * Enumerate functions and return their pseudocode in one engine run.
 *
 * Entry-only comparison was honest but thin. This is the inventory the loop
 * needs to say "62 of 64 functions match" instead of "the entry matches".
 *
 * Results are cached per (file bytes, cap, script version): analysing the same
 * target on every iteration is what made engine mode take minutes. The list
 * cache and the staged script path share SCRIPT_VERSION, so a changed script
 * invalidates both the compiled class and the cached answers.
 */
function listCachePath(binaryPath, maxFunctions) {
  const root = resolveWorkRoot();
  if (!root) return null;
  let stamp = binaryPath;
  try {
    const stat = statSync(binaryPath);
    stamp = `${binaryPath}:${stat.size}:${stat.mtimeMs}`;
  } catch { /* the engine will report an unreadable file */ }
  const key = createHash('sha256').update(`${stamp}:${maxFunctions}:${SCRIPT_VERSION}`).digest('hex');
  return join(root, 'cache', 'function-lists', `v${SCRIPT_VERSION}`, `${key}.json`);
}


// --------------------------------------------------------- export overlay ----

const EXPORT_READ_BYTES_CAP = 64 * 1024 * 1024;

/**
 * Overlay real export names onto a function listing: a function whose RVA is
 * an exported address is renamed to its export name and flagged
 * `exported: true` (the previous FUN_* name is kept as `listedAs`).
 *
 * Why this exists: Ghidra's analysis does not always promote export labels to
 * function names (measured on sqlite3.dll: 341/358 code exports sit inside the
 * cap-200 window's address span, yet the listing carried zero export names),
 * and export names are the anchors an analyst reaches for first. The FUN_* name
 * is never replaced (a first rename pass broke every gate that requested the
 * old names - measured in the full suite, 2026-11-21); the export name is an
 * additional identity that the gate and the pairing layer both resolve.
 *
 * MSVC /INCREMENTAL builds add one twist (measured on sqlite3.dll, 151/361):
 * the export RVA points at a 5-byte `jmp rel32` thunk, not at the function
 * body. The overlay therefore resolves two candidate RVAs per export - the
 * export address itself and, when that byte is 0xe9, the jump target - and
 * renames the function whose START matches either (via: 'direct' / 'thunk').
 * The overlay is exact - RVA matches against the binary's own export table,
 * parsed node-side (lib/structure.js parsePeExports) - and read-time only: the
 * cache keeps the raw names, so the result is deterministic on every read.
 */
function applyExportNames(listing, binaryPath) {
  try {
    const stat = statSync(binaryPath);
    if (stat.size > EXPORT_READ_BYTES_CAP) {
      return { ...listing, exportNamesApplied: 0, exportNamesNote: 'binary exceeds the export-read cap; names not overlaid' };
    }
    const bytes = readFileSync(binaryPath);
    const layout = readPeLayout(bytes);
    const { exports, count } = parsePeExports(bytes);
    if (exports.length === 0) return { ...listing, exportNamesApplied: 0 };
    const byRva = new Map();
    for (const entry of exports) {
      if (entry.forwarded || entry.rva === null) continue;
      const candidates = [{ rva: entry.rva, via: 'direct' }];
      const off = rvaToOffset(layout, entry.rva);
      if (off !== null && off + 5 <= bytes.length && bytes[off] === 0xe9) {
        candidates.push({ rva: entry.rva + 5 + bytes.readInt32LE(off + 1), via: 'thunk' });
      }
      for (const candidate of candidates) {
        if (!byRva.has(candidate.rva)) byRva.set(candidate.rva, { name: entry.name, via: candidate.via });
      }
    }
    let applied = 0;
    let viaThunk = 0;
    const functions = (listing.functions ?? []).map((fn) => {
      const rva = Number.parseInt(String(fn.rva).replace(/^0x/i, ''), 16);
      const hit = Number.isFinite(rva) ? byRva.get(rva) : undefined;
      if (hit === undefined || hit.name === fn.name) return fn;
      applied += 1;
      if (hit.via === 'thunk') viaThunk += 1;
      // The FUN_* name stays: downstream pairing keys on it (older gate
      // records, drafts and hypotheses all request it). The export name rides
      // along as a second resolvable identity.
      return { ...fn, exportName: hit.name, exported: true, via: hit.via };
    });
    return { ...listing, functions, exportNamesApplied: applied, exportNamesViaThunk: viaThunk || undefined, exportCount: count };
  } catch {
    return { ...listing, exportNamesApplied: 0, exportNamesNote: 'export overlay failed; raw names kept' };
  }
}

export async function listFunctionsWithGhidra(binaryPath, { maxFunctions = 48, timeoutMs, signal } = {}) {
  const cachePath = listCachePath(binaryPath, maxFunctions);
  if (cachePath !== null) {
    try {
      const cached = JSON.parse(await readFile(cachePath, 'utf8'));
      if (cached && Array.isArray(cached.functions)) {
        return applyExportNames({ ok: true, engine: 'ghidra-local', cached: true, fromCache: true, ...cached }, binaryPath);
      }
    } catch { /* a missing or broken cache means one engine run */ }
  }
  const outcome = await invoke(binaryPath, ['0', 'list', String(maxFunctions)], { timeoutMs, signal });
  if (outcome.code === 'unavailable' || outcome.ok === false) return outcome;
  if (outcome.timedOut) {
    return { ok: false, code: 'timeout', reason: `Ghidra did not finish within ${timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`, elapsedMs: outcome.elapsedMs };
  }
  const parsed = parseFunctionList(outcome.text);
  if (!parsed.done || parsed.done.ok !== true) {
    return {
      ok: false,
      code: 'no-answer',
      reason: (outcome.stderr || outcome.stdout || '').split(/\r?\n/).filter(Boolean).slice(-3).join(' | ') || 'the list pass produced no answer',
      elapsedMs: outcome.elapsedMs,
    };
  }
  const result = {
    ok: true,
    engine: 'ghidra-local',
    elapsedMs: outcome.elapsedMs,
    cached: outcome.cached,
    analysisTimedOut: outcome.analysisTimedOut === true,
    analysisTimeoutSeconds: ANALYSIS_TIMEOUT_SECONDS,
    total: parsed.done.total,
    emitted: parsed.done.emitted,
    failed: parsed.done.failed,
    truncated: parsed.done.truncated,
    timeStopped: parsed.done.timeStopped === true,
    budgetMs: parsed.done.budgetMs ?? null,
    functions: parsed.functions,
  };
  if (cachePath !== null) {
    try {
      await mkdir(dirname(cachePath), { recursive: true });
      await writeFile(cachePath, JSON.stringify({
        total: result.total,
        emitted: result.emitted,
        failed: result.failed,
        truncated: result.truncated,
        analysisTimedOut: result.analysisTimedOut,
        timeStopped: result.timeStopped,
        budgetMs: result.budgetMs,
        functions: result.functions,
      }, null, 2), 'utf8');
    } catch { /* caching is an optimisation, not a requirement */ }
  }
  return applyExportNames(result, binaryPath);
}
