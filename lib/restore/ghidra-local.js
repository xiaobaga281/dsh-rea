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
 * @module dsh-rea-restore/lib/ghidra-local
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { cpus } from 'node:os';
import { dirname, join } from 'node:path';
import { detectGhidra, ENGINE_ENV_OVERRIDES } from '../infra/engines.js';
import { PLUGIN_ROOT } from '../infra/paths.js';
import { parsePeExports, readPeLayout, rvaToOffset } from '../static/structure.js';
import { resolveWorkRoot } from '../infra/work-root.js';

/** Scripts are copied out of the bundle so Ghidra never writes into it. */
const SCRIPT_DIR = join(PLUGIN_ROOT, 'scripts', 'ghidra');
/** Bump when ProbeAddress.java changes: Ghidra caches compiled classes by path. */
const SCRIPT_VERSION = 5;
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
export { resolveWorkRoot } from '../infra/work-root.js';

export async function ghidraLocalReadiness(env = process.env) {
  const ghidra = await detectGhidra({ ...env, ...ENGINE_ENV_OVERRIDES });
  if (!ghidra.available) return { ready: false, reason: 'Ghidra not installed', path: null };
  if (!ghidra.ready) {
    return {
      ready: false,
      reason: ghidra.javaRequirement?.note ?? 'Ghidra installed but no usable JDK',
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

const MAX_OUTPUT = 32 * 1024 * 1024;
const INVENTORY_PAGE_MAX = 200;
const CALL_EVIDENCE_LIMIT = 32;
const REFERENCE_EVIDENCE_LIMIT = 32;
const INVENTORY_BUDGET_MS = 240_000;

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

export async function sha256File(binaryPath) {
  const handle = await open(binaryPath, 'r');
  const hash = createHash('sha256');
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      hash.update(chunk.subarray(0, bytesRead));
    }
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

export function projectNameForContent(targetSha256) {
  return `p${createHash('sha256').update(`${targetSha256}:v${SCRIPT_VERSION}`).digest('hex').slice(0, 16)}`;
}

export function hasUsableProject(projectDir, name) {
  return existsSync(join(projectDir, `${name}.gpr`))
    && (existsSync(join(projectDir, `${name}.rep`, 'data'))
      || existsSync(join(projectDir, `${name}.rep`, 'idata')));
}

export function projectStatePath(targetSha256, root = resolveWorkRoot()) {
  if (!root || !/^[a-f0-9]{64}$/i.test(String(targetSha256))) return null;
  return join(root, 'cache', 'project-names', `v${SCRIPT_VERSION}`, `${targetSha256}.json`);
}

function freshProjectName(projectDir, base) {
  if (!existsSync(join(projectDir, `${base}.gpr`)) && !existsSync(join(projectDir, `${base}.rep`))) return base;
  for (let index = 1; ; index += 1) {
    const candidate = `${base}-recovered${index === 1 ? '' : `-${index}`}`;
    if (!existsSync(join(projectDir, `${candidate}.gpr`)) && !existsSync(join(projectDir, `${candidate}.rep`))) return candidate;
  }
}

export async function selectProjectName(projectDir, targetSha256, root = resolveWorkRoot()) {
  const base = projectNameForContent(targetSha256);
  const statePath = projectStatePath(targetSha256, root);
  if (statePath) {
    try {
      const state = JSON.parse(await readFile(statePath, 'utf8'));
      if (state?.targetSha256 === targetSha256 && state?.scriptVersion === SCRIPT_VERSION
        && /^[a-z0-9][a-z0-9._-]*$/i.test(String(state?.projectName))
        && hasUsableProject(projectDir, state.projectName)) return state.projectName;
    } catch { /* an absent or damaged pointer falls back to the content project */ }
  }
  return hasUsableProject(projectDir, base) ? base : freshProjectName(projectDir, base);
}

export async function rememberActiveProjectName(root, projectDir, targetSha256, projectName) {
  const statePath = projectStatePath(targetSha256, root);
  if (!statePath || !/^[a-z0-9][a-z0-9._-]*$/i.test(String(projectName))
    || !hasUsableProject(projectDir, projectName)) return false;
  const temporary = `${statePath}.${process.pid}.tmp`;
  try {
    await mkdir(dirname(statePath), { recursive: true });
    await writeFile(temporary, JSON.stringify({ targetSha256, scriptVersion: SCRIPT_VERSION, projectName }), 'utf8');
    await rename(temporary, statePath);
    return true;
  } catch {
    await rm(temporary, { force: true }).catch(() => {});
    return false;
  }
}

export function inventoryCachePath(targetSha256, { pageSize = 48 } = {}, root = resolveWorkRoot()) {
  if (!root || !/^[a-f0-9]{64}$/i.test(String(targetSha256))) return null;
  const size = Math.max(1, Math.min(INVENTORY_PAGE_MAX, Math.floor(Number(pageSize) || 48)));
  const configuration = [size, CALL_EVIDENCE_LIMIT, REFERENCE_EVIDENCE_LIMIT, INVENTORY_BUDGET_MS].join(':');
  const key = createHash('sha256').update(`${targetSha256}:v${SCRIPT_VERSION}:${configuration}`).digest('hex');
  return join(root, 'cache', 'function-lists', `v${SCRIPT_VERSION}`, `${key}.json`);
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

function engineFailureReason(result) {
  const lines = `${result?.stdout ?? ''}\n${result?.stderr ?? ''}`.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const meaningful = lines.filter((line) => /error|exception|caused by|denied|access|lock|unable|no program|invalid project|corrupt/i.test(line));
  return (meaningful.length > 0 ? meaningful : lines).slice(-8).join(' | ') || 'the script produced no answer';
}

export function hasEngineAnswer(text, mode) {
  return mode === 'list' ? parseFunctionList(text).done !== null : findProbe(text) !== null;
}

export function shouldRecoverProject(text, mode) {
  return !hasEngineAnswer(text, mode) && /lock|in use|Unable to open project|No program files found|Project (?:data directory|marker file) not found|ClosedException|File is closed|DomainObjectException|Import failed/i.test(String(text ?? ''));
}

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

async function invokeOnce(binaryPath, scriptArgs, { timeoutMs, signal, targetSha256 = null } = {}) {
  const readiness = await ghidraLocalReadiness();
  if (!readiness.ready) return { ok: false, code: 'unavailable', reason: readiness.reason };
  let contentSha = targetSha256;
  if (contentSha === null) {
    try {
      contentSha = await sha256File(binaryPath);
    } catch (error) {
      return { ok: false, code: 'unreadable', reason: `cannot hash target bytes: ${error?.message ?? error}` };
    }
  }
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
  const name = projectNameForContent(contentSha);
  const tail = ['-scriptPath', scripts, '-postScript', SCRIPT_NAME, ...scriptArgs];
  const env = childEnv(ghidra, root);
  const command = process.platform === 'win32' ? (process.env.ComSpec || 'cmd.exe') : headless;
  const wrap = (rest) => (process.platform === 'win32' ? ['/d', '/s', '/c', headless, ...rest] : rest);

  const started = Date.now();
  let projectName = await selectProjectName(projectDir, contentSha, root);
  let usedCache = hasUsableProject(projectDir, projectName);
  // `-process` takes an *optional* program name; passing the project name there
  // makes Ghidra look for a program with that name and abort. With no argument
  // it processes the single program the project holds.
  const analysisFlags = ['-max-cpu', String(MAX_CPU), '-analysisTimeoutPerFile', String(ANALYSIS_TIMEOUT_SECONDS)];
  let result = await run(command, wrap([projectDir, projectName, ...(usedCache
    ? ['-process', '-noanalysis', '-max-cpu', String(MAX_CPU)]
    : ['-import', binaryPath, ...analysisFlags]), ...tail]), { env, timeoutMs, signal });

  // A locked or damaged cached project must not poison later probes. Keep it
  // untouched for diagnosis and import into a fresh recovery project instead.
  const attemptText = `${result.stdout}\n${result.stderr}`;
  if (usedCache && shouldRecoverProject(attemptText, scriptArgs[1])) {
    projectName = freshProjectName(projectDir, name);
    usedCache = false;
    result = await run(command, wrap([projectDir, projectName, '-import', binaryPath, ...analysisFlags, ...tail]), { env, timeoutMs, signal });
    const retryText = `${result.stdout}\n${result.stderr}`;
    if (shouldRecoverProject(retryText, scriptArgs[1])) {
      projectName = freshProjectName(projectDir, name);
      usedCache = false;
      result = await run(command, wrap([projectDir, projectName, '-import', binaryPath, ...analysisFlags, ...tail]), { env, timeoutMs, signal });
    }
  }

  const text = `${result.stdout}\n${result.stderr}`;
  if (hasEngineAnswer(text, scriptArgs[1])) {
    await rememberActiveProjectName(root, projectDir, contentSha, projectName);
  }
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
      reason: engineFailureReason(run_),
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
      reason: outcome.probe?.error ?? engineFailureReason(outcome),
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
      if (current) {
        const body = current.body.join('\n');
        functions.push({ ...current, body, decompiled: body.trim() !== '(decompile failed)' });
      }
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
const integer = (value) => Number.isInteger(value) && value >= 0;

export function aggregateFunctionPages(input, { allowDecompileFailures = false } = {}) {
  const pages = Array.isArray(input) ? input : [];
  const functions = [];
  const byRva = new Map();
  const byExport = new Map();
  const cursors = new Set();
  const duplicateSamples = [];
  let total = null;
  let pageSize = null;
  let expectedCursor = 0;
  let emitted = 0;
  let failed = 0;
  let timeStopped = false;
  let deduplicated = 0;
  const fail = (reason, code = 'inventory-invalid') => ({
    ok: false, code, reason, total, emitted, failed, truncated: true,
    timeStopped, inventoryComplete: false, enumerationComplete: false, deduplicated, functions, pages: pages.length,
  });
  if (pages.length === 0) return fail('the function inventory returned no pages', 'no-answer');

  for (const parsed of pages) {
    const header = parsed?.header;
    const done = parsed?.done;
    if (!header || !done || done.ok !== true) return fail('a function page is missing its LIST or LIST_DONE marker');
    if (!integer(done.total) || !integer(done.cursor) || !integer(done.emitted) || !integer(done.failed)) {
      return fail('a function page has invalid total/cursor/emitted/failed metadata');
    }
    if (total === null) total = done.total;
    if (done.total !== total || header.total !== total) return fail(`function page total mismatch: expected ${total}, received ${done.total}/${header.total}`, 'inventory-total-mismatch');
    if (cursors.has(done.cursor)) return fail(`duplicate function page at cursor ${done.cursor}`, 'inventory-duplicate-page');
    if (!integer(header.cursor) || header.cursor !== done.cursor || header.cursor !== expectedCursor) {
      return fail(`missing function page: expected cursor ${expectedCursor}, received ${done.cursor}`, 'inventory-page-mismatch');
    }
    cursors.add(done.cursor);
    if (!integer(header.pageSize) || header.pageSize < 1 || header.pageSize > INVENTORY_PAGE_MAX || done.pageSize !== header.pageSize) {
      return fail('a function page has an invalid or inconsistent pageSize');
    }
    if (pageSize === null) pageSize = header.pageSize;
    if (header.pageSize !== pageSize) return fail(`function page size mismatch: expected ${pageSize}, received ${header.pageSize}`);
    if (header.emitted !== done.emitted || !Array.isArray(parsed.functions) || parsed.functions.length !== done.emitted || done.emitted > pageSize) {
      return fail('a function page emitted count does not match its function records');
    }
    emitted += done.emitted;
    failed += done.failed;
    timeStopped ||= done.timeStopped === true;
    if (done.failed > 0 && !allowDecompileFailures) return fail(`${done.failed} function decompilation(s) failed`, 'decompile-failed');
    if (timeStopped) return fail('the function inventory stopped at its decompile deadline', 'inventory-time-stopped');
    const end = done.cursor + done.emitted;
    const final = end === total;
    if (done.nextCursor !== null && (!integer(done.nextCursor) || done.nextCursor !== end)) {
      return fail(done.nextCursor <= done.cursor
        ? `cursor loop at ${done.nextCursor}`
        : `cursor does not advance to the next page boundary: ${done.nextCursor}`, 'inventory-cursor-invalid');
    }
    if (final && done.nextCursor !== null) return fail('the final function page advertises another cursor');
    if (!final && (done.nextCursor === null || done.emitted !== pageSize)) return fail(`missing function page after cursor ${done.cursor}`, 'inventory-missing-page');
    const completionMarkerValid = done.inventoryComplete === final
      || (allowDecompileFailures && done.failed > 0 && final);
    if (!completionMarkerValid) return fail('a function page inventoryComplete marker disagrees with its cursor boundary');

    for (const fn of parsed.functions) {
      if (!fn || typeof fn.name !== 'string' || fn.name.length === 0 || typeof fn.rva !== 'string' || !/^0x[0-9a-f]+$/i.test(fn.rva)) {
        return fail('a function record has no stable name/RVA identity');
      }
      const rva = fn.rva.toLowerCase();
      const exportName = typeof fn.exportName === 'string' && fn.exportName.length > 0 ? fn.exportName : null;
      let index = byRva.get(rva) ?? (exportName === null ? undefined : byExport.get(exportName));
      if (index !== undefined) {
        deduplicated += 1;
        if (duplicateSamples.length < 8) duplicateSamples.push(`${fn.name}@${fn.rva}`);
        functions[index] = { ...functions[index], ...fn, name: functions[index].name, rva: functions[index].rva, body: functions[index].body || fn.body };
      } else {
        index = functions.length;
        functions.push(fn);
        byRva.set(rva, index);
      }
      if (exportName !== null) byExport.set(exportName, index);
    }
    expectedCursor = end;
    if (final) {
      if (emitted !== total) return fail(`function inventory total mismatch: ${emitted} emitted for ${total} total`, 'inventory-total-mismatch');
      if (deduplicated > 0) return fail(`${deduplicated} duplicate function identity record(s) cannot establish complete coverage: ${duplicateSamples.join(', ')}`, 'inventory-duplicate-identity');
      if (failed > 0) {
        return {
          ok: false, code: 'decompile-failed', reason: `${failed} function decompilation(s) failed`,
          engine: 'ghidra-local', total, emitted, failed, truncated: false, timeStopped: false,
          inventoryComplete: false, enumerationComplete: true, pageSize, pages: pages.length,
          deduplicated, functions,
        };
      }
      return {
        ok: true, code: null, reason: null, engine: 'ghidra-local', total, emitted, failed: 0,
        truncated: false, timeStopped: false, inventoryComplete: true, enumerationComplete: true,
        pageSize, pages: pages.length, deduplicated, functions,
      };
    }
  }
  return {
    ok: true, code: 'inventory-partial', reason: 'more function pages are required', engine: 'ghidra-local',
    total, emitted, failed, truncated: false, timeStopped, inventoryComplete: false,
    pageSize, pages: pages.length, deduplicated, functions,
  };
}


export function selectedInventoryCoverage(listing, names, { sourceFunctions = null } = {}) {
  const requested = Array.isArray(names) ? names : [];
  const missing = [];
  const failed = [];
  const ambiguous = [];
  const enumerated = listing?.inventoryComplete === true || listing?.enumerationComplete === true;
  const usable = enumerated && listing?.truncated !== true && listing?.timeStopped !== true
    && listing?.analysisTimedOut !== true && Array.isArray(listing?.functions);
  let decompiled = 0;
  const sourceFallback = [];
  for (const name of requested) {
    const matches = usable
      ? listing.functions.filter((fn) => fn?.name === name || fn?.exportName === name)
      : [];
    if (matches.length === 0) {
      missing.push(name);
      continue;
    }
    if (matches.length > 1) {
      ambiguous.push(name);
      continue;
    }
    const fn = matches[0];
    const sourceName = sourceFunctions?.has(fn.name) ? fn.name : (fn.exportName && sourceFunctions?.has(fn.exportName) ? fn.exportName : null);
    const body = String(fn.body ?? '').trim();
    const bodyDecompiled = fn.decompiled !== false && body.length > 0 && body !== '(decompile failed)';
    if (bodyDecompiled) decompiled += 1;
    else if (sourceName !== null) sourceFallback.push(name);
    else failed.push(name);
  }
  return {
    complete: usable && requested.length > 0 && missing.length === 0 && failed.length === 0 && ambiguous.length === 0 && sourceFallback.length === 0,
    requested: requested.length, found: requested.length - missing.length - ambiguous.length,
    decompiled, missing, failed, ambiguous, sourceFallback,
  };
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

export async function listFunctionsWithGhidra(binaryPath, { maxFunctions = 48, timeoutMs, signal, allowPartial = false, allowDecompileFailures = false } = {}) {
  const pageSize = Math.max(1, Math.min(INVENTORY_PAGE_MAX, Math.floor(Number(maxFunctions) || 48)));
  let targetSha256;
  try {
    targetSha256 = await sha256File(binaryPath);
  } catch (error) {
    return { ok: false, code: 'unreadable', reason: `cannot hash target bytes: ${error?.message ?? error}` };
  }
  const cachePath = inventoryCachePath(targetSha256, { pageSize });
  if (cachePath !== null) {
    try {
      const cached = JSON.parse(await readFile(cachePath, 'utf8'));
      if (cached?.targetSha256 === targetSha256 && cached.scriptVersion === SCRIPT_VERSION
        && cached.pageSize === pageSize && cached.inventoryComplete === true
        && cached.ok === true && cached.failed === 0 && cached.truncated === false
        && cached.timeStopped === false && cached.analysisTimedOut === false
        && Number.isFinite(cached.total) && cached.emitted === cached.total
        && Array.isArray(cached.functions) && cached.functions.length === cached.total) {
        return applyExportNames({ engine: 'ghidra-local', cached: true, fromCache: true, ...cached }, binaryPath);
      }
    } catch { /* a missing or broken cache means one engine run */ }
  }

  const pages = [];
  let cursor = 0;
  let elapsedMs = 0;
  let cached = false;
  let budgetMs = null;
  let analysisTimedOut = false;
  for (let pageIndex = 0; pageIndex < 100_000; pageIndex += 1) {
    const outcome = await invoke(binaryPath, ['0', 'list', String(pageSize), String(cursor)], { timeoutMs, signal, targetSha256 });
    elapsedMs += outcome.elapsedMs ?? 0;
    cached = cached || outcome.cached === true;
    analysisTimedOut = analysisTimedOut || outcome.analysisTimedOut === true;
    if (outcome.code === 'unavailable' || outcome.ok === false) return { ...outcome, elapsedMs, analysisTimedOut, inventoryComplete: false, truncated: true };
    if (outcome.timedOut) {
      const reason = `Ghidra did not finish within ${timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`;
      const partial = allowPartial ? aggregateFunctionPages(pages, { allowDecompileFailures }) : null;
      if (partial?.ok && partial.functions.length > 0) {
        return { ...partial, ok: false, code: 'inventory-partial', reason, elapsedMs, cached, analysisTimedOut, inventoryComplete: false, timeStopped: true };
      }
      return { ok: false, code: 'timeout', reason, elapsedMs, analysisTimedOut, inventoryComplete: false, truncated: true, timeStopped: true };
    }
    const parsed = parseFunctionList(outcome.text);
    if (!parsed.done || parsed.done.ok !== true) {
      return {
        ok: false, code: 'no-answer', elapsedMs, inventoryComplete: false, truncated: true,
        reason: engineFailureReason(outcome),
      };
    }
    pages.push(parsed);
    budgetMs = parsed.done.budgetMs ?? budgetMs;
    const result = aggregateFunctionPages(pages, { allowDecompileFailures });
    if (!result.ok) return { ...result, elapsedMs, cached, analysisTimedOut };
    if (result.inventoryComplete) {
      if (analysisTimedOut) {
        return { ...result, ok: false, code: 'analysis-timeout', reason: 'Ghidra analysis timed out; the inventory is not complete', elapsedMs, cached, analysisTimedOut: true, analysisTimeoutSeconds: ANALYSIS_TIMEOUT_SECONDS, inventoryComplete: false, truncated: true };
      }
      const complete = {
        ...result, targetSha256, scriptVersion: SCRIPT_VERSION, elapsedMs, cached,
        analysisTimedOut, analysisTimeoutSeconds: ANALYSIS_TIMEOUT_SECONDS, budgetMs,
      };
      if (cachePath !== null) {
        try {
          await mkdir(dirname(cachePath), { recursive: true });
          await writeFile(cachePath, JSON.stringify(complete, null, 2), 'utf8');
        } catch { /* caching is an optimisation, not a requirement */ }
      }
      return applyExportNames(complete, binaryPath);
    }
    cursor = parsed.done.nextCursor;
  }
  return { ok: false, code: 'inventory-page-limit', reason: 'the function inventory exceeded the page safety limit', elapsedMs, inventoryComplete: false, truncated: true };
}
