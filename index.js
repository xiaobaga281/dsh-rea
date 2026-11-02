/**
 * Host half of `dsh-rea`.
 *
 * REA (github.com/morluto/rea, npm package `rea-agents`, MIT) ships a stdio MCP
 * server (`rea mcp`) carrying a very large tool catalog - roughly 207 tools for
 * native binaries, archives, JavaScript/Electron, APKs, browsers, packets,
 * firmware and static-artifact inspection. This package wires that server into
 * the Harness itself rather than through an MCP bridge row, because a bridge row
 * has to state the child's command in YAML, while here the path is resolved once
 * from the vendored package beside this file.
 *
 * What is registered:
 *
 *   - tools: every REA tool as `mcp__rea__<tool>`, with the server's own input
 *     schema. The public-name contract (64 chars, [A-Za-z0-9_-], lossy-change
 *     hash) is the same one the shipped MCP bridge uses, so a name registered
 *     here can never collide with one registered through a bridge row.
 *   - skills: the upstream `reverse-engineer-anything` skill and its reference
 *     documents, installed into the user DSH skills directory so the
 *     filesystem skill provider discovers them.
 *   - one own tool: `rea_doctor`, a read-only readiness report from REA itself.
 *
 * Tool definitions are registered as plain objects (`ctx.tools.register` is the
 * registry seam, and the host validates the JSON schema it is handed) rather
 * than through `defineTool` from `@deepseek-ai/dsh-tools`: a profile bundle is
 * resolved against the profile's node_modules, where that shipped package is
 * not present, so importing it would fail at activation. The imported modules
 * are Node builtins plus a locally shimmed commonjs bridge helper only.
 *
 * The runtime is shipped as a compressed archive and unpacked on first
 * activation into the DSH home, so the bundle itself stays small while the
 * closure of REA's dependencies - which lazy `require`s several packages only
 * on specific code paths - stays complete. A trimmed tree was measured and
 * rejected: it fails at runtime, on whichever tool touches the missing module.
 *
 * The child runs on the Harness's own node with absolute paths: no npx, no
 * network, no npm cache at call time. It is spawned once and supervised: if it
 * exits, the catalog is re-synced after a bounded backoff while the tools stay
 * registered (calls fail loudly meanwhile), and disposal closes the transport.
 *
 * @module dsh-rea
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, writeFile, readdir } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import https from 'node:https';

const PLUGIN_ROOT = resolve(fileURLToPath(import.meta.url), '..');

/** ── Runtime archive ──────────────────────────────────────────────────── */

/**
 * Where the unpacked runtime lives, and the archive that fills it.
 *
 * The cache sits in the DSH home rather than beside the bundle: a bundle is
 * linked into the profile, and a workspace sandbox has been observed reverting
 * large trees written beside it, which would silently break the plugin.
 */
const RUNTIME_DIR = join(homedir(), '.dsh', 'rea-runtime');
const RUNTIME_ARCHIVE = join(PLUGIN_ROOT, 'vendor', 'rea-runtime.tgz');
const RUNTIME_DIGEST = join(PLUGIN_ROOT, 'vendor', 'rea-runtime.sha256');
const RUNTIME_MARKER = join(RUNTIME_DIR, '.installed.json');

/** Ghidra 12.1.4 is the version REA 6.7.0 validates on the native path. */
const GHIDRA_RELEASE = {
  version: '12.1.4',
  api: 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.4_build',
  url: 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip',
  sha256: 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db',
};
const JADX_RELEASE = {
  version: '0.7.1',
  url: 'https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar',
  sha256: '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75',
};
const APKTOOL_RELEASE = {
  version: '3.0.3',
  url: 'https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar',
  sha256: 'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423',
};
const WABT_RELEASE = {
  version: '1.0.42',
  url: 'https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-windows-x64.tar.gz',
  sha256: '62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88',
};
const TOOL_STATE = new Map();
const ENGINE_CONFIG_FILE = join(homedir(), '.dsh', 'rea-engines', 'config.json');
const ENGINE_CONFIG = {};
try {
  const saved = JSON.parse(readFileSync(ENGINE_CONFIG_FILE, 'utf8'));
  for (const key of ['GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_JADX_MCP_JAR', 'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_KUNA_COMMAND']) {
    if (typeof saved?.[key] === 'string' && saved[key].length > 0) ENGINE_CONFIG[key] = saved[key];
  }
} catch {}
const ENGINE_ROOT = join(homedir(), '.dsh', 'rea-engines');
const GHIDRA_ROOT = join(ENGINE_ROOT, 'ghidra');
const GHIDRA_ARCHIVE = join(ENGINE_ROOT, `ghidra-${GHIDRA_RELEASE.version}.zip`);
const GHIDRA_STATE = { phase: 'idle', bytes: 0, total: 0, message: '', error: null, path: null, version: null };
const ENGINE_ENV_OVERRIDES = { ...ENGINE_CONFIG };
let GHIDRA_INSTALL_PROMISE;

/** SHA-256 of a file without holding a large archive in memory. */
async function sha256File(path) {
  const digest = createHash('sha256');
  await new Promise((resolveDigest, rejectDigest) => {
    const stream = createReadStream(path);
    stream.on('data', (chunk) => digest.update(chunk));
    stream.once('error', rejectDigest);
    stream.once('end', resolveDigest);
  });
  return digest.digest('hex');
}

/** True when the unpacked runtime is present and matches the shipped archive. */
async function runtimeIsCurrent() {
  if (!existsSync(join(RUNTIME_DIR, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs'))) return false;
  try {
    const marker = JSON.parse(await readFile(RUNTIME_MARKER, 'utf8'));
    const expected = (await readFile(RUNTIME_DIGEST, 'utf8')).trim();
    return marker?.archiveSha256 === expected;
  } catch {
    return false;
  }
}

/**
 * Unpack the shipped runtime into the DSH home, once.
 *
 * `tar` is used rather than a JS unpacker because it is present on Windows 10+
 * and every supported host, and it handles the 1 700-file `dist` tree without a
 * dependency. The marker records the archive digest, so a plugin update
 * replaces the runtime instead of leaving a stale one behind.
 */
async function unpackRuntime(log) {
  if (await runtimeIsCurrent()) return true;
  if (!existsSync(RUNTIME_ARCHIVE)) {
    log?.(`dsh-rea: the runtime archive is missing at ${RUNTIME_ARCHIVE}`);
    return false;
  }
  try {
    await rm(RUNTIME_DIR, { recursive: true, force: true });
    // The archive holds the contents of a node_modules directory, so the
    // unpack target is the node_modules subdirectory, not the runtime root.
    const nodeModules = join(RUNTIME_DIR, 'node_modules');
    await mkdir(nodeModules, { recursive: true });
    const expected = (await readFile(RUNTIME_DIGEST, 'utf8')).trim();
    const actual = await sha256File(RUNTIME_ARCHIVE);
    if (actual !== expected) {
      log?.(`dsh-rea: the runtime archive failed its checksum; expected ${expected}, got ${actual}`);
      return false;
    }
    const outcome = spawn('tar', ['-xzf', RUNTIME_ARCHIVE, '-C', nodeModules], {
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    outcome.stderr?.setEncoding('utf8');
    outcome.stderr?.on('data', (chunk) => { stderr += chunk; });
    const code = await new Promise((resolveExit) => {
      outcome.once('exit', (exitCode) => resolveExit(exitCode));
      outcome.once('error', (error) => { stderr += String(error?.message ?? error); resolveExit(-1); });
    });
    if (code !== 0) {
      log?.(`dsh-rea: unpacking the runtime failed (tar exit ${code}): ${stderr.slice(0, 300)}`);
      return false;
    }
    const digest = await sha256File(RUNTIME_ARCHIVE);
    await writeFile(RUNTIME_MARKER, `${JSON.stringify({
      installedBy: 'dsh-rea',
      archiveSha256: digest,
      unpackedAt: new Date().toISOString(),
      nodeModules: join(RUNTIME_DIR, 'node_modules'),
    }, null, 2)}\n`);
    return existsSync(join(RUNTIME_DIR, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs'));
  } catch (error) {
    log?.(`dsh-rea: could not unpack the runtime: ${error.message}`);
    return false;
  }
}

/**
 * Resolve the rea-agents package root: the unpacked cache first, a vendored
 * tree second. Absence is reported by the caller, never thrown at module load,
 * so a broken install lets the Host boot and explain itself.
 */
async function resolveReaPackage(log) {
  if (await unpackRuntime(log)) return join(RUNTIME_DIR, 'node_modules', 'rea-agents');
  const vendored = join(PLUGIN_ROOT, 'vendor', 'node_modules', 'rea-agents');
  if (existsSync(join(vendored, 'scripts', 'rea.mjs'))) return vendored;
  return undefined;
}

/** Return a Java major version from `java -version`, without assuming stdout. */
function javaProbe(home) {
  const command = home ? join(home, 'bin', process.platform === 'win32' ? 'java.exe' : 'java') : 'java';
  const result = spawnSync(command, ['-version'], { encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  const text = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const match = text.match(/version\s+"(\d+)(?:\.(\d+))?/i);
  const major = match ? Number(match[1]) === 1 ? Number(match[2]) : Number(match[1]) : null;
  return {
    available: result.status === 0 && major !== null,
    home: home ?? null,
    command,
    version: match?.[1] ? match[1] : null,
    major,
    fullJdk: false,
    output: text.trim().slice(0, 600),
  };
}

/** Discover a usable full JDK. Ghidra requires a full 64-bit JDK, not a JRE. */
function detectJava(base = process.env) {
  const candidates = [];
  if (typeof base.JAVA_HOME === 'string' && base.JAVA_HOME.length > 0) candidates.push(resolve(base.JAVA_HOME));
  if (process.platform === 'win32') {
    candidates.push('C:/Program Files/Java/jdk-21', 'C:/Program Files/Java/jdk-17');
    candidates.push('C:/Program Files/Eclipse Adoptium/jdk-21.0.*/');
  }
  for (const home of candidates) {
    if (home.includes('*')) continue;
    if (!existsSync(join(home, 'bin', process.platform === 'win32' ? 'java.exe' : 'java'))) continue;
    const probe = javaProbe(home);
    const compiler = existsSync(join(home, 'bin', process.platform === 'win32' ? 'javac.exe' : 'javac'));
    if (probe.available) return { ...probe, home, fullJdk: compiler };
  }
  const pathProbe = javaProbe();
  const homeFromCommand = pathProbe.command && pathProbe.command !== 'java' ? dirname(dirname(pathProbe.command)) : null;
  return { ...pathProbe, home: homeFromCommand, fullJdk: homeFromCommand ? existsSync(join(homeFromCommand, 'bin', process.platform === 'win32' ? 'javac.exe' : 'javac')) : false };
}

async function findGhidraRoot(candidate) {
  if (!candidate) return null;
  const root = resolve(candidate);
  if (existsSync(join(root, 'support', process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless')) && existsSync(join(root, 'Ghidra', 'application.properties'))) return root;
  try {
    const entries = await readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const nested = join(root, entry.name);
      if (existsSync(join(nested, 'support', process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless')) && existsSync(join(nested, 'Ghidra', 'application.properties'))) return nested;
    }
  } catch {}
  return null;
}

function readGhidraVersion(root) {
  try {
    const text = readFileSync(join(root, 'Ghidra', 'application.properties'), 'utf8');
    return text.match(/^application\.version=(.+)$/m)?.[1]?.trim() ?? null;
  } catch { return null; }
}

async function detectGhidra(base = process.env) {
  const configured = typeof base.GHIDRA_INSTALL_DIR === 'string' && base.GHIDRA_INSTALL_DIR.length > 0
    ? await findGhidraRoot(base.GHIDRA_INSTALL_DIR) : null;
  const cached = configured ? null : await findGhidraRoot(GHIDRA_ROOT);
  const root = configured ?? cached;
  const java = detectJava(base);
  return {
    available: Boolean(root),
    ready: Boolean(root && java.available && java.fullJdk),
    source: configured ? 'GHIDRA_INSTALL_DIR' : cached ? 'rea-engines-cache' : null,
    path: root,
    version: root ? readGhidraVersion(root) : null,
    java,
    requiresDownload: !root,
    requiresJdk: Boolean(root && (!java.available || !java.fullJdk)),
    release: GHIDRA_RELEASE,
  };
}

function downloadFile(url, target, onProgress) {
  return new Promise((resolveDownload, reject) => {
    const request = https.get(url, { headers: { 'User-Agent': 'dsh-rea' } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadFile(response.headers.location, target, onProgress).then(resolveDownload, reject);
        return;
      }
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`download returned HTTP ${response.statusCode}`)); return; }
      const total = Number(response.headers['content-length'] ?? 0);
      let received = 0;
      GHIDRA_STATE.total = total;
      const output = createWriteStream(target);
      response.on('data', (chunk) => { received += chunk.length; GHIDRA_STATE.bytes = received; onProgress?.(received, total); });
      output.on('error', reject);
      response.on('error', reject);
      output.on('finish', () => output.close(resolveDownload));
      response.pipe(output);
    });
    request.on('error', reject);
  });
}

function applyGhidraEnvironment(detected) {
  if (detected?.path) ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR = detected.path;
  if (detected?.java?.home && detected.java.fullJdk) ENGINE_ENV_OVERRIDES.JAVA_HOME = detected.java.home;
}

async function installExternalTool(tool, log) {
  const release = tool === 'jadx' ? JADX_RELEASE : tool === 'apktool' ? APKTOOL_RELEASE : tool === 'wabt' ? WABT_RELEASE : null;
  if (!release) throw new Error(`${tool} cannot be installed automatically; use its licensed/native distribution and configure its absolute path.`);
  if (TOOL_STATE.get(tool)?.phase === 'ready') return TOOL_STATE.get(tool);
  const state = { phase: 'downloading', bytes: 0, total: 0, message: `Downloading ${tool}`, error: null, version: release.version };
  TOOL_STATE.set(tool, state);
  try {
    await mkdir(ENGINE_ROOT, { recursive: true });
    const archive = join(ENGINE_ROOT, `${tool}-${release.version}${tool === 'wabt' ? '.tar.gz' : '.jar'}`);
    await downloadFile(release.url, archive, (bytes, total) => { state.bytes = bytes; state.total = total; });
    const actual = await sha256File(archive);
    if (actual !== release.sha256) throw new Error(`${tool} checksum mismatch: expected ${release.sha256}, got ${actual}`);
    state.phase = 'configuring';
    if (tool === 'jadx') {
      ENGINE_ENV_OVERRIDES.REA_JADX_MCP_JAR = archive;
      state.path = archive;
    } else if (tool === 'apktool') {
      const launcher = join(ENGINE_ROOT, 'apktool.bat');
      await writeFile(launcher, `@echo off\r\nsetlocal\r\nif defined JAVA_HOME (set "JAVA=%JAVA_HOME%\\bin\\java.exe") else (set "JAVA=java")\r\n"%JAVA%" -jar "${archive}" %*\r\n`, 'utf8');
      ENGINE_ENV_OVERRIDES.REA_APKTOOL_COMMAND = launcher;
      state.path = launcher;
    } else {
      const root = join(ENGINE_ROOT, `wabt-${release.version}`);
      await rm(root, { recursive: true, force: true }); await mkdir(root, { recursive: true });
      const outcome = spawn('tar', ['-xzf', archive, '-C', root], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      let stderr = ''; outcome.stderr?.setEncoding('utf8'); outcome.stderr?.on('data', (chunk) => { stderr += chunk; });
      const code = await new Promise((done) => { outcome.once('error', (e) => { stderr += e.message; done(-1); }); outcome.once('exit', done); });
      if (code !== 0) throw new Error(`WABT extraction failed: ${stderr.slice(0, 400)}`);
      const entries = await readdir(root, { withFileTypes: true });
      const nested = entries.find((entry) => entry.isDirectory());
      const bin = join(root, nested?.name ?? '', 'bin');
      ENGINE_ENV_OVERRIDES.REA_WABT_BIN_DIRECTORY = bin;
      state.path = bin;
    }
    state.phase = 'ready'; state.message = `${tool} ready`; return state;
  } catch (error) { state.phase = 'error'; state.error = error.message; throw error; }
}

async function installGhidra(log) {
  if (GHIDRA_INSTALL_PROMISE) return GHIDRA_INSTALL_PROMISE;
  GHIDRA_INSTALL_PROMISE = (async () => {
    try {
      const existing = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
      if (existing.available) return existing;
      await mkdir(ENGINE_ROOT, { recursive: true });
      GHIDRA_STATE.phase = 'downloading'; GHIDRA_STATE.bytes = 0; GHIDRA_STATE.total = 0; GHIDRA_STATE.error = null; GHIDRA_STATE.message = `Downloading Ghidra ${GHIDRA_RELEASE.version}`;
      await downloadFile(GHIDRA_RELEASE.url, GHIDRA_ARCHIVE);
      const actual = await sha256File(GHIDRA_ARCHIVE);
      if (actual !== GHIDRA_RELEASE.sha256) throw new Error(`Ghidra checksum mismatch: expected ${GHIDRA_RELEASE.sha256}, got ${actual}`);
      GHIDRA_STATE.phase = 'extracting'; GHIDRA_STATE.message = 'Extracting Ghidra';
      await rm(GHIDRA_ROOT, { recursive: true, force: true });
      await mkdir(GHIDRA_ROOT, { recursive: true });
      const outcome = spawn('tar', ['-xf', GHIDRA_ARCHIVE, '-C', GHIDRA_ROOT], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      let stderr = '';
      outcome.stderr?.setEncoding('utf8'); outcome.stderr?.on('data', (chunk) => { stderr += chunk; });
      const code = await new Promise((done) => { outcome.once('error', (error) => { stderr += error.message; done(-1); }); outcome.once('exit', done); });
      if (code !== 0) throw new Error(`Ghidra extraction failed (tar ${code}): ${stderr.slice(0, 500)}`);
      const detected = await detectGhidra({ ...process.env, GHIDRA_INSTALL_DIR: GHIDRA_ROOT });
      if (!detected.available) throw new Error('Ghidra archive extracted, but its installation root was not found');
      GHIDRA_STATE.phase = 'ready'; GHIDRA_STATE.path = detected.path; GHIDRA_STATE.version = detected.version; GHIDRA_STATE.message = 'Ghidra ready';
      applyGhidraEnvironment(detected);
      log?.(`dsh-rea: Ghidra ${detected.version ?? GHIDRA_RELEASE.version} prepared at ${detected.path}`);
      return detected;
    } catch (error) {
      GHIDRA_STATE.phase = 'error'; GHIDRA_STATE.error = error.message; GHIDRA_STATE.message = 'Ghidra preparation failed';
      throw error;
    } finally {
      GHIDRA_INSTALL_PROMISE = undefined;
    }
  })();
  return GHIDRA_INSTALL_PROMISE;
}

/**
 * Appended to every REA tool result. REA returns Evidence records, and a
 * truncated or resource-constrained result must be paged or exported rather
 * than re-requested; this is the instruction that keeps a 207-tool catalog
 * from being hammered with repeats.
 */
const RESULT_GUIDANCE = [
  'REA returns Evidence records: every conclusion carries its observation, its',
  'limitations and an Evidence ID. Cite that ID, keep the stated coverage limits,',
  'and never present a static-analysis detail as observed execution.',
  '',
  'When a result is truncated or reports a resource constraint, page it with',
  'inspect_analysis_view or export it with export_evidence_bundle instead of',
  'repeating the same call. Route the target once (see the',
  'reverse-engineer-anything skill), then ask the focused follow-up tools',
  'directly.',
].join('\n');

/** DeepSeek function-name contract: at most 64 characters, only [A-Za-z0-9_-]. */
const MAX_PUBLIC_NAME_LENGTH = 64;
const INVALID_NAME_CHARS = /[^A-Za-z0-9_-]/g;
const HASH_LENGTH = 12;

/** Deterministic public name for one REA tool: `mcp__rea__<raw>`, or a hashed lossy form. */
function publicToolName(rawName) {
  const joined = `mcp__rea__${rawName}`;
  const normalized = joined.replace(INVALID_NAME_CHARS, '_');
  if (normalized === joined && normalized.length <= MAX_PUBLIC_NAME_LENGTH) return normalized;
  const hash = createHash('sha256').update(`rea\0${rawName}`).digest('hex').slice(0, HASH_LENGTH);
  return `${normalized.slice(0, MAX_PUBLIC_NAME_LENGTH - HASH_LENGTH - 1)}_${hash}`;
}

/** ── MCP stdio client ─────────────────────────────────────────────────── */

/** Default per-call and buffer budgets; REA's native providers can take minutes. */
const DEFAULT_TOOL_CALL_TIMEOUT_MS = 900_000;
/**
 * REA's own minimum stdio receive-buffer size. A value below it makes REA exit
 * with `REA_MCP_MAX_RESPONSE_BYTES: Too small` before it serves anything, so the
 * floor is asserted here rather than discovered through a dead child.
 */
const REA_MIN_MAX_RESPONSE_BYTES = 10_485_760;
const DEFAULT_MAX_BUFFER_BYTES = REA_MIN_MAX_RESPONSE_BYTES;
const STDERR_BUDGET = 64 * 1024;

/**
 * One REA MCP child process with a newline-delimited JSON-RPC client.
 *
 * The transport is hand-written on purpose: MCP stdio framing here is
 * line-delimited JSON, the catalog is large, and the whole point of the plugin
 * is that nothing stands between a tool call and the server. Requests are
 * matched by id, notifications are consumed, and the child's stderr is kept
 * bounded for diagnostics.
 */
class ReaMcpClient {
  constructor({ command, args, env, toolCallTimeoutMs, log }) {
    this.command = command;
    this.args = args;
    this.env = env;
    this.toolCallTimeoutMs = toolCallTimeoutMs;
    this.log = typeof log === 'function' ? log : () => {};
    this.child = undefined;
    this.stderr = '';
    this.nextId = 1;
    this.pending = new Map();
    this.disposed = false;
    this.ready = this.#start();
  }

  /** Spawn the child, wire stdio, and complete the MCP handshake. */
  async #start() {
    this.child = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: this.env,
      windowsHide: true,
    });
    let buffer = '';
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (line.length > 0) this.#onLine(line);
      }
    });
    let stderrBytes = 0;
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk) => {
      if (stderrBytes >= STDERR_BUDGET) return;
      this.stderr += chunk;
      stderrBytes += chunk.length;
      if (stderrBytes > STDERR_BUDGET) this.stderr = `${this.stderr.slice(0, STDERR_BUDGET)}\n[stderr truncated]`;
    });
    this.child.on('error', (error) => {
      this.log(`rea: child process error: ${error.message}`);
      this.#failAll(new Error(`the REA child process could not be started: ${error.message}`));
    });
    this.child.on('exit', (code, signal) => {
      if (this.disposed) return;
      this.#failAll(new Error(`the REA child process exited (code ${code}, signal ${signal ?? 'none'})`));
    });

    await this.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'dsh-rea', version: '1.0.0' },
    }, 120_000);
    this.notify('notifications/initialized', {});
  }

  /** Parse one JSON-RPC line: answer a matching waiter, consume a notification. */
  #onLine(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      this.log(`rea: ignoring a non-JSON child line (${line.length} bytes)`);
      return;
    }
    if (typeof message.id !== 'number') return;
    const waiter = this.pending.get(message.id);
    if (waiter === undefined) return;
    this.pending.delete(message.id);
    clearTimeout(waiter.timer);
    if (message.error !== undefined) {
      waiter.reject(new Error(message.error.message ?? JSON.stringify(message.error)));
    } else {
      waiter.resolve(message.result);
    }
  }

  /** Reject every waiter; used when the child dies. */
  #failAll(error) {
    for (const waiter of this.pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.pending.clear();
  }

  /** Send a request and await its result with a timeout; the timeout rejects. */
  request(method, params, timeoutMs = this.toolCallTimeoutMs) {
    if (this.disposed) return Promise.reject(new Error('the REA client is disposed'));
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.child.stdin.write(`${payload}\n`);
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error(`${method} could not be written to the REA child: ${error.message}`));
      }
    });
  }

  /** Send a notification; the child does not answer it. */
  notify(method, params) {
    if (this.disposed || this.child === undefined) return;
    try {
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
    } catch {
      // A dead child has nothing to tell; the callers see the exit path.
    }
  }

  /** `tools/list`, following the pagination cursor the protocol allows. */
  async listTools() {
    const tools = [];
    let cursor;
    do {
      const result = await this.request('tools/list', cursor === undefined ? {} : { cursor }, 180_000);
      if (Array.isArray(result?.tools)) tools.push(...result.tools);
      cursor = result?.nextCursor;
    } while (typeof cursor === 'string' && cursor.length > 0);
    return tools;
  }

  /** `tools/call`; cancellation is checked before sending. */
  callTool(name, args, signal) {
    if (signal?.aborted) return Promise.reject(new Error('the tool call was canceled before REA received it'));
    return this.request('tools/call', { name, arguments: args ?? {} });
  }

  /** Close stdin, wait briefly, then force-kill. */
  async dispose() {
    this.disposed = true;
    this.#failAll(new Error('the REA client is disposed'));
    const child = this.child;
    if (child === undefined) return;
    try { child.stdin.end(); } catch {}
    await new Promise((resolveExit) => {
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} resolveExit(); }, 5_000);
      timer.unref?.();
      child.once('exit', () => { clearTimeout(timer); resolveExit(); });
      try { child.kill('SIGTERM'); } catch {}
    });
  }
}

/** ── Tool bridge ──────────────────────────────────────────────────────── */

/** Flatten an MCP content array into the text the model reads. */
function textOf(content) {
  const parts = [];
  for (const block of Array.isArray(content) ? content : []) {
    if (block?.type === 'text') parts.push(block.text ?? '');
    else if (block?.type === 'image') parts.push(`[image result not forwarded: ${block.mimeType ?? 'unknown type'}; ask REA for the text view of this finding]`);
    else if (block?.type === 'audio') parts.push(`[audio result unsupported: ${block.mimeType ?? 'unknown type'}]`);
    else if (block?.type === 'resource_link') parts.push(`Resource link: ${block.name} (${block.uri})`);
    else if (block?.type === 'resource') parts.push('[embedded resource unsupported]');
    else parts.push('[unsupported MCP content block]');
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
 * `deferred` marks the tool's schema as deferred: the harness holds it out of
 * the request payload until the model asks for that tool, which is what keeps a
 * 207-tool catalog (about 86 KB, roughly 21k tokens) from being paid on every
 * turn. The tool stays fully callable - only its advertisement is deferred.
 */
function buildTool(client, entry, deferred) {
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
      const result = await client.callTool(rawName, args, exec?.signal);
      if (result?.isError === true) throw new Error(textOf(result.content) || 'REA reported an error without a message');
      const text = textOf(result?.content);
      if (text.length === 0 && result?.structuredContent !== undefined) {
        try { return { text: JSON.stringify(result.structuredContent, null, 2) }; } catch { /* fall through */ }
      }
      return { text };
    },
    // Analysis is CPU- and disk-heavy; one at a time keeps REA's sessions sane.
    isConcurrencySafe: () => false,
  };
}

/**
 * Install the bundled skill into the user DSH skills root.
 *
 * Copied rather than pointed at, because the filesystem skill provider reads
 * directories and a copy is what REA's own setup writes. The copy is
 * idempotent and version-stamped so a plugin update replaces it, and a partial
 * failure is reported rather than half-installed.
 */
async function installSkill(log, skillDir, version) {
  if (skillDir === undefined || !existsSync(skillDir)) {
    log?.('dsh-rea: the rea skill directory is missing; skipping skill installation');
    return undefined;
  }
  const skillsRoot = join(homedir(), '.dsh', 'skills');
  const target = join(skillsRoot, 'reverse-engineer-anything');
  try {
    await mkdir(skillsRoot, { recursive: true });
    await cp(skillDir, target, { recursive: true, force: true });
    // A stamp beside the skill, so a reinstall is visible in the logs and a
    // stale copy from an older version can be told apart.
    await writeFile(join(skillsRoot, '.reverse-engineer-anything.rea.json'),
      `${JSON.stringify({ installedBy: 'dsh-rea', rea: version, at: new Date().toISOString() }, null, 2)}\n`);
    return target;
  } catch (error) {
    log?.(`dsh-rea: could not install the reverse-engineer-anything skill: ${error.message}`);
    return undefined;
  }
}

/** ── Config, environment, doctor tool ─────────────────────────────────── */

/**
 * Resolve the row's config into the shape the client wants.
 *
 * REA's own parser bounds both profiles (`compact`|`full` input, `full`|`off`
 * output), so anything else is refused here with the boundary named instead of
 * being handed to a child that would die on it.
 */
function resolveConfig(config = {}) {
  const schemaProfile = config.schemaProfile === 'full' ? 'full' : 'compact';
  const outputSchemaProfile = config.outputSchemaProfile === 'full' ? 'full' : 'off';
  const toolCallTimeoutMs = Number.isFinite(config.toolCallTimeoutMs) && config.toolCallTimeoutMs > 0
    ? Math.floor(config.toolCallTimeoutMs)
    : DEFAULT_TOOL_CALL_TIMEOUT_MS;
  const maxBufferBytes = Number.isFinite(config.maxBufferBytes) && config.maxBufferBytes >= REA_MIN_MAX_RESPONSE_BYTES
    ? Math.floor(config.maxBufferBytes)
    : DEFAULT_MAX_BUFFER_BYTES;
  return {
    schemaProfile,
    outputSchemaProfile,
    toolCallTimeoutMs,
    maxBufferBytes,
    logLevel: typeof config.logLevel === 'string' ? config.logLevel : 'info',
    enabled: config.enabled !== false,
    // Deferring the catalog is what makes a 207-tool bridge affordable: the
    // schemas stay out of the request payload until a tool is actually asked
    // for. `false` restores the always-advertised behaviour.
    deferCatalog: config.deferCatalog !== false,
  };
}

/** Provider and engine settings REA reads; passed through from this process. */
const PASSTHROUGH_ENV_NAMES = [
  'GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_GHIDRA_STARTUP_TIMEOUT_MS',
  'REA_HOPPER_STARTUP_TIMEOUT_MS', 'REA_GHIDRA_LANGUAGE_ID',
  'REA_GHIDRA_COMPILER_SPEC_ID', 'REA_GHIDRA_DISABLED_ANALYZERS',
  'REA_GHIDRA_NATIVEAOT_JAR', 'REA_GHIDRA_SEED_FILE', 'REA_IDA_MCP_CONFIG',
  'REA_JEB_MCP_TIMEOUT_MS', 'REA_KUNA_COMMAND', 'REA_ILSPY_CMD_PATH',
  'REA_ANALYSIS_PROVIDER', 'REA_JADX_MCP_JAR', 'REA_JADX_OPERATION_TIMEOUT_MS',
  'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_TSHARK_COMMAND',
  'REA_SIGROK_COMMAND', 'REA_SWIFTC_COMPILE_TIMEOUT_MS',
  'REA_PWNTOOLS_PYTHON', 'HOPPER_LAUNCHER_PATH', 'HOPPER_TARGET_PATH',
  'HOPPER_TARGET_KIND', 'HOPPER_LOADER_ARGS_JSON', 'TMP', 'TEMP',
];

/**
 * The environment the REA child runs with.
 *
 * This plugin's settings are written in, and every provider path the person has
 * configured in the session is passed through: REA never installs an engine, so
 * the only way it can use one is for its path to reach the child.
 */
function childEnvironment(config, base) {
  const env = { ...base, ...ENGINE_ENV_OVERRIDES };
  env.REA_MCP_INPUT_SCHEMA_PROFILE = config.schemaProfile;
  env.REA_MCP_OUTPUT_SCHEMA_PROFILE = config.outputSchemaProfile;
  env.REA_MCP_MAX_RESPONSE_BYTES = String(config.maxBufferBytes);
  env.REA_LOG_LEVEL = config.logLevel;
  env.REA_PACKAGE_VERSION = config.reaVersion ?? 'unknown';
  for (const name of PASSTHROUGH_ENV_NAMES) {
    const value = base[name];
    if (typeof value === 'string' && value.length > 0 && env[name] === undefined) env[name] = value;
  }
  return env;
}

function jsonResponse(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  response.end(JSON.stringify(payload));
}

async function readRequestJson(request) {
  if (!request || typeof request[Symbol.asyncIterator] !== 'function') return {};
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) throw new Error('request body too large');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  return value && typeof value === 'object' ? value : {};
}

async function persistEngineConfig() {
  await mkdir(ENGINE_ROOT, { recursive: true });
  await writeFile(ENGINE_CONFIG_FILE, `${JSON.stringify(ENGINE_ENV_OVERRIDES, null, 2)}\n`, 'utf8');
}

async function environmentStatus() {
  const ghidra = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  return {
    ok: true,
    platform: process.platform,
    architecture: process.arch,
    runtime: {
      archive: existsSync(RUNTIME_ARCHIVE),
      unpacked: existsSync(join(RUNTIME_DIR, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs')),
      path: RUNTIME_DIR,
    },
    java: ghidra.java,
    ghidra: {
      phase: GHIDRA_STATE.phase,
      message: GHIDRA_STATE.message,
      error: GHIDRA_STATE.error,
      bytes: GHIDRA_STATE.bytes,
      total: GHIDRA_STATE.total,
      available: ghidra.available,
      ready: ghidra.ready,
      source: ghidra.source,
      path: ghidra.path,
      version: ghidra.version,
      requiredVersion: GHIDRA_RELEASE.version,
      downloadBytes: 569649598,
      archiveSha256: GHIDRA_RELEASE.sha256,
    },
    external: {
      jadx: Boolean(ENGINE_ENV_OVERRIDES.REA_JADX_MCP_JAR || process.env.REA_JADX_MCP_JAR),
      apktool: Boolean(ENGINE_ENV_OVERRIDES.REA_APKTOOL_COMMAND || process.env.REA_APKTOOL_COMMAND),
      wabt: Boolean(ENGINE_ENV_OVERRIDES.REA_WABT_BIN_DIRECTORY || process.env.REA_WABT_BIN_DIRECTORY),
      rizin: Boolean(ENGINE_ENV_OVERRIDES.REA_KUNA_COMMAND || process.env.REA_KUNA_COMMAND),
    },
    externalState: Object.fromEntries([...TOOL_STATE.entries()].map(([key, state]) => [key, { phase: state.phase, bytes: state.bytes, total: state.total, message: state.message, error: state.error, version: state.version, path: state.path }])), 
    configured: Object.fromEntries(['GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_JADX_MCP_JAR', 'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_KUNA_COMMAND'].map((key) => [key, ENGINE_ENV_OVERRIDES[key] ?? process.env[key] ?? ''])),
    configFile: ENGINE_CONFIG_FILE,
  };
}

function mountEnvironmentRoutes(ctx, { onInstallGhidra, onRestart }) {
  if (!ctx.webServer?.register) return () => {};
  const routes = [
    {
      path: '/rea/environment',
      method: 'GET',
      handler: async (_request, response) => jsonResponse(response, 200, await environmentStatus()),
    },
    {
      path: '/rea/ghidra/install',
      method: 'POST',
      handler: async (_request, response) => {
        try {
          const installed = await onInstallGhidra();
          const restarted = await onRestart(installed);
          jsonResponse(response, 200, { ...(await environmentStatus()), restarted });
        } catch (error) {
          jsonResponse(response, 200, { ...(await environmentStatus()), ok: false, error: error.message });
        }
      },
    },
    {
      path: '/rea/engine/config',
      method: 'POST',
      handler: async (request, response) => {
        try {
          const body = await readRequestJson(request);
          const allowed = ['GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_JADX_MCP_JAR', 'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_KUNA_COMMAND'];
          for (const key of allowed) {
            if (body[key] === undefined) continue;
            const value = String(body[key]).trim();
            if (value.length === 0) delete ENGINE_ENV_OVERRIDES[key];
            else if (!/^[A-Za-z]:[\\/]|^\//.test(value)) throw new Error(`${key} must be an absolute path`);
            else ENGINE_ENV_OVERRIDES[key] = value;
          }
          await persistEngineConfig();
          const detected = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
          applyGhidraEnvironment(detected);
          const restarted = await onRestart(detected);
          jsonResponse(response, 200, { ...(await environmentStatus()), restarted });
        } catch (error) {
          jsonResponse(response, 200, { ...(await environmentStatus()), ok: false, error: error.message });
        }
      },
    },
    {
      path: '/rea/engine/install',
      method: 'POST',
      handler: async (request, response) => {
        try {
          const body = await readRequestJson(request);
          const tool = String(body.tool || '').toLowerCase();
          const installed = await installExternalTool(tool);
          await persistEngineConfig();
          const restarted = await onRestart(installed);
          jsonResponse(response, 200, { ...(await environmentStatus()), installed: tool, restarted });
        } catch (error) {
          jsonResponse(response, 200, { ...(await environmentStatus()), ok: false, error: error.message });
        }
      },
    },
  ];
  const disposers = routes.map(({ path, method, handler }) => ctx.webServer.register({
    kind: 'exact', path,
    handler: async (request, response) => {
      if (request.method !== method) { jsonResponse(response, 405, { ok: false, error: 'method-not-allowed' }); return; }
      try { await handler(request, response); } catch (error) { jsonResponse(response, 200, { ok: false, error: error.message }); }
    },
  }));
  return () => { for (const dispose of disposers) { try { dispose?.(); } catch {} } };
}

/** One read-only readiness tool: REA's own doctor, run as a one-shot child. */
function buildDoctorTool(config, entry) {
  return {
    name: 'rea_doctor',
    description: 'Run REA\'s own readiness check and report it as JSON: whether the REA MCP child starts, its server state, and which analysis engines (Ghidra, Hopper, IDA, JADX, Kuna, Apktool) are available or missing. Read-only; never opens a target.',
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
      const code = await new Promise((resolveExit) => {
        const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} resolveExit(null); }, 120_000);
        timer.unref?.();
        child.once('exit', (exitCode) => { clearTimeout(timer); resolveExit(exitCode); });
      });
      exec?.signal?.throwIfAborted?.();
      const body = stdout.trim();
      if (body.length > 0) return { report: body };
      return { report: `rea mcp doctor produced no report (exit ${code ?? 'timed out'})${stderr.trim() ? `\nstderr:\n${stderr.trim()}` : ''}` };
    },
    isConcurrencySafe: () => true,
  };
}

/** ── Plugin entry ─────────────────────────────────────────────────────── */

/** Services this plugin needs; `tools` is the registry REA's catalog lands in. */
export const inject = ['tools', 'webServer'];

/** How long to wait between respawns, and how many attempts before stopping. */
const RECONNECT_DELAY_MS = 2_000;
const RECONNECT_MAX_ATTEMPTS = 5;

/**
 * Discovery tool for the deferred catalog.
 *
 * With `deferCatalog` on (the default) the 207 REA tool schemas are held out of
 * the request payload, so the model cannot read them off the tool list. This
 * tool is the small, always-advertised index it searches instead: it answers
 * "which REA tool does X" by name, so the right deferred tool can then be asked
 * for directly. Its own schema is a few hundred bytes.
 */
function buildCatalogTool(catalog) {
  return {
    name: 'rea_catalog',
    description: 'List or search REA\'s reverse-engineering tools by keyword. Use this to find the right tool name before calling an mcp__rea__* tool, since REA\'s full catalog is deferred to keep it out of context. No argument lists every tool; a keyword filters by name and description.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'Keyword to match against tool names and descriptions. Omit to list every tool name.' },
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
      const entries = catalog.entries();
      const matches = query.length === 0
        ? entries
        : entries.filter((entry) => entry.name.toLowerCase().includes(query) || entry.description.toLowerCase().includes(query));
      const head = query.length === 0
        ? `REA tool catalog (${matches.length} tools). Call one as mcp__rea__<name>:`
        : `REA tools matching "${query}" (${matches.length} of ${entries.length}):`;
      const lines = matches.slice(0, 120).map((entry) => `- ${entry.name}: ${entry.description}`);
      if (matches.length > 120) lines.push(`- … ${matches.length - 120} more; narrow the query`);
      return { text: [head, ...lines].join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/**
 * Plugin entry: connect one REA MCP child and register its tools.
 *
 * Startup is awaited, so a broken runtime is visible immediately instead of
 * failing on the first model call. The child is supervised for the lifetime of
 * the plugin: if it exits, the catalog is re-synced after a bounded backoff
 * while the tools stay listed; disposal closes the transport.
 */
export async function apply(ctx, rawConfig = {}) {
  const config = resolveConfig(rawConfig);
  const log = (message) => ctx.logger?.warn?.(message);

  // The runtime is resolved (and unpacked, on first activation) before anything
  // else, so every later step can rely on the absolute entrypoint.
  const reaPackage = await resolveReaPackage(log);
  const REA_ENTRY = reaPackage ? join(reaPackage, 'scripts', 'rea.mjs') : undefined;
  const REA_VERSION = (() => {
    try {
      return JSON.parse(readFileSync(join(reaPackage, 'package.json'), 'utf8')).version ?? 'unknown';
    } catch {
      return 'unknown';
    }
  })();
  const REA_SKILL_DIR = reaPackage
    ? join(reaPackage, 'skills', 'reverse-engineer-anything')
    : undefined;
  config.reaVersion = REA_VERSION;

  const spawnChild = () => new ReaMcpClient({
    command: process.execPath,
    args: [REA_ENTRY, 'mcp'],
    env: childEnvironment(config, process.env),
    toolCallTimeoutMs: config.toolCallTimeoutMs,
    log,
  });

  // If a user already has a valid Ghidra/JDK pair, use it immediately without
  // changing their process environment; only the child receives the overrides.
  const detectedGhidra = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  applyGhidraEnvironment(detectedGhidra);

  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildDoctorTool(config, REA_ENTRY));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: doctor tool');

  // The discovery index, populated by the first sync and replaced on every
  // re-sync, so it always names the tools the server actually advertises.
  const catalog = {
    entries: () => [],
  };
  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildCatalogTool(catalog));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: catalog tool');

  if (REA_ENTRY === undefined || !config.enabled) {
    log(`dsh-rea: ${REA_ENTRY === undefined ? 'the rea-agents runtime could not be resolved (the archive is missing or failed to unpack)' : 'disabled by config'}; no REA tools registered (rea_doctor still reports the state).`);
    return;
  }

  // The skill directory is installed before the connection, so a first session
  // has both halves even if the MCP handshake later fails.
  const skillPath = await installSkill(log, REA_SKILL_DIR, REA_VERSION);
  if (skillPath !== undefined) ctx.logger?.info?.(`dsh-rea: installed the reverse-engineer-anything skill at ${skillPath}`);

  let client;
  try {
    client = spawnChild();
    await client.ready;
  } catch (error) {
    log(`dsh-rea: the REA MCP server did not start (${error.message}); no REA tools registered.${client?.stderr ? `\nchild stderr:\n${client.stderr}` : ''}`);
    try { await client?.dispose(); } catch {}
    return;
  }

  /** Live registrations owned by this server, keyed by public name. */
  let disposers = new Map();
  /** Serializes syncs so a list-changed notification cannot interleave one. */
  let syncing = false;
  let attempts = 0;
  let reconnectTimer;

  async function sync() {
    const entries = await client.listTools();
    const next = new Map();
    const index = [];
    for (const entry of entries) {
      if (typeof entry?.name !== 'string') continue;
      const definition = buildTool(client, entry, config.deferCatalog);
      next.set(definition.name, definition);
      index.push({
        name: definition.name,
        description: typeof entry.description === 'string' ? entry.description : entry.name,
      });
    }
    catalog.entries = () => index;
    for (const dispose of disposers.values()) { try { dispose(); } catch {} }
    const fresh = new Map();
    try {
      for (const [name, definition] of next) fresh.set(name, ctx.tools.register(definition));
    } catch (error) {
      for (const dispose of fresh.values()) { try { dispose(); } catch {} }
      log(`dsh-rea: tool registration failed (${error.message}); the previous catalog stays active.`);
      return;
    }
    disposers = fresh;
    attempts = 0;
    ctx.logger?.info?.(`dsh-rea: ${fresh.size} REA tools registered${config.deferCatalog ? ' (deferred)' : ''}`);
  }

  async function resync(reason) {
    if (syncing) return;
    syncing = true;
    try {
      await sync();
    } catch (error) {
      log(`dsh-rea: tool sync failed (${reason}): ${error.message}`);
    } finally {
      syncing = false;
    }
  }

  async function restartAfterEngineInstall() {
    try { await client?.dispose(); } catch {}
    const next = spawnChild();
    await next.ready;
    client = next;
    await resync('after Ghidra preparation');
    return true;
  }

  if (ctx.webServer?.register) {
    const routeDispose = mountEnvironmentRoutes(ctx, {
      onInstallGhidra: async () => {
        const detected = await installGhidra(log);
        applyGhidraEnvironment(detected);
        return detected;
      },
      onRestart: restartAfterEngineInstall,
    });
    ctx.effect(() => routeDispose, 'dsh-rea: environment routes');
  }

  try {
    await sync();
  } catch (error) {
    log(`dsh-rea: the first tool sync failed: ${error.message}; no REA tools registered.`);
    try { await client.dispose(); } catch {}
    return;
  }

  /**
   * The child exiting after registration is recoverable: the tools stay listed
   * (calls fail loudly), and a fresh child replaces this one on a bounded
   * backoff. Giving up is logged explicitly so the remedy is visible.
   */
  const supervise = (current) => {
    current.child.on('exit', () => {
      if (current.disposed || client !== current) return;
      if (attempts >= RECONNECT_MAX_ATTEMPTS) {
        log(`dsh-rea: the REA child kept exiting after ${RECONNECT_MAX_ATTEMPTS} attempts; reconnect stopped. Restart the session to try again.`);
        return;
      }
      attempts += 1;
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(() => {
        void (async () => {
          try {
            const next = spawnChild();
            await next.ready;
            client = next;
            supervise(next);
            await resync('after reconnect');
          } catch (error) {
            log(`dsh-rea: reconnect attempt ${attempts} failed: ${error.message}`);
          }
        })();
      }, RECONNECT_DELAY_MS);
      reconnectTimer.unref?.();
    });
  };
  supervise(client);

  ctx.effect(() => () => {
    clearTimeout(reconnectTimer);
    void client.dispose();
  }, 'dsh-rea: connection');
}

export { ReaMcpClient, buildTool, childEnvironment, installSkill, publicToolName, resolveConfig, textOf };
