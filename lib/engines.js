/**
 * Engine discovery and preparation: Java, Ghidra, JADX, Apktool, WABT.
 *
 * This plugin never bundles an engine. It finds what is already installed, lets
 * the person point at anything it cannot find, and downloads the four pinned
 * artifacts that have a stable public release - each verified against a
 * checksum fixed in this file, so "prepare" cannot install something else.
 *
 * Everything is pinned to one version because REA validates specific builds on
 * its native path. Nothing here is guessed at runtime.
 *
 * @module dsh-rea/lib/engines
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { chmod, mkdir, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { downloadFile, extractArchive } from './download.js';
import { engineHealth } from './engine-health.js';
import { explainWorkRoot, resolveWorkRoot } from './work-root.js';
import { ENGINE_CONFIG_FILE, ENGINE_ROOT, GHIDRA_ROOT, RUNTIME_ARCHIVE, RUNTIME_DIR, RUNTIME_ENTRY } from './paths.js';
import { sha256File } from './runtime.js';

const IS_WINDOWS = process.platform === 'win32';
const JDK_CACHE_TTL_MS = 15_000;

/** Ghidra 12.1.4 is the version REA 6.7.0 validates on the native path. */
export const GHIDRA_RELEASE = {
  version: '12.1.4',
  url: 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip',
  sha256: 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db',
  bytes: 569_649_598,
};
/**
 * The JDK Ghidra 12.x refuses to start without. A JDK 17 is a fine JDK and a
 * useless engine dependency: Ghidra's launcher exits with "JDK 21+ (64-bit)
 * could not be found" before it ever reads a byte of the target file.
 */
export const GHIDRA_JAVA_MAJOR = 21;

/** Judge a detected JDK against the engine that will consume it. */
export function javaRequirement(java = {}) {
  const major = Number(java.major);
  const known = Number.isFinite(major) && major > 0;
  return {
    required: GHIDRA_JAVA_MAJOR,
    major: known ? major : null,
    // An unknown version is not evidence of sufficiency.
    sufficient: known && major >= GHIDRA_JAVA_MAJOR,
    note: !java.available || (known && major >= GHIDRA_JAVA_MAJOR)
      ? null
      : `JDK ${java.version ?? major ?? 'unknown'} is older than JDK ${GHIDRA_JAVA_MAJOR}, which Ghidra ${GHIDRA_RELEASE.version} requires`,
  };
}

export const JADX_RELEASE = {
  version: '0.7.1',
  url: 'https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar',
  sha256: '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75',
};
export const APKTOOL_RELEASE = {
  version: '3.0.3',
  url: 'https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar',
  sha256: 'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423',
};
/**
 * WABT publishes one archive per platform, and only the Windows x64 build is
 * pinned here. Rather than download an unpinned binary on other platforms, the
 * prepare action reports that no build is available and points at the path
 * field; `wabtAsset()` is what both the route and the sidebar consult.
 */
export const WABT_RELEASE = {
  version: '1.0.42',
  assets: {
    'win32-x64': {
      url: 'https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-windows-x64.tar.gz',
      sha256: '62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88',
    },
  },
};

/** The pinned WABT build for this platform, or `null` when there is none. */
export function wabtAsset(platform = process.platform, arch = process.arch) {
  return WABT_RELEASE.assets[`${platform}-${arch}`] ?? null;
}

/** Paths the sidebar may write, and the only names that reach the child's env. */
export const ENGINE_KEYS = [
  'GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_JADX_MCP_JAR',
  'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_KUNA_COMMAND',
];

function loadEngineConfig() {
  try {
    const saved = JSON.parse(readFileSync(ENGINE_CONFIG_FILE, 'utf8'));
    const loaded = {};
    for (const key of ENGINE_KEYS) {
      if (typeof saved?.[key] === 'string' && saved[key].length > 0) loaded[key] = saved[key];
    }
    return loaded;
  } catch {
    return {};
  }
}

/** Saved engine paths; mutated by the sidebar and injected into every child. */
export const ENGINE_ENV_OVERRIDES = loadEngineConfig();

/** Latest progress for a downloaded engine, per tool. */
export const TOOL_STATE = new Map();

/** Latest progress for Ghidra, which has its own download and extraction phases. */
export const GHIDRA_STATE = { phase: 'idle', bytes: 0, total: 0, message: '', error: null, path: null, version: null };

const GHIDRA_ARCHIVE = join(ENGINE_ROOT, `ghidra-${GHIDRA_RELEASE.version}.zip`);

export async function persistEngineConfig() {
  await mkdir(ENGINE_ROOT, { recursive: true });
  await writeFile(ENGINE_CONFIG_FILE, `${JSON.stringify(ENGINE_ENV_OVERRIDES, null, 2)}\n`, 'utf8');
}

/** A stable fingerprint of the saved paths, used to decide whether to restart. */
export function engineConfigSignature() {
  return JSON.stringify(ENGINE_KEYS.map((key) => [key, ENGINE_ENV_OVERRIDES[key] ?? null]));
}

function isAbsolutePath(value) {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\');
}

/**
 * Apply paths from the sidebar form.
 *
 * An empty value clears the override, which is how a person reverts to whatever
 * the environment already provides. Only absolute paths are accepted: these
 * strings become the child's `JAVA_HOME`/`REA_*` values, and a relative one
 * would resolve against the plugin's cwd instead of anything the person meant.
 */
export async function saveEnginePaths(body = {}) {
  const before = engineConfigSignature();
  // Validate everything before touching the live overrides: a form with one bad
  // field used to apply the fields before it and then throw, leaving memory and
  // the saved file out of step.
  const updates = [];
  for (const key of ENGINE_KEYS) {
    if (!(key in body)) continue;
    const value = String(body[key] ?? '').trim();
    if (value.length > 0 && !isAbsolutePath(value)) {
      const error = new Error(`${key} must be an absolute path`);
      error.statusCode = 400;
      throw error;
    }
    updates.push([key, value]);
  }
  for (const [key, value] of updates) {
    if (value.length === 0) delete ENGINE_ENV_OVERRIDES[key];
    else ENGINE_ENV_OVERRIDES[key] = value;
  }
  const changed = engineConfigSignature() !== before;
  if (changed) await persistEngineConfig();
  return { changed };
}

/* ── Java ─────────────────────────────────────────────────────────────── */

const javaBinary = () => (IS_WINDOWS ? 'java.exe' : 'java');
const javacBinary = () => (IS_WINDOWS ? 'javac.exe' : 'javac');

/** A full JDK ships a compiler; a JRE does not, and Ghidra needs the former. */
function hasCompiler(home) {
  if (typeof home !== 'string' || home.length === 0) return false;
  return existsSync(join(home, 'bin', javacBinary()));
}

/**
 * Probe one Java installation.
 *
 * `-XshowSettings:properties` is asked for because it reports `java.home` and
 * `java.version` on one line each, which is how a `java` found on PATH can be
 * traced back to the JDK it belongs to. `-version` alone never says where it
 * lives, and the earlier implementation consequently reported "no JDK" for a
 * perfectly good JDK that was simply on PATH.
 */
function probeJava(home) {
  const command = home ? join(home, 'bin', javaBinary()) : 'java';
  const result = spawnSync(command, ['-XshowSettings:properties', '-version'], {
    encoding: 'utf8', windowsHide: true, timeout: 10_000,
  });
  const text = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const settingsHome = text.match(/^\s*java\.home\s*=\s*(.+)$/m)?.[1]?.trim() ?? null;
  const settingsVersion = text.match(/^\s*java\.version\s*=\s*(.+)$/m)?.[1]?.trim() ?? null;
  const legacy = text.match(/version\s+"(\d+)(?:\.(\d+))?/i);
  const major = settingsVersion
    ? Number(settingsVersion.split('.')[0])
    : legacy
      ? (Number(legacy[1]) === 1 ? Number(legacy[2]) : Number(legacy[1]))
      : null;
  const resolvedHome = home ?? settingsHome ?? null;
  return {
    available: result.status === 0 && major !== null,
    home: resolvedHome,
    command,
    version: settingsVersion ?? legacy?.[1] ?? null,
    major,
    fullJdk: hasCompiler(resolvedHome),
    output: text.trim().slice(0, 600),
  };
}

/** Directories that hold one JDK per child directory, per platform. */
function jdkParents() {
  if (IS_WINDOWS) {
    return [
      'C:/Program Files/Java',
      'C:/Program Files/Eclipse Adoptium',
      'C:/Program Files/Microsoft',
      'C:/Program Files/Amazon Corretto',
      'C:/Program Files/Zulu',
      'C:/Program Files/BellSoft',
    ];
  }
  if (process.platform === 'darwin') return ['/Library/Java/JavaVirtualMachines'];
  return ['/usr/lib/jvm', '/usr/java'];
}

/** Rank directory names by their first number, newest first. */
function versionRank(name) {
  const match = name.match(/(\d+)(?:\.(\d+))?/);
  if (!match) return -1;
  return Number(match[1]) === 1 ? Number(match[2] ?? 1) : Number(match[1]);
}

function installedJdkHomes() {
  const homes = [];
  for (const parent of jdkParents()) {
    let entries;
    try {
      entries = readdirSync(parent, { withFileTypes: true });
    } catch {
      continue;
    }
    const directories = entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort((left, right) => versionRank(right) - versionRank(left));
    for (const name of directories) {
      homes.push(process.platform === 'darwin'
        ? join(parent, name, 'Contents', 'Home')
        : join(parent, name));
    }
  }
  return homes;
}

let jdkCache = { at: 0, key: '', value: undefined };

/**
 * Discover a usable full JDK.
 *
 * A full JDK is preferred over the first Java found: a machine often carries
 * both a JDK and a JRE, and Ghidra cannot launch on the latter.
 */
export function detectJava(base = process.env) {
  const key = String(base.JAVA_HOME ?? '');
  const now = Date.now();
  if (jdkCache.value !== undefined && jdkCache.key === key && now - jdkCache.at < JDK_CACHE_TTL_MS) return jdkCache.value;
  const value = detectJavaUncached(base);
  jdkCache = { at: now, key, value };
  return value;
}

function detectJavaUncached(base) {
  const candidates = [];
  if (typeof base.JAVA_HOME === 'string' && base.JAVA_HOME.length > 0) candidates.push(resolve(base.JAVA_HOME));
  candidates.push(...installedJdkHomes());
  const seen = new Set();
  const probes = [];
  for (const home of candidates) {
    if (seen.has(home)) continue;
    seen.add(home);
    if (!existsSync(join(home, 'bin', javaBinary()))) continue;
    const probe = probeJava(home);
    if (probe.available) probes.push({ ...probe, home: probe.home ?? home, fullJdk: probe.fullJdk || hasCompiler(home) });
  }
  const onPath = probeJava(undefined);
  if (onPath.available) probes.push(onPath);
  if (probes.length === 0) return onPath;
  return probes.find((probe) => probe.fullJdk) ?? probes[0];
}

/* ── Ghidra ───────────────────────────────────────────────────────────── */

async function findGhidraRoot(candidate) {
  if (!candidate) return null;
  const root = resolve(candidate);
  const launcher = join(root, 'support', IS_WINDOWS ? 'analyzeHeadless.bat' : 'analyzeHeadless');
  const properties = join(root, 'Ghidra', 'application.properties');
  if (existsSync(launcher) && existsSync(properties)) return root;
  try {
    const entries = await readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const nested = join(root, entry.name);
      if (existsSync(join(nested, 'support', IS_WINDOWS ? 'analyzeHeadless.bat' : 'analyzeHeadless'))
        && existsSync(join(nested, 'Ghidra', 'application.properties'))) return nested;
    }
  } catch {}
  return null;
}

function readGhidraVersion(root) {
  try {
    const text = readFileSync(join(root, 'Ghidra', 'application.properties'), 'utf8');
    return text.match(/^application\.version=(.+)$/m)?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

export async function detectGhidra(base = process.env) {
  const configuredDir = typeof base.GHIDRA_INSTALL_DIR === 'string' && base.GHIDRA_INSTALL_DIR.length > 0
    ? base.GHIDRA_INSTALL_DIR : '';
  const configured = configuredDir ? await findGhidraRoot(configuredDir) : null;
  const cached = configured ? null : await findGhidraRoot(GHIDRA_ROOT);
  const root = configured ?? cached;
  const java = detectJava(base);
  const requirement = javaRequirement(java);
  return {
    available: Boolean(root),
    // A JDK that exists but is too old is not a ready engine. Reporting it as
    // one is how "jdk ok (17.0.8)" appeared next to "ghidra missing" while every
    // decompile attempt died before reading the file.
    ready: Boolean(root && java.available && java.fullJdk && requirement.sufficient),
    source: configured ? 'GHIDRA_INSTALL_DIR' : cached ? 'rea-engines-cache' : null,
    path: root,
    version: root ? readGhidraVersion(root) : null,
    java: { ...java, requiredMajor: requirement.required, sufficientForGhidra: requirement.sufficient, note: requirement.note },
    javaRequirement: requirement,
    requiresDownload: !root,
    requiresJdk: Boolean(root && (!java.available || !java.fullJdk || !requirement.sufficient)),
    release: GHIDRA_RELEASE,
  };
}

/** Push a discovered engine into the environment later children inherit. */
export function applyGhidraEnvironment(detected) {
  if (detected?.path) ENGINE_ENV_OVERRIDES.GHIDRA_INSTALL_DIR = detected.path;
  if (detected?.java?.home && detected.java.fullJdk) ENGINE_ENV_OVERRIDES.JAVA_HOME = detected.java.home;
}

let ghidraInstall;

/**
 * Prepare Ghidra, once per process.
 *
 * Concurrent clicks share one download; a failed attempt clears the promise so
 * the button works again instead of hanging on a promise that already rejected.
 * The archive is kept when extraction fails (so a retry does not re-download
 * 543 MB) and removed once the install succeeds.
 */
export function installGhidra(log) {
  if (ghidraInstall) return ghidraInstall;
  ghidraInstall = runGhidraInstall(log).finally(() => { ghidraInstall = undefined; });
  return ghidraInstall;
}

async function runGhidraInstall(log) {
  const existing = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  if (existing.available) return existing;
  try {
    await mkdir(ENGINE_ROOT, { recursive: true });
    const archiveAlreadyValid = existsSync(GHIDRA_ARCHIVE)
      && await sha256File(GHIDRA_ARCHIVE).then((digest) => digest === GHIDRA_RELEASE.sha256).catch(() => false);
    if (!archiveAlreadyValid) {
      GHIDRA_STATE.phase = 'downloading';
      GHIDRA_STATE.bytes = 0;
      GHIDRA_STATE.total = GHIDRA_RELEASE.bytes;
      GHIDRA_STATE.error = null;
      GHIDRA_STATE.message = `Downloading Ghidra ${GHIDRA_RELEASE.version}`;
      await downloadFile(GHIDRA_RELEASE.url, GHIDRA_ARCHIVE, {
        onProgress: (bytes, total) => { GHIDRA_STATE.bytes = bytes; if (total > 0) GHIDRA_STATE.total = total; },
        log: (message) => log?.warn?.(message),
      });
      const actual = await sha256File(GHIDRA_ARCHIVE);
      if (actual !== GHIDRA_RELEASE.sha256) {
        await rm(GHIDRA_ARCHIVE, { force: true }).catch(() => {});
        throw new Error(`Ghidra checksum mismatch: expected ${GHIDRA_RELEASE.sha256}, got ${actual}`);
      }
    }
    GHIDRA_STATE.phase = 'extracting';
    GHIDRA_STATE.message = 'Extracting Ghidra';
    const staging = `${GHIDRA_ROOT}.staging-${process.pid}`;
    await rm(staging, { recursive: true, force: true });
    await mkdir(staging, { recursive: true });
    await extractArchive(GHIDRA_ARCHIVE, staging, { log: (message) => log?.warn?.(message) });
    const detected = await findGhidraRoot(staging);
    if (!detected) throw new Error('the Ghidra archive was extracted, but no installation root (support/analyzeHeadless) was found in it');
    await rm(GHIDRA_ROOT, { recursive: true, force: true });
    await rename(staging, GHIDRA_ROOT);
    const installed = await detectGhidra({ ...process.env, GHIDRA_INSTALL_DIR: GHIDRA_ROOT });
    if (!installed.available) throw new Error('Ghidra was unpacked, but its installation root could not be re-detected');
    GHIDRA_STATE.phase = 'ready';
    GHIDRA_STATE.error = null;
    GHIDRA_STATE.path = installed.path;
    GHIDRA_STATE.version = installed.version;
    GHIDRA_STATE.message = 'Ghidra ready';
    applyGhidraEnvironment(installed);
    await rm(GHIDRA_ARCHIVE, { force: true }).catch(() => {});
    log?.info?.(`dsh-rea: Ghidra ${installed.version ?? GHIDRA_RELEASE.version} prepared at ${installed.path}`);
    return installed;
  } catch (error) {
    GHIDRA_STATE.phase = 'error';
    GHIDRA_STATE.error = error.message;
    GHIDRA_STATE.message = 'Ghidra preparation failed';
    throw error;
  }
}

/* ── JADX, Apktool, WABT ──────────────────────────────────────────────── */

function toolSpec(tool) {
  if (tool === 'jadx') return { release: JADX_RELEASE, kind: 'jadx', archive: `jadx-${JADX_RELEASE.version}.jar` };
  if (tool === 'apktool') return { release: APKTOOL_RELEASE, kind: 'apktool', archive: `apktool-${APKTOOL_RELEASE.version}.jar` };
  if (tool === 'wabt') {
    const asset = wabtAsset();
    if (!asset) return null;
    return { release: { ...WABT_RELEASE, ...asset }, kind: 'wabt', archive: `wabt-${WABT_RELEASE.version}.tar.gz` };
  }
  return null;
}

const toolInstalls = new Map();

/**
 * Download and wire one external engine.
 *
 * Concurrent requests share one install: two clicks used to write the same
 * archive from two sockets and fail the checksum. The promise is cleared when
 * it settles, so a failure is retryable.
 */
export function installExternalTool(tool, log) {
  if (toolInstalls.has(tool)) return toolInstalls.get(tool);
  const promise = runToolInstall(tool, log).finally(() => toolInstalls.delete(tool));
  toolInstalls.set(tool, promise);
  return promise;
}

async function runToolInstall(tool, log) {
  const spec = toolSpec(tool);
  if (!spec) {
    const error = new Error(tool === 'wabt'
      ? `no pinned WABT build exists for ${process.platform}-${process.arch}; install WABT yourself and set REA_WABT_BIN_DIRECTORY`
      : `${tool} cannot be installed automatically; use its licensed distribution and set its absolute path`);
    error.statusCode = 400;
    throw error;
  }
  if (TOOL_STATE.get(tool)?.phase === 'ready') return TOOL_STATE.get(tool);
  const state = { phase: 'downloading', bytes: 0, total: 0, message: `Downloading ${tool}`, error: null, version: spec.release.version, path: null };
  TOOL_STATE.set(tool, state);
  try {
    await mkdir(ENGINE_ROOT, { recursive: true });
    const archive = join(ENGINE_ROOT, spec.archive);
    await downloadFile(spec.release.url, archive, {
      onProgress: (bytes, total) => { state.bytes = bytes; state.total = total; },
      log: (message) => log?.warn?.(message),
    });
    const actual = await sha256File(archive);
    if (actual !== spec.release.sha256) {
      await rm(archive, { force: true }).catch(() => {});
      throw new Error(`${tool} checksum mismatch: expected ${spec.release.sha256}, got ${actual}`);
    }
    state.phase = 'configuring';
    state.message = `Configuring ${tool}`;
    if (spec.kind === 'jadx') {
      ENGINE_ENV_OVERRIDES.REA_JADX_MCP_JAR = archive;
      state.path = archive;
    } else if (spec.kind === 'apktool') {
      state.path = await writeApktoolLauncher(archive);
      ENGINE_ENV_OVERRIDES.REA_APKTOOL_COMMAND = state.path;
    } else {
      const root = join(ENGINE_ROOT, `wabt-${spec.release.version}`);
      await rm(root, { recursive: true, force: true });
      await mkdir(root, { recursive: true });
      await extractArchive(archive, root, { log: (message) => log?.warn?.(message) });
      const bin = await findWabtBin(root);
      if (!bin) throw new Error('the WABT archive was extracted, but no bin directory with wasm2wat was found');
      ENGINE_ENV_OVERRIDES.REA_WABT_BIN_DIRECTORY = bin;
      state.path = bin;
    }
    state.phase = 'ready';
    state.message = `${tool} ready`;
    log?.info?.(`dsh-rea: ${tool} ${spec.release.version} prepared at ${state.path}`);
    return state;
  } catch (error) {
    state.phase = 'error';
    state.error = error.message;
    state.message = `${tool} preparation failed`;
    throw error;
  }
}

/** A launcher rather than the jar directly: REA executes a command, not a jar. */
async function writeApktoolLauncher(jar) {
  if (IS_WINDOWS) {
    const launcher = join(ENGINE_ROOT, 'apktool.bat');
    await writeFile(launcher, `@echo off\r\nsetlocal\r\nif defined JAVA_HOME (set "JAVA=%JAVA_HOME%\\bin\\java.exe") else (set "JAVA=java")\r\n"%JAVA%" -jar "${jar}" %*\r\n`, 'utf8');
    return launcher;
  }
  const launcher = join(ENGINE_ROOT, 'apktool');
  const script = `#!/bin/sh\nJAVA="\${JAVA_HOME:+$JAVA_HOME/bin/}java"\nexec "$JAVA" -jar "${jar}" "$@"\n`;
  await writeFile(launcher, script, 'utf8');
  await chmod(launcher, 0o755);
  return launcher;
}

async function findWabtBin(root) {
  if (existsSync(join(root, 'bin', IS_WINDOWS ? 'wasm2wat.exe' : 'wasm2wat'))) return join(root, 'bin');
  try {
    const entries = await readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const candidate = join(root, entry.name, 'bin');
      if (existsSync(join(candidate, IS_WINDOWS ? 'wasm2wat.exe' : 'wasm2wat'))) return candidate;
    }
  } catch {}
  return null;
}

/* ── Status ───────────────────────────────────────────────────────────── */

const configuredValue = (key) => ENGINE_ENV_OVERRIDES[key] ?? process.env[key] ?? '';

/**
 * The confirm paths the local layer names, and whether each can run here.
 *
 * 1.8.0's plan steps told the analyst to "confirm with batch_decompile" without
 * asking whether Ghidra existed; on a host with no engine installed that is an
 * instruction nobody can follow, and the report reads as if it were one. This
 * probe is what turns the seam between "hypothesis" and "confirmation" from a
 * claim into a fact the caller can see.
 *
 * Probing is read-only: `where`/`command -v` for the external binaries, the
 * existing Ghidra/JADX detection for the managed ones. No engine is started.
 */
const PROVIDER_PROBES = [
  { key: 'objdump', command: 'objdump', args: ['--version'], unlocks: 'linear disassembly of a section or address range' },
  { key: 'rizin', command: 'rizin', args: ['-v'], unlocks: 'function-level disassembly, xrefs, and debug sessions' },
  { key: 'gdb', command: 'gdb', args: ['--version'], unlocks: 'breakpoint-level confirmation of a hypothesis' },
  { key: 'frida', command: 'frida', args: ['--version'], unlocks: 'runtime hooking of a decoder this layer cannot read statically' },
];

function probeCommand(command, configured = '') {
  if (configured) {
    // A configured path is trusted only if it exists; a stale env var is the
    // most common way a report ends up promising an engine that is gone.
    const path = configured.replace(/^"|"$/g, '');
    if (existsSync(path)) return { ready: true, path, source: 'config', reason: null };
  }
  // `where` on Windows, `which` elsewhere; `command` is a shell builtin and
  // cannot be spawned directly. Either way the engine itself is never executed:
  // a capability check must not open a session or attach to a target.
  const locator = IS_WINDOWS ? 'where' : 'which';
  const result = spawnSync(locator, [command], {
    encoding: 'utf8', timeout: 8_000, windowsHide: true, maxBuffer: 256 * 1024,
  });
  const ok = result.error === undefined && result.status === 0 && `${result.stdout ?? ''}`.trim().length > 0;
  const first = `${result.stdout ?? ''}`.trim().split('\n')[0]?.trim() ?? '';
  return {
    ready: ok,
    path: ok ? first : null,
    source: ok ? 'path' : null,
    reason: ok ? null : (result.error?.code ?? `${command} not on PATH`),
  };
}

/**
 * Compact "can this actually run" map for the providers the plan names.
 * Keys match the confirm tools in `lib/plan.js`.
 */
export async function providerReadiness() {
  const ghidra = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  const providers = {};
  for (const probe of PROVIDER_PROBES) {
    const configured = probe.key === 'rizin' ? configuredValue('REA_KUNA_COMMAND') : '';
    providers[probe.key] = { ...probeCommand(probe.command, configured), unlocks: probe.unlocks };
  }
  providers.ghidra = {
    ready: Boolean(ghidra.ready),
    path: ghidra.path ?? null,
    source: ghidra.source ?? null,
    reason: ghidra.ready ? null : (ghidra.available
      ? (ghidra.java?.sufficientForGhidra === false
        ? `JDK ${ghidra.java.version ?? 'unknown'} is too old - Ghidra ${GHIDRA_RELEASE.version} needs JDK ${GHIDRA_JAVA_MAJOR}+`
        : 'Ghidra found but not usable (JDK or version)')
      : 'Ghidra not installed'),
    unlocks: 'decompilation to C-like pseudocode; the only path to structured recovery',
  };
  // A first-party twin for `ghidra`: the same installation, driven through
  // analyzeHeadless in a project directory this plugin owns. It exists because
  // REA's Windows runtime cannot be written into by the child JVM, so `ghidra`
  // can be permanently unavailable on a host where Ghidra itself works fine.
  // Reporting it separately keeps "the engine is broken" and "the wrapper's
  // sandbox is broken" from looking like the same fact.
  const localRoot = resolveWorkRoot();
  const localBlocked = !ghidra.available
    ? 'Ghidra not installed'
    : (!ghidra.ready
      ? (ghidra.java?.sufficientForGhidra === false
        ? `JDK ${ghidra.java.version ?? 'unknown'} is too old - Ghidra ${GHIDRA_RELEASE.version} needs JDK ${GHIDRA_JAVA_MAJOR}+`
        : 'Ghidra installed but no usable JDK')
      : (localRoot ? null : 'no writable project directory free of dot-prefixed elements and spaces'));
  providers['ghidra-local'] = {
    ready: Boolean(localRoot && ghidra.ready),
    path: ghidra.path ?? null,
    source: 'first-party',
    projectDir: localRoot ?? null,
    reason: localBlocked,
    unlocks: 'the same decompilation as `ghidra`, run by this plugin instead of through REA',
    candidates: localRoot ? undefined : explainWorkRoot(),
  };
  providers.jadx = {
    ready: Boolean(configuredValue('REA_JADX_MCP_JAR')),
    path: configuredValue('REA_JADX_MCP_JAR') || null,
    source: configuredValue('REA_JADX_MCP_JAR') ? 'config' : null,
    reason: configuredValue('REA_JADX_MCP_JAR') ? null : 'JADX jar not configured',
    unlocks: 'Java/APK decompilation to near-source',
  };
  // A provider whose last launch died in this session is not ready, whatever
  // the files say. The failure is recorded by the tool layer, because that is
  // the only place that sees the engine actually run.
  for (const [key, state] of Object.entries(providers)) {
    const health = engineHealth(key);
    if (!health) continue;
    providers[key] = {
      ...state,
      ready: false,
      reason: `${health.reason}（${health.count > 1 ? `${health.count} 次，` : ''}最近 ${health.lastAt}）`,
      health,
    };
  }
  const keys = Object.keys(providers);
  const live = keys.filter((key) => providers[key].ready);
  return {
    platform: process.platform,
    providers,
    live: live.length,
    total: keys.length,
    note: live.length === 0
      ? 'No confirmation path can run on this host: every experiment the plan names needs an engine that is not installed. Install one before treating any hypothesis as settled.'
      : null,
    // Kept separate from `reason`: "not installed" is a setup task, "found but
    // its last launch failed" is a defect report, and they read differently.
    failed: Object.fromEntries(keys.filter((key) => providers[key].health).map((key) => [key, providers[key].health])),
  };
}

/** Everything the sidebar renders, in one round trip. */
export async function environmentStatus() {
  const ghidra = await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES });
  return {
    ok: true,
    platform: process.platform,
    architecture: process.arch,
    runtime: {
      archive: existsSync(RUNTIME_ARCHIVE),
      unpacked: existsSync(RUNTIME_ENTRY),
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
      downloadBytes: GHIDRA_RELEASE.bytes,
      archiveSha256: GHIDRA_RELEASE.sha256,
    },
    external: {
      jadx: Boolean(configuredValue('REA_JADX_MCP_JAR')),
      apktool: Boolean(configuredValue('REA_APKTOOL_COMMAND')),
      wabt: Boolean(configuredValue('REA_WABT_BIN_DIRECTORY')),
      rizin: Boolean(configuredValue('REA_KUNA_COMMAND')),
    },
    externalCanPrepare: {
      jadx: true,
      apktool: true,
      wabt: Boolean(wabtAsset()),
      rizin: false,
    },
    externalState: Object.fromEntries([...TOOL_STATE.entries()].map(([key, state]) => [key, {
      phase: state.phase, bytes: state.bytes, total: state.total,
      message: state.message, error: state.error, version: state.version, path: state.path,
    }])),
    configured: Object.fromEntries(ENGINE_KEYS.map((key) => [key, configuredValue(key)])),
    configFile: ENGINE_CONFIG_FILE,
  };
}
