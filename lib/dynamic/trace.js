/**
 * Runtime traces: run a binary in a throwaway directory and record what it did.
 *
 * The static tiers describe what a binary *declares*; this module records what
 * it *does* when executed. It exists for the opt-in T4 runtime comparison and
 * is the second execution path in the plugin after the Frida probe. The same
 * boundary applies:
 *
 *   - the caller must enable `allowSampleExecution` and confirm each call;
 *   - by default each binary runs with its own network access: there is no
 *     sandbox. With `sandbox: true` (plus the separate `sandboxSampleExecution`
 *     policy flag) the sample is started through scripts/rea-sandbox.ps1 in a
 *     no-capability AppContainer inside a no-breakaway Job Object - kernel
 *     enforcement instead of user-mode hooks. A failed sandbox launch is
 *     fail-closed: the run is reported as "did not run", never retried
 *     unsandboxed;
 *   - the working directory is fresh per run, so files the program creates are
 *     attributable to it;
 *   - stdout/stderr are capped, the process tree is killed on timeout, and the
 *     trace is data - never executed or replayed.
 *
 * What it cannot see: registry writes, services, named pipes outside the
 * working directory, and anything that needs interactive input. Those are
 * listed in the comparison's limitations rather than silently scored as equal.
 *
 * @module dsh-rea/lib/trace
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

import { isSandboxHarnessFile, startSandboxed } from './sandbox.js';

const MAX_STREAM = 256 * 1024;
const MAX_FILES = 200;
const MAX_DEPTH = 4;
const MAX_FILE_BYTES = 1024 * 1024;

const toPosix = (value) => value.split(sep).join('/');

function killTree(pid) {
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
    } else {
      process.kill(-pid, 'SIGKILL');
    }
  } catch {
    // The timeout result is what matters; a process already gone is fine.
  }
}

/**
 * List the files a run left behind, with content hashes. Names are relative to
 * the run directory so two runs in different directories compare directly.
 */
export async function snapshotFiles(root, { maxFiles = MAX_FILES, maxDepth = MAX_DEPTH } = {}) {
  const files = [];
  const walk = async (directory, depth) => {
    if (depth > maxDepth || files.length >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      const full = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await walk(full, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      let info;
      try {
        info = await stat(full);
      } catch {
        continue;
      }
      const record = { path: toPosix(relative(root, full)), size: info.size, sha256: null };
      if (info.size <= MAX_FILE_BYTES) {
        try {
          record.sha256 = createHash('sha256').update(await readFile(full)).digest('hex');
        } catch {
          // An unreadable file still counts by name and size.
        }
      }
      files.push(record);
    }
  };
  await walk(root, 0);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

/**
 * Neutral identity values handed to the executed binary instead of this
 * machine's real names. Both sides of a comparison run with the same values, so
 * the diff stays fair; a sample that echoes COMPUTERNAME/USERNAME now reports
 * the sandbox names instead of the analyst's host. getenv-level only - a
 * program that asks Win32 directly (GetComputerNameW/GetUserNameW) still hears
 * the truth, and that blind spot is stated in the limitations.
 */
const IDENTITY_MASK = process.platform === 'win32'
  ? {
    COMPUTERNAME: 'rea-sandbox',
    USERNAME: 'analyst',
    USERDOMAIN: 'REAGROUP',
    HOMEDRIVE: 'C:',
    HOMEPATH: '\\Users\\analyst',
  }
  : {
    HOSTNAME: 'rea-sandbox',
    USER: 'analyst',
    LOGNAME: 'analyst',
  };

/**
 * The sandboxed variant of runTrace: same result shape, kernel-enforced start.
 * The launcher's stdout/stderr ARE the child's stdout/stderr (inherited
 * handles; the launcher's own diagnostics go to -DiagFile). A non-zero child
 * exit or a watchdog timeout stays a result, never an error; a launch failure
 * is fail-closed (ok:false, no unsandboxed retry).
 */
async function runSandboxedTrace({ exePath, args, workDir, timeoutMs, signal, isolateProfile, maskIdentity }) {
  const outcome = await startSandboxed({
    exe: exePath,
    args,
    workDir,
    timeoutMs,
    signal,
    noMask: !maskIdentity,
  });
  // The launcher's own diag/pid artifacts carry per-run values (pid/tid/SID)
  // and would always differ between two runs - harness, not sample behaviour.
  const files = (await snapshotFiles(workDir)).filter((file) => !isSandboxHarnessFile(file.path));
  const sandboxRecord = {
    enabled: true,
    ran: outcome.ran === true,
    jobEnforced: outcome.jobEnforced,
    containerSid: outcome.containerSid,
    desktop: outcome.desktop,
    pid: outcome.pid,
    tid: outcome.tid,
    timedOut: outcome.timedOut === true,
    launcherKilled: outcome.launcherKilled === true,
    notes: outcome.notes ?? [],
    reason: outcome.reason ?? null,
  };
  if (!outcome.ran) {
    return {
      ok: false,
      reason: outcome.reason ?? 'the sandbox did not start the sample',
      exitCode: null,
      signal: null,
      timedOut: false,
      durationMs: outcome.durationMs ?? 0,
      stdout: '',
      stderr: outcome.launcherStderr ?? '',
      files,
      profileIsolated: isolateProfile,
      identityMasked: maskIdentity,
      sandbox: sandboxRecord,
    };
  }
  return {
    ok: !outcome.timedOut,
    reason: outcome.timedOut ? `timed out after ${timeoutMs} ms` : null,
    exitCode: outcome.exitCode,
    signal: null,
      timedOut: outcome.timedOut === true,
      durationMs: outcome.durationMs,
      stdout: maskProcessId(outcome.launcherStdout ?? '', outcome.pid),
      stderr: maskProcessId(outcome.launcherStderr ?? '', outcome.pid),
      files,
    profileIsolated: isolateProfile,
    identityMasked: maskIdentity,
    sandbox: sandboxRecord,
  };
}

/**
 * Run one binary and capture its observable behaviour. Never rejects for a
 * non-zero exit: that is a result, not an error.
 *
 * `sandbox: true` runs the binary through the kernel-enforced launcher
 * (lib/sandbox.js) instead of a bare spawn. The result shape is unchanged
 * plus a `sandbox` record; a launch failure resolves ok:false with the
 * launcher's reason and never falls back to an unsandboxed spawn. A
 * caller-supplied `env` is not honoured in sandbox mode: the launcher applies
 * its own neutral identity and profile redirection.
 */
export async function runTrace({ exePath, args = [], workDir, timeoutMs = 15_000, env = null, signal, isolateProfile = true, maskIdentity = true, sandbox = false } = {}) {
  // A caller may hand us a fresh path; creating it here keeps "run in an empty
  // directory" from depending on the caller remembering to.
  await mkdir(workDir, { recursive: true });
  if (sandbox) {
    return runSandboxedTrace({ exePath, args, workDir, timeoutMs, signal, isolateProfile, maskIdentity });
  }
  // Redirect the locations a program reaches for state outside its own folder
  // (%TEMP%, %APPDATA%, $HOME) into the run directory. This turns "wrote a
  // config somewhere" into an observable file; it does not cover the registry,
  // services or named pipes, which stay listed as blind spots.
  const profile = {};
  let profileEnv = {};
  if (isolateProfile) {
    profile.temp = join(workDir, 'profile', 'temp');
    profile.appdata = join(workDir, 'profile', 'appdata');
    profile.local = join(workDir, 'profile', 'localappdata');
    profile.home = join(workDir, 'profile', 'home');
    await Promise.all(Object.values(profile).map((path) => mkdir(path, { recursive: true })));
    profileEnv = process.platform === 'win32'
      ? {
        TEMP: profile.temp, TMP: profile.temp,
        APPDATA: profile.appdata, LOCALAPPDATA: profile.local,
        USERPROFILE: profile.home, HOME: profile.home,
      }
      : {
        TMPDIR: profile.temp, TEMP: profile.temp, TMP: profile.temp,
        HOME: profile.home,
        XDG_CACHE_HOME: join(profile.local, 'cache'),
        XDG_CONFIG_HOME: join(profile.appdata, 'config'),
        XDG_DATA_HOME: join(profile.local, 'share'),
      };
  }
  return new Promise((resolvePromise) => {
    const started = Date.now();
    const child = spawn(exePath, args, {
      cwd: workDir,
      // Identity masking is applied last on purpose: a caller-supplied `env`
      // cannot re-import the real COMPUTERNAME/USERNAME past it. Both sides of
      // a comparison receive the identical mask, so the diff stays fair.
      env: { ...process.env, ...profileEnv, ...(env ?? {}), ...(maskIdentity ? IDENTITY_MASK : {}) },
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      // A separate process group lets a non-Windows timeout kill children too.
      detached: process.platform !== 'win32',
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let spawnError = null;

    const timer = setTimeout(() => {
      timedOut = true;
      if (child.pid) killTree(child.pid);
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }, Math.max(1_000, timeoutMs));

    child.stdout.on('data', (chunk) => { stdout = (stdout + chunk).slice(-MAX_STREAM); });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-MAX_STREAM); });
    child.on('error', (error) => { spawnError = error; });
    const onAbort = () => { if (child.pid) killTree(child.pid); };
    signal?.addEventListener('abort', onAbort, { once: true });

    child.on('close', async (code, closeSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      const files = await snapshotFiles(workDir);
      resolvePromise({
        ok: spawnError === null && !timedOut,
        reason: spawnError ? spawnError.message : timedOut ? `timed out after ${timeoutMs} ms` : null,
        exitCode: typeof code === 'number' ? code : null,
        signal: closeSignal ?? null,
        timedOut,
        durationMs: Date.now() - started,
        stdout: maskProcessId(stdout, child.pid),
        stderr: maskProcessId(stderr, child.pid),
        files,
        profileIsolated: isolateProfile,
        identityMasked: maskIdentity,
      });
    });
  });
}

const normalize = (text) => String(text ?? '').replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trimEnd();

/**
 * Replace the run's own process id in captured output with [PID]: a sample
 * that prints its pid would otherwise make two runs of the same binary differ
 * and cap the comparison's discrimination (measured: 82.5% parity ceiling).
 * Only whole-number occurrences are replaced - a pid inside a longer number
 * stays untouched. The structured record keeps the real pid (sandbox.pid).
 */
function maskProcessId(text, pid) {
  if (!pid || typeof text !== 'string' || !text.includes(String(pid))) return text;
  return text.replace(new RegExp(`(?<!\\d)${pid}(?!\\d)`, 'g'), '[PID]');
}

function lineSimilarity(left, right) {
  const a = normalize(left).split('\n').filter((line) => line.length > 0);
  const b = normalize(right).split('\n').filter((line) => line.length > 0);
  const setA = new Set(a);
  const setB = new Set(b);
  if (setA.size === 0 && setB.size === 0) return null;
  const shared = [...setA].filter((line) => setB.has(line)).length;
  const union = new Set([...setA, ...setB]).size;
  return union === 0 ? null : shared / union;
}

function streamDiff(target, rebuilt) {
  const same = normalize(target) === normalize(rebuilt);
  return {
    score: same ? 1 : lineSimilarity(target, rebuilt),
    identical: same,
    targetLines: normalize(target).length === 0 ? 0 : normalize(target).split('\n').length,
    rebuiltLines: normalize(rebuilt).length === 0 ? 0 : normalize(rebuilt).split('\n').length,
  };
}

function fileDiff(targetFiles, rebuiltFiles) {
  const map = (files) => new Map(files.map((file) => [file.path, file.sha256 ?? `size:${file.size}`]));
  const a = map(targetFiles);
  const b = map(rebuiltFiles);
  const missing = [...a.keys()].filter((path) => !b.has(path));
  const added = [...b.keys()].filter((path) => !a.has(path));
  const changed = [...a.keys()].filter((path) => b.has(path) && b.get(path) !== a.get(path));
  if (a.size === 0 && b.size === 0) return { score: null, recall: null, precision: null, missing, added, changed, targetSize: 0, rebuiltSize: 0 };
  const recall = a.size === 0 ? null : (a.size - missing.length - changed.length) / a.size;
  const precision = b.size === 0 ? null : (b.size - added.length - changed.length) / b.size;
  const score = recall === null && precision === null
    ? null
    : recall === null
      ? precision
      : precision === null
        ? recall
        : (recall + precision) / 2;
  return { score, recall, precision, missing: missing.slice(0, 20), added: added.slice(0, 20), changed: changed.slice(0, 20), targetSize: a.size, rebuiltSize: b.size };
}

/**
 * Compare two traces. Output and file state carry the weight because they are
 * the side effects a reader can verify; stderr is kept separate so a warning
 * does not hide a wrong result.
 */
export function compareTraces(target, rebuilt, options = {}) {
  if (!target || !rebuilt) {
    return { status: 'blocked', score: null, reason: 'one side produced no trace', limitations: traceLimitations(options) };
  }
  if (!target.ok || !rebuilt.ok) {
    return {
      status: 'blocked',
      score: null,
      reason: `target: ${target.reason ?? 'ran'}; rebuilt: ${rebuilt.reason ?? 'ran'}`,
      exit: { score: null, same: false },
      stdout: streamDiff(target.stdout, rebuilt.stdout),
      stderr: streamDiff(target.stderr, rebuilt.stderr),
      files: fileDiff(target.files, rebuilt.files),
      limitations: traceLimitations(options),
    };
  }
  const exitSame = target.exitCode === rebuilt.exitCode;
  const stdout = streamDiff(target.stdout, rebuilt.stdout);
  const stderr = streamDiff(target.stderr, rebuilt.stderr);
  const files = fileDiff(target.files, rebuilt.files);
  const components = [
    [exitSame ? 1 : 0, 0.2],
    [stdout.score, 0.35],
    [stderr.score, 0.15],
    [files.score, 0.3],
  ].filter(([value]) => typeof value === 'number');
  const weight = components.reduce((sum, [, itemWeight]) => sum + itemWeight, 0);
  const score = weight === 0 ? null : components.reduce((sum, [value, itemWeight]) => sum + value * itemWeight, 0) / weight;
  return {
    status: score === null ? 'empty' : 'ran',
    score,
    reason: score === null ? 'neither side produced output, files or a comparable exit' : null,
    exit: { score: exitSame ? 1 : 0, same: exitSame, target: target.exitCode, rebuilt: rebuilt.exitCode },
    stdout,
    stderr,
    files,
    durations: { target: target.durationMs, rebuilt: rebuilt.durationMs },
    limitations: traceLimitations(options),
  };
}

export function traceLimitations({ sandbox = false } = {}) {
  const containment = sandbox
    ? 'Both binaries were executed in a throwaway working directory inside the kernel-enforced sandbox (no-capability AppContainer + no-breakaway Job Object): non-loopback TCP is denied by the kernel (WSAEACCES), loopback stays blocked unless an administrator has granted the CheckNetIsolation exemption, and UDP sendto is not blocked. Kernel drivers, side channels and in-container privilege escalation are out of scope.'
    : 'Both binaries were executed in a throwaway working directory. There is no sandbox: they keep the host\'s network access and can touch anything the current user can touch.';
  const identityTail = sandbox
    ? 'It does not hook Win32: GetComputerNameW, GetUserNameW and friends still return the real host identity. Network containment comes from the kernel sandbox, not from the environment mask.'
    : 'It does not hook Win32: GetComputerNameW, GetUserNameW and friends still return the real host identity, and no network-level sandboxing is provided.';
  return [
    containment,
    'The file dimension observes files under the run directory; TEMP/APPDATA/HOME are redirected there, but registry writes, services, named pipes, network peers and files written to absolute paths outside it remain invisible and are not scored.',
    'A program that waits for interactive input hits the timeout and reports it as a blocked trace rather than as a behavioural difference.',
    `Identity masking rewrites the environment variables a getenv-style read would return (COMPUTERNAME/USERNAME/USERDOMAIN on Windows, HOSTNAME/USER on POSIX) to neutral values, identically for both binaries. ${identityTail}`,
  ];
}
