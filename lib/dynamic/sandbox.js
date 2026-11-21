/**
 * Kernel-enforced sample containment: AppContainer + Job Object.
 *
 * The other execution paths in this plugin (trace, observer, dump, probe) run
 * the sample with the host's own rights and rely on user-mode hooks that a
 * direct syscall, DoH/DoT, raw-DNS or ConnectEx call simply walks past. This
 * module is the second layer: it starts the sample through
 * `scripts/rea-sandbox.ps1`, which creates a no-capability AppContainer token
 * (NtCreateLowBoxToken route - the SECURITY_CAPABILITIES attribute is rejected
 * on this OS build) plus a Job Object with KILL_ON_JOB_CLOSE and no breakaway,
 * assigns the suspended child to the job before its first instruction, and
 * waits. Enforcement is in the kernel (token checks + WFP + job limits), so a
 * connect() to a non-permitted address fails with WSAEACCES (10013) even when
 * the sample issues it directly.
 *
 * Launcher contract (see the ps1 header): every diagnostics line is
 * "rea-sandbox: key=value". A run that produced `pid=` and `child-exit=` with
 * `job-enforced=true` executed the sample; a run without `pid=`, with an
 * `error=` line before `pid=`, or with `job-enforced=false` did not - and that
 * is fail-closed: callers report "the sample did not run" and never fall back
 * to an unsandboxed spawn. Since 2026-11-20 an assign-job failure is
 * fail-closed too: the launcher terminates the suspended child before its
 * first instruction, so there is no token-only degraded-but-ran outcome. A
 * non-zero child exit or a watchdog termination is a *result* (exitCode /
 * timedOut), not an error, matching lib/trace.js's "non-zero exit is a result"
 * contract.
 *
 * Cleanup: the launcher's -TimeoutMs watchdog (TerminateJobObject inside the
 * launcher) is the primary path, and since the 2026-11-20 LimitFlags fix the
 * launcher also terminates any orphan descendants before closing the job
 * handle. ERRATA 2026-11-20: "KILL_ON_JOB_CLOSE alone proved unreliable on
 * this OS build when the launcher is killed externally (measured 2026-11-19)"
 * described a mechanism that was never enabled - the launcher passed a
 * zero-initialised limit struct, so the flag was never set (launcher bug, not
 * OS behaviour). With the flag actually assigned, an external launcher kill is
 * measured to reap the job tree (test/sandbox.test.js, 2026-11-20).
 * When this module had to kill the launcher (or the launcher died with the
 * child still alive), it kills the child tree with `taskkill /PID <pid> /T /F`,
 * but only after checking the live pid still carries the sample's image name,
 * because a reused pid must not be killed.
 *
 * Not covered (stated, not hidden): kernel drivers, side channels, privilege
 * escalation inside the container, IPC through objects whose DACL grants the
 * container access anyway. UDP sendto is not blocked by the AppContainer
 * network isolation on this build (measured); TCP/DNS-via-connect is.
 *
 * @module dsh-rea/lib/sandbox
 */

import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';

import { PLUGIN_ROOT } from '../infra/paths.js';

export const SANDBOX_LAUNCHER = join(PLUGIN_ROOT, 'scripts', 'rea-sandbox.ps1');

/** Harness artifacts the launcher writes into the run directory (plus
 * leaf-pid.txt, written by test fixtures' orphan leaf as its startup
 * handshake). They carry per-run values (pid/tid/SID) that would always differ
 * between two runs, so behaviour comparisons must exclude them from the file
 * snapshot. */
export const SANDBOX_HARNESS_FILES = ['sandbox-diag.txt', 'sandbox-pid.txt', 'leaf-pid.txt'];

/** Is this relative path one of the sandbox harness's own artifacts? */
export function isSandboxHarnessFile(relativePath) {
  return SANDBOX_HARNESS_FILES.includes(String(relativePath).split('/').pop());
}

/** Default wall-clock cap for the launcher itself: child timeout plus setup margin. */
const LAUNCHER_MARGIN_MS = 90_000;
const LAUNCHER_MIN_MS = 30_000;
const MAX_DIAG = 64 * 1024;

/** Quote one argument for a Win32 command line (the launcher splices -Arguments verbatim). */
export function windowsQuoteArgument(value) {
  const text = String(value ?? '');
  if (text.length === 0) return '""';
  if (/^[\w./\\:-]+$/.test(text)) return text;
  return `"${text.replace(/(\\*)"/g, '$1$1\\"').replace(/\\+$/, (m) => m + m)}"`;
}

/**
 * Parse one launcher diagnostics payload and classify the outcome.
 * Pure: no I/O, so tests can pin it against the measured V1-V5 samples.
 */
export function parseSandboxDiag(text) {
  const diag = String(text ?? '');
  const lines = diag.split(/\r?\n/).filter((line) => line.startsWith('rea-sandbox: '));
  const pick = (pattern) => {
    for (let index = 0; index < lines.length; index += 1) {
      const match = lines[index].match(pattern);
      if (match) return { index, match };
    }
    return null;
  };
  const pidMatch = pick(/^rea-sandbox: pid=(\d+) tid=(\d+)$/);
  const exitMatch = pick(/^rea-sandbox: child-exit=(\d+)$/);
  const errorMatch = pick(/^rea-sandbox: error=(.+)$/);
  const warnMatches = lines
    .map((line, index) => ({ index, match: line.match(/^rea-sandbox: warn=(.+)$/) }))
    .filter((entry) => entry.match)
    .map((entry) => entry.match[1].trim());
  // Startup failure = an error line before the pid marker, or any error when
  // no pid marker exists. An assign-job failure (job-enforced=false) is ALSO
  // fail-closed even though pid= exists: the launcher terminates the suspended
  // child before its first instruction (see the ps1 header), so "ran" requires
  // the job layer to have enforced - a token-only run never counts as a run.
  const startupError = errorMatch && (!pidMatch || errorMatch.index < pidMatch.index)
    ? errorMatch.match[1].trim()
    : null;
  const jobEnforcedMatch = pick(/^rea-sandbox: job-enforced=(true|false)$/);
  const containmentFailed = jobEnforcedMatch !== null && jobEnforcedMatch.match[1] === 'false';
  const timeoutMatch = pick(/^rea-sandbox: timeout=(\d+) action=terminate-job$/);
  const desktopMatch = pick(/^rea-sandbox: desktop=(\S+)$/);
  const sidMatch = pick(/^rea-sandbox: container-sid=(\S+)$/);
  const jobHandleMatch = pick(/^rea-sandbox: job-handle=(\S+)$/);
  const ran = pidMatch !== null && exitMatch !== null && startupError === null && !containmentFailed;
  const reason = ran
    ? null
    : containmentFailed
      ? `sandbox containment failed: the job layer did not enforce (assign failed) and the launcher terminated the child before its first instruction - the sample did not run${errorMatch && errorMatch.index >= (pidMatch?.index ?? 0) ? ` (${errorMatch.match[1].trim()})` : ''}`
      : startupError
        ? `sandbox launch failed: ${startupError}`
        : pidMatch
          ? 'sandbox launcher produced no child-exit marker'
          : diag.trim().length === 0
            ? 'sandbox launcher produced no diagnostics'
            : `sandbox launcher produced no pid marker: ${diag.trim().slice(-200)}`;
  return {
    ran,
    reason,
    pid: pidMatch ? Number(pidMatch.match[1]) : null,
    tid: pidMatch ? Number(pidMatch.match[2]) : null,
    childExit: exitMatch ? Number(exitMatch.match[1]) : null,
    timedOut: timeoutMatch !== null,
    timeoutMs: timeoutMatch ? Number(timeoutMatch.match[1]) : null,
    jobEnforced: jobEnforcedMatch ? jobEnforcedMatch.match[1] === 'true' : null,
    desktop: desktopMatch ? desktopMatch.match[1] : null,
    containerSid: sidMatch ? sidMatch.match[1] : null,
    jobHandle: jobHandleMatch ? jobHandleMatch.match[1] : null,
    startupError,
    warnings: warnMatches,
    lines,
  };
}

function readCapped(filePath) {
  return readFile(filePath, 'utf8').then(
    (text) => (text.length > MAX_DIAG ? text.slice(-MAX_DIAG) : text),
    () => null,
  );
}

/** tasklist check, name-verified: a reused pid must never be killed. Exported
 * for the sandbox tests, which poll an orphan fixture's leaf the same way. */
export async function pidAliveWithName(pid, exeBase) {
  if (!pid || process.platform !== 'win32') return false;
  const wanted = String(exeBase).toLowerCase();
  const listing = await new Promise((resolvePromise) => {
    const child = spawn('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('error', () => resolvePromise(null));
    child.on('close', () => resolvePromise(out));
  });
  if (listing === null) return false;
  const firstCell = listing.split(/\r?\n/).find((line) => line.trim().length > 0);
  if (!firstCell) return false;
  const name = firstCell.split(',')[0]?.replace(/^"|"$/g, '').trim().toLowerCase() ?? '';
  return name.length > 0 && (name === wanted || wanted.endsWith(name) || name.endsWith(wanted));
}

function taskkillTree(pid) {
  try {
    spawn('taskkill', ['/pid', String(pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
  } catch {
    // Best effort: the fallback is belt-and-braces behind the watchdog.
  }
}

/**
 * Start the launcher and resolve as soon as the child pid is known (the
 * launcher writes -OutPid right after CreateProcess, before job assignment),
 * so a caller can attach Frida while the launcher keeps waiting. `wait()`
 * resolves with the full classified outcome after the launcher exits.
 *
 * Fail-closed: every launch-phase problem surfaces through `wait()` as
 * `ran: false` with a reason - the caller reports it and never falls back to
 * an unsandboxed spawn.
 */
export function launchSandboxed({
  exe,
  args = [],
  workDir,
  timeoutMs = 15_000,
  suspend = false,
  desktop = false,
  noContainer = false,
  noMask = false,
  diagFile,
  pidFile,
  launcherTimeoutMs,
  signal,
} = {}) {
  return new Promise((resolvePromise) => {
    if (process.platform !== 'win32') {
      resolvePromise({ ok: false, pid: null, tid: null, wait: () => Promise.resolve({
        ran: false, ok: false, reason: 'the sandbox launcher requires Windows (AppContainer + Job Object APIs)',
      }) });
      return;
    }
    if (!exe || typeof exe !== 'string') {
      resolvePromise({ ok: false, pid: null, tid: null, wait: () => Promise.resolve({
        ran: false, ok: false, reason: 'sandbox launch needs an exe path',
      }) });
      return;
    }
    const effectiveTimeoutMs = Math.max(1_000, Math.floor(Number(timeoutMs) || 15_000));
    const capMs = Math.max(LAUNCHER_MIN_MS, (launcherTimeoutMs ?? 0) || effectiveTimeoutMs + LAUNCHER_MARGIN_MS);
    const diag = diagFile ?? join(workDir ?? '.', 'sandbox-diag.txt');
    const pidPath = pidFile ?? join(workDir ?? '.', 'sandbox-pid.txt');
    const launcherArgs = [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', SANDBOX_LAUNCHER,
      '-Executable', exe,
      '-Arguments', args.length === 0 ? '' : args.map(windowsQuoteArgument).join(' '),
      '-WorkDir', workDir ?? '.',
      '-DiagFile', diag,
      '-OutPid', pidPath,
      '-TimeoutMs', String(effectiveTimeoutMs),
    ];
    if (suspend) launcherArgs.push('-Suspend');
    if (desktop) launcherArgs.push('-Desktop');
    if (noContainer) launcherArgs.push('-NoContainer');
    if (noMask) launcherArgs.push('-NoMask');

    const started = Date.now();
    const launcher = spawn('powershell.exe', launcherArgs, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let launcherStdout = '';
    let launcherStderr = '';
    let launcherError = null;
    let launcherKilled = false;
    let launcherExitCode = null;
    let exitResolve;
    const exited = new Promise((r) => { exitResolve = r; });
    // Registered immediately: a launcher that dies before writing the pid must
    // still produce a classified fail-closed outcome, not a hang.
    launcher.on('close', (code) => { launcherExitCode = code; exitResolve(); });
    launcher.on('error', (error) => { launcherError = error; exitResolve(); });
    launcher.stdout.on('data', (chunk) => { launcherStdout = (launcherStdout + chunk).slice(-MAX_DIAG); });
    launcher.stderr.on('data', (chunk) => { launcherStderr = (launcherStderr + chunk).slice(-MAX_DIAG); });

    const killLauncher = () => {
      launcherKilled = true;
      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', String(launcher.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
      }
      try { launcher.kill('SIGKILL'); } catch { /* gone */ }
    };
    const onAbort = () => killLauncher();
    signal?.addEventListener('abort', onAbort, { once: true });
    const capTimer = setTimeout(() => killLauncher(), capMs);

    const readOutcome = async () => {
      clearTimeout(capTimer);
      signal?.removeEventListener('abort', onAbort);
      await exited;
      const diagText = (await readCapped(diag)) ?? '';
      const parsed = parseSandboxDiag(diagText);
      const notes = [];
      if (launcherKilled) notes.push('the launcher was killed at the caller timeout; KILL_ON_JOB_CLOSE should have reaped the job tree (enabled since the 2026-11-20 LimitFlags fix), and the name-verified taskkill below stays as belt-and-braces');
      // Belt-and-braces fallback (name-verified): whenever a child pid is known,
      // verify it against the sample's image name and kill the tree if it still
      // lives after the launcher exited. On the fixed launcher the job layer
      // reaps everything (orphans terminated pre-close, KILL_ON_JOB_CLOSE
      // enabled), so this only fires on a genuine anomaly - but the comment
      // below promises coverage and the pid-name check keeps a reused pid safe.
      const exeBase = basename(exe);
      const childMayLive = parsed.pid !== null;
      if (childMayLive && (await pidAliveWithName(parsed.pid, exeBase))) {
        taskkillTree(parsed.pid);
        notes.push(`the job layer did not reap the child; used taskkill /PID ${parsed.pid} /T fallback (pid name-verified)`);
      }
      return {
        ...parsed,
        ok: parsed.ran,
        exitCode: parsed.childExit,
        durationMs: Date.now() - started,
        launcherExitCode,
        launcherKilled,
        launcherStdout,
        launcherStderr,
        launcherError: launcherError ? launcherError.message : null,
        notes,
        diag: diagText,
        diagFile: diag,
        pidFile: pidPath,
        ...(parsed.ran ? {} : {
          reason: `${parsed.reason ?? 'sandbox launch failed'}${launcherStderr.trim() ? ` | launcher stderr: ${launcherStderr.trim().slice(-300)}` : ''}`,
        }),
      };
    };

    // Phase 1: wait until the child pid exists AND the launcher finished the
    // job assignment (the diag's job-enforced line lands right after it), or
    // the launcher exited. Attaching Frida before the assignment completes
    // would race the job bookkeeping.
    const pidDeadline = Date.now() + capMs;
    void (async () => {
      let pid = null;
      while (Date.now() < pidDeadline && launcherError === null) {
        try {
          const text = (await readFile(pidPath, 'utf8')).trim();
          if (/^\d+$/.test(text)) pid = Number(text);
        } catch { /* not written yet */ }
        if (pid !== null) {
          const diagText = (await readCapped(diag)) ?? '';
          if (/^rea-sandbox: (job-enforced=|error=assign-job)/m.test(diagText) || launcherExitCode !== null) break;
        } else if (launcherExitCode !== null) {
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      const early = parseSandboxDiag((await readCapped(diag)) ?? '');
      resolvePromise({
        ok: pid !== null || early.ran,
        pid: pid ?? early.pid,
        tid: early.tid,
        containerSid: early.containerSid,
        jobEnforced: early.jobEnforced,
        diagFile: diag,
        pidFile: pidPath,
        wait: readOutcome,
      });
    })();
  });
}

/** Convenience for callers that do not interleave: launch and await the outcome. */
export async function startSandboxed(options = {}) {
  const session = await launchSandboxed(options);
  return session.wait();
}

/** Is sandboxed execution possible on this host? Used for honest refusals. */
export async function sandboxReadiness() {
  if (process.platform !== 'win32') {
    return { ready: false, reason: 'the sandbox launcher requires Windows (AppContainer + Job Object APIs)' };
  }
  try {
    const info = await stat(SANDBOX_LAUNCHER);
    if (!info.isFile()) return { ready: false, reason: `sandbox launcher missing: ${SANDBOX_LAUNCHER}` };
  } catch {
    return { ready: false, reason: `sandbox launcher missing: ${SANDBOX_LAUNCHER}` };
  }
  return { ready: true, reason: null, launcher: SANDBOX_LAUNCHER };
}
