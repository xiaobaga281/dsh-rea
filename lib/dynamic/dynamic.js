/**
 * Opt-in dynamic probing.
 *
 * Everything else in this plugin reads bytes. This module is the one place
 * where a target is executed, and it exists only because some keys are derived
 * at run time and cannot be recovered statically. The boundary is explicit:
 *
 *   - the caller must set `allowSampleExecution` (off by default);
 *   - each call must also pass `confirm: true`;
 *   - by default the child runs the target with the target's own network
 *     access and no kernel containment - that path is for samples the analyst
 *     is authorised to run; with `sandbox: true` (plus the separate
 *     `sandboxSampleExecution` config gate) the target is instead started
 *     suspended inside the kernel-enforced container (lib/sandbox.js:
 *     no-capability AppContainer + no-breakaway job) and the helper attaches
 *     by pid - a launch whose job layer did not enforce is reported as
 *     "the sample did not run" (fail-closed, never an unsandboxed fallback);
 *   - the probe hooks one function by RVA and dumps one buffer argument on
 *     return; it does not modify files on disk or persist anything, but it
 *     does inject a Frida agent and patch the hooked code in memory - the
 *     traces that leaves inside the target process are documented in
 *     docs/detection-surface.md (the detection-surface matrix).
 *
 * @module dsh-rea/lib/dynamic
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { PLUGIN_ROOT } from '../infra/paths.js';
import { launchSandboxed } from './sandbox.js';

const HELPER = join(PLUGIN_ROOT, 'scripts', 'dynamic', 'probe.py');
const MAX_OUTPUT = 512 * 1024;

function killTree(pid) {
  if (!pid) return;
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
    } else {
      process.kill(-pid, 'SIGKILL');
    }
  } catch {
    // Best effort: the timeout result is what matters.
  }
}

/** Interpreters to try, in order. `py -3` is the Windows launcher and often
 * carries the Frida install when the `python` on PATH is a different build. */
const PYTHON_CANDIDATES = [
  { command: 'python', args: [] },
  { command: 'py', args: ['-3'] },
  { command: 'python3', args: [] },
];

/**
 * Whether Python + Frida can run a probe here. Spawns only the interpreter, and
 * reports which interpreter answered so the actual probe uses the same one.
 */
export async function dynamicReadiness({ candidates = PYTHON_CANDIDATES } = {}) {
  const reasons = [];
  for (const candidate of candidates) {
    const outcome = await new Promise((resolvePromise) => {
      const child = spawn(candidate.command, [...candidate.args, '-c', 'import frida;print(frida.__version__)'], { windowsHide: true });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (chunk) => { stdout += chunk; });
      child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4_000); });
      child.on('error', (error) => resolvePromise({ ready: false, reason: `${candidate.command}: ${error.message}` }));
      child.on('close', (code) => {
        const version = stdout.trim();
        resolvePromise(code === 0 && version.length > 0
          ? { ready: true, version, reason: null }
          : { ready: false, reason: `${candidate.command}${candidate.args.join(' ')}: ${(stderr.trim() || `python exited with ${code}`).slice(0, 200)}` });
      });
    });
    if (outcome.ready) {
      return { ready: true, version: outcome.version, reason: null, command: candidate.command, args: candidate.args };
    }
    reasons.push(outcome.reason);
  }
  const detail = reasons.join(' | ');
  return {
    ready: false,
    version: null,
    command: null,
    args: [],
    reason: `no Python with Frida found (tried ${candidates.map((item) => `${item.command}${item.args.length ? ` ${item.args.join(' ')}` : ''}`).join(', ')}). Install it with "pip install frida". ${detail}`.slice(0, 600),
  };
}

/**
 * Run one probe. The caller has already enforced policy; this function only
 * executes the helper and parses its single JSON line.
 *
 * `sandbox: true` starts the sample through the kernel-enforced launcher
 * (created suspended inside the AppContainer + Job), then the helper attaches
 * by pid; a launch failure is fail-closed and never falls back to an
 * unsandboxed spawn. `workDir` is the launcher's run directory (required in
 * sandbox mode).
 */
export function runDynamicProbe({ target, breakRva, argIndex = 0, length = 64, timeoutMs = 20_000, python = 'python', pythonArgs = [], signal, sandbox = false, workDir = null } = {}) {
  return new Promise(async (resolvePromise) => {
    if (sandbox && !workDir) {
      resolvePromise({ ok: false, reason: 'sandboxed probing needs a workDir for the sandbox launcher' });
      return;
    }
    let session = null;
    let extraArgs = [];
    if (sandbox) {
      session = await launchSandboxed({
        exe: target,
        workDir,
        timeoutMs: Math.max(1_000, timeoutMs) + 30_000,
        suspend: true,
      });
      if (!session.pid) {
        const outcome = await session.wait();
        resolvePromise({ ok: false, reason: outcome.reason ?? 'the sandbox did not start the sample' });
        return;
      }
      extraArgs = ['--pid', String(session.pid), '--tid', String(session.tid ?? '')];
    }
    const child = spawn(python, [
      ...pythonArgs,
      HELPER,
      target,
      `0x${Number(breakRva).toString(16)}`,
      String(argIndex),
      String(length),
      String(timeoutMs),
      ...extraArgs,
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    // The helper prints its single JSON answer and exits - but the Frida
    // cleanup at interpreter exit can deadlock (measured on this build), and a
    // container child holding the inherited pipe handles can stall the close
    // event long after the answer is available. Resolve from the stream the
    // moment the answer line lands; never depend on the helper's exit.
    const finishFromAnswer = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearInterval(answerWatch);
      signal?.removeEventListener('abort', onAbort);
      killTree(child.pid);
      if (session?.pid) killTree(session.pid);
      try { child.kill('SIGKILL'); } catch { /* gone */ }
      const reap = session
        ? session.wait().catch(() => null)
        : Promise.resolve(null);
      reap.then((sandboxOutcome) => {
        if (payload.error !== undefined) {
          resolvePromise({ ok: false, reason: payload.error, raw: payload });
          return;
        }
        resolvePromise({
          ok: true,
          ...payload,
          ...(sandboxOutcome && sandboxOutcome.ran
            ? { sandbox: { ran: true, jobEnforced: sandboxOutcome.jobEnforced, pid: sandboxOutcome.pid } }
            : {}),
        });
      });
    };
    const scanStdout = () => {
      if (settled) return;
      const lines = stdout.split(/\r?\n/).filter(Boolean);
      for (let index = lines.length - 1; index >= 0; index -= 1) {
        try {
          const payload = JSON.parse(lines[index]);
          if (payload && (typeof payload.hex === 'string' || typeof payload.error === 'string')) {
            finishFromAnswer(payload);
            return;
          }
        } catch { /* keep looking for the JSON line */ }
      }
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearInterval(answerWatch);
      signal?.removeEventListener('abort', onAbort);
      killTree(child.pid);
      try { child.kill('SIGKILL'); } catch { /* gone */ }
      resolvePromise({ ok: false, reason: `the probe did not finish within ${timeoutMs + (sandbox ? 45_000 : 20_000)} ms` });
    }, Math.max(5_000, timeoutMs + (sandbox ? 45_000 : 20_000)));
    const answerWatch = setInterval(scanStdout, 100);
    const onAbort = () => { try { child.kill('SIGKILL'); } catch { /* gone */ } };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.on('data', (chunk) => { stdout = (stdout + chunk).slice(-MAX_OUTPUT); scanStdout(); });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-MAX_OUTPUT); });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearInterval(answerWatch);
      signal?.removeEventListener('abort', onAbort);
      resolvePromise({ ok: false, reason: error.message });
    });
    child.on('close', (code) => {
      if (settled) return;
      scanStdout();
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearInterval(answerWatch);
      signal?.removeEventListener('abort', onAbort);
      resolvePromise({ ok: false, reason: (stderr.trim() || `probe exited with ${code}`).slice(0, 600) });
    });
  });
}
