/**
 * Side-effect observation through API hooks.
 *
 * The file trace sees what landed in the run directory. This module sees the
 * calls that do not leave a file: registry writes, named pipes, service
 * creation, IPv4/IPv6 outbound connections and DNS lookup attempts. It runs the
 * sample under Frida with hooks and collects normalised `family:operation
 * detail` events, so a target and a rebuild can be compared as sets.
 *
 * It observes attempts, not successes: a failed call still appears, and calls
 * resolved at runtime through GetProcAddress or the IAT are visible too,
 * because the hook patches the export address itself. The window is bounded by
 * a measured behaviour (frida 17.26.3 / Win11 26300, root cause unknown): after
 * the first connect-family call the observer goes silent for the rest of the
 * process, so the report covers that first call and the attempts made before it
 * - never continuous observation past it.
 *
 * @module dsh-rea-restore/lib/observe
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { PLUGIN_ROOT } from '../infra/paths.js';
import { launchSandboxed } from './sandbox.js';

const HELPER = join(PLUGIN_ROOT, 'scripts', 'dynamic', 'observe.py');
const MAX_OUTPUT = 64 * 1024;

function killTree(pid) {
  if (!pid) return;
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
    } else {
      process.kill(-pid, 'SIGKILL');
    }
  } catch {
    // Best effort.
  }
}

/**
 * Run one observation window. `sandbox: true` starts the sample through the
 * kernel-enforced launcher (created suspended, attached by pid, hooks before
 * the first instruction) instead of a Frida spawn; a launch failure is
 * fail-closed and never falls back to an unsandboxed spawn.
 */
export function runSideEffectObserver({ target, durationMs = 1_500, timeoutMs = 60_000, blockEgress = true, python = 'python', pythonArgs = [], sandbox = false, workDir = null } = {}) {
  return new Promise(async (resolvePromise) => {
    if (!existsSync(HELPER)) {
      resolvePromise({ ok: false, reason: `observer helper missing: ${HELPER}` });
      return;
    }
    const finish = (value) => resolvePromise(value);
    // The sandbox launcher session (null on the plain spawn path); read by
    // runPython's finish so a stray container child is reaped with python.
    let session = null;
    const runPython = async (extraArgs) => new Promise((resolvePython) => {
      const child = spawn(python, [
        ...pythonArgs, HELPER, target, String(Math.max(200, durationMs)), String(Math.max(1_000, timeoutMs)),
        blockEgress === false ? '0' : '1',
        ...extraArgs,
      ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let settled = false;
      let timer = null;
      let answerWatch = null;
      // The helper prints its single JSON answer and exits - but the Frida
      // cleanup at interpreter exit can deadlock (measured on this build), and
      // a container child holding the inherited pipe handles can stall the
      // close event long after the answer is available. Resolve from the
      // stream the moment the answer line lands; never depend on the exit.
      const finish = (value) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (answerWatch) clearInterval(answerWatch);
        killTree(child.pid);
        if (session?.pid) killTree(session.pid);
        try { child.kill('SIGKILL'); } catch { /* gone */ }
        resolvePython(value);
      };
      const scanStdout = () => {
        if (settled) return;
        const lines = stdout.split(/\r?\n/).filter(Boolean);
        for (let index = lines.length - 1; index >= 0; index -= 1) {
          try {
            const answer = JSON.parse(lines[index]);
            if (answer && (answer.ok === true || typeof answer.error === 'string')) {
              finish(answer.ok === true
                ? {
                  ok: true,
                  events: Array.isArray(answer.events) ? answer.events : [],
                  warnings: Array.isArray(answer.warnings) ? answer.warnings : [],
                  durationMs,
                }
                : { ok: false, reason: answer.error ?? 'the observer produced no answer' });
              return;
            }
          } catch { /* keep looking for the JSON line */ }
        }
      };
      timer = setTimeout(() => {
        finish({ ok: false, reason: 'the observer did not finish in its time budget' });
      }, Math.max(10_000, durationMs + timeoutMs + 30_000));
      answerWatch = setInterval(scanStdout, 100);
      child.stdout.on('data', (chunk) => { stdout = (stdout + chunk).slice(-MAX_OUTPUT); scanStdout(); });
      child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-MAX_OUTPUT); });
      child.on('error', (error) => {
        finish({ ok: false, reason: `cannot start the observer (${error.message})` });
      });
      child.on('close', () => {
        scanStdout();
        finish({ ok: false, reason: stderr.trim() || 'the observer produced no answer' });
      });
    });

    if (!sandbox) {
      finish(await runPython([]));
      return;
    }
    // Kernel-enforced path: the launcher creates the child suspended inside
    // the AppContainer + Job; this helper attaches by pid and installs hooks
    // before the first instruction. Fail-closed on any launch failure.
    if (!workDir) {
      finish({ ok: false, reason: 'sandboxed observation needs a workDir for the sandbox launcher' });
      return;
    }
    session = await launchSandboxed({
      exe: target,
      workDir,
      timeoutMs: Math.max(200, durationMs) + 20_000,
      suspend: true,
    });
    if (!session.pid) {
      const outcome = await session.wait();
      finish({ ok: false, reason: outcome.reason ?? 'the sandbox did not start the sample' });
      return;
    }
    const observed = await runPython(['--pid', String(session.pid), '--tid', String(session.tid ?? '')]);
    // The python helper terminated the child; await the launcher so the job is
    // closed and classified (bounded by the launcher's own -TimeoutMs watchdog).
    const outcome = await session.wait();
    if (!observed.ok) {
      finish(observed);
      return;
    }
    finish({
      ...observed,
      warnings: [
        ...observed.warnings,
        // A job-assignment failure is fail-closed (ran=false in the parsed
        // outcome): there is no token-only-degraded-but-ran outcome to warn
        // about here.
        ...(outcome.notes ?? []),
      ],
      sandbox: { ran: true, jobEnforced: outcome.jobEnforced, pid: outcome.pid, timedOut: outcome.timedOut },
    });
  });
}

const family = (event) => String(event).split(/[:\s]/, 1)[0];

export function summarizeEvents(events) {
  const groups = { registry: 0, pipe: 0, network: 0, dns: 0, service: 0, other: 0 };
  for (const event of events) {
    const key = family(event);
    groups[key] = (groups[key] ?? 0) + 1;
  }
  return groups;
}

export function compareEventSets(targetEvents = [], rebuiltEvents = []) {
  const a = new Set(targetEvents.map((event) => String(event)));
  const b = new Set(rebuiltEvents.map((event) => String(event)));
  const missing = [...a].filter((event) => !b.has(event));
  const added = [...b].filter((event) => !a.has(event));
  const recall = a.size === 0 ? null : (a.size - missing.length) / a.size;
  const precision = b.size === 0 ? null : (b.size - added.length) / b.size;
  const score = recall === null && precision === null
    ? null
    : recall === null
      ? precision
      : precision === null
        ? recall
        : (recall + precision) / 2;
  return {
    status: score === null ? 'empty' : 'ran',
    score,
    recall,
    precision,
    targetSize: a.size,
    rebuiltSize: b.size,
    // The full event cap: rendered excerpts sort and re-slice downstream, and
    // slicing here silently dropped everything past the first 20 in insertion
    // order (measured: winsock-init registry queries crowded a connect event
    // out of the report).
    missing: missing.slice(0, 200),
    added: added.slice(0, 200),
    groups: { target: summarizeEvents(targetEvents), rebuilt: summarizeEvents(rebuiltEvents) },
  };
}

export function observeLimitations() {
  return [
    'The observer records attempted calls through user-mode API hooks on export addresses: registry (open/create/query/set/delete/close, both character sets), named pipes, services, IPv4/IPv6 outbound connections (ws2_32!connect and WSAConnect) and DNS lookup attempts (getaddrinfo, GetAddrInfoW, GetAddrInfoExW and dnsapi!DnsQuery_W). Calls resolved at runtime through GetProcAddress or the IAT are visible, because the hook patches the export address itself. Still invisible: direct syscalls that bypass ntdll, kernel drivers, raw-socket DNS on port 53, DNS over HTTPS/TLS (an ordinary 443 connection whose query content is unreadable), QUIC, UDP sendto traffic (no connect event) and ConnectEx (not hooked).',
    'Registry handles are resolved to full key paths: opens seen through the hooks build a handle->path map, and any other handle (transactional opens, ntdll-direct opens, inherited handles) falls back to NtQueryKey(KeyNameInformation), normalized to the same hk* shorthand so event sets stay comparable. Resolution is best effort: a handle without query access or one whose resolution fails is reported as the raw handle value, and a per-user hive is reported under its hive shorthand (hku/hkcr) without the account SID. RegCloseKey drops the mapping so a reused handle value cannot inherit the previous key\'s path.',
    'Measured window (frida 17.26.3 / Win11 26300, root cause unknown): after the first connect-family call the observer goes silent for the rest of that process - the report covers that first call and the hooked attempts made before it, never continuous observation past it. ws2_32 and dnsapi exports are mounted at script load when already loaded and through attachModuleObserver plus polling otherwise, so the first call into a freshly loaded module can land before its hooks attach; mount failures and never-loaded watched modules surface as warnings, not silence. An attempt is not a success, and processes the sample launches are not observed.',
    'Egress blocking (blockSampleEgress, on by default) is user-mode best effort: on entry to connect/WSAConnect the observer rewrites a non-loopback sockaddr family to an unusable value so the call fails before any packet is sent, and records network:connect-blocked. Loopback (::1, 127.0.0.1) is allowed through and observed as network:connect. It cannot stop direct syscalls that bypass ntdll, raw sockets, ConnectEx, kernel drivers, or DNS sent over UDP sendto (including a getaddrinfo lookup for a real name - that resolver packet still leaves the host); AF_UNIX and unknown address families are treated as non-loopback and blocked, which can break legitimate local IPC. The other execution paths (rea_trace_behavior, rea_memory_dump, rea_dynamic_probe) do not go through this observer and are not covered by the block. Both binaries run under the same switch, so a blocked attempt is a property of the harness, not a behavioural difference - the report states it was taken under egress blocking.',
    'Host identity (machine name, account name, home-directory paths) is redacted from the rendered report and masked to neutral values in the executed processes\' environment; the full JSON written to the artifact directory keeps the raw values because it is a local file. Use it only on samples you are authorised to run.',
  ];
}
