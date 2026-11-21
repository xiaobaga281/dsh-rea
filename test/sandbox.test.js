/**
 * Kernel-enforced sandbox (AppContainer + Job Object) integration.
 *
 * Unit layer: parseSandboxDiag is pinned against the MEASURED diagnostics of
 * the launcher validation matrix (V1 normal run, V2 watchdog timeout, V3
 * missing executable, V4 non-executable target, V5 self-exit 3) plus a
 * synthetic assign-failure fixture - the four outcome classes the launcher
 * contract distinguishes, with classification from the diag contract only.
 *
 * Live layer (Windows only, project gcc fixtures, zero external network):
 * the sample runs to completion inside the container, 192.0.2.1:9 is denied
 * by the kernel (WSAEACCES 10013 at 0 ms; host-normal contrast: 21 s timeout),
 * the job locks the process tree (breakaway denied), the watchdog terminates
 * a runaway child, an orphaned grandchild is reaped when the launcher exits
 * (C-1: LimitFlags was never set before 2026-11-20 - the orphan test measured
 * the broken tree first and is the reproduction record), a failed launch is
 * fail-closed, and an assign-job failure is fail-closed too (C-2: the launcher
 * terminates the suspended child before its first instruction). Loopback
 * (127.0.0.1 / ::1) is measured as BLOCKED on a non-admin host: the
 * CheckNetIsolation loopback exemption is administrator-only (measured err=5),
 * so the test pins that limitation instead of claiming a pass.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createArtifactStore } from '../lib/artifacts.js';
import { compileC } from '../lib/build.js';
import { buildDynamicProbeTool } from '../lib/dynamic-tools.js';
import { buildMemoryDumpTool } from '../lib/memdump-tools.js';
import { buildSideEffectsTool } from '../lib/observe-tools.js';
import { isSandboxHarnessFile, parseSandboxDiag, pidAliveWithName, SANDBOX_LAUNCHER, startSandboxed, windowsQuoteArgument } from '../lib/sandbox.js';
import { runTrace } from '../lib/trace.js';
import { buildTraceBehaviorTool } from '../lib/trace-tools.js';

const IS_WIN = process.platform === 'win32';

// ---- measured launcher diagnostics (validation matrix, 2026-11-19) ----
const DIAG_V1_NORMAL = [
  'rea-sandbox: container-sid=S-1-15-2-1669798304-1193962169-1626343427-3215346415-4103508380-1540202634-3524362428',
  'rea-sandbox: job-handle=0xa7c',
  'rea-sandbox: pid=33372 tid=20940',
  'rea-sandbox: job-enforced=true',
  'rea-sandbox: child-exit=0',
  '',
].join('\n');
const DIAG_V2_WATCHDOG = [
  'rea-sandbox: container-sid=S-1-15-2-3375190064-1169089364-1518382742-2510936193-715575634-2122075859-2158849441',
  'rea-sandbox: job-handle=0x954',
  'rea-sandbox: pid=31772 tid=18628',
  'rea-sandbox: job-enforced=true',
  'rea-sandbox: timeout=2500 action=terminate-job',
  'rea-sandbox: child-exit=1',
  '',
].join('\n');
const DIAG_V4_BAD_EXE = [
  'rea-sandbox: container-sid=S-1-15-2-3424997525-583839137-1161515390-3322240792-3007049929-1167195396-1693174499',
  'rea-sandbox: job-handle=0xa40',
  'rea-sandbox: error=create-process err=193',
  '',
].join('\n');
const DIAG_V5_SELF_EXIT = [
  'rea-sandbox: container-sid=S-1-15-2-1791549690-1616160428-3578336770-1355556578-2766554189-4095603689-1012730159',
  'rea-sandbox: job-handle=0xa70',
  'rea-sandbox: pid=14536 tid=9360',
  'rea-sandbox: job-enforced=true',
  'rea-sandbox: child-exit=3',
  '',
].join('\n');
// Synthetic: AssignProcessToJobObject failure cannot be triggered naturally
// (every measured run assigned fine), so the contract is pinned with this
// fixture: pid= and child-exit= exist, the error= comes AFTER pid=, and
// job-enforced=false. Since C-2 (2026-11-20) this is fail-closed: the launcher
// terminates the suspended child before its first instruction, so the sample
// did NOT run - "ran" requires the job layer to have enforced.
const DIAG_ASSIGN_FAILED = [
  'rea-sandbox: container-sid=S-1-15-2-1000000000-2000000000-3000000000-4000000000-5000000000-6000000000-7000000000',
  'rea-sandbox: job-handle=0xabc',
  'rea-sandbox: pid=4242 tid=4243',
  'rea-sandbox: error=assign-job err=5',
  'rea-sandbox: job-enforced=false',
  'rea-sandbox: child-exit=0',
  '',
].join('\n');

test('diag V1: a normal run is classified as ran with job enforcement', () => {
  const parsed = parseSandboxDiag(DIAG_V1_NORMAL);
  assert.equal(parsed.ran, true);
  assert.equal(parsed.ok, undefined); // classification only; ok is added by the launcher path
  assert.equal(parsed.childExit, 0);
  assert.equal(parsed.pid, 33372);
  assert.equal(parsed.tid, 20940);
  assert.equal(parsed.jobEnforced, true);
  assert.equal(parsed.timedOut, false);
  assert.equal(parsed.startupError, null);
  assert.match(parsed.containerSid, /^S-1-15-2-/);
});

test('diag V2: a watchdog timeout ran the sample and is a result, not a launch failure', () => {
  const parsed = parseSandboxDiag(DIAG_V2_WATCHDOG);
  assert.equal(parsed.ran, true);
  assert.equal(parsed.timedOut, true);
  assert.equal(parsed.timeoutMs, 2500);
  assert.equal(parsed.childExit, 1);
  assert.equal(parsed.jobEnforced, true);
});

test('diag V3: no diagnostics at all is fail-closed', () => {
  const parsed = parseSandboxDiag('');
  assert.equal(parsed.ran, false);
  assert.equal(parsed.pid, null);
  assert.match(parsed.reason, /no diagnostics/);
});

test('diag V4: an error before pid is a startup failure (fail-closed)', () => {
  const parsed = parseSandboxDiag(DIAG_V4_BAD_EXE);
  assert.equal(parsed.ran, false);
  assert.equal(parsed.pid, null);
  assert.match(parsed.startupError, /create-process err=193/);
  assert.match(parsed.reason, /sandbox launch failed/);
});

test('diag V5: a non-zero self exit is a result (ran), never an error', () => {
  const parsed = parseSandboxDiag(DIAG_V5_SELF_EXIT);
  assert.equal(parsed.ran, true);
  assert.equal(parsed.childExit, 3);
  assert.equal(parsed.startupError, null);
});

test('diag synthetic: assign failure is fail-closed - the sample did NOT run (containment failed)', () => {
  const parsed = parseSandboxDiag(DIAG_ASSIGN_FAILED);
  assert.equal(parsed.ran, false);
  assert.equal(parsed.jobEnforced, false);
  assert.equal(parsed.childExit, 0);
  assert.equal(parsed.startupError, null);
  assert.match(parsed.reason, /containment failed/);
  assert.match(parsed.reason, /assign-job/);
  assert.deepEqual(parsed.warnings, []);
});

test('windowsQuoteArgument builds a splicable command line', () => {
  assert.equal(windowsQuoteArgument(''), '""');
  assert.equal(windowsQuoteArgument('sleep'), 'sleep');
  assert.equal(windowsQuoteArgument('a b'), '"a b"');
  assert.equal(windowsQuoteArgument('say "hi"'), '"say \\"hi\\""');
});

test('the launcher is refused up front off-Windows', { skip: IS_WIN ? false : 'runs only as a negative check on Windows hosts' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-'));
  try {
    const outcome = await startSandboxed({ exe: 'nope.exe', workDir: dir, timeoutMs: 5_000 });
    assert.equal(outcome.ran, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- live container matrix (Windows + project gcc; zero external traffic) ----

const CRT_FIXTURE = [
  '#include <stdio.h>',
  '#include <stdlib.h>',
  '#include <string.h>',
  '#include <windows.h>',
  'int main(int argc, char **argv) {',
  '  /* prints its own pid on purpose: the comparison masks per-run pids to',
  '   * [PID], so this must not dilute the parity score (verifier finding) */',
  '  printf("crt-ok pid=%d argc=%d\\n", (int)GetCurrentProcessId(), argc);',
  '  {',
  '    HANDLE tok = NULL;',
  '    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {',
  '      int isApp = 0; DWORD ret = 0;',
  '      if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)29, &isApp, sizeof isApp, &ret))',
  '        printf("token is-app-container=%d\\n", isApp);',
  '      DWORD len = 0;',
  '      GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);',
  '      if (len > 0 && len <= 128) {',
  '        char buf[128];',
  '        if (GetTokenInformation(tok, TokenIntegrityLevel, buf, len, &ret)) {',
  '          void **label = (void **)buf;',
  '          UCHAR *sidBytes = (UCHAR *)label[0];',
  '          if (sidBytes) printf("token integrity-rid=0x%04lX\\n", (unsigned long)((DWORD *)(sidBytes + 8))[sidBytes[1] - 1]);',
  '        }',
  '      }',
  '      CloseHandle(tok);',
  '    }',
  '  }',
  '  printf("env %s=%s %s=%s\\n", "COMPUTERNAME", getenv("COMPUTERNAME"), "USERNAME", getenv("USERNAME"));',
  '  {',
  '    FILE *f = fopen("sandbox-fixture.txt", "w");',
  '    if (f) { fputs("written-in-container\\n", f); fclose(f); printf("file-write-ok\\n"); }',
  '    else printf("file-write-FAILED err=%d\\n", (int)GetLastError());',
  '  }',
  '  if (argc > 1 && strcmp(argv[1], "sleep") == 0) { printf("sleeping\\n"); fflush(stdout); Sleep(6000); printf("woke\\n"); }',
  '  fflush(stdout);',
  '  return 0;',
  '}',
].join('\n');

// Blocking-connect probe: the kernel deny for a no-capability AppContainer
// surfaces as WSAEACCES (10013) at 0 ms on the blocking connect (measured;
// the nonblocking variant only shows a silent drop). Destinations: RFC 5737
// TEST-NET 192.0.2.1 (unroutable, no external traffic) and the caller's ::1
// listener port. Loopback is measured-blocked without the admin-only
// exemption, and the fixture records the exact outcome either way.
const NET_FIXTURE = [
  '#define WIN32_LEAN_AND_MEAN',
  '#include <winsock2.h>',
  '#include <ws2tcpip.h>',
  '#include <stdio.h>',
  '#include <stdlib.h>',
  'static void tryConnect(const char *label, int family, const char *ip, unsigned short port) {',
  '  SOCKET s = socket(family, SOCK_STREAM, 0);',
  '  if (s == INVALID_SOCKET) { printf("net dst=%s socket-fail err=%d\\n", label, WSAGetLastError()); return; }',
  '  struct sockaddr_in a4; struct sockaddr_in6 a6; struct sockaddr *sa; int sl;',
  '  DWORD t0 = GetTickCount(); int rc;',
  '  if (family == AF_INET) { memset(&a4, 0, sizeof a4); a4.sin_family = AF_INET; a4.sin_port = htons(port); inet_pton(AF_INET, ip, &a4.sin_addr); sa = (struct sockaddr *)&a4; sl = (int)sizeof a4; }',
  '  else { memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6; a6.sin6_port = htons(port); inet_pton(AF_INET6, ip, &a6.sin6_addr); sa = (struct sockaddr *)&a6; sl = (int)sizeof a6; }',
  '  rc = connect(s, sa, sl);',
  '  if (rc == 0) printf("net dst=%s rc=0 err=0 ms=%lu\\n", label, (unsigned long)(GetTickCount() - t0));',
  '  else printf("net dst=%s rc=%d err=%d ms=%lu\\n", label, rc, WSAGetLastError(), (unsigned long)(GetTickCount() - t0));',
  '  closesocket(s);',
  '}',
  'int main(int argc, char **argv) {',
  '  WSADATA w;',
  '  if (WSAStartup(MAKEWORD(2, 2), &w) != 0) { printf("net WSAStartup failed\\n"); return 1; }',
  '  unsigned short lp = (argc > 1) ? (unsigned short)atoi(argv[1]) : 9;',
  '  tryConnect("192.0.2.1:9", AF_INET, "192.0.2.1", 9);',
  '  { char label[64]; sprintf(label, "[::1]:%u", (unsigned)lp); tryConnect(label, AF_INET6, "::1", lp); }',
  '  WSACleanup(); fflush(stdout); return 0;',
  '}',
].join('\n');

// Job-tree probe: the fixture spawns ITSELF (same exe path, so the launcher's
// RX ACE covers it) as a grandchild. Parent asserts in-job membership, that a
// CREATE_BREAKAWAY_FROM_JOB spawn is denied by the kernel (the job does not
// allow breakaway), and that the normal child also reports in-job. The
// "orphan" / "orphan-leaf" branches (C-0/C-1) build a real orphan: the parent
// spawns the leaf, waits only for the leaf's STARTUP handshake (leaf-pid.txt,
// excluded from snapshots via SANDBOX_HARNESS_FILES) and returns - the leaf
// stays inside the job, heartbeating, after the parent and the launcher exit.
const JOB_TREE_FIXTURE = [
  '#define WIN32_LEAN_AND_MEAN',
  '#include <winsock2.h>',
  '#include <ws2tcpip.h>',
  '#include <windows.h>',
  '#include <stdio.h>',
  '#include <string.h>',
  'static int inJob(void) { BOOL b = FALSE; if (IsProcessInJob(GetCurrentProcess(), NULL, &b)) return b ? 1 : 0; return -1; }',
  'static void printTokenState(const char *who) {',
  '  HANDLE tok = NULL;',
  '  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return;',
  '  {',
  '    int isApp = 0; DWORD ret = 0;',
  '    if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)29, &isApp, sizeof isApp, &ret))',
  '      printf("%s token is-app-container=%d\\n", who, isApp);',
  '    DWORD len = 0;',
  '    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);',
  '    if (len > 0 && len <= 128) {',
  '      char buf[128];',
  '      if (GetTokenInformation(tok, TokenIntegrityLevel, buf, len, &ret)) {',
  '        void **label = (void **)buf;',
  '        UCHAR *sidBytes = (UCHAR *)label[0];',
  '        if (sidBytes) printf("%s token integrity-rid=0x%04lX\\n", who, (unsigned long)((DWORD *)(sidBytes + 8))[sidBytes[1] - 1]);',
  '      }',
  '    }',
  '  }',
  '  CloseHandle(tok);',
  '}',
  'int main(int argc, char **argv) {',
  '  if (argc > 1 && strcmp(argv[1], "leaf") == 0) { printf("leaf in-job=%d\\n", inJob()); fflush(stdout); return 0; }',
  '  if (argc > 1 && strcmp(argv[1], "orphan-leaf") == 0) {',
  '    /* Orphan self-check (C-0 qualification, 2026-11-20): while this leaf',
  '     * lives orphaned inside the job, is the container token still binding',
  '     * it? Every fact is printed BEFORE the leaf-pid.txt handshake so it is',
  '     * on stdout even though the fixed launcher reaps this leaf fast. */',
  '    printf("leaf in-job=%d\\n", inJob());',
  '    printTokenState("leaf");',
  '    {',
  '      WSADATA w;',
  '      if (WSAStartup(MAKEWORD(2, 2), &w) == 0) {',
  '        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);',
  '        if (s != INVALID_SOCKET) {',
  '          struct sockaddr_in a; memset(&a, 0, sizeof a);',
  '          a.sin_family = AF_INET; a.sin_port = htons(9);',
  '          inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);',
  '          DWORD t0 = GetTickCount();',
  '          int rc = connect(s, (struct sockaddr *)&a, sizeof a);',
  '          printf("leaf net dst=192.0.2.1:9 rc=%d err=%d ms=%lu\\n", rc, (rc == 0) ? 0 : WSAGetLastError(), (unsigned long)(GetTickCount() - t0));',
  '          closesocket(s);',
  '        }',
  '        WSACleanup();',
  '      }',
  '    }',
  '    fflush(stdout);',
  '    FILE *pf = fopen("leaf-pid.txt", "w");',
  '    if (pf) { fprintf(pf, "%lu", (unsigned long)GetCurrentProcessId()); fclose(pf); }',
  '    for (int tick = 0; tick < 60; tick++) { Sleep(500); printf("leaf-alive %d\\n", tick); fflush(stdout); }',
  '    return 0;',
  '  }',
  '  if (argc > 1 && strcmp(argv[1], "orphan") == 0) {',
  '    char oexe[MAX_PATH];',
  '    char ocmd[MAX_PATH + 32];',
  '    GetModuleFileNameA(NULL, oexe, MAX_PATH);',
  '    printf("orphan parent in-job=%d\\n", inJob());',
  '    {',
  '      STARTUPINFOA si; PROCESS_INFORMATION pi;',
  '      memset(&si, 0, sizeof si); si.cb = sizeof si;',
  '      si.dwFlags = STARTF_USESTDHANDLES;',
  '      si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError = GetStdHandle(STD_ERROR_HANDLE);',
  '      _snprintf(ocmd, sizeof ocmd - 1, "\\"%s\\" orphan-leaf", oexe); ocmd[sizeof ocmd - 1] = 0;',
  '      if (!CreateProcessA(oexe, ocmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {',
  '        printf("orphan leaf spawn FAILED err=%d\\n", (int)GetLastError()); fflush(stdout); return 1;',
  '      }',
  '      CloseHandle(pi.hThread); CloseHandle(pi.hProcess);',
  '    }',
  '    /* Handshake only: wait until the leaf is verifiably alive (pid file),',
  '     * never for its exit. Returning leaves the leaf in the job after the',
  '     * launcher\'s wait unblocks - the orphan the cleanup must reap. */',
  '    for (int i = 0; i < 40; i++) {',
  '      FILE *check = fopen("leaf-pid.txt", "r");',
  '      if (check) { fclose(check); break; }',
  '      Sleep(50);',
  '    }',
  '    fflush(stdout);',
  '    return 0;',
  '  }',
  '  char exe[MAX_PATH];',
  '  GetModuleFileNameA(NULL, exe, MAX_PATH);',
  '  char cmd[MAX_PATH + 16];',
  '  printf("self in-job=%d\\n", inJob());',
  '  {',
  '    STARTUPINFOA si; PROCESS_INFORMATION pi;',
  '    memset(&si, 0, sizeof si); si.cb = sizeof si;',
  '    si.dwFlags = STARTF_USESTDHANDLES;',
  '    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError = GetStdHandle(STD_ERROR_HANDLE);',
  '    _snprintf(cmd, sizeof cmd - 1, "\\"%s\\" leaf", exe); cmd[sizeof cmd - 1] = 0;',
  '    SetLastError(0);',
  '    if (!CreateProcessA(exe, cmd, NULL, NULL, TRUE, CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi))',
  '      printf("breakaway denied err=%d\\n", (int)GetLastError());',
  '    else { printf("breakaway UNEXPECTED-OK pid=%d\\n", (int)pi.dwProcessId); WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }',
  '  }',
  '  {',
  '    STARTUPINFOA si; PROCESS_INFORMATION pi;',
  '    memset(&si, 0, sizeof si); si.cb = sizeof si;',
  '    si.dwFlags = STARTF_USESTDHANDLES;',
  '    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError = GetStdHandle(STD_ERROR_HANDLE);',
  '    _snprintf(cmd, sizeof cmd - 1, "\\"%s\\" leaf", exe); cmd[sizeof cmd - 1] = 0;',
  '    if (!CreateProcessA(exe, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))',
  '      printf("leaf spawn FAILED err=%d\\n", (int)GetLastError());',
  '    else {',
  '      WaitForSingleObject(pi.hProcess, 10000);',
  '      DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);',
  '      printf("leaf exit=%lu\\n", (unsigned long)code);',
  '      CloseHandle(pi.hThread); CloseHandle(pi.hProcess);',
  '    }',
  '  }',
  '  fflush(stdout);',
  '  return 0;',
  '}',
].join('\n');

async function compileFixture(source, name, extraArgs = []) {
  const dir = await mkdtemp(join(tmpdir(), `dsh-rea-sandbox-${name}-`));
  const built = await compileC({ sourceText: source, workDir: dir, name, extraArgs });
  if (!built.ok) {
    await rm(dir, { recursive: true, force: true });
    throw new Error(`fixture ${name} did not compile: ${built.reason}`);
  }
  return { dir, exePath: built.outPath };
}

test('a sample runs to completion inside the kernel sandbox', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(CRT_FIXTURE, 'sbxcrt');
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-run-'));
  try {
    const trace = await runTrace({ exePath: fixture.exePath, workDir: runDir, timeoutMs: 20_000, sandbox: true });
    assert.equal(trace.ok, true, trace.reason);
    assert.equal(trace.exitCode, 0);
    assert.equal(trace.sandbox?.ran, true);
    assert.equal(trace.sandbox?.jobEnforced, true, `job not enforced: ${JSON.stringify(trace.sandbox)}`);
    // The token is a no-capability AppContainer at low integrity.
    assert.match(trace.stdout, /token is-app-container=1/);
    assert.match(trace.stdout, /token integrity-rid=0x1000/);
    // Neutral identity reaches the sample through the launcher env.
    assert.match(trace.stdout, /env COMPUTERNAME=rea-sandbox USERNAME=analyst/);
    // File writes land in the run directory and are captured by the snapshot.
    assert.match(trace.stdout, /file-write-ok/);
    assert.ok(trace.files.some((file) => file.path === 'sandbox-fixture.txt'), JSON.stringify(trace.files));
    // The launcher's own per-run artifacts (diag/pid: pid/tid/SID differ every
    // run) are harness, not sample behaviour - they must not be scored.
    assert.ok(!trace.files.some((file) => isSandboxHarnessFile(file.path)), JSON.stringify(trace.files));
    // The sample's own pid is masked to [PID] in the captured output (the raw
    // value stays in the structured sandbox record).
    assert.match(trace.stdout, /crt-ok pid=\[PID\]/);
    assert.ok(!trace.stdout.includes(String(trace.sandbox?.pid)), 'the raw pid must not remain in the compared stdout');
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(runDir, { recursive: true, force: true });
  }
});

test('default (sandbox off) keeps the plain spawn path with no sandbox record', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(CRT_FIXTURE, 'sbxplain');
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-plain-'));
  try {
    const trace = await runTrace({ exePath: fixture.exePath, workDir: runDir, timeoutMs: 20_000 });
    assert.equal(trace.ok, true, trace.reason);
    assert.equal(trace.sandbox, undefined);
    // Same binary outside the container: no AppContainer token.
    assert.match(trace.stdout, /token is-app-container=0/);
    assert.ok(!trace.stdout.includes('integrity-rid=0x1000'), 'plain run must not be low integrity');
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(runDir, { recursive: true, force: true });
  }
});

test('kernel deny: 192.0.2.1 is refused by the container (WSAEACCES 10013), host-normal is not', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(NET_FIXTURE, 'sbxnet', ['-lws2_32']);
  // Live loopback listener for the ::1 leg; zero external traffic (192.0.2.1
  // is RFC 5737 TEST-NET, unroutable).
  const accepted = [];
  const server = createServer((socket) => { accepted.push(socket.remoteAddress); socket.on('data', () => {}); socket.end(); });
  await new Promise((resolvePromise) => server.listen(0, '::1', resolvePromise));
  const port = server.address().port;
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-net-'));
  try {
    const inside = await runTrace({ exePath: fixture.exePath, args: [String(port)], workDir: runDir, timeoutMs: 40_000, sandbox: true });
    assert.equal(inside.ok, true, inside.reason);
    assert.equal(inside.sandbox?.ran, true);
    // THE kernelDeny evidence: instant WSAEACCES inside the container.
    const v4 = inside.stdout.match(/net dst=192\.0\.2\.1:9 rc=(-?\d+) err=(\d+) ms=(\d+)/);
    assert.ok(v4, `missing 192.0.2.1 line: ${inside.stdout}`);
    assert.equal(Number(v4[2]), 10013, `expected WSAEACCES 10013, got: ${v4[0]}`);
    assert.equal(Number(v4[3]), 0, `expected an instant deny, got: ${v4[0]}`);
    // Loopback leg: recorded either way. On a non-admin host the container
    // blocks loopback too (timeout), because the CheckNetIsolation exemption
    // is administrator-only (measured err=5) - pinned as a limitation. The
    // invariant that must hold in both worlds: loopback never fails with the
    // internet-deny code.
    const v6 = inside.stdout.match(/net dst=\[::1\]:(\d+) rc=(-?\d+) err=(\d+) ms=(\d+)/);
    assert.ok(v6, `missing ::1 line: ${inside.stdout}`);
    assert.notEqual(Number(v6[3]), 10013, `loopback must not fail with the internet-deny code: ${v6[0]}`);

    // Falsifiable contrast: the same binary OUTSIDE the container on the same
    // host does not get the instant deny (unroutable address times out) and
    // does connect over ::1 - so the 10013 is the container, not the address.
    const hostDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-host-'));
    try {
      const host = await runTrace({ exePath: fixture.exePath, args: [String(port)], workDir: hostDir, timeoutMs: 40_000 });
      assert.equal(host.ok, true, host.reason);
      assert.equal(host.sandbox, undefined);
      const hostV4 = host.stdout.match(/net dst=192\.0\.2\.1:9 rc=(-?\d+) err=(\d+) ms=(\d+)/);
      assert.ok(hostV4, `missing host 192.0.2.1 line: ${host.stdout}`);
      assert.notEqual(Number(hostV4[2]), 10013, `host-normal run must not get the container deny: ${hostV4[0]}`);
      const hostV6 = host.stdout.match(/net dst=\[::1\]:(\d+) rc=(-?\d+) err=(\d+) ms=(\d+)/);
      assert.ok(hostV6, `missing host ::1 line: ${host.stdout}`);
      assert.equal(Number(hostV6[2]), 0, `host-normal ::1 should connect to the live listener: ${hostV6[0]}`);
    } finally {
      await rm(hostDir, { recursive: true, force: true });
    }
  } finally {
    server.close();
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(runDir, { recursive: true, force: true });
  }
});

test('the job locks the tree: in-job membership, breakaway denied, child inherits the job', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(JOB_TREE_FIXTURE, 'sbxtree', ['-lws2_32']);
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-tree-'));
  try {
    const trace = await runTrace({ exePath: fixture.exePath, workDir: runDir, timeoutMs: 30_000, sandbox: true });
    assert.equal(trace.ok, true, trace.reason);
    assert.match(trace.stdout, /self in-job=1/);
    assert.match(trace.stdout, /breakaway denied err=5/);
    assert.match(trace.stdout, /leaf in-job=1/);
    assert.match(trace.stdout, /leaf exit=0/);
    assert.ok(!trace.stdout.includes('UNEXPECTED-OK'), 'breakaway must never succeed');
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(runDir, { recursive: true, force: true });
  }
});

// C-4② fixture: a sample that sleeps long enough that "still alive after the
// poll window" can only be a cleanup failure, never a natural exit.
const SLEEP_LONG_FIXTURE = [
  '#define WIN32_LEAN_AND_MEAN',
  '#include <windows.h>',
  '#include <stdio.h>',
  'int main(void) { printf("kill-on-close sample alive\\n"); fflush(stdout); Sleep(15000); printf("natural exit\\n"); return 0; }',
].join('\n');

// C-0/C-4①: the launcher's wait covers only the direct child. An orphaned
// grandchild must be reaped - deterministically by the launcher's pre-close
// terminate (C-1 fix 2) and by KILL_ON_JOB_CLOSE as the last line of defence.
// The leaf's pid comes from leaf-pid.txt (a file snapshot, not stdout: the
// trace output masks pids). t0 is the diag child-exit line, which the launcher
// writes immediately before exiting - independent of the node stream EOF,
// which an orphan holding the inherited stdout pipe delays.
test('an orphaned grandchild is reaped when the launcher exits, with the cleanup marker in the diag', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(JOB_TREE_FIXTURE, 'sbxorphan', ['-lws2_32']);
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-orphan-'));
  let leafPid = null;
  try {
    const tracePromise = runTrace({ exePath: fixture.exePath, args: ['orphan'], workDir: runDir, timeoutMs: 45_000, sandbox: true });
    const diagPath = join(runDir, 'sandbox-diag.txt');
    let t0 = null;
    const diagDeadline = Date.now() + 60_000;
    while (Date.now() < diagDeadline) {
      let text = '';
      try { text = await readFile(diagPath, 'utf8'); } catch { /* not written yet */ }
      if (/^rea-sandbox: child-exit=/m.test(text)) { t0 = Date.now(); break; }
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 200));
    }
    assert.ok(t0 !== null, 'the launcher never reported child-exit within 60 s');
    const pidDeadline = Date.now() + 3_000;
    while (Date.now() < pidDeadline && leafPid === null) {
      try {
        const text = (await readFile(join(runDir, 'leaf-pid.txt'), 'utf8')).trim();
        if (/^\d+$/.test(text)) leafPid = Number(text);
      } catch { /* handshake not observed yet */ }
      if (leafPid === null) await new Promise((resolveSleep) => setTimeout(resolveSleep, 100));
    }
    assert.ok(leafPid !== null, 'the orphan leaf never completed its startup handshake (leaf-pid.txt missing 3 s after the launcher exit)');
    const timeline = { leafPid, pollStartedAfterLauncherExitMs: Date.now() - t0, aliveChecks: [] };
    let goneAfterMs = null;
    const windowDeadline = Date.now() + 8_000;
    while (Date.now() < windowDeadline) {
      if (!(await pidAliveWithName(leafPid, 'sbxorphan.exe'))) { goneAfterMs = Date.now() - t0; break; }
      timeline.aliveChecks.push(Date.now() - t0);
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 250));
    }
    const trace = await tracePromise;
    // Container-token qualification (ask: does the container token still bind
    // the orphan?): the leaf's own report is taken while the launcher has
    // already exited - a live process keeps its token.
    assert.match(trace.stdout, /leaf in-job=1/);
    assert.match(trace.stdout, /leaf token is-app-container=1/);
    assert.match(trace.stdout, /leaf token integrity-rid=0x1000/);
    // Container-network qualification (C-0, 2026-11-20): the orphan leaf's own
    // fresh connect is kernel-denied with instant WSAEACCES - the token that
    // binds networking is still fully effective on the orphaned process. The
    // reaping below is therefore resource cleanup, never an isolation break.
    assert.match(trace.stdout, /leaf net dst=192\.0\.2\.1:9 rc=-1 err=10013 ms=0/,
      `the orphan leaf must report the container deny itself: ${trace.stdout}`);
    assert.equal(trace.sandbox?.ran, true);
    assert.equal(trace.sandbox?.jobEnforced, true, `job not enforced: ${JSON.stringify(trace.sandbox)}`);
    assert.ok(goneAfterMs !== null && goneAfterMs <= 5_000,
      `REPRO DATA the orphaned leaf must be reaped within 5 s of the launcher exit; timeline=${JSON.stringify({ ...timeline, goneAfterMs, stillAliveAfterMs: goneAfterMs === null ? Date.now() - t0 : null })}`);
    const diagText = await readFile(diagPath, 'utf8');
    assert.match(diagText, /rea-sandbox: action=terminate-job reason=orphan-descendants/, `missing cleanup marker in diag:\n${diagText}`);
  } finally {
    // Best effort only: on a red run the orphan may still be alive and hold
    // the exe/directory locks - the measured assertion must surface, not a
    // cleanup error, and a leftover temp directory is the honest cost.
    if (leafPid !== null && await pidAliveWithName(leafPid, 'sbxorphan.exe')) {
      try { spawn('taskkill', ['/pid', String(leafPid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' }); await new Promise((resolveSleep) => setTimeout(resolveSleep, 500)); } catch { /* best effort */ }
    }
    await rm(fixture.dir, { recursive: true, force: true }).catch(() => {});
    await rm(runDir, { recursive: true, force: true }).catch(() => {});
  }
});

// C-4②: re-qualification of the "KILL_ON_JOB_CLOSE is unreliable on this
// build" narrative (measured 2026-11-19). Root cause found in the launcher
// source: JOBOBJECT_EXTENDED_LIMIT_INFORMATION was passed zero-initialised -
// LimitFlags was never assigned, so the flag was never enabled and the
// 2026-11-19 measurement described a mechanism that did not exist. With the
// flag actually set, killing ONLY the launcher (taskkill /F, no /T - the
// sample must survive the kill itself) closes the last job handle and the
// kernel reaps the tree.
test('killing the launcher externally reaps the job tree (KILL_ON_JOB_CLOSE actually enabled)', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(SLEEP_LONG_FIXTURE, 'sbxkill');
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-kill-'));
  let samplePid = null;
  try {
    const launcher = spawn('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', SANDBOX_LAUNCHER,
      '-Executable', fixture.exePath,
      '-Arguments', '',
      '-WorkDir', runDir,
      '-DiagFile', join(runDir, 'sandbox-diag.txt'),
      '-OutPid', join(runDir, 'sandbox-pid.txt'),
      '-TimeoutMs', '60000',
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const pidDeadline = Date.now() + 20_000;
    while (Date.now() < pidDeadline && samplePid === null) {
      try {
        const text = (await readFile(join(runDir, 'sandbox-pid.txt'), 'utf8')).trim();
        if (/^\d+$/.test(text)) samplePid = Number(text);
      } catch { /* launcher has not created the child yet */ }
      if (samplePid === null) await new Promise((resolveSleep) => setTimeout(resolveSleep, 150));
    }
    assert.ok(samplePid !== null, 'the launcher never wrote sandbox-pid.txt within 20 s');
    let diagText = '';
    const diagDeadline = Date.now() + 10_000;
    while (Date.now() < diagDeadline) {
      try { diagText = await readFile(join(runDir, 'sandbox-diag.txt'), 'utf8'); } catch { /* not yet */ }
      if (/^rea-sandbox: job-enforced=true$/m.test(diagText)) break;
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 150));
    }
    assert.match(diagText, /rea-sandbox: job-enforced=true/, `the job was never enforced before the external kill:\n${diagText}`);
    // In-situ proof the flag is really enabled (C-1 root cause: the pre-fix
    // launcher passed a zero-initialised limit struct, so the OS job carried
    // LimitFlags=0). The launcher now reads the limits back after
    // SetInformationJobObject and prints them.
    assert.match(diagText, /rea-sandbox: job-limit-flags=0x2000/, `KILL_ON_JOB_CLOSE was never set in the OS job object:\n${diagText}`);
    assert.ok(await pidAliveWithName(samplePid, 'sbxkill.exe'), 'the sample must be alive right before the launcher kill');
    // Kill ONLY the launcher process: no /T, so the sample survives the kill
    // itself and whatever reaps it next is the kernel job cleanup.
    await new Promise((resolveKill) => {
      const killer = spawn('taskkill', ['/pid', String(launcher.pid), '/f'], { windowsHide: true, stdio: 'ignore' });
      killer.on('close', resolveKill);
      killer.on('error', resolveKill);
    });
    const t0 = Date.now();
    let goneAfterMs = null;
    const windowDeadline = Date.now() + 8_000;
    while (Date.now() < windowDeadline) {
      if (!(await pidAliveWithName(samplePid, 'sbxkill.exe'))) { goneAfterMs = Date.now() - t0; break; }
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 250));
    }
    assert.ok(goneAfterMs !== null && goneAfterMs <= 5_000,
      `REPRO DATA the job tree must be reaped by the kernel within 5 s of the launcher kill; measured=${JSON.stringify({ samplePid, goneAfterMs, stillAliveAfterMs: goneAfterMs === null ? Date.now() - t0 : null })}`);
  } finally {
    // Best effort only: on a red run the sample is still alive and holds the
    // exe/directory locks - the measured assertion must surface, not a
    // cleanup error, and a leftover temp directory is the honest cost.
    if (samplePid !== null && await pidAliveWithName(samplePid, 'sbxkill.exe')) {
      try { spawn('taskkill', ['/pid', String(samplePid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' }); await new Promise((resolveSleep) => setTimeout(resolveSleep, 500)); } catch { /* best effort */ }
    }
    await rm(fixture.dir, { recursive: true, force: true }).catch(() => {});
    await rm(runDir, { recursive: true, force: true }).catch(() => {});
  }
});

test('the watchdog terminates a runaway sample (timeout is a result, not an error)', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(CRT_FIXTURE, 'sbxsleep');
  const runDir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-sleep-'));
  try {
    const trace = await runTrace({ exePath: fixture.exePath, args: ['sleep'], workDir: runDir, timeoutMs: 2_500, sandbox: true });
    assert.equal(trace.ok, false);
    assert.equal(trace.timedOut, true);
    assert.equal(trace.sandbox?.ran, true, 'the sample DID start - a watchdog kill is a result');
    assert.equal(trace.sandbox?.timedOut, true);
    assert.match(trace.stdout, /sleeping/);
    assert.ok(!trace.stdout.includes('woke'), 'the watchdog must have terminated the job before the 6 s sleep ended');
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(runDir, { recursive: true, force: true });
  }
});

test('a launch failure is fail-closed: no sample, no fallback', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-miss-'));
  try {
    const outcome = await startSandboxed({ exe: join(dir, 'does-not-exist.exe'), workDir: dir, timeoutMs: 5_000 });
    assert.equal(outcome.ran, false);
    assert.equal(outcome.ok, false);
    assert.ok(outcome.reason && outcome.reason.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- tool-level gate: sandbox=true is its own opt-in, never implied ----

test('every execution tool refuses sandbox=true without sandboxSampleExecution', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-gate-'));
  try {
    const store = createArtifactStore({ root: join(dir, 'artifacts'), base: dir });
    const exe = join(dir, 'whatever.exe');
    await writeFile(exe, 'MZ-nope');
    const config = { allowSampleExecution: true };
    const trace = buildTraceBehaviorTool({ config, store });
    assert.match((await trace.execute({ target: exe, rebuilt: exe, confirm: true, sandbox: true })).text, /sandbox=true requires sandboxSampleExecution=true/);
    const observe = buildSideEffectsTool({ config, store });
    assert.match((await observe.execute({ target: exe, rebuilt: exe, confirm: true, sandbox: true })).text, /sandbox=true requires sandboxSampleExecution=true/);
    const dump = buildMemoryDumpTool({ config, store });
    assert.match((await dump.execute({ target: exe, output: join(dir, 'out.exe'), confirm: true, sandbox: true })).text, /sandbox=true requires sandboxSampleExecution=true/);
    const probe = buildDynamicProbeTool({ config, store });
    assert.match((await probe.execute({ target: exe, breakRva: '0x1000', confirm: true, sandbox: true })).text, /sandbox=true requires sandboxSampleExecution=true/);
    // absent sandbox flag stays on the documented user-mode path (node itself
    // as the "sample": a real executable, so the plain spawn path runs)
    const plain = await trace.execute({ target: process.execPath, rebuilt: process.execPath, confirm: true });
    assert.doesNotMatch(plain.text, /sandboxSampleExecution/);
    assert.doesNotMatch(plain.text, /containment: kernel-enforced/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the trace tool runs both binaries inside the kernel sandbox when enabled', { skip: IS_WIN ? false : 'sandbox launcher is Windows-only' }, async () => {
  const fixture = await compileFixture(CRT_FIXTURE, 'sbxtool');
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-sandbox-tool-'));
  try {
    const store = createArtifactStore({ root: join(dir, 'artifacts'), base: dir });
    const tool = buildTraceBehaviorTool({ config: { allowSampleExecution: true, sandboxSampleExecution: true }, store });
    const result = await tool.execute({ target: fixture.exePath, rebuilt: fixture.exePath, confirm: true, sandbox: true, timeoutMs: 20_000 });
    assert.match(result.text, /containment: kernel-enforced sandbox/);
    assert.match(result.text, /ran=true \(job enforced=true\)/);
    // Harness artifacts (diag/pid) are excluded from the file snapshot, so two
    // runs of the same binary keep full parity (measured 62.5% before the fix).
    assert.match(result.text, /runtime behaviour: 100\.0%/);
    // The limitations must not contradict the containment line above.
    assert.doesNotMatch(result.text, /There is no sandbox/);
    assert.match(result.text, /kernel-enforced sandbox \(no-capability AppContainer/);
  } finally {
    await rm(fixture.dir, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});
