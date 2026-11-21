import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildReadiness, compileC } from '../lib/build.js';
import { dynamicReadiness } from '../lib/dynamic.js';
import { buildMemoryDumpTool } from '../lib/memdump-tools.js';
import { parseImageLayout, rebuildImageFromMemory } from '../lib/memdump.js';

const DUMP_HELPER = fileURLToPath(new URL('../scripts/dynamic/dump.py', import.meta.url));

// The helper installs kernel32 VirtualAlloc/VirtualProtect plus ntdll
// NtAllocateVirtualMemory/NtProtectVirtualMemory EXECUTE-marking hooks in the
// agent. With the VirtualAlloc hook installed, a spawned sample can stay alive
// indefinitely and stop answering (the measured failure mode documented in the
// helper's header), which masks the death report. The death-path test drives a
// test-local variant of the helper with the VirtualAlloc hook AND both ntdll
// hooks removed (same trigger family since W2) - the hooks are the trigger,
// the rest of the helper (resume, deadline, process_gone, death report) runs
// exactly as shipped.
const EXEC_HOOK_PATTERN = / {4}try \{\r?\n {6}const \w+ = findExport\('(?:VirtualAlloc|NtAllocateVirtualMemory|NtProtectVirtualMemory)'\);[\s\S]*?\} catch \(error\) \{ send\(\{ event: 'hook-error', error: '(?:VirtualAlloc|NtAllocateVirtualMemory|NtProtectVirtualMemory): ' \+ String\(error\) \}\); \}/g;
// Only the ntdll layer (W2): used to pin the pre-W2 blind spot - a packer that
// marks memory through direct ntdll calls produces NO exec-mark without it.
const NTDLL_HOOK_PATTERN = / {4}try \{\r?\n {6}const \w+ = findExport\('(?:NtAllocateVirtualMemory|NtProtectVirtualMemory)'\);[\s\S]*?\} catch \(error\) \{ send\(\{ event: 'hook-error', error: '(?:NtAllocateVirtualMemory|NtProtectVirtualMemory): ' \+ String\(error\) \}\); \}/g;

/** A minimal PE with two sections and an image-layout-friendly header. */
function samplePE() {
  const b = Buffer.alloc(0x400);
  b.fill(0x11);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  const coff = 0x84;
  b.writeUInt16LE(2, coff + 2);
  b.writeUInt16LE(0xe0, coff + 16);
  const opt = 0x98;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt32LE(0x1000, opt + 16);
  b.writeUInt32LE(0x1000, opt + 32);
  b.writeUInt32LE(0x200, opt + 36);
  b.writeUInt32LE(0x3000, opt + 56);
  b.writeUInt32LE(0x400, opt + 60);
  const table = opt + 0xe0;
  const section = (index, name, virtualAddress, virtualSize, rawSize, rawPointer) => {
    const at = table + index * 40;
    b.write(name, at, 'latin1');
    b.writeUInt32LE(virtualSize, at + 8);
    b.writeUInt32LE(virtualAddress, at + 12);
    b.writeUInt32LE(rawSize, at + 16);
    b.writeUInt32LE(rawPointer, at + 20);
  };
  section(0, '.text', 0x1000, 0x500, 0x200, 0x200);
  section(1, '.rdata', 0x2000, 0x300, 0x200, 0x400);
  return b;
}

test('a memory image is rebuilt into an image-layout PE with section offsets equal to RVAs', () => {
  const disk = samplePE();
  const memory = Buffer.alloc(0x3000, 0xaa);
  memory.write('CODE', 0x1000, 'latin1');
  memory.write('DATA', 0x2000, 'latin1');
  const rebuilt = rebuildImageFromMemory({ diskBuffer: disk, memoryBuffer: memory });
  assert.equal(rebuilt.ok, true, rebuilt.reason);
  assert.equal(rebuilt.buffer.length, 0x3000);
  assert.equal(rebuilt.buffer.toString('latin1', 0, 2), 'MZ');
  assert.equal(rebuilt.buffer.toString('latin1', 0x1000, 0x1004), 'CODE');
  assert.equal(rebuilt.buffer.toString('latin1', 0x2000, 0x2004), 'DATA');
  const layout = parseImageLayout(rebuilt.buffer);
  assert.equal(layout.sections[0].pointerToRawData, 0x1000);
  assert.equal(layout.sections[1].pointerToRawData, 0x2000);
  assert.equal(layout.fileAlignment, 0x1000, 'file alignment follows section alignment');
});

test('a non-PE or an empty dump is refused with a reason, not a broken file', () => {
  const rebuilt = rebuildImageFromMemory({ diskBuffer: Buffer.from('not a pe'), memoryBuffer: Buffer.alloc(16) });
  assert.equal(rebuilt.ok, false);
  assert.match(rebuilt.reason, /not a PE/);
  const empty = rebuildImageFromMemory({ diskBuffer: samplePE(), memoryBuffer: Buffer.alloc(0) });
  assert.equal(empty.ok, false);
  assert.match(empty.reason, /empty/);
});

test('the memory dump tool is gated and refuses to clobber an existing output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-dump-'));
  try {
    const target = join(dir, 'sample.exe');
    const output = join(dir, 'out.exe');
    await writeFile(target, samplePE());
    await writeFile(output, 'existing');
    const disabled = buildMemoryDumpTool({ config: {} });
    assert.match((await disabled.execute({ target, output, confirm: true })).text, /sample execution is disabled/);
    const unconfirmed = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    assert.match((await unconfirmed.execute({ target, output, confirm: false })).text, /confirm must be true/);
    const enabled = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    assert.match((await enabled.execute({ target, output, confirm: true })).text, /already exists/);
    assert.equal(await readFile(output, 'utf8'), 'existing');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a real process can be dumped at its entry point and the rebuilt image parses', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-dump-'));
  try {
    const source = join(dir, 'sample.c');
    await writeFile(source, '#include <stdio.h>\nint main(void) { printf("REA_MEMORY_MARKER\\n"); return 0; }\n', 'utf8');
    const built = await compileC({ sourceText: await readFile(source, 'utf8'), workDir: join(dir, 'build'), name: 'sample' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    const answer = await tool.execute({ target: built.outPath, output, confirm: true, delayMs: 0, timeoutMs: 60_000 });
    assert.match(answer.text, /memory image/);
    assert.equal(existsSync(output), true);
    const layout = parseImageLayout(await readFile(output));
    assert.ok(layout.sections.length >= 1);
    assert.match(answer.text, /imports, \d+ strings/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('waitForExec dumps after the sample marks memory executable and reports entry as none when control flow never enters', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-'));
  try {
    const source = [
      '#include <windows.h>',
      'int main(void) {',
      '  unsigned char *code = (unsigned char *)VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);',
      '  if (code) { code[0] = 0x90; code[1] = 0xC3; }',
      '  for (;;) { Sleep(100); }',
      '  return 0;',
      '}',
    ].join('\n');
    const built = await compileC({ sourceText: source, workDir: join(dir, 'build'), name: 'oep' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    // Same spawn-instability guard as the watch tests (plan §13 residual: this
    // no-mark variant lacked the bounded retry until 2026-11-21, and the flake
    // did hit it once in the full suite). A clean run always produces an image
    // and 'entry: none', so the environmental early-death signature can never
    // masquerade as a pass.
    const answer = await executeDumpWithRetry(tool, {
      target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 8_000,
    });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /waited for an executable memory marking/);
    assert.match(answer.text, /oep signal: VirtualAlloc 0x[0-9a-f]+/i);
    assert.match(answer.text, /entry: none before the timeout/);
    assert.doesNotMatch(answer.text, /control flow entered/);
    assert.equal(existsSync(output), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('waitForExec reports the exec-entry hit when control flow enters the marked region', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-'));
  try {
    // Allocates RWX, writes a 38-byte trampoline into it, calls into it, and
    // sleeps. The trampoline writes "REA_OEP_EXEC" through an absolute
    // address (movabs rax,<g_marker>) into .bss, so the dumped image only
    // contains the marker if control flow really entered and executed the
    // trampoline - exactly the evidence the report is asked for.
    const source = [
      '#include <windows.h>',
      '#include <stdint.h>',
      '',
      'static volatile unsigned char g_marker[32];',
      '',
      'int main(void) {',
      '  unsigned char *code = (unsigned char *)VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);',
      '  if (!code) return 1;',
      '  /* movabs rax,<g_marker>; movabs rcx,"REA_OEP_"; mov [rax],rcx;',
      '     movabs rcx,"EXEC"+NULs; mov [rax+8],rcx; ret  (38 bytes) */',
      '  unsigned char trampoline[38] = {',
      '    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,',
      '    0x48, 0xB9, 0x52, 0x45, 0x41, 0x5F, 0x4F, 0x45, 0x50, 0x5F,',
      '    0x48, 0x89, 0x08,',
      '    0x48, 0xB9, 0x45, 0x58, 0x45, 0x43, 0x00, 0x00, 0x00, 0x00,',
      '    0x48, 0x89, 0x48, 0x08,',
      '    0xC3',
      '  };',
      '  unsigned long long markerAddress = (unsigned long long)(uintptr_t)g_marker;',
      '  int i;',
      '  for (i = 0; i < 8; i++) trampoline[2 + i] = (unsigned char)((markerAddress >> (8 * i)) & 0xFF);',
      '  for (i = 0; i < 38; i++) code[i] = trampoline[i];',
      '  ((void (*)(void))code)();',
      '  for (;;) { Sleep(100); }',
      '  return 0;',
      '}',
    ].join('\n');
    const built = await compileC({ sourceText: source, workDir: join(dir, 'build'), name: 'oepjump' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    const answer = await executeDumpWithRetry(tool, {
      target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 30_000,
    });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /waited for an executable memory marking/);
    assert.match(answer.text, /oep signal: VirtualAlloc 0x[0-9a-f]+/i);
    assert.match(answer.text, /entry: control flow entered the marked region/);
    assert.match(answer.text, /inside main module: no/);
    assert.match(answer.text, /movabs/);
    assert.match(answer.text, /48 b8/);
    assert.equal(existsSync(output), true);
    // The dump contains the string only the trampoline could have written.
    const rebuilt = await readFile(output);
    assert.ok(rebuilt.indexOf('REA_OEP_EXEC') >= 0, 'the trampoline marker is missing from the rebuilt image');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('waitForExec reports the explicit no-mark variant for a sample that never marks memory', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-'));
  try {
    // Sleeps forever and never calls VirtualAlloc/VirtualProtect: no
    // executable marking can fire, so the sample must survive to the deadline,
    // the dump must still happen, and the report must use the no-mark entry
    // variant (not the marked-but-never-entered one, not a hit).
    const source = [
      '#include <windows.h>',
      'int main(void) {',
      '  for (;;) { Sleep(100); }',
      '  return 0;',
      '}',
    ].join('\n');
    const built = await compileC({ sourceText: source, workDir: join(dir, 'build'), name: 'nomark' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true } });
    // Same spawn-instability guard as the watch tests (plan §13 residual: this
    // no-mark variant lacked the bounded retry until 2026-11-21, and the flake
    // did hit it once in the full suite). A clean run always produces an image
    // and 'entry: none', so the environmental early-death signature can never
    // masquerade as a pass.
    const answer = await executeDumpWithRetry(tool, {
      target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 8_000,
    });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /waited for an executable memory marking/);
    assert.match(answer.text, /oep signal: none before the timeout/);
    assert.match(answer.text, /entry: none before the timeout - no executable memory marking was observed/);
    assert.doesNotMatch(answer.text, /control flow was never observed in the marked region/);
    assert.doesNotMatch(answer.text, /control flow entered/);
    assert.equal(existsSync(output), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a process that dies before the dump deadline fails with the explicit no-image reason', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-die-'));
  try {
    // Drive the helper directly on a sample that exits long before the
    // deadline: the image is gone with the process, so the helper must report
    // what was and was not observed instead of a generic timeout. where.exe
    // with no arguments prints its usage and exits immediately.
    const helperSource = await readFile(DUMP_HELPER, 'utf8');
    const patched = helperSource.replace(
      EXEC_HOOK_PATTERN,
      '    /* EXECUTE-marking hooks removed by the test: the kernel32 VirtualAlloc and ntdll NtAllocate/NtProtectVirtualMemory hooks can keep a spawned sample alive (the failure mode documented in the helper header), which would mask the death report this test pins. */',
    );
    assert.notEqual(patched, helperSource, 'the EXECUTE-marking hook blocks were not found in the dump helper');
    const variant = join(dir, 'dump-noalloc-hook.py');
    await writeFile(variant, patched, 'utf8');
    const where = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'where.exe');
    const raw = join(dir, 'gone.raw');
    const run = spawnSync(readiness.command, [
      ...readiness.args, variant, where, raw, '40960', '0', '8000', '1',
    ], { encoding: 'utf8', timeout: 60_000, windowsHide: true });
    assert.equal(run.error, undefined, `the helper run was interrupted: ${run.error}`);
    assert.equal(run.status, 0, `helper exit ${run.status}: ${run.stderr?.slice(-300)}`);
    const line = run.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
    const answer = JSON.parse(line);
    assert.equal(answer.ok, undefined, `the helper reported success where a death report was due: ${line}`);
    assert.match(answer.error, /the process exited before the dump/);
    assert.match(answer.error, /process-terminated/);
    assert.match(answer.error, /no exec-mark observed/);
    assert.match(answer.error, /entry: none/);
    assert.deepEqual(answer.warnings, []);
    assert.equal(existsSync(raw), false, 'no image may be written for a process that died before the dump');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- W1 (2026-11-20): process-wide exec-mark watch ---------------------------------

// The multithreaded spawn path is environment-sensitive (measured 2026-11-20:
// the fixture dies under Frida spawn on some runs even with ZERO hooks
// installed - a Frida-layer instability, not a hook or plugin effect; the same
// source runs fine without Frida). The live assertions below therefore allow
// up to 3 attempts and, when every attempt died this way, SKIP with the
// environmental reason instead of failing: the early-death signatures below
// prove the sample died BEFORE any exec-mark, so the watch was never
// exercised - a broken watch cannot produce them (a clean run always marks
// first and would report 'entry: none', which fails the assertions).
const ENVIRONMENTAL_DEATH = /no image — (?:the process exited before the dump|no dump before the timeout)/;

async function executeDumpWithRetry(tool, input, attempts = 3) {
  let last = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const answer = await tool.execute(input);
    if (!ENVIRONMENTAL_DEATH.test(answer.text)) {
      return answer;
    }
    last = answer;
  }
  return last;
}

// Skip guard for the tool-driven live tests: every retry hit the environmental
// early-death signature, so the environment - not the watch - decided the run.
function skipIfEnvironmentalDeath(t, answer) {
  if (ENVIRONMENTAL_DEATH.test(answer.text)) {
    t.skip(`environment: the sample died under Frida spawn before any exec-mark in every attempt, so the watch was never exercised - ${answer.text.slice(0, 140)}`);
    return true;
  }
  return false;
}

// The exec-mark fires in a worker thread (its VirtualAlloc) while the MAIN
// thread is the one that jumps into the marked region - exactly the
// "marking thread != executing thread" scenario the single-thread Stalker
// watch used to miss (oep signal present, entry: none). The process-wide
// watch (mark-time threads + post-mark NtCreateThreadEx threads, capped) must
// catch the entry on the executing thread.

const MULTITHREAD_MARK_FIXTURE = [
  '#include <windows.h>',
  '#include <stdint.h>',
  '',
  'static HANDLE g_events[2];',
  'static unsigned char *g_code[2];',
  '',
  'static DWORD WINAPI worker(LPVOID param) {',
  '  int idx = (int)(intptr_t)param;',
  '  unsigned char *code = (unsigned char *)VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);',
  '  if (!code) return 1;',
  '  /* mov eax, 0x60+idx; ret - the stub main will call cross-thread */',
  '  code[0] = 0xB8; code[1] = (unsigned char)(0x60 + idx); code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; code[5] = 0xC3;',
  '  g_code[idx] = code;',
  '  SetEvent(g_events[idx]);',
  '  return 0;',
  '}',
  '',
  'int main(void) {',
  '  g_events[0] = CreateEventW(NULL, FALSE, FALSE, NULL);',
  '  g_events[1] = CreateEventW(NULL, FALSE, FALSE, NULL);',
  '  CreateThread(NULL, 0, worker, (LPVOID)0, 0, NULL);',
  '  CreateThread(NULL, 0, worker, (LPVOID)1, 0, NULL);',
  '  WaitForMultipleObjects(2, g_events, TRUE, 5000);',
  '  /* the workers marked; main executes - the pre-fix blind spot */',
  '  if (g_code[0]) ((void (*)(void))g_code[0])();',
  '  if (g_code[1]) ((void (*)(void))g_code[1])();',
  '  for (;;) { Sleep(100); }',
  '  return 0;',
  '}',
].join('\n');

// Control: the marking thread (a worker, not main) also executes its own
// region - the case the old single-thread watch already covered. Keeps the
// new process-wide watch from regressing the covered case.
const WORKER_SELF_EXEC_FIXTURE = [
  '#include <windows.h>',
  '',
  'static HANDLE g_done;',
  '',
  'static DWORD WINAPI worker(LPVOID param) {',
  '  (void)param;',
  '  unsigned char *code = (unsigned char *)VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);',
  '  if (!code) { SetEvent(g_done); return 1; }',
  '  code[0] = 0xB8; code[1] = 0x60; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; code[5] = 0xC3;',
  '  ((void (*)(void))code)();',
  '  SetEvent(g_done);',
  '  for (;;) { Sleep(100); }',
  '  return 0;',
  '}',
  '',
  'int main(void) {',
  '  g_done = CreateEventW(NULL, FALSE, FALSE, NULL);',
  '  CreateThread(NULL, 0, worker, NULL, 0, NULL);',
  '  WaitForSingleObject(g_done, 5000);',
  '  for (;;) { Sleep(100); }',
  '  return 0;',
  '}',
].join('\n');

test('the process-wide watch catches the entry when a worker marks and the main thread executes', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-mt-'));
  try {
    const built = await compileC({ sourceText: MULTITHREAD_MARK_FIXTURE, workDir: join(dir, 'build'), name: 'oepmt' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    let saved = null;
    const store = { async write(name, body) { saved = JSON.parse(body); return join(dir, name); } };
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true }, store });
    const answer = await executeDumpWithRetry(tool, { target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 8_000 });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /waited for an executable memory marking/);
    assert.match(answer.text, /oep signal: VirtualAlloc 0x[0-9a-f]+/i);
    assert.match(answer.text, /entry: control flow entered the marked region/);
    assert.equal(existsSync(output), true);
    // Process-wide evidence from the helper's structured record: the hitting
    // thread (main) must be inside the followed set, and the mark-time watch
    // must have covered main plus both workers (plus any agent threads).
    assert.equal(saved.oepSignal.kind, 'VirtualAlloc');
    assert.equal(saved.execEntry.inRegion, true);
    assert.ok(Number.isInteger(saved.execEntry.threadId) && saved.execEntry.threadId > 0,
      `the hitting thread must be reported: ${JSON.stringify(saved.execEntry)}`);
    assert.ok(Array.isArray(saved.watchThreads) && saved.watchThreads.includes(saved.execEntry.threadId),
      `the hitting thread must be in the followed set: watchThreads=${JSON.stringify(saved.watchThreads)} hit=${saved.execEntry.threadId}`);
    assert.ok(saved.followedCount >= 3,
      `main + two workers must be followed at mark time, got followedCount=${saved.followedCount}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a worker that marks and executes its own region still hits (single-thread control)', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-wt-'));
  try {
    const built = await compileC({ sourceText: WORKER_SELF_EXEC_FIXTURE, workDir: join(dir, 'build'), name: 'oepwt' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    let saved = null;
    const store = { async write(name, body) { saved = JSON.parse(body); return join(dir, name); } };
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true }, store });
    const answer = await executeDumpWithRetry(tool, { target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 8_000 });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /oep signal: VirtualAlloc 0x[0-9a-f]+/i);
    assert.match(answer.text, /entry: control flow entered the marked region/);
    assert.equal(existsSync(output), true);
    assert.equal(saved.oepSignal.kind, 'VirtualAlloc');
    assert.equal(saved.execEntry.inRegion, true);
    assert.ok(Array.isArray(saved.watchThreads) && saved.watchThreads.includes(saved.execEntry.threadId),
      `the executing worker must be in the followed set: ${JSON.stringify(saved.watchThreads)}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- W2 (2026-11-20): ntdll-layer exec-mark hooks ----------------------------------
// A packer that resolves NtAllocateVirtualMemory/NtProtectVirtualMemory via
// GetProcAddress (or calls the exports directly) never touches the kernel32
// hooks - pre-W2 this fixture produced NO exec-mark at all. The ntdll hooks
// share the note() pathway with layer='ntdll'; source attribution keeps
// kernel32 callers booked by the kernel32 layer (kind stays VirtualAlloc),
// and shellcode issuing the syscalls directly (no ntdll export) remains a
// declared blind spot.
const NTDLL_DIRECT_FIXTURE = [
  '#include <windows.h>',
  '#include <stdio.h>',
  '',
  'typedef long NTSTATUS;',
  'typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);',
  'typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);',
  '',
  'int main(void) {',
  '  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");',
  '  if (!ntdll) return 1;',
  '  PFN_NtAllocateVirtualMemory pAlloc = (PFN_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");',
  '  PFN_NtProtectVirtualMemory pProtect = (PFN_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");',
  '  if (!pAlloc || !pProtect) return 1;',
  '  PVOID base = NULL;',
  '  SIZE_T size = 4096;',
  '  NTSTATUS st = pAlloc(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);',
  '  if (st != 0 || !base) return 1;',
  '  unsigned char *code = (unsigned char *)base;',
  '  code[0] = 0xB8; code[1] = 0x60; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; code[5] = 0xC3;',
  '  ULONG oldProtect = 0;',
  '  st = pProtect(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, &oldProtect);',
  '  if (st != 0) return 1;',
  '  ((void (*)(void))code)();',
  '  for (;;) { Sleep(100); }',
  '  return 0;',
  '}',
].join('\n');

// The blind-spot pin: the helper variant has ONLY the ntdll hooks stripped
// (kernel32 hooks stay). No hook ever fires for this fixture, so the wait
// deadline expires with no mark and the dump still happens - the pre-W2
// behaviour, kept as a permanent negative control. The sample stays resident
// on purpose: the measured kernel32!VirtualAlloc exit deadlock (plan §13 T3)
// can turn an exiting sample into a generic "no dump before the timeout", so
// pinning the death-report variant would race the sample's exit; the resident
// sample makes the explicit no-mark report deterministic.
test('without the ntdll hook layer a direct-ntdll marker produces no exec-mark at all', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-ntdll-red-'));
  try {
    const built = await compileC({ sourceText: NTDLL_DIRECT_FIXTURE, workDir: join(dir, 'build'), name: 'oepntdllred' });
    assert.equal(built.ok, true, built.reason);
    const helperSource = await readFile(DUMP_HELPER, 'utf8');
    const patched = helperSource.replace(
      NTDLL_HOOK_PATTERN,
      '    /* ntdll hook removed by the test: pins the pre-W2 blind spot (direct-ntdll markers were invisible). */',
    );
    assert.notEqual(patched, helperSource, 'the ntdll hook blocks were not found in the dump helper');
    const variant = join(dir, 'dump-ntdll-stripped.py');
    await writeFile(variant, patched, 'utf8');
    const sizeOfImage = parseImageLayout(await readFile(built.outPath)).sizeOfImage;
    const raw = join(dir, 'nomark.raw');
    const run = spawnSync(readiness.command, [
      ...readiness.args, variant, built.outPath, raw, String(sizeOfImage), '0', '8000', '1',
    ], { encoding: 'utf8', timeout: 120_000, windowsHide: true });
    assert.equal(run.error, undefined, `the helper run was interrupted: ${run.error}`);
    assert.equal(run.status, 0, `helper exit ${run.status}: ${run.stderr?.slice(-300)}`);
    const line = run.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
    const answer = JSON.parse(line);
    if (typeof answer.error === 'string' && /the process exited before the dump|no dump before the timeout/.test(answer.error)) {
      t.skip(`environment: the sample died under Frida spawn before any exec-mark - the watch was never exercised (${answer.error.slice(0, 140)})`);
      return;
    }
    // The stable no-mark variant: the wait deadline expires, the dump still
    // happens, and the structured report states that no executable marking
    // was observed at all (oepSignal/execEntry both explicitly null).
    assert.equal(answer.ok, true, `the stripped helper did not produce the explicit no-mark report: ${line}`);
    assert.equal(answer.oepSignal, null);
    assert.equal(answer.execEntry, null);
    assert.equal(answer.entryWatch, 'armed');
    assert.deepEqual(answer.warnings, []);
    assert.equal(existsSync(raw), true, 'the image must still be dumped for the no-mark report');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a packer that marks memory by calling ntdll directly gets an ntdll-layer exec-mark and entry', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-oep-ntdll-'));
  try {
    const built = await compileC({ sourceText: NTDLL_DIRECT_FIXTURE, workDir: join(dir, 'build'), name: 'oepntdll' });
    assert.equal(built.ok, true, built.reason);
    const output = join(dir, 'dumped.exe');
    let saved = null;
    const store = { async write(name, body) { saved = JSON.parse(body); return join(dir, name); } };
    const tool = buildMemoryDumpTool({ config: { allowSampleExecution: true }, store });
    const answer = await executeDumpWithRetry(tool, { target: built.outPath, output, confirm: true, waitForExec: true, timeoutMs: 8_000 });
    if (skipIfEnvironmentalDeath(t, answer)) return;
    assert.match(answer.text, /waited for an executable memory marking/);
    // The mark comes from the ntdll layer - the kernel32 hooks never see this
    // sample's allocation/protection calls (pre-W2: no mark at all).
    assert.match(answer.text, /oep signal: (NtProtectVirtualMemory|NtAllocateVirtualMemory) 0x[0-9a-f]+/i);
    assert.match(answer.text, /entry: control flow entered the marked region/);
    assert.equal(existsSync(output), true);
    assert.equal(saved.oepSignal.layer, 'ntdll');
    assert.equal(saved.execEntry.inRegion, true);
    assert.equal(saved.execEntry.insideMainModule, false);
    // Double-gate proof: the recorded mark is the sample's own page and the
    // ntdll hook (not the kernel32 layer) reported it. The helper's raw JSON
    // for this fixture (measured in the W2 A/B, warnings=[]) shows no agent
    // page stole the mark and no duplicate fired.
    assert.match(saved.oepSignal.kind, /^Nt(Allocate|Protect)VirtualMemory$/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
