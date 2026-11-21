/**
 * Rebuild a PE file from a running process's memory image.
 *
 * Packers decrypt code into memory and leave the on-disk file carrying the stub.
 * A memory image of the main module therefore contains the code the loader
 * actually runs. It is not a file yet: the section headers still point at the
 * on-disk layout. This module patches them into an image-layout PE (raw offset
 * equals virtual address, file alignment equals section alignment) so the
 * plugin's own parsers and Ghidra can read it.
 *
 * The OEP evidence is two-level, and neither level alone is the OEP: an
 * "oep signal" is a page-or-larger executable memory marking seen through
 * kernel32-level hooks, and an "entry" additionally reports the address and
 * instruction where control flow was first observed inside the marked region
 * (waitForExec only, Stalker across the process's threads: the marking thread,
 * every thread alive at the mark, and post-mark thread creations - capped, so
 * coverage can be partial). Neither level names the
 * original entry point with certainty; the report states what was and was not
 * observed and leaves the judgement to the analyst.
 *
 * @module dsh-rea/lib/memdump
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { parsePEImports } from './intel.js';
import { PLUGIN_ROOT } from './paths.js';
import { launchSandboxed } from './sandbox.js';
import { readPeLayout } from './structure.js';
import { extractStrings } from './triage.js';

const HELPER = join(PLUGIN_ROOT, 'scripts', 'dynamic', 'dump.py');
const MAX_IMAGE = 128 * 1024 * 1024;
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
    // Best effort: the timeout result is what matters.
  }
}

/** Parse the PE fields a memory rebuild needs, or null for a non-PE. */
export function parseImageLayout(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x40) return null;
  if (buffer.toString('latin1', 0, 2) !== 'MZ') return null;
  const pe = buffer.readUInt32LE(0x3c);
  if (pe + 24 > buffer.length || buffer.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
  const coff = pe + 4;
  const sectionCount = buffer.readUInt16LE(coff + 2);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  const optional = coff + 20;
  if (optional + optionalSize > buffer.length) return null;
  const magic = buffer.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const sectionAlignment = buffer.readUInt32LE(optional + 32);
  const fileAlignment = buffer.readUInt32LE(optional + 36);
  const sizeOfImage = buffer.readUInt32LE(optional + 56);
  const sizeOfHeaders = buffer.readUInt32LE(optional + 60);
  const table = optional + optionalSize;
  if (sizeOfImage === 0 || table + sectionCount * 40 > buffer.length) return null;
  const sections = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const header = table + index * 40;
    sections.push({
      header,
      name: buffer.toString('latin1', header, header + 8).replace(/\0+$/, ''),
      virtualSize: buffer.readUInt32LE(header + 8),
      virtualAddress: buffer.readUInt32LE(header + 12),
      sizeOfRawData: buffer.readUInt32LE(header + 16),
      pointerToRawData: buffer.readUInt32LE(header + 20),
    });
  }
  return {
    pe,
    optional,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    sections,
  };
}

/**
 * Rebuild an image-layout PE. Headers come from disk (they describe the mapped
 * layout); section bodies come from memory.
 */
export function rebuildImageFromMemory({ diskBuffer, memoryBuffer } = {}) {
  const layout = parseImageLayout(diskBuffer);
  if (layout === null) return { ok: false, reason: 'the on-disk file is not a PE with a readable optional header' };
  if (!Buffer.isBuffer(memoryBuffer) || memoryBuffer.length === 0) return { ok: false, reason: 'the memory image is empty' };
  const size = Math.min(layout.sizeOfImage, memoryBuffer.length, MAX_IMAGE);
  if (size < layout.sizeOfHeaders) return { ok: false, reason: 'the memory image is smaller than the PE headers' };
  const output = Buffer.alloc(size);
  diskBuffer.copy(output, 0, 0, Math.min(layout.sizeOfHeaders, diskBuffer.length, size));
  let copied = 0;
  for (const section of layout.sections) {
    const span = Math.max(section.virtualSize, section.sizeOfRawData);
    if (span === 0 || section.virtualAddress >= size) continue;
    const available = Math.min(span, size - section.virtualAddress, memoryBuffer.length - section.virtualAddress);
    if (available <= 0) continue;
    memoryBuffer.copy(output, section.virtualAddress, section.virtualAddress, section.virtualAddress + available);
    // Image layout: the raw pointer is the virtual address and the raw size is
    // the mapped size. This is what makes the file readable again.
    output.writeUInt32LE(available, section.header + 16);
    output.writeUInt32LE(section.virtualAddress, section.header + 20);
    copied += available;
  }
  // FileAlignment must equal SectionAlignment once offsets are RVAs.
  if (layout.sectionAlignment >= 0x200) output.writeUInt32LE(layout.sectionAlignment, layout.optional + 36);
  return {
    ok: true,
    buffer: output,
    layout,
    copiedBytes: copied,
    sections: layout.sections.map((section) => section.name),
  };
}

/**
 * Run the dump helper and rebuild the image. The caller has already enforced
 * policy; this function only executes the helper and parses its JSON line.
 *
 * `sandbox: true` starts the sample through the kernel-enforced launcher
 * (created suspended inside the AppContainer + Job), then the helper attaches
 * by pid; a launch failure is fail-closed and never falls back to an
 * unsandboxed spawn. `workDir` is the launcher's run directory (required in
 * sandbox mode).
 */
export function dumpModuleMemory({ target, output, delayMs = 0, timeoutMs = 60_000, waitForExec = false, python = 'python', pythonArgs = [], sandbox = false, workDir = null } = {}) {
  return new Promise(async (resolvePromise) => {
    if (!existsSync(HELPER)) {
      resolvePromise({ ok: false, reason: `dump helper missing: ${HELPER}` });
      return;
    }
    let diskBuffer;
    try {
      diskBuffer = await readFile(target);
    } catch (error) {
      resolvePromise({ ok: false, reason: `cannot read the target (${error?.message ?? error})` });
      return;
    }
    const layout = parseImageLayout(diskBuffer);
    if (layout === null) {
      resolvePromise({ ok: false, reason: 'the target is not a PE with a readable optional header' });
      return;
    }
    if (layout.sizeOfImage > MAX_IMAGE) {
      resolvePromise({ ok: false, reason: `the image is ${layout.sizeOfImage} bytes, over the ${MAX_IMAGE}-byte cap` });
      return;
    }
    if (sandbox && !workDir) {
      resolvePromise({ ok: false, reason: 'sandboxed dumping needs a workDir for the sandbox launcher' });
      return;
    }
    let session = null;
    let extraArgs = [];
    if (sandbox) {
      // Kernel-enforced path: child created suspended in the container; the
      // helper attaches by pid. Fail-closed: no unsandboxed retry.
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
    const rawPath = `${output}.raw`;
    const child = spawn(python, [
      ...pythonArgs, HELPER, target, rawPath, String(layout.sizeOfImage), String(Math.max(0, delayMs)), String(Math.max(1_000, timeoutMs)), waitForExec ? '1' : '0',
      ...extraArgs,
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let answerHandled = false;
    let timer = null;
    let answerWatch = null;
    // The helper prints its single JSON answer (the raw image file is written
    // before it) and exits - but the Frida cleanup at interpreter exit can
    // deadlock (measured on this build), and a container child holding the
    // inherited pipe handles can stall the close event long after the answer
    // is available. Resolve from the stream the moment the answer line lands;
    // never depend on the helper's exit.
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (answerWatch) clearInterval(answerWatch);
      killTree(child.pid);
      if (session?.pid) killTree(session.pid);
      try { child.kill('SIGKILL'); } catch { /* gone */ }
      resolvePromise(value);
    };
    const handleAnswer = async (answer) => {
      // Dispatched exactly once by scanStdout (answerHandled); the awaited
      // launcher reap below must not race the helper's close event.
      // The helper already terminated the container child; if that kill lost
      // a race (measured), end the child now so the launcher's wait returns
      // immediately - otherwise this await would run into the launcher's own
      // -TimeoutMs watchdog and the node-side timer would win the race.
      if (session?.pid) killTree(session.pid);
      // Reap the launcher so the job is closed and classified (bounded by its
      // own -TimeoutMs watchdog).
      const sandboxOutcome = session ? await session.wait().catch(() => null) : null;
      if (!answer || answer.ok !== true) {
        try { await unlink(rawPath); } catch { /* nothing to clean */ }
        // Failure paths carry the helper's warnings so a failed run can show
        // what was observed along the way (hook errors, script faults, ...)
        // instead of a bare "no dump before the timeout".
        const detail = answer?.error ?? (stderr.trim() || 'the dump helper produced no answer');
        const helperWarnings = Array.isArray(answer?.warnings)
          ? answer.warnings.filter((item) => typeof item === 'string' && item.length > 0)
          : [];
        if (sandboxOutcome) {
          if (!sandboxOutcome.ran) {
            finish({ ok: false, reason: sandboxOutcome.reason ?? 'the sandbox did not start the sample' });
            return;
          }
          // A job-assignment failure is fail-closed (ran=false, handled above):
          // there is no token-only-degraded-but-ran outcome to warn about.
          helperWarnings.push(...(sandboxOutcome.notes ?? []));
        }
        const suffix = helperWarnings.length > 0
          ? ` (helper warnings: ${helperWarnings.join(' | ').slice(0, 800)})`
          : '';
        finish({ ok: false, reason: `${detail}${suffix}` });
        return;
      }
      let memoryBuffer;
      try {
        memoryBuffer = await readFile(rawPath);
      } catch (error) {
        finish({ ok: false, reason: `cannot read the raw image (${error?.message ?? error})` });
        return;
      }
      const rebuilt = rebuildImageFromMemory({ diskBuffer, memoryBuffer });
      if (!rebuilt.ok) {
        try { await unlink(rawPath); } catch { /* nothing to clean */ }
        finish(rebuilt);
        return;
      }
      try {
        await writeFile(output, rebuilt.buffer);
      } catch (error) {
        finish({ ok: false, reason: `cannot write ${output} (${error?.message ?? error})` });
        return;
      }
      try { await unlink(rawPath); } catch { /* best effort */ }
      const imports = parsePEImports(rebuilt.buffer);
      const strings = extractStrings(rebuilt.buffer, { minLength: 6, maxStrings: 2_000 }).map((item) => item.value);
      finish({
        ok: true,
        bytes: rebuilt.buffer.length,
        delayMs,
        waitForExec,
        oepSignal: answer.oepSignal ?? null,
        execEntry: answer.execEntry ?? null,
        entryWatch: answer.entryWatch ?? null,
        entryWatchReason: answer.entryWatchReason ?? null,
        watchThread: answer.watchThread ?? null,
        watchThreads: Array.isArray(answer.watchThreads) ? answer.watchThreads : [],
        followedCount: typeof answer.followedCount === 'number' ? answer.followedCount : null,
        base: answer.base ?? null,
        sections: rebuilt.sections,
        entryRva: readPeLayout(rebuilt.buffer)?.entryRva ?? null,
        imports: imports?.apiFlat?.length ?? 0,
        strings: strings.length,
        ...(sandboxOutcome ? {
          sandbox: {
            ran: true,
            jobEnforced: sandboxOutcome.jobEnforced,
            pid: sandboxOutcome.pid,
            timedOut: sandboxOutcome.timedOut,
            notes: sandboxOutcome.notes ?? [],
          },
        } : {}),
      });
    };
    const scanStdout = () => {
      if (settled || answerHandled) return;
      const lines = stdout.split(/\r?\n/).filter(Boolean);
      for (let index = lines.length - 1; index >= 0; index -= 1) {
        try {
          const answer = JSON.parse(lines[index]);
          if (answer && (answer.ok === true || typeof answer.error === 'string')) {
            // Mark synchronously: the handling awaits the launcher's exit, and
            // the helper's close event must not race it with a "no answer".
            answerHandled = true;
            void handleAnswer(answer);
            return;
          }
        } catch { /* keep looking for the JSON line */ }
      }
    };
    timer = setTimeout(() => {
      finish({ ok: false, reason: 'the dump helper did not finish in its time budget' });
      // Sandbox mode: the timer must outlast the launcher's own -TimeoutMs
      // watchdog (timeoutMs + 30s) so the launcher's classification, not this
      // timer, decides the outcome when the helper hangs.
    }, Math.max(5_000, timeoutMs + (sandbox ? 45_000 : 30_000)));
    answerWatch = setInterval(scanStdout, 100);
    child.stdout.on('data', (chunk) => { stdout = (stdout + chunk).slice(-MAX_OUTPUT); scanStdout(); });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-MAX_OUTPUT); });
    child.on('error', (error) => {
      finish({ ok: false, reason: `cannot start the dump helper (${error.message})` });
    });
    child.on('close', (code) => {
      scanStdout();
      if (!answerHandled) finish({ ok: false, reason: stderr.trim() || 'the dump helper produced no answer' });
    });
  });
}

export function dumpHelperPath() {
  return HELPER;
}
