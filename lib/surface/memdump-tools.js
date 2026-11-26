/**
 * The opt-in memory-image dump tool.
 *
 * This is the generic unpacking path for samples that are not UPX: run the
 * sample suspended (or after a delay), read the main module's mapped memory,
 * and rebuild a PE from it. It executes the sample, so it is gated exactly like
 * the Frida probe and the runtime trace: policy flag plus per-call confirmation,
 * no sandbox.
 *
 * @module dsh-rea-restore/lib/memdump-tools
 */

import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';

import { dynamicReadiness } from '../dynamic/dynamic.js';
import { dumpModuleMemory } from '../dynamic/memdump.js';
import { evidenceProducer, identifyFile } from '../infra/evidence.js';
import { markUntrusted, withRedactedOutput } from './tools.js';

/**
 * The entry line states which of the four possible outcomes happened: a hit
 * with the observed address/instruction, an explicit none (with the blind
 * spots named so "none" is never read as "did not happen"), an unavailable
 * watch, or a watch that was not requested. Values taken from the process are
 * wrapped as untrusted; the fixed wording around them is the tool's own.
 */
function renderEntryLine(result) {
  const watch = result.entryWatch;
  if (watch === 'off' || watch === null || watch === undefined) return 'entry: not requested';
  if (result.execEntry) {
    const detail = [result.execEntry.hit, result.execEntry.instruction, result.execEntry.bytes]
      .filter((item) => typeof item === 'string' && item.length > 0)
      .join(' ');
    const wrapped = markUntrusted('oep-entry', detail, { maxChars: 300 });
    const inside = result.execEntry.insideMainModule === true ? 'yes' : 'no';
    return `entry: control flow entered the marked region at ${wrapped} (inside main module: ${inside})`;
  }
  if (watch === 'unavailable') {
    return `entry watch unavailable: ${result.entryWatchReason ?? 'the entry watcher did not run'}`;
  }
  if (result.oepSignal) {
    const parts = [];
    if (result.watchThread) parts.push(`watched thread ${result.watchThread}`);
    if (Number.isFinite(result.followedCount) && result.followedCount > 0) parts.push(`${result.followedCount} thread(s) followed process-wide`);
    if (result.entryWatch === 'partial') parts.push('thread watch cap reached - coverage is partial');
    const watched = parts.length > 0 ? ` (${parts.join(', ')}, kernel32+ntdll-level hooks)` : ' (kernel32+ntdll-level hooks)';
    return `entry: none before the timeout - control flow was never observed in the marked region${watched}; the dump may still contain the stub`;
  }
  return 'entry: none before the timeout - no executable memory marking was observed, so there was no region to watch (kernel32+ntdll-level hooks)';
}

export function buildMemoryDumpTool({ config, store, readiness = dynamicReadiness, dump = dumpModuleMemory } = {}) {
  const tool = {
    name: 'rea_memory_dump',
    description: 'OPT-IN SAMPLE EXECUTION. Spawns the target suspended, reads the main module\'s memory image, and rebuilds an image-layout PE the analyzers can read. This is the generic path for samples that are not UPX: raise delayMs so a packer can unpack before the dump. With waitForExec=true the dump additionally waits for control flow to be observed entering the marked executable region (Stalker across the process\'s threads: the marking thread, every thread alive at the mark, and post-mark thread creations via an NtCreateThreadEx hook, capped at 16 threads - Frida\'s own modules are excluded from instrumentation) and reports the hit address, instruction and hitting thread; that narrows the guess but is still not a guarantee of the original entry point, and an early dump still contains the unpacker. Declared blind spots: the race window between a post-mark thread\'s creation and the follow, threads created by hardcoded syscalls, and the thread cap (coverage is reported as partial). The EXECUTE marking is observed through two hook layers - kernel32!VirtualAlloc/VirtualProtect and ntdll!NtAllocateVirtualMemory/NtProtectVirtualMemory (the structured result names the layer: kernel32 callers keep kind VirtualAlloc/VirtualProtect, direct ntdll callers report kind NtAllocateVirtualMemory/NtProtectVirtualMemory with layer ntdll). Blind spots: UPX-style in-place unpackers keep their sections RWX from the loader, so no kernel32- or ntdll-level EXECUTE marking fires and the signal/entry lines show an explicit none - unpack UPX with rea_unpack instead; shellcode that issues the allocation/protection syscalls directly, without going through any ntdll export, is invisible to both layers; and a packed sample that runs for many seconds under the hooks can stop the Frida agent from responding (measured with UPX 5.3.0 after 8-20 s) - keep delayMs short for packed targets. Root cause pinned by the A/B experiment matrix (2026-11-19, frida 17.26.3): the kernel32!VirtualAlloc hook itself is the trigger, independent of the sample type - empty hook callbacks still hang (3/3), install timing does not matter, VirtualProtect-only never hangs, and a sample that exits while the hook is installed deadlocks the Frida agent at its exit path (process stays alive, agent stops answering even a dump request). That is the Frida Interceptor layer, not plugin callback code, so the plugin mitigates - short waits, hard-clamped waitForExec timeout, explicit failures - and does not claim a fix. Requires allowSampleExecution=true and confirm=true. By default the sample runs with its own network access and there is no sandbox; with sandbox=true AND sandboxSampleExecution=true in the config, the sample is started inside a kernel-enforced sandbox (no-capability AppContainer + no-breakaway Job Object) instead and the dumper attaches by pid - a failed sandbox launch is reported and never falls back to an unsandboxed run. The dumper injects a Frida agent and (with waitForExec) rewrites executed code on the watched thread via Stalker; the in-process traces are documented in docs/detection-surface.md.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        target: { type: 'string', description: 'Absolute path of the sample to execute and dump.' },
        output: { type: 'string', description: 'Absolute path for the rebuilt PE. Refuses to overwrite unless overwrite=true.' },
        delayMs: { type: 'number', description: 'Milliseconds to let the sample run before dumping, 0-30000. 0 dumps at the entry point, still suspended. Defaults to 0. For packed targets keep this at 8000 ms or less: a packed sample that runs long under the kernel32 hooks can stop the Frida agent from responding (hooking kernel32!VirtualAlloc is the trigger, independent of the sample type), and prefer rea_unpack for UPX - its in-place unpacking never fires an EXECUTE marking, so the signal/entry lines report an explicit none for UPX samples.' },
        waitForExec: { type: 'boolean', description: 'Resume, wait for the first executable memory marking (an EXECUTE-flag VirtualProtect/VirtualAlloc or NtProtectVirtualMemory/NtAllocateVirtualMemory - kernel32 callers stay kind VirtualAlloc/VirtualProtect, direct ntdll callers report layer ntdll), then watch the process\'s threads with Stalker (marking thread, threads alive at the mark, and post-mark creations, capped) until control flow is first observed entering the marked region before dumping; the report records the hit address and instruction, or an explicit "none". Still not a real OEP finder. For packed samples always pair it with a short timeoutMs (8000 ms or less): UPX-style in-place unpackers never mark memory executable, so this reports an explicit none for them, and a longer wait only runs into the agent failure documented under delayMs - the failure always surfaces as an explicit result, never a hang. Defaults to false.' },
        timeoutMs: { type: 'number', description: 'Wait for the dump, 1000-180000 ms. Defaults to 60000. For packed samples use 8000 ms or less - packed samples can stop responding under the kernel32 hooks after 8-20 s, so a longer timeout only delays the explicit failure (the result is still a clean error or an explicit none, never a hang). With waitForExec=true this is enforced: values above 8000 ms are clamped to 8000 ms and the result text states the clamp, because the A/B matrix showed a longer wait cannot succeed under the kernel32 hooks.' },
        overwrite: { type: 'boolean', description: 'Allow replacing an existing output file. Defaults to false.' },
        sandbox: { type: 'boolean', description: 'Run the sample inside the kernel-enforced sandbox (no-capability AppContainer + no-breakaway Job Object) via scripts/runtime/rea-sandbox.ps1 and attach the dumper by pid. Requires sandboxSampleExecution=true in the config row or policy panel in addition to allowSampleExecution and confirm. Default false. Windows only; a sandbox launch failure is a fail-closed "did not run", never an unsandboxed fallback.' },
        confirm: { type: 'boolean', description: 'Must be true. A second confirmation, separate from the policy flag.' },
      },
      required: ['target', 'output', 'confirm'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no dump result)' }]; },
    },
    async execute(input) {
      if (config?.allowSampleExecution !== true) {
        return { text: 'rea_memory_dump: sample execution is disabled. Set "allowSampleExecution: true" on the dsh-rea-restore row (or in the policy panel) if running samples is intended. Everything else in this plugin reads bytes only.' };
      }
      if (input?.confirm !== true) {
        return { text: 'rea_memory_dump: confirm must be true. This call runs the sample; the policy flag alone is not a per-call confirmation.' };
      }
      for (const key of ['target', 'output']) {
        if (!isAbsolute(String(input?.[key] ?? ''))) return { text: `rea_memory_dump: ${key} must be an absolute path` };
      }
      try {
        const info = await stat(input.target);
        if (!info.isFile()) return { text: 'rea_memory_dump: target is not a file' };
      } catch {
        return { text: 'rea_memory_dump: target does not exist' };
      }
      if (input?.overwrite !== true) {
        try {
          await stat(input.output);
          return { text: `rea_memory_dump: output already exists (${input.output}); pass overwrite=true to replace it` };
        } catch {
          // Expected: the output does not exist yet.
        }
      }
      let targetIdentity;
      try { targetIdentity = await identifyFile(input.target); }
      catch (error) { return { text: `rea_memory_dump: cannot bind target bytes (${error?.message ?? error})` }; }
      const delayMs = Number.isFinite(input?.delayMs) ? Math.max(0, Math.min(30_000, Math.floor(input.delayMs))) : 0;
      let timeoutMs = Number.isFinite(input?.timeoutMs) ? Math.max(1_000, Math.min(180_000, Math.floor(input.timeoutMs))) : 60_000;
      const waitForExec = input?.waitForExec === true;
      // Hard guarantee (T3 root-cause round, 2026-11-19): with the kernel32
      // VirtualAlloc hook installed, a sample that exits while the hook is up
      // deadlocks the Frida agent at the process exit path (A/B matrix: empty
      // hook callbacks still hang 3/3, so the trigger is the hook itself, not
      // our callback code). A waitForExec beyond 8000 ms cannot succeed - it
      // only extends the explicit failure and the window in which the hooked
      // process stays alive without answering.
      let timeoutNote = null;
      if (waitForExec && timeoutMs > 8_000) {
        timeoutNote = `timeoutMs ${timeoutMs} clamped to 8000 for waitForExec - under the kernel32 hooks a longer wait only runs into the measured agent failure (the VirtualAlloc hook itself is the trigger; the failure always surfaces as an explicit result, never a hang)`;
        timeoutMs = 8_000;
      }

      // Kernel-enforced containment is a separate, opt-in layer on top of
      // allowSampleExecution - never implied by it. Refused before any
      // readiness work so a misconfigured call costs nothing.
      const sandbox = input?.sandbox === true;
      if (sandbox && config?.sandboxSampleExecution !== true) {
        return { text: 'rea_memory_dump: sandbox=true requires sandboxSampleExecution=true on the dsh-rea-restore row (or in the policy panel). The kernel-enforced sandbox is its own opt-in containment layer, separate from allowSampleExecution.' };
      }
      const readinessState = await readiness();
      if (!readinessState.ready) {
        return { text: `rea_memory_dump: the dynamic engine is not available (${readinessState.reason}). Install Frida for the current Python (pip install frida) and retry.` };
      }
      try {
        await mkdir(dirname(input.output), { recursive: true });
      } catch (error) {
        return { text: `rea_memory_dump: cannot create the output directory (${error?.message ?? error})` };
      }
      // In sandbox mode the launcher needs a run directory of its own (the
      // container's profile redirect lands there); it is cleaned up after.
      const sandboxWorkDir = sandbox ? await mkdtemp(join(tmpdir(), 'dsh-rea-dump-')) : null;
      let result;
      try {
        result = await dump({
          target: input.target,
          output: input.output,
          delayMs,
          timeoutMs,
          waitForExec,
          python: readinessState.command,
          pythonArgs: readinessState.args,
          sandbox,
          workDir: sandboxWorkDir,
        });
      } finally {
        if (sandboxWorkDir) await rm(sandboxWorkDir, { recursive: true, force: true }).catch(() => {});
      }
      if (!result.ok) {
        return { text: `rea_memory_dump: no image — ${result.reason}` };
      }
      let artifact;
      try {
        artifact = await identifyFile(input.output);
        const targetAfter = await identifyFile(input.target);
        if (targetAfter.sha256 !== targetIdentity.sha256) throw new Error('target bytes changed during dumping');
      } catch (error) { return { text: `rea_memory_dump: cannot bind image bytes (${error?.message ?? error})` }; }
      const lines = [
        `memory image — ${input.target}`,
        `dump: ${delayMs === 0 && !waitForExec ? 'at the entry point (still suspended)' : `after ${delayMs} ms of execution`}${waitForExec ? ' (waited for an executable memory marking)' : ''} | frida ${readinessState.version}`,
        `oep signal: ${result.oepSignal ? `${result.oepSignal.kind} ${result.oepSignal.addr} size ${result.oepSignal.size} prot 0x${Number(result.oepSignal.prot).toString(16)}` : waitForExec ? 'none before the timeout — the dump may still contain the stub' : 'not requested'}`,
        renderEntryLine(result),
        `output: ${input.output} (${result.bytes} bytes, image-layout PE)`,
        `sections: ${result.sections.join(', ')}`,
        `parsed after rebuild: entry ${result.entryRva === null ? 'n/a' : `0x${Number(result.entryRva).toString(16)}`}, ${result.imports} imports, ${result.strings} strings (entry and imports come from the on-disk PE headers - for a packed sample they describe the stub's tables, not the unpacked program)`,
        ...(timeoutNote ? [`note: ${timeoutNote}`] : []),
        'the sample was executed; the rebuilt file is a memory image, not proof of the original layout',
      ];
      const text = lines.join('\n');
      if (store?.write) {
        try {
          const saved = await store.write('memory-dump.json', JSON.stringify({ target: input.target, targetSha256: targetIdentity.sha256, output: input.output, delayMs, ...result }, null, 2));
          if (!store?.writeEvidence) return { text: `${text}\n\nfull JSON: ${saved}\nreceipt: unavailable; this image cannot be applied` };
          const receipt = await store.writeEvidence({
            type: 'memory-dump', status: 'success', producer: evidenceProducer('rea_memory_dump', {
              policy: { allowSampleExecution: true, sandbox, sandboxSampleExecution: config?.sandboxSampleExecution === true }, confirm: true,
            }),
            targetSha256: targetIdentity.sha256, artifact,
            coverage: { complete: result.entryWatch !== 'partial', entryObserved: result.execEntry?.hit === true },
            details: { delayMs, timeoutMs, waitForExec, sandbox, dumpSha256: artifact.sha256 },
            limitations: ['the output is a memory image, not the original disk layout', 'entry observation is partial when the thread watch cap is reached'],
          });
          return { text: `${text}\n\nfull JSON: ${saved}\nevidence receipt: ${receipt.receiptPath}\nevidenceId: ${receipt.evidenceId}` };
        } catch (error) {
          return { text: `${text}\n\nreceipt: not saved; this image cannot be applied (${error?.message ?? error})` };
        }
      }
      return { text: `${text}\n\nreceipt: unavailable; this image cannot be applied` };
    },
    isConcurrencySafe: () => false,
  };
  // The report carries the target/output paths; redact host identity from the
  // rendered text while the disk JSON keeps them (local file).
  return withRedactedOutput(tool);
}
