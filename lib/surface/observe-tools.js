/**
 * The opt-in side-effect comparison tool.
 *
 * Runs the target and the rebuild under a Frida observer and compares what they
 * tried to do outside their own process: registry writes, named pipes, service
 * creation, IPv4/IPv6 outbound connections and DNS lookup attempts. The file
 * trace covers the working directory; this covers the state that never becomes
 * a file.
 *
 * @module dsh-rea/lib/observe-tools
 */

import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';

import { dynamicReadiness } from '../dynamic/dynamic.js';
import { compareEventSets, observeLimitations, runSideEffectObserver } from '../dynamic/observe.js';
import { withRedactedOutput } from './tools.js';

const pct = (value) => (typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : 'n/a');

function render({ targetPath, rebuiltPath, target, rebuilt, comparison }) {
  const lines = [
    `Side effects — ${targetPath} ↔ ${rebuiltPath}`,
    'both binaries were executed under API hooks; the events are untrusted observations, and the window ends at the first connect-family call',
    '',
    `target: ${target.events.length} event(s), ${target.durationMs} ms — ${JSON.stringify(comparison.groups.target)}`,
    `rebuilt: ${rebuilt.events.length} event(s), ${rebuilt.durationMs} ms — ${JSON.stringify(comparison.groups.rebuilt)}`,
    '',
  ];
  if (comparison.status === 'empty') {
    lines.push('side effects: neither run attempted a hooked call (empty, not a pass)');
  } else {
    lines.push(`side effects: ${pct(comparison.score)} (recall ${pct(comparison.recall)}, precision ${pct(comparison.precision)})`);
    // Sorted so a family's position does not depend on call order: a
    // toolchain's init burst (ws2_32 startup issues a wall of registry
    // queries) must not crowd a rare pipe/service/network event out of the
    // excerpt. The disk JSON keeps insertion order.
    if (comparison.missing.length > 0) lines.push(`  missing from the rebuild: ${[...comparison.missing].sort().slice(0, 30).join(' | ')}${comparison.missing.length > 30 ? ' …' : ''}`);
    if (comparison.added.length > 0) lines.push(`  rebuilt-only: ${[...comparison.added].sort().slice(0, 30).join(' | ')}${comparison.added.length > 30 ? ' …' : ''}`);
  }
  const warnings = [...new Set([...(target.warnings ?? []), ...(rebuilt.warnings ?? [])])];
  if (warnings.length > 0) lines.push('', `hook warnings: ${warnings.slice(0, 6).join(' | ')}`);
  lines.push('', 'limits:');
  for (const limit of observeLimitations()) lines.push(`- ${limit}`);
  return lines.join('\n');
}

export function buildSideEffectsTool({ config, store } = {}) {
  const tool = {
    name: 'rea_side_effects',
    description: 'OPT-IN EXECUTION OF BOTH BINARIES. Runs the target and the rebuild under Frida hooks for registry writes, named pipes, service creation, IPv4/IPv6 outbound connections and DNS lookup attempts, then compares the attempted calls as sets (recall and precision). By default (blockSampleEgress, on unless disabled) non-loopback connect attempts are made to fail before any packet leaves the host and are reported as network:connect-blocked; loopback (::1/127.0.0.1) is allowed through and observed. With sandbox=true AND sandboxSampleExecution=true in the config, each binary instead runs inside a kernel-enforced sandbox (no-capability AppContainer + no-breakaway Job Object): non-loopback TCP is denied by the kernel itself (WSAEACCES), which covers the direct-syscall/raw-socket blind spots of the user-mode block (UDP sendto is still not blocked by the container on this build). Requires allowSampleExecution=true and confirm=true. Calls resolved through GetProcAddress or the IAT are visible; after the first connect-family call the observer goes silent, so only that call and earlier attempts are reported. An attempt is not a success, and a blocked attempt is not evidence the sample behaved - both sides run under the same switch. The observer injects a Frida agent and patches hooked export addresses in memory; the in-process traces are documented in docs/detection-surface.md. Use it when the file-level trace is clean but the program is expected to touch machine state.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        target: { type: 'string', description: 'Absolute path of the original sample to execute.' },
        rebuilt: { type: 'string', description: 'Absolute path of the rebuilt binary to execute.' },
        durationMs: { type: 'number', description: 'How long each binary runs before the report, 200-30000 ms. Defaults to 1500.' },
        sandbox: { type: 'boolean', description: 'Run both binaries inside the kernel-enforced sandbox (AppContainer + Job Object) via scripts/rea-sandbox.ps1, attaching the observer by pid. Requires sandboxSampleExecution=true in the config row or policy panel in addition to allowSampleExecution and confirm. Default false. Windows only; a sandbox launch failure is a fail-closed "did not run", never an unsandboxed fallback.' },
        confirm: { type: 'boolean', description: 'Must be true. A second confirmation, separate from the policy flag.' },
      },
      required: ['target', 'rebuilt', 'confirm'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no observation)' }]; },
    },
    async execute(input) {
      if (config?.allowSampleExecution !== true) {
        return { text: 'rea_side_effects: sample execution is disabled. Set "allowSampleExecution: true" on the dsh-rea row (or in the policy panel) if running samples is intended. Everything else in this plugin reads bytes only.' };
      }
      if (input?.confirm !== true) {
        return { text: 'rea_side_effects: confirm must be true. This call runs both binaries; the policy flag alone is not a per-call confirmation.' };
      }
      for (const key of ['target', 'rebuilt']) {
        if (!isAbsolute(String(input?.[key] ?? ''))) return { text: `rea_side_effects: ${key} must be an absolute path` };
      }
      if (!store?.write) return { text: 'rea_side_effects: no artifact store is available in this session' };
      for (const key of ['target', 'rebuilt']) {
        try {
          const info = await stat(input[key]);
          if (!info.isFile()) return { text: `rea_side_effects: ${key} is not a file` };
        } catch {
          return { text: `rea_side_effects: ${key} does not exist` };
        }
      }
      const durationMs = Number.isFinite(input?.durationMs) ? Math.max(200, Math.min(30_000, Math.floor(input.durationMs))) : 1_500;
      // Host protection: non-loopback connects are failed before any packet by
      // the observer itself (user-mode, best effort). Both sides run under the
      // same switch, so the comparison stays fair.
      const blockEgress = config?.blockSampleEgress !== false;
      // Kernel-enforced containment is a separate, opt-in layer on top of
      // allowSampleExecution - never implied by it.
      const sandbox = input?.sandbox === true;
      if (sandbox && config?.sandboxSampleExecution !== true) {
        return { text: 'rea_side_effects: sandbox=true requires sandboxSampleExecution=true on the dsh-rea row (or in the policy panel). The kernel-enforced sandbox is its own opt-in containment layer, separate from allowSampleExecution.' };
      }

      const readiness = await dynamicReadiness();
      if (!readiness.ready) {
        return { text: `rea_side_effects: the dynamic engine is not available (${readiness.reason}). Install Frida for the current Python (pip install frida) and retry.` };
      }
      // In sandbox mode each run gets its own launcher work directory (the
      // container writes its profile redirect there); it is cleaned up after.
      const runOne = async (label, exePath) => {
        if (!sandbox) {
          return runSideEffectObserver({ target: exePath, durationMs, blockEgress, python: readiness.command, pythonArgs: readiness.args });
        }
        const workDir = await mkdtemp(join(tmpdir(), `dsh-rea-observe-${label}-`));
        try {
          return await runSideEffectObserver({ target: exePath, durationMs, blockEgress, python: readiness.command, pythonArgs: readiness.args, sandbox: true, workDir });
        } finally {
          await rm(workDir, { recursive: true, force: true }).catch(() => {});
        }
      };
      const target = await runOne('target', input.target);
      if (!target.ok) return { text: `rea_side_effects: the target produced no observation — ${target.reason}` };
      const rebuilt = await runOne('rebuilt', input.rebuilt);
      if (!rebuilt.ok) return { text: `rea_side_effects: the rebuild produced no observation — ${rebuilt.reason}` };

      const comparison = compareEventSets(target.events, rebuilt.events);
      const text = render({ targetPath: input.target, rebuiltPath: input.rebuilt, target, rebuilt, comparison });
      const record = {
        targetPath: input.target, rebuiltPath: input.rebuilt, durationMs, blockEgress, sandbox,
        target: { events: target.events, warnings: target.warnings },
        rebuilt: { events: rebuilt.events, warnings: rebuilt.warnings },
        comparison,
      };
      try {
        const saved = await store.write('side-effects.json', JSON.stringify(record, null, 2));
        // The disk JSON keeps the raw events (local file); the returned text is
        // redacted by the wrapper around execute.
        return { text: `${text}\n\nfull JSON: ${saved}` };
      } catch (error) {
        return { text: `${text}\n\nfull JSON: not saved (${error?.message ?? error})` };
      }
    },
    isConcurrencySafe: () => false,
  };
  // The report names the machine (DNS events carry the hostname), so the
  // rendered text is redacted; the disk JSON keeps the raw events.
  return withRedactedOutput(tool);
}
