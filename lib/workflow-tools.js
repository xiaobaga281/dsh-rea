/**
 * Plugin-owned workflow tools: cross-session result queries, corpus triage,
 * local coarse diff, fuzz harness templates, and the trusted playbook runner.
 *
 * All of them work without a live REA child (except playbook calls, which are
 * proxied through the guarded parent caller). Output is bounded; full reports
 * go to the artifact directory.
 *
 * @module dsh-rea/lib/workflow-tools
 */

import { createHash } from 'node:crypto';
import { readdir, stat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

import { buildProtocolTool, buildWindowsToolsTool } from './external-adapters.js';
import { extractIocs } from './intel.js';
import { loadSample } from './intel-tools.js';
import { listPlaybooks, runPlaybook } from './playbook.js';
import { triageFile } from './triage.js';
import { markUntrusted } from './tools.js';

export { buildProtocolTool, buildWindowsToolsTool };

const textOutput = (fallback) => ({
  schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
  render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : fallback }]; },
});

/** Ask the cross-session index instead of re-running a long analysis. */
export function buildQueryResultsTool(resultIndex) {
  return {
    name: 'rea_query_results',
    description: 'Query the cross-session index of previous REA results. Each entry records the tool, timestamp, Evidence IDs, confidence, coverage keys and provider. Use it to reuse an analysis instead of repeating it. Read-only.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        tool: { type: 'string', description: 'Substring of the tool name.' },
        since: { type: 'string', description: 'ISO timestamp lower bound.' },
        minConfidence: { type: 'number', description: 'Only results whose numeric confidence is at least this.' },
        evidenceId: { type: 'string', description: 'Find results carrying this Evidence ID.' },
        keyword: { type: 'string', description: 'Match tool name, Evidence IDs and result kind.' },
        limit: { type: 'number', description: 'Maximum entries, at most 200. Defaults to 20.' },
      },
    },
    output: textOutput('(no result index)'),
    async execute(args) {
      const result = await resultIndex.queryDetailed({
        tool: args?.tool, since: args?.since, minConfidence: args?.minConfidence,
        evidenceId: args?.evidenceId, keyword: args?.keyword, limit: args?.limit,
      });
      const rows = result.items;
      const lines = [];
      if (result.truncated) {
        lines.push(`[index truncated: scanned ${result.scanned} of ${result.totalLines} lines; older entries are not searchable]`);
      }
      if (rows.length === 0) return { text: [...lines, 'No indexed results match. Results are recorded as REA tools are called; run an analysis first.'].join('\n') };
      lines.push(`Indexed results (${rows.length}, newest first):`);
      for (const row of rows) {
        lines.push(`- ${row.at} ${row.tool}${row.confidence !== undefined ? ` confidence=${row.confidence}` : ''}${row.evidenceCount ? ` evidence=${row.evidenceCount}` : ''}${row.provider ? ` provider=${row.provider}` : ''}${row.resultChars ? ` chars=${row.resultChars}` : ''}`);
        if (row.evidenceIds?.length) lines.push(`  ids: ${row.evidenceIds.slice(0, 5).join(', ')}`);
      }
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** First-pass triage over a directory, with bounded output and index records. */
export function buildBatchTriageTool({ resultIndex, triageOptions, maxBatch = 50, store }) {
  return {
    name: 'rea_batch_triage',
    description: 'Run the local static triage over every file in a directory (non-recursive), then write a summary report. Never executes a sample. Use this to triage a corpus before choosing deep-analysis targets.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        directory: { type: 'string', description: 'Absolute path to a directory of samples.' },
        pattern: { type: 'string', description: 'Optional case-insensitive substring filter on file names.' },
        limit: { type: 'number', description: 'Maximum files, capped by batchTriageLimit. Defaults to that config value.' },
      },
      required: ['directory'],
    },
    output: textOutput('(no batch triage result)'),
    async execute(args) {
      const directory = String(args?.directory ?? '');
      if (!isAbsolute(directory)) return { text: 'directory must be an absolute path.' };
      let names;
      try { names = await readdir(directory); } catch (error) { return { text: `directory is unreadable: ${error.message}` }; }
      const needle = typeof args?.pattern === 'string' ? args.pattern.toLowerCase() : '';
      const cap = Number.isFinite(args?.limit) ? Math.min(Math.max(Math.floor(args.limit), 1), maxBatch) : maxBatch;
      const candidates = names.filter((name) => needle === '' || name.toLowerCase().includes(needle)).slice(0, cap);
      const counts = { 'likely-packed-or-protected': 0, 'possibly-obfuscated': 0, 'appears-unpacked': 0 };
      const rows = [];
      for (const name of candidates) {
        const path = join(directory, name);
        let info;
        try { info = await stat(path); } catch { continue; }
        if (!info.isFile()) continue;
        try {
          const report = await triageFile(path, {
            maxBytes: triageOptions?.maxBytes ?? 64 * 1024 * 1024,
            yaraRulesDir: triageOptions?.yaraRulesDir ?? undefined,
          });
          counts[report.verdict] = (counts[report.verdict] ?? 0) + 1;
          rows.push(`- ${name}: ${report.verdict} (${report.confidence}) ${report.format} entropy=${report.entropy.overall} sha256=${report.file.sha256.slice(0, 16)}…`);
          await resultIndex?.record({
            at: new Date().toISOString(), tool: 'rea_triage', hasStructured: true,
            resultChars: 0, evidenceCount: 0, resultKind: `batch:${report.verdict}`,
            targetSha256: report.file.sha256,
          });
        } catch (error) {
          rows.push(`- ${name}: skipped (${error.message})`);
        }
      }
      const body = [`Batch triage — ${directory}`, `files examined: ${rows.length} of ${candidates.length} candidates`,
        `packed/protected: ${counts['likely-packed-or-protected']} | possibly obfuscated: ${counts['possibly-obfuscated']} | unpacked: ${counts['appears-unpacked']}`,
        '', ...rows].join('\n');
      const path = store ? await store.write('batch-triage.md', body) : null;
      return { text: `${body.slice(0, 6_000)}${path ? `\n\nFull report: ${path}` : ''}` };
    },
    isConcurrencySafe: () => true,
  };
}

/** Coarse two-sample comparison; a hint list, not a structural binary diff. */
export function buildDiffHintTool({ triageOptions }) {
  return {
    name: 'rea_diff_hint',
    description: 'Coarse local comparison of two binaries: entropy, section layout, sampled-string overlap, packer signatures and size delta. Produces a prioritised list of where to look first. This is NOT structural binary diffing (no CFG isomorphism or BSim); use Ghidra BSim/Diaphora for that.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        left: { type: 'string', description: 'Absolute path to the first (older) binary.' },
        right: { type: 'string', description: 'Absolute path to the second (newer) binary.' },
      },
      required: ['left', 'right'],
    },
    output: textOutput('(no diff hint)'),
    async execute(args) {
      for (const key of ['left', 'right']) {
        if (!isAbsolute(args?.[key] ?? '')) return { text: `${key} must be an absolute path.` };
      }
      const options = { maxBytes: triageOptions?.maxBytes ?? 64 * 1024 * 1024 };
      let a; let b; let samples;
      try {
        [a, b, samples] = await Promise.all([
          triageFile(args.left, options), triageFile(args.right, options),
          Promise.all([loadSample(args.left, options.maxBytes), loadSample(args.right, options.maxBytes)]),
        ]);
      } catch (error) {
        return { text: `diff could not read both files: ${error.message}` };
      }
      const [leftSample, rightSample] = samples;
      const leftApis = new Set(leftSample.imports?.apiFlat ?? []);
      const addedApis = (rightSample.imports?.apiFlat ?? []).filter((api) => !leftApis.has(api));
      const highRiskApis = addedApis.filter((api) => /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|WinHttp|InternetConnect|HttpSendRequest|RegSetValue|CreateService|CryptEncrypt|GetAsyncKeyState|NtQueryInformationProcess/i.test(api));
      const leftIocs = new Set(extractIocs(leftSample.strings).map((item) => item.value.toLowerCase()));
      const newNetwork = extractIocs(rightSample.strings).filter((item) => ['url', 'domain', 'ipv4'].includes(item.type) && !leftIocs.has(item.value.toLowerCase()));
      const leftStrings = new Set(leftSample.strings.map((item) => item.value));
      const rightStrings = new Set(rightSample.strings.map((item) => item.value));
      const union = new Set([...leftStrings, ...rightStrings]).size;
      const overlap = union > 0 ? [...rightStrings].filter((value) => leftStrings.has(value)).length / union : 0;
      const blockSet = (buffer) => {
        const hashes = new Set();
        for (let at = 0; at < buffer.length; at += 4096) {
          hashes.add(createHash('sha256').update(buffer.subarray(at, at + 4096)).digest('hex').slice(0, 16));
        }
        return hashes;
      };
      const leftBlocks = blockSet(leftSample.buffer);
      const rightBlocks = blockSet(rightSample.buffer);
      const sharedBlocks = [...rightBlocks].filter((hash) => leftBlocks.has(hash)).length;
      const blockSimilarity = rightBlocks.size > 0 ? (sharedBlocks / rightBlocks.size).toFixed(3) : 'n/a';
      const leftSections = new Map(a.sections.map((section) => [section.name, section]));
      const changed = b.sections.filter((section) => {
        const before = leftSections.get(section.name);
        return before === undefined || (before.entropy !== null && section.entropy !== null && Math.abs(before.entropy - section.entropy) >= 0.5);
      }).map((section) => `${section.name} (entropy ${leftSections.get(section.name)?.entropy ?? 'new'} → ${section.entropy})`);
      const added = [...rightStrings].filter((value) => !leftStrings.has(value)).slice(0, 12);
      const lines = [
        `Coarse diff hint — ${a.file.name} ↔ ${b.file.name}`,
        `size: ${a.file.size} → ${b.file.size} (${b.file.size - a.file.size >= 0 ? '+' : ''}${b.file.size - a.file.size})`,
        `format: ${a.format} → ${b.format}`,
        `entropy: ${a.entropy.overall} → ${b.entropy.overall}`,
        `verdict: ${a.verdict} → ${b.verdict}`,
        `sampled-string Jaccard: ${overlap.toFixed(3)} | 4 KB block overlap: ${blockSimilarity}`,
        '',
        'priority 1 · new high-risk imported APIs (strongest static signal):',
        ...(highRiskApis.length > 0 ? highRiskApis.slice(0, 12).map((api) => `- ${api}`) : [`- none (${addedApis.length} other new imports)`]),
        '',
        'priority 2 · new network indicators (untrusted sample data):',
        ...(newNetwork.length > 0 ? newNetwork.slice(0, 10).map((item) => `- ${item.type}: ${markUntrusted('ioc', item.value, { maxChars: 160 })}`) : ['- none in the sampled window']),
        '',
        'priority 3 · sections with changed entropy or new names:',
        ...(changed.length > 0 ? changed.map((line) => `- ${line}`) : ['- none detected at section granularity']),
        '',
        'priority 4 · new sampled strings (untrusted sample data):',
        ...(added.length > 0 ? [markUntrusted('strings', added.join(' | '), { maxChars: 1_500 })] : ['- none in the sampled window']),
        '',
        'Limits: sampled strings and imports only, no function-level matching, no CFG comparison. This is NOT structural binary diffing; use Ghidra BSim/Diaphora for that.',
        'Confirm candidates with batch_decompile + compare_functions before drawing conclusions.',
      ];
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Generate a fuzz harness skeleton from a recorded crash description. */
export function buildFuzzHarnessTool({ store }) {
  return {
    name: 'rea_fuzz_harness',
    description: 'Generate a libFuzzer / AFL++ harness template from a crash description or an inspect_recorded_crash result. Text generation only: never compiles, never runs a target. Review the stub before use.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        crash: { type: 'string', description: 'Crash description or JSON text from inspect_recorded_crash.' },
        language: { type: 'string', description: 'c (default), cpp, or rust.' },
      },
      required: ['crash'],
    },
    output: textOutput('(no harness)'),
    async execute(args) {
      const language = ['c', 'cpp', 'rust'].includes(args?.language) ? args.language : 'c';
      const crash = String(args?.crash ?? '');
      const signal = /(SIGSEGV|SIGABRT|SIGILL|EXCEPTION_ACCESS_VIOLATION|0x[0-9a-f]{8,})/i.exec(crash)?.[1] ?? 'unspecified signal';
      const template = language === 'rust'
        ? `#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\n// Crash under test: ${signal}\n// TODO: replace with the entry point that consumed the crashing input.\nfuzz_target!(|data: &[u8]| {\n    if data.is_empty() { return; }\n    let _ = target_entry(data);\n});\n`
        : `#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n\n/* Crash under test: ${signal} */\n/* TODO: declare and call the entry point that consumed the crashing input. */\nint target_entry(const uint8_t *data, size_t size);\n\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    if (size == 0) return 0;\n    uint8_t *copy = (uint8_t *)malloc(size);\n    if (!copy) return 0;\n    memcpy(copy, data, size);\n    target_entry(copy, size);\n    free(copy);\n    return 0;\n}\n`;
      const crashExcerpt = markUntrusted('crash-input', crash, { maxChars: 2_000 });
      const body = `# Fuzz harness template\n\n${crashExcerpt}\n\n\`\`\`${language}\n${template}\`\`\`\n\nBuild: clang -fsanitize=fuzzer,address harness.c target.c -o fuzz\nDedup: minimise the crashing input, then compare stack hashes before filing.\n`;
      const path = store ? await store.write(`fuzz-harness.${language === 'rust' ? 'rs' : 'c'}`, body) : null;
      return { text: `${body.slice(0, 3_000)}${path ? `\n\nSaved: ${path}` : ''}` };
    },
    isConcurrencySafe: () => true,
  };
}

/** Trusted playbook runner: one named script instead of hundreds of turns. */
export function buildPlaybookTool({ dir, timeoutMs, maxCalls, callTool, toolNames, store }) {
  return {
    name: 'rea_run_playbook',
    description: 'Run a trusted .mjs playbook from the playbook directory. The script can call REA tools via rea.call(name, args), which is guarded and audited like a normal call. TRUSTED CODE ONLY: this is a child process for isolation, not a sandbox against malicious scripts. Omit name to list installed playbooks.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        name: { type: 'string', description: 'Playbook file name, e.g. "rename-decryptors.mjs". Omit to list.' },
        input: { description: 'JSON value passed to the playbook as input.' },
      },
    },
    output: textOutput('(no playbook result)'),
    async execute(args) {
      const name = typeof args?.name === 'string' ? args.name.trim() : '';
      if (name.length === 0) {
        const available = await listPlaybooks(dir);
        return { text: `Playbook directory: ${dir}\nInstalled: ${available.length > 0 ? available.join(', ') : '(none)'}\nCreate a .mjs file exporting default async ({ rea, artifact, input }) => {...} to install one.` };
      }
      const outcome = await runPlaybook({
        dir, name, input: args?.input ?? {}, timeoutMs, maxCalls, callTool, toolNames,
      });
      const body = [
        `Playbook ${name}: ${outcome.ok ? 'completed' : `failed — ${outcome.error ?? 'see log'}`}`,
        `calls: ${outcome.calls} | duration: ${outcome.durationMs} ms`,
        '',
        'result:',
        outcome.result ?? '(none)',
        '',
        'log:',
        ...(outcome.logs.length > 0 ? outcome.logs.slice(0, 30).map((line) => `- ${line}`) : ['(empty)']),
      ].join('\n');
      if (outcome.ok && store) {
        await store.write('playbook-result.md', body);
      }
      return { text: body };
    },
    isConcurrencySafe: () => false,
  };
}

/** All workflow tools, as [definition, effect label] pairs. */
export function buildWorkflowTools({ resultIndex, triageOptions, maxBatch, store }) {
  return [
    [buildQueryResultsTool(resultIndex), 'dsh-rea: result index query'],
    [buildBatchTriageTool({ resultIndex, triageOptions, maxBatch, store }), 'dsh-rea: batch triage'],
    [buildDiffHintTool({ triageOptions }), 'dsh-rea: diff hint'],
    [buildFuzzHarnessTool({ store }), 'dsh-rea: fuzz harness'],
  ];
}
