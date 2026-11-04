/**
 * Reverse-engineering and anti-tracking tools built on the local intel core.
 *
 * All four read a file (or a supplied text) and never execute the sample,
 * call an engine, or touch the network. Sample-derived strings are wrapped
 * as untrusted data before they reach the model.
 *
 * @module dsh-rea/lib/intel-tools
 */

import { open, stat } from 'node:fs/promises';

import {
  antiAnalysisMatrix, capabilityProfile, collectEnvTokens, detectLeaks,
  extractIocs, parsePEImports, sanitizeText, summarizeIocs, trackingSurface,
  analystExposure,
} from './intel.js';
import { channelSummary, extractDeepStrings } from './strings.js';
import { markUntrusted } from './tools.js';

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;

const textOutput = (fallback) => ({
  schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
  render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : fallback }]; },
});

async function loadSample(path, cap = DEFAULT_MAX_BYTES) {
  const pathString = String(path ?? '');
  const info = await stat(pathString);
  if (!info.isFile()) throw new Error(`${pathString} is not a regular file`);
  const size = Math.min(info.size, cap);
  const handle = await open(pathString, 'r');
  const buffer = Buffer.alloc(size);
  try { await handle.read(buffer, 0, size, 0); } finally { await handle.close(); }
  return {
    buffer,
    path: pathString,
    size: info.size,
    truncated: info.size > size,
    strings: extractDeepStrings(buffer, { minLength: 5, maxStrings: 4_000 }),
    imports: parsePEImports(buffer),
  };
}

const toolNames = (triageOptions) => triageOptions?.availableTools ?? null;

function fileHeader(sample) {
  return [
    `file: ${sample.path}`,
    `size: ${sample.size} bytes${sample.truncated ? ' (read capped)' : ''}`,
    `strings sampled: ${sample.strings.length} (${Object.entries(channelSummary(sample.strings)).map(([k, v]) => `${k}=${v}`).join(', ')})`,
    `PE imports: ${sample.imports ? `${sample.imports.dlls.length} DLLs / ${sample.imports.apiFlat.length} APIs` : 'not a PE (or no import table)'}`,
  ];
}

/** Structured indicators plus an import-driven capability profile. */
export function buildIocExtractTool({ store, maxBytes = DEFAULT_MAX_BYTES, triageOptions }) {
  return {
    name: 'rea_ioc_extract',
    description: 'Extract structured indicators of compromise from a local file without executing it: URLs, domains, IPs, emails, registry keys, PDB paths, wallet addresses, user agents, named pipes. Also parses the PE import table and maps imported APIs to ATT&CK-style capability hints. Results are deduplicated and saved as JSON. Use this early to decide what to verify dynamically.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Absolute path of the sample or text file.' },
        detail: { type: 'boolean', description: 'Include every indicator (up to 120) instead of the top 8 per type. Defaults to false.' },
      },
      required: ['path'],
    },
    output: textOutput('(no indicators)'),
    async execute(args) {
      let sample;
      try { sample = await loadSample(args?.path, maxBytes); } catch (error) { return { text: `rea_ioc_extract: ${error.message}` }; }
      const iocs = extractIocs(sample.strings);
      const tracking = trackingSurface(sample.strings, sample.imports);
      const profile = capabilityProfile({ imports: sample.imports, strings: sample.strings, tracking });
      const summary = summarizeIocs(iocs);
      const byType = new Map();
      for (const ioc of iocs) {
        if (!byType.has(ioc.type)) byType.set(ioc.type, []);
        byType.get(ioc.type).push(ioc);
      }
      const lines = [
        'Static indicators (no execution, no network)',
        ...fileHeader(sample),
        `indicators: ${summary.total} (${Object.entries(summary.byType).map(([k, v]) => `${k}=${v}`).join(', ') || 'none'}; ${summary.derived} recovered from XOR/base64 and need manual verification)`,
        '',
      ];
      const limit = args?.detail === true ? 120 : 8;
      for (const [type, items] of byType) {
        const confirmed = items.filter((item) => !item.derived);
        const recovered = items.filter((item) => item.derived);
        lines.push(`${type} (${confirmed.length} confirmed${recovered.length > 0 ? `, ${recovered.length} recovered` : ''}):`);
        for (const item of confirmed.slice(0, limit)) {
          lines.push(`  @${item.at ?? '?'} ${markUntrusted('ioc', item.value, { maxChars: 200 })}`);
        }
        if (confirmed.length > limit) lines.push(`  … ${confirmed.length - limit} more; use detail=true`);
        for (const item of recovered.slice(0, 6)) {
          lines.push(`  [${item.encoding}] ${markUntrusted('recovered-ioc', item.value, { maxChars: 200 })} — verify manually`);
        }
      }
      lines.push('', 'Recovered indicators come from single-byte XOR or base64 decoding and carry a higher false-positive rate; treat them as leads, not confirmed infrastructure.');
      if (sample.imports && !sample.imports.empty) {
        lines.push('', 'high-signal imported APIs:');
        const risky = sample.imports.apiFlat.filter((api) => /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThread|SetWindowsHookEx|GetAsyncKeyState|WinHttp|InternetConnect|HttpSendRequest|RegSetValue|CreateService|CryptEncrypt|BitBlt|GetDC|GetComputerName|GetAdaptersInfo|IsDebuggerPresent|NtQueryInformationProcess/i.test(api));
        lines.push(risky.length > 0 ? `  ${risky.slice(0, 24).join(', ')}` : '  (no high-signal import matched)');
        lines.push('', 'imported DLLs:');
        for (const dll of sample.imports.dlls.slice(0, 20)) lines.push(`  ${markUntrusted('dll', dll.name, { maxChars: 120 })}: ${dll.functions.length} functions`);
      }
      lines.push('', 'capability hints (verify against disassembly, not observed behaviour):');
      if (profile.capabilities.length === 0) lines.push('  none matched');
      for (const item of profile.capabilities) lines.push(`  ${item.id} ${item.name} [${item.confidence}] — ${item.evidence.slice(0, 3).join(', ')}`);
      lines.push('', profile.limitations);
      if (store?.write) {
        const saved = await store.write('ioc-extract.json', JSON.stringify({
          file: sample.path, size: sample.size, iocs, imports: sample.imports,
          tracking, capabilities: profile.capabilities,
        }, null, 2));
        lines.push('', `full JSON: ${saved}`);
      }
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Tracking / fingerprinting surface of a sample. */
export function buildTrackingSurfaceTool({ maxBytes = DEFAULT_MAX_BYTES, triageOptions }) {
  return {
    name: 'rea_tracking_surface',
    description: 'Map how a sample can track a person or device: analytics/telemetry SDKs, advertising and device identifiers, browser and host fingerprinting APIs, location collection, persistent tracking state, clipboard/contacts access, attribution and egress endpoints. Returns categories, severity, evidence strings and an overall level. Pure static parsing; no execution and no network.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Absolute path of the sample.' },
        detail: { type: 'boolean', description: 'Show every matched marker per family. Defaults to false.' },
      },
      required: ['path'],
    },
    output: textOutput('(no tracking surface)'),
    async execute(args) {
      let sample;
      try { sample = await loadSample(args?.path, maxBytes); } catch (error) { return { text: `rea_tracking_surface: ${error.message}` }; }
      const report = trackingSurface(sample.strings, sample.imports);
      const iocs = extractIocs(sample.strings);
      const network = iocs.filter((item) => ['url', 'domain', 'ipv4'].includes(item.type));
      const lines = [
        'Tracking and fingerprinting surface',
        ...fileHeader(sample),
        `level: ${report.level} (score ${report.score})`,
        `categories: ${report.categories.join(', ') || 'none'}`,
        '',
      ];
      if (report.findings.length === 0) lines.push('No known tracking markers in the sampled strings/imports. Encrypted or dynamically resolved indicators cannot be ruled out.');
      for (const item of report.findings) {
        lines.push(`[${item.severity}] ${item.label} — ${item.markerCount} markers`);
        for (const evidence of item.evidence.slice(0, args?.detail === true ? 8 : 3)) {
          lines.push(`  ${markUntrusted('marker', evidence, { maxChars: 160 })}`);
        }
      }
      lines.push('', `network indicators: ${network.length}`);
      for (const item of network.slice(0, 12)) lines.push(`  ${item.type}: ${markUntrusted('ioc', item.value, { maxChars: 160 })}`);
      lines.push('', 'analyst notes (do not use as evasion guidance):');
      lines.push('- Treat every marker as a hypothesis; confirm with xrefs or a recorded trace before attributing tracking behaviour.');
      lines.push('- If the sample will be executed, isolate the analysis network first; the plugin itself never connects to a sample endpoint.');
      lines.push('- Reports containing these indicators also contain local paths — run rea_sanitize_report before sharing.');
      lines.push('', report.limitations);
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Anti-debugging / anti-VM / anti-hook technique matrix with real next steps. */
export function buildAntiAnalysisTool({ maxBytes = DEFAULT_MAX_BYTES, triageOptions }) {
  return {
    name: 'rea_anti_analysis',
    description: 'Identify static signs of anti-analysis: debugger presence APIs, hardware breakpoint checks, timing loops, CPUID/hypervisor and VM artifacts, sandbox heuristics, inline-hook and instrumentation detection, anti-dump protection, self-integrity checks and TLS callbacks. Each matched technique carries evidence, a defensive analysis countermeasure, and only tools the running REA server actually advertises. Pure static parsing; suggests analysis steps, never evasion.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Absolute path of the sample.' },
      },
      required: ['path'],
    },
    output: textOutput('(no anti-analysis matrix)'),
    async execute(args) {
      let sample;
      try { sample = await loadSample(args?.path, maxBytes); } catch (error) { return { text: `rea_anti_analysis: ${error.message}` }; }
      const report = antiAnalysisMatrix(sample.strings, sample.imports, toolNames(triageOptions));
      const lines = [
        'Anti-analysis technique matrix',
        ...fileHeader(sample),
        `techniques: ${report.techniques.length} (${report.categories.join(', ') || 'none'})`,
        '',
      ];
      if (report.techniques.length === 0) lines.push('No known anti-analysis markers matched. Packed samples and custom checks will not be visible statically.');
      for (const item of report.techniques) {
        lines.push(`[${item.category}] ${item.technique}`);
        lines.push(`  evidence: ${markUntrusted('markers', item.evidence.join(' | '), { maxChars: 400 })}`);
        lines.push(`  countermeasure: ${item.countermeasure}`);
        lines.push(`  next tools: ${item.nextTools.length > 0 ? item.nextTools.join(', ') : '(none advertised for this technique)'}`);
      }
      lines.push('', report.limitations);
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Detect and remove analyst-environment identifiers before sharing a report. */
export function buildSanitizeReportTool({ store, env = process.env }) {
  return {
    name: 'rea_sanitize_report',
    description: 'Check or sanitise a report before sharing it: finds local usernames, home paths, hostnames, absolute Windows/Unix paths, IPs, emails, MAC addresses, tokens, API keys and proxy credentials that would identify the analyst machine. mode=check only lists leaks; mode=sanitize replaces them with stable placeholders and saves a clean copy. Never executes the sample and never sends data anywhere.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        text: { type: 'string', description: 'Report text to check or sanitise. Use this OR path.' },
        path: { type: 'string', description: 'Absolute path of a report file to check or sanitise.' },
        mode: { type: 'string', enum: ['check', 'sanitize'], description: 'Defaults to check.' },
      },
    },
    output: textOutput('(no report)'),
    async execute(args) {
      const tokens = collectEnvTokens(env);
      let body = typeof args?.text === 'string' ? args.text : '';
      let source = 'supplied text';
      if (!body && typeof args?.path === 'string') {
        try {
          const sample = await loadSample(args.path, 8 * 1024 * 1024);
          body = sample.buffer.toString('utf8');
          source = args.path;
        } catch (error) { return { text: `rea_sanitize_report: ${error.message}` }; }
      }
      if (!body) return { text: 'rea_sanitize_report: supply either text or path.' };
      const mode = args?.mode === 'sanitize' ? 'sanitize' : 'check';
      const lines = [`Report exposure check — ${source}`, `mode: ${mode}`, `characters: ${body.length}`, ''];
      if (mode === 'check') {
        const leaks = detectLeaks(body, tokens);
        if (leaks.length === 0) lines.push('No analyst-environment identifiers or secret patterns found.');
        else {
          lines.push(`findings: ${leaks.length} kinds / ${leaks.reduce((n, item) => n + item.count, 0)} occurrences`);
          for (const item of leaks) lines.push(`  [${item.kind}] ${markUntrusted('leak', item.sample, { maxChars: 120 })} ×${item.count}`);
          lines.push('', 'Run with mode="sanitize" to produce a shareable copy; review it before publishing.');
        }
        return { text: lines.join('\n') };
      }
      const clean = sanitizeText(body, tokens);
      lines.push(`leaks detected: ${clean.leaks.reduce((n, item) => n + item.count, 0)}`);
      for (const item of clean.replacements) lines.push(`  ${item.kind} → ${item.placeholder} (${item.count})`);
      if (clean.replacements.length === 0) lines.push('  nothing to replace');
      lines.push('', 'Remaining findings after sanitisation (should be empty):');
      const remaining = detectLeaks(clean.text, tokens);
      lines.push(remaining.length === 0 ? '  none' : remaining.map((item) => `  [${item.kind}] ${item.sample}`).join('\n'));
      if (store?.write) {
        const saved = await store.write('sanitized-report.txt', clean.text);
        lines.push('', `clean copy: ${saved}`);
      }
      lines.push('', `preview (first 1200 chars):\n${clean.text.slice(0, 1_200)}`);
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Anti-tracking: map how the app owner could link this analysis back to you. */
export function buildAnalystExposureTool({ maxBytes = DEFAULT_MAX_BYTES, triageOptions }) {
  return {
    name: 'rea_analyst_exposure',
    description: 'Anti-tracking preflight for reverse engineering: when you analyse an app, its owner may collect account IDs, install/advertising identifiers, push tokens, IP and User-Agent, device/browser fingerprints and behavioural telemetry that link the session back to you. This tool maps that linkage chain from static evidence, lists every telemetry endpoint found (including XOR/base64/UTF-16 hidden ones), prints hosts-style block rules as TEXT ONLY, and gives a defensive preflight checklist. It never modifies your system, never connects anywhere, and is not evasion or impersonation guidance.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Absolute path of the app / sample to evaluate.' },
        mode: { type: 'string', enum: ['full', 'matrix', 'endpoints', 'preflight'], description: 'Defaults to full.' },
      },
      required: ['path'],
    },
    output: textOutput('(no exposure report)'),
    async execute(args) {
      let sample;
      try { sample = await loadSample(args?.path, maxBytes); } catch (error) { return { text: `rea_analyst_exposure: ${error.message}` }; }
      const iocs = extractIocs(sample.strings);
      const tracking = trackingSurface(sample.strings, sample.imports);
      const exposure = analystExposure({ tracking, iocs, imports: sample.imports, strings: sample.strings });
      const mode = ['matrix', 'endpoints', 'preflight'].includes(args?.mode) ? args.mode : 'full';
      const lines = [
        'Analyst exposure / anti-tracking preflight',
        ...fileHeader(sample),
        `level: ${exposure.level} | linkage chains: ${exposure.chains.length} | endpoints: ${exposure.endpoints.length}`,
        `dynamically resolved API hints: ${exposure.dynamicApis.length > 0 ? exposure.dynamicApis.slice(0, 12).join(', ') : 'none (no GetProcAddress/LoadLibrary style loader seen)'}`,
        '',
      ];
      if (mode === 'full' || mode === 'matrix') {
        lines.push('identity linkage chains (observed in static evidence):');
        if (exposure.chains.length === 0) lines.push('  none matched — not proof that the app collects nothing');
        for (const chain of exposure.chains) {
          lines.push(`[${chain.severity}] ${chain.identifier}`);
          lines.push(`  risk: ${chain.risk}`);
          lines.push(`  evidence: ${markUntrusted('markers', chain.evidence.join(' | '), { maxChars: 400 })}`);
          lines.push(`  mitigation: ${chain.mitigation}`);
        }
        lines.push('');
      }
      if (mode === 'full' || mode === 'endpoints') {
        lines.push('telemetry / egress endpoints (including recovered hidden strings):');
        lines.push(exposure.endpoints.length === 0 ? '  none found statically' : exposure.endpoints.slice(0, 40).map((item) => `  ${markUntrusted('ioc', item, { maxChars: 200 })}${exposure.recoveredEndpoints.includes(item) ? '  [recovered — verify before blocking]' : ''}`).join('\n'));
        lines.push(`  ${exposure.recoveredEndpoints.length} of ${exposure.endpoints.length} endpoints were recovered from XOR/base64 and carry a higher false-positive rate.`);
        lines.push('', 'hosts-style block rules (TEXT ONLY — this tool never modifies your system):');
        lines.push(exposure.blockRules.length === 0 ? '  (no host to block)' : exposure.blockRules.map((rule) => `  ${rule}`).join('\n'));
        lines.push('');
      }
      if (mode === 'full' || mode === 'preflight') {
        lines.push('preflight checklist:');
        exposure.preflight.forEach((item, index) => lines.push(`  ${index + 1}. ${item}`));
        lines.push('');
      }
      lines.push(exposure.limitations);
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

export function buildIntelTools({ store, maxBytes, triageOptions, env }) {
  return [
    [buildIocExtractTool({ store, maxBytes, triageOptions }), 'dsh-rea: ioc extract'],
    [buildTrackingSurfaceTool({ maxBytes, triageOptions }), 'dsh-rea: tracking surface'],
    [buildAntiAnalysisTool({ maxBytes, triageOptions }), 'dsh-rea: anti-analysis matrix'],
    [buildAnalystExposureTool({ maxBytes, triageOptions }), 'dsh-rea: analyst exposure'],
    [buildSanitizeReportTool({ store, env }), 'dsh-rea: report sanitizer'],
  ];
}

export { loadSample, parsePEImports };
