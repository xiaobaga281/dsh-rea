/**
 * Attacker persona: use the shipped product, not the library internals.
 *
 * Every number here comes out of a tool that the plugin actually registers, so
 * the score reflects what an analyst sees in the report - including formatting
 * and truncation - rather than what a private helper could return.
 *
 * Nothing is executed; the sample is only read.
 */
import { readFileSync } from 'node:fs';

import { apply } from '../../index.js';
import { APIS, BEHAVIOURS, CANARY, ENDPOINTS, IOC_TEXT, PLAN } from './truth.mjs';

const TRUTH_VALUES = new Set([...ENDPOINTS, ...IOC_TEXT, ...CANARY]);

/** Boot the plugin the same way the host does, then keep the tool map. */
export async function loadTools({ cwd } = {}) {
  const registered = new Map();
  const ctx = {
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    tools: { register(descriptor) { registered.set(descriptor.name, descriptor); return () => registered.delete(descriptor.name); } },
    webServer: { register() { return () => {}; } },
    effect(fn) { fn(); return () => {}; },
    ...(cwd ? { cwd } : {}),
  };
  await apply(ctx, { catalogProbe: false });
  return registered;
}

function textOf(result) {
  if (!result) return '';
  if (typeof result === 'string') return result;
  if (typeof result.text === 'string') return result.text;
  // rea_triage returns { report }, rea_ioc_extract returns structured content
  // with a text block; both are "what the analyst sees".
  if (typeof result.report === 'string') return result.report;
  if (Array.isArray(result)) return result.map(textOf).join('\n');
  return '';
}

async function call(tools, name, args) {
  const tool = tools.get(name);
  if (!tool?.execute) return { ok: false, text: '', missing: true };
  try {
    return { ok: true, text: textOf(await tool.execute(args)) };
  } catch (error) {
    return { ok: false, text: '', error: error.message };
  }
}

/** The IoC tool persists the full structured result; read it back. */
function readSavedJson(text) {
  const match = String(text).match(/full JSON:\s*(.+)\s*$/m);
  if (!match) return null;
  try { return JSON.parse(readFileSync(match[1].trim(), 'utf8')); } catch { return null; }
}

/**
 * Technique identity, not its evidence list. The report prints at most a few
 * evidence markers per technique, so marker-level recall measures the printer's
 * truncation rather than the analyser's reach.
 */
function techniqueLines(text) {
  return [...String(text).matchAll(/^\[([a-z-]+)\]\s+(.+)$/gm)].map((match) => `${match[1]}| ${match[2].trim()}`);
}

/**
 * Run the analysis and return only what the reports exposed. The caller
 * decides what counts as a hit.
 */
export async function attack(tools, path) {
  const ioc = await call(tools, 'rea_ioc_extract', { path, detail: true });
  const tracking = await call(tools, 'rea_tracking_surface', { path, detail: true });
  const anti = await call(tools, 'rea_anti_analysis', { path });
  const exposure = await call(tools, 'rea_analyst_exposure', { path });
  // The analyst-level questions - what is it built from, what is it for, what
  // would settle what is still unknown - are answered by triage, so they are
  // scored from triage's own report rather than from a private helper.
  const triage = await call(tools, 'rea_triage', { path });
  const triageText = triage.text;

  const saved = readSavedJson(ioc.text);
  const values = new Set();
  const types = new Map();
  if (saved?.iocs) {
    for (const item of saved.iocs) {
      values.add(String(item.value));
      if (!types.has(item.type)) types.set(item.type, new Set());
      types.get(item.type).add(String(item.value));
    }
  } else {
    // Fallback: scrape "  @offset value" / "[channel] value — verify manually".
    for (const line of ioc.text.split('\n')) {
      const cleaned = line.replace(/^\s*(?:@\d+\s+|\[[^\]]+\]\s+)/, '').replace(/\s+—\s+verify manually\s*$/, '').trim();
      if (!cleaned || /^[a-z ]+\(/.test(cleaned) || cleaned.startsWith('file:')) continue;
      values.add(cleaned);
    }
  }

  const trackingIds = new Set((saved?.tracking?.findings ?? []).map((item) => item.id));
  const antiTechniques = new Set(techniqueLines(anti.text));
  const allText = [ioc.text, tracking.text, anti.text, exposure.text].join('\n');
  const watermarks = CANARY.filter((value) => allText.includes(value));
  const endpoints = ENDPOINTS.filter((url) => values.has(url));
  const iocText = IOC_TEXT.filter((value) => [...values].some((item) => item.includes(value)));
  const noise = [...values].filter((value) => !TRUTH_VALUES.has(value)
    && ![ENDPOINTS, IOC_TEXT].flat().some((truth) => value.includes(truth)));
  const unresolved = /unresolved encrypted region/i.test(ioc.text);

  // Names and behaviours are matched case-insensitively against the report an
  // analyst would read, never read back from the module that produced them.
  const apiHits = APIS.filter((api) => new RegExp(`\\b${api}\\b`, 'i').test(triageText));
  const behaviorHits = BEHAVIOURS.filter((label) => triageText.toLowerCase().includes(label.toLowerCase()));
  // Run the first machine-readable probe the report offers. A confirm step
  // that cannot be executed is a wish; this is where it gets tested.
  const probeMatch = triageText.match(/probe:\s*([a-z_]+)\s*@\s*(0x[0-9a-f]+)/i);
  let probe = null;
  if (probeMatch) {
    const [, toolName, address] = probeMatch;
    const opened = await call(tools, 'mcp__rea__open_binary', { path });
    const result = await call(tools, `mcp__rea__${toolName}`, { address });
    const textProbe = result.text.slice(0, 4000);
    const named = /"name"\s*:\s*\{\s*"state"\s*:\s*"available"\s*,\s*"value"\s*:\s*"([^"]+)"/.exec(textProbe);
    probe = {
      tool: toolName,
      address,
      opened: opened.ok,
      ok: result.ok && /"state"\s*:\s*"available"/.test(textProbe),
      name: named?.[1] ?? null,
      excerpt: textProbe.slice(0, 300),
    };
  }

  const planAt = triageText.toLowerCase().indexOf('experiments (ranked');
  const planBlock = planAt >= 0 ? triageText.slice(planAt) : '';
  const planOk = planBlock.length > 0
    && new RegExp(PLAN.hook, 'i').test(planBlock)
    && PLAN.action.test(planBlock);

  return {
    path,
    ok: ioc.ok && tracking.ok && anti.ok && exposure.ok && triage.ok,
    triageOk: triage.ok,
    errors: [ioc, tracking, anti, exposure, triage].filter((item) => !item.ok).map((item) => item.error ?? 'missing tool'),
    endpoints,
    iocText,
    trackingIds: [...trackingIds],
    antiTechniques: [...antiTechniques],
    watermarks,
    unresolved,
    apiHits,
    behaviorHits,
    planOk,
    probe,
    planExcerpt: planBlock.split('\n').slice(0, 6).join('\n'),
    noise,
    indicatorCount: values.size,
    types: Object.fromEntries([...types].map(([type, set]) => [type, set.size])),
    excerpts: {
      ioc: ioc.text.split('\n').slice(0, 6).join('\n'),
      exposure: exposure.text.split('\n').slice(0, 4).join('\n'),
      structure: triageText.split('\n').find((line) => line.startsWith('structure:')) ?? '',
      behaviour: triageText.split('\n').find((line) => line.startsWith('behaviour:')) ?? '',
    },
  };
}
