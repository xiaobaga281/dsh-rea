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
import { CANARY, ENDPOINTS, IOC_TEXT } from './truth.mjs';

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

  return {
    path,
    ok: ioc.ok && tracking.ok && anti.ok && exposure.ok,
    errors: [ioc, tracking, anti, exposure].filter((item) => !item.ok).map((item) => item.error ?? 'missing tool'),
    endpoints,
    iocText,
    trackingIds: [...trackingIds],
    antiTechniques: [...antiTechniques],
    watermarks,
    unresolved,
    noise,
    indicatorCount: values.size,
    types: Object.fromEntries([...types].map(([type, set]) => [type, set.size])),
    excerpts: {
      ioc: ioc.text.split('\n').slice(0, 6).join('\n'),
      exposure: exposure.text.split('\n').slice(0, 4).join('\n'),
    },
  };
}
