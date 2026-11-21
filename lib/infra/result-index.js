/**
 * Cross-session result index and structured-result snapshots.
 *
 * REA returns a rich `structuredContent` envelope (evidence_id, confidence,
 * coverage, provider, limitations). The bridge flattens it to text for the
 * model, which is right for context and wrong for reuse: those fields are the
 * only machine-readable anchors an analysis has. This module records a small
 * sidecar per call into one append-only JSONL file outside the session
 * directories, so results survive expiry and can be queried later.
 *
 * JSONL rather than SQLite: no native dependency, no version-gated API, and a
 * plain file remains greppable and easy to back up. Entries are bounded and the
 * query reads at most the last `maxScan` lines.
 *
 * @module dsh-rea/lib/result-index
 */

import { appendFile, mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';

const MAX_SCAN_LINES = 20_000;
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_RETENTION_DAYS = 30;
const COMPACT_EVERY = 100;
const GENESIS = '0'.repeat(64);

const asArray = (value) => (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value]);

/** Pull the useful anchors out of any of REA's result envelope shapes. */
export function snapshotMeta(toolName, result, text) {
  const raw = result?.structuredContent;
  let payload = raw;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch { payload = null; }
  }
  if (!payload || typeof payload !== 'object') {
    // A text result may still be a JSON envelope returned in the text block.
    if (typeof text === 'string' && text.trimStart().startsWith('{')) {
      try { payload = JSON.parse(text); } catch { payload = null; }
    }
  }
  const body = payload?.result && typeof payload.result === 'object'
    ? { ...payload, ...payload.result } : (payload ?? {});
  const evidence = asArray(body.evidence ?? body.records ?? body.observations ?? body.items);
  const evidenceIds = evidence
    .map((item) => item?.evidence_id ?? item?.evidenceId ?? item?.id)
    .filter((id) => typeof id === 'string').slice(0, 40);
  const confidence = body.confidence ?? body.normalized_result?.confidence ?? null;
  const coverage = body.coverage ?? body.coverage_summary ?? body.normalized_result?.coverage ?? null;
  const resultKind = body.predicate_type ?? body.operation ?? body.kind ?? null;
  const hasStructured = Boolean(raw !== undefined && raw !== null);
  return {
    at: new Date().toISOString(),
    tool: String(toolName),
    hasStructured,
    resultChars: typeof text === 'string' ? text.length : 0,
    evidenceIds: evidenceIds.length > 0 ? evidenceIds : undefined,
    evidenceCount: evidenceIds.length,
    confidence: typeof confidence === 'number' ? confidence : undefined,
    coverageKeys: coverage && typeof coverage === 'object' ? Object.keys(coverage).slice(0, 20) : undefined,
    provider: body.provider?.id ?? body.provider?.name ?? (typeof body.provider === 'string' ? body.provider : undefined),
    resultKind: typeof resultKind === 'string' ? resultKind : undefined,
  };
}

export function createResultIndex({ base, maxScanLines = MAX_SCAN_LINES, maxBytes = DEFAULT_MAX_BYTES, retentionDays = DEFAULT_RETENTION_DAYS, now = () => Date.now() } = {}) {
  const file = join(base, 'results.jsonl');
  const hashLine = (line) => createHash('sha256').update(line).digest('hex');
  let lastHash = null;
  let writes = 0;
  // One serial append queue: 157 read-only tools may finish in the same tick,
  // and interleaved appendFile calls are not a safe way to write JSONL.
  let chain = Promise.resolve();

  const parseLines = (body) => body.split('\n').filter(Boolean);

  async function tailHash() {
    if (lastHash !== null) return lastHash;
    try {
      const lines = parseLines(await readFile(file, 'utf8'));
      const last = lines[lines.length - 1];
      lastHash = last ? (JSON.parse(last).hash ?? hashLine(last)) : GENESIS;
    } catch {
      lastHash = GENESIS;
    }
    return lastHash;
  }

  /** Drop expired lines, then trim from the front until under 75% of the cap. */
  async function compact() {
    let info;
    try { info = await stat(file); } catch { return { removed: 0, bytes: 0 }; }
    let lines;
    try { lines = parseLines(await readFile(file, 'utf8')); } catch { return { removed: 0, bytes: 0 }; }
    const cutoff = now() - Math.max(0, retentionDays) * 24 * 60 * 60 * 1000;
    let kept = lines.filter((line) => {
      let at = 0;
      try { at = Date.parse(JSON.parse(line).at) || 0; } catch { return true; }
      return !at || at >= cutoff;
    });
    let bytes = kept.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0);
    const target = Math.floor(maxBytes * 0.75);
    while (kept.length > 1 && (info.size > maxBytes && bytes > target || bytes > maxBytes)) {
      bytes -= Buffer.byteLength(kept.shift()) + 1;
    }
    if (kept.length === lines.length && info.size <= maxBytes) return { removed: 0, bytes };
    const tmp = `${file}.tmp`;
    await writeFile(tmp, kept.length > 0 ? `${kept.join('\n')}\n` : '', 'utf8');
    await rename(tmp, file);
    const last = kept[kept.length - 1];
    lastHash = last ? (JSON.parse(last).hash ?? hashLine(last)) : GENESIS;
    return { removed: lines.length - kept.length, bytes };
  }

  async function append(meta) {
    await mkdir(dirname(file), { recursive: true });
    const prevHash = await tailHash();
    const body = JSON.stringify({ ...meta, prevHash });
    const hash = hashLine(body);
    await appendFile(file, `${JSON.stringify({ ...meta, prevHash, hash })}\n`, 'utf8');
    lastHash = hash;
    if (++writes % COMPACT_EVERY === 0) await compact();
    return true;
  }

  async function queryDetailed({ tool, since, minConfidence, evidenceId, keyword, limit = 20 } = {}) {
    let body;
    try { body = await readFile(file, 'utf8'); } catch { return { items: [], truncated: false, scanned: 0, totalLines: 0 }; }
    const all = parseLines(body);
    const scanned = all.slice(-maxScanLines);
    const items = [];
    for (const line of scanned) {
      try { items.push(JSON.parse(line)); } catch {}
    }
    const needle = typeof keyword === 'string' ? keyword.toLowerCase() : '';
    const floor = Number.isFinite(minConfidence) ? minConfidence : null;
    const matched = items.filter((item) => {
      if (tool && !String(item.tool).includes(tool)) return false;
      if (since && String(item.at) < since) return false;
      if (floor !== null && !(typeof item.confidence === 'number' && item.confidence >= floor)) return false;
      if (evidenceId && !(item.evidenceIds ?? []).includes(evidenceId)) return false;
      if (needle) {
        const haystack = `${item.tool} ${(item.evidenceIds ?? []).join(' ')} ${item.resultKind ?? ''}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
    const cap = Number.isFinite(limit) ? Math.min(Math.max(Math.floor(limit), 1), 200) : 20;
    return {
      items: matched.slice(-cap).reverse(),
      truncated: all.length > maxScanLines,
      scanned: scanned.length,
      totalLines: all.length,
    };
  }

  const store = {
    file,
    compact,

    /** Append one bounded line. Failures are swallowed: indexing is best-effort. */
    record(meta) {
      const next = chain.then(() => append(meta)).catch(() => false);
      chain = next;
      return next;
    },

    /** Backwards-compatible array result; use queryDetailed for truncation info. */
    async query(options) {
      return (await queryDetailed(options)).items;
    },

    queryDetailed,
  };
  return store;
}
