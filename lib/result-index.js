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

import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const MAX_SCAN_LINES = 20_000;

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

export function createResultIndex({ base, maxScanLines = MAX_SCAN_LINES } = {}) {
  const file = join(base, 'results.jsonl');
  const store = {
    file,

    /** Append one bounded line. Failures are swallowed: indexing is best-effort. */
    async record(meta) {
      try {
        await mkdir(dirname(file), { recursive: true });
        await appendFile(file, `${JSON.stringify(meta)}\n`, 'utf8');
        return true;
      } catch {
        return false;
      }
    },

    /**
     * Filter the recent tail of the index. `keyword` matches tool name and
     * evidence IDs, `since` is an ISO timestamp, `minConfidence` applies only
     * to entries that carry a numeric confidence.
     */
    async query({ tool, since, minConfidence, evidenceId, keyword, limit = 20 } = {}) {
      let body;
      try { body = await readFile(file, 'utf8'); } catch { return []; }
      const lines = body.split('\n').filter(Boolean).slice(-maxScanLines);
      const items = [];
      for (const line of lines) {
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
      return matched.slice(-cap).reverse();
    },
  };
  return store;
}
