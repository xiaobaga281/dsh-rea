/**
 * Human- and machine-readable exports for REA's Evidence bundles.
 *
 * REA only emits JSON. That is fine for a program and poor for everything
 * else: a report a person can archive, and a SARIF file a CI system can ingest,
 * are both cheap to derive from the same bundle. Both are deterministic pure
 * functions of the bundle so they can be tested without a running child.
 *
 * The bundle shape is deliberately tolerated rather than asserted: upstream
 * nests things under `result`, uses `records`/`observations` interchangeably,
 * and describes unknowns in more than one way. A missing field is rendered as
 * "not stated" rather than crashing the export.
 *
 * @module dsh-rea/lib/export
 */

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function text(value, fallback = 'not stated') {
  if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map((item) => text(item, '')).filter(Boolean).join('; ') || fallback;
  if (value && typeof value === 'object') {
    try { return JSON.stringify(value); } catch { return fallback; }
  }
  return fallback;
}

function unwrap(input) {
  let bundle = input;
  if (typeof bundle === 'string') {
    try { bundle = JSON.parse(bundle); } catch { return {}; }
  }
  if (!bundle || typeof bundle !== 'object') return {};
  // A tool result commonly wraps the payload in `result`, or `bundle`.
  return bundle.result && typeof bundle.result === 'object' ? { ...bundle, ...bundle.result }
    : bundle.bundle && typeof bundle.bundle === 'object' ? { ...bundle, ...bundle.bundle }
      : bundle;
}

function normalizeEvidence(records) {
  return asArray(records).map((record, index) => {
    const item = record && typeof record === 'object' ? record : { value: record };
    const limitation = item.limitation ?? item.limitations ?? item.coverage ?? item.coverage_limits;
    return {
      id: text(item.id ?? item.evidence_id ?? item.evidenceId ?? item.uid, `E${index + 1}`),
      observation: text(item.observation ?? item.summary ?? item.description ?? item.text ?? item.value, 'not stated'),
      limitation: text(limitation, 'not stated'),
      confidence: item.confidence ?? item.certainty ?? null,
      kind: text(item.kind ?? item.type ?? item.source, 'unspecified'),
      location: item.address ?? item.location ?? item.artifact ?? null,
      inferred: item.inferred === true || /infer|decompil|reconstruct|pseudo/i.test(text(item.kind ?? item.type, '')),
    };
  });
}

function normalizeUnknowns(records) {
  return asArray(records).map((record, index) => {
    const item = record && typeof record === 'object' ? record : { value: record };
    const severity = String(item.severity ?? item.priority ?? 'unknown').toLowerCase();
    const level = /high|critical|blocker/.test(severity) ? 'error'
      : /medium|moderate/.test(severity) ? 'warning' : 'note';
    return {
      id: text(item.id ?? item.unknown_id ?? item.uid, `U${index + 1}`),
      question: text(item.question ?? item.description ?? item.summary ?? item.text ?? item.value, 'not stated'),
      severity: text(item.severity ?? item.priority, 'unknown'),
      authority: text(item.required_authority_level ?? item.requiredAuthority ?? item.authority ?? item.authority_level, 'not stated'),
      status: text(item.status ?? item.resolution_state, 'open'),
      level,
    };
  });
}

/** Normalize any of REA's bundle shapes into one flat structure. */
export function normalizeBundle(input) {
  const bundle = unwrap(input);
  const evidence = normalizeEvidence(bundle.evidence ?? bundle.records ?? bundle.observations ?? bundle.items);
  const unknowns = normalizeUnknowns(bundle.unknowns ?? bundle.residual_unknowns ?? bundle.residualUnknowns ?? bundle.open_questions);
  const coverage = bundle.coverage ?? bundle.reconstruction_coverage ?? bundle.coverage_summary ?? null;
  const target = text(bundle.target ?? bundle.target_path ?? bundle.artifact ?? bundle.binary, 'not stated');
  return {
    target,
    generatedAt: typeof bundle.generated_at === 'string' ? bundle.generated_at : null,
    revision: bundle.revision ?? bundle.expected_revision ?? null,
    evidence,
    unknowns,
    coverage,
    inferredCount: evidence.filter((item) => item.inferred).length,
  };
}

function escapeCell(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, 400);
}

function coverageLines(coverage) {
  if (coverage === null || coverage === undefined) return ['Coverage: not stated.'];
  if (typeof coverage !== 'object') return [`Coverage: ${text(coverage)}`];
  const lines = Object.entries(coverage).map(([key, value]) => `- ${key}: ${text(value)}`);
  return lines.length > 0 ? lines : ['Coverage: not stated.'];
}

/** A Markdown report suitable for archiving as-is. */
export function toMarkdown(input, { generatedAt = new Date().toISOString() } = {}) {
  const bundle = normalizeBundle(input);
  const lines = [
    '# REA reconstruction report',
    '',
    `- Generated: ${bundle.generatedAt ?? generatedAt}`,
    `- Target: ${bundle.target}`,
    ...(bundle.revision !== null ? [`- Evidence revision: ${text(bundle.revision)}`] : []),
    '',
    '> **Inference boundary.** Decompiler and reconstruction output is an inference, not source code.',
    '> Every claim below carries the coverage limits REA stated for it. Static-analysis details are not observed execution.',
    '> Items marked *inferred* have not been confirmed against disassembly or a runtime trace.',
    '',
    '## Coverage',
    '',
    ...coverageLines(bundle.coverage),
    '',
    `## Evidence (${bundle.evidence.length})`,
    '',
  ];
  if (bundle.evidence.length === 0) {
    lines.push('No Evidence records were included in the bundle.', '');
  } else {
    lines.push('| ID | Observation | Stated limits | Confidence | Kind | Location |', '| --- | --- | --- | --- | --- | --- |');
    for (const item of bundle.evidence) {
      lines.push(`| ${escapeCell(item.id)} | ${escapeCell(item.observation)}${item.inferred ? ' *(inferred)*' : ''} | ${escapeCell(item.limitation)} | ${escapeCell(item.confidence ?? 'not stated')} | ${escapeCell(item.kind)} | ${escapeCell(item.location ?? '—')} |`);
    }
    lines.push('');
  }

  lines.push(`## Residual unknowns (${bundle.unknowns.length})`, '');
  if (bundle.unknowns.length === 0) {
    lines.push('No residual unknowns were recorded.', '');
  } else {
    lines.push('| ID | Question | Severity | Required authority | Status |', '| --- | --- | --- | --- | --- |');
    for (const item of bundle.unknowns) {
      lines.push(`| ${escapeCell(item.id)} | ${escapeCell(item.question)} | ${escapeCell(item.severity)} | ${escapeCell(item.authority)} | ${escapeCell(item.status)} |`);
    }
    lines.push('');
  }
  lines.push(
    '## Notes',
    '',
    `- ${bundle.inferredCount} of ${bundle.evidence.length} Evidence records are marked as inferred.`,
    `- Unresolved unknowns: ${bundle.unknowns.filter((item) => !/resolved|closed|verified/i.test(item.status)).length}.`,
    '',
  );
  return lines.join('\n');
}

/**
 * SARIF 2.1.0. Each unknown is a result (severity -> level); Evidence records
 * are attached as a tool rule so the finding is machine-readable in CI without
 * pretending that a static observation is a vulnerability.
 */
export function toSarif(input, { toolName = 'dsh-rea', toolVersion = 'unknown' } = {}) {
  const bundle = normalizeBundle(input);
  const rules = bundle.evidence.map((item) => ({
    id: `REA${String(item.id).replace(/[^A-Za-z0-9._-]/g, '_')}`,
    shortDescription: { text: String(item.observation).slice(0, 200) },
    fullDescription: { text: `Stated limits: ${item.limitation}` },
    defaultConfiguration: { level: 'note' },
    properties: {
      'dsh-rea/evidence-id': item.id,
      'dsh-rea/inferred': item.inferred,
      'dsh-rea/confidence': item.confidence,
      'dsh-rea/kind': item.kind,
    },
  }));
  const results = bundle.unknowns.map((item, index) => ({
    ruleId: `REA_UNKNOWN_${index + 1}`,
    level: item.level,
    message: { text: `${item.question} (required authority: ${item.authority}; status: ${item.status})` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: String(bundle.target) === 'not stated' ? 'unknown' : String(bundle.target) },
      },
    }],
    properties: {
      'dsh-rea/unknown-id': item.id,
      'dsh-rea/severity': item.severity,
      'dsh-rea/required-authority': item.authority,
    },
  }));
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: toolName,
          version: toolVersion,
          informationUri: 'https://github.com/xiaobaga281/dsh-rea',
          rules: [
            ...rules,
            ...bundle.unknowns.map((_item, index) => ({
              id: `REA_UNKNOWN_${index + 1}`,
              shortDescription: { text: 'Residual unknown from an REA reconstruction' },
              defaultConfiguration: { level: 'warning' },
            })),
          ],
        },
      },
      invocations: [{ executionSuccessful: true, toolExecutionNotifications: [] }],
      results,
      properties: {
        'dsh-rea/target': bundle.target,
        'dsh-rea/evidence-count': bundle.evidence.length,
        'dsh-rea/unknown-count': bundle.unknowns.length,
        'dsh-rea/coverage': bundle.coverage,
      },
    }],
  };
}

/** Both formats, ready to hand to an artifact store. */
export function renderReports(input, options = {}) {
  const markdown = toMarkdown(input, options);
  const sarif = `${JSON.stringify(toSarif(input, options), null, 2)}\n`;
  return { markdown, sarif };
}
