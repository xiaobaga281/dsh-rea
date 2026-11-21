/**
 * Compare a rebuilt binary with the target it was reconstructed from.
 *
 * The loop's claim is falsifiable only if "match" is measured, not asserted.
 * Three tiers, each with its own denominator and its own honest failure mode:
 *
 *   T1 structure  - imports (recall and precision), section layout, string recall
 *   T2 functions  - entry-function pseudocode similarity via the plugin's Ghidra
 *   T3 literals   - constants written in the reconstructed source vs the target
 *
 * An empty tier is `null`, never 1.0: the 1.8.10 gate once reported "100%" for
 * a run whose ceiling was empty, and that is the exact failure this module must
 * not repeat. A blocked tier is removed and the weights renormalised, with the
 * reason carried into the report.
 *
 * T2 compares pseudocode, so a different compiler is a real difference: an MSVC
 * target against a gcc rebuild scores low even when the source is identical.
 * The limitation is printed, not hidden.
 *
 * @module dsh-rea/lib/compare
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { behaviorLimitations, compareBehaviorContracts, contractFrom } from '../static/behavior.js';
import { compileC } from './build.js';
import { decompileWithGhidra, ghidraLocalReadiness, listFunctionsWithGhidra } from './ghidra-local.js';
import { compareInteractionContracts, interactionContractFrom, interactionLimitations } from '../static/interaction.js';
import { detectAttributionCanaries, extractIocs } from '../static/intel.js';
import { extractDeepStrings } from '../static/strings.js';
import { parsePEImports } from '../static/intel.js';
import { readPeLayout, rvaToOffset } from '../static/structure.js';
import { extractStrings } from '../static/triage.js';

const MAX_BYTES = 64 * 1024 * 1024;
const STRING_CAP = 4_000;
const MAX_LITERALS = 200;

const ratio = (part, whole) => (whole === 0 ? null : part / whole);
const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');
const mean = (values) => (values.length === 0 ? null : values.reduce((sum, value) => sum + value, 0) / values.length);

async function load(path, maxBytes) {
  const buffer = await readFile(path);
  if (buffer.length > maxBytes) throw new Error(`${path} is ${buffer.length} bytes, over the ${maxBytes}-byte compare cap`);
  return buffer;
}

function apiSet(imports, exclude = null) {
  const names = new Set((imports?.apiFlat ?? [])
    .map((name) => String(name).toLowerCase())
    .filter((name) => name.length > 0 && !name.startsWith('#')));
  if (exclude) for (const name of exclude) names.delete(name);
  return names;
}

/**
 * Build metadata every compiler emits: PDB names, build IDs, its own type
 * vocabulary. Two compilations always disagree on them, so they are neither
 * payload nor evidence of a difference.
 */
const BUILD_ARTIFACT = [
  /\.pdb$/i,
  /^RSDS/,
  /buildid/i,
  /^GCC: /,
  /^clang version/i,
  /^Microsoft \(R\)/,
  /^'[^']+'$/,
  /^\.(?:text|rdata|data|reloc|pdata|xdata|bss|idata|tls|rsrc)$/i,
  // Source and object paths embedded by sanitizer/assert machinery. They change
  // with every work directory and are never payload.
  /\.(?:c|h|cc|cpp|hpp|o|obj|lib)$/i,
];

export function isBuildArtifact(value) {
  return BUILD_ARTIFACT.some((pattern) => pattern.test(value));
}

function stringSet(buffer, exclude = null) {
  const values = new Set(extractStrings(buffer, { minLength: 6, maxStrings: STRING_CAP }).map((item) => item.value));
  if (exclude) for (const value of exclude) values.delete(value);
  return values;
}

/**
 * Payload indicators: IoC-shaped values and attribution canaries, after the
 * toolchain floor and build metadata are removed.
 *
 * Plain strings are a bad payload measure: a rebuild of decompiled code
 * reproduces hundreds of compiler-adjacent strings and still misses the one URL
 * that matters. Indicators are what survives that comparison - a URL, a domain,
 * a registry path, a mutex, a per-copy canary - and they are meaningful on real
 * targets where no truth source exists.
 *
 * Encoded config is included through the same decode channels triage uses
 * (XOR / repeating-key XOR / zlib / base64 / RC4 candidates). Without this, an
 * encoded target has an empty payload tier and "no score" could read as "no
 * payload to recover", which is the wrong lesson: R1/R2-style specimens do
 * carry payload, it is just not plaintext.
 */
function payloadIndicators(buffer, floor) {
  const values = new Set([...stringSet(buffer, floor?.strings ?? null)].filter((value) => !isBuildArtifact(value)));
  const encoding = {};
  for (const item of extractDeepStrings(buffer, { minLength: 6, maxStrings: 2_000, report: encoding })) {
    const value = String(item.value ?? '');
    if (value.length === 0 || isBuildArtifact(value)) continue;
    if (floor?.strings?.has?.(value)) continue;
    values.add(value);
  }
  return indicatorsFromStrings(values, floor);
}

/**
 * Turn raw values into payload tokens. Dynamic evidence has to go through the
 * same expansion as in-binary strings, or a recovered URL would add
 * `ioc:<url>` on one side while the rebuild's URL also yields its host token on
 * the other, and a correct rebuild would read as imprecise.
 */
export function indicatorsFromStrings(values, floor = null) {
  const kept = [...values]
    .map((value) => String(value ?? ''))
    .filter((value) => value.length > 0 && !isBuildArtifact(value) && !floor?.strings?.has?.(value));
  const strings = kept.map((value) => ({ value }));
  const indicators = new Set();
  for (const ioc of extractIocs(strings)) indicators.add(`ioc:${String(ioc.value).toLowerCase()}`);
  const canaries = detectAttributionCanaries(strings);
  for (const marker of canaries.markers ?? []) {
    // Generic hex/uuid tokens are test vectors and library constants as often
    // as per-copy watermarks; only the explicit kinds count as payload.
    if (marker.kind !== 'canary-param' && marker.kind !== 'label-token') continue;
    indicators.add(`canary:${String(marker.value).toLowerCase()}`);
  }
  return indicators;
}

/**
 * What any build from this toolchain carries for free.
 *
 * A rebuilt binary imports the CRT and contains the compiler's own strings
 * whether or not anything was reconstructed. Counting those as recovered made
 * a stub-heavy baseline score 99.5% on its first run. The floor is measured
 * from a compiled empty program, never hand-listed, and subtracted from both
 * sides of the comparison.
 */
export function floorFromSkeleton(buffer) {
  return {
    imports: apiSet(parsePEImports(buffer)),
    strings: stringSet(buffer),
  };
}

export function emptyFloor() {
  return { imports: new Set(), strings: new Set() };
}

/**
 * Compile an empty program with the same toolchain and measure what it carries.
 * One build per caller; the zig/gcc cache makes it a sub-second operation once
 * the toolchain has been used.
 *
 * `listFunctions` also measures the function-level floor: which functions this
 * toolchain injects into every binary. The Ghidra list cache keys on the binary
 * bytes, so this is one engine run per toolchain build, then free. A failed
 * inventory leaves `functionFloor` null and the caller reports the deduction as
 * off - it never fabricates a floor.
 */
export async function measureToolchainFloor({ workDir, name = 'toolchain-floor', listFunctions = false, maxFunctions = 200, timeoutMs, signal } = {}) {
  const built = await compileC({ sourceText: 'int main(void) { return 0; }\n', workDir, name });
  if (!built.ok) {
    return { floor: emptyFloor(), functionFloor: null, functionFloorReason: built.reason ?? built.code, reason: built.reason ?? built.code, path: null };
  }
  const buffer = await readFile(built.outPath);
  let functionFloor = null;
  let functionFloorReason = null;
  if (listFunctions) {
    const listed = await listFunctionsWithGhidra(built.outPath, { maxFunctions, timeoutMs, signal });
    if (listed.ok) functionFloor = functionFloorFromInventory(listed.functions);
    else functionFloorReason = listed.reason ?? listed.code ?? 'the floor function inventory failed';
  }
  return { floor: floorFromSkeleton(buffer), functionFloor, functionFloorReason, reason: null, path: built.outPath };
}

/**
 * The function-level toolchain floor from a measured inventory.
 *
 * `main` and decompiler-generated names (`FUN_*`) are never deducted by name:
 * `main` is the analyst's entry point, and a `FUN_*` name is every unnamed
 * function in every binary, target and rebuild alike. Their bodies still join
 * the body-hash set - a body hash is measured evidence, not a name.
 */
export function functionFloorFromInventory(functions) {
  const names = new Set();
  const rvas = new Set();
  const bodyHashes = new Map();
  let count = 0;
  for (const fn of functions ?? []) {
    if (!fn?.name) continue;
    count += 1;
    if (fn.name !== 'main' && !/^FUN_/.test(fn.name)) {
      names.add(fn.name);
      rvas.add(fn.rva);
    }
    bodyHashes.set(sha256(normalizePseudocode(fn.body)), fn.name);
  }
  return { names, rvas, bodyHashes, count };
}

/** Coerce a floor that may have crossed JSON (Sets become arrays, Maps objects). */
function coerceFunctionFloor(floor) {
  if (!floor || typeof floor !== 'object') return null;
  const names = floor.names instanceof Set ? floor.names : new Set(Array.isArray(floor.names) ? floor.names : []);
  const rvas = floor.rvas instanceof Set ? floor.rvas : new Set(Array.isArray(floor.rvas) ? floor.rvas : []);
  let bodyHashes;
  if (floor.bodyHashes instanceof Map) bodyHashes = floor.bodyHashes;
  else if (Array.isArray(floor.bodyHashes)) bodyHashes = new Map(floor.bodyHashes.map((hash) => [hash, null]));
  else if (floor.bodyHashes && typeof floor.bodyHashes === 'object') bodyHashes = new Map(Object.entries(floor.bodyHashes));
  else bodyHashes = new Map();
  if (names.size === 0 && rvas.size === 0 && bodyHashes.size === 0) return null;
  return { names, rvas, bodyHashes };
}

/**
 * Evidence class for one target function against the floor.
 *
 * `name-only` is the weakest class: the name survived but the body differs,
 * which is exactly what an optimised or hand-written rebuild of a real function
 * can look like. It is reported for audit and never deducted - the deduction
 * prefers under-counting to eating a user function.
 */
export function classifyAgainstFunctionFloor(fn, floor) {
  const name = String(fn?.name ?? '');
  const nameHit = floor.names.has(name);
  const rvaHit = floor.rvas.has(fn?.rva);
  const bodyHit = floor.bodyHashes.has(sha256(normalizePseudocode(fn?.body)));
  if (nameHit && (rvaHit || bodyHit)) return rvaHit ? 'name+rva' : 'name+body-hash';
  if (bodyHit) return 'body-hash';
  if (nameHit) return 'name-only';
  return null;
}

/**
 * Split a target window into what the floor explains (`deducted`), what it only
 * names (`nameOnly`, kept in the denominator but listed for audit), and the
 * rest (`kept`, the deducted denominator).
 */
export function splitByFunctionFloor(functions, floor) {
  const kept = [];
  const deducted = [];
  const nameOnly = [];
  for (const fn of functions ?? []) {
    const matchedBy = classifyAgainstFunctionFloor(fn, floor);
    if (matchedBy === null) kept.push(fn);
    else if (matchedBy === 'name-only') {
      nameOnly.push({ name: fn.name, rva: fn.rva ?? null, matchedBy });
      kept.push(fn);
    } else {
      deducted.push({ name: fn.name, rva: fn.rva ?? null, matchedBy });
    }
  }
  return { kept, deducted, nameOnly };
}

/** Union of two measured floors (empty program ∪ full-stub pipeline). */
export function unionFunctionFloors(left, right) {
  const a = coerceFunctionFloor(left);
  const b = coerceFunctionFloor(right);
  if (!a) return b;
  if (!b) return a;
  return {
    names: new Set([...a.names, ...b.names]),
    rvas: new Set([...a.rvas, ...b.rvas]),
    bodyHashes: new Map([...a.bodyHashes, ...b.bodyHashes]),
  };
}

/** Quoted string constants in the reconstructed source, minus format specifiers. */
export function sourceLiterals(sourceText) {
  const literals = new Set();
  for (const match of String(sourceText).matchAll(/"((?:[^"\\\n]|\\.){2,160})"/g)) {
    const value = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    if (!/[A-Za-z]{2}/.test(value)) continue;
    literals.add(value);
    if (literals.size >= MAX_LITERALS) break;
  }
  return literals;
}

/**
 * Pseudocode tokens with the parts that always differ removed.
 *
 * Addresses, decimal constants and decompiler-generated temporary names carry
 * no semantics; two compilations of one source disagree on all of them. The
 * function names and structure words that remain are what the comparison is
 * about.
 */
export function normalizePseudocode(code) {
  return String(code ?? '')
    .toLowerCase()
    // Only addresses and large immediates are noise; small constants are the
    // structural evidence (offsets 0x20, masks 0xfffffffd, flags 0x24).
    .replace(/0x[0-9a-f]{5,}/g, ' hexnum ')
    .replace(/\b\d{6,}\b/g, ' num ')
    .replace(/dat_[0-9a-f]+/g, ' global ')
    // Decompiler-generated names only: uVar1 / iVar2 / param_1 / local_8 /
    // in_EAX / unaff_EBX / extraout_EAX. A bare word starting with "u" is not a
    // temporary, and erasing it would delete real identifiers.
    .replace(/\b(?:u?var\d+|param_\d+|local_[0-9a-f]+|unaff_[a-z0-9_]+|in_stack_[0-9a-f]+|extraout_[a-z0-9_]+|in_[a-z]{2,4})\b/g, ' var ')
    .replace(/[^a-z0-9_]+/g, ' ')
    .trim();
}

export function pseudocodeSimilarity(left, right) {
  const trigrams = (text) => {
    const tokens = text.split(/\s+/).filter(Boolean);
    const grams = new Set();
    for (let index = 0; index + 3 <= tokens.length; index += 1) {
      grams.add(tokens.slice(index, index + 3).join(' '));
    }
    return grams;
  };
  const a = trigrams(normalizePseudocode(left));
  const b = trigrams(normalizePseudocode(right));
  if (a.size === 0 || b.size === 0) return null;
  let shared = 0;
  for (const gram of a) if (b.has(gram)) shared += 1;
  return { similarity: shared / (a.size + b.size - shared), leftGrams: a.size, rightGrams: b.size };
}

/**
 * Control-flow shape similarity from the per-function CFG metrics Ghidra emits.
 *
 * Text similarity and shape similarity answer different questions: a
 * re-ordered function can print different pseudocode with the same CFG, and a
 * stub can print similar text with no branches. Both are averaged per function.
 */
export function cfgSimilarity(left, right) {
  if (!left || !right) return null;
  const keys = ['blocks', 'edges', 'conditionals', 'loops', 'maxFanout'];
  let sum = 0;
  let count = 0;
  for (const key of keys) {
    const a = Number(left[key]);
    const b = Number(right[key]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
    sum += 1 - Math.abs(a - b) / Math.max(a, b, 1);
    count += 1;
  }
  return count === 0 ? null : sum / count;
}

/**
 * Semantic signature similarity for cross-compiler restoration.
 *
 * Compilers print different types, names and block layouts for the same logic;
 * what survives is the small structural constants (member offsets, masks,
 * flags), the operators and the control-flow vocabulary. This is the metric a
 * function-level restoration review uses when the target was built by another
 * compiler.
 */
const semanticTokens = (code) => {
  const text = String(code ?? '').toLowerCase();
  return {
    constants: new Set([...text.matchAll(/0x[0-9a-f]{1,4}\b|\b\d{1,5}\b/g)].map((match) => match[0])),
    operators: new Set(text.match(/&&|\|\||==|!=|<=|>=|<<|>>|[&|^+\-*/<>]/g) ?? []),
    keywords: new Set(text.match(/\b(?:if|while|for|switch|case|return|goto|break|continue)\b/g) ?? []),
    calls: (text.match(/\b[a-z_]\w*\s*\(/g) ?? []).length,
  };
};

const jaccard = (left, right) => {
  const union = new Set([...left, ...right]);
  if (union.size === 0) return null;
  let shared = 0;
  for (const value of left) if (right.has(value)) shared += 1;
  return shared / union.size;
};

export function semanticSimilarity(left, right) {
  const a = semanticTokens(left);
  const b = semanticTokens(right);
  const constants = jaccard(a.constants, b.constants);
  const operators = jaccard(a.operators, b.operators);
  const keywords = jaccard(a.keywords, b.keywords);
  const calls = Math.max(a.calls, b.calls) === 0 ? null : 1 - Math.abs(a.calls - b.calls) / Math.max(a.calls, b.calls);
  const parts = [constants, operators, keywords, calls].filter((value) => typeof value === 'number');
  if (parts.length === 0) return null;
  return {
    similarity: parts.reduce((sum, value) => sum + value, 0) / parts.length,
    constants,
    operators,
    keywords,
    calls,
  };
}

// ---------------------------------------------------------- semantic hypotheses --
//
// A hypothesis is a claim about what a region of the target does, stated with
// evidence that can be grepped in the target's own decompilation and a
// prediction that an independent channel can confirm or contradict. The check
// below is the falsifiable half: it never runs the target, never trusts the
// hypothesis text, and can only return verified / unverified / refuted.

const SAME_CHANNEL_NOTE = 'same-channel: hypothesis and check both derive from the target\'s own Ghidra decompilation; independent confirmation (raw disassembly or dynamic trace) is still open';
const DYNAMIC_RESOLUTION_NOTE = 'the target imports GetProcAddress/LoadLibrary-style resolvers, so a missing static import does not by itself rule out a dynamically resolved call';
import { findListedFunction, normalizeQuote, toRvaNumber } from '../static/function-matching.js';
export { findListedFunction, normalizeQuote, toRvaNumber };

export const HYPOTHESIS_BOUNDARY = 'status=verified means the named channel confirmed the prediction against measured target evidence; it is not proof of uniqueness or of the original source. unverified means no available channel could decide the claim. refuted means available evidence contradicts the prediction.';

/**
 * Check one semantic hypothesis against measured target evidence.
 *
 * `context` carries the measured channels: { layout, imports, strings,
 * functions } - a PE layout, parsed imports, deep strings (plain + decoded)
 * and the Ghidra function inventory with bodies. Any channel may be absent;
 * a check whose channel is absent is `unverified`, never a pass.
 *
 * Status rules:
 *   - every evidence quote must be found (whitespace-normalised grep) in the
 *     cited function's listing, or the hypothesis is rejected: a quote the
 *     listing does not contain is a contradiction, and a cited location the
 *     inventory does not cover is unverifiable;
 *   - calls-target: the named function's own decompiled body must contain the
 *     call. This is same-engine evidence, so a verified result always carries
 *     the same-channel caveat in its detail;
 *   - import-used: a hit verifies a binary-level hypothesis only. For a
 *     function-level hypothesis it is necessary, not sufficient -> unverified.
 *     A miss refutes only when the function's own body also lacks the name (or,
 *     for binary-level, when the target has no dynamic-resolution imports);
 *     otherwise the absence is recorded as unverified with the blind spot named;
 *   - string-literal: the value must survive the deep-string channels;
 *   - constant-at-rva: the bytes at the predicted address must equal the
 *     predicted hex (little-endian, as stored).
 */
export function checkSemanticHypothesis(targetBuffer, context, hypothesis) {
  const buffer = Buffer.isBuffer(targetBuffer) ? targetBuffer : Buffer.from(targetBuffer ?? []);
  const { layout = null, imports = null, strings = null, functions = null } = context ?? {};
  const id = String(hypothesis?.id ?? 'hypothesis');
  const statement = String(hypothesis?.statement ?? '');
  const prediction = hypothesis?.prediction ?? null;
  const kind = typeof prediction?.kind === 'string' ? prediction.kind : '';
  const value = prediction?.value;
  const level = hypothesis?.functionName || hypothesis?.rva ? 'function' : 'binary';
  const functionName = hypothesis?.functionName ? String(hypothesis.functionName) : null;

  const result = {
    id,
    level,
    statement,
    prediction,
    status: 'unverified',
    detail: '',
    sameChannel: kind === 'calls-target',
    evidence: [],
    boundary: HYPOTHESIS_BOUNDARY,
    checkedAt: new Date().toISOString(),
  };

  // ---- evidence gate -------------------------------------------------------
  let evidenceRefuted = false;
  let evidenceUnverifiable = false;
  const evidenceItems = Array.isArray(hypothesis?.evidence) ? hypothesis.evidence : [];
  for (const item of evidenceItems) {
    const quote = String(item?.quote ?? '');
    const citeRva = item?.rva ?? hypothesis?.rva ?? null;
    const fn = findListedFunction(functions, citeRva, item?.functionName ?? functionName);
    const hit = fn !== null && quote.length > 0 && normalizeQuote(fn.body).includes(normalizeQuote(quote));
    // The original quote is carried verbatim; the check only adds where it hit.
    result.evidence.push({
      channel: String(item?.channel ?? 'ghidra-decompile'),
      rva: citeRva ?? fn?.rva ?? null,
      quote,
      locatable: fn !== null,
      hit,
    });
    if (fn === null) evidenceUnverifiable = true;
    else if (!hit) evidenceRefuted = true;
  }

  const cited = findListedFunction(functions, hypothesis?.rva, functionName);
  const finish = (status, detail) => {
    result.status = status;
    result.detail = detail;
    return result;
  };

  if (!prediction || typeof kind !== 'string' || kind.length === 0 || value === undefined || value === null || String(value).length === 0) {
    return finish('unverified', 'no checkable prediction (prediction.kind and prediction.value are required)');
  }
  if (evidenceRefuted) {
    const missed = result.evidence.filter((item) => !item.hit).map((item) => `"${item.quote.slice(0, 60)}"`).join(', ');
    return finish('refuted', `evidence contradicts the listing: ${missed} does not appear in the cited decompilation`);
  }
  if (evidenceUnverifiable) {
    return finish('unverified', 'cited evidence location is outside the measured function inventory; the claim can be neither confirmed nor contradicted here');
  }

  // ---- prediction channels -------------------------------------------------
  if (kind === 'calls-target') {
    if (!Array.isArray(functions) || functions.length === 0) {
      return finish('unverified', 'no decompiled function inventory was supplied; the calls-target channel cannot run');
    }
    if (!cited) {
      return finish('unverified', `function ${functionName ?? hypothesis?.rva ?? '?'} is not in the measured inventory; the calls-target channel cannot run`);
    }
    const callPattern = new RegExp(`\\b${String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`);
    if (callPattern.test(String(cited.body ?? ''))) {
      return finish('verified', `the decompiled body of ${cited.name} calls ${value}. ${SAME_CHANNEL_NOTE}`);
    }
    return finish('refuted', `the decompiled body of ${cited.name} contains no call to ${value}. ${SAME_CHANNEL_NOTE}`);
  }

  if (kind === 'import-used') {
    const api = String(value);
    if (!imports || !Array.isArray(imports.apiFlat)) {
      return finish('unverified', 'no import table could be parsed; the import-used channel cannot run');
    }
    const hit = imports.apiFlat.some((name) => String(name).toLowerCase() === api.toLowerCase());
    const dynamicResolvers = imports.apiFlat.some((name) => /getprocaddress|loadlibrary|getmodulehandle/i.test(String(name)));
    if (hit && level === 'binary') {
      return finish('verified', `import table contains ${api}`);
    }
    if (hit) {
      return finish('unverified', `import table contains ${api} — necessary, not sufficient: ${functionName ?? 'the cited function'} calling it needs the calls-target channel`);
    }
    // Miss: the function's own body can still refute the claim outright.
    if (cited && !normalizeQuote(String(cited.body ?? '')).includes(api.toLowerCase())) {
      return finish('refuted', `neither the decompiled body of ${cited.name} nor the import table shows ${api}${dynamicResolvers ? `; ${DYNAMIC_RESOLUTION_NOTE}` : ''}`);
    }
    if (dynamicResolvers) {
      return finish('unverified', `import table does not contain ${api}; ${DYNAMIC_RESOLUTION_NOTE}`);
    }
    return finish('refuted', `import table does not contain ${api}, and the target imports no dynamic-resolution API that could hide it`);
  }

  if (kind === 'string-literal') {
    if (!Array.isArray(strings)) {
      return finish('unverified', 'no string evidence was supplied; the string-literal channel cannot run');
    }
    const wanted = normalizeQuote(value);
    const found = strings.find((entry) => normalizeQuote(entry?.value).includes(wanted));
    if (found) {
      return finish('verified', `string "${String(value).slice(0, 80)}" present in the target (${found.encoding ?? 'ascii'} at 0x${Number(found.offset ?? 0).toString(16)})`);
    }
    return finish('refuted', `string "${String(value).slice(0, 80)}" is absent from the target's static and decoded strings; a value constructed only at run time through an uncovered channel would not appear here`);
  }

  if (kind === 'constant-at-rva') {
    if (!layout) {
      return finish('unverified', 'no PE layout was supplied; the constant-at-rva channel cannot run');
    }
    const address = toRvaNumber(prediction?.rva ?? value);
    if (address === null) {
      return finish('unverified', 'constant-at-rva needs the address in prediction.rva');
    }
    const rva = address >= layout.imageBase ? address - layout.imageBase : address;
    const offset = rvaToOffset(layout, rva);
    if (offset === null || offset + 1 > buffer.length) {
      return finish('unverified', `address 0x${rva.toString(16)} is not mapped into the file`);
    }
    const expected = String(prediction?.value ?? value).replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '').toLowerCase();
    if (expected.length < 2) {
      return finish('unverified', 'constant-at-rva needs the expected bytes as a hex string in prediction.value');
    }
    const length = Math.min(expected.length / 2, buffer.length - offset);
    const actual = buffer.subarray(offset, offset + length).toString('hex');
    if (actual === expected.slice(0, length * 2) && length * 2 >= expected.length) {
      const owner = Array.isArray(functions)
        ? functions.find((fn) => toRvaNumber(fn?.rva) !== null && rva >= toRvaNumber(fn.rva) && rva < toRvaNumber(fn.rva) + Math.max(1, Number(fn.size) || 0))
        : null;
      const scope = owner ? `the address lies inside ${owner.name}, so this is function-scoped evidence` : 'the address lies outside the listed functions (data or outside the window)';
      return finish('verified', `bytes at 0x${rva.toString(16)} (file 0x${offset.toString(16)}) equal ${actual}; ${scope}`);
    }
    return finish('refuted', `bytes at 0x${rva.toString(16)} are ${actual || '(none)'}, not the predicted ${expected}`);
  }

  return finish('unverified', `unknown prediction kind "${kind}"; no channel can run it`);
}

/**
 * Pair target functions with their counterparts in the rebuild.
 *
 * Entry RVAs first: a rebuild from the right source with the same recipe lays
 * functions out identically, and the RVA survives a preferred-base change.
 * A name match is the fallback for non-stripped builds where layout drifted.
 */
export function matchFunctionLists(targetFunctions, rebuiltFunctions) {
  const byRva = new Map(rebuiltFunctions.map((item) => [item.rva, item]));
  const byName = new Map(rebuiltFunctions.map((item) => [item.name, item]));
  const used = new Set();
  const pairs = [];
  for (const target of targetFunctions) {
    let match = byRva.get(target.rva);
    if (!match) {
      const named = byName.get(target.name);
      if (named && !used.has(named)) match = named;
    }
    if (match) used.add(match);
    pairs.push({ target, rebuilt: match ?? null });
  }
  return pairs;
}

/**
 * Extract top-level function bodies from a source file by name.
 *
 * A restoration review scores the draft's source against the target's
 * pseudocode: re-decompiling the rebuild loses call arguments (Ghidra prints
 * `helper();` for a call that passes four) and would score the decompiler's
 * recovery, not the restoration. The binary still has to compile and contain
 * the function (the inventory pairing checks that part).
 */
/**
 * Extract whole function blocks, including the return type and storage class.
 *
 * `extractSourceFunctions` starts at the function name because T2 only needs the
 * body. Rewriting needs the declaration too: replacing `main(void) {...}` with
 * `int main(void) {...}` used to produce `int int main`, which is how a
 * mechanical repair turned into a compile error.
 */
export function extractFunctionBlocks(sourceText) {
  const blocks = new Map();
  const text = String(sourceText ?? '');
  const pattern = /\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g;
  for (const match of text.matchAll(pattern)) {
    const name = match[1];
    const start = text.indexOf('{', match.index);
    if (start < 0) continue;
    let depth = 0;
    let end = start;
    for (; end < text.length; end += 1) {
      if (text[end] === '{') depth += 1;
      else if (text[end] === '}') {
        depth -= 1;
        if (depth === 0) { end += 1; break; }
      }
    }
    let declarationStart = match.index;
    while (declarationStart > 0 && !/[\n;{}]/.test(text[declarationStart - 1])) declarationStart -= 1;
    while (declarationStart < match.index && /\s/.test(text[declarationStart])) declarationStart += 1;
    blocks.set(name, text.slice(declarationStart, end));
  }
  return blocks;
}

export function extractSourceFunctions(sourceText) {
  const bodies = new Map();
  const text = String(sourceText ?? '');
  const pattern = /\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g;
  for (const match of text.matchAll(pattern)) {
    const name = match[1];
    const start = text.indexOf('{', match.index);
    if (start < 0) continue;
    let depth = 0;
    let end = start;
    for (; end < text.length; end += 1) {
      if (text[end] === '{') depth += 1;
      else if (text[end] === '}') {
        depth -= 1;
        if (depth === 0) { end += 1; break; }
      }
    }
    bodies.set(name, text.slice(match.index, end));
  }
  return bodies;
}

/**
 * Score a function inventory the way the loop reports it: every target function
 * counts, and one with no counterpart contributes zero. Averaging only over the
 * matched pairs would let a rebuild that dropped half the program keep a high
 * score.
 *
 * `metric` selects what "similar" means: mixed (text + CFG, the loop default),
 * cfg (cross-compiler restoration, where the source is right but the compiler
 * prints different pseudocode), semantic (structural constants/operators/
 * keywords/calls), or text.
 */
export function scoreFunctionLists(targetFunctions, rebuiltFunctions, { metric = 'mixed', matchBy = 'rva', threshold = 0.9, rebuiltBodies = null } = {}) {
  const pairs = matchBy === 'name'
    ? matchFunctionListsByName(targetFunctions, rebuiltFunctions)
    : matchFunctionLists(targetFunctions, rebuiltFunctions);
  if (rebuiltBodies) {
    for (const pair of pairs) {
      const sourceName = rebuiltBodies.has(pair.target.name)
        ? pair.target.name
        : (pair.target.exportName && rebuiltBodies.has(pair.target.exportName) ? pair.target.exportName : null);
      if (pair.rebuilt && sourceName !== null) {
        pair.rebuilt = { ...pair.rebuilt, body: rebuiltBodies.get(sourceName) };
      }
    }
  }
  if (pairs.length === 0) return { pairs: 0, matched: 0, coverage: null, score: null, mismatches: [], threshold };
  let matched = 0;
  let sum = 0;
  const mismatches = [];
  for (const pair of pairs) {
    if (!pair.rebuilt) {
      mismatches.push({ name: pair.target.name, rva: pair.target.rva, reason: 'no counterpart' });
      continue;
    }
    const text = metric === 'cfg' || metric === 'semantic' ? null : pseudocodeSimilarity(pair.target.body, pair.rebuilt.body);
    const semantic = metric === 'semantic' ? semanticSimilarity(pair.target.body, pair.rebuilt.body) : null;
    const cfg = metric === 'text' || metric === 'semantic' ? null : cfgSimilarity(pair.target.cfg, pair.rebuilt.cfg);
    const values = [text?.similarity, semantic?.similarity, cfg].filter((value) => typeof value === 'number');
    if (values.length === 0) {
      mismatches.push({ name: pair.target.name, rva: pair.target.rva, reason: 'no comparable tokens, semantics or CFG' });
      continue;
    }
    const similarity = values.reduce((sum, value) => sum + value, 0) / values.length;
    matched += 1;
    sum += similarity;
    if (similarity < threshold) {
      mismatches.push({
        name: pair.target.name,
        rva: pair.target.rva,
        similarity: Number(similarity.toFixed(3)),
        textSimilarity: text === null ? null : Number(text.similarity.toFixed(3)),
        semanticSimilarity: semantic === null ? null : Number(semantic.similarity.toFixed(3)),
        semanticComponents: semantic === null ? null : {
          constants: Number(semantic.constants.toFixed(3)),
          operators: Number(semantic.operators.toFixed(3)),
          keywords: Number(semantic.keywords.toFixed(3)),
          calls: semantic.calls === null ? null : Number(semantic.calls.toFixed(3)),
        },
        cfgSimilarity: cfg === null ? null : Number(cfg.toFixed(3)),
        rebuiltName: pair.rebuilt.name,
      });
    }
  }
  return {
    pairs: pairs.length,
    matched,
    coverage: matched / pairs.length,
    score: sum / pairs.length,
    threshold,
    belowThreshold: mismatches.filter((item) => typeof item.similarity === 'number').length,
    mismatches: mismatches.slice(0, 20),
  };
}

/** Name-only pairing: the caller restored specific functions by name. */
export function matchFunctionListsByName(targetFunctions, rebuiltFunctions) {
  const byName = new Map(rebuiltFunctions.map((item) => [item.name, item]));
  const used = new Set();
  const pairs = [];
  for (const target of targetFunctions) {
    let match = byName.get(target.name)
      ?? (target.exportName ? byName.get(target.exportName) : undefined);
    if (match && used.has(match)) match = null;
    if (match) used.add(match);
    pairs.push({ target, rebuilt: match ?? null });
  }
  return pairs;
}

function diffSets(targetSet, rebuiltSet) {
  const missing = [...targetSet].filter((value) => !rebuiltSet.has(value));
  const added = [...rebuiltSet].filter((value) => !targetSet.has(value));
  return {
    recall: ratio(targetSet.size - missing.length, targetSet.size),
    precision: ratio(rebuiltSet.size - added.length, rebuiltSet.size),
    missing: missing.slice(0, 20),
    added: added.slice(0, 20),
    targetSize: targetSet.size,
    rebuiltSize: rebuiltSet.size,
  };
}

/**
 * Resolve the opt-in T5 interaction tier from the engine inventories. Pure:
 * the already-fetched lists and parsed binaries come in, the tier record comes
 * out. Kept out of compareBuilds so the blocked/empty/truncated rules can be
 * exercised directly - a truncated inventory that surfaces no target facts
 * must read blocked, never a scored zero.
 */
export function buildInteractionTier({ enabled = false, engine = true, targetList = null, rebuiltList = null, target = null, rebuilt = null, floorStrings = null } = {}) {
  let t5 = {
    status: 'skipped',
    score: null,
    reason: 'the interaction tier is opt-in; pass interaction=true to score windows, dialogs, message handling and control ids',
    windows: null,
    messages: null,
    controls: null,
    resources: null,
    targetFacts: 0,
    rebuiltFacts: 0,
    inventoryTruncated: false,
  };
  if (enabled !== true) return t5;
  if (engine === false) {
    t5.status = 'blocked';
    t5.reason = 'the interaction tier reuses the engine function inventory; pass engine=true so the inventory exists';
    return t5;
  }
  if (!targetList?.ok || !rebuiltList?.ok || !Array.isArray(targetList.functions) || targetList.functions.length === 0 || !Array.isArray(rebuiltList.functions) || rebuiltList.functions.length === 0) {
    t5.status = 'blocked';
    t5.reason = `the interaction tier needs the engine function inventory (${targetList?.reason ?? rebuiltList?.reason ?? 'the inventory produced no functions'})`;
    return t5;
  }
  const inventoryTruncated = [targetList, rebuiltList].some((list) => list.truncated === true || list.analysisTimedOut === true || list.timeStopped === true);
  const targetInteraction = interactionContractFrom({
    buffer: target?.buffer ?? null, layout: target?.layout ?? null, imports: target?.imports ?? null, functions: targetList.functions, floorStrings,
  });
  const rebuiltInteraction = interactionContractFrom({
    buffer: rebuilt?.buffer ?? null, layout: rebuilt?.layout ?? null, imports: rebuilt?.imports ?? null, functions: rebuiltList.functions, floorStrings,
  });
  t5 = compareInteractionContracts(targetInteraction, rebuiltInteraction);
  t5.targetFacts = targetInteraction.facts.length;
  t5.rebuiltFacts = rebuiltInteraction.facts.length;
  t5.inventoryTruncated = inventoryTruncated;
  if (inventoryTruncated) {
    t5.note = 'the function inventory was truncated; window procedures beyond the cap are invisible to this tier';
  }
  // A truncated inventory that surfaced no target facts cannot tell "no GUI"
  // from "the window procedure was cut off": that is blocked, not 0.
  if (t5.status === 'empty' && inventoryTruncated && targetInteraction.facts.length === 0) {
    t5.status = 'blocked';
    t5.score = null;
    t5.reason = 'the truncated inventory surfaced no interaction facts for the target; a missing window procedure in a truncated inventory is not evidence of an empty interaction surface';
  }
  return t5;
}

/**
 * Run the comparison. `engine: false` skips T2; a missing engine blocks it with
 * the readiness reason instead of scoring zero.
 */
export async function compareBuilds({
  targetPath, rebuiltPath, sourceText = null, engine = true, maxBytes = MAX_BYTES, timeoutMs, signal, runtimeFloor = null,
  maxFunctions = 48, functionFilter = null, functionMetric = 'mixed', functionThreshold = 0.9,
  behavior = false, dynamicEvidence = null, deductFunctions = false, functionFloor = null,
  interaction = false,
} = {}) {
  const floor = runtimeFloor ?? emptyFloor();
  const [targetBuffer, rebuiltBuffer] = await Promise.all([load(targetPath, maxBytes), load(rebuiltPath, maxBytes)]);
  const [targetLayout, rebuiltLayout] = [readPeLayout(targetBuffer), readPeLayout(rebuiltBuffer)];
  const targetImports = parsePEImports(targetBuffer);
  const rebuiltImports = parsePEImports(rebuiltBuffer);

  // Values recovered from a dynamic trace exist at run time, not in the file.
  // They are real target truth, so they join the target's sets; leaving them out
  // would penalise a rebuild that correctly carries a runtime-derived key.
  const dynamicStrings = new Set((dynamicEvidence?.strings ?? []).map((value) => String(value).trim()).filter((value) => value.length >= 3));
  const dynamicIndicators = new Set((dynamicEvidence?.iocs ?? []).map((value) => String(value).trim()).filter((value) => value.length > 0));

  const apiDiff = diffSets(apiSet(targetImports, floor.imports), apiSet(rebuiltImports, floor.imports));
  const targetIndicators = payloadIndicators(targetBuffer, floor);
  for (const token of indicatorsFromStrings(new Set([...dynamicStrings, ...dynamicIndicators]), floor)) targetIndicators.add(token);
  const rebuiltIndicators = payloadIndicators(rebuiltBuffer, floor);
  const indicatorDiff = diffSets(targetIndicators, rebuiltIndicators);
  // T3 checks literals a draft declares against everything the target still
  // carries, not only indicators: a declared literal may be an ordinary string.
  const targetStringsForLiterals = stringSet(targetBuffer, floor.strings);
  for (const value of dynamicStrings) targetStringsForLiterals.add(value);
  const sectionNames = (layout) => new Set((layout?.sections ?? []).map((section) => section.name));
  const targetSections = sectionNames(targetLayout);
  const rebuiltSections = sectionNames(rebuiltLayout);
  const sectionDiff = diffSets(targetSections, rebuiltSections);
  const sectionJaccard = targetSections.size + rebuiltSections.size === 0
    ? null
    : [...targetSections].filter((name) => rebuiltSections.has(name)).length / new Set([...targetSections, ...rebuiltSections]).size;

  // T1 is structural only; the strings moved to the payload tier so the same
  // evidence is not counted twice.
  const t1Score = mean([apiDiff.recall, apiDiff.precision, sectionJaccard].filter((value) => value !== null));
  // Payload: indicators and canaries the target still carries after the
  // toolchain floor. A rebuild that dropped the config loses recall; one that
  // invented indicators loses precision. Measurable with no truth source.
  const payloadScore = mean([indicatorDiff.recall, indicatorDiff.precision].filter((value) => value !== null));

  // T2: the entry function only for now. A full function inventory is the loop's
  // next step; comparing one function is honest about its scope.
  let t2 = { status: 'blocked', score: null, reason: null, scope: null, entryRva: null, similarity: null };
  // Toolchain-function deduction is opt-in and never applies to a named-function
  // review: the reviewer asked for exactly those functions, so they are the
  // denominator whatever the floor says.
  const activeFloor = deductFunctions === true && functionFilter === null
    ? coerceFunctionFloor(functionFloor)
    : null;
  // The function inventories are hoisted so the opt-in interaction tier (T5)
  // can reuse them: T5 resolves window procedures against the same lists, and
  // the per-file cache in ghidra-local.js makes that reuse free. They stay
  // null whenever the engine tier did not run, which is how T5 reports blocked.
  let targetList = null;
  let rebuiltList = null;
  if (engine !== false) {
    const readiness = await ghidraLocalReadiness();
    if (!readiness.ready) {
      t2.reason = readiness.reason ?? 'Ghidra is not ready';
    } else if (!targetLayout || targetLayout.entryRva === 0) {
      t2.reason = 'the target has no entry point to decompile';
    } else {
      [targetList, rebuiltList] = await Promise.all([
        listFunctionsWithGhidra(targetPath, { maxFunctions, timeoutMs, signal }),
        listFunctionsWithGhidra(rebuiltPath, { maxFunctions, timeoutMs, signal }),
      ]);
      if (targetList.ok && rebuiltList.ok && targetList.functions.length > 0 && rebuiltList.functions.length > 0) {
        // A restoration review names its functions; layout-based pairing would
        // pair the wrong bodies once the rebuild has its own layout.
        // A requested name matches either the inventory name (FUN_*) or the
        // export name the overlay attached - both identities are first-class.
        const inFilter = (item) => functionFilter.some((wanted) => wanted === item.name || wanted === item.exportName);
        const filteredTargets = functionFilter
          ? targetList.functions.filter(inFilter)
          : targetList.functions;
        const filteredRebuilt = functionFilter
          ? rebuiltList.functions.filter(inFilter)
          : rebuiltList.functions;
        // Double report: with an active floor the same window is scored twice.
        // `score` averages only the functions the floor does not explain
        // (denominator.after); `scoreAll` is the undeducted average over the
        // whole window (denominator.before). The "no counterpart scores zero"
        // rule is unchanged inside both averages.
        const split = activeFloor !== null && filteredTargets.length > 0
          ? splitByFunctionFloor(filteredTargets, activeFloor)
          : null;
        const scoredTargets = split ? split.kept : filteredTargets;
        const scoreOptions = {
          metric: functionMetric,
          matchBy: functionFilter ? 'name' : 'rva',
          threshold: functionThreshold,
          rebuiltBodies: functionFilter && typeof sourceText === 'string' ? extractSourceFunctions(sourceText) : null,
        };
        const emptyInventory = { score: null, pairs: 0, matched: 0, coverage: null, mismatches: [], belowThreshold: 0 };
        const inventory = scoredTargets.length === 0
          ? emptyInventory
          : scoreFunctionLists(scoredTargets, filteredRebuilt, scoreOptions);
        const inventoryAll = split && filteredTargets.length > 0
          ? scoreFunctionLists(filteredTargets, filteredRebuilt, scoreOptions)
          : null;
        const deductionFields = split === null ? {} : {
          scoreAll: inventoryAll === null ? null : inventoryAll.score,
          denominator: { before: filteredTargets.length, after: split.kept.length },
          deducted: split.deducted.slice(0, 20),
          deductedTotal: split.deducted.length,
          nameOnlyAudit: split.nameOnly.slice(0, 20),
          nameOnlyTotal: split.nameOnly.length,
          functionFloor: { names: activeFloor.names.size, rvas: activeFloor.rvas.size, bodies: activeFloor.bodyHashes.size },
        };
        if (filteredTargets.length === 0) {
          t2.reason = functionFilter
            ? `none of the requested functions are in the target inventory: ${functionFilter.join(', ')}`
            : 'the target inventory is empty';
        } else if (split !== null && split.kept.length === 0) {
          // Every window function matched the floor: there is nothing left to
          // average, and inventing a score would repeat the empty-denominator
          // failure. The undeducted average stays on record as scoreAll.
          t2.reason = `all ${filteredTargets.length} target functions in the window matched the toolchain floor; the deducted denominator is empty`;
          Object.assign(t2, deductionFields);
        } else if (inventory.score === null) {
          t2.reason = 'both inventories produced no comparable tokens';
          Object.assign(t2, deductionFields);
        } else {
          t2 = {
            status: 'ran',
            score: inventory.score,
            reason: null,
            scope: 'all-functions',
            entryRva: targetLayout.entryRva,
            coverage: inventory.coverage,
            matched: inventory.matched,
            functions: inventory.pairs,
            threshold: inventory.threshold,
            belowThreshold: inventory.belowThreshold ?? 0,
            truncated: targetList.truncated || rebuiltList.truncated || targetList.timeStopped || rebuiltList.timeStopped || targetList.analysisTimedOut || rebuiltList.analysisTimedOut,
            analysisTimedOut: targetList.analysisTimedOut === true || rebuiltList.analysisTimedOut === true,
            mismatches: inventory.mismatches,
            ...deductionFields,
          };
        }
      } else {
        // Older Ghidra scripts or an unstable analysis: keep the entry tier and
        // say why the inventory is missing, rather than silently degrading.
        const inventoryReason = targetList.reason ?? rebuiltList.reason ?? 'the function inventory produced no functions';
        const [targetCode, rebuiltCode] = await Promise.all([
          decompileWithGhidra(targetPath, { rva: targetLayout.entryRva, timeoutMs, signal }),
          decompileWithGhidra(rebuiltPath, { rva: rebuiltLayout?.entryRva ?? targetLayout.entryRva, timeoutMs, signal }),
        ]);
        if (!targetCode.ok || !rebuiltCode.ok) {
          t2.reason = `${inventoryReason}; entry fallback failed: ${targetCode.ok ? (rebuiltCode.reason ?? rebuiltCode.code) : (targetCode.reason ?? targetCode.code)}`;
        } else {
          const similarity = pseudocodeSimilarity(targetCode.code, rebuiltCode.code);
          if (similarity === null) {
            t2.reason = `${inventoryReason}; both entry decompilations produced no comparable tokens`;
          } else {
            t2 = {
              status: 'ran',
              score: similarity.similarity,
              reason: null,
              scope: 'entry',
              fallbackReason: inventoryReason,
              entryRva: targetLayout.entryRva,
              similarity,
              targetFunction: targetCode.function ?? null,
              rebuiltFunction: rebuiltCode.function ?? null,
            };
          }
        }
      }
    }
  } else {
    t2.reason = 'engine comparison disabled for this call';
  }

  // T3: constants from the reconstructed source against the target's strings.
  let t3 = { status: 'skipped', score: null, reason: 'no source text supplied', literals: 0, matched: [], unmatched: [] };
  if (typeof sourceText === 'string' && sourceText.length > 0) {
    const literals = sourceLiterals(sourceText);
    const matched = [];
    const unmatched = [];
    for (const literal of literals) {
      const found = [...targetStringsForLiterals].some((value) => value.includes(literal));
      (found ? matched : unmatched).push(literal);
    }
    t3 = {
      status: 'ran',
      score: ratio(matched.length, literals.size),
      reason: literals.size === 0 ? 'the source declares no string constants' : null,
      literals: literals.size,
      matched: matched.slice(0, 20),
      unmatched: unmatched.slice(0, 20),
    };
  }

  // T4: the behaviour surface, opt-in because it re-reads the same bytes as T1
  // and payload. It answers the question the structural tiers cannot: does the
  // rebuild emit the same messages, keep the same state and reach for the same
  // families of side effects.
  let t4 = {
    status: 'skipped',
    score: null,
    reason: 'the behaviour tier is opt-in; pass behavior=true to score outputs, state and effects',
    outputs: null,
    state: null,
    effects: null,
    families: null,
  };
  if (behavior === true) {
    const deepValues = (buffer) => extractDeepStrings(buffer, { minLength: 5, maxStrings: 1_500 }).map((entry) => entry.value);
    const targetContract = contractFrom({
      imports: [...apiSet(targetImports, floor.imports)],
      strings: deepValues(targetBuffer),
      floorStrings: floor.strings,
    });
    const rebuiltContract = contractFrom({
      imports: [...apiSet(rebuiltImports, floor.imports)],
      strings: deepValues(rebuiltBuffer),
      floorStrings: floor.strings,
    });
    t4 = compareBehaviorContracts(targetContract, rebuiltContract);
  }

  // T5: the GUI interaction surface, opt-in because it reads the engine's
  // function inventory a second time (a cache hit, not a second analysis). It
  // answers what the structural tiers cannot: does the rebuild keep the same
  // window procedures, message handling, control ids and dialog resources.
  const t5 = buildInteractionTier({
    enabled: interaction,
    engine,
    targetList,
    rebuiltList,
    target: { buffer: targetBuffer, layout: targetLayout, imports: targetImports },
    rebuilt: { buffer: rebuiltBuffer, layout: rebuiltLayout, imports: rebuiltImports },
    floorStrings: floor.strings,
  });

  const tiers = {
    t1: { status: t1Score === null ? 'empty' : 'ran', score: t1Score, imports: apiDiff, sections: { ...sectionDiff, jaccard: sectionJaccard } },
    payload: { status: payloadScore === null ? 'empty' : 'ran', score: payloadScore, indicators: indicatorDiff },
    t2,
    t3,
    t4,
    t5,
  };
  const WEIGHTS = { t1: 0.35, payload: 0.30, t2: 0.20, t3: 0.15, t4: 0.15, t5: 0.15 };
  const present = Object.entries(WEIGHTS).filter(([key]) => typeof tiers[key].score === 'number');
  const totalWeight = present.reduce((sum, [, weight]) => sum + weight, 0);
  const overall = present.length === 0
    ? null
    : present.reduce((sum, [key, weight]) => sum + tiers[key].score * weight, 0) / totalWeight;

  return {
    target: { path: targetPath, size: targetBuffer.length, sha256: sha256(targetBuffer), format: targetLayout ? 'pe' : 'non-pe' },
    rebuilt: { path: rebuiltPath, size: rebuiltBuffer.length, sha256: sha256(rebuiltBuffer), format: rebuiltLayout ? 'pe' : 'non-pe' },
    tiers,
    overall,
    weightsUsed: Object.fromEntries(present.map(([key, weight]) => [key, Number((weight / totalWeight).toFixed(3))])),
    dynamicEvidence: { strings: dynamicStrings.size, indicators: dynamicIndicators.size },
    limitations: [
      activeFloor !== null
        ? 'T2 compares function inventories up to the configured cap (48 by default, 200 maximum) with a 180-second decompile deadline; a truncated inventory says so. Target functions identified against the measured same-toolchain floor (name+RVA, name+body-hash, or body-hash only, each recorded with its matchedBy) are removed from the denominator before averaging: t2.score is the deducted average, t2.scoreAll keeps the undeducted average for comparison, and name-only hits are listed for audit but not deducted. Within either average, a target function with no counterpart scores zero rather than being dropped.'
        : 'T2 compares function inventories up to the configured cap (48 by default, 200 maximum) with a 180-second decompile deadline; a truncated inventory says so, and a target function with no counterpart scores zero rather than being dropped from the average.',
      'When the inventory cannot be produced, T2 falls back to the entry function and names the fallback; an entry comparison is a weaker claim than a function inventory.',
      'A different compiler changes the pseudocode: an MSVC target against a gcc rebuild scores low even when the source is identical.',
      'The payload tier compares IoC-shaped indicators and attribution canaries after subtracting the toolchain floor. Indicators that only exist in encoded form are invisible to it and need the decode channels or a dynamic trace.',
      ...(t4.status === 'ran' ? behaviorLimitations() : []),
      ...(t5.status === 'ran' ? interactionLimitations() : []),
      ...(t5.status === 'ran' && t5.inventoryTruncated
        ? ['T5 ran against a truncated function inventory: window procedures beyond the cap are invisible, so a missing interaction fact may be a coverage gap rather than a reconstruction gap.']
        : []),
      ...(dynamicStrings.size > 0 || dynamicIndicators.size > 0
        ? [`${dynamicStrings.size} dynamic string(s) and ${dynamicIndicators.size} dynamic indicator(s) were added to the target's truth set: they exist at run time, not in the file, so a static-only report would score a correct rebuild as fabrication.`]
        : []),
      'This is behavioural evidence about a rebuild, not proof that the recovered source is the original source. Equivalent source compiles differently.',
    ],
  };
}
