/**
 * Sample identity: the facts that let one binary be linked to its family.
 *
 * A junior report says what a sample contains. A senior report says where it
 * came from: the same import set under a different overlay is the same build
 * family; an RSDS record names the project that produced it; a Rich header
 * names the toolchain that built it; an entry point beyond the raw data says a
 * stub unpacked at run time. None of that is behaviour - it is provenance, and
 * a static analyser can read every bit of it from the bytes.
 *
 * Everything here is pure parsing of one Buffer. Nothing executes the sample,
 * nothing reaches the network, and every claim keeps its evidence offset so a
 * human can re-check it. Where a mapping would have to come from an offline
 * dataset (Rich product ids to named compilers) the raw numbers are printed
 * instead of a guess.
 *
 * @module dsh-rea/lib/identity
 */

import { createHash } from 'node:crypto';

// ------------------------------------------------------------------ imphash --
/**
 * Import hash: md5 over "dll:api" in file order, DLL extension dropped,
 * names lowercased, ordinals kept as #N. The de-facto family pivot for PE
 * samples; a match is a strong hint of a common build lineage, never proof -
 * the same import set can be compiled twice by unrelated projects, and a
 * loader that resolves at runtime leaves the hash near-empty.
 */
export function imphashFromImports(imports) {
  if (!imports || !Array.isArray(imports.dlls) || imports.dlls.length === 0) return null;
  if (imports.truncated) return null;
  const parts = [];
  for (const dll of imports.dlls) {
    const name = String(dll.name).toLowerCase().replace(/\.(dll|exe|ocx|sys)$/, '');
    for (const api of dll.functions) {
      parts.push(`${name}:${String(api).toLowerCase()}`);
    }
  }
  if (parts.length === 0) return null;
  return createHash('md5').update(parts.join('')).digest('hex');
}

// ---------------------------------------------------------------- code view --
/**
 * Format the mixed-endian CodeView GUID: the first three groups are
 * little-endian, the last eight bytes are raw, as MSBuild prints it.
 */
function formatGuid(bytes, at) {
  const swap = (hex) => hex.match(/../g).reverse().join('');
  const hex = bytes.subarray(at, at + 16).toString('hex');
  return `${swap(hex.slice(0, 8))}-${swap(hex.slice(8, 12))}-${swap(hex.slice(12, 16))}-${hex.slice(16, 32)}`.toLowerCase();
}

const CV_MAX_RECORDS = 4;

/**
 * PDB identity records (RSDS = CodeView 7.0) recovered from raw bytes.
 *
 * Reading the debug directory would be the canonical route, but packers,
 * cert-table truncation and stripped directories routinely hide it, while the
 * RSDS block itself survives in .pdata, in overlays or in the resource blob.
 * A record counts only when the path after guid+age is printable and ends in
 * `.pdb` with a sane age, so a stray "RSDS" in unrelated data is not
 * evidence.
 */
export function recoverCodeView(buffer) {
  const out = [];
  const seen = new Set();
  let at = buffer.indexOf('RSDS', 0, 'latin1');
  // CV_INFO_PDB70: 'RSDS' | guid[16] | age[4] | path NUL-terminated.
  while (at !== -1 && out.length < CV_MAX_RECORDS && at + 28 <= buffer.length) {
    const pathStart = at + 24;
    let end = pathStart;
    while (end < buffer.length && end - pathStart < 512 && buffer[end] >= 0x20 && buffer[end] <= 0x7e) end += 1;
    const terminated = end < buffer.length && buffer[end] === 0;
    const path = terminated && end > pathStart ? buffer.toString('latin1', pathStart, end) : null;
    if (path && /\.pdb$/i.test(path)) {
      const age = buffer.readUInt32LE(at + 20);
      const guid = formatGuid(buffer, at + 4);
      const key = `${guid}:${path.toLowerCase()}`;
      if (age > 0 && age < 0x10000 && !seen.has(key)) {
        seen.add(key);
        out.push({ guid, age, path, at });
      }
    }
    at = buffer.indexOf('RSDS', at + 4, 'latin1');
  }
  return out;
}

// --------------------------------------------------------------- rich header --
const DAN_S = 0x536e6144; // 'DanS' LE
const RICH = 0x68636952; // 'Rich' LE
const HCR_Q = 0x3f526348; // 'HcR?' LE

/**
 * Rich header: the MSVC build stamp XOR-embedded between the DOS stub and the
 * PE header. Recovery is self-validating - the block opens with "DanS" over a
 * zero word and closes with "Rich", "HcR?" and the key word itself. If the
 * three markers do not agree on one key there is no header, and the answer is
 * null rather than a guess. Modern Windows system binaries stopped shipping
 * the header around 2017, so absence on a signed Microsoft file is normal.
 */
export function richHeader(buffer) {
  if (buffer.length < 0x40 || buffer.toString('latin1', 0, 2) !== 'MZ') return null;
  const e_lfanew = buffer.readUInt32LE(0x3c);
  if (e_lfanew <= 0x40 || e_lfanew > 0x1000 || e_lfanew + 4 > buffer.length) return null;
  const limit = e_lfanew;
  const u32 = (at) => buffer.readUInt32LE(at);
  for (let dansAt = 0x80; dansAt + 16 <= limit; dansAt += 4) {
    const key = u32(dansAt) ^ DAN_S;
    if (key === 0) continue;
    if ((u32(dansAt + 4) ^ key) !== 0) continue; // zero word follows DanS
    let richAt = -1;
    for (let p = dansAt + 8; p + 8 <= limit; p += 4) {
      if ((u32(p) ^ key) === RICH) { richAt = p; break; }
    }
    if (richAt === -1 || richAt + 12 > buffer.length) continue;
    if ((u32(richAt + 4) ^ key) !== HCR_Q) continue;
    if (u32(richAt + 8) !== key) continue;
    const span = richAt - (dansAt + 8);
    if (span < 8 || span % 8 !== 0 || span / 8 > 96) continue;
    const entries = [];
    for (let at = dansAt + 8; at < richAt; at += 8) {
      const compId = u32(at) ^ key;
      const count = u32(at + 4) ^ key;
      if (count <= 0 || count > 10_000_000) { entries.length = 0; break; }
      entries.push({ product: compId & 0xffff, build: (compId >>> 16) & 0xffff, count });
    }
    if (entries.length === 0) continue;
    return { at: dansAt, key: `0x${key.toString(16)}`, entries };
  }
  return null;
}

// ------------------------------------------------------------- entry checks --
/**
 * Entry-point placement anomalies that read as "a stub unpacks before main".
 */
export function entryAnomalies(layout) {
  const issues = [];
  if (!layout || !Array.isArray(layout.sections)) return issues;
  const entrySection = layout.sections.find((section) => layout.entryRva >= section.virtualAddress
    && layout.entryRva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize));
  if (!entrySection) {
    issues.push('entry point lies outside every section');
    return issues;
  }
  if (entrySection.rawSize > 0 && layout.entryRva >= entrySection.virtualAddress + entrySection.rawSize) {
    issues.push(`entry RVA 0x${(layout.entryRva >>> 0).toString(16)} sits past the raw data of ${entrySection.name} (virtual 0x${(entrySection.virtualSize >>> 0).toString(16)} vs raw 0x${(entrySection.rawSize >>> 0).toString(16)}): those bytes only exist after the stub unpacks at run time`);
  }
  if (/\.(rsrc|data|reloc|debug)/i.test(entrySection.name)) {
    issues.push(`entry point is in ${entrySection.name}, not .text (typical for packers and loaders)`);
  }
  return issues;
}

// ---------------------------------------------------------------- timestamp --
/**
 * COFF TimeDateStamp as raw plus UTC text. Beyond 2038 (or a decade ahead of
 * the clock) this is almost never a real build date: Microsoft randomizes the
 * stamp of system binaries precisely to break "compile time as evidence", and
 * many packers zero or scramble it. The text flags that instead of letting a
 * reader quote "built 2084" as a fact.
 */
export function peTimeStamp(buffer) {
  if (buffer.length < 0x40 || buffer.toString('latin1', 0, 2) !== 'MZ') return null;
  const pe = buffer.readUInt32LE(0x3c);
  if (pe + 12 > buffer.length || buffer.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
  const value = buffer.readUInt32LE(pe + 8);
  if (value === 0) return { raw: 0, iso: null, note: 'zeroed (common with deterministic builds and packers)' };
  const date = new Date(value * 1000);
  const future = date.getTime() > Date.now() + 365 * 86400 * 1000;
  return {
    raw: value,
    iso: date.toISOString().replace('.000Z', 'Z'),
    ...(future ? { note: 'in the future: randomized stamp (MS system binaries) or packer artifact, not a build date' } : {}),
  };
}
