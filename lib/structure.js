/**
 * Structural recovery for targets that hide their shape, not just their text.
 *
 * String recovery answers "what does it say"; this answers "what is it made of".
 * Three questions matter before any decompiler is opened:
 *
 *   1. Is there anything before the entry point? A TLS callback is the standard
 *      place for an anti-debug check that fires first.
 *   2. Is the control flow flattened? A dispatch table of code pointers in a
 *      read-only section is the signature - not proof, and the count is what
 *      decides, because a compiler switch table looks exactly the same.
 *   3. Do the sections make sense? W+X, raw size zero with a virtual size, and
 *      overlapping file ranges are what a hand-rolled loader looks like.
 *
 * API-hash recovery is deliberately *not* reimplemented here: `api-hash.js`
 * already owns the dictionary, the five algorithms and the provenance rules,
 * and a second copy would drift. This module consumes its results.
 *
 * Everything is read-only and heuristic. Each finding carries the evidence that
 * produced it, so a human can check the reasoning instead of trusting a verdict.
 *
 * @module dsh-rea/lib/structure
 */

import { recoverHashedApis } from './api-hash.js';

// ---------------------------------------------------------------- PE layout --

const u16 = (bytes, at) => bytes.readUInt16LE(at);
const u32 = (bytes, at) => bytes.readUInt32LE(at);

/**
 * Minimal header reader: sections, data directories and image base.
 *
 * `triage.js` has its own PE reader built around entropy and ratios; this one
 * exists for characteristics and directories. Merging them would give one
 * function two unrelated jobs, so they stay separate and small.
 */
export function readPeLayout(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length < 0x40 || buffer.toString('latin1', 0, 2) !== 'MZ') return null;
  const pe = u32(buffer, 0x3c);
  if (pe + 24 > buffer.length || buffer.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
  const coff = pe + 4;
  const sectionCount = u16(buffer, coff + 2);
  const optionalSize = u16(buffer, coff + 16);
  const optional = coff + 20;
  if (optional + optionalSize > buffer.length) return null;
  const magic = u16(buffer, optional);
  const plus = magic === 0x20b;
  if (!plus && magic !== 0x10b) return null;
  const imageBase = plus ? Number(buffer.readBigUInt64LE(optional + 24)) : u32(buffer, optional + 28);
  const entryRva = u32(buffer, optional + 16);
  const directoryCount = u32(buffer, optional + (plus ? 108 : 92));
  const directoryAt = optional + (plus ? 112 : 96);
  const dataDirs = [];
  for (let index = 0; index < Math.min(directoryCount, 16); index += 1) {
    const at = directoryAt + index * 8;
    if (at + 8 > buffer.length) break;
    dataDirs.push({ rva: u32(buffer, at), size: u32(buffer, at + 4) });
  }
  const sections = [];
  const table = optional + optionalSize;
  for (let index = 0; index < Math.min(sectionCount, 96); index += 1) {
    const at = table + index * 40;
    if (at + 40 > buffer.length) break;
    const characteristics = u32(buffer, at + 36);
    sections.push({
      name: buffer.toString('latin1', at, at + 8).replace(/\0.*$/, '').trim(),
      virtualAddress: u32(buffer, at + 12),
      virtualSize: u32(buffer, at + 8),
      rawPointer: u32(buffer, at + 20),
      rawSize: u32(buffer, at + 16),
      characteristics,
      executable: (characteristics & 0x20000020) !== 0,
      writable: (characteristics & 0x80000000) !== 0,
      readable: (characteristics & 0x40000000) !== 0,
    });
  }
  return { plus, imageBase, entryRva, dataDirs, sections, sizeOfHeaders: u32(buffer, optional + 60) };
}

export function rvaToOffset(layout, rva) {
  for (const section of layout.sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      const delta = rva - section.virtualAddress;
      return delta < section.rawSize ? section.rawPointer + delta : null;
    }
  }
  return rva < layout.sizeOfHeaders ? rva : null;
}

export function sectionOfRva(layout, rva) {
  for (const section of layout.sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) return section.name;
  }
  return null;
}

// -------------------------------------------------------------- TLS callback --

/** Callbacks in the TLS directory run before the entry point, every time. */
export function parseTlsCallbacks(bytes, layout) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const directory = layout.dataDirs[9];
  if (!directory || directory.rva === 0 || directory.size === 0) return { present: false, callbacks: [] };
  const at = rvaToOffset(layout, directory.rva);
  if (at === null || at + 24 > buffer.length) return { present: false, callbacks: [] };
  const field = layout.plus ? at + 24 : at + 12;
  if (field + 4 > buffer.length) return { present: false, callbacks: [] };
  const callbacksVa = layout.plus ? Number(buffer.readBigUInt64LE(field)) : u32(buffer, field);
  if (callbacksVa === 0 || callbacksVa < layout.imageBase) {
    return { present: true, directoryRva: directory.rva, callbacks: [], note: 'callback array address is not a VA (possibly unrelocated)' };
  }
  const arrayAt = rvaToOffset(layout, callbacksVa - layout.imageBase);
  if (arrayAt === null) return { present: true, directoryRva: directory.rva, callbacks: [], note: 'callback array is outside the mapped image' };
  const callbacks = [];
  for (let index = 0; index < 16; index += 1) {
    const slot = arrayAt + index * (layout.plus ? 8 : 4);
    if (slot + 4 > buffer.length) break;
    const value = layout.plus ? Number(buffer.readBigUInt64LE(slot)) : u32(buffer, slot);
    if (value === 0) break;
    const rva = value - layout.imageBase;
    callbacks.push({ va: value, rva, section: sectionOfRva(layout, rva) });
  }
  return { present: true, directoryRva: directory.rva, callbacks };
}

// ------------------------------------------------------ control-flow flattening --

/**
 * Number of code-pointer tables above which "flattening" stops being a
 * supportable hypothesis. Measured on 7-Zip's 600 KB console build: 33 such
 * tables, all compiler switch tables. A hand-written dispatcher is one table,
 * occasionally two; nobody writes thirty-three.
 */
const FLATTEN_MAX_TABLES = 3;
const FLATTEN_MIN_ENTRIES = 16;

/**
 * Code-pointer tables are runs of code pointers in a read-only section. Export
 * address tables look identical, so the export directory is excluded: reporting
 * a normal DLL's EAT as a flattened state machine would be worse than silence.
 */
export function findCodePointerTables(bytes, layout, { minEntries = 12 } = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const executable = layout.sections.filter((section) => section.executable);
  if (executable.length === 0) return [];
  const inCode = (value) => executable.some((section) => value >= layout.imageBase + section.virtualAddress
    && value < layout.imageBase + section.virtualAddress + Math.max(section.virtualSize, section.rawSize));
  const exportDir = layout.dataDirs[0];
  const exportRange = exportDir && exportDir.rva > 0
    ? [exportDir.rva, exportDir.rva + Math.max(exportDir.size, 0x28)]
    : null;

  const found = [];
  const consider = (section, run) => {
    if (!run || run.entries < minEntries) return;
    found.push({
      section: section.name,
      rva: section.virtualAddress + (run.start - section.rawPointer),
      at: run.start,
      entries: run.entries,
    });
  };

  for (const section of layout.sections) {
    if (section.executable || section.rawSize < 64) continue;
    const start = section.rawPointer;
    const end = Math.min(start + Math.min(section.rawSize, 256 * 1024), buffer.length);
    let run = null;
    for (let at = start; at + 4 <= end; at += 4) {
      const value = u32(buffer, at);
      const rva = value - layout.imageBase;
      const usable = value > layout.imageBase && inCode(value)
        && !(exportRange && rva >= exportRange[0] && rva < exportRange[1]);
      if (usable) {
        if (!run) run = { start: at, entries: 0 };
        run.entries += 1;
      } else {
        consider(section, run);
        run = null;
      }
    }
    consider(section, run);
  }
  return found;
}

/**
 * Decide whether any of those tables may be called a flattened dispatcher.
 *
 * A compiler switch table and a CFF dispatch table have the *same* static shape:
 * a run of code pointers in .rdata, referenced from one indirect jump. The
 * difference lives in the decoder loop, which is code - deciding it offline
 * would need a disassembler this layer does not have. So the only honest move is
 * to count: a binary with dozens of such tables has a switch-heavy compiler, and
 * a single-table claim about it is unsupportable. Below that threshold the
 * hypothesis is still only a hypothesis, hence `confidence: 'low'` on every
 * entry and a note explaining what would refute it.
 */
export function classifyCodePointerTables(tables, { maxTables = FLATTEN_MAX_TABLES, minEntries = FLATTEN_MIN_ENTRIES } = {}) {
  if (tables.length === 0) {
    return { dispatchTables: [], note: null };
  }
  if (tables.length > maxTables) {
    return {
      dispatchTables: [],
      note: `${tables.length} code-pointer tables in read-only sections: the count itself says compiler switch tables, not flattening, so no dispatcher is claimed`,
    };
  }
  const candidates = tables.filter((table) => table.entries >= minEntries);
  if (candidates.length === 0) {
    return {
      dispatchTables: [],
      note: `${tables.length} small code-pointer table(s), none large enough to carry a state machine`,
    };
  }
  return {
    dispatchTables: candidates.slice(0, 2).map((table) => ({ ...table, confidence: 'low' })),
    note: null,
  };
}

// ------------------------------------------------------------------ anomalies --

export function structuralAnomalies(layout, { importsPresent = false } = {}) {
  const anomalies = [];
  if (!importsPresent) anomalies.push('no import directory: API names must be resolved from hashes, ordinals or delay-load entries');
  for (const section of layout.sections) {
    if (section.writable && section.executable) anomalies.push(`section ${section.name} is writable and executable (W+X)`);
    if (section.rawSize === 0 && section.virtualSize > 0) {
      anomalies.push(`section ${section.name} has no raw data but reserves ${section.virtualSize} bytes at run time`);
    }
    // A .data section far larger in memory than in the file is ordinary
    // uninitialised data - every C program has one. It only matters when the
    // expansion happens in *code*, where it means a stub unpacking itself.
    if (section.executable && section.rawSize > 0 && section.virtualSize > section.rawSize * 4) {
      anomalies.push(`executable section ${section.name} virtual size is ${(section.virtualSize / section.rawSize).toFixed(1)}x its raw size: room for a self-unpacking stub`);
    }
  }
  const ordered = layout.sections.filter((section) => section.rawSize > 0).sort((a, b) => a.rawPointer - b.rawPointer);
  for (let index = 1; index < ordered.length; index += 1) {
    const previous = ordered[index - 1];
    if (previous.rawPointer + previous.rawSize > ordered[index].rawPointer) {
      anomalies.push(`sections ${previous.name} and ${ordered[index].name} overlap in the file`);
    }
  }
  if (sectionOfRva(layout, layout.entryRva) === null) {
    anomalies.push(`entry point RVA 0x${layout.entryRva.toString(16)} is outside every section`);
  }
  return anomalies;
}

/**
 * One call that answers "what is this made of", used by triage and the duel.
 * The hash scan is bounded to read-only sections so instruction immediates in
 * code do not turn into fake API names.
 */
export function structureProfile(bytes, { hashLimit = 512 * 1024, salt = null } = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const layout = readPeLayout(buffer);
  if (!layout) return null;

  const data = Buffer.from(buffer);
  const importsDir = layout.dataDirs[1];
  const importsPresent = Boolean(importsDir && importsDir.rva !== 0 && importsDir.size !== 0);

  // Restrict the shared scanner to the data sections by handing it a view with
  // code zeroed out. Cheaper than a second implementation, and it keeps one
  // dictionary and one set of hash functions in the project.
  const masked = Buffer.alloc(data.length);
  for (const section of layout.sections) {
    if (section.executable || section.rawSize === 0) continue;
    const end = Math.min(section.rawPointer + section.rawSize, data.length);
    if (section.rawPointer < end) data.copy(masked, section.rawPointer, section.rawPointer, end);
  }
  const hashed = recoverHashedApis(masked, { scanBytes: Math.min(data.length, hashLimit), salt });

  const tls = parseTlsCallbacks(buffer, layout);
  const tables = findCodePointerTables(buffer, layout);
  const classified = classifyCodePointerTables(tables);

  return {
    imageBase: layout.imageBase,
    entryRva: layout.entryRva,
    importsPresent,
    importDirectory: importsPresent ? { rva: importsDir.rva, size: importsDir.size } : null,
    tls,
    codePointerTables: tables,
    dispatchTables: classified.dispatchTables,
    dispatchNote: classified.note,
    hashedApis: {
      count: hashed.apis.length,
      truncated: hashed.truncated,
      // A salted table only exists as a finding when the salt came from the
      // sample itself; recording that keeps the report from implying the
      // algorithm was guessed.
      salt: Number.isInteger(salt) && salt !== 0 ? salt >>> 0 : null,
      algorithms: [...new Set(hashed.apis.map((item) => item.algorithm))],
      items: hashed.apis.slice(0, 48).map((item) => ({ api: item.api, algorithm: item.algorithm, at: item.at })),
    },
    anomalies: structuralAnomalies(layout, { importsPresent }),
    sections: layout.sections.map((section) => ({
      name: section.name, virtualAddress: section.virtualAddress, virtualSize: section.virtualSize,
      rawPointer: section.rawPointer, rawSize: section.rawSize,
      executable: section.executable, writable: section.writable,
    })),
  };
}
