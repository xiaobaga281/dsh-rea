/**
 * Tiny shared primitives for the PE/.NET byte parsers (lib/structure.js,
 * lib/managed.js, lib/cil.js). Deliberately dependency-free so every parser
 * reads bytes through one tested implementation instead of three lookalikes.
 *
 * @module dsh-rea/lib/managed-internals
 */
export const u8 = (bytes, at) => bytes.readUInt8(at);
export const u16 = (bytes, at) => bytes.readUInt16LE(at);
export const u32 = (bytes, at) => bytes.readUInt32LE(at);
export const index = (bytes, at, width) => (width === 2 ? bytes.readUInt16LE(at) : bytes.readUInt32LE(at));

// ------------------------------------------------------- shared PE layout ----

// The layout primitives live in this shared module (not in structure.js) so
// the managed parser can use them without an import cycle: structure.js
// imports parseManaged, so managed.js cannot import structure.js back.


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
  // Fall through overlapping ranges: a section that contains the RVA but not
  // its raw data is not the answer, and returning null here would make the
  // widest virtual range swallow every later section (grown VirtualSize is a
  // classic malformed-PE and packer artifact).
  for (const section of layout.sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      const delta = rva - section.virtualAddress;
      if (delta < section.rawSize) return section.rawPointer + delta;
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
