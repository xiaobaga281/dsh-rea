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
