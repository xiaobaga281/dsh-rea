/**
 * Container recovery: find data that is compressed or packed inside the file
 * instead of merely encoded.
 *
 * The duel's D3 generation compressed its whole config with zlib. Nothing in
 * 1.6.0 touched it - a plain `strings` pass cannot see through deflate, and the
 * XOR channels only look at the bytes as they are. Compressed config is
 * extremely common in real samples (zlib, gzip, and raw deflate produced by
 * hand-rolled packers), so the analyser needs a first-class pass for it.
 *
 * Everything here is bounded: a byte cap per stream, a cap on streams, and a
 * scan window. Decompression is done by Node's zlib on a Buffer that has already
 * been read from disk - the sample is never executed.
 */
import { inflateRawSync, inflateSync } from 'node:zlib';

const DEFAULT_SCAN = 4 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT = 2 * 1024 * 1024;

/** Section table of a PE file, or null when the input is not a PE. */
export function peSections(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length < 0x40 || buffer.toString('latin1', 0, 2) !== 'MZ') return null;
  const pe = buffer.readUInt32LE(0x3c);
  if (pe + 24 > buffer.length || buffer.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
  const coff = pe + 4;
  const count = buffer.readUInt16LE(coff + 2);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  const opt = coff + 20;
  if (opt + optionalSize > buffer.length) return null;
  const table = opt + optionalSize;
  const sections = [];
  for (let i = 0; i < Math.min(count, 96); i += 1) {
    const at = table + i * 40;
    if (at + 40 > buffer.length) break;
    const characteristics = buffer.readUInt32LE(at + 36);
    sections.push({
      name: buffer.toString('latin1', at, at + 8).replace(/\0/g, '').trim(),
      virtualAddress: buffer.readUInt32LE(at + 12),
      rawSize: buffer.readUInt32LE(at + 16),
      rawOffset: buffer.readUInt32LE(at + 20),
      // MEM_WRITE is 0x80000000: a section is read-only when that bit is clear
      // and MEM_READ (0x40000000) is set.
      readOnly: (characteristics & 0x80000000) === 0 && (characteristics & 0x40000000) !== 0,
      executable: (characteristics & 0x20000020) !== 0,
    });
  }
  return sections;
}

const looksCompressed = (data) => {
  if (data.length < 48) return false;
  const sample = data.subarray(0, Math.min(data.length, 4096));
  let printable = 0;
  for (const byte of sample) if (byte >= 0x20 && byte <= 0x7e) printable += 1;
  return printable / sample.length > 0.5;
};

/**
 * Locate and open deflate/gzip streams.
 *
 * A zlib header is self-validating: the two bytes form a multiple of 31, which
 * makes a false positive about 1 in 31 per position but reduces to near zero
 * once inflate actually succeeds. Raw deflate has no header at all, so it is
 * only attempted at the start of a high-entropy region, where a packer would
 * have placed it.
 *
 * @returns {Array<{at:number, kind:string, data:Buffer}>}
 */
export function inflateCandidates(bytes, {
  scanBytes = DEFAULT_SCAN,
  maxStreams = 6,
  maxOutput = DEFAULT_MAX_OUTPUT,
  regions = [],
  // A stream can legitimately expand to binary: a packed config is often a
  // compressed record table that is itself XORed. The zlib checksum already
  // proves the stream is real, so text output is not a validity signal.
  requireText = false,
} = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const out = [];
  const seenLength = new Set();

  const attempt = (at, kind) => {
    if (out.length >= maxStreams || at < 0 || at >= buffer.length) return;
    let data;
    try {
      const options = { maxOutputLength: maxOutput };
      data = kind === 'deflate-raw'
        ? inflateRawSync(buffer.subarray(at), options)
        : inflateSync(buffer.subarray(at), options);
    } catch {
      return;
    }
    if (!data || data.length < 48) return;
    if (requireText && !looksCompressed(data)) return;
    // The same stream can be reached from several offsets once the header is
    // located; one entry per decoded length keeps the string list clean.
    const key = `${data.length}:${data.toString('latin1', 0, 12)}`;
    if (seenLength.has(key)) return;
    seenLength.add(key);
    out.push({ at, kind, data });
  };

  const limit = Math.min(buffer.length - 2, scanBytes);
  let attempts = 0;
  for (let at = 0; at <= limit; at += 1) {
    const b0 = buffer[at];
    const b1 = buffer[at + 1];
    if (b0 === 0x78 && (b1 === 0x01 || b1 === 0x5e || b1 === 0x9c || b1 === 0xda || b1 === 0x9d)
      && ((b0 << 8) | b1) % 31 === 0) {
      attempt(at, 'zlib');
      attempts += 1;
    } else if (b0 === 0x1f && b1 === 0x8b) {
      attempt(at, 'gzip');
      attempts += 1;
    }
    if (out.length >= maxStreams || attempts > 512) break;
  }

  if (out.length < maxStreams) {
    for (const region of regions) {
      for (const delta of [0, 1, 2, 3, 8, 16]) {
        attempt(Math.max(0, region.start - delta), 'deflate-raw');
        if (out.length >= maxStreams) break;
      }
      if (out.length >= maxStreams) break;
    }
  }
  return out;
}

/** High-entropy spans that no recovered container or blob explains. */
export function unresolvedRegions(report, { slack = 96 } = {}) {
  if (!report || !Array.isArray(report.regions)) return [];
  const explained = [
    ...(report.blobs ?? []).map((blob) => ({ start: blob.start, end: blob.end })),
    ...(report.containers ?? []).map((item) => ({ start: item.at, end: item.at + slack })),
  ];
  return report.regions.filter((region) => !explained.some((span) => (
    region.start <= span.end + slack && region.end >= span.start - slack
  )));
}
