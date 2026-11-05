/**
 * What is actually inside an APK.
 *
 * An APK is a ZIP whose entries are already deflate-compressed, so whole-file
 * entropy is 8.0 and every block is "high entropy" — the same shape the PE
 * heuristics read as "packed". On a 238 MB release APK that produced
 * "possibly-obfuscated (0.45)" and the advice to go find an OEP, which is not a
 * thing an Android package has.
 *
 * The index is at the end of the file, so the only correct way to read it is to
 * seek there. This module does that with a file handle: no 238 MB buffer, no
 * extraction, no execution.
 *
 * @module dsh-rea/lib/android
 */

import { open, stat } from 'node:fs/promises';
import { inflateRawSync } from 'node:zlib';
import { parseBinaryXml, summarizeManifest } from './axml.js';

const EOCD = 0x06054b50;
const CEN = 0x02014b50;
const APK_SIG_MAGIC = Buffer.from('APK Sig Block 42', 'latin1');

/** Seek to the end, find the central directory, return its records. */
export async function readArchiveIndex(path, { maxEntries = 4000 } = {}) {
  const info = await stat(path);
  const handle = await open(path, 'r');
  try {
    const tailLength = Math.min(66_000, info.size);
    const tail = Buffer.alloc(tailLength);
    await handle.read(tail, 0, tailLength, info.size - tailLength);
    let eocd = -1;
    for (let at = tail.length - 22; at >= 0; at -= 1) {
      if (tail.readUInt32LE(at) === EOCD) { eocd = at; break; }
    }
    if (eocd < 0) return { ok: false, reason: 'no end-of-central-directory record (not a ZIP, or truncated)' };
    const count = tail.readUInt16LE(eocd + 10);
    const directorySize = tail.readUInt32LE(eocd + 12);
    const directoryOffset = tail.readUInt32LE(eocd + 16);
    if (directoryOffset === 0xffffffff || count === 0xffff) {
      return { ok: false, reason: 'ZIP64 archive; this reader handles the 32-bit form only' };
    }

    const directory = Buffer.alloc(directorySize);
    await handle.read(directory, 0, directorySize, directoryOffset);

    // The APK signing block sits immediately before the index and is how v2/v3
    // signatures are stored; its absence is worth reporting, not inferring.
    let signedV2 = false;
    if (directoryOffset >= 16) {
      const magic = Buffer.alloc(16);
      await handle.read(magic, 0, 16, directoryOffset - 16);
      signedV2 = magic.equals(APK_SIG_MAGIC);
    }

    const entries = [];
    let cursor = 0;
    while (cursor + 46 <= directory.length && entries.length < maxEntries) {
      if (directory.readUInt32LE(cursor) !== CEN) break;
      const method = directory.readUInt16LE(cursor + 10);
      const compressedSize = directory.readUInt32LE(cursor + 20);
      const uncompressedSize = directory.readUInt32LE(cursor + 24);
      const nameLength = directory.readUInt16LE(cursor + 28);
      const extraLength = directory.readUInt16LE(cursor + 30);
      const commentLength = directory.readUInt16LE(cursor + 32);
      const localOffset = directory.readUInt32LE(cursor + 42);
      const name = directory.toString('utf8', cursor + 46, cursor + 46 + nameLength);
      entries.push({ name, method, compressedSize, uncompressedSize, localOffset });
      cursor += 46 + nameLength + extraLength + commentLength;
    }
    return {
      ok: true,
      size: info.size,
      entries,
      truncated: entries.length >= maxEntries,
      signedV2,
      directoryOffset,
    };
  } finally {
    await handle.close();
  }
}

const isDex = (name) => /^classes\d*\.dex$/.test(name);
const isNative = (name) => name.startsWith('lib/') && name.endsWith('.so');

/**
 * Turn an entry list into the facts an Android analyst asks for first.
 *
 * Deliberately counts and names rather than greps: the dex is compressed, and
 * "there are 41 native libraries across two ABIs" is a claim that survives
 * review, while a string pulled out of a deflate stream is a guess.
 */
export function summarizeApk(index, { name = '' } = {}) {
  if (!index?.ok) return null;
  const entries = index.entries;
  const dex = entries.filter((entry) => isDex(entry.name));
  const native = entries.filter((entry) => isNative(entry.name));
  const abis = new Map();
  for (const entry of native) {
    const abi = entry.name.split('/')[1] ?? 'unknown';
    const bucket = abis.get(abi) ?? [];
    bucket.push({ name: entry.name.split('/').pop(), bytes: entry.uncompressedSize });
    abis.set(abi, bucket);
  }
  const manifest = entries.find((entry) => entry.name === 'AndroidManifest.xml');
  const resources = entries.find((entry) => entry.name === 'resources.arsc');
  const signatureFiles = entries.filter((entry) => /^META-INF\/.*\.(RSA|DSA|EC|SF)$/i.test(entry.name));
  const uncompressed = entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0);
  const compressed = entries.reduce((sum, entry) => sum + entry.compressedSize, 0);

  const assets = entries.filter((entry) => entry.name.startsWith('assets/'));
  const res = entries.filter((entry) => entry.name.startsWith('res/'));
  return {
    entries: entries.length,
    indexTruncated: index.truncated === true,
    signature: {
      v1: signatureFiles.length > 0,
      v2OrNewer: index.signedV2,
      files: signatureFiles.slice(0, 4).map((entry) => entry.name),
    },
    manifest: manifest ? { name: manifest.name, bytes: manifest.uncompressedSize } : null,
    resources: resources ? { bytes: resources.uncompressedSize } : null,
    dex: {
      count: dex.length,
      names: dex.slice(0, 8).map((entry) => entry.name),
      bytes: dex.reduce((sum, entry) => sum + entry.uncompressedSize, 0),
    },
    native: {
      count: native.length,
      abis: [...abis.entries()].map(([abi, list]) => ({
        abi,
        count: list.length,
        bytes: list.reduce((sum, item) => sum + item.bytes, 0),
        largest: list.sort((a, b) => b.bytes - a.bytes).slice(0, 3).map((item) => item.name),
      })),
    },
    assets: { count: assets.length, bytes: assets.reduce((sum, entry) => sum + entry.uncompressedSize, 0) },
    resourcesCount: res.length,
    bytes: { compressed, uncompressed, ratio: compressed === 0 ? null : Number((uncompressed / compressed).toFixed(2)) },
    name,
  };
}

/** Read one entry, inflating it if the archive deflated it. */
export async function readEntryData(path, entry) {
  const handle = await open(path, 'r');
  try {
    const head = Buffer.alloc(30);
    await handle.read(head, 0, 30, entry.localOffset);
    if (head.readUInt32LE(0) !== 0x04034b50) throw new Error('bad local file header');
    const nameLength = head.readUInt16LE(26);
    const extraLength = head.readUInt16LE(28);
    const start = entry.localOffset + 30 + nameLength + extraLength;
    const raw = Buffer.alloc(entry.compressedSize);
    await handle.read(raw, 0, entry.compressedSize, start);
    if (entry.method === 0) return raw;
    if (entry.method === 8) return inflateRawSync(raw);
    throw new Error(`unsupported compression method ${entry.method}`);
  } finally {
    await handle.close();
  }
}

/**
 * Decode AndroidManifest.xml without apktool.
 *
 * The manifest is a few tens of kilobytes inside the archive; decoding it needs
 * a ZIP entry read and a binary-XML parse, not a JVM. apktool is still the right
 * tool for resources and smali - this is the part that answers "what is this".
 */
export async function readManifest(path) {
  const index = await readArchiveIndex(path, { maxEntries: 20_000 });
  if (!index.ok) return { ok: false, reason: index.reason };
  const entry = index.entries.find((item) => item.name === 'AndroidManifest.xml');
  if (!entry) return { ok: false, reason: 'no AndroidManifest.xml entry' };
  const data = await readEntryData(path, entry);
  const parsed = parseBinaryXml(data);
  const summary = summarizeManifest(parsed);
  return summary ? { ok: true, ...summary } : { ok: false, reason: parsed.reason ?? 'manifest had no <manifest> element' };
}
