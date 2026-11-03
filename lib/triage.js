/**
 * Static triage for an unknown binary - the "first ten minutes" of reverse
 * engineering that REA's tool surface does not cover at all.
 *
 * Everything here is local and read-only: no analysis engine, no execution of
 * the sample, no network. It answers the questions that decide which path the
 * rest of an analysis should take - is this packed, is it obfuscated, is the
 * entry point in a plausible section, are there encrypted strings - before a
 * decompiler wastes time on bytes it cannot interpret.
 *
 * The conclusions are heuristic by construction. The report says so, and names
 * the evidence behind each one; it is triage, not proof.
 *
 * @module dsh-rea/lib/triage
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { open, readdir, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';

/** A 28 MB runtime is fine to hash; a sample is capped so this never OOMs. */
export const DEFAULT_MAX_TRIAGE_BYTES = 64 * 1024 * 1024;
const DEFAULT_BLOCK_SIZE = 4096;
const HIGH_ENTROPY = 7.0;
const STRING_MIN_LENGTH = 5;
const MAX_STRINGS = 120;

/** Shannon entropy over a byte range, 0..8. */
export function shannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Blocked entropy reveals packed regions that whole-file entropy averages away. */
export function entropyProfile(bytes, blockSize = DEFAULT_BLOCK_SIZE) {
  const blocks = [];
  for (let offset = 0; offset < bytes.length; offset += blockSize) {
    const slice = bytes.subarray(offset, Math.min(offset + blockSize, bytes.length));
    blocks.push({ offset, size: slice.length, entropy: Number(shannonEntropy(slice).toFixed(3)) });
  }
  const high = blocks.filter((block) => block.entropy >= HIGH_ENTROPY).length;
  const sum = blocks.reduce((total, block) => total + block.entropy, 0);
  return {
    overall: Number(shannonEntropy(bytes).toFixed(3)),
    blockSize,
    highBlockRatio: blocks.length === 0 ? 0 : Number((high / blocks.length).toFixed(3)),
    mean: blocks.length === 0 ? 0 : Number((sum / blocks.length).toFixed(3)),
    max: blocks.length === 0 ? 0 : Math.max(...blocks.map((block) => block.entropy)),
    blocks,
  };
}

/** Printable ASCII runs, with a cheap UTF-16LE pass for Windows samples. */
export function extractStrings(bytes, { minLength = STRING_MIN_LENGTH, maxStrings = MAX_STRINGS } = {}) {
  const found = [];
  const push = (value, offset, encoding) => {
    if (value.length >= minLength && found.length < maxStrings) found.push({ offset, encoding, value: value.slice(0, 300) });
  };
  let run = '';
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    if (byte >= 0x20 && byte <= 0x7e) {
      if (run.length === 0) start = index;
      run += String.fromCharCode(byte);
    } else {
      push(run, start, 'ascii');
      run = '';
    }
    if (found.length >= maxStrings) break;
  }
  push(run, start, 'ascii');

  // UTF-16LE: ASCII byte followed by a zero byte. Only collect if the ASCII
  // pass found few strings, otherwise PE/ELF headers dominate both lists.
  if (found.length < maxStrings) {
    run = '';
    start = 0;
    for (let index = 0; index + 1 < bytes.length; index += 2) {
      const byte = bytes[index];
      if (byte >= 0x20 && byte <= 0x7e && bytes[index + 1] === 0) {
        if (run.length === 0) start = index;
        run += String.fromCharCode(byte);
      } else {
        push(run, start, 'utf16le');
        run = '';
      }
      if (found.length >= maxStrings) break;
    }
    push(run, start, 'utf16le');
  }
  return found;
}

const XOR_MARKERS = [
  'http', 'software', 'kernel32', 'user32', 'getprocaddress', 'loadlibrary',
  'virtualalloc', 'createfile', 'cmd.exe', 'this program', 'regedit',
  'connect', 'socket', 'password', 'mozi', 'c:\\',
];

/**
 * Single-byte XOR probe over a bounded sample. A hit means "someone XOR'd
 * readable text with one byte", which is the cheapest string encryption there
 * is; it is a hint to look closer, not a decryption of the whole sample.
 */
export function xorProbe(bytes, { sampleBytes = 64 * 1024, limit = 3 } = {}) {
  const sample = bytes.subarray(0, Math.min(bytes.length, sampleBytes));
  if (sample.length === 0) return [];
  const hits = [];
  for (let key = 1; key < 256; key += 1) {
    let printable = 0;
    const decoded = Buffer.allocUnsafe(sample.length);
    for (let index = 0; index < sample.length; index += 1) {
      const value = sample[index] ^ key;
      decoded[index] = value;
      if (value >= 0x20 && value <= 0x7e) printable += 1;
    }
    const lower = decoded.toString('latin1').toLowerCase();
    const markers = XOR_MARKERS.filter((marker) => lower.includes(marker));
    if (markers.length === 0) continue;
    hits.push({ key, printableRatio: Number((printable / sample.length).toFixed(3)), markers: markers.slice(0, 4) });
  }
  return hits
    .sort((a, b) => b.markers.length - a.markers.length || b.printableRatio - a.printableRatio)
    .slice(0, limit);
}

/** Byte/string signatures of common packers, protectors and obfuscators. */
export const PACKER_SIGNATURES = [
  { family: 'UPX', markers: ['UPX0', 'UPX1', 'UPX!', '$Id: UPX'] },
  { family: 'VMProtect', markers: ['.vmp0', '.vmp1', 'VMProtect'] },
  { family: 'Themida / WinLicense', markers: ['Themida', '.themida', 'WinLicen', 'Oreans'] },
  { family: 'ASPack', markers: ['.aspack', '.adata', 'ASPack'] },
  { family: 'MPRESS', markers: ['.MPRESS', 'MPRESS'] },
  { family: 'PECompact / Petite / FSG', markers: ['PECompact', 'PEC2', 'petite', 'FSG!'] },
  { family: 'Armadillo / Enigma / Obsidium', markers: ['Armadillo', 'Enigma', 'Obsidium'] },
  { family: 'NSIS installer', markers: ['NullsoftInst', 'NSIS'] },
  { family: 'PyInstaller', markers: ['pyi-', 'PyInstaller', 'PYZ-00.pyz', 'MEI\x0c\x0b\x0a\x0b\x0e'] },
  { family: 'AutoIt', markers: ['AU3!EA'] },
  { family: '.NET Reactor', markers: ['.NET Reactor', 'Reactor'] },
  { family: 'ConfuserEx', markers: ['ConfuserEx', 'Confuser'] },
  { family: 'Eazfuscator / SmartAssembly / Dotfuscator', markers: ['Eazfuscator', 'SmartAssembly', 'Dotfuscator'] },
];

export function detectPackers(bytes) {
  const matches = [];
  for (const signature of PACKER_SIGNATURES) {
    const markers = signature.markers.filter((marker) => bytes.indexOf(Buffer.from(marker, 'latin1')) !== -1);
    if (markers.length > 0) matches.push({ family: signature.family, markers });
  }
  return matches;
}

const SUSPICIOUS_SECTIONS = /^(upx\d?|\.vmp\d?|\.themida|\.aspack|\.adata|\.mpress\d?|pec\d?|petite|fsg|nsp\d?|\.reactor|confuser|\.enigma|\.packed)$/i;
const EXECUTABLE_SECTIONS = /^(\.text|\.code|text|code|__text|\.init|\.rdata)$/i;

/** Minimal PE/COFF reader - only the fields a triage decision needs. */
export function parsePE(bytes) {
  if (bytes.length < 0x40) return null;
  const peOffset = bytes.readUInt32LE(0x3c);
  if (peOffset + 24 > bytes.length || bytes.toString('latin1', peOffset, peOffset + 4) !== 'PE\0\0') return null;
  const coff = peOffset + 4;
  const sectionCount = bytes.readUInt16LE(coff + 2);
  const optionalSize = bytes.readUInt16LE(coff + 16);
  const optional = coff + 20;
  if (optional + optionalSize > bytes.length) return null;
  const magic = bytes.readUInt16LE(optional);
  const plus = magic === 0x20b;
  if (!plus && magic !== 0x10b) return null;
  const entryRva = bytes.readUInt32LE(optional + 16);
  const directoryCountOffset = optional + (plus ? 108 : 92);
  const directoryOffset = optional + (plus ? 112 : 96);
  const importDir = directoryCountOffset + 4 <= bytes.length && bytes.readUInt32LE(directoryCountOffset) > 1
    ? { rva: bytes.readUInt32LE(directoryOffset + 8), size: bytes.readUInt32LE(directoryOffset + 12) }
    : null;

  const sections = [];
  const table = optional + optionalSize;
  for (let index = 0; index < Math.min(sectionCount, 96); index += 1) {
    const at = table + index * 40;
    if (at + 40 > bytes.length) break;
    const name = bytes.toString('latin1', at, at + 8).replace(/\0.*$/, '').trim();
    const virtualSize = bytes.readUInt32LE(at + 8);
    const virtualAddress = bytes.readUInt32LE(at + 12);
    const rawSize = bytes.readUInt32LE(at + 16);
    const rawPointer = bytes.readUInt32LE(at + 20);
    let entropy = null;
    if (rawSize > 0 && rawPointer + rawSize <= bytes.length) {
      entropy = Number(shannonEntropy(bytes.subarray(rawPointer, rawPointer + rawSize)).toFixed(3));
    }
    sections.push({
      name,
      virtualSize,
      virtualAddress,
      rawSize,
      rawPointer,
      entropy,
      // A virtual size far larger than the raw data is the classic
      // self-unpacking signature: the unpacker allocates at runtime.
      virtualToRawRatio: rawSize > 0 ? Number((virtualSize / rawSize).toFixed(2)) : null,
      executable: (bytes.readUInt32LE(at + 36) & 0x20000000) !== 0,
    });
  }
  const entrySection = sections.find((section) => entryRva >= section.virtualAddress
    && entryRva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize));
  return {
    format: plus ? 'pe32+' : 'pe32',
    machine: bytes.readUInt16LE(coff),
    sectionCount,
    entryRva,
    entrySection: entrySection?.name ?? null,
    import: importDir,
    sections,
  };
}

/** Minimal ELF reader: sections and their names, enough for anomaly detection. */
export function parseELF(bytes) {
  if (bytes.length < 52 || bytes.toString('latin1', 1, 4) !== 'ELF') return null;
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  const u16 = (at) => (little ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at));
  const u32 = (at) => (little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at));
  const u64 = (at) => (little ? Number(bytes.readBigUInt64LE(at)) : Number(bytes.readBigUInt64BE(at)));
  const shoff = is64 ? u64(40) : u32(32);
  const shentsize = is64 ? u16(58) : u16(46);
  const shnum = is64 ? u16(60) : u16(48);
  const shstrndx = is64 ? u16(62) : u16(50);
  if (!Number.isFinite(shoff) || shoff + shentsize * shnum > bytes.length || shnum === 0) return null;
  const strTableAt = shoff + shentsize * shstrndx;
  if (strTableAt + (is64 ? 24 : 20) > bytes.length) return null;
  const strOffset = is64 ? u64(strTableAt + 24) : u32(strTableAt + 16);
  const strSize = is64 ? u64(strTableAt + 32) : u32(strTableAt + 20);
  if (!Number.isFinite(strOffset) || strOffset + strSize > bytes.length) return null;

  const sections = [];
  for (let index = 0; index < Math.min(shnum, 128); index += 1) {
    const at = shoff + index * shentsize;
    if (at + shentsize > bytes.length) break;
    const nameAt = strOffset + u32(at);
    if (nameAt >= bytes.length) continue;
    const end = bytes.indexOf(0, nameAt);
    const name = bytes.toString('latin1', nameAt, end === -1 ? Math.min(nameAt + 32, bytes.length) : end);
    const offset = is64 ? u64(at + 24) : u32(at + 16);
    const size = is64 ? u64(at + 32) : u32(at + 20);
    let entropy = null;
    if (Number.isFinite(offset) && Number.isFinite(size) && size > 0 && offset + size <= bytes.length) {
      entropy = Number(shannonEntropy(bytes.subarray(offset, offset + size)).toFixed(3));
    }
    sections.push({ name, size, entropy });
  }
  return { format: is64 ? 'elf64' : 'elf32', sections };
}

/** Minimal Mach-O reader, including the encryption-info load command. */
export function parseMachO(bytes) {
  if (bytes.length < 32) return null;
  const magic = bytes.readUInt32BE(0);
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const le = magic === 0xfeedface || magic === 0xfeedfacf;
  if (![0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe].includes(magic)) return null;
  const u32 = (at) => (le ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at));
  const ncmds = u32(16);
  const sections = [];
  let encrypted = false;
  let cursor = is64 ? 32 : 28;
  for (let index = 0; index < Math.min(ncmds, 256); index += 1) {
    if (cursor + 8 > bytes.length) break;
    const cmd = u32(cursor);
    const cmdsize = u32(cursor + 4);
    if (cmdsize < 8 || cursor + cmdsize > bytes.length) break;
    if (cmd === 0x21 || cmd === 0x2c) encrypted = u32(cursor + 8 + 8) !== 0;
    const segment = cmd === 0x1 || cmd === 0x19;
    if (segment) {
      const nsects = u32(cursor + (is64 ? 64 : 48));
      const first = cursor + (is64 ? 72 : 56);
      const stride = is64 ? 80 : 68;
      for (let s = 0; s < Math.min(nsects, 64); s += 1) {
        const at = first + s * stride;
        if (at + stride > bytes.length) break;
        const name = bytes.toString('latin1', at, at + 16).replace(/\0.*$/, '').trim();
        const size = is64 ? Number(bytes.readBigUInt64LE(at + 40)) : u32(at + 36);
        const offset = u32(at + (is64 ? 48 : 40));
        let entropy = null;
        if (size > 0 && offset + size <= bytes.length) {
          entropy = Number(shannonEntropy(bytes.subarray(offset, offset + size)).toFixed(3));
        }
        sections.push({ name, size, entropy });
      }
    }
    cursor += cmdsize;
  }
  return { format: is64 ? 'macho64' : 'macho32', encrypted, sections };
}

/** Identify the container without trusting a file extension. */
export function identifyFormat(bytes) {
  return parsePE(bytes) ?? parseELF(bytes) ?? parseMachO(bytes) ?? { format: 'unknown', sections: [] };
}

function verdictFor({ entropy, format, packers, xorHits, size }) {
  const reasons = [];
  let score = 0;
  if (packers.length > 0) {
    score += 0.6;
    reasons.push(`matched packer/protector signatures: ${packers.map((item) => item.family).join(', ')}`);
  }
  if (entropy.overall >= 7.2) {
    score += 0.2;
    reasons.push(`whole-file entropy ${entropy.overall} is near random (packed or encrypted)`);
  }
  if (entropy.highBlockRatio >= 0.85 && entropy.blocks.length > 1) {
    score += 0.15;
    reasons.push(`${(entropy.highBlockRatio * 100).toFixed(0)}% of blocks are high-entropy`);
  }
  const suspicious = format.sections.filter((section) => SUSPICIOUS_SECTIONS.test(section.name));
  if (suspicious.length > 0) {
    score += 0.4;
    reasons.push(`suspicious section names: ${suspicious.map((section) => section.name).join(', ')}`);
  }
  // A virtual/raw ratio alone is a weak signal: .bss and ordinary padding
  // produce 4-8x legitimately. Require a second indicator (suspicious name,
  // zero raw data, or high entropy in that section) before counting it.
  const selfUnpacking = format.sections.filter((section) => (section.virtualToRawRatio ?? 0) >= 8
    && (SUSPICIOUS_SECTIONS.test(section.name) || section.rawSize === 0 || (section.entropy ?? 0) >= 6.5));
  if (selfUnpacking.length > 0) {
    score += 0.25;
    reasons.push(`virtual size exceeds raw size by 8x or more in ${selfUnpacking.map((section) => section.name).join(', ')} (with a second anomaly)`);
  }
  const highEntropySections = format.sections.filter((section) => (section.entropy ?? 0) >= 7.2);
  if (highEntropySections.length > 0) {
    score += 0.15;
    reasons.push(`high-entropy sections: ${highEntropySections.map((section) => section.name).join(', ')}`);
  }
  if (format.entrySection && !EXECUTABLE_SECTIONS.test(format.entrySection)) {
    score += 0.15;
    reasons.push(`entry point is in ${format.entrySection}, not a conventional code section`);
  }
  // A small import table only means something on a non-trivial file; tiny
  // hand-built or stub binaries would otherwise all be flagged as packed.
  if (format.import && format.import.size > 0 && format.import.size < 64 && size >= 16 * 1024) {
    score += 0.1;
    reasons.push('import directory is unusually small for a file of this size');
  }
  if (format.encrypted === true) {
    score += 0.5;
    reasons.push('Mach-O LC_ENCRYPTION_INFO reports an encrypted segment');
  }
  if (xorHits.length > 0) {
    score += 0.1;
    reasons.push(`single-byte XOR ${xorHits.map((hit) => `0x${hit.key.toString(16)}`).join(', ')} reveals readable markers (likely obfuscated strings)`);
  }

  const confidence = Number(Math.min(1, score).toFixed(2));
  const verdict = confidence >= 0.6 ? 'likely-packed-or-protected'
    : confidence >= 0.3 ? 'possibly-obfuscated' : 'appears-unpacked';
  if (reasons.length === 0) reasons.push('no packing, entropy or section anomalies detected by these heuristics');
  return { verdict, confidence, reasons };
}

/** Pure analysis over a buffer; every field is serialisable. */
export function triageBuffer(bytes, { name = 'buffer', blockSize = DEFAULT_BLOCK_SIZE } = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const entropy = entropyProfile(buffer, blockSize);
  const packers = detectPackers(buffer);
  const format = identifyFormat(buffer);
  const strings = extractStrings(buffer);
  const xorHits = xorProbe(buffer);
  const conclusion = verdictFor({ entropy, format, packers, xorHits, size: buffer.length });
  const nextSteps = conclusion.verdict === 'appears-unpacked'
    ? [
      'Continue with rea_status, then open_binary and function-level analysis.',
      'Treat decompiler output as inference; verify against disassembly and Evidence IDs.',
    ]
    : [
      'Do not trust decompiler output yet: locate the OEP / unpack before static analysis.',
      'Prefer a dynamic snapshot (Frida/GDB) or an offline dump of the unpacked image.',
      'Re-run this triage on the dumped image to confirm the protection is gone.',
    ];

  return {
    schemaVersion: 1,
    file: {
      name,
      size: buffer.length,
      sha256: createHash('sha256').update(buffer).digest('hex'),
    },
    format: format.format,
    entropy: {
      overall: entropy.overall,
      blockSize: entropy.blockSize,
      highBlockRatio: entropy.highBlockRatio,
      mean: entropy.mean,
      max: entropy.max,
      blockCount: entropy.blocks.length,
    },
    sections: format.sections,
    entryRva: format.entryRva ?? null,
    entrySection: format.entrySection ?? null,
    import: format.import ?? null,
    encryptedSegment: format.encrypted ?? null,
    packers,
    strings: {
      count: strings.length,
      encodings: [...new Set(strings.map((item) => item.encoding))],
      samples: strings.slice(0, 20).map((item) => ({ at: item.offset, encoding: item.encoding, value: item.value })),
    },
    xorCandidates: xorHits,
    yara: { status: 'not-configured', matches: [] },
    verdict: conclusion.verdict,
    confidence: conclusion.confidence,
    reasons: conclusion.reasons,
    nextSteps,
    limitations: [
      'Heuristic triage only: entropy and signatures produce false positives (installers, compressed resources) and false negatives (custom packers).',
      'No code is executed and no engine is invoked; this is not a substitute for a disassembly or a dynamic trace.',
      'Strings are sampled, not exhaustive; a sample larger than the read cap is truncated.',
    ],
  };
}

/**
 * Optional YARA pass. The rule directory is user-supplied (`~/.dsh/rea-yara`);
 * an absent binary or absent rules is reported, never treated as a failure.
 */
export async function scanWithYara(path, rulesDir, { timeoutMs = 30_000 } = {}) {
  let rules;
  try {
    rules = (await readdir(rulesDir)).filter((file) => /\.(yar|yara)$/i.test(file));
  } catch {
    return { status: 'no-rule-directory', matches: [] };
  }
  if (rules.length === 0) return { status: 'no-rules', matches: [] };
  const result = spawnSync('yara', [...rules.map((file) => join(rulesDir, file)), path], {
    encoding: 'utf8', timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true,
  });
  if (result.error) return { status: `yara-unavailable: ${result.error.code ?? result.error.message}`, matches: [] };
  if (result.status !== 0) return { status: `yara-exit-${result.status}`, matches: [] };
  const matches = String(result.stdout ?? '').split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 100);
  return { status: 'ok', matches };
}

/** Read a bounded slice of one file and analyse it. Never writes, never executes. */
export async function triageFile(path, {
  maxBytes = DEFAULT_MAX_TRIAGE_BYTES,
  yaraRulesDir,
  blockSize = DEFAULT_BLOCK_SIZE,
} = {}) {
  const absolute = resolve(path);
  if (!isAbsolute(path)) throw new Error('path must be absolute');
  const info = await stat(absolute);
  if (!info.isFile()) throw new Error('path must name a regular file');
  const length = Math.min(info.size, maxBytes);
  const bytes = Buffer.alloc(length);
  const handle = await open(absolute, 'r');
  try {
    await handle.read(bytes, 0, length, 0);
  } finally {
    await handle.close();
  }
  const report = triageBuffer(bytes, { name: join(absolute).split(/[\\/]/).pop(), blockSize });
  report.file.path = absolute;
  report.file.fullSize = info.size;
  report.file.truncated = info.size > maxBytes;
  if (yaraRulesDir) report.yara = await scanWithYara(absolute, yaraRulesDir);
  if (report.yara.matches.length > 0) {
    report.reasons.push(`YARA matched: ${report.yara.matches.join('; ')}`);
    report.confidence = 1;
    report.verdict = 'likely-packed-or-protected';
  }
  return report;
}
