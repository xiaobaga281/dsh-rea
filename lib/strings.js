/**
 * Deep string recovery for static analysis.
 *
 * The first capability dry-run scored 0/5 on hidden indicators: single-byte
 * XOR config strings, UTF-16LE strings starting at an odd offset, and base64
 * blobs were invisible to the ASCII + even-offset UTF-16 pass. This module
 * keeps the cheap original scan and adds derived channels, each tagged with how
 * it was recovered so a finding is never mistaken for plaintext.
 *
 * A later hardening ladder (L0 plaintext -> L5 attribution canaries) showed the
 * remaining cliff: as soon as a sample moved to a 4-byte repeating XOR or an
 * RC4 config blob, recall fell from 89% to 6%. The channels below close that
 * gap with crib dragging, high-entropy blob decryption, stack-string
 * reassembly and reversed-string detection.
 *
 * Cost is bounded: derived passes scan a configurable window (512 KB by
 * default) and stop at maxResults. Nothing here executes the sample.
 *
 * @module dsh-rea/lib/strings
 */

import {
  SEMANTIC_ANCHOR, candidateKeys, cribDragKeys, findHighEntropyRegions,
  joinStackFragments, looksLikeText, recoverBlobs,
} from './crypto-recovery.js';

const DEFAULT_WINDOW = 512 * 1024;
const MIN_DERIVED = 6;
const MAX_PER_KEY = 12;

// A derived XOR run must carry a semantic anchor. Without this, 255 keys over
// a high-entropy section produce thousands of printable-but-meaningless runs
// and pollute the IoC list with false emails and domains.
const readable = (value) => looksLikeText(value, { minLength: MIN_DERIVED, maxLength: 240 });

// A key confirmed by crib consistency (2-4 bytes over eight crib characters)
// is not a guess, so the anchor requirement that protects the 255-key
// single-byte scan would only throw away valid short identifiers here.
const readableLoose = (value) => {
  if (value.length < MIN_DERIVED || value.length > 240) return false;
  const good = (value.match(/[a-zA-Z0-9 .:/\\_\-?=&%@+()[\],;'"]/g) ?? []).length;
  const letters = (value.match(/[a-zA-Z]/g) ?? []).length;
  if (good / value.length < 0.95 || letters / value.length < 0.5) return false;
  return /[a-zA-Z]{3}/.test(value) && !/(.)\1{6,}/.test(value);
};

/**
 * @param {Buffer} bytes
 * @param {{minLength?:number, maxStrings?:number, windowBytes?:number, xor?:boolean,
 *          base64?:boolean, keyedXor?:boolean, blobs?:boolean, stack?:boolean,
 *          reversed?:boolean}} options
 * @returns {Array<{value:string, offset:number, encoding:string, derived:boolean, key?:number}>}
 */
export function extractDeepStrings(bytes, {
  minLength = 5,
  maxStrings = 2_000,
  windowBytes = DEFAULT_WINDOW,
  xor = true,
  base64 = true,
  keyedXor = true,
  blobs = true,
  stack = true,
  reversed = true,
} = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const slice = buffer.subarray(0, Math.min(buffer.length, windowBytes));
  const found = [];
  const seen = new Set();
  const push = (value, offset, encoding, derived = false, key) => {
    if (value.length < minLength || found.length >= maxStrings) return;
    const normalised = value.slice(0, 300);
    const fingerprint = normalised.toLowerCase();
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    found.push({ value: normalised, offset, encoding, derived, ...(key === undefined ? {} : { key }) });
  };

  const scanAscii = (source, base, tag) => {
    let run = '';
    let start = 0;
    for (let index = 0; index < source.length; index += 1) {
      const byte = source[index];
      if (byte >= 0x20 && byte <= 0x7e) {
        if (run.length === 0) start = index;
        run += String.fromCharCode(byte);
      } else {
        push(run, base + start, tag, tag !== 'ascii');
        run = '';
      }
      if (found.length >= maxStrings) break;
    }
    push(run, base + start, tag, tag !== 'ascii');
  };

  const scanWide = (source, base, tag) => {
    for (const phase of [0, 1]) {
      let run = '';
      let start = 0;
      for (let index = phase; index + 1 < source.length; index += 2) {
        const byte = source[index];
        if (byte >= 0x20 && byte <= 0x7e && source[index + 1] === 0) {
          if (run.length === 0) start = index;
          run += String.fromCharCode(byte);
        } else {
          push(run, base + start, tag, true);
          run = '';
        }
        if (found.length >= maxStrings) break;
      }
      push(run, base + start, tag, true);
    }
  };

  // 1. Plain ASCII runs (whole file, not just the derived window).
  scanAscii(buffer, 0, 'ascii');

  // 2. UTF-16LE at BOTH phases. The old pass only stepped from offset 0, so a
  //    wide string that began at an odd byte offset was invisible.
  scanWide(slice, 0, 'utf16le');

  // 3. UTF-16BE (common in Java/Android resources and some config blobs).
  let run = '';
  let start = 0;
  for (let index = 0; index + 1 < slice.length; index += 2) {
    const byte = slice[index + 1];
    if (slice[index] === 0 && byte >= 0x20 && byte <= 0x7e) {
      if (run.length === 0) start = index;
      run += String.fromCharCode(byte);
    } else {
      push(run, start, 'utf16be');
      run = '';
    }
    if (found.length >= maxStrings) break;
  }
  push(run, start, 'utf16be');

  // Extract structured indicators from a run that is too noisy or too long to
  // pass whole-run scoring. Shared by the XOR channel and the salvage pass.
  const salvageInto = (value, offset, tag) => {
    if (value.length < 12) return 0;
    let added = 0;
    for (const rule of SALVAGE_RULES) {
      rule.lastIndex = 0;
      for (const match of value.match(rule) ?? []) {
        if (match.length < 8) continue;
        const before = found.length;
        push(match, offset, tag, true);
        if (found.length > before) added += 1;
      }
    }
    return added;
  };

  // 4. Single-byte XOR over a bounded window. Only readable, word-like runs
  //    survive; the 255-key scan over a large PE section would otherwise be
  //    pure noise. Each hit records the key so it can be verified by hand.
  if (xor) {
    for (let key = 1; key < 256 && found.length < maxStrings; key += 1) {
      let current = '';
      let at = 0;
      let accepted = 0;
      const tag = `xor-0x${key.toString(16).padStart(2, '0')}`;
      const consider = () => {
        if (accepted >= MAX_PER_KEY || current.length < MIN_DERIVED) return;
        if (readable(current)) {
          const before = found.length;
          push(current, at, tag, true, key);
          if (found.length > before) accepted += 1;
          return;
        }
        // Adjacent encoded records decode into one long run because the NUL
        // terminator itself decodes to a printable byte. Whole-run scoring
        // rejects it; the structured part is still worth keeping.
        if (current.length >= 40 && salvageInto(current, at, `${tag}>salvage`) > 0) accepted += 1;
      };
      for (let index = 0; index < slice.length; index += 1) {
        const decoded = slice[index] ^ key;
        if (decoded >= 0x20 && decoded <= 0x7e) {
          if (current.length === 0) at = index;
          current += String.fromCharCode(decoded);
        } else {
          consider();
          current = '';
        }
      }
      consider();
    }
  }

  // 5. Repeating-key XOR (2-4 byte keys) recovered by crib dragging. This is
  //    the single biggest gap the ladder exposed: one extra key byte used to
  //    drop recall from 89% to 6%.
  const recoveredKeys = [];
  if (keyedXor) {
    for (const candidate of cribDragKeys(slice, { maxKeyLen: 4 })) {
      recoveredKeys.push(candidate.key);
      scanAsciiDecoded(slice, candidate.key, `xor${candidate.keyLen}-${candidate.hex}`, push, found, maxStrings);
    }
  }

  // 6. Encrypted blobs: high-entropy regions tried against nearby printable
  //    key candidates, for both RC4 and keyed XOR. Validation is the semantic
  //    anchor in the decrypted prefix, never the shape of the key.
  if (blobs) {
    const regions = findHighEntropyRegions(slice);
    if (regions.length > 0) {
      const keys = candidateKeys(slice, { regions });
      for (const blob of recoverBlobs(slice, { regions, keys })) {
        const tag = `${blob.mode}:${blob.key}`;
        recoveredKeys.push(Buffer.from(blob.key, 'latin1'));
        scanAscii(blob.data, blob.start, `${tag}>ascii`);
        scanWide(blob.data, blob.start, `${tag}>utf16le`);
        scanReversed(blob.data, blob.start, tag, push, found, maxStrings);
      }
    }
  }

  // 7. Base64-looking substrings INSIDE any recovered run. A whole run rarely
  //    is pure base64 (headers, adjacent XOR blobs and delimiters get glued to
  //    it), so slide over candidates instead of requiring a perfect line.
  if (base64) {
    for (const item of [...found]) {
      const candidates = String(item.value).match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [];
      for (const candidate of candidates) {
        const aligned = candidate.slice(0, candidate.length - (candidate.length % 4));
        if (aligned.length < 16) continue;
        // The blob may have picked up 1-3 leading characters from adjacent
        // bytes; try the four possible frame offsets before giving up.
        for (let shift = 0; shift < 4; shift += 1) {
          const body = aligned.slice(shift);
          const framed = body.slice(0, body.length - (body.length % 4));
          if (framed.length < 16) continue;
          let decoded;
          try { decoded = Buffer.from(framed, 'base64'); } catch { continue; }
          const text = decoded.toString('utf8');
          if (readable(text)) { push(text, item.offset, 'base64', true); break; }
          // Nested: base64 of repeating-key XOR. Try the keys already recovered
          // from the surrounding data before declaring the blob opaque.
          let nested = false;
          for (const key of recoveredKeys) {
            for (const candidateText of [xorKeyToText(decoded, key), xorKeyToText(decoded, key, 1)]) {
              if (readable(candidateText)) {
                push(candidateText, item.offset, `base64>xor${key.length}-${key.toString('hex')}`, true);
                nested = true;
                break;
              }
            }
            if (nested) break;
          }
          if (nested) break;
        }
      }
    }
  }

  // 8. Reversed literals. Cheap to test, and a common way to keep a URL out of
  //    a plain `strings` dump without any real encryption.
  if (reversed) {
    for (const item of [...found]) {
      if (item.encoding !== 'ascii' && !item.encoding.endsWith('>ascii')) continue;
      if (item.value.length < 12 || item.value.length > 200) continue;
      if (readable(item.value)) continue;
      const flipped = [...item.value].reverse().join('');
      if (readable(flipped)) push(flipped, item.offset, 'reversed', true);
    }
  }

  // 9. Stack strings: short immediates concatenated at runtime.
  if (stack) {
    for (const joined of joinStackFragments(found.slice())) {
      push(joined.value, joined.offset, 'stack-string', true);
    }
  }

  // 10. Salvage. A decoded XOR/RC4 run often glues several literals together
  //     with junk at both ends - the terminator itself decodes to a printable
  //     byte, so the next record merges into the same run. Whole-run scoring
  //     then rejects a perfectly good URL. Extract the structured part instead
  //     of throwing the run away.
  for (const item of [...found]) {
    if (!item.derived) continue;
    salvageInto(item.value, item.offset, `${String(item.encoding).split('>')[0]}>salvage`);
    if (found.length >= maxStrings) break;
  }

  return found;
}

const SALVAGE_RULES = [
  /https?:\/\/[^\s"'`\\|<>]{4,200}/gi,
  /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|me|tk|su|pw|onion|dev|app|cloud|example)\b/gi,
  /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"']{2,120}/gi,
  /\b[A-Za-z]:\\(?:[^\s"<>|:*?]{1,80}\\)*[^\s"<>|:*?]{1,80}/g,
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
];

function xorKeyToText(buffer, key, shift = 0) {
  const out = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i += 1) out[i] = buffer[i] ^ key[(i + shift) % key.length];
  return out.toString('latin1');
}

function scanAsciiDecoded(slice, key, tag, push, found, maxStrings) {
  let run = '';
  let at = 0;
  const accept = (value, offset) => {
    // A key confirmed by crib consistency is not a guess, so short API names
    // such as "cpuid" or "VMXh" are worth keeping here; only the 255-key
    // single-byte scan needs the strict anchor filter.
    if (value.length >= MIN_DERIVED) {
      // Plain IPv4 has no letters at all, so the word-likeness test would drop
      // the single most useful network indicator in an encrypted config.
      if (readableLoose(value) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) push(value, offset, tag, true);
      return;
    }
    if (value.length >= 4 && /[A-Za-z]{2}/.test(value) && !/(.)\1{3,}/.test(value)) push(value, offset, tag, true);
  };
  for (let index = 0; index < slice.length; index += 1) {
    const decoded = slice[index] ^ key[index % key.length];
    if (decoded >= 0x20 && decoded <= 0x7e) {
      if (run.length === 0) at = index;
      run += String.fromCharCode(decoded);
    } else {
      accept(run, at);
      run = '';
    }
    if (found.length >= maxStrings) return;
  }
  accept(run, at);
}

function scanReversed(source, base, tag, push, found, maxStrings) {
  let run = '';
  let at = 0;
  for (let index = 0; index < source.length; index += 1) {
    const byte = source[index];
    if (byte >= 0x20 && byte <= 0x7e) {
      if (run.length === 0) at = index;
      run += String.fromCharCode(byte);
    } else {
      considerReversed(run, base + at, tag, push, found);
      run = '';
    }
    if (found.length >= maxStrings) return;
  }
  considerReversed(run, base + at, tag, push, found);
}

function considerReversed(run, at, tag, push, found) {
  if (run.length < 12 || run.length > 200 || readable(run)) return;
  const flipped = [...run].reverse().join('');
  if (readable(flipped)) push(flipped, at, `${tag}>reversed`, true);
}

/** Which channels actually produced findings; useful for honest reporting. */
export function channelSummary(strings) {
  const channels = {};
  for (const item of strings) {
    const outer = String(item.encoding).split('>')[0];
    const channel = outer.startsWith('xor') ? 'xor'
      : outer.startsWith('rc4') ? 'rc4'
        : outer === 'stack-string' ? 'stack'
          : outer;
    channels[channel] = (channels[channel] ?? 0) + 1;
  }
  return channels;
}

export { SEMANTIC_ANCHOR };
