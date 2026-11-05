/**
 * Deep string recovery for static analysis.
 *
 * The first capability dry-run scored 0/5 on hidden indicators: single-byte
 * XOR config strings, UTF-16LE strings starting at an odd offset, and base64
 * blobs were invisible to the ASCII + even-offset UTF-16 pass. This module
 * keeps the cheap original scan and adds derived channels, each tagged with how
 * it was recovered so a finding is never mistaken for plaintext.
 *
 * A hardening ladder (L0 plaintext -> L5 attribution canaries) then showed the
 * next cliff: a 4-byte repeating XOR or an RC4 config blob dropped recall from
 * 89% to 6%. Those channels closed that gap.
 *
 * The duel against a progressively hardened target added the rest:
 *   - compressed containers (zlib / gzip / raw deflate), scanned recursively
 *   - position-dependent encoding, where byte i is shifted by i
 *   - interleaved lanes, where two strings are merged byte by byte
 *   - a custom base64 alphabet stored next to the blob
 *   - length-prefixed containers, which broke the old "printable blob" checks
 *
 * Cost is bounded: derived passes scan a configurable window (512 KB by
 * default), recursion stops at maxDepth, and every pass respects maxStrings.
 * Nothing here executes the sample.
 *
 * @module dsh-rea/lib/strings
 */

import { inflateCandidates } from './containers.js';
import {
  SEMANTIC_ANCHOR, candidateKeys, cribDragKeys, findHighEntropyRegions,
  joinStackFragments, looksLikeText, recoverBlobs,
} from './crypto-recovery.js';

const DEFAULT_WINDOW = 512 * 1024;
const MIN_DERIVED = 6;
const MAX_PER_KEY = 12;
const STANDARD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// A derived XOR run must carry a semantic anchor. Without this, 255 keys over
// a high-entropy section produce thousands of printable-but-meaningless runs
// and pollute the IoC list with false emails and domains.
const readable = (value) => looksLikeText(value, { minLength: MIN_DERIVED, maxLength: 240 });

// Fragments that every accepted single-byte-XOR hit contains, because they are
// the same things SEMANTIC_ANCHOR and SALVAGE_RULES test for. Kept short so the
// probe pass stays linear. These are matched byte-exactly: folding case would
// make "hkey_" also match a decode of "HKEY_", and the two decodes differ by a
// single 0x20 in the key, so the set would hold a case-flipped twin of every
// real key and the twin would race the real one into the dedupe filter. The few
// anchors that genuinely appear capitalised are simply listed twice.
//
// Nothing shorter than four characters belongs here. Deriving a key from the
// first byte costs nothing, so a probe of length L only constrains L - 1 bytes
// and yields a false key once every 256^(L-1) offsets - which on a 512 KB window
// means '.io' invents 8 keys, and a bare ':\\' probe invents hundreds. Those
// invented keys each cost a full scan and swamp the real one; four characters
// brings the expected count to 0.03.
const XOR_PROBES = [
  'https://', 'http://', 'www.', 'mozilla/', 'Mozilla/',
  'hkey_', 'HKEY_', 'hklm', 'HKLM', 'hkcu', 'HKCU',
  '.com', '.net', '.org', '.php', '.dll', '.exe', '.json', '.gif', '.txt',
  '.example', '.app', '.xyz',
  'telemetry', 'analytics', 'firebase', 'crashlytics', 'appsflyer', 'mixpanel',
  'sentry', 'adjust', 'umeng', 'bugly',
  'frida', 'xposed', 'magisk', 'sandboxie', 'vbox', 'vmware', 'qemu', 'cuckoo',
  'cpuid', 'rdtsc', 'oauth', 'bearer ', 'user_id', 'android_id', 'device_token',
  'getprocaddress', 'loadlibrary', 'virtualalloc', 'isdebuggerpresent',
];

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
 *          reversed?:boolean, containers?:boolean, delta?:boolean,
 *          interleave?:boolean, customBase64?:boolean, maxDepth?:number,
 *          report?:object}} options
 * @returns {Array<{value:string, offset:number, encoding:string, derived:boolean, key?:number}>}
 */
export function extractDeepStrings(bytes, options = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const {
    minLength = 5,
    maxStrings = 2_000,
    windowBytes = DEFAULT_WINDOW,
    xor = true,
    base64 = true,
    keyedXor = true,
    blobs = true,
    stack = true,
    reversed = true,
    containers = true,
    delta = true,
    interleave = true,
    customBase64 = true,
    maxDepth = 2,
    report = null,
  } = options;

  const found = [];
  const seen = new Set();
  if (report) {
    report.regions = report.regions ?? [];
    report.blobs = report.blobs ?? [];
    report.containers = report.containers ?? [];
  }

  const push = (value, offset, encoding, derived = false, key) => {
    if (value.length < minLength || found.length >= maxStrings) return;
    const normalised = value.slice(0, 300);
    // Long base64 blobs are routinely 4-800 characters; truncating before the
    // decoder sees them silently drops every record after the first few. Keep
    // the full run non-enumerably so reports stay small but decoding stays
    // complete.
    const fingerprint = value.length > 300 ? `${normalised.toLowerCase()}#${value.length}` : normalised.toLowerCase();
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    const entry = { value: normalised, offset, encoding, derived, ...(key === undefined ? {} : { key }) };
    if (value.length > normalised.length) {
      Object.defineProperty(entry, 'raw', { value: value.slice(0, 65_536), enumerable: false });
    }
    found.push(entry);
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

  const scanAsciiDecoded = (slice, key, tag) => {
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
  };

  const scanReversed = (source, base, tag) => {
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
  };

  /** Decode a base64 body using a custom alphabet; null when a char is foreign. */
  const decodeWithAlphabet = (text, alphabet) => {
    const table = new Map();
    for (let i = 0; i < alphabet.length; i += 1) table.set(alphabet[i], i);
    const out = [];
    let bits = 0;
    let value = 0;
    for (const char of text) {
      const digit = table.get(char);
      if (digit === undefined) return null;
      value = (value << 6) | digit;
      bits += 6;
      if (bits >= 8) { bits -= 8; out.push((value >> bits) & 0xff); }
    }
    return Buffer.from(out);
  };

  /** A 64-char permutation stored next to the blob is a custom base64 table. */
  const findAlphabet = (items) => {
    for (const item of items) {
      const runs = String(item.value).match(/[A-Za-z0-9+/]{64}/g) ?? [];
      for (const run of runs) {
        const sorted = [...run].sort().join('');
        if (sorted === [...STANDARD_B64].sort().join('')) return run;
      }
    }
    return null;
  };

  /**
   * Take a decoded buffer and mine it: either as text, or as another container.
   * Kept depth-limited so a packer that nests ten layers cannot stall the scan.
   */
  const absorb = (data, at, prefix, depth) => {
    if (found.length >= maxStrings || !data || data.length < 16 || depth >= maxDepth) return 0;
    const before = found.length;
    // Compressed bytes look like text to a printable-run scanner (about 37% of
    // them are printable), so scanning the raw frame adds junk and, worse, makes
    // a truncated frame look like a success. Mine a container only through
    // inflate; mine plaintext directly.
    const container = (data[0] === 0x78 && (((data[0] << 8) | data[1]) % 31 === 0))
      || (data[0] === 0x1f && data[1] === 0x8b);
    const streams = inflateCandidates(data, { scanBytes: data.length, maxStreams: 2, regions: [] });
    for (const stream of streams) {
      if (report) report.containers.push({ at, kind: `${prefix}>${stream.kind}`, bytes: stream.data.length });
      run(stream.data, { depth: depth + 1, prefix: `${prefix}>${stream.kind}` });
    }
    if (!container) run(data, { depth: depth + 1, prefix });
    return found.length - before;
  };

  let recoveredKeys = [];

  function run(source, { depth = 0, prefix = '' } = {}) {
    const tag = (name) => (prefix ? `${prefix}>${name}` : name);
    const runStart = found.length;
    const local = () => found.slice(runStart);
    const slice = source.subarray(0, Math.min(source.length, depth === 0 ? windowBytes : source.length));

    // 1. Plain ASCII runs (whole file at depth 0, not just the derived window).
    scanAscii(depth === 0 ? source : slice, 0, tag('ascii'));

    // 2. UTF-16LE at BOTH phases. The old pass only stepped from offset 0, so a
    //    wide string that began at an odd byte offset was invisible.
    scanWide(slice, 0, tag('utf16le'));

    // 3. UTF-16BE (common in Java/Android resources and some config blobs).
    let runText = '';
    let start = 0;
    for (let index = 0; index + 1 < slice.length; index += 2) {
      const byte = slice[index + 1];
      if (slice[index] === 0 && byte >= 0x20 && byte <= 0x7e) {
        if (runText.length === 0) start = index;
        runText += String.fromCharCode(byte);
      } else {
        push(runText, start, tag('utf16be'));
        runText = '';
      }
      if (found.length >= maxStrings) break;
    }
    push(runText, start, tag('utf16be'));

    // 4. Single-byte XOR over a bounded window. Only readable, word-like runs
    //    survive; the 255-key scan over a large PE section would otherwise be
    //    pure noise. Each hit records the key so it can be verified by hand.
    if (xor && depth === 0) {
      // Three problems meet here. A single-byte XOR of plain ASCII with a small
      // key is still plain ASCII, so a file full of literal text makes every key
      // look productive. Running the string builder for all 255 keys cost 2.5 s
      // on a 600 KB installer. And ranking keys by their longest printable run -
      // the obvious triage - picks the *wrong* ones: a key in 0x21..0x3f maps an
      // entire plaintext block into a second printable range and wins with a
      // 319-byte run, while the key that was actually used scores 153 and loses.
      //
      // So the triage asks "which key provably produces a semantic anchor", not
      // "which key produces a long run". For probe P and key k, P appears at
      // offset i exactly when k = window[i] ^ P[0] and the rest of P follows
      // under that same k, so one linear pass per probe yields the keys that are
      // worth a full scan - no run-length guessing and no arbitrary key cap.
      // A Set lookup per offset is 28 million hashes across the probe list, which
      // costs more than the string building it is supposed to protect. A 256-entry
      // flag array answers the same question with one array read.
      const keysToScan = [];
      const seenKey = new Uint8Array(256);
      const acceptKey = (key) => {
        if (key === 0 || seenKey[key] === 1) return false;
        seenKey[key] = 1;
        keysToScan.push(key);
        return true;
      };
      for (const probe of XOR_PROBES) {
        if (keysToScan.length >= 96) break;
        const head = probe.charCodeAt(0);
        const tail = [];
        for (let index = 1; index < probe.length; index += 1) tail.push(probe.charCodeAt(index));
        const limit = slice.length - probe.length;
        for (let at = 0; at <= limit; at += 1) {
          const key = slice[at] ^ head;
          if (seenKey[key] === 1) continue;
          let matched = true;
          for (let step = 0; step < tail.length; step += 1) {
            if ((slice[at + 1 + step] ^ key) !== tail[step]) { matched = false; break; }
          }
          if (matched) acceptKey(key);
        }
      }
      // A bare IPv4 has no letters at all, so no textual probe can reach it, and
      // a C2 address is exactly the kind of IoC that must not be lost. The key
      // cancels out of the XOR difference between neighbours, so anchoring on the
      // dot at index j pins the key to window[j] ^ '.'; what is left is to check
      // that the window really is four dotted octets. Two or three loose digit
      // tests are not enough - each one only removes 8/256 of the offset space,
      // which still invents dozens of keys - so the whole d.d.d.d shape is walked
      // with an early bail on the first mismatch.
      const digitAt = (buffer, index, key) => {
        const decoded = buffer[index] ^ key;
        return decoded >= 0x30 && decoded <= 0x39;
      };
      const fourOctetsFrom = (buffer, dot, key) => {
        let index = dot;
        for (let group = 0; group < 3; group += 1) {
          if (index >= buffer.length || (buffer[index] ^ key) !== 0x2e) return false;
          index += 1;
          let digits = 0;
          while (digits < 3 && index < buffer.length && digitAt(buffer, index, key)) { index += 1; digits += 1; }
          if (digits === 0) return false;
        }
        return true;
      };
      for (let at = 1; at + 6 < slice.length; at += 1) {
        const key = slice[at] ^ 0x2e;
        if (seenKey[key] === 1) continue;
        // Cheap gate first: a digit before the dot, and the first octet closing
        // on time. Everything else is settled by the full walk.
        if (!digitAt(slice, at - 1, key) || (slice[at + 2] ^ key) !== 0x2e) continue;
        if (fourOctetsFrom(slice, at, key)) acceptKey(key);
      }

      for (const key of keysToScan) {
        if (found.length >= maxStrings) break;
        let current = '';
        let at = 0;
        let accepted = 0;
        const tagName = tag(`xor-0x${key.toString(16).padStart(2, '0')}`);
        const consider = () => {
          if (accepted >= MAX_PER_KEY || current.length < MIN_DERIVED) return;
          if (readable(current) && SEMANTIC_ANCHOR.test(current)) {
            const before = found.length;
            push(current, at, tagName, true, key);
            if (found.length > before) accepted += 1;
            return;
          }
          // Adjacent encoded records decode into one long run because the NUL
          // terminator itself decodes to a printable byte. Whole-run scoring
          // rejects it; the structured part is still worth keeping.
          if (current.length >= 40 && salvageInto(current, at, `${tagName}>salvage`) > 0) accepted += 1;
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
    if (keyedXor) {
      for (const candidate of cribDragKeys(slice, { maxKeyLen: 4 })) {
        recoveredKeys.push(candidate.key);
        scanAsciiDecoded(slice, candidate.key, tag(`xor${candidate.keyLen}-${candidate.hex}`));
      }
    }

    // 6. Encrypted blobs: high-entropy regions tried against nearby printable
    //    key candidates, for both RC4 and keyed XOR. Validation is the semantic
    //    anchor in the decrypted prefix, never the shape of the key.
    if (blobs) {
      const regions = findHighEntropyRegions(slice);
      if (depth === 0 && report) report.regions = regions;
      if (regions.length > 0) {
        const keys = candidateKeys(slice, { regions });
        for (const blob of recoverBlobs(slice, { regions, keys })) {
          const tagName = tag(`${blob.mode}:${blob.key}`);
          recoveredKeys.push(Buffer.from(blob.key, 'latin1'));
          if (report) report.blobs.push({ start: blob.start, end: blob.end, mode: blob.mode });
          scanAscii(blob.data, blob.start, `${tagName}>ascii`);
          scanWide(blob.data, blob.start, `${tagName}>utf16le`);
          scanReversed(blob.data, blob.start, tagName);
        }
      }
    }

    // 7. Position-dependent encoding: out[i] = plain[i] + i. No key exists, so
    //    no key search can find it; the shape of the decoded text is the only
    //    signal. The counter restarts per record, so trying every offset is
    //    enough - a wrong offset shifts every byte by the same constant and
    //    fails the word-likeness test within a few characters.
    if (delta && depth === 0) {
      for (let at = 0; at + 8 < slice.length; at += 1) {
        let printable = 0;
        for (let j = 0; j < 8; j += 1) {
          const byte = (slice[at + j] - j) & 0xff;
          if (byte >= 0x20 && byte <= 0x7e) printable += 1;
        }
        if (printable < 8) continue;
        let text = '';
        for (let j = 0; j < 240 && at + j < slice.length; j += 1) {
          const byte = (slice[at + j] - j) & 0xff;
          if (byte < 0x20 || byte > 0x7e) break;
          text += String.fromCharCode(byte);
        }
        if (text.length < 8) continue;
        // Any shifted run of printable bytes can look word-like; these were the
        // single largest source of false positives in the duel (464 fabricated
        // strings on one sample). Require the structure an indicator has.
        const structured = /https?:\/\/|@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b(?:HKLM|HKCU|HKEY_)|[A-Za-z]:\\|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+\.(?:com|net|org|example|app|io|cn|ru|xyz|cloud)\b|[A-Za-z] [A-Za-z]/.test(text);
        if (!structured) continue;
        if (readableLoose(text) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) push(text, at, tag('delta'), true);
        if (found.length >= maxStrings) break;
      }
    }

    // 8. Interleaved lanes: two strings merged byte by byte. Both lanes are
    //    unreadable in place; splitting recovers each one intact.
    if (interleave && depth === 0) {
      for (const phase of [0, 1]) {
        let lane = '';
        let laneAt = phase;
        for (let index = phase; index < slice.length; index += 2) {
          const byte = slice[index];
          if (byte >= 0x20 && byte <= 0x7e) {
            if (lane.length === 0) laneAt = index;
            lane += String.fromCharCode(byte);
          } else {
            if (lane.length >= 12 && readableLoose(lane)) push(lane, laneAt, tag('interleave'), true);
            lane = '';
          }
        }
        if (lane.length >= 12 && readableLoose(lane)) push(lane, laneAt, tag('interleave'), true);
        if (found.length >= maxStrings) break;
      }
    }

    // 9. Base64-looking substrings INSIDE any recovered run. A whole run rarely
    //    is pure base64 (headers, adjacent XOR blobs and delimiters get glued to
    //    it), so slide over candidates instead of requiring a perfect line.
    if (base64) {
      const alphabet = customBase64 ? findAlphabet(local()) : null;
      const decodeAt = (run, offset, tagName, decode) => {
        const body = run.slice(offset);
        // Unpadded base64 is common in packers. Dropping the trailing partial
        // group costs the last two bytes, which is exactly the zlib checksum -
        // so try the untrimmed body as well before giving up.
        const trimmed = body.slice(0, body.length - (body.length % 4));
        const frames = [];
        if (trimmed.length >= 16) frames.push(trimmed);
        if (body.length >= 16 && body.length !== trimmed.length) frames.push(body);
        for (const frame of frames) {
          const bytes = decode(frame);
          if (!bytes || bytes.length < 12) continue;
          const text = bytes.toString('utf8');
          if (readable(text)) { push(text, 0, tagName, true); return true; }
          // What is left is a compressed stream, ciphertext that the nested
          // channels can still open, or the bit-shifted junk a wrong offset
          // produces. Only "did this yield anything" tells them apart, so let
          // absorb decide. Gating on printable ratio here instead was a bug: it
          // kept the shifted junk and threw away the ciphertext, which is
          // exactly the b64(XOR(blob)) layout this channel has to reach.
          if (absorb(bytes, 0, tagName, depth) > 0) return true;
        }
        return false;
      };
      // A base64 blob glued to a decoded run can start at any offset: the XOR of
      // the previous record decodes to printable junk, so the run does not begin
      // at the blob. Sweeping every offset costs a nested scan per offset, so the
      // sweep is unconditional only for config-sized blobs, where ciphertext
      // looks like nothing in particular and absorb is the only way to rule an
      // offset in or out. A large blob must already look like text or a
      // compressed stream, which keeps embedded resources from being re-scanned
      // two hundred times.
      const SWEEP_LIMIT = 4_096;
      const worthSweeping = (framed, decode, minPrintable) => {
        const bytes = decode(framed);
        if (!bytes || bytes.length < 8) return false;
        const text = bytes.toString('latin1');
        if (bytes[0] === 0x78 && (((bytes[0] << 8) | bytes[1]) % 31 === 0)) return true;
        if (bytes[0] === 0x1f && bytes[1] === 0x8b) return true;
        const printable = (text.match(/[\x20-\x7e]/g) ?? []).length / text.length;
        return printable >= minPrintable && /[A-Za-z]{3}/.test(text);
      };
      for (const item of local()) {
        const candidates = String(item.raw ?? item.value).match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? [];
        for (const candidate of candidates) {
          const sweep = candidate.length <= SWEEP_LIMIT;
          const maxOffset = Math.min(candidate.length - 16, 200);
          for (let offset = 0; offset <= maxOffset; offset += 1) {
            const probe = candidate.slice(offset, offset + 24);
            const framedProbe = probe.slice(0, probe.length - (probe.length % 4));
            if (framedProbe.length < 16) break;
            const decode = (body) => Buffer.from(body, 'base64');
            if (!sweep && !worthSweeping(framedProbe, decode, 0.85)) continue;
            if (decodeAt(candidate, offset, tag('base64'), decode)) break;
          }
          if (!alphabet) continue;
          for (let offset = 0; offset <= maxOffset; offset += 1) {
            const probe = candidate.slice(offset, offset + 24);
            const framedProbe = probe.slice(0, probe.length - (probe.length % 4));
            if (framedProbe.length < 16) break;
            const decode = (body) => decodeWithAlphabet(body, alphabet);
            if (!sweep && !worthSweeping(framedProbe, decode, 0.6)) continue;
            if (decodeAt(candidate, offset, tag('b64custom'), decode)) break;
          }
        }
        if (found.length >= maxStrings) break;
      }
    }

    // 10. Reversed literals. Cheap to test, and a common way to keep a URL out
    //     of a plain `strings` dump without any real encryption.
    if (reversed && depth === 0) {
      for (const item of local()) {
        if (item.encoding !== tag('ascii')) continue;
        if (item.value.length < 12 || item.value.length > 200) continue;
        if (readable(item.value)) continue;
        const flipped = [...item.value].reverse().join('');
        if (readable(flipped)) push(flipped, item.offset, tag('reversed'), true);
      }
    }

    // 11. Stack strings: short immediates concatenated at runtime.
    if (stack && depth === 0) {
      for (const joined of joinStackFragments(local())) {
        push(joined.value, joined.offset, tag('stack-string'), true);
      }
    }

    // 12. Salvage. A decoded XOR/RC4 run often glues several literals together
    //     with junk at both ends - the terminator itself decodes to a printable
    //     byte, so the next record merges into the same run. Whole-run scoring
    //     then rejects a perfectly good URL. Extract the structured part instead
    //     of throwing the run away.
    for (const item of local()) {
      if (!item.derived) continue;
      salvageInto(item.value, item.offset, `${String(item.encoding).split('>')[0]}>salvage`);
      if (found.length >= maxStrings) break;
    }

    // 13. Compressed containers last: they produce whole new buffers to mine.
    if (containers && depth < maxDepth && found.length < maxStrings) {
      // A container may name its own key: `cfg=deflate+xor;key=2b8d41f0;`.
      // The header was already visible to a reader, but the inflated bytes were
      // then XORed, so the config inside stayed high-entropy and unreachable -
      // including the salt a salted hash table needs. Apply the declared key
      // instead of hoping crib-dragging finds it.
      const declared = declaredContainerKey(slice);
      for (const stream of inflateCandidates(slice, { regions: depth === 0 && report ? report.regions : [] })) {
        if (report) report.containers.push({ at: stream.at, kind: tag(stream.kind), bytes: stream.data.length });
        if (declared) {
          const decoded = Buffer.alloc(stream.data.length);
          for (let index = 0; index < decoded.length; index += 1) {
            decoded[index] = stream.data[index] ^ declared.key[index % declared.key.length];
          }
          run(decoded, { depth: depth + 1, prefix: tag(`${stream.kind}>declared-key`) });
        }
        run(stream.data, { depth: depth + 1, prefix: tag(stream.kind) });
      }
    }
  }

  run(buffer);
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

/**
 * A container header that states its own XOR key.
 *
 * Real loaders write `cfg=deflate+xor;key=<hex>;` in front of the blob they
 * describe. The header is plaintext, so a reader can see it; the payload is
 * DEFLATE-then-XOR, so after inflation it is still unreadable. Applying the
 * declared key is what turns the header from a comment into an instruction.
 *
 * Bounded on purpose: only a hex key of 2-8 bytes, only in the first 4 KiB,
 * so a stray `key=` in unrelated text cannot drive a decode.
 */
const DECLARED_KEY_PATTERN = /cfg=[a-z0-9+]*xor[a-z0-9+]*;key=([0-9a-f]{4,16});/i;

function declaredContainerKey(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return null;
  const text = buffer.subarray(0, Math.min(buffer.length, 4096)).toString('latin1');
  const match = DECLARED_KEY_PATTERN.exec(text);
  if (!match) return null;
  if (match[1].length % 2 !== 0) return null;
  const key = Buffer.from(match[1], 'hex');
  if (key.length < 2 || key.length > 8) return null;
  return { key, at: match.index };
}

function xorKeyToText(buffer, key, shift = 0) {
  const out = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i += 1) out[i] = buffer[i] ^ key[(i + shift) % key.length];
  return out.toString('latin1');
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
          : outer === 'b64custom' ? 'base64'
            : outer;
    channels[channel] = (channels[channel] ?? 0) + 1;
  }
  return channels;
}

export { SEMANTIC_ANCHOR };
