/**
 * Deep string recovery for static analysis.
 *
 * The first capability dry-run scored 0/5 on hidden indicators: single-byte
 * XOR config strings, UTF-16LE strings starting at an odd offset, and base64
 * blobs were invisible to the ASCII + even-offset UTF-16 pass. This module
 * keeps the cheap original scan and adds three derived channels, each tagged
 * with how it was recovered so a finding is never mistaken for plaintext.
 *
 * Cost is bounded: XOR and UTF-16 passes scan a configurable window (512 KB by
 * default) and stop at maxResults. Nothing here executes the sample.
 *
 * @module dsh-rea/lib/strings
 */

const DEFAULT_WINDOW = 512 * 1024;
const MIN_DERIVED = 6;
const MAX_PER_KEY = 12;

// A derived XOR run must carry a semantic anchor. Without this, 255 keys over
// a high-entropy section produce thousands of printable-but-meaningless runs
// and pollute the IoC list with false emails and domains.
const SEMANTIC_ANCHOR = /(?:https?:\/\/|www\.|\.(?:com|net|org|io|ru|cn|example|dll|exe|pdb|txt|db|json)|@[a-z0-9.-]+\.[a-z]{2,}|(?:firebase|crashlytics|frida|xposed|magisk|tlscallback|adjust|umeng|sentry|appsflyer|mixpanel|bugly|vmware|vbox|qemu|cuckoo|sandboxie|telemetry|analytics|installation_id|device_token|user_agent|getprocaddress|loadlibrary|virtualalloc|isdebuggerpresent|hkey_|bearer |oauth))/i;

function readable(value) {
  if (value.length < MIN_DERIVED || value.length > 240) return false;
  const good = (value.match(/[a-zA-Z0-9 .:/_\-?=&%@+()[\],;'"]/g) ?? []).length;
  const letters = (value.match(/[a-zA-Z]/g) ?? []).length;
  if (good / value.length < 0.92 || letters / value.length < 0.55) return false;
  if (!/[a-zA-Z]{3}/.test(value) || !SEMANTIC_ANCHOR.test(value)) return false;
  // Long runs of one character are XOR artefacts, not text.
  return !/(.)\1{6,}/.test(value);
}

/**
 * @param {Buffer} bytes
 * @param {{minLength?:number, maxStrings?:number, windowBytes?:number, xor?:boolean, base64?:boolean}} options
 * @returns {Array<{value:string, offset:number, encoding:string, derived:boolean, key?:number}>}
 */
export function extractDeepStrings(bytes, {
  minLength = 5,
  maxStrings = 2_000,
  windowBytes = DEFAULT_WINDOW,
  xor = true,
  base64 = true,
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

  // 1. Plain ASCII runs (whole file, not just the derived window).
  let run = '';
  let start = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    const byte = buffer[index];
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

  // 2. UTF-16LE at BOTH phases. The old pass only stepped from offset 0, so a
  //    wide string that began at an odd byte offset was invisible.
  for (const phase of [0, 1]) {
    run = '';
    start = 0;
    for (let index = phase; index + 1 < slice.length; index += 2) {
      const byte = slice[index];
      if (byte >= 0x20 && byte <= 0x7e && slice[index + 1] === 0) {
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

  // 3. UTF-16BE (common in Java/Android resources and some config blobs).
  run = '';
  start = 0;
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

  // 4. Single-byte XOR over a bounded window. Only readable, word-like runs
  //    survive; the 255-key scan over a large PE section would otherwise be
  //    pure noise. Each hit records the key so it can be verified by hand.
  if (xor) {
    for (let key = 1; key < 256 && found.length < maxStrings; key += 1) {
      run = '';
      start = 0;
      let accepted = 0;
      const consider = () => {
        if (accepted >= MAX_PER_KEY || run.length < MIN_DERIVED || !readable(run)) return;
        const before = found.length;
        push(run, start, `xor-0x${key.toString(16).padStart(2, '0')}`, true, key);
        if (found.length > before) accepted += 1;
      };
      for (let index = 0; index < slice.length; index += 1) {
        const decoded = slice[index] ^ key;
        if (decoded >= 0x20 && decoded <= 0x7e) {
          if (run.length === 0) start = index;
          run += String.fromCharCode(decoded);
        } else {
          consider();
          run = '';
        }
      }
      consider();
    }
  }

  // 5. Base64-looking substrings INSIDE any recovered run. A whole run rarely
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
          try { decoded = Buffer.from(framed, 'base64').toString('utf8'); } catch { continue; }
          if (readable(decoded)) { push(decoded, item.offset, 'base64', true); break; }
        }
      }
    }
  }

  return found;
}

/** Which channels actually produced findings; useful for honest reporting. */
export function channelSummary(strings) {
  const channels = {};
  for (const item of strings) {
    const channel = item.encoding.startsWith('xor-') ? 'xor' : item.encoding;
    channels[channel] = (channels[channel] ?? 0) + 1;
  }
  return channels;
}
