/**
 * Key and blob recovery for static string analysis.
 *
 * The hardening ladder showed the 1.5.0 pipeline collapsing from 89% to 6% the
 * moment a target stops using single-byte XOR, and to 0% once the import table
 * is reduced to ordinals. Two cheap, well-understood techniques close most of
 * that gap without executing anything:
 *
 *   1. Crib dragging - assume a known prefix ("https://", "HKLM\\", "Mozilla/")
 *      sits somewhere in the data. For a repeating key of length L, every byte
 *      of the crib pins one key position; eight crib bytes over-determine L<=4,
 *      so a random position almost never produces a consistent key.
 *   2. Blob decryption - locate high-entropy regions, collect nearby printable
 *      candidates as keys, and validate each trial decryption against semantic
 *      anchors instead of trusting the key name.
 *
 * Everything here is bounded and heuristic. It never executes the sample and
 * never touches the network. A recovery is a lead, not proof.
 *
 * @module dsh-rea/lib/crypto-recovery
 */

/** A recovered run must look like text, not like a lucky byte sequence. */
export const SEMANTIC_ANCHOR = /(?:https?:\/\/|www\.|\.(?:com|net|org|io|ru|cn|example|dll|exe|pdb|txt|db|json|php|gif)|@[a-z0-9.-]+\.[a-z]{2,}|(?:firebase|crashlytics|frida|xposed|magisk|tlscallback|adjust|umeng|sentry|appsflyer|mixpanel|bugly|vmware|vbox|qemu|cuckoo|sandboxie|telemetry|analytics|installation_id|device_token|user_agent|getprocaddress|loadlibrary|virtualalloc|isdebuggerpresent|hkey_|bearer |oauth|android_id|rdtsc|cpuid|document\.cookie|user_id))/i;

export function looksLikeText(value, { minLength = 6, maxLength = 240 } = {}) {
  if (typeof value !== 'string') return false;
  if (value.length < minLength || value.length > maxLength) return false;
  const good = (value.match(/[a-zA-Z0-9 .:/\\_\-?=&%@+()[\],;'"]/g) ?? []).length;
  const letters = (value.match(/[a-zA-Z]/g) ?? []).length;
  if (good / value.length < 0.92 || letters / value.length < 0.55) return false;
  if (!/[a-zA-Z]{3}/.test(value) || !SEMANTIC_ANCHOR.test(value)) return false;
  return !/(.)\1{6,}/.test(value);
}

// 512-byte blocks: a 128-byte sample cannot estimate entropy above ~6.5 even
// when it is perfectly random, so the threshold would never be reached.
const BLOCK = 512;

export function blockEntropy(buffer, at, length) {
  const counts = new Uint32Array(256);
  const end = Math.min(buffer.length, at + length);
  const size = end - at;
  if (size <= 0) return 0;
  for (let i = at; i < end; i += 1) counts[buffer[i]] += 1;
  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / size;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Contiguous high-entropy spans, which is where encrypted config usually lives. */
export function findHighEntropyRegions(buffer, {
  blockSize = BLOCK,
  minEntropy = 7.2,
  minLength = 256,
  maxRegions = 8,
  scanBytes = 2 * 1024 * 1024,
} = {}) {
  const limit = Math.min(buffer.length, scanBytes);
  const regions = [];
  let start = -1;
  for (let at = 0; at < limit; at += blockSize) {
    const high = blockEntropy(buffer, at, blockSize) >= minEntropy;
    if (high && start < 0) start = at;
    if (!high && start >= 0) {
      if (at - start >= minLength) regions.push({ start, end: at });
      start = -1;
      if (regions.length >= maxRegions) break;
    }
  }
  if (start >= 0 && limit - start >= minLength && regions.length < maxRegions) regions.push({ start, end: limit });
  return regions;
}

const KEYLIKE = /(?:key|secret|salt|pass|cfg|config|iv|aes|rc4|xor|blob|token)/i;

/** Printable runs that could be a key, best candidates first. */
export function candidateKeys(buffer, { regions = [], minLength = 8, maxLength = 64, maxKeys = 48 } = {}) {
  const found = new Map();
  let run = '';
  let start = 0;
  const score = (value, at) => {
    if (value.length < minLength || value.length > maxLength) return;
    if (/:\/\/|\\|\//.test(value)) return;                  // URLs and paths are not keys
    if (/^Mozilla|^[A-Z]:\\/.test(value)) return;
    let weight = 0;
    if (KEYLIKE.test(value)) weight += 3;
    if (regions.some((region) => Math.abs(region.start - at) < 8192)) weight += 2;
    if (/^[A-Za-z0-9_!@#$%^&*+=.-]+$/.test(value)) weight += 1;
    if (/^[0-9a-f]{16,}$/i.test(value)) weight += 1;
    if (weight === 0) return;
    const previous = found.get(value);
    if (!previous || previous.score < weight) found.set(value, { value, at, score: weight });
  };
  const consider = (value, at) => {
    score(value, at);
    // A config line ("cfg=rc4;key=Secret;build=x") hides the real key inside a
    // longer printable run; try the individual assignments as well.
    if (!/[=;,&|]/.test(value)) return;
    for (const token of value.split(/[;,&|]+/)) {
      if (!token) continue;
      score(token, at);
      const eq = token.indexOf('=');
      if (eq > 0 && eq < token.length - 1) score(token.slice(eq + 1), at + eq + 1);
    }
  };
  const flush = () => { if (run.length > 0) consider(run, start); run = ''; };
  for (let index = 0; index < buffer.length; index += 1) {
    const byte = buffer[index];
    if (byte >= 0x20 && byte <= 0x7e) {
      if (run.length === 0) start = index;
      run += String.fromCharCode(byte);
    } else {
      flush();
    }
  }
  flush();
  return [...found.values()]
    .sort((a, b) => b.score - a.score || a.at - b.at)
    .slice(0, maxKeys);
}

export function rc4Keystream(key, length) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    const swap = s[i]; s[i] = s[j]; s[j] = swap;
  }
  const stream = Buffer.alloc(length);
  let i = 0; j = 0;
  for (let n = 0; n < length; n += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const swap = s[i]; s[i] = s[j]; s[j] = swap;
    stream[n] = s[(s[i] + s[j]) & 0xff];
  }
  return stream;
}

export function xorWithKey(buffer, key, at = 0) {
  const out = Buffer.alloc(Math.max(0, buffer.length - at));
  for (let i = 0; i < out.length; i += 1) out[i] = buffer[at + i] ^ key[i % key.length];
  return out;
}

const CRIBS = [
  'https://', 'http://', 'HKLM\\', 'HKEY_', 'Mozilla/', 'C:\\', 'android_', 'Firebase',
  'Crashlytics', 'IsDebugger', 'document', '/v1/collect', 'telemetry', '.example',
];

/**
 * Recover a repeating-key XOR key by assuming a known plaintext prefix appears
 * somewhere. Returns candidate keys ranked by how much text they reveal.
 *
 * Only the first `discoveryBytes` are searched: the scan is O(positions x
 * cribs x key lengths x crib length), and a byte-by-byte sweep of a whole
 * section once cost a full second per file. A confirmed key is then applied to
 * the full window by the caller, so recall does not depend on where the blob
 * sits after the discovery window.
 */
export function cribDragKeys(buffer, {
  maxKeyLen = 4,
  cribs = CRIBS,
  discoveryBytes = 96 * 1024,
  probeBytes = 128 * 1024,
  maxCandidates = 4,
} = {}) {
  const limit = Math.min(buffer.length, discoveryBytes);
  const keys = new Set();
  const key = new Int32Array(4);
  for (const crib of cribs) {
    const bytes = Buffer.from(crib, 'latin1');
    const size = bytes.length;
    if (size < 6) continue;
    for (let keyLen = 2; keyLen <= maxKeyLen; keyLen += 1) {
      for (let residue = 0; residue < keyLen; residue += 1) {
        const phases = new Uint8Array(size);
        for (let k = 0; k < size; k += 1) phases[k] = (residue + k) % keyLen;
        for (let pos = residue; pos + size <= limit; pos += keyLen) {
          key.fill(-1, 0, keyLen);
          let consistent = true;
          for (let k = 0; k < size; k += 1) {
            const phase = phases[k];
            const value = buffer[pos + k] ^ bytes[k];
            const existing = key[phase];
            if (existing === -1) key[phase] = value;
            else if (existing !== value) { consistent = false; break; }
          }
          if (!consistent) continue;
          let complete = true;
          for (let phase = 0; phase < keyLen; phase += 1) if (key[phase] < 0) { complete = false; break; }
          if (!complete) continue;
          keys.add(`${keyLen}:${Buffer.from(key.subarray(0, keyLen)).toString('hex')}`);
          if (keys.size > 512) break;
        }
        if (keys.size > 512) break;
      }
      if (keys.size > 512) break;
    }
  }

  const scored = [];
  const probe = Math.min(buffer.length, probeBytes);
  for (const encoded of keys) {
    const [lengthText, hex] = encoded.split(':');
    const length = Number(lengthText);
    if (!Number.isInteger(length) || length < 2 || length > maxKeyLen) continue;
    const key = Buffer.from(hex, 'hex');
    if (key.length !== length) continue;
    let anchors = 0;
    let runs = 0;
    let current = '';
    const chunks = [];
    const flush = () => {
      if (current.length >= 8 && looksLikeText(current)) { runs += 1; chunks.push(current); }
      current = '';
    };
    for (let i = 0; i < probe; i += 1) {
      const decoded = buffer[i] ^ key[i % length];
      if (decoded >= 0x20 && decoded <= 0x7e) current += String.fromCharCode(decoded);
      else flush();
    }
    flush();
    anchors = (chunks.join('\n').match(new RegExp(SEMANTIC_ANCHOR.source, 'gi')) ?? []).length;
    const score = runs + anchors * 2;
    if (score >= 2 && anchors >= 1) scored.push({ key, keyLen: length, hex, score, runs });
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, maxCandidates);
}

const QUICK = 16;

/**
 * Alignment score for one candidate offset.
 *
 * Requiring all 16 bytes to be printable looks safe but fails on any real
 * container: a length-prefixed record starts with four binary bytes, so a
 * perfect plaintext scores 12/16 at its true offset and is rejected while a
 * random offset occasionally scores higher later in the window. Allow a small
 * structural budget and reward a semantic anchor instead.
 */
const windowScore = (buffer, at, keystream, window = QUICK) => {
  if (at < 0 || at + window > buffer.length || keystream.length < window) return -1;
  let printable = 0;
  let text = '';
  for (let i = 0; i < window; i += 1) {
    const byte = buffer[at + i] ^ keystream[i];
    if (byte >= 0x20 && byte <= 0x7e) { printable += 1; text += String.fromCharCode(byte); }
    else text += ' ';
  }
  if (printable < window - 4) return printable;
  return printable + (SEMANTIC_ANCHOR.test(text) ? 8 : 0);
};

/**
 * Try every candidate key against every high-entropy region, for both RC4 and
 * keyed XOR. Alignment matters for RC4 (the keystream is position dependent),
 * so the region start is searched byte by byte over a bounded window. The
 * filter is deliberately mechanical - 16 printable bytes cannot happen by
 * chance often - and the surviving candidates are then validated against
 * semantic anchors, never against the shape of the key.
 */
export function recoverBlobs(buffer, {
  regions,
  keys,
  maxDecrypt = 256 * 1024,
  // A length-prefixed container spends 4 binary bytes per record plus a NUL
  // terminator, so a perfectly good plaintext lands near 0.79 - the old 0.82
  // gate rejected every structured config while still passing random data at
  // 0.37. 0.70 keeps a wide margin against a wrong key.
  minPrintableRatio = 0.70,
  alignmentWindow = 8192,
  maxKeys = 12,
} = {}) {
  const results = [];
  const shortlist = keys
    .map((item) => (Buffer.isBuffer(item) ? item : Buffer.from(item.value ?? item, 'latin1')))
    .filter((item) => item.length >= 4)
    .slice(0, maxKeys);
  for (const region of regions) {
    const from = Math.max(0, region.start - alignmentWindow);
    const to = Math.min(buffer.length, region.start + 1024, buffer.length - QUICK);
    for (const key of shortlist) {
      const head = rc4Keystream(key, QUICK);
      let bestAt = -1;
      let bestScore = QUICK - 5;
      for (let at = from; at < to; at += 1) {
        const score = windowScore(buffer, at, head);
        if (score > bestScore) { bestScore = score; bestAt = at; }
      }
      if (bestAt < 0) continue;
      // Decrypt past the coarse region end, then cut at the first long
      // non-printable stretch. Blob boundaries are fuzzy; the plaintext
      // boundary is not, and truncating at the region end would silently drop
      // every string that sits after it.
      const limit = Math.min(buffer.length - bestAt, maxDecrypt, Math.max(region.end - bestAt, 512) + 4096);
      const stream = rc4Keystream(key, limit);
      const whole = Buffer.alloc(limit);
      for (let i = 0; i < limit; i += 1) whole[i] = buffer[bestAt + i] ^ stream[i];
      // The blob boundary is fuzzy, so cut where the decrypted stream stops
      // looking like text: plaintext stays above ~90% printable, a wrong tail
      // (padding, code, the next section) sits near 37%.
      let end = limit;
      // 256-byte window: a 64-byte window swings between 0.6 and 0.9 inside a
      // length-prefixed container (short records carry 5 structural bytes) and
      // would cut the blob in the middle of a valid config.
      const span = 256;
      const ring = new Uint8Array(span);
      let window = 0;
      for (let i = 0; i < limit; i += 1) {
        const printable = whole[i] >= 0x20 && whole[i] <= 0x7e ? 1 : 0;
        const slot = i % span;
        window += printable - ring[slot];
        ring[slot] = printable;
        if (i >= span * 2 && i % 16 === 0 && window / span < 0.5) {
          // The dip is already ~128 bytes into the random tail; cutting a full
          // window back also removes the last records. Walk back to the last
          // 64-byte span that still looks like text.
          let cut = i;
          const floor = Math.max(0, i - 2048);
          for (let back = i; back > floor; back -= 8) {
            let good = 0;
            for (let k = back - 64; k < back; k += 1) if (whole[k] >= 0x20 && whole[k] <= 0x7e) good += 1;
            if (good / 64 >= 0.8) { cut = back; break; }
          }
          end = cut;
          break;
        }
      }
      while (end > 0 && (whole[end - 1] < 0x20 || whole[end - 1] > 0x7e)) end -= 1;
      const length = end;
      if (length < 128) continue;
      const data = whole.subarray(0, length);
      const printable = (data.toString('latin1').match(/[\x20-\x7e]/g) ?? []).length;
      if (printable / length < minPrintableRatio) continue;
      if (!SEMANTIC_ANCHOR.test(data.toString('latin1', 0, Math.min(length, 8192)))) continue;
      results.push({ start: bestAt, end: bestAt + length, key: key.toString('latin1'), mode: 'rc4', data });
    }
    // Keyed XOR is alignment independent, so one pass per key is enough.
    for (const key of shortlist) {
      const data = xorWithKey(buffer, key, region.start);
      const sample = data.toString('latin1', 0, Math.min(data.length, 4096));
      const printable = (sample.match(/[\x20-\x7e]/g) ?? []).length;
      if (!SEMANTIC_ANCHOR.test(sample)) continue;
      if (printable / Math.max(1, sample.length) < minPrintableRatio) continue;
      results.push({ start: region.start, end: region.start + data.length, key: key.toString('latin1'), mode: 'xor-key', data });
    }
  }
  // One strong result per region/mode keeps the derived-string list readable.
  const best = new Map();
  for (const item of results) {
    const id = `${item.mode}:${item.start}`;
    const previous = best.get(id);
    if (!previous || item.data.length > previous.data.length) best.set(id, item);
  }
  return [...best.values()];
}

/**
 * Reassemble stack strings: short immediates pushed one at a time and joined at
 * runtime. Only chains of three or more short fragments that form real text are
 * reported, which keeps random code bytes out of the result.
 */
export function joinStackFragments(fragments, { maxGap = 32, maxLength = 15, minFragments = 3 } = {}) {
  const usable = fragments
    .filter((item) => item.encoding === 'ascii' && item.value.length >= 3 && item.value.length <= maxLength)
    .sort((a, b) => a.offset - b.offset);
  const out = [];
  for (let i = 0; i < usable.length; i += 1) {
    const chain = [usable[i]];
    let end = usable[i].offset + usable[i].value.length;
    for (let j = i + 1; j < usable.length && j < i + 14; j += 1) {
      if (usable[j].offset - end > maxGap) break;
      chain.push(usable[j]);
      end = usable[j].offset + usable[j].value.length;
    }
    // Take the longest join that reads as text. Stopping at the first readable
    // prefix would return "https://telemetry." instead of the whole URL.
    for (let take = chain.length; take >= minFragments; take -= 1) {
      const text = chain.slice(0, take).map((item) => item.value).join('');
      if (looksLikeText(text, { minLength: 12 })) {
        out.push({ value: text, offset: chain[0].offset, fragments: take });
        break;
      }
    }
  }
  return out;
}
