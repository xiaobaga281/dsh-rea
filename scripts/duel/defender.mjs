/**
 * Defender persona: keep making the target harder.
 *
 * Every generation contains the SAME literals (see truth.mjs) and only changes
 * how they are stored. Generations are cumulative - D3 keeps D2's tricks and
 * adds new ones - which is how a real target evolves after each analysis.
 *
 *   D0  control: plaintext, no protection
 *   D1  odd-phase UTF-16 + single-byte XOR          (defeated by 1.5.0)
 *   D2  RC4 config blob + 4-byte XOR + stack + reversed + API hashes
 *   D3  + zlib container + position-dependent (delta) + interleaved lanes
 *       + custom base64 alphabet + unknown-algorithm hash table
 *   D4  + nesting (zlib of XORed records) + decoy blobs and decoy tables
 *   D5  + a config encrypted with a runtime-derived key that is NOT in the file
 *
 * Usage: import { buildGeneration } from './defender.mjs'
 */
import { deflateSync } from 'node:zlib';

import { ALL_STRINGS, ANTI, CANARY, ENDPOINTS, IOC_TEXT, MARKERS } from './truth.mjs';

// ------------------------------------------------------------------ encoders --

const align = (value, to) => Math.ceil(value / to) * to;

const rc4 = (key, data) => {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = Buffer.alloc(data.length);
  let i = 0; j = 0;
  for (let n = 0; n < data.length; n += 1) {
    i = (i + 1) & 0xff; j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
};

const xorRepeat = (input, key) => {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, 'latin1');
  const out = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw[i] ^ key[i % key.length];
  return out;
};

const utf16 = (text) => {
  const out = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i += 1) out.writeUInt16LE(text.charCodeAt(i), i * 2);
  return out;
};

const records = (list) => Buffer.concat(list.map((text) => {
  const body = Buffer.from(`${text}\0`, 'latin1');
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length);
  return Buffer.concat([prefix, body]);
}));

/**
 * Position-dependent encoding: out[i] = plain[i] + i. The counter resets per
 * record, which is what a hand-rolled loop in a config loader usually does.
 */
const deltaEncode = (list) => Buffer.concat(list.map((text) => {
  const body = Buffer.from(`${text}\0`, 'latin1');
  const out = Buffer.alloc(body.length);
  for (let i = 0; i < body.length; i += 1) out[i] = (body[i] + i) & 0xff;
  return out;
}));

/** Two lanes merged byte by byte: neither lane is readable until split. */
const interleave = (left, right) => {
  const a = Buffer.from(`${left}\0`, 'latin1');
  const b = Buffer.from(`${right}\0`, 'latin1');
  const out = Buffer.alloc(Math.max(a.length, b.length) * 2);
  for (let i = 0; i < out.length / 2; i += 1) {
    out[i * 2] = a[i] ?? 0;
    out[i * 2 + 1] = b[i] ?? 0;
  }
  return out;
};

/** Custom base64 alphabet: a permuted set, so the standard table decodes junk. */
const STANDARD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// A true permutation: gcd(17, 64) = 1, so every index lands exactly once.
const B64_ALPHABET = [...Array(64)].map((_, index) => STANDARD_B64[(index * 17 + 5) % 64]).join('');
const b64Custom = (buffer) => {
  const text = buffer.toString('base64').replace(/=+$/, '');
  let out = '';
  for (const char of text) out += B64_ALPHABET[STANDARD_B64.indexOf(char)];
  return Buffer.from(out, 'latin1');
};

/** A hash algorithm that is not in the analyser's dictionary. */
const hashUnknown = (name) => {
  let h = 0x2f;
  for (const byte of Buffer.from(name, 'latin1')) h = (Math.imul(h, 0x1f) ^ byte) >>> 0;
  return h;
};

// ---------------------------------------------------------------- PE builder --

const IMPORT_GROUPS = [
  { dll: 'KERNEL32.dll', apis: ['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread', 'GetComputerNameA', 'GetVolumeInformationA', 'QueryPerformanceCounter'] },
  { dll: 'WININET.dll', apis: ['InternetConnectA', 'HttpSendRequestA'] },
  { dll: 'ADVAPI32.dll', apis: ['RegSetValueExA', 'CryptEncrypt'] },
];

/**
 * Build the read-only section.
 *
 * `imports: false` is the D6 step: no descriptors, no DLL names, no thunks, so
 * the import directory has nothing to point at. What remains is the hash table,
 * which is what a real loader leaves behind.
 *
 * TLS and the dispatch table need virtual addresses that depend on where .text
 * lands, and that depends on this section's length. They are reserved here as
 * zero-filled slots and patched in buildPE once textVa is known.
 */
function buildRdata(payload, { hashTable = null, imports = true, tls = false, dispatch = 0 } = {}) {
  const parts = [];
  let cursor = 0;
  const put = (buffer, padding = 0) => {
    const at = cursor;
    parts.push({ at, buffer });
    cursor = align(cursor + buffer.length + padding, 4);
    return at;
  };

  let descriptorsAt = null;
  const dllNameAt = [];
  const thunkAt = [];
  if (imports) {
    descriptorsAt = put(Buffer.alloc(20 * (IMPORT_GROUPS.length + 1)));
    for (const entry of IMPORT_GROUPS) dllNameAt.push(put(Buffer.from(`${entry.dll}\0`, 'latin1'), 2));
    for (const entry of IMPORT_GROUPS) {
      const thunk = Buffer.alloc(4 * (entry.apis.length + 1));
      thunkAt.push({ at: put(thunk), entry, names: entry.apis });
    }
    for (const group of thunkAt) {
      const patched = Buffer.alloc(4 * (group.entry.apis.length + 1));
      group.entry.apis.forEach((api, slot) => {
        const at = put(Buffer.from(`\0\0${api}\0`, 'latin1'), 2);
        patched.writeUInt32LE(0x1000 + at, slot * 4);
      });
      parts.find((item) => item.at === group.at).buffer = patched;
    }
  }

  if (hashTable && hashTable.length > 0) {
    const table = Buffer.alloc(hashTable.length * 4);
    hashTable.forEach((value, index) => table.writeUInt32LE(value >>> 0, index * 4));
    put(table);
  }

  // IMAGE_TLS_DIRECTORY32: Start, End, Index, AddressOfCallbacks, ZeroFill, Characteristics.
  const tlsAt = tls ? put(Buffer.alloc(24)) : null;
  const callbacksAt = tls ? put(Buffer.alloc(8)) : null;
  // A dispatch table is just an array of code pointers; the state variable and
  // the indirect jump live in .text, which this fixture does not need to encode.
  const dispatchAt = dispatch > 0 ? put(Buffer.alloc(dispatch * 4)) : null;

  const payloadAt = align(cursor, 16);
  parts.push({ at: payloadAt, buffer: payload });

  const size = align(payloadAt + payload.length, 0x10);
  const rdata = Buffer.alloc(size);
  for (const part of parts) part.buffer.copy(rdata, part.at);

  if (imports) {
    IMPORT_GROUPS.forEach((entry, index) => {
      const at = descriptorsAt + index * 20;
      rdata.writeUInt32LE(0x1000 + thunkAt[index].at, at);
      rdata.writeUInt32LE(0x1000 + dllNameAt[index], at + 12);
      rdata.writeUInt32LE(0x1000 + thunkAt[index].at, at + 16);
    });
  }

  return { buffer: rdata, info: { tlsAt, callbacksAt, dispatchAt, dispatchCount: dispatch } };
}

function buildText(stackChunks = []) {
  const buffer = Buffer.alloc(0x3000);
  let seed = 0x1f2e3d4c;
  for (let i = 0; i < buffer.length; i += 1) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    buffer[i] = seed >>> 24;
  }
  if (stackChunks.length === 0) return buffer;
  const JUNK = [0xcc, 0x90, 0x00, 0xeb, 0x00];
  let at = 0x140;
  for (const chunk of stackChunks) {
    buffer.write(`${chunk}\0`, at, 'latin1');
    at += chunk.length + 1;
    for (const byte of JUNK) { buffer[at] = byte; at += 1; }
  }
  return buffer;
}

const TLS_CODE_RVA = 0x800;

function buildPE({ rdata, text, imports = true, info = null, overlap = false }) {
  const headers = 0x200;
  const rdataRaw = align(rdata.length, 0x200);
  const textRaw = align(text.length, 0x200);
  const rdataVa = 0x1000;
  const textVa = rdataVa + align(rdataRaw, 0x1000);
  const imageSize = textVa + align(textRaw, 0x1000);
  const total = headers + rdataRaw + textRaw;
  // Overlapping raw ranges are a loader signature: .text starts inside .rdata's
  // last page, so a file-offset-based tool and an RVA-based tool disagree about
  // what is where.
  const textPointer = headers + rdataRaw - (overlap ? 0x200 : 0);
  const file = Buffer.alloc(total);

  // TLS and the dispatch table can only be filled in now that textVa is known.
  if (info) {
    if (info.tlsAt !== null) {
      rdata.writeUInt32LE(0x400000 + rdataVa + info.callbacksAt, info.tlsAt + 12);
      rdata.writeUInt32LE(0x400000 + textVa + TLS_CODE_RVA, info.callbacksAt);
      rdata.writeUInt32LE(0, info.callbacksAt + 4);
    }
    if (info.dispatchAt !== null) {
      for (let index = 0; index < info.dispatchCount; index += 1) {
        rdata.writeUInt32LE(0x400000 + textVa + 0x100 + index * 0x20, info.dispatchAt + index * 4);
      }
    }
  }

  file.write('MZ', 0, 'latin1');
  file.writeUInt32LE(0x80, 0x3c);
  const pe = 0x80;
  file.write('PE\0\0', pe, 'latin1');
  const coff = pe + 4;
  file.writeUInt16LE(0x14c, coff);
  file.writeUInt16LE(2, coff + 2);
  file.writeUInt16LE(0xe0, coff + 16);
  file.writeUInt16LE(0x0102, coff + 18);
  const opt = coff + 20;
  file.writeUInt16LE(0x10b, opt);
  file.writeUInt32LE(textVa + 0x100, opt + 16);
  file.writeUInt32LE(0x400000, opt + 28);
  file.writeUInt32LE(0x1000, opt + 32);
  file.writeUInt32LE(0x200, opt + 36);
  file.writeUInt32LE(imageSize, opt + 56);
  file.writeUInt32LE(headers, opt + 60);
  file.writeUInt16LE(3, opt + 68);
  file.writeUInt32LE(16, opt + 92);
  if (imports) {
    file.writeUInt32LE(rdataVa, opt + 96 + 8);
    file.writeUInt32LE(0x40, opt + 96 + 12);
  }
  if (info?.tlsAt !== null && info?.tlsAt !== undefined) {
    file.writeUInt32LE(rdataVa + info.tlsAt, opt + 96 + 9 * 8);
    file.writeUInt32LE(24, opt + 96 + 9 * 8 + 4);
  }

  const writeSection = (index, name, va, rawSize, rawPointer, characteristics) => {
    const at = opt + 0xe0 + index * 40;
    file.write(name.padEnd(8, '\0'), at, 'latin1');
    file.writeUInt32LE(rawSize, at + 8);
    file.writeUInt32LE(va, at + 12);
    file.writeUInt32LE(rawSize, at + 16);
    file.writeUInt32LE(rawPointer, at + 20);
    file.writeUInt32LE(characteristics, at + 36);
  };
  writeSection(0, '.rdata', rdataVa, rdataRaw, headers, 0x40000040);
  writeSection(1, '.text', textVa, textRaw, textPointer, 0x60000020);

  rdata.copy(file, headers);
  text.copy(file, textPointer);
  return file;
}

// -------------------------------------------------------------- generations --

const KEY4 = [0x9e, 0x37, 0x79, 0xb4];
const RC4_KEY = 'OrbitCfgKey2026!';
const NESTED_KEY = [0x2b, 0x8d, 0x41, 0xf0];

/**
 * Salted hash: the same loop as the parameterised family, then XOR with a
 * per-build constant that only exists inside the sealed config. No algorithm
 * family can recover the names, because the missing input is not an algorithm
 * parameter - it is data the file refuses to hand over statically.
 */
const SALTED_SEED = 0x5d3a91c7;
const saltedHash = (name) => {
  let hash = 0x2f;
  for (const byte of Buffer.from(name, 'latin1')) hash = (Math.imul(hash, 0x1f) ^ byte) >>> 0;
  return (hash ^ SALTED_SEED) >>> 0;
};

/** ROR13, the hash Metasploit and most shellcode loaders use. */
const ror13Hash = (name) => {
  let hash = 0;
  for (const byte of Buffer.from(name, 'latin1')) hash = (((hash >>> 13) | (hash << 19)) + byte) >>> 0;
  return hash >>> 0;
};

/** Deterministic decoys: random bytes that must not turn into fake indicators. */
function decoyBlobs(count, size, seed = 0x1234abcd) {
  const out = [];
  let state = seed >>> 0;
  for (let n = 0; n < count; n += 1) {
    const buffer = Buffer.alloc(size);
    for (let i = 0; i < size; i += 1) {
      state = (state * 1664525 + 1013904223) >>> 0;
      buffer[i] = state >>> 24;
    }
    out.push(buffer);
  }
  return out;
}

// Every literal list goes through track(). A generation can then only claim
// coverage it actually encoded, which is how two fixture gaps (an omitted ANTI
// block, a lost endpoint) were caught before they could be read as detector
// failures.
let tracked = new Set();
const track = (values) => { for (const value of values) tracked.add(value); return values; };

const GENERATIONS = {
  D0: () => ({
    note: 'control: every literal is plaintext',
    payload: records(track([...ENDPOINTS, ...MARKERS, ...ANTI, ...IOC_TEXT, `canary=${CANARY[0]}`])),
  }),

  D1: () => {
    const parts = [Buffer.from([0])];
    const xor = new Set([ENDPOINTS[2], ENDPOINTS[4], 'installation_id']);
    const wide = new Set([...ANTI.slice(0, 6), ENDPOINTS[3]]);
    for (const text of track([...ENDPOINTS, ...MARKERS, ...ANTI, ...IOC_TEXT, `canary=${CANARY[0]}`])) {
      if (xor.has(text)) parts.push(xorRepeat(`${text}\0`, [0x5a]));
      else if (wide.has(text)) parts.push(Buffer.concat([Buffer.from([0x41]), utf16(`${text}\0`)]));
      else parts.push(Buffer.from(`${text}\0`, 'latin1'));
    }
    return { note: 'odd-phase UTF-16 + single-byte XOR', payload: Buffer.concat(parts) };
  },

  D2: () => {
    const plain = records(track([...ENDPOINTS, ...MARKERS, ...ANTI, ...IOC_TEXT]).map((text) => (
      text === ENDPOINTS[1] ? [...text].reverse().join('') : text
    )));
    const stack = [];
    track([ENDPOINTS[0], `canary=${CANARY[0]}`]);
    for (let i = 0; i < ENDPOINTS[0].length; i += 6) stack.push(ENDPOINTS[0].slice(i, i + 6));
    return {
      note: 'RC4 config blob + reversed literal + stack strings + ROR13 API hashes',
      payload: Buffer.concat([
        Buffer.from(`cfg=rc4;key=${RC4_KEY};build=release\0`, 'latin1'),
        rc4(Buffer.from(RC4_KEY, 'latin1'), plain),
        Buffer.from(`canary=${CANARY[0]}\0`, 'latin1'),
      ]),
      stack,
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map((api) => {
        let h = 0;
        for (const byte of Buffer.from(api, 'latin1')) h = (((h >>> 13) | (h << 19)) + byte) >>> 0;
        return h;
      }),
    };
  },

  D3: () => {
    // The watermark rides inside the compressed table: detecting it proves the
    // container channel and the attribution detector actually met.
    const compressed = deflateSync(records(track([
      ...ENDPOINTS.slice(0, 2), ...MARKERS.slice(0, 10), `canary=${CANARY[0]}`,
    ])));
    const delta = deltaEncode(track([ENDPOINTS[2], ...IOC_TEXT.slice(0, 3)]));
    track([ENDPOINTS[3], ENDPOINTS[4]]);
    const lanes = interleave(ENDPOINTS[3], ENDPOINTS[4]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(records(track([...MARKERS.slice(10), ...IOC_TEXT.slice(3), ...ANTI]))),
      Buffer.from('\0', 'latin1'),
    ]);
    return {
      note: 'zlib container + delta-coded records + interleaved lanes + custom base64 + unknown hash',
      payload: Buffer.concat([
        Buffer.from('cfg=deflate;v=3\0', 'latin1'),
        Buffer.from(compressed), Buffer.from('\0', 'latin1'),
        delta, Buffer.from('\0', 'latin1'),
        lanes, Buffer.from('\0', 'latin1'),
        custom,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(hashUnknown),
    };
  },

  D4: () => {
    // Nesting: the record table is XORed first, then compressed. Recovering it
    // needs inflate AND a second decode pass inside the inflated bytes.
    const inner = xorRepeat(records(track([...ENDPOINTS.slice(0, 2), ...MARKERS, ...ANTI.slice(0, 4)])), NESTED_KEY);
    const nested = Buffer.concat([Buffer.from(`cfg=deflate+xor;key=${Buffer.from(NESTED_KEY).toString('hex')};\0`, 'latin1'), deflateSync(inner)]);
    track([ENDPOINTS[2], ENDPOINTS[3]]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(deflateSync(records(track([
        ENDPOINTS[4], ...ANTI.slice(4), ...IOC_TEXT, `canary=${CANARY[0]}`,
      ])))),
      Buffer.from('\0', 'latin1'),
    ]);
    const decoys = decoyBlobs(24, 1536);
    return {
      note: 'nested zlib(XOR(records)) + base64(zlib(records)) + 24 high-entropy decoys',
      payload: Buffer.concat([
        nested, Buffer.from('\0', 'latin1'),
        interleave(ENDPOINTS[2], ENDPOINTS[3]), Buffer.from('\0', 'latin1'),
        custom,
        ...decoys,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(hashUnknown),
      decoys: decoys.length,
    };
  },

  D5: () => {
    // Same layers as D4, plus one config sealed with a key derived at run time
    // from the volume serial. That key is genuinely absent from the file, so no
    // static method can open the blob; the analyser must say so instead of
    // silently reporting nothing.
    const sealed = rc4(Buffer.from('runtime-derived-key-placeholder', 'latin1'),
      records(track([ENDPOINTS[1], ANTI[8], IOC_TEXT[2], `canary=${CANARY[0]}`])));
    const inner = xorRepeat(records(track([...ENDPOINTS.slice(0, 1), ...MARKERS, ...ANTI.slice(0, 8)])), NESTED_KEY);
    track([ENDPOINTS[3], ENDPOINTS[4]]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(deflateSync(records(track([ENDPOINTS[2], ...ANTI.slice(8), ...IOC_TEXT])))),
      Buffer.from('\0', 'latin1'),
    ]);
    const decoys = decoyBlobs(18, 1536, 0x77aa33cc);
    return {
      note: 'config sealed with a runtime-derived key (unrecoverable) + the D4 layers elsewhere',
      payload: Buffer.concat([
        Buffer.from('cfg=rc4;key=derive(GetVolumeInformationA.serial);\0', 'latin1'),
        Buffer.from('sealed=', 'latin1'), sealed, Buffer.from('\0', 'latin1'),
        Buffer.from(`cfg=deflate+xor;key=${Buffer.from(NESTED_KEY).toString('hex')};\0`, 'latin1'),
        deflateSync(inner),
        Buffer.from('\0', 'latin1'),
        interleave(ENDPOINTS[4], ENDPOINTS[3]), Buffer.from('\0', 'latin1'),
        custom,
        ...decoys,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(hashUnknown),
      decoys: decoys.length,
      unrecoverable: true,
    };
  },

  D6: () => {
    // D5 moved the strings out of reach of a decoder; D6 moves the *structure*
    // out of reach of the report. Three changes, all of them what a loader
    // actually looks like when its author expected a static analyst:
    //
    //   - the import directory is gone, so the only way to name the APIs is the
    //     hash table (ROR13, the one Metasploit uses);
    //   - a TLS callback runs before the entry point, which is where the
    //     anti-debug check lives in the real thing;
    //   - a dispatch table of code pointers sits in .rdata, the signature of
    //     control-flow flattening.
    //
    // The key-derivation hint moves inside the nested layer as well: D5 left it
    // in plaintext, so "plan a dynamic trace" could be answered without
    // decoding anything. Here the analyst has to open the container first,
    // which is the order an independent analyst actually works in.
    const sealed = rc4(Buffer.from('runtime-derived-key-placeholder', 'latin1'),
      records(track([ENDPOINTS[1], ANTI[8], IOC_TEXT[2], `canary=${CANARY[0]}`])));
    const inner = xorRepeat(records([
      ...track([ENDPOINTS[0], ...MARKERS, ...ANTI.slice(0, 8)]),
      'cfg=rc4;key=derive(GetVolumeInformationA.serial);',
    ]), NESTED_KEY);
    track([ENDPOINTS[2], ENDPOINTS[3], ENDPOINTS[4]]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(deflateSync(records(track([ENDPOINTS[2], ...ANTI.slice(8), ...IOC_TEXT])))),
      Buffer.from('\0', 'latin1'),
    ]);
    const decoys = decoyBlobs(18, 1536, 0x51bd2e77);
    return {
      note: 'import directory removed + ROR13 API hashes + TLS callback + flattened dispatch table',
      payload: Buffer.concat([
        Buffer.from('sealed=', 'latin1'), sealed, Buffer.from('\0', 'latin1'),
        Buffer.from(`cfg=deflate+xor;key=${Buffer.from(NESTED_KEY).toString('hex')};\0`, 'latin1'),
        deflateSync(inner),
        Buffer.from('\0', 'latin1'),
        interleave(ENDPOINTS[3], ENDPOINTS[4]), Buffer.from('\0', 'latin1'),
        custom,
        ...decoys,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(ror13Hash),
      decoys: decoys.length,
      unrecoverable: true,
      pe: { imports: false, tls: true, dispatch: 24 },
    };
  },

  D7: () => {
    // D6 gave the analyst a hash table it could open. D7 keeps every structural
    // trick but swaps the hash for a private one, then adds two sections that
    // overlap in the file: the import directory is still gone, the TLS callback
    // is still there, and the only way to name an API is to notice that the
    // table exists and admit the algorithm is unknown.
    //
    // This is the honesty generation. A tool that invents names here is worse
    // than one that reports "7 hash entries, algorithm unknown".
    const sealed = rc4(Buffer.from('runtime-derived-key-placeholder', 'latin1'),
      records(track([ENDPOINTS[1], ANTI[8], IOC_TEXT[2], `canary=${CANARY[0]}`])));
    const inner = xorRepeat(records([
      ...track([ENDPOINTS[0], ...MARKERS, ...ANTI.slice(0, 8)]),
      'cfg=rc4;key=derive(GetVolumeInformationA.serial);',
    ]), NESTED_KEY);
    track([ENDPOINTS[2], ENDPOINTS[3], ENDPOINTS[4]]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(deflateSync(records(track([ENDPOINTS[2], ...ANTI.slice(8), ...IOC_TEXT])))),
      Buffer.from('\0', 'latin1'),
    ]);
    const decoys = decoyBlobs(20, 1024, 0x2f9a11c3);
    return {
      note: 'unknown hash algorithm + stripped imports + TLS callback + overlapping sections',
      payload: Buffer.concat([
        Buffer.from('sealed=', 'latin1'), sealed, Buffer.from('\0', 'latin1'),
        Buffer.from(`cfg=deflate+xor;key=${Buffer.from(NESTED_KEY).toString('hex')};\0`, 'latin1'),
        deflateSync(inner), Buffer.from('\0', 'latin1'),
        interleave(ENDPOINTS[3], ENDPOINTS[4]), Buffer.from('\0', 'latin1'),
        custom,
        ...decoys,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(hashUnknown),
      decoys: decoys.length,
      unrecoverable: true,
      pe: { imports: false, tls: true, dispatch: 16, overlap: true },
    };
  },

  D8: () => {
    // The next boundary is not structural, it is informational: the hash loop is
    // ordinary, but its salt is generated per build and stored inside the
    // sealed config. Every algorithm family fails, and the correct answer is
    // "10 hash entries, algorithm unknown, salt probably sealed" - not a guess.
    const sealed = rc4(Buffer.from('runtime-derived-key-placeholder', 'latin1'),
      records(track([ENDPOINTS[1], ANTI[8], IOC_TEXT[2], `canary=${CANARY[0]}`])));
    const inner = xorRepeat(records([
      ...track([ENDPOINTS[0], ...MARKERS, ...ANTI.slice(0, 8)]),
      `cfg=rc4;key=derive(GetVolumeInformationA.serial);salt=0x${SALTED_SEED.toString(16)};`,
    ]), NESTED_KEY);
    track([ENDPOINTS[2], ENDPOINTS[3], ENDPOINTS[4]]);
    const custom = Buffer.concat([
      Buffer.from('abc=', 'latin1'), Buffer.from(B64_ALPHABET, 'latin1'), Buffer.from(';\0', 'latin1'),
      b64Custom(deflateSync(records(track([ENDPOINTS[2], ...ANTI.slice(8), ...IOC_TEXT])))),
      Buffer.from('\0', 'latin1'),
    ]);
    const decoys = decoyBlobs(22, 1280, 0x6b1f0d42);
    return {
      note: 'salted API hashes (salt sealed) + stripped imports + TLS callback + overlapping sections',
      payload: Buffer.concat([
        Buffer.from('sealed=', 'latin1'), sealed, Buffer.from('\0', 'latin1'),
        Buffer.from(`cfg=deflate+xor;key=${Buffer.from(NESTED_KEY).toString('hex')};\0`, 'latin1'),
        deflateSync(inner), Buffer.from('\0', 'latin1'),
        interleave(ENDPOINTS[3], ENDPOINTS[4]), Buffer.from('\0', 'latin1'),
        custom,
        ...decoys,
      ]),
      hashTable: IMPORT_GROUPS.flatMap((group) => group.apis).map(saltedHash),
      decoys: decoys.length,
      unrecoverable: true,
      pe: { imports: false, tls: true, dispatch: 16, overlap: true },
    };
  },
};

export const GENERATION_IDS = Object.keys(GENERATIONS);

function assertCoverage(id) {
  const missing = ALL_STRINGS.filter((value) => !tracked.has(value));
  if (missing.length > 0) throw new Error(`${id} does not carry: ${missing.join(', ')}`);
  if (![...tracked].some((value) => value.startsWith('canary='))) {
    throw new Error(`${id} carries no attribution watermark`);
  }
}

/**
 * Build one generation. Returns the file bytes plus the defender's own notes
 * (the attacker never receives the notes).
 */
export function buildGeneration(id) {
  tracked = new Set();
  const spec = GENERATIONS[id]();
  assertCoverage(id);
  const pe = spec.pe ?? {};
  const built = buildRdata(spec.payload, { hashTable: spec.hashTable ?? null, ...pe });
  const text = buildText(spec.stack ?? []);
  const buffer = buildPE({
    rdata: built.buffer,
    text,
    imports: pe.imports !== false,
    info: built.info,
    overlap: Boolean(pe.overlap),
  });
  return { id, buffer, note: spec.note, decoys: spec.decoys ?? 0, unrecoverable: Boolean(spec.unrecoverable) };
}
