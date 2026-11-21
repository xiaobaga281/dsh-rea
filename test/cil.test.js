/**
 * Pure-byte unit tests for the CIL layer (lib/cil.js): opcode table sanity,
 * method-body headers (tiny/fat), exception-clause parsing, instruction
 * decoding with branch/switch targets, token resolution, and #US string
 * decoding. No fixtures, no processes, no sockets - smoke-layer safe.
 *
 * The opcode table itself is generated from System.Reflection.Emit.OpCodes;
 * the corpus-wide decode checks (every method of a real assembly consumes
 * exactly its code bytes) live in test/managed.test.js.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeUserStringAt, disassembleIl, parseMethodBody } from '../lib/static/cil.js';

test('the opcode table covers the documented set with unique values', async () => {
  const { OPCODES } = await import('../lib/static/cil.js');
  assert.equal(OPCODES.get(0x00)?.name, 'nop');
  assert.equal(OPCODES.get(0x28)?.name, 'call');
  assert.equal(OPCODES.get(0x72)?.name, 'ldstr');
  assert.equal(OPCODES.get(0xfe06)?.name, 'ldftn');
  assert.equal(OPCODES.get(0xfe1c)?.name, 'sizeof');
  // Measured-from-.NET corrections that a from-memory table would get wrong.
  assert.equal(OPCODES.get(0x59)?.name, 'sub');
  assert.equal(OPCODES.get(0xc3)?.name, 'ckfinite');
  assert.equal(OPCODES.get(0x7e)?.name, 'ldsfld');
  // Unassigned slots stay absent: 0x24, 0x77, 0x78, 0xfe08, 0xfe1f.
  for (const gap of [0x24, 0x77, 0x78, 0xfe08, 0xfe1f]) {
    assert.equal(OPCODES.has(gap), false, `0x${gap.toString(16)} should be unassigned`);
  }
});

test('tiny and fat method bodies are parsed with their bounds', () => {
  const tiny = Buffer.from([0x0a, 0x16, 0x2a]); // header (2<<2)|2, ldc.i4.0, ret
  const body = parseMethodBody(tiny, 0);
  assert.equal(body.kind, 'tiny');
  assert.equal(body.codeAt, 1);
  assert.equal(body.codeLength, 2);
  assert.equal(body.maxStack, 8);
  assert.deepEqual(body.eh, []);

  const fat = Buffer.alloc(20);
  fat.writeUInt16LE((3 << 12) | 0x03 | 0x10, 0); // 3 dwords, FatFormat(0x3), InitLocals
  fat.writeUInt16LE(1, 2); // maxstack
  fat.writeUInt32LE(4, 4); // code size
  fat.writeUInt32LE(0x11000001, 8); // locals sig token
  fat.set([0x16, 0x2a, 0x00, 0x00], 12); // ldc.i4.0, ret, padding
  const fatBody = parseMethodBody(fat, 0);
  assert.equal(fatBody.kind, 'fat');
  assert.equal(fatBody.maxStack, 1);
  assert.equal(fatBody.localsToken, 0x11000001);
  assert.equal(fatBody.codeAt, 12);
  assert.equal(fatBody.codeLength, 4);
});

test('exception clauses parse in both small and fat encodings', () => {
  // Fat header (MoreSects) + small EH section with one catch clause.
  const bytes = Buffer.alloc(12 + 4 + 4 + 12);
  bytes.writeUInt16LE((3 << 12) | 0x03 | 0x08, 0); // FatFormat + MoreSects
  bytes.writeUInt16LE(1, 2);
  bytes.writeUInt32LE(4, 4); // code size
  bytes.writeUInt32LE(0, 8);
  bytes.set([0x16, 0x2a, 0x00, 0x00], 12); // code + pad to 4
  const sectionAt = 16; // right after the 4-byte code, already 4-aligned
  bytes.writeUInt8(0x01, sectionAt); // small EHTable section
  bytes.writeUInt8(16, sectionAt + 1); // section size: 4 header + 12 clause
  bytes.writeUInt16LE(0x0000, sectionAt + 4); // flags: catch
  bytes.writeUInt16LE(0, sectionAt + 6); // tryOffset
  bytes.writeUInt8(2, sectionAt + 8); // tryLength
  bytes.writeUInt16LE(2, sectionAt + 9); // handlerOffset (packed, no padding)
  bytes.writeUInt8(2, sectionAt + 11); // handlerLength
  bytes.writeUInt32LE(0x01000001, sectionAt + 12); // class token (TypeRef 1)
  const body = parseMethodBody(bytes, 0);
  assert.equal(body.kind, 'fat');
  assert.equal(body.eh.length, 1);
  assert.equal(body.eh[0].kind, 'catch');
  assert.equal(body.eh[0].tryOffset, 0);
  assert.equal(body.eh[0].tryLength, 2);
  assert.equal(body.eh[0].handlerOffset, 2);
  assert.equal(body.eh[0].classToken, 0x01000001);

  // Fat clause: 24 bytes, all u32.
  const fatEh = Buffer.alloc(12 + 4 + 4 + 24);
  fatEh.writeUInt16LE((3 << 12) | 0x03 | 0x08, 0);
  fatEh.writeUInt16LE(1, 2);
  fatEh.writeUInt32LE(4, 4);
  fatEh.writeUInt32LE(0, 8);
  fatEh.set([0x16, 0x2a, 0x00, 0x00], 12);
  fatEh.writeUInt32LE(0x41 | (28 << 8), 16); // fat EHTable at offset 16, section size 28 (4 + 24)
  fatEh.writeUInt32LE(0x0002, 20); // flags: finally (clause starts at 20)
  fatEh.writeUInt32LE(0, 24);
  fatEh.writeUInt32LE(2, 28);
  fatEh.writeUInt32LE(2, 32);
  fatEh.writeUInt32LE(2, 36);
  fatEh.writeUInt32LE(0, 40); // finally: no class token
  const fatBody = parseMethodBody(fatEh, 0);
  assert.equal(fatBody.eh.length, 1);
  assert.equal(fatBody.eh[0].kind, 'finally');
  assert.equal(fatBody.eh[0].classToken, 0);
});

test('branch targets, switch tables and token operands decode against real offsets', () => {
  const resolve = (token) => (token === 0x06000001 ? { kind: 'method', text: 'Prog::Main' } : null);
  // br.s +6 (forward), br.s -2 (backward, lands after the operand)
  const code = Buffer.from([0x2b, 0x06, 0x2b, 0xfe]);
  const dis = disassembleIl(code, resolve);
  assert.deepEqual(dis.instructions.map((item) => item.n), ['br.s', 'br.s']);
  assert.equal(dis.instructions[0].tg, 8);
  assert.equal(dis.instructions[1].tg, 2); // 4 (next instruction) + (-2)
  assert.equal(dis.summary.branches, 2);

  // switch with 2 targets after a 4-byte count
  const sw = Buffer.alloc(2 + 4 + 8);
  sw[0] = 0x45;
  sw.writeUInt32LE(2, 1);
  sw.writeInt32LE(1, 5);
  sw.writeInt32LE(-1, 9);
  const swDis = disassembleIl(sw, null);
  assert.equal(swDis.instructions[0].n, 'switch');
  assert.deepEqual(swDis.instructions[0].tgs, [14, 12]); // relative to the end of the table (offset 13)

  // call with a resolvable method token lands in the apis bucket
  const call = Buffer.from([0x28, 0x01, 0x00, 0x00, 0x06, 0x2a]);
  const callDis = disassembleIl(call, resolve);
  assert.equal(callDis.instructions[0].t, 'Prog::Main');
  assert.deepEqual(callDis.summary.apis, ['Prog::Main']);
  assert.equal(callDis.summary.calls, 1);

  // ldstr lands in the strings bucket via the resolver
  const ldstr = Buffer.from([0x72, 0x01, 0x00, 0x00, 0x70]);
  const strDis = disassembleIl(ldstr, (token) => ({ kind: 'string', text: 'hi' }));
  assert.deepEqual(strDis.summary.strings, ['hi']);
});

test('an unassigned opcode stops decoding with an explicit marker, never a guessed length', () => {
  const code = Buffer.from([0x16, 0x24, 0x16, 0x2a]); // ldc.i4.0, UNASSIGNED 0x24, ...
  const dis = disassembleIl(code, null);
  assert.equal(dis.summary.unknown, 1);
  assert.equal(dis.truncated, true);
  assert.match(dis.instructions[1].n, /unknown 0x24/);
  assert.equal(dis.instructions.length, 2); // decoding stopped at the gap
});

test('the instruction cap bounds runaway methods and reports truncation', () => {
  const code = Buffer.alloc(64, 0x00); // 64 nops
  const dis = disassembleIl(code, null, { instrCap: 4 });
  assert.equal(dis.instructions.length, 4);
  assert.equal(dis.truncated, true);
});

test('user strings decode as length-prefixed UTF-16LE with the flag byte excluded', () => {
  // "AB": length 5 (4 char bytes + 1 flag), utf16le A B, flag 0x00
  const encoded = Buffer.from([0x05, 0x41, 0x00, 0x42, 0x00, 0x00]);
  assert.deepEqual(decodeUserStringAt(encoded, 0), { text: 'AB', bytes: 6 });
  // 0x00 alone is an empty heap entry
  assert.deepEqual(decodeUserStringAt(Buffer.from([0x00]), 0), { text: '', bytes: 1 });
  // length 1 = flag byte only, still empty text
  assert.deepEqual(decodeUserStringAt(Buffer.from([0x01, 0x00]), 0), { text: '', bytes: 2 });
  // two-byte length prefix: 0x81 0x00 -> length 128? no: ((0x81 & 0x3f) << 8) | 0x00 = 256... keep small
  const wide = Buffer.from([0x81, 0x00, ...Buffer.alloc(300)]);
  const decoded = decodeUserStringAt(wide, 0, 128);
  assert.equal(decoded.bytes, 2 + 256);
  // out of range is null, never a throw
  assert.equal(decodeUserStringAt(Buffer.from([0x05, 0x41]), 10), null);
});
