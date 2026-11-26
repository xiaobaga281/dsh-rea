/**
 * Bounded CIL method-body parsing and disassembly for managed assemblies.
 *
 * This is the layer between "metadata manifest" (lib/managed.js) and a full
 * CIL decompiler, and it is deliberately the former plus instruction-level
 * reading, NOT the latter: it decodes method bodies into opcode/operand
 * listings, resolves metadata tokens to names, and summarises which methods,
 * fields, types and user strings a body reaches — enough to attribute
 * behaviour to a managed sample. It does not rebuild expressions, types or
 * control flow into source-shaped output, and it never claims to.
 *
 * The opcode table is not transcribed from memory: it is generated from the
 * local .NET runtime's own System.Reflection.Emit.OpCodes (name, value,
 * operand type), so mnemonic/operand-size pairs are authoritative for the
 * runtime this plugin runs on. Gaps in the table (0x24, 0x77, 0x78, 0xFE08,
 * ...) are unassigned opcodes; hitting one means the stream is corrupt or the
 * table is stale, and decoding stops with an explicit marker instead of
 * guessing a length and desynchronising.
 *
 * Everything here is pure byte parsing: no I/O, no processes, safe for the
 * smoke test layer.
 *
 * @module dsh-rea-restore/lib/cil
 */
import { u8, u16, u32 } from './managed-internals.js';

// ------------------------------------------------------------- opcode table --

/**
 * ECMA-335 Partition III opcodes, sourced from System.Reflection.Emit.OpCodes.
 * Format: opcode value (0x00XX for one-byte, 0xFEYY for two-byte) ->
 * [mnemonic, OperandType]. Values omitted from this table are unassigned.
 */
const OPCODE_DATA = [
  [0x00, 'nop', 'InlineNone'], [0x01, 'break', 'InlineNone'],
  [0x02, 'ldarg.0', 'InlineNone'], [0x03, 'ldarg.1', 'InlineNone'],
  [0x04, 'ldarg.2', 'InlineNone'], [0x05, 'ldarg.3', 'InlineNone'],
  [0x06, 'ldloc.0', 'InlineNone'], [0x07, 'ldloc.1', 'InlineNone'],
  [0x08, 'ldloc.2', 'InlineNone'], [0x09, 'ldloc.3', 'InlineNone'],
  [0x0a, 'stloc.0', 'InlineNone'], [0x0b, 'stloc.1', 'InlineNone'],
  [0x0c, 'stloc.2', 'InlineNone'], [0x0d, 'stloc.3', 'InlineNone'],
  [0x0e, 'ldarg.s', 'ShortInlineVar'], [0x0f, 'ldarga.s', 'ShortInlineVar'],
  [0x10, 'starg.s', 'ShortInlineVar'], [0x11, 'ldloc.s', 'ShortInlineVar'],
  [0x12, 'ldloca.s', 'ShortInlineVar'], [0x13, 'stloc.s', 'ShortInlineVar'],
  [0x14, 'ldnull', 'InlineNone'], [0x15, 'ldc.i4.m1', 'InlineNone'],
  [0x16, 'ldc.i4.0', 'InlineNone'], [0x17, 'ldc.i4.1', 'InlineNone'],
  [0x18, 'ldc.i4.2', 'InlineNone'], [0x19, 'ldc.i4.3', 'InlineNone'],
  [0x1a, 'ldc.i4.4', 'InlineNone'], [0x1b, 'ldc.i4.5', 'InlineNone'],
  [0x1c, 'ldc.i4.6', 'InlineNone'], [0x1d, 'ldc.i4.7', 'InlineNone'],
  [0x1e, 'ldc.i4.8', 'InlineNone'], [0x1f, 'ldc.i4.s', 'ShortInlineI'],
  [0x20, 'ldc.i4', 'InlineI'], [0x21, 'ldc.i8', 'InlineI8'],
  [0x22, 'ldc.r4', 'ShortInlineR'], [0x23, 'ldc.r8', 'InlineR'],
  [0x25, 'dup', 'InlineNone'], [0x26, 'pop', 'InlineNone'],
  [0x27, 'jmp', 'InlineMethod'], [0x28, 'call', 'InlineMethod'],
  [0x29, 'calli', 'InlineSig'], [0x2a, 'ret', 'InlineNone'],
  [0x2b, 'br.s', 'ShortInlineBrTarget'], [0x2c, 'brfalse.s', 'ShortInlineBrTarget'],
  [0x2d, 'brtrue.s', 'ShortInlineBrTarget'], [0x2e, 'beq.s', 'ShortInlineBrTarget'],
  [0x2f, 'bge.s', 'ShortInlineBrTarget'], [0x30, 'bgt.s', 'ShortInlineBrTarget'],
  [0x31, 'ble.s', 'ShortInlineBrTarget'], [0x32, 'blt.s', 'ShortInlineBrTarget'],
  [0x33, 'bne.un.s', 'ShortInlineBrTarget'], [0x34, 'bge.un.s', 'ShortInlineBrTarget'],
  [0x35, 'bgt.un.s', 'ShortInlineBrTarget'], [0x36, 'ble.un.s', 'ShortInlineBrTarget'],
  [0x37, 'blt.un.s', 'ShortInlineBrTarget'],
  [0x38, 'br', 'InlineBrTarget'], [0x39, 'brfalse', 'InlineBrTarget'],
  [0x3a, 'brtrue', 'InlineBrTarget'], [0x3b, 'beq', 'InlineBrTarget'],
  [0x3c, 'bge', 'InlineBrTarget'], [0x3d, 'bgt', 'InlineBrTarget'],
  [0x3e, 'ble', 'InlineBrTarget'], [0x3f, 'blt', 'InlineBrTarget'],
  [0x40, 'bne.un', 'InlineBrTarget'], [0x41, 'bge.un', 'InlineBrTarget'],
  [0x42, 'bgt.un', 'InlineBrTarget'], [0x43, 'ble.un', 'InlineBrTarget'],
  [0x44, 'blt.un', 'InlineBrTarget'], [0x45, 'switch', 'InlineSwitch'],
  [0x46, 'ldind.i1', 'InlineNone'], [0x47, 'ldind.u1', 'InlineNone'],
  [0x48, 'ldind.i2', 'InlineNone'], [0x49, 'ldind.u2', 'InlineNone'],
  [0x4a, 'ldind.i4', 'InlineNone'], [0x4b, 'ldind.u4', 'InlineNone'],
  [0x4c, 'ldind.i8', 'InlineNone'], [0x4d, 'ldind.i', 'InlineNone'],
  [0x4e, 'ldind.r4', 'InlineNone'], [0x4f, 'ldind.r8', 'InlineNone'],
  [0x50, 'ldind.ref', 'InlineNone'], [0x51, 'stind.ref', 'InlineNone'],
  [0x52, 'stind.i1', 'InlineNone'], [0x53, 'stind.i2', 'InlineNone'],
  [0x54, 'stind.i4', 'InlineNone'], [0x55, 'stind.i8', 'InlineNone'],
  [0x56, 'stind.r4', 'InlineNone'], [0x57, 'stind.r8', 'InlineNone'],
  [0x58, 'add', 'InlineNone'], [0x59, 'sub', 'InlineNone'],
  [0x5a, 'mul', 'InlineNone'], [0x5b, 'div', 'InlineNone'],
  [0x5c, 'div.un', 'InlineNone'], [0x5d, 'rem', 'InlineNone'],
  [0x5e, 'rem.un', 'InlineNone'], [0x5f, 'and', 'InlineNone'],
  [0x60, 'or', 'InlineNone'], [0x61, 'xor', 'InlineNone'],
  [0x62, 'shl', 'InlineNone'], [0x63, 'shr', 'InlineNone'],
  [0x64, 'shr.un', 'InlineNone'], [0x65, 'neg', 'InlineNone'],
  [0x66, 'not', 'InlineNone'], [0x67, 'conv.i1', 'InlineNone'],
  [0x68, 'conv.i2', 'InlineNone'], [0x69, 'conv.i4', 'InlineNone'],
  [0x6a, 'conv.i8', 'InlineNone'], [0x6b, 'conv.r4', 'InlineNone'],
  [0x6c, 'conv.r8', 'InlineNone'], [0x6d, 'conv.u4', 'InlineNone'],
  [0x6e, 'conv.u8', 'InlineNone'], [0x6f, 'callvirt', 'InlineMethod'],
  [0x70, 'cpobj', 'InlineType'], [0x71, 'ldobj', 'InlineType'],
  [0x72, 'ldstr', 'InlineString'], [0x73, 'newobj', 'InlineMethod'],
  [0x74, 'castclass', 'InlineType'], [0x75, 'isinst', 'InlineType'],
  [0x76, 'conv.r.un', 'InlineNone'], [0x79, 'unbox', 'InlineType'],
  [0x7a, 'throw', 'InlineNone'], [0x7b, 'ldfld', 'InlineField'],
  [0x7c, 'ldflda', 'InlineField'], [0x7d, 'stfld', 'InlineField'],
  [0x7e, 'ldsfld', 'InlineField'], [0x7f, 'ldsflda', 'InlineField'],
  [0x80, 'stsfld', 'InlineField'], [0x81, 'stobj', 'InlineType'],
  [0x82, 'conv.ovf.i1.un', 'InlineNone'], [0x83, 'conv.ovf.i2.un', 'InlineNone'],
  [0x84, 'conv.ovf.i4.un', 'InlineNone'], [0x85, 'conv.ovf.i8.un', 'InlineNone'],
  [0x86, 'conv.ovf.u1.un', 'InlineNone'], [0x87, 'conv.ovf.u2.un', 'InlineNone'],
  [0x88, 'conv.ovf.u4.un', 'InlineNone'], [0x89, 'conv.ovf.u8.un', 'InlineNone'],
  [0x8a, 'conv.ovf.i.un', 'InlineNone'], [0x8b, 'conv.ovf.u.un', 'InlineNone'],
  [0x8c, 'box', 'InlineType'], [0x8d, 'newarr', 'InlineType'],
  [0x8e, 'ldlen', 'InlineNone'], [0x8f, 'ldelema', 'InlineType'],
  [0x90, 'ldelem.i1', 'InlineNone'], [0x91, 'ldelem.u1', 'InlineNone'],
  [0x92, 'ldelem.i2', 'InlineNone'], [0x93, 'ldelem.u2', 'InlineNone'],
  [0x94, 'ldelem.i4', 'InlineNone'], [0x95, 'ldelem.u4', 'InlineNone'],
  [0x96, 'ldelem.i8', 'InlineNone'], [0x97, 'ldelem.i', 'InlineNone'],
  [0x98, 'ldelem.r4', 'InlineNone'], [0x99, 'ldelem.r8', 'InlineNone'],
  [0x9a, 'ldelem.ref', 'InlineNone'], [0x9b, 'stelem.i', 'InlineNone'],
  [0x9c, 'stelem.i1', 'InlineNone'], [0x9d, 'stelem.i2', 'InlineNone'],
  [0x9e, 'stelem.i4', 'InlineNone'], [0x9f, 'stelem.i8', 'InlineNone'],
  [0xa0, 'stelem.r4', 'InlineNone'], [0xa1, 'stelem.r8', 'InlineNone'],
  [0xa2, 'stelem.ref', 'InlineNone'], [0xa3, 'ldelem', 'InlineType'],
  [0xa4, 'stelem', 'InlineType'], [0xa5, 'unbox.any', 'InlineType'],
  [0xb3, 'conv.ovf.i1', 'InlineNone'], [0xb4, 'conv.ovf.u1', 'InlineNone'],
  [0xb5, 'conv.ovf.i2', 'InlineNone'], [0xb6, 'conv.ovf.u2', 'InlineNone'],
  [0xb7, 'conv.ovf.i4', 'InlineNone'], [0xb8, 'conv.ovf.u4', 'InlineNone'],
  [0xb9, 'conv.ovf.i8', 'InlineNone'], [0xba, 'conv.ovf.u8', 'InlineNone'],
  [0xc2, 'refanyval', 'InlineType'], [0xc3, 'ckfinite', 'InlineNone'],
  [0xc6, 'mkrefany', 'InlineType'], [0xd0, 'ldtoken', 'InlineTok'],
  [0xd1, 'conv.u2', 'InlineNone'], [0xd2, 'conv.u1', 'InlineNone'],
  [0xd3, 'conv.i', 'InlineNone'], [0xd4, 'conv.ovf.i', 'InlineNone'],
  [0xd5, 'conv.ovf.u', 'InlineNone'], [0xd6, 'add.ovf', 'InlineNone'],
  [0xd7, 'add.ovf.un', 'InlineNone'], [0xd8, 'mul.ovf', 'InlineNone'],
  [0xd9, 'mul.ovf.un', 'InlineNone'], [0xda, 'sub.ovf', 'InlineNone'],
  [0xdb, 'sub.ovf.un', 'InlineNone'], [0xdc, 'endfinally', 'InlineNone'],
  [0xdd, 'leave', 'InlineBrTarget'], [0xde, 'leave.s', 'ShortInlineBrTarget'],
  [0xdf, 'stind.i', 'InlineNone'], [0xe0, 'conv.u', 'InlineNone'],
  // 0xf8-0xff are internal prefix markers, never valid instruction starts.
  [0xfe00, 'arglist', 'InlineNone'], [0xfe01, 'ceq', 'InlineNone'],
  [0xfe02, 'cgt', 'InlineNone'], [0xfe03, 'cgt.un', 'InlineNone'],
  [0xfe04, 'clt', 'InlineNone'], [0xfe05, 'clt.un', 'InlineNone'],
  [0xfe06, 'ldftn', 'InlineMethod'], [0xfe07, 'ldvirtftn', 'InlineMethod'],
  [0xfe09, 'ldarg', 'InlineVar'], [0xfe0a, 'ldarga', 'InlineVar'],
  [0xfe0b, 'starg', 'InlineVar'], [0xfe0c, 'ldloc', 'InlineVar'],
  [0xfe0d, 'ldloca', 'InlineVar'], [0xfe0e, 'stloc', 'InlineVar'],
  [0xfe0f, 'localloc', 'InlineNone'], [0xfe11, 'endfilter', 'InlineNone'],
  [0xfe12, 'unaligned.', 'ShortInlineI'], [0xfe13, 'volatile.', 'InlineNone'],
  [0xfe14, 'tail.', 'InlineNone'], [0xfe15, 'initobj', 'InlineType'],
  [0xfe16, 'constrained.', 'InlineType'], [0xfe17, 'cpblk', 'InlineNone'],
  [0xfe18, 'initblk', 'InlineNone'], [0xfe1a, 'rethrow', 'InlineNone'],
  [0xfe1c, 'sizeof', 'InlineType'], [0xfe1d, 'refanytype', 'InlineNone'],
  [0xfe1e, 'readonly.', 'InlineNone'],
];

const OPCODES = new Map(OPCODE_DATA.map(([value, name, operand]) => [value, { name, operand }]));
export { OPCODES };

const OPERAND_KIND = {
  InlineNone: 'none',
  ShortInlineVar: 'u8',
  InlineVar: 'u16',
  ShortInlineI: 'i8',
  InlineI: 'i32',
  InlineI8: 'i64',
  ShortInlineR: 'f32',
  InlineR: 'f64',
  ShortInlineBrTarget: 'br8',
  InlineBrTarget: 'br32',
  InlineSwitch: 'switch',
  InlineMethod: 'tok',
  InlineSig: 'tok',
  InlineString: 'tok',
  InlineType: 'tok',
  InlineField: 'tok',
  InlineTok: 'tok',
};

function opcodeAt(code, at) {
  const first = u8(code, at);
  if (first !== 0xfe) return { value: first, length: 1 };
  if (at + 1 >= code.length) return { value: null, length: 1 };
  return { value: 0xfe00 | u8(code, at + 1), length: 2 };
}

// ------------------------------------------------------------ method bodies --

const MAX_EH_CLAUSES = 256;
const COR_ILEXCEPTION_CLAUSE_FILTER = 0x0001;
const COR_ILEXCEPTION_CLAUSE_FINALLY = 0x0002;
const COR_ILEXCEPTION_CLAUSE_FAULT = 0x0004;

/**
 * Parse one method body header (ECMA-335 II.25.4) and its exception clauses.
 *
 * @returns {object} `{ kind, maxStack, localsToken, codeAt, codeLength, eh,
 *   truncated, error? }` — `kind` is 'tiny' | 'fat' | null. Never throws on
 *   malformed input; degraded results carry `error` and safe bounds.
 */
export function parseMethodBody(bytes, at, { codeCap = 64 * 1024 } = {}) {
  if (at < 0 || at >= bytes.length) {
    return { kind: null, maxStack: 0, localsToken: 0, codeAt: 0, codeLength: 0, eh: [], truncated: false, error: 'method RVA outside the mapped image' };
  }
  const first = u8(bytes, at);
  let kind = null;
  let headerBytes = 0;
  let maxStack = 8; // tiny bodies imply maxstack 8
  let localsToken = 0;
  let codeLength = 0;
  let moreSects = false;
  if ((first & 0x03) === 0x02) {
    kind = 'tiny';
    headerBytes = 1;
    codeLength = first >> 2;
  } else if ((first & 0x03) === 0x03) {
    kind = 'fat';
    if (at + 12 > bytes.length) {
      return { kind: 'fat', maxStack: 0, localsToken: 0, codeAt: 0, codeLength: 0, eh: [], truncated: false, error: 'fat header is truncated' };
    }
    const flagsSize = u16(bytes, at);
    const headerDwords = (flagsSize >> 12) & 0xfff;
    headerBytes = headerDwords * 4;
    maxStack = u16(bytes, at + 2);
    codeLength = u32(bytes, at + 4);
    localsToken = u32(bytes, at + 8);
    moreSects = (flagsSize & 0x08) !== 0;
  } else {
    return { kind: null, maxStack: 0, localsToken: 0, codeAt: 0, codeLength: 0, eh: [], truncated: false, error: `unknown method body header 0x${first.toString(16)}` };
  }
  const codeAt = at + headerBytes;
  let truncated = false;
  if (codeAt + codeLength > bytes.length) {
    codeLength = Math.max(0, bytes.length - codeAt);
    truncated = true;
  }
  if (codeLength > codeCap) {
    codeLength = codeCap;
    truncated = true;
  }

  const eh = [];
  if (moreSects && !truncated) {
    // The EH section follows the code, padded to a 4-byte boundary. Its header
    // carries the section's byte size (1 byte for the small format, 3 bytes
    // for fat), so the clause count is derived from that size - the count is
    // not stored in the flags byte. The layouts are the packed byte streams of
    // ECMA-335 II.25.4.5 (12-byte small / 24-byte fat clauses), pinned against
    // ilasm output in test/managed.test.js.
    let sectionAt = codeAt + codeLength;
    sectionAt = (sectionAt + 3) & ~3;
    if (sectionAt + 4 <= bytes.length) {
      const sectionByte = u8(bytes, sectionAt);
      const fat = (sectionByte & 0x40) !== 0;
      const clauseSize = fat ? 24 : 12;
      const dataSize = fat ? u32(bytes, sectionAt) >>> 8 : u8(bytes, sectionAt + 1);
      let count = dataSize >= 4 ? Math.floor((dataSize - 4) / clauseSize) : 0;
      if (count > MAX_EH_CLAUSES) {
        count = MAX_EH_CLAUSES;
        truncated = true;
      }
      let clauseAt = sectionAt + 4;
      for (let i = 0; i < count; i += 1) {
        if (clauseAt + clauseSize > bytes.length) { truncated = true; break; }
        const flags = fat ? u32(bytes, clauseAt) : u16(bytes, clauseAt);
        const tryOffset = fat ? u32(bytes, clauseAt + 4) : u16(bytes, clauseAt + 2);
        const tryLength = fat ? u32(bytes, clauseAt + 8) : u8(bytes, clauseAt + 4);
        const handlerOffset = fat ? u32(bytes, clauseAt + 12) : u16(bytes, clauseAt + 5);
        const handlerLength = fat ? u32(bytes, clauseAt + 16) : u8(bytes, clauseAt + 7);
        const classToken = fat ? u32(bytes, clauseAt + 20) : u32(bytes, clauseAt + 8);
        const label = (flags & COR_ILEXCEPTION_CLAUSE_FILTER) !== 0 ? 'filter'
          : (flags & COR_ILEXCEPTION_CLAUSE_FINALLY) !== 0 ? 'finally'
            : (flags & COR_ILEXCEPTION_CLAUSE_FAULT) !== 0 ? 'fault' : 'catch';
        eh.push({ kind: label, flags, tryOffset, tryLength, handlerOffset, handlerLength, classToken });
        clauseAt += clauseSize;
      }
    }
  }
  return { kind, maxStack, localsToken, codeAt, codeLength, eh, truncated };
}

// ----------------------------------------------------------- disassembling --

const SWITCH_TARGET_RENDER_CAP = 16;

/**
 * Decode a CIL code stream into instructions plus a behaviour summary.
 *
 * @param {Buffer} code the raw IL bytes of one method body
 * @param {((token: number) => {kind: string, text: string}|null)|null} resolveToken
 *   metadata-token resolver built by the caller (see lib/managed.js)
 * @param {{instrCap?: number}} [options]
 * @returns {object} `{ instructions, summary, truncated }` — instructions are
 *   `{ o, n, t?, tg?, tgs? }`; the summary buckets resolved tokens into
 *   `apis` (methods), `strings`, `fields`, `types` and counts branches.
 */
export function disassembleIl(code, resolveToken, { instrCap = 400 } = {}) {
  const instructions = [];
  const apis = new Set();
  const strings = new Set();
  const fields = new Set();
  const types = new Set();
  let branches = 0;
  let calls = 0;
  let unknown = 0;
  let truncated = false;

  const addToken = (token) => {
    const resolved = resolveToken ? resolveToken(token) : null;
    if (!resolved) return `token 0x${token.toString(16).padStart(8, '0')}`;
    if (resolved.kind === 'method' || resolved.kind === 'sig') apis.add(resolved.text);
    else if (resolved.kind === 'field') fields.add(resolved.text);
    else if (resolved.kind === 'type') types.add(resolved.text);
    else if (resolved.kind === 'string') strings.add(resolved.text);
    return resolved.text;
  };

  let at = 0;
  while (at < code.length) {
    if (instructions.length >= instrCap) { truncated = true; break; }
    const offset = at;
    const { value, length } = opcodeAt(code, at);
    if (value === null) { unknown += 1; truncated = true; break; }
    const entry = OPCODES.get(value);
    if (!entry) {
      instructions.push({ o: offset, n: `unknown 0x${value.toString(16)}` });
      unknown += 1;
      // Unknown opcode: operand size is unknowable, so continuing would
      // desynchronise the stream. Stop with an explicit marker.
      at = code.length;
      truncated = true;
      break;
    }
    at += length;
    const kind = OPERAND_KIND[entry.operand] ?? 'none';
    const instruction = { o: offset, n: entry.name };
    if (kind === 'u8') {
      if (at + 1 > code.length) { truncated = true; break; }
      instruction.t = u8(code, at);
      at += 1;
    } else if (kind === 'u16') {
      if (at + 2 > code.length) { truncated = true; break; }
      instruction.t = u16(code, at);
      at += 2;
    } else if (kind === 'i8') {
      if (at + 1 > code.length) { truncated = true; break; }
      instruction.t = code.readInt8(at);
      at += 1;
    } else if (kind === 'i32') {
      if (at + 4 > code.length) { truncated = true; break; }
      instruction.t = code.readInt32LE(at);
      at += 4;
    } else if (kind === 'i64') {
      if (at + 8 > code.length) { truncated = true; break; }
      instruction.t = code.readBigInt64LE(at).toString();
      at += 8;
    } else if (kind === 'f32') {
      if (at + 4 > code.length) { truncated = true; break; }
      instruction.t = code.readFloatLE(at);
      at += 4;
    } else if (kind === 'f64') {
      if (at + 8 > code.length) { truncated = true; break; }
      instruction.t = code.readDoubleLE(at);
      at += 8;
    } else if (kind === 'br8') {
      if (at + 1 > code.length) { truncated = true; break; }
      const delta = code.readInt8(at);
      at += 1;
      instruction.tg = at + delta; // ECMA III.1.2: offset from the next instruction
      branches += 1;
    } else if (kind === 'br32') {
      if (at + 4 > code.length) { truncated = true; break; }
      const delta = code.readInt32LE(at);
      at += 4;
      instruction.tg = at + delta;
      branches += 1;
    } else if (kind === 'switch') {
      if (at + 4 > code.length) { truncated = true; break; }
      const count = code.readUInt32LE(at);
      at += 4;
      if (at + count * 4 > code.length) { truncated = true; break; }
      const tableEnd = at + count * 4;
      const targets = [];
      for (let i = 0; i < count; i += 1) targets.push(tableEnd + code.readInt32LE(at + i * 4));
      at = tableEnd;
      instruction.tgs = targets;
      branches += 1;
    } else if (kind === 'tok') {
      if (at + 4 > code.length) { truncated = true; break; }
      const token = code.readUInt32LE(at);
      at += 4;
      instruction.t = addToken(token);
      if (entry.operand === 'InlineMethod' || entry.operand === 'InlineSig') calls += 1;
    }
    // Render switch targets compactly: the full table stays in `tgs` only
    // when small, otherwise the summary notes the count.
    if (instruction.tgs && instruction.tgs.length > SWITCH_TARGET_RENDER_CAP) {
      instruction.t = `${instruction.tgs.length} targets`;
      delete instruction.tgs;
    }
    instructions.push(instruction);
  }
  return {
    instructions,
    truncated,
    summary: {
      apis: [...apis].sort(),
      strings: [...strings].sort(),
      fields: [...fields].sort(),
      types: [...types].sort(),
      branches,
      calls,
      unknown,
    },
  };
}

// ------------------------------------------------------------ user strings --

/**
 * Decode one length-prefixed UTF-16LE string from the #US heap (ECMA-335
 * II.24.2.4). `at` is the byte offset stored in an ldstr token; the encoded
 * length includes one trailing flag byte that is not part of the text.
 *
 * @returns {{text: string, bytes: number}|null} `bytes` is the full encoded
 *   length (prefix + payload), so heap walks can advance without re-decoding.
 */
export function decodeUserStringAt(buffer, at, maxChars = 128) {
  if (at === undefined || at === null || at < 0 || at >= buffer.length) return null;
  const first = u8(buffer, at);
  let length;
  let header;
  if (first < 0x80) { length = first; header = 1; } else if (first < 0xc0) {
    if (at + 2 > buffer.length) return null;
    length = ((first & 0x3f) << 8) | u8(buffer, at + 1);
    header = 2;
  } else if (first < 0xe0) {
    if (at + 4 > buffer.length) return null;
    length = ((first & 0x1f) << 24) | (u8(buffer, at + 1) << 16) | (u8(buffer, at + 2) << 8) | u8(buffer, at + 3);
    header = 4;
  } else return null;
  if (length <= 1) return { text: '', bytes: header + Math.max(0, length) };
  const charBytes = Math.min((length - 1) & ~1, maxChars * 2);
  if (at + header + charBytes > buffer.length) return null;
  return { text: buffer.toString('utf16le', at + header, at + header + charBytes), bytes: header + length };
}
