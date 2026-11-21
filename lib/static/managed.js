/**
 * .NET managed-assembly manifest, parsed locally from PE bytes.
 *
 * `structure.js` already answers "is this managed" from data directory 14; this
 * module answers "what is inside it": the BSJB metadata root, the stream
 * directory, the heaps, and a capped walk of the #~ tables (Module, TypeDef,
 * MethodDef, Assembly, ManifestResource).
 *
 * With `cil: true` the walk additionally disassembles a capped selection of
 * method bodies (lib/cil.js): opcode/operand listings, metadata tokens
 * resolved to type/method/field names, user strings, and the assembly's
 * P/Invoke surface (ImplMap). This is instruction-level evidence, not a
 * decompiler: it does not rebuild expressions or control flow into
 * source-shaped output.
 *
 * Honesty boundary: the default output is a metadata manifest, never program
 * logic; the optional CIL layer lists instructions and referenced names but
 * does not reconstruct semantics. Obfuscated assemblies still parse (renamed
 * types/methods are listed exactly as the tables carry them);
 * NativeAOT / ReadyToRun single-file publishes carry no usable #~ stream and
 * surface as `metadata: null` with a note. Deep CIL logic recovery still
 * belongs to the upstream REA `inspect_managed_*` tools.
 *
 * Measured header quirk, pinned by test/managed.test.js — do not "fix" it back
 * to the textbook layout: ECMA-335 sizes IMAGE_COR20_HEADER at 64 bytes with
 * StrongNameSignature at +24. The measured corpora disagree: System.Data.dll
 * (4.8, CLR directory size 72) has cb=72 and carries the strong-name RVA/size
 * at +32/+36 — the 256-byte signature sits immediately before the metadata
 * root, so `strongName.rva + strongName.size == header.metadataRva` holds,
 * while the +24 slot holds unrelated values. The unsigned ilasm fixture has
 * zeros in both slots. This module reads +32/+36; a future corpus with cb=64
 * would need a size-branched layout — implement that on evidence, not ahead
 * of it.
 *
 * @module dsh-rea/lib/managed
 */
import { rvaToOffset } from './managed-internals.js';
import { decodeUserStringAt, disassembleIl, parseMethodBody } from './cil.js';
import { index, u16, u32, u8 } from './managed-internals.js';

// ------------------------------------------------------------- table schema --
//
// ECMA-335 II.22 table numbers and II.24 row layouts. Row widths depend on the
// row counts of neighbouring tables, so every table's layout must be known to
// locate any table behind it — there is no shortcut to MethodDef or Assembly.

const T_MODULE = 0x00;
const T_TYPEREF = 0x01;
const T_TYPEDEF = 0x02;
const T_FIELDPTR = 0x03;
const T_FIELD = 0x04;
const T_METHODPTR = 0x05;
const T_METHODDEF = 0x06;
const T_MEMBERREF = 0x0a;
const T_MODULEREF = 0x1a;
const T_TYPESPEC = 0x1b;
const T_IMPLMAP = 0x1c;
const T_ASSEMBLY = 0x20;
const T_METHODSPEC = 0x2b;
const T_MANIFESTRESOURCE = 0x28;

const TABLE_NAMES = [
  'Module', 'TypeRef', 'TypeDef', 'FieldPtr', 'Field', 'MethodPtr', 'MethodDef',
  'ParamPtr', 'Param', 'InterfaceImpl', 'MemberRef', 'Constant', 'CustomAttribute',
  'FieldMarshal', 'DeclSecurity', 'ClassLayout', 'FieldLayout', 'StandAloneSig',
  'EventMap', 'EventPtr', 'Event', 'PropertyMap', 'PropertyPtr', 'Property',
  'MethodSemantics', 'MethodImpl', 'ModuleRef', 'TypeSpec', 'ImplMap', 'FieldRVA',
  'EncLog', 'EncMap', 'Assembly', 'AssemblyProcessor', 'AssemblyOS', 'AssemblyRef',
  'AssemblyRefProcessor', 'AssemblyRefOS', 'File', 'ExportedType', 'ManifestResource',
  'NestedClass', 'GenericParam', 'MethodSpec', 'GenericParamConstraint',
];

/**
 * Coded-index tag sets (ECMA-335 II.24.2.6) with their tag sizes in bits.
 *
 * The tag size is normally ceil(log2(tableCount)), but CustomAttributeType is
 * the measured exception: three tag slots (MethodDef, MemberRef, unused) would
 * give 2 bits, yet System.Data.dll only reconciles when its index is sized as
 * 3 bits (threshold 2^13) — with 2 bits every table behind CustomAttribute
 * drifts by 2 bytes × 2308 rows and the Assembly table lands on garbage.
 * test/managed.test.js pins this via the System.Data corpus.
 */
const CODED_INDEXES = {
  TypeDefOrRef: { tables: [0x02, 0x01, 0x1b], bits: 2 },
  HasConstant: { tables: [0x04, 0x08, 0x17], bits: 2 },
  HasCustomAttribute: { tables: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b], bits: 5 },
  HasFieldMarshal: { tables: [0x04, 0x08], bits: 1 },
  HasDeclSecurity: { tables: [0x02, 0x06, 0x20], bits: 2 },
  MemberRefParent: { tables: [0x02, 0x01, 0x1b, 0x1a, 0x06, 0x1b], bits: 3 },
  HasSemantics: { tables: [0x14, 0x17], bits: 1 },
  MethodDefOrRef: { tables: [0x06, 0x0a], bits: 1 },
  MemberForwarded: { tables: [0x04, 0x06], bits: 1 },
  Implementation: { tables: [0x26, 0x23, 0x27], bits: 2 },
  CustomAttributeType: { tables: [0x06, 0x0a, 0x0a], bits: 3 },
  ResolutionScope: { tables: [0x00, 0x1a, 0x23, 0x01], bits: 2 },
  TypeOrMethodDef: { tables: [0x02, 0x06], bits: 1 },
};

const S = (name) => ({ c: name });
const T = (table) => ({ t: table });

const SCHEMAS = [
  /* 0x00 Module */ ['u16', 'str', 'guid', 'guid', 'guid'],
  /* 0x01 TypeRef */ [S('ResolutionScope'), 'str', 'str'],
  /* 0x02 TypeDef */ ['u32', 'str', 'str', S('TypeDefOrRef'), T(0x04), T(0x06)],
  /* 0x03 FieldPtr */ [T(0x04)],
  /* 0x04 Field */ ['u16', 'str', 'blob'],
  /* 0x05 MethodPtr */ [T(0x06)],
  /* 0x06 MethodDef */ ['u32', 'u16', 'u16', 'str', 'blob', T(0x08)],
  /* 0x07 ParamPtr */ [T(0x08)],
  /* 0x08 Param */ ['u16', 'u16', 'str'],
  /* 0x09 InterfaceImpl */ [T(0x02), S('TypeDefOrRef')],
  /* 0x0A MemberRef */ [S('MemberRefParent'), 'str', 'blob'],
  /* 0x0B Constant */ ['u8', 'u8', S('HasConstant'), 'blob'],
  /* 0x0C CustomAttribute */ [S('HasCustomAttribute'), S('CustomAttributeType'), 'blob'],
  /* 0x0D FieldMarshal */ [S('HasFieldMarshal'), 'blob'],
  /* 0x0E DeclSecurity */ ['u16', S('HasDeclSecurity'), 'blob'],
  /* 0x0F ClassLayout */ ['u16', 'u32', T(0x02)],
  /* 0x10 FieldLayout */ ['u32', T(0x04)],
  /* 0x11 StandAloneSig */ ['blob'],
  /* 0x12 EventMap */ [T(0x02), T(0x14)],
  /* 0x13 EventPtr */ [T(0x14)],
  /* 0x14 Event */ ['u16', 'str', S('TypeDefOrRef')],
  /* 0x15 PropertyMap */ [T(0x02), T(0x17)],
  /* 0x16 PropertyPtr */ [T(0x17)],
  /* 0x17 Property */ ['u16', 'str', 'blob'],
  /* 0x18 MethodSemantics */ ['u16', T(0x06), S('HasSemantics')],
  /* 0x19 MethodImpl */ [T(0x02), S('MethodDefOrRef'), S('MethodDefOrRef')],
  /* 0x1A ModuleRef */ ['str'],
  /* 0x1B TypeSpec */ ['blob'],
  /* 0x1C ImplMap */ ['u16', S('MemberForwarded'), 'str', T(0x1a)],
  /* 0x1D FieldRVA */ ['u32', T(0x04)],
  /* 0x1E EncLog */ ['u32', 'u32'],
  /* 0x1F EncMap */ ['u32'],
  /* 0x20 Assembly */ ['u32', 'u16', 'u16', 'u16', 'u16', 'u32', 'blob', 'str', 'str'],
  /* 0x21 AssemblyProcessor */ ['u32'],
  /* 0x22 AssemblyOS */ ['u32', 'u32', 'u32'],
  /* 0x23 AssemblyRef */ ['u16', 'u16', 'u16', 'u16', 'u32', 'blob', 'str', 'str', 'blob'],
  /* 0x24 AssemblyRefProcessor */ ['u32', T(0x23)],
  /* 0x25 AssemblyRefOS */ ['u32', 'u32', 'u32', T(0x23)],
  /* 0x26 File */ ['u32', 'str', 'blob'],
  /* 0x27 ExportedType */ ['u32', 'u32', 'str', 'str', S('Implementation')],
  /* 0x28 ManifestResource */ ['u32', 'u32', 'str', S('Implementation')],
  /* 0x29 NestedClass */ [T(0x02), T(0x02)],
  /* 0x2A GenericParam */ ['u16', 'u16', S('TypeOrMethodDef'), 'str'],
  /* 0x2B MethodSpec */ [S('MethodDefOrRef'), 'blob'],
  /* 0x2C GenericParamConstraint */ [T(0x2a), S('TypeDefOrRef')],
];

// ----------------------------------------------------------------- layout ----

/**
 * Column widths depend on row counts, so a "context" carries the #~ header
 * facts and every width decision reads from it.
 */
function makeContext(rowCounts, heapSizes) {
  const rowCount = (table) => rowCounts.get(table) ?? 0;
  const ctx = {
    rowCount,
    strings: (heapSizes & 0x01) !== 0 ? 4 : 2,
    guids: (heapSizes & 0x02) !== 0 ? 4 : 2,
    blobs: (heapSizes & 0x04) !== 0 ? 4 : 2,
  };
  ctx.columnWidth = (column) => {
    if (typeof column === 'string') {
      if (column === 'u8') return 1;
      if (column === 'u16') return 2;
      if (column === 'u32') return 4;
      return ctx[column === 'str' ? 'strings' : column === 'guid' ? 'guids' : 'blobs'];
    }
    if (column.t !== undefined) return rowCount(column.t) < 65536 ? 2 : 4;
    const { tables, bits } = CODED_INDEXES[column.c];
    let widest = 0;
    for (const table of tables) widest = Math.max(widest, rowCount(table));
    return widest < 2 ** (16 - bits) ? 2 : 4;
  };
  return ctx;
}

/** Per-table column list [{kind, offset, width}] plus the row width. */
function tableLayout(schema, ctx) {
  let offset = 0;
  const columns = schema.map((column) => {
    const kind = typeof column === 'string' ? column : (column.t !== undefined ? 'idx' : 'coded');
    const width = ctx.columnWidth(column);
    const entry = { kind, offset, width };
    offset += width;
    return entry;
  });
  return { columns, width: offset };
}

// ------------------------------------------------------------------ parse ----

/**
 * Parse the .NET metadata manifest of a PE.
 *
 * @param {Buffer|Uint8Array} bytes the whole file
 * @param {object|null} layout a `readPeLayout()` result
 * @param {object} [options]
 * @param {number} [options.typeCap] maximum TypeDef rows listed (default 64)
 * @param {number} [options.methodCapPerType] maximum method names per type (default 32)
 * @param {number} [options.resourceCap] maximum ManifestResource rows listed (default 16)
 * @param {boolean} [options.cil] also disassemble method bodies (default false)
 * @param {number} [options.cilMethodCap] maximum method bodies disassembled (default 48)
 * @param {number} [options.cilInstrCap] maximum instructions kept per method (default 400)
 * @param {number} [options.cilPinvokeCap] maximum ImplMap entries listed (default 64)
 * @returns {object|null} null for a non-PE or a PE without a CLR directory;
 *   otherwise `{ managed: true, present: true, header, metadata, module,
 *   assembly, types, resources, tableRows, caps, cil?, note? }`. Never throws on
 *   malformed metadata — degraded results carry a `note`.
 */
export function parseManaged(bytes, layout, { typeCap = 64, methodCapPerType = 32, resourceCap = 16, cil = false, cilMethodCap = 48, cilInstrCap = 400, cilPinvokeCap = 64 } = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const directory = layout?.dataDirs?.[14];
  if (!directory || directory.rva === 0 || directory.size === 0) return null;

  const base = { managed: true, present: true, rva: directory.rva, size: directory.size };
  const headerAt = rvaToOffset(layout, directory.rva);
  if (headerAt === null || headerAt + 40 > buffer.length) {
    return { ...base, header: null, metadata: null, note: 'CLR header is outside the mapped image' };
  }
  const header = {
    rva: directory.rva,
    size: directory.size,
    cb: u32(buffer, headerAt),
    runtime: `${u16(buffer, headerAt + 4)}.${u16(buffer, headerAt + 6)}`,
    metadataRva: u32(buffer, headerAt + 8),
    metadataSize: u32(buffer, headerAt + 12),
    flags: u32(buffer, headerAt + 16),
    entryPointToken: u32(buffer, headerAt + 20),
    // Measured layout (+32/+36), NOT the canonical +24 — see the module header
    // comment. test/managed.test.js pins this against System.Data.dll.
    strongName: { rva: u32(buffer, headerAt + 32), size: u32(buffer, headerAt + 36) },
  };
  const result = { ...base, header, strongName: header.strongName, metadata: null, caps: { typeCap, methodCapPerType, resourceCap, cil, cilMethodCap, cilInstrCap, cilPinvokeCap } };

  const mdAt = rvaToOffset(layout, header.metadataRva);
  if (mdAt === null || mdAt + 16 > buffer.length || buffer.toString('latin1', mdAt, mdAt + 4) !== 'BSJB') {
    result.note = 'metadata root missing or not BSJB';
    return result;
  }

  try {
    return parseMetadata(buffer, layout, mdAt, header, result, { typeCap, methodCapPerType, resourceCap, cil, cilMethodCap, cilInstrCap, cilPinvokeCap });
  } catch (error) {
    result.note = `metadata walk stopped: ${error?.message ?? error}`;
    return result;
  }
}

function parseMetadata(buffer, layout, mdAt, header, result, caps) {
  // ---- BSJB root and stream directory -------------------------------------
  const versionLength = u32(buffer, mdAt + 12);
  const versionAt = mdAt + 16;
  const version = buffer.toString('latin1', versionAt, Math.min(versionAt + versionLength, buffer.length)).replace(/\0+$/, '');
  let cursor = versionAt + versionLength;
  const streams = {};
  const streamAt = {};
  if (cursor + 4 <= buffer.length) {
    const streamCount = u16(buffer, cursor + 2);
    cursor += 4;
    for (let i = 0; i < streamCount && cursor + 8 <= buffer.length; i += 1) {
      const offset = u32(buffer, cursor);
      const size = u32(buffer, cursor + 4);
      cursor += 8;
      const nameStart = cursor;
      while (cursor < buffer.length && buffer[cursor] !== 0) cursor += 1;
      const name = buffer.toString('latin1', nameStart, cursor);
      // Names are NUL-terminated and the directory continues on a 4-byte
      // boundary relative to the metadata root.
      cursor = mdAt + ((cursor + 1 - mdAt + 3) & ~3);
      streams[name] = size;
      streamAt[name] = mdAt + offset;
    }
  }
  const metadata = { rva: header.metadataRva, size: header.metadataSize, version, streams };
  result.metadata = metadata;
  metadata.usStrings = streams['#US'] !== undefined ? readUsStrings(buffer, streamAt['#US'], streams['#US']) : [];

  // ---- #~ tables header -----------------------------------------------------
  const tablesName = streams['#~'] !== undefined ? '#~' : (streams['#-'] !== undefined ? '#-' : null);
  if (tablesName === null) {
    result.note = 'no #~ tables stream (NativeAOT/ReadyToRun or EnC metadata)';
    return result;
  }
  if (tablesName === '#-') {
    result.note = 'EnC (#-) metadata: uncompressed tables are not walked';
    return result;
  }
  const tablesAt = streamAt[tablesName];
  if (tablesAt === undefined || tablesAt + 24 > buffer.length) {
    result.note = 'tables stream is outside the mapped image';
    return result;
  }
  // #~ header: +4/+5 are u8 Major/Minor — reading them as one u16 would shift
  // Valid to +10 and Rows to +26 (the prototype's actual bug). +7 is reserved
  // and varies between builds (0 on ilasm output, 16 on System.Data.dll); it
  // is not part of the layout, and Rows at +24 holds on both corpora.
  const heapSizes = u8(buffer, tablesAt + 6);
  const valid = buffer.readBigUInt64LE(tablesAt + 8);
  const rowCounts = new Map();
  for (let table = 0; table < 64; table += 1) {
    if (((valid >> BigInt(table)) & 1n) === 0n) continue;
    const at = tablesAt + 24 + rowCounts.size * 4;
    if (at + 4 > buffer.length) {
      result.note = 'row-count array is truncated';
      return result;
    }
    rowCounts.set(table, u32(buffer, at));
  }

  const ctx = makeContext(rowCounts, heapSizes);
  const stringsAt = streamAt['#Strings'];
  const blobsAt = streamAt['#Blob'];
  const readString = (idx) => {
    if (stringsAt === undefined || idx === 0) return '';
    const start = stringsAt + idx;
    if (start < 0 || start >= buffer.length) return '';
    const stop = Math.min(start + 1024, buffer.length);
    let end = start;
    while (end < stop && buffer[end] !== 0) end += 1;
    return buffer.toString('utf8', start, end);
  };
  const blobLength = (idx) => {
    if (blobsAt === undefined || idx === 0) return 0;
    const at = blobsAt + idx;
    if (at >= buffer.length) return 0;
    const first = u8(buffer, at);
    if (first < 0x80) return first;
    if (first < 0xc0) return at + 1 < buffer.length ? ((first & 0x3f) << 8) | u8(buffer, at + 1) : 0;
    return at + 3 < buffer.length
      ? ((first & 0x1f) << 24) | (u8(buffer, at + 1) << 16) | (u8(buffer, at + 2) << 8) | u8(buffer, at + 3)
      : 0;
  };

  // ---- locate every present table ------------------------------------------
  const offsets = new Map();
  const layouts = new Map();
  let cursor2 = tablesAt + 24 + rowCounts.size * 4;
  for (let table = 0; table < 64; table += 1) {
    if (!rowCounts.has(table)) continue;
    const schema = SCHEMAS[table];
    if (!schema) {
      result.note = `table 0x${table.toString(16)} is not in the local schema; tables behind it are not located`;
      break;
    }
    const lay = tableLayout(schema, ctx);
    layouts.set(table, lay);
    offsets.set(table, cursor2);
    cursor2 += lay.width * rowCounts.get(table);
  }

  const field = (table, row, column) => {
    const lay = layouts.get(table);
    const at = offsets.get(table) + row * lay.width + lay.columns[column].offset;
    if (at + lay.columns[column].width > buffer.length) return 0;
    return index(buffer, at, lay.columns[column].width);
  };

  // ---- Module ---------------------------------------------------------------
  if (offsets.has(T_MODULE)) {
    const module = { name: readString(field(T_MODULE, 0, 1)), mvidIndex: field(T_MODULE, 0, 2) };
    result.module = module;
    result.moduleName = module.name;
  }

  // ---- Assembly ---------------------------------------------------------------
  if (offsets.has(T_ASSEMBLY)) {
    result.assembly = {
      name: readString(field(T_ASSEMBLY, 0, 7)),
      version: `${field(T_ASSEMBLY, 0, 1)}.${field(T_ASSEMBLY, 0, 2)}.${field(T_ASSEMBLY, 0, 3)}.${field(T_ASSEMBLY, 0, 4)}`,
      culture: readString(field(T_ASSEMBLY, 0, 8)),
      hashAlgId: field(T_ASSEMBLY, 0, 0),
      flags: field(T_ASSEMBLY, 0, 5),
      publicKeyBytes: blobLength(field(T_ASSEMBLY, 0, 6)),
    };
    result.assemblyName = result.assembly.name;
  }

  // ---- TypeDef / MethodDef ----------------------------------------------------
  const methodDefTotal = rowCounts.get(T_METHODDEF) ?? 0;
  result.methodDefTotal = methodDefTotal;
  if (offsets.has(T_TYPEDEF) && offsets.has(T_METHODDEF)) {
    const total = rowCounts.get(T_TYPEDEF) ?? 0;
    const shown = Math.min(total, caps.typeCap);
    const types = [];
    let methodsTruncated = false;
    const useMethodPtr = offsets.has(T_METHODPTR) && (rowCounts.get(T_METHODPTR) ?? 0) > 0;
    for (let row = 0; row < shown; row += 1) {
      const name = readString(field(T_TYPEDEF, row, 1));
      const namespace = readString(field(T_TYPEDEF, row, 2));
      const flags = field(T_TYPEDEF, row, 0);
      const first = field(T_TYPEDEF, row, 5);
      const last = row + 1 < total ? field(T_TYPEDEF, row + 1, 5) : (useMethodPtr ? (rowCounts.get(T_METHODPTR) ?? 0) : methodDefTotal) + 1;
      const count = Math.max(0, last - first);
      const methods = [];
      for (let slot = 0; slot < Math.min(count, caps.methodCapPerType); slot += 1) {
        let methodRow = first + slot; // 1-based; rows 1..N of MethodDef/MethodPtr
        if (useMethodPtr) methodRow = field(T_METHODPTR, methodRow - 1, 0);
        if (methodRow < 1 || methodRow > methodDefTotal) continue;
        methods.push({
          name: readString(field(T_METHODDEF, methodRow - 1, 3)),
          rva: field(T_METHODDEF, methodRow - 1, 0),
          flags: field(T_METHODDEF, methodRow - 1, 2),
        });
      }
      if (count > methods.length) methodsTruncated = true;
      types.push({ name, namespace, flags, methodCount: count, methods });
    }
    result.types = types;
    result.typeDefTotal = total;
    result.typesTruncated = shown < total;
    result.methodsTruncated = methodsTruncated;
  }

  // ---- ManifestResource --------------------------------------------------------
  if (offsets.has(T_MANIFESTRESOURCE)) {
    const total = rowCounts.get(T_MANIFESTRESOURCE) ?? 0;
    const shown = Math.min(total, caps.resourceCap);
    const resources = [];
    for (let row = 0; row < shown; row += 1) {
      resources.push({
        name: readString(field(T_MANIFESTRESOURCE, row, 2)),
        offset: field(T_MANIFESTRESOURCE, row, 0),
        flags: field(T_MANIFESTRESOURCE, row, 1),
      });
    }
    result.resources = resources;
    result.resourceTotal = total;
    result.resourcesTruncated = shown < total;
  }

  if (caps.cil) {
    result.cil = buildCilSection({ buffer, layout, streamAt, rowCounts, offsets, field, readString, caps, header });
  }

  result.tableRows = Object.fromEntries([...rowCounts].map(([table, count]) => [TABLE_NAMES[table] ?? `0x${table.toString(16)}`, count]));
  result.caps = caps;
  return result;
}

// --------------------------------------------------------------------- CIL ----

/**
 * Bounded CIL pass over the parsed tables: resolve tokens to names, walk
 * MethodDef bodies through lib/cil.js, and collect the assembly's P/Invoke
 * surface. Runs only when the caller asked for it (`cil: true`); degraded
 * inputs produce notes, never throws.
 */
function buildCilSection({ buffer, layout, streamAt, rowCounts, offsets, field, readString, caps, header }) {
  const section = {
    requested: true,
    methodBodiesSeen: 0,
    methods: [],
    pinvoke: [],
    pinvokeTotal: 0,
    caps: { methodCap: caps.cilMethodCap, instrCap: caps.cilInstrCap, pinvokeCap: caps.cilPinvokeCap },
  };
  const methodDefTotal = rowCounts.get(T_METHODDEF) ?? 0;
  const typeDefTotal = rowCounts.get(T_TYPEDEF) ?? 0;
  const fieldTotal = rowCounts.get(T_FIELD) ?? 0;
  if (!offsets.has(T_TYPEDEF) || !offsets.has(T_METHODDEF)) {
    section.note = 'TypeDef/MethodDef tables absent; no CIL pass';
    return section;
  }
  const useMethodPtr = offsets.has(T_METHODPTR) && (rowCounts.get(T_METHODPTR) ?? 0) > 0;
  const useFieldPtr = offsets.has(T_FIELDPTR) && (rowCounts.get(T_FIELDPTR) ?? 0) > 0;
  const methodPtrTotal = rowCounts.get(T_METHODPTR) ?? 0;
  const lastMethodSlot = (row) => (row + 1 < typeDefTotal
    ? field(T_TYPEDEF, row + 1, 5)
    : (useMethodPtr ? methodPtrTotal : methodDefTotal) + 1);

  const typeLabel = (row) => {
    const name = readString(field(T_TYPEDEF, row, 1));
    const namespace = readString(field(T_TYPEDEF, row, 2));
    return namespace ? `${namespace}.${name}` : name;
  };

  // Pass 1: ownership maps (MethodDef/Field row -> declaring type label) so
  // tokens resolve to `Namespace.Type::member` instead of bare member names.
  const methodOwner = new Map();
  const fieldOwner = new Map();
  for (let row = 0; row < typeDefTotal; row += 1) {
    const label = typeLabel(row);
    for (let slot = field(T_TYPEDEF, row, 5); slot < lastMethodSlot(row); slot += 1) {
      const defRow = useMethodPtr ? field(T_METHODPTR, slot - 1, 0) : slot;
      if (defRow >= 1 && defRow <= methodDefTotal) methodOwner.set(defRow, label);
    }
    const fieldLast = row + 1 < typeDefTotal ? field(T_TYPEDEF, row + 1, 4) : fieldTotal + 1;
    for (let slot = field(T_TYPEDEF, row, 4); slot < fieldLast; slot += 1) {
      const defRow = useFieldPtr ? field(T_FIELDPTR, slot - 1, 0) : slot;
      if (defRow >= 1 && defRow <= fieldTotal) fieldOwner.set(defRow, label);
    }
  }

  // Pass 1b: ImplMap -> P/Invoke surface (the managed sample's native API
  // calls), keyed by MethodDef row for call-site resolution.
  const pinvokeByMethod = new Map();
  const implMapTotal = rowCounts.get(T_IMPLMAP) ?? 0;
  for (let row = 0; row < implMapTotal; row += 1) {
    const flags = field(T_IMPLMAP, row, 0);
    const forwarded = field(T_IMPLMAP, row, 1); // coded MemberForwarded: tag 0 = Field, tag 1 = MethodDef
    const importName = readString(field(T_IMPLMAP, row, 2));
    const scope = field(T_IMPLMAP, row, 3);
    const dll = scope >= 1 ? readString(field(T_MODULEREF, scope - 1, 0)) : '';
    section.pinvokeTotal += 1;
    if ((forwarded & 0x01) !== 0x01) continue;
    const methodRow = forwarded >>> 1;
    if (methodRow < 1 || methodRow > methodDefTotal) continue;
    const owner = methodOwner.get(methodRow) ?? '?';
    const name = readString(field(T_METHODDEF, methodRow - 1, 3));
    pinvokeByMethod.set(methodRow, { dll, entry: importName, flags });
    if (section.pinvoke.length < caps.cilPinvokeCap) {
      section.pinvoke.push({ method: `${owner}::${name}`, dll, entry: importName });
    }
  }
  if (section.pinvokeTotal > section.pinvoke.length) section.pinvokeTruncated = true;

  const typerefName = (rid) => {
    const name = readString(field(T_TYPEREF, rid - 1, 1));
    const namespace = readString(field(T_TYPEREF, rid - 1, 2));
    return namespace ? `${namespace}.${name}` : name;
  };
  const typedefName = (rid) => {
    const name = readString(field(T_TYPEDEF, rid - 1, 1));
    const namespace = readString(field(T_TYPEDEF, rid - 1, 2));
    return namespace ? `${namespace}.${name}` : name;
  };
  const memberParentName = (coded) => {
    const tag = coded & 0x07;
    const rid = coded >>> 3;
    if (rid === 0) return '?';
    // MemberRefParent: 0 TypeDef, 1 TypeRef, 2 TypeSpec, 3 ModuleRef,
    // 4 MethodDef, 5 TypeSpec (ECMA-335 II.24.2.6).
    if (tag === 0) return typedefName(rid);
    if (tag === 1) return typerefName(rid);
    if (tag === 3) return `module:${readString(field(T_MODULEREF, rid - 1, 0))}`;
    if (tag === 4) return `${methodOwner.get(rid) ?? '?'}::${readString(field(T_METHODDEF, rid - 1, 3))}`;
    return 'typespec';
  };

  const usAt = streamAt?.['#US'];
  const resolveToken = (token) => {
    const table = (token >>> 24) & 0xff;
    const rid = token & 0x00ffffff;
    if (rid === 0) return null;
    if (table === 0x06) { // MethodDef
      const pinv = pinvokeByMethod.get(rid);
      if (pinv) return { kind: 'method', text: `${pinv.dll}!${pinv.entry}` };
      return { kind: 'method', text: `${methodOwner.get(rid) ?? '?'}::${readString(field(T_METHODDEF, rid - 1, 3))}` };
    }
    if (table === 0x0a) { // MemberRef
      const name = readString(field(T_MEMBERREF, rid - 1, 1));
      return { kind: 'method', text: `${memberParentName(field(T_MEMBERREF, rid - 1, 0))}::${name}` };
    }
    if (table === 0x2b) { // MethodSpec -> underlying MethodDef/MemberRef
      const v = field(T_METHODSPEC, rid - 1, 0);
      const base = resolveToken(((v & 0x01) === 0 ? 0x06 : 0x0a) << 24 | (v >>> 1));
      return { kind: 'method', text: base ? `${base.text}{generic}` : `methodspec 0x${token.toString(16).padStart(8, '0')}` };
    }
    if (table === 0x04) { // Field
      const name = readString(field(T_FIELD, rid - 1, 1));
      const owner = fieldOwner.get(rid);
      return { kind: 'field', text: owner ? `${owner}::${name}` : name };
    }
    if (table === 0x01) return { kind: 'type', text: typerefName(rid) };
    if (table === 0x02) return { kind: 'type', text: typedefName(rid) };
    if (table === 0x1b) return { kind: 'type', text: 'typespec' };
    if (table === 0x70) { // UserString: the rid is a byte offset into #US
      const decoded = usAt === undefined ? null : decodeUserStringAt(buffer, usAt + rid, 128);
      return { kind: 'string', text: decoded ? decoded.text : `us:0x${rid.toString(16)}` };
    }
    if (table === 0x11) return { kind: 'sig', text: 'sig' };
    return { kind: 'tok', text: `token 0x${token.toString(16).padStart(8, '0')}` };
  };

  // Pass 2: disassemble bodies in table order until the cap.
  const entryToken = header?.entryPointToken ?? 0;
  const entryRow = (entryToken >>> 24) === 0x06 ? entryToken & 0x00ffffff : 0;
  for (let row = 0; row < typeDefTotal; row += 1) {
    const label = typeLabel(row);
    const last = lastMethodSlot(row);
    for (let slot = field(T_TYPEDEF, row, 5); slot < last; slot += 1) {
      const defRow = useMethodPtr ? field(T_METHODPTR, slot - 1, 0) : slot;
      if (defRow < 1 || defRow > methodDefTotal) continue;
      const rva = field(T_METHODDEF, defRow - 1, 0);
      if (rva === 0) continue; // abstract / extern / P/Invoke: no IL body
      const name = readString(field(T_METHODDEF, defRow - 1, 3));
      if (section.methods.length >= caps.cilMethodCap) {
        section.methodBodiesSeen += 1;
        continue;
      }
      section.methodBodiesSeen += 1;
      const at = rvaToOffset(layout, rva);
      if (at === null) {
        section.methods.push({ type: label, name, rva, note: 'body RVA outside the mapped image' });
        continue;
      }
      const body = parseMethodBody(buffer, at);
      if (body.kind === null || body.error) {
        section.methods.push({ type: label, name, rva, note: body.error ?? 'unparseable method body' });
        continue;
      }
      const code = buffer.subarray(body.codeAt, body.codeAt + body.codeLength);
      const dis = disassembleIl(code, resolveToken, { instrCap: caps.cilInstrCap });
      section.methods.push({
        type: label,
        name,
        rva,
        entrypoint: defRow === entryRow ? true : undefined,
        header: body.kind,
        maxStack: body.maxStack,
        codeBytes: body.codeLength,
        instructionCount: dis.instructions.length,
        instructionsTruncated: dis.truncated || undefined,
        bodyTruncated: body.truncated || undefined,
        instructions: dis.instructions,
        eh: body.eh.length > 0 ? body.eh : undefined,
        strings: dis.summary.strings.length > 0 ? dis.summary.strings : undefined,
        apis: dis.summary.apis.length > 0 ? dis.summary.apis : undefined,
        fields: dis.summary.fields.length > 0 ? dis.summary.fields : undefined,
        types: dis.summary.types.length > 0 ? dis.summary.types : undefined,
        branches: dis.summary.branches > 0 ? dis.summary.branches : undefined,
        unknownOpcodes: dis.summary.unknown > 0 ? dis.summary.unknown : undefined,
      });
    }
  }
  if (section.methodBodiesSeen > section.methods.length) section.truncated = true;
  return section;
}

/** Decode the first bounded strings of the #US heap (UTF-16LE, length-prefixed). */
function readUsStrings(buffer, usAt, usSize) {
  const strings = [];
  if (usAt === undefined || usAt >= buffer.length) return strings;
  const stop = Math.min(usAt + usSize, buffer.length);
  let at = usAt;
  while (at < stop && strings.length < 8) {
    const decoded = decodeUserStringAt(buffer, at, 128);
    if (decoded === null || at + decoded.bytes > stop) break;
    if (decoded.text.length > 0) strings.push(decoded.text);
    at += decoded.bytes;
  }
  return strings;
}
