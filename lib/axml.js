/**
 * A reader for Android's binary XML (AXML).
 *
 * `AndroidManifest.xml` inside an APK is not text: it is a chunked binary
 * format with a string pool and typed attributes. apktool decodes it well, but
 * requiring a 20 MB jar (and a JVM start) to answer "what is this app called and
 * what does it ask for" is a poor trade when the format is small and stable.
 *
 * Only the parts a triage report needs are implemented: the string pool, start
 * elements, and typed attribute values. There is no rendering, no resource
 * resolution, and no attempt to interpret `@ref/...` values beyond reporting
 * that they point at a resource.
 *
 * @module dsh-rea/lib/axml
 */

const RES_STRING_POOL = 0x0001;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;

const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

function readLength8(buffer, offset) {
  let length = buffer[offset];
  let cursor = offset + 1;
  if (length & 0x80) {
    length = ((length & 0x7f) << 8) | buffer[cursor];
    cursor += 1;
  }
  return { length, cursor };
}

/** UTF-8 pools store the character count first, then the byte count. */
function readUtf8(buffer, offset) {
  const first = readLength8(buffer, offset);
  const second = readLength8(buffer, first.cursor);
  const start = second.cursor;
  return buffer.toString('utf8', start, start + second.length);
}

function readUtf16(buffer, offset) {
  let length = buffer.readUInt16LE(offset);
  let cursor = offset + 2;
  if (length & 0x8000) {
    length = ((length & 0x7fff) << 16) | buffer.readUInt16LE(cursor);
    cursor += 2;
  }
  return buffer.toString('utf16le', cursor, cursor + length * 2);
}

function readStringPool(buffer, offset) {
  const headerSize = buffer.readUInt16LE(offset + 2);
  const count = buffer.readUInt32LE(offset + 8);
  const flags = buffer.readUInt32LE(offset + 16);
  const stringsStart = buffer.readUInt32LE(offset + 20);
  const utf8 = (flags & 0x100) !== 0;
  const strings = [];
  for (let index = 0; index < count; index += 1) {
    const at = offset + stringsStart + buffer.readUInt32LE(offset + headerSize + index * 4);
    try {
      strings.push(utf8 ? readUtf8(buffer, at) : readUtf16(buffer, at));
    } catch {
      strings.push('');
    }
  }
  return { strings, end: offset + buffer.readUInt32LE(offset + 4) };
}

function typedValue(buffer, dataType, data, strings) {
  switch (dataType) {
    case TYPE_STRING:
      return strings[data] ?? '';
    case TYPE_INT_BOOLEAN:
      return data !== 0;
    case TYPE_INT_DEC:
      return data | 0;
    case TYPE_INT_HEX:
      return `0x${(data >>> 0).toString(16)}`;
    case TYPE_REFERENCE:
      return data === 0 ? null : `@0x${(data >>> 0).toString(16)}`;
    case TYPE_FLOAT:
      return Buffer.from(new Uint32Array([data]).buffer).readFloatLE(0);
    default:
      return data;
  }
}

/**
 * Parse a binary XML document into start elements.
 *
 * Returns `{ elements: [{ name, attributes }], strings }`, where each attribute
 * is already resolved to a JS value. Namespaced attributes keep their local
 * name only; `android:name` and `name` both arrive as `name`, which is what a
 * manifest reader wants.
 */
export function parseBinaryXml(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) return { ok: false, reason: 'too short' };
  if (buffer.readUInt16LE(0) !== 0x0003) return { ok: false, reason: 'not a binary XML document' };
  let strings = [];
  const elements = [];
  let cursor = buffer.readUInt16LE(2) || 8;
  while (cursor + 8 <= buffer.length) {
    const type = buffer.readUInt16LE(cursor);
    const size = buffer.readUInt32LE(cursor + 4);
    if (size <= 0 || cursor + size > buffer.length) break;
    if (type === RES_STRING_POOL) {
      strings = readStringPool(buffer, cursor).strings;
    } else if (type === RES_XML_START_ELEMENT) {
      const headerSize = buffer.readUInt16LE(cursor + 2);
      const nameIndex = buffer.readUInt32LE(cursor + 20);
      const attributeStart = buffer.readUInt16LE(cursor + 24);
      const attributeSize = buffer.readUInt16LE(cursor + 26);
      const attributeCount = buffer.readUInt16LE(cursor + 28);
      const attributes = {};
      for (let index = 0; index < attributeCount; index += 1) {
        // `attributeStart` is relative to the attrExt structure, which begins
        // after the node header. Using cursor + attributeStart lands inside the
        // namespace/name fields and turns every attribute into garbage - element
        // names still parse, which is what made this look like it worked.
        const at = cursor + headerSize + attributeStart + index * attributeSize;
        if (at + 20 > cursor + size) break;
        const attributeName = strings[buffer.readUInt32LE(at + 4)] ?? '';
        const dataType = buffer[at + 15];
        const data = buffer.readUInt32LE(at + 16);
        if (attributeName) attributes[attributeName] = typedValue(buffer, dataType, data, strings);
      }
      elements.push({ name: strings[nameIndex] ?? '', attributes });
    } else if (type === RES_XML_END_ELEMENT) {
      // Depth is not tracked: the manifest reader walks the flat list.
    }
    cursor += size;
  }
  return { ok: elements.length > 0, elements, strings, reason: elements.length > 0 ? null : 'no elements' };
}

/** A handful of manifest facts, in the order an analyst asks for them. */
export function summarizeManifest(parsed) {
  if (!parsed?.ok) return null;
  const root = parsed.elements.find((element) => element.name === 'manifest');
  if (!root) return null;
  const application = parsed.elements.find((element) => element.name === 'application') ?? { attributes: {} };
  const usesSdk = parsed.elements.find((element) => element.name === 'uses-sdk') ?? { attributes: {} };
  const permissions = parsed.elements
    .filter((element) => element.name === 'uses-permission' || element.name === 'uses-permission-sdk-23')
    .map((element) => element.attributes.name)
    .filter((value) => typeof value === 'string');
  const components = parsed.elements.filter((element) => ['activity', 'service', 'receiver', 'provider'].includes(element.name));
  const exported = components.filter((element) => element.attributes.exported === true);
  return {
    package: root.attributes.package ?? null,
    versionName: root.attributes.versionName ?? null,
    versionCode: root.attributes.versionCode ?? null,
    minSdk: usesSdk.attributes.minSdkVersion ?? null,
    targetSdk: usesSdk.attributes.targetSdkVersion ?? null,
    permissions: { count: permissions.length, list: permissions.slice(0, 24) },
    components: {
      count: components.length,
      exported: exported.map((element) => ({ kind: element.name, name: element.attributes.name ?? null })).slice(0, 12),
    },
    flags: {
      debuggable: application.attributes.debuggable === true,
      allowBackup: application.attributes.allowBackup === true,
      usesCleartextTraffic: application.attributes.usesCleartextTraffic === true,
    },
    application: {
      name: application.attributes.name ?? null,
      label: typeof application.attributes.label === 'string' ? application.attributes.label : null,
    },
  };
}
