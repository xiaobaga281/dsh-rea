/**
 * What is appended after the last section, and what built the PE in the first
 * place.
 *
 * A 28 MB installer is not a packed binary. Its `.text` is an ordinary Delphi
 * stub, and the 27 MB that follow the last section are a compressed
 * installation payload. Whole-file entropy cannot tell those apart - it only
 * sees 28 MB of compressed bytes and reports "near random", which is how the
 * tool ended up telling an analyst to find an OEP that does not exist.
 *
 * @module dsh-rea/lib/installer
 */

const text = (value) => Buffer.from(value, 'latin1');

/** Signatures that live at the start of the appended data. */
const HEAD_SIGNATURES = [
  { id: 'inno-setup', name: 'Inno Setup installer', kind: 'installer', magic: 'zlb', payload: 'Inno Setup "zlb" compressed blocks' },
  { id: 'zip-sfx', name: 'ZIP self-extracting archive', kind: 'self-extracting', magic: 'PK\x03\x04', payload: 'ZIP archive' },
  { id: 'rar-sfx', name: 'RAR self-extracting archive', kind: 'self-extracting', magic: 'Rar!\x1a\x07', payload: 'RAR archive' },
  { id: '7z-sfx', name: '7-Zip self-extracting archive', kind: 'self-extracting', magic: "7z\xbc\xaf\x27\x1c", payload: '7z archive' },
  { id: 'cab-sfx', name: 'Cabinet self-extracting archive', kind: 'self-extracting', magic: 'MSCF', payload: 'Microsoft Cabinet' },
];

/** Signatures anywhere in a bounded tail, because installers put their index last. */
const TAIL_SIGNATURES = [
  { id: 'nsis', name: 'NSIS installer', kind: 'installer', magic: 'NullsoftInst', payload: 'NSIS compressed sections' },
  { id: 'installshield', name: 'InstallShield installer', kind: 'installer', magic: 'InstallShield', payload: 'InstallShield cabinet data' },
  { id: 'pyinstaller', name: 'PyInstaller bundle', kind: 'installer', magic: 'MEI\x0c\x0b\x0a\x0b\x0e', payload: 'PyInstaller CArchive' },
  { id: 'electron', name: 'Electron application', kind: 'application', magic: 'app.asar', payload: 'asar archive' },
];

const within = (buffer, from, to, needle) => {
  const haystack = buffer.subarray(Math.max(0, from), Math.min(buffer.length, to));
  return haystack.indexOf(text(needle));
};

/**
 * Identify the appended payload.
 *
 * Only the head of the overlay and a bounded tail are searched: scanning 28 MB
 * for every signature would cost more than the answer is worth, and every
 * format in this table puts its marker in one of those two places.
 */
export function identifyOverlay(bytes, { overlayOffset = null } = {}) {
  const innoVersion = /Inno Setup Setup Data \((\d+(?:\.\d+)*)\)/.exec(
    bytes.toString('latin1', 0, Math.min(bytes.length, 2 * 1024 * 1024)),
  )?.[1] ?? null;
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const start = Number.isInteger(overlayOffset) && overlayOffset > 0 && overlayOffset < buffer.length
    ? overlayOffset
    : null;
  const payloadBytes = start === null ? 0 : buffer.length - start;
  const head = start === null ? Buffer.alloc(0) : buffer.subarray(start, Math.min(buffer.length, start + 8192));
  const evidence = [];

  if (start !== null) {
    for (const signature of HEAD_SIGNATURES) {
      if (head.subarray(0, signature.magic.length).toString('latin1') === signature.magic) {
        evidence.push(`overlay starts with "${signature.magic}"`);
        return {
          id: signature.id, name: signature.name, kind: signature.kind,
          version: signature.id === 'inno-setup' ? innoVersion : null,
          payload: signature.payload, payloadBytes, offset: start, evidence,
        };
      }
    }
    // Inno Setup 6 writes its index later in the overlay, and older releases
    // spell it out. Either marker is decisive even when the first block is a
    // different compressor.
    const inno = within(buffer, start, start + 8192, 'Inno Setup Setup Data')
      ?? within(buffer, start, start + 8192, 'InnoSetupLdr');
    if (inno >= 0) {
      evidence.push('"Inno Setup Setup Data" inside the overlay');
      return {
        id: 'inno-setup', name: 'Inno Setup installer', kind: 'installer', version: innoVersion,
        payload: 'Inno Setup compressed installation data', payloadBytes, offset: start, evidence,
      };
    }
  }

  const tailFrom = Math.max(0, buffer.length - 256 * 1024);
  for (const signature of TAIL_SIGNATURES) {
    const at = within(buffer, tailFrom, buffer.length, signature.magic);
    if (at >= 0) {
      evidence.push(`"${signature.magic}" at 0x${(tailFrom + at).toString(16)}`);
      return { id: signature.id, name: signature.name, kind: signature.kind, payload: signature.payload, payloadBytes, offset: start, evidence };
    }
  }
  return payloadBytes > 0 ? { id: null, name: 'unidentified overlay', kind: 'unknown', payload: null, payloadBytes, offset: start, evidence: [] } : null;
}

/**
 * Which compiler produced the PE.
 *
 * Section names are the cheapest reliable signal: Delphi and C++ Builder use
 * `.itext` / `.didata` / `.edata` / `.tls` and nothing else does, and a Go
 * binary carries `.gopclntab` or a build-id note.
 */
export function detectToolchain(bytes, format = {}) {
  const names = new Set((format.sections ?? []).map((section) => String(section.name).toLowerCase()));
  if (names.has('.itext') && (names.has('.didata') || names.has('.edata'))) {
    return { id: 'delphi', name: 'Delphi / C++ Builder', evidence: 'sections .itext + .didata/.edata' };
  }
  if (names.has('.gopclntab') || names.has('.go.buildinfo')) {
    return { id: 'go', name: 'Go', evidence: 'Go-specific section' };
  }
  if (names.has('.wixburn')) return { id: 'wix-burn', name: 'WiX Burn bundle', evidence: 'section .wixburn' };
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const head = buffer.subarray(0, Math.min(buffer.length, 1024 * 1024));
  if (head.indexOf(text('Go build ID:')) >= 0 || head.indexOf(text('runtime.morestack')) >= 0) {
    return { id: 'go', name: 'Go', evidence: 'Go runtime string' };
  }
  if (head.indexOf(text('rust_panic')) >= 0 || head.indexOf(text('core::panicking')) >= 0) {
    return { id: 'rust', name: 'Rust', evidence: 'Rust panic strings' };
  }
  if (head.indexOf(text('UPX!')) >= 0) return { id: 'upx', name: 'UPX', evidence: '"UPX!" marker' };
  return null;
}
