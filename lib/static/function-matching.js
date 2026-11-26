/**
 * Shared function-inventory helpers: the pairing primitives used by both the
 * restoration compare (restore layer) and the interaction extractor (static
 * layer). They live outside compare.js so the static layer can use them
 * without depending on the restore layer (no import cycle).
 *
 * @module dsh-rea-restore/lib/function-matching
 */

export const toRvaNumber = (value) => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const text = value.trim();
    if (/^0x[0-9a-f]+$/i.test(text)) return Number.parseInt(text, 16);
    if (/^\d+$/.test(text)) return Number.parseInt(text, 10);
  }
  return null;
};

export const normalizeQuote = (text) => String(text ?? '').toLowerCase().replace(/\s+/g, ' ').trim();

export function findListedFunction(functions, rva, name) {
  if (!Array.isArray(functions)) return null;
  if (name) {
    const byName = functions.find((fn) => fn?.name === name);
    if (byName) return byName;
  }
  const wanted = toRvaNumber(rva);
  if (wanted !== null) {
    const byRva = functions.find((fn) => toRvaNumber(fn?.rva) === wanted);
    if (byRva) return byRva;
  }
  return null;
}
