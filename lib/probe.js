/**
 * Local structural probe.
 *
 * `verify` used to mean "an engine ran this address and resolved a name". When
 * the engine cannot start, that leaves the dimension unmeasurable: honest, but
 * useless, because the report can still be checked against the file it talks
 * about.
 *
 * This probe answers two questions with the file alone:
 *
 *   - is this RVA inside an executable section? A TLS callback must be code,
 *     and a plan that points at `.rdata` is wrong no matter what the prose says;
 *   - does the dword at this RVA point into an executable section? That is what
 *     a dispatcher entry is.
 *
 * It cannot name a symbol, so it is a weaker claim than an engine run, and the
 * duel scores it as such. What it removes is the case where "the engine is not
 * installed" silently turns a correct plan into an unscored one.
 *
 * @module dsh-rea/lib/probe
 */

import { readPeLayout, rvaToOffset } from './structure.js';

const sectionAt = (layout, rva) => layout.sections.find((section) => (
  rva >= section.virtualAddress
  && rva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize)
)) ?? null;

const hex = (value, width) => `0x${(value >>> 0).toString(16).padStart(width, '0')}`;

/**
 * Read the mapped bytes at one address and classify what is there.
 *
 * `address` is accepted as VA or RVA: anything at or above `imageBase` is
 * treated as a VA, because a plan prints VAs and a reader copies them verbatim.
 */
export function probeAddress(bytes, { address, kind = 'code', pointerBytes = null } = {}) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const layout = readPeLayout(buffer);
  if (!layout) return { ok: false, error: 'not a PE image', verdict: 'unsupported' };

  const numeric = typeof address === 'string' ? Number.parseInt(address.replace(/^0x/i, ''), 16) : Number(address);
  if (!Number.isFinite(numeric)) return { ok: false, error: `unreadable address: ${address}`, verdict: 'invalid' };
  const imageBase = layout.imageBase >>> 0;
  const va = numeric >>> 0;
  const rva = (va >= imageBase ? va - imageBase : va) >>> 0;

  const section = sectionAt(layout, rva);
  const offset = rvaToOffset(layout, rva);
  if (offset === null || offset === undefined || offset < 0 || offset >= buffer.length) {
    return {
      ok: true, address: va, rva, section: section?.name ?? null,
      executable: section?.executable === true, mapped: false,
      bytes: null, pointer: null, verdict: 'unmapped',
    };
  }

  const width = pointerBytes ?? (layout.is64 ? 8 : 4);
  const available = Math.min(16, buffer.length - offset);
  const raw = buffer.subarray(offset, offset + available);
  const mapped = true;
  const executable = section?.executable === true;

  let pointer = null;
  if (available >= width) {
    const value = width === 8 ? Number(raw.readBigUInt64LE(0)) : raw.readUInt32LE(0);
    const targetRva = value >= imageBase ? value - imageBase : null;
    const target = targetRva === null ? null : sectionAt(layout, targetRva);
    pointer = {
      value: value >>> 0,
      targetRva: targetRva === null ? null : targetRva >>> 0,
      targetSection: target?.name ?? null,
      targetExecutable: target?.executable === true,
    };
  }

  let verdict;
  if (kind === 'pointer') {
    verdict = pointer?.targetExecutable === true ? 'pointer' : 'not-a-code-pointer';
  } else {
    verdict = executable ? 'code' : 'not-executable';
  }

  return {
    ok: true,
    address: va,
    rva,
    imageBase,
    section: section?.name ?? null,
    executable,
    mapped,
    bytes: [...raw].map((byte) => byte.toString(16).padStart(2, '0')).join(' '),
    pointer,
    kind,
    verdict,
  };
}

/** One-line reason a probe failed, for the report to print instead of "failed". */
export function describeVerdict(result) {
  if (!result?.ok) return result?.error ?? 'probe could not run';
  if (result.verdict === 'unmapped') return `RVA ${hex(result.rva, 4)} is not mapped to file bytes (virtual-only region)`;
  if (result.verdict === 'not-executable') {
    return `${hex(result.rva, 4)} is in ${result.section ?? 'no section'}, which is not executable`;
  }
  if (result.verdict === 'not-a-code-pointer') {
    const target = result.pointer;
    if (!target) return 'not enough bytes for a pointer';
    return `${hex(target.value, 4)} does not point into an executable section (${target.targetSection ?? 'unmapped'})`;
  }
  if (result.verdict === 'pointer') return `${hex(result.pointer.value, 4)} points into ${result.pointer.targetSection}`;
  return `${hex(result.rva, 4)} is executable code in ${result.section}`;
}
