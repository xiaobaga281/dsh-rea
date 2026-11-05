/**
 * Where a first-party engine may keep its working files.
 *
 * Ghidra rejects any path element that starts with a dot ("Path element
 * starting with '.' is not permitted"), and its launcher hands `_JAVA_OPTIONS`
 * to the JVM, which splits that variable on whitespace - so a property value
 * containing a space would arrive truncated. Both constraints are about the
 * *spelling* of the directory, and both are cheap to check before a 15-second
 * launch fails.
 *
 * Kept separate from `lib/ghidra-local.js` so `lib/engines.js` can report on the
 * directory without importing the runner that imports it.
 *
 * @module dsh-rea/lib/work-root
 */

import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { PLUGIN_ROOT } from './paths.js';

const SUBDIRECTORIES = ['projects', 'scripts', 'tmp', 'cache', 'settings'];

/** Ghidra aborts on any path element that starts with a dot. */
export const hasDotElement = (directory) => resolve(directory)
  .split(sep)
  .some((element) => element.startsWith('.'));

/** Why a candidate cannot be used, or null when it can. */
export function rejectReason(directory) {
  if (hasDotElement(directory)) return 'a path element starts with "." (Ghidra rejects it)';
  if (String(directory).includes(' ')) return 'the path contains a space (JVM options are split on whitespace)';
  return null;
}

export function candidates(env = process.env) {
  return [
    env.DSH_REA_GHIDRA_WORK,
    join(PLUGIN_ROOT, 'ghidra-work'),
    join(homedir(), 'dsh-rea-work'),
    env.LOCALAPPDATA ? join(env.LOCALAPPDATA, 'dsh-rea', 'ghidra-work') : null,
  ].filter((value) => typeof value === 'string' && value.length > 0);
}

let cached;

/** First writable candidate that Ghidra will accept, or null. */
export function resolveWorkRoot(env = process.env) {
  if (cached) return cached;
  for (const candidate of candidates(env)) {
    const full = resolve(candidate);
    if (rejectReason(full)) continue;
    try {
      for (const name of SUBDIRECTORIES) mkdirSync(join(full, name), { recursive: true });
      cached = full;
      return full;
    } catch {
      // Not writable here; try the next candidate rather than failing the probe.
    }
  }
  return null;
}

/** Test seam: forget the cached root so a different env can be evaluated. */
export function resetWorkRoot() {
  cached = undefined;
}

/** Every candidate with the reason it was accepted or skipped. */
export function explainWorkRoot(env = process.env) {
  return candidates(env).map((candidate) => {
    const full = resolve(candidate);
    const rejected = rejectReason(full);
    let writable = false;
    if (!rejected) {
      try {
        for (const name of SUBDIRECTORIES) mkdirSync(join(full, name), { recursive: true });
        writable = true;
      } catch {
        writable = false;
      }
    }
    return {
      path: full,
      usable: !rejected && writable,
      reason: rejected ?? (writable ? null : 'not writable'),
    };
  });
}
