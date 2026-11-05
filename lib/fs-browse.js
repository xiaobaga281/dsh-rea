/**
 * A directory picker needs a directory listing, and a directory listing is a
 * filesystem read on the Host. That is why this module is deliberately small
 * and narrow:
 *
 *   - it returns **directory names only** - never file contents, never sizes,
 *     never timestamps. A panel that could proxy arbitrary file reads would be
 *     a worse hole than the scope check it exists to configure;
 *   - the path must be absolute, so a relative argument cannot be resolved
 *     against a working directory the caller does not control;
 *   - entries are capped, so pointing it at `C:\` cannot stall the panel.
 *
 * The route that calls it is the same origin-checked JSON POST as the other
 * state-changing endpoints, because "list every folder on this machine" is
 * reconnaissance even when it changes nothing.
 *
 * @module dsh-rea/lib/fs-browse
 */

import { readdir, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';

/** Names that make a picker unusable are still worth showing; the cap is for width. */
const DEFAULT_LIMIT = 400;

export class BrowseError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = 'BrowseError';
    this.statusCode = statusCode;
  }
}

/** Drive letters on Windows, `/` elsewhere. */
async function roots() {
  if (process.platform !== 'win32') return ['/'];
  const found = [];
  for (let code = 65; code <= 90; code += 1) {
    const drive = `${String.fromCharCode(code)}:\\`;
    try {
      const info = await stat(drive);
      if (info.isDirectory()) found.push(drive);
    } catch { /* an absent drive is not an error */ }
  }
  return found;
}

/**
 * List the subdirectories of one path.
 *
 * `path` may be empty, which returns the roots of the filesystem instead of an
 * error: that is the state a picker opens in, and making the caller special-case
 * it would leak the platform into the panel.
 */
export async function listDirectories(input, { limit = DEFAULT_LIMIT } = {}) {
  const raw = typeof input === 'string' ? input.trim() : '';
  const drives = await roots();
  if (raw.length === 0) {
    return { path: null, parent: null, entries: drives.map((drive) => ({ name: drive, path: drive })), roots: drives };
  }
  if (!isAbsolute(raw)) throw new BrowseError(`"${raw}" is not an absolute path`);
  const target = resolve(raw);

  let info;
  try {
    info = await stat(target);
  } catch (error) {
    // The picker polls a path a person typed; a typo is a 404 with a reason,
    // not a stack trace.
    throw new BrowseError(`${target} cannot be read: ${error?.code ?? error?.message ?? 'unknown error'}`, 404);
  }
  if (!info.isDirectory()) throw new BrowseError(`${target} is not a directory`);

  let names = [];
  try {
    names = await readdir(target, { withFileTypes: true });
  } catch (error) {
    throw new BrowseError(`${target} cannot be listed: ${error?.code ?? error?.message ?? 'unknown error'}`, 403);
  }

  const entries = names
    // Symlinks are skipped rather than followed: a junction loop would make the
    // picker wander forever, and a scope root should be a real directory.
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({ name: entry.name, path: join(target, entry.name) }))
    .sort((left, right) => left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: 'base' }));

  const parent = dirname(target);
  return {
    path: target,
    parent: parent === target ? null : parent,
    entries: entries.slice(0, limit),
    truncated: entries.length > limit,
    roots: drives,
  };
}
