/**
 * The vendored REA runtime: checksum, unpack, and the bundled skill.
 *
 * The runtime ships as one compressed archive instead of a `node_modules` tree
 * because REA lazy-`require`s a number of packages on specific code paths; only
 * the complete closure survives all 207 tools. Unpacking happens once into the
 * DSH home and is versioned by the archive digest in a marker file, so an
 * upgrade replaces the tree instead of leaving a stale one behind.
 *
 * @module dsh-rea/lib/runtime
 */

import { createHash } from 'node:crypto';
import { createReadStream, existsSync } from 'node:fs';
import { cp, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { extractTarball } from './download.js';
import { PLUGIN_ROOT, RUNTIME_ARCHIVE, RUNTIME_DIGEST, RUNTIME_DIR, RUNTIME_ENTRY, RUNTIME_MARKER, SKILL_NAME, SKILLS_ROOT } from './paths.js';

const UNPACK_TIMEOUT_MS = 10 * 60_000;

/** SHA-256 of a file without holding a large archive in memory. */
export async function sha256File(path) {
  const digest = createHash('sha256');
  await new Promise((resolveDigest, rejectDigest) => {
    const stream = createReadStream(path);
    stream.on('data', (chunk) => digest.update(chunk));
    stream.once('error', rejectDigest);
    stream.once('end', resolveDigest);
  });
  return digest.digest('hex');
}

/** A tiny read-json helper: absence and corruption both answer `undefined`. */
export async function readJsonFile(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return undefined;
  }
}

/** True when the unpacked runtime is present and matches the shipped archive. */
export async function runtimeIsCurrent() {
  if (!existsSync(RUNTIME_ENTRY)) return false;
  const marker = await readJsonFile(RUNTIME_MARKER);
  if (marker === undefined) return false;
  try {
    const expected = (await readFile(RUNTIME_DIGEST, 'utf8')).trim();
    return marker?.archiveSha256 === expected;
  } catch {
    return false;
  }
}

/**
 * Unpack the shipped runtime, atomically.
 *
 * The archive is checksummed first, extracted into a sibling staging directory,
 * and only swapped into place once `rea.mjs` is actually there. A failure at any
 * point leaves the previous runtime untouched - the earlier implementation
 * removed the live tree before extracting, so a transient `tar` failure cost
 * every REA tool until the plugin was reinstalled.
 */
export async function unpackRuntime(log) {
  if (await runtimeIsCurrent()) return true;
  if (!existsSync(RUNTIME_ARCHIVE)) {
    log?.warn?.(`dsh-rea: the runtime archive is missing at ${RUNTIME_ARCHIVE}; no REA tools can be registered.`);
    return false;
  }
  const staging = `${RUNTIME_DIR}.staging-${process.pid}`;
  try {
    const expected = (await readFile(RUNTIME_DIGEST, 'utf8')).trim();
    const digest = await sha256File(RUNTIME_ARCHIVE);
    if (digest !== expected) {
      log?.warn?.(`dsh-rea: the runtime archive failed its checksum; expected ${expected}, got ${digest}`);
      return false;
    }
    await rm(staging, { recursive: true, force: true });
    const nodeModules = join(staging, 'node_modules');
    await mkdir(nodeModules, { recursive: true });
    // The archive holds the contents of a node_modules directory, so the unpack
    // target is the node_modules subdirectory, not the runtime root.
    const tar = await extractTarball(RUNTIME_ARCHIVE, nodeModules, { timeoutMs: UNPACK_TIMEOUT_MS });
    if (tar.code !== 0) {
      log?.warn?.(`dsh-rea: unpacking the runtime failed (tar exit ${tar.code}): ${tar.stderr.slice(0, 300).trim()}`);
      await rm(staging, { recursive: true, force: true }).catch(() => {});
      return false;
    }
    if (!existsSync(join(nodeModules, 'rea-agents', 'scripts', 'rea.mjs'))) {
      log?.warn?.('dsh-rea: the unpacked runtime does not contain rea-agents/scripts/rea.mjs; keeping the previous runtime.');
      await rm(staging, { recursive: true, force: true }).catch(() => {});
      return false;
    }
    try {
      await rm(RUNTIME_DIR, { recursive: true, force: true });
      await rename(staging, RUNTIME_DIR);
    } catch {
      // A cross-device or briefly locked rename falls back to a copy; slower,
      // but the alternative is losing the runtime.
      await cp(nodeModules, join(RUNTIME_DIR, 'node_modules'), { recursive: true });
      await rm(staging, { recursive: true, force: true }).catch(() => {});
    }
    await writeFile(RUNTIME_MARKER, `${JSON.stringify({
      installedBy: 'dsh-rea',
      archiveSha256: digest,
      unpackedAt: new Date().toISOString(),
      nodeModules: join(RUNTIME_DIR, 'node_modules'),
    }, null, 2)}\n`);
    return existsSync(RUNTIME_ENTRY);
  } catch (error) {
    log?.warn?.(`dsh-rea: could not unpack the runtime: ${error.message}`);
    await rm(staging, { recursive: true, force: true }).catch(() => {});
    return false;
  }
}

/**
 * Resolve the `rea-agents` package root: the unpacked cache first, a vendored
 * tree second (development checkouts only). Absence is reported by the caller,
 * never thrown at module load, so a broken install lets the Host boot and
 * explain itself.
 */
export async function resolveReaPackage(log) {
  if (await unpackRuntime(log)) return join(RUNTIME_DIR, 'node_modules', 'rea-agents');
  const vendored = join(PLUGIN_ROOT, 'vendor', 'node_modules', 'rea-agents');
  if (existsSync(join(vendored, 'scripts', 'rea.mjs'))) return vendored;
  return undefined;
}

/**
 * Install the bundled skill into the user DSH skills root.
 *
 * Version-stamped, so a session does not recopy the reference set on every
 * activation, and a plugin update replaces the tree - including removing
 * reference documents the upstream skill no longer ships. A directory that does
 * not carry this plugin's stamp is merged into instead of deleted, because it
 * may be the person's own copy.
 */
export async function installSkill({ log, skillDir, version } = {}) {
  if (!skillDir || !existsSync(skillDir)) {
    log?.warn?.('dsh-rea: the rea skill directory is missing; skipping skill installation.');
    return undefined;
  }
  const target = join(SKILLS_ROOT, SKILL_NAME);
  const stampPath = join(target, '.dsh-rea.json');
  // Releases before 1.1.0 stamped beside the skill directory instead of inside
  // it; recognising that marker keeps an upgrade from warning about a directory
  // this plugin created in the first place.
  const legacyStampPath = join(SKILLS_ROOT, `.${SKILL_NAME}.rea.json`);
  try {
    const stamp = await readJsonFile(stampPath);
    if (stamp?.rea === version && existsSync(join(target, 'SKILL.md'))) return target;
    await mkdir(SKILLS_ROOT, { recursive: true });
    const legacy = await readJsonFile(legacyStampPath);
    let owned = stamp !== undefined || legacy !== undefined;
    if (!owned && existsSync(target)) {
      const existing = await readdir(target).catch(() => []);
      owned = existing.length === 0;
      if (!owned) log?.warn?.(`dsh-rea: ${target} exists without a dsh-rea stamp; merging the bundled skill into it instead of replacing it.`);
    }
    if (owned) await rm(target, { recursive: true, force: true });
    await cp(skillDir, target, { recursive: true, force: true });
    await writeFile(stampPath, `${JSON.stringify({ installedBy: 'dsh-rea', rea: version, at: new Date().toISOString() }, null, 2)}\n`);
    return target;
  } catch (error) {
    log?.warn?.(`dsh-rea: could not install the reverse-engineer-anything skill: ${error.message}`);
    return undefined;
  }
}
