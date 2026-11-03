/**
 * Self-update: check the release feed, download through redundant mirrors, and
 * swap the plugin directory.
 *
 * Two independent layers are redundant, because either one failing is enough to
 * strand an update:
 *
 *   - *metadata*: the GitHub REST API first, then a static `update.json`
 *     committed to the repository and served by a CDN. The manifest exists so a
 *     blocked `api.github.com` is not the end of the story.
 *   - *bytes*: the release asset is fetched from the first mirror that returns a
 *     body matching the expected SHA-256. A mirror that is down, throttled, or
 *     serving something else loses its turn and the next one is tried.
 *
 * Integrity is the SHA-256 published with the release, never the transport: a
 * mirror is untrusted by definition, and an archive whose digest does not match
 * is deleted rather than installed. Anyone who can rewrite both the metadata and
 * the asset can still substitute content - there is no signing key here - so the
 * manifest source is pinned to this repository.
 *
 * @module dsh-rea/lib/update
 */

import { mkdir, readFile, readdir, rename, rm } from 'node:fs/promises';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { downloadFile, extractArchive, fetchText } from './download.js';
import { sha256File } from './runtime.js';
import { PLUGIN_ROOT } from './paths.js';

export const REPOSITORY = 'xiaobaga281/dsh-rea';
const RELEASE_API = `https://api.github.com/repos/${REPOSITORY}/releases/latest`;
const MANIFEST_SOURCES = [
  `https://cdn.jsdelivr.net/gh/${REPOSITORY}@main/update.json`,
  `https://raw.githubusercontent.com/${REPOSITORY}/main/update.json`,
];

/**
 * Ordered fallbacks for the asset itself. The first entry is GitHub; the rest
 * are public read-through proxies for it. They are third-party infrastructure
 * and are only ever trusted to move bytes - the digest decides.
 */
export const DEFAULT_MIRRORS = [
  { id: 'github', label: 'GitHub', prefix: '' },
  { id: 'ghproxy', label: 'ghproxy.net', prefix: 'https://ghproxy.net/' },
  { id: 'gh-proxy', label: 'gh-proxy.com', prefix: 'https://gh-proxy.com/' },
  { id: 'ghfast', label: 'ghfast.top', prefix: 'https://ghfast.top/' },
  { id: 'gitmirror', label: 'hub.gitmirror.com', prefix: 'https://hub.gitmirror.com/' },
  { id: 'moeyy', label: 'github.moeyy.xyz', prefix: 'https://github.moeyy.xyz/' },
];

/** Live state for the sidebar; the shape is serialised straight to the client. */
export const UPDATE_STATE = {
  phase: 'idle',
  current: null,
  latest: null,
  hasUpdate: false,
  notes: '',
  releaseUrl: null,
  publishedAt: null,
  asset: null,
  source: null,
  mirror: null,
  mirrors: [],
  bytes: 0,
  total: 0,
  message: '',
  error: null,
  checkedAt: null,
  restartRequired: false,
  installTarget: null,
};

let checkPromise;
let installPromise;

/** Semver-ish comparison that tolerates a leading `v` and a missing patch. */
export function compareVersions(left, right) {
  const parse = (value) => {
    const clean = String(value ?? '').trim().replace(/^v/i, '');
    const [core, pre] = clean.split('-');
    const numbers = core.split('.').map((part) => Number.parseInt(part, 10) || 0);
    while (numbers.length < 3) numbers.push(0);
    return { numbers, pre: pre ?? null };
  };
  const a = parse(left);
  const b = parse(right);
  const length = Math.max(a.numbers.length, b.numbers.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (a.numbers[index] ?? 0) - (b.numbers[index] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  if (a.pre === b.pre) return 0;
  if (a.pre === null) return 1;
  if (b.pre === null) return -1;
  return a.pre > b.pre ? 1 : -1;
}

/** Pull the digest the release notes carry next to the asset name. */
export function digestFromNotes(notes) {
  return String(notes ?? '').match(/sha256[:\s]+([0-9a-f]{64})/i)?.[1]?.toLowerCase() ?? null;
}

function normalizeRelease(json) {
  const version = String(json.tag_name ?? json.name ?? '').replace(/^v/i, '');
  if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error('release feed has no usable tag');
  const notes = typeof json.body === 'string' ? json.body : '';
  const assets = Array.isArray(json.assets) ? json.assets : [];
  const asset = assets.find((entry) => entry?.name === `dsh-rea-${version}.tgz`)
    ?? assets.find((entry) => typeof entry?.name === 'string' && entry.name.endsWith('.tgz'));
  return {
    version,
    notes,
    releaseUrl: json.html_url ?? `https://github.com/${REPOSITORY}/releases/tag/v${version}`,
    publishedAt: json.published_at ?? null,
    asset: asset
      ? { name: asset.name, size: asset.size ?? 0, url: asset.browser_download_url, sha256: digestFromNotes(notes) }
      : null,
    source: 'api.github.com',
  };
}

function normalizeManifest(json) {
  const version = String(json?.version ?? '').replace(/^v/i, '');
  if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error('manifest has no usable version');
  const assetUrl = json.asset_url
    ?? `https://github.com/${REPOSITORY}/releases/download/v${version}/dsh-rea-${version}.tgz`;
  return {
    version,
    notes: typeof json.notes === 'string' ? json.notes : '',
    releaseUrl: json.release_url ?? `https://github.com/${REPOSITORY}/releases/tag/v${version}`,
    publishedAt: json.published_at ?? null,
    asset: { name: `dsh-rea-${version}.tgz`, size: Number(json.size ?? 0), url: assetUrl, sha256: String(json.sha256 ?? '').toLowerCase() || null },
    source: 'update.json',
  };
}

/** Try every metadata source in order; only a well-formed answer wins. */
async function fetchLatest(log) {
  const attempts = [];
  const sources = [
    async () => normalizeRelease(JSON.parse(await fetchText(RELEASE_API, { timeoutMs: 12_000, maxBytes: 256 * 1024 }))),
    ...MANIFEST_SOURCES.map((url) => async () => normalizeManifest(JSON.parse(await fetchText(url, { timeoutMs: 12_000, maxBytes: 64 * 1024 })))),
  ];
  for (const [index, source] of sources.entries()) {
    try {
      return await source();
    } catch (error) {
      const label = index === 0 ? 'api.github.com' : MANIFEST_SOURCES[index - 1];
      attempts.push(`${label}: ${error.message}`);
      log?.warn?.(`dsh-rea: update metadata source ${label} failed (${error.message})`);
    }
  }
  throw new Error(`no release metadata source answered (${attempts.join('; ')})`);
}

/**
 * Ask whether a newer release exists.
 *
 * Concurrent calls share one request: the sidebar polls, and a button press
 * during a poll must not fan out into two network round trips per source.
 */
export function checkForUpdate(log, { current } = {}) {
  if (checkPromise) return checkPromise;
  checkPromise = (async () => {
    UPDATE_STATE.phase = 'checking';
    UPDATE_STATE.message = 'Checking for updates';
    UPDATE_STATE.error = null;
    UPDATE_STATE.current = current ?? UPDATE_STATE.current;
    try {
      const latest = await fetchLatest(log);
      UPDATE_STATE.latest = latest.version;
      UPDATE_STATE.hasUpdate = compareVersions(latest.version, UPDATE_STATE.current) > 0;
      UPDATE_STATE.notes = latest.notes;
      UPDATE_STATE.releaseUrl = latest.releaseUrl;
      UPDATE_STATE.publishedAt = latest.publishedAt;
      UPDATE_STATE.asset = latest.asset;
      UPDATE_STATE.source = latest.source;
      UPDATE_STATE.checkedAt = new Date().toISOString();
      UPDATE_STATE.phase = 'idle';
      UPDATE_STATE.message = UPDATE_STATE.hasUpdate
        ? `dsh-rea ${latest.version} is available`
        : `dsh-rea ${UPDATE_STATE.current} is up to date`;
      return UPDATE_STATE;
    } catch (error) {
      UPDATE_STATE.phase = 'error';
      UPDATE_STATE.error = error.message;
      UPDATE_STATE.message = 'Update check failed';
      return UPDATE_STATE;
    } finally {
      checkPromise = undefined;
    }
  })();
  return checkPromise;
}

/** The directory a swap actually replaces: a symlinked plugin updates its target. */
export function resolveInstallTarget(root = PLUGIN_ROOT) {
  try {
    return lstatSync(root).isSymbolicLink() ? realpathSync(root) : root;
  } catch {
    return root;
  }
}

async function renameWithRetry(from, to, attempts = 4) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await rename(from, to);
      return;
    } catch (error) {
      lastError = error;
      await new Promise((done) => setTimeout(done, 250 * (attempt + 1)));
    }
  }
  throw lastError;
}

/**
 * Download and install the release the last check found.
 *
 * The archive is verified *before* the running directory is touched, and the
 * swap keeps the previous tree beside it until the new one is in place, so a
 * failed update leaves a working plugin rather than a half-written one.
 */
export function installUpdate(log, { target: explicitTarget } = {}) {
  if (installPromise) return installPromise;
  installPromise = (async () => {
    try {
      const asset = UPDATE_STATE.asset;
      if (!asset?.url) throw new Error('no release asset is known; check for updates first');
      if (!asset.sha256) throw new Error('the release publishes no SHA-256, so the download cannot be verified; refusing to install');
      const target = explicitTarget ?? resolveInstallTarget();
      UPDATE_STATE.installTarget = target;
      UPDATE_STATE.error = null;
      UPDATE_STATE.restartRequired = false;

      const parent = dirname(target);
      const stamp = Date.now();
      const staging = join(parent, `.dsh-rea-update-${stamp}`);
      const archive = join(staging, asset.name);
      await mkdir(staging, { recursive: true });

      const mirrors = (Array.isArray(UPDATE_STATE.mirrors) && UPDATE_STATE.mirrors.length > 0)
        ? UPDATE_STATE.mirrors
        : DEFAULT_MIRRORS;
      const attempts = [];
      let verified = false;
      for (const mirror of mirrors) {
        UPDATE_STATE.mirror = mirror.label;
        UPDATE_STATE.bytes = 0;
        UPDATE_STATE.total = asset.size || 0;
        UPDATE_STATE.phase = 'downloading';
        UPDATE_STATE.message = `Downloading ${asset.name} via ${mirror.label}`;
        try {
          await downloadFile(`${mirror.prefix}${asset.url}`, archive, {
            onProgress: (bytes, total) => { UPDATE_STATE.bytes = bytes; if (total > 0) UPDATE_STATE.total = total; },
            retries: 1,
            log: (message) => log?.warn?.(message),
          });
          const actual = await sha256File(archive);
          if (actual !== asset.sha256) {
            throw new Error(`checksum mismatch (expected ${asset.sha256.slice(0, 12)}…, got ${actual.slice(0, 12)}…)`);
          }
          verified = true;
          break;
        } catch (error) {
          attempts.push(`${mirror.label}: ${error.message}`);
          await rm(archive, { force: true }).catch(() => {});
          log?.warn?.(`dsh-rea: update mirror ${mirror.label} failed (${error.message}); trying the next one`);
        }
      }
      if (!verified) {
        throw new Error(`every update mirror failed (${attempts.join('; ')})`);
      }

      UPDATE_STATE.phase = 'extracting';
      UPDATE_STATE.message = 'Verifying and extracting the package';
      const extracted = join(staging, 'extracted');
      await mkdir(extracted, { recursive: true });
      await extractArchive(archive, extracted, { log: (message) => log?.warn?.(message) });
      const packageRoot = join(extracted, 'package');
      if (!existsSync(join(packageRoot, 'index.js')) || !existsSync(join(packageRoot, 'package.json'))) {
        throw new Error('the downloaded archive does not look like a dsh-rea package');
      }
      const manifest = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
      if (compareVersions(manifest.version, UPDATE_STATE.latest) !== 0) {
        throw new Error(`the archive contains ${manifest.version}, expected ${UPDATE_STATE.latest}`);
      }
      if (compareVersions(manifest.version, UPDATE_STATE.current) <= 0) {
        throw new Error(`the archive contains ${manifest.version}, which is not newer than ${UPDATE_STATE.current}`);
      }

      UPDATE_STATE.phase = 'installing';
      UPDATE_STATE.message = 'Replacing the plugin directory';
      const backup = `${target}.bak-${stamp}`;
      await renameWithRetry(target, backup);
      try {
        await renameWithRetry(packageRoot, target);
      } catch (error) {
        await renameWithRetry(backup, target).catch(() => {});
        throw new Error(`could not move the new version into place (${error.message}); the previous version was restored`);
      }
      await rm(staging, { recursive: true, force: true }).catch(() => {});
      // Keep the tree that was just replaced; older backups are 30 MB each and
      // only the immediately previous one is a usable rollback target.
      try {
        const base = basename(target);
        for (const name of await readdir(parent)) {
          if (name.startsWith(`${base}.bak-`) && join(parent, name) !== backup) {
            await rm(join(parent, name), { recursive: true, force: true }).catch(() => {});
          }
        }
      } catch {}
      UPDATE_STATE.phase = 'restart-required';
      UPDATE_STATE.restartRequired = true;
      UPDATE_STATE.current = manifest.version;
      UPDATE_STATE.message = `dsh-rea ${manifest.version} installed; restart the session to load it`;
      log?.info?.(`dsh-rea: updated to ${manifest.version} from ${target}; previous tree kept at ${backup}`);
      return UPDATE_STATE;
    } catch (error) {
      UPDATE_STATE.phase = 'error';
      UPDATE_STATE.error = error.message;
      UPDATE_STATE.message = 'Update failed';
      return UPDATE_STATE;
    } finally {
      installPromise = undefined;
    }
  })();
  return installPromise;
}

/** A copy safe to serialise into the sidebar payload. */
export function updateStatus(version) {
  UPDATE_STATE.current = UPDATE_STATE.current ?? version ?? null;
  return {
    current: UPDATE_STATE.current,
    phase: UPDATE_STATE.phase,
    latest: UPDATE_STATE.latest,
    hasUpdate: UPDATE_STATE.hasUpdate,
    notes: UPDATE_STATE.notes,
    releaseUrl: UPDATE_STATE.releaseUrl,
    publishedAt: UPDATE_STATE.publishedAt,
    source: UPDATE_STATE.source,
    mirror: UPDATE_STATE.mirror,
    bytes: UPDATE_STATE.bytes,
    total: UPDATE_STATE.total,
    message: UPDATE_STATE.message,
    error: UPDATE_STATE.error,
    checkedAt: UPDATE_STATE.checkedAt,
    restartRequired: UPDATE_STATE.restartRequired,
    asset: UPDATE_STATE.asset ? { name: UPDATE_STATE.asset.name, size: UPDATE_STATE.asset.size, sha256: UPDATE_STATE.asset.sha256 } : null,
    mirrors: (UPDATE_STATE.mirrors.length > 0 ? UPDATE_STATE.mirrors : DEFAULT_MIRRORS).map((mirror) => mirror.label),
  };
}

/** Allow `config.updateMirrors` to replace the built-in list. */
export function configureMirrors(prefixes) {
  if (!Array.isArray(prefixes) || prefixes.length === 0) {
    UPDATE_STATE.mirrors = [];
    return;
  }
  UPDATE_STATE.mirrors = prefixes
    .filter((entry) => typeof entry === 'string' && /^https?:\/\//.test(entry))
    .map((entry, index) => ({ id: `custom-${index}`, label: new URL(entry).host, prefix: entry.endsWith('/') ? entry : `${entry}/` }));
  // A custom list is an addition, not a replacement: a mistyped mirror must not
  // be able to lock the person out of the official one.
  UPDATE_STATE.mirrors = [...DEFAULT_MIRRORS, ...UPDATE_STATE.mirrors];
}
