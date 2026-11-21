/**
 * Optional detached signature for `update.json`.
 *
 * The digest in the manifest and the archive both come from the same GitHub
 * account, so a compromised account defeats the SHA-256 check. A detached
 * minisign signature moves the trust anchor to an operator-held key. It is
 * opt-in: without `trustedManifestKey` the plugin behaves exactly as before,
 * and `pinnedSha256` remains the strongest local control.
 *
 * Signing (publisher):
 *   DSH_REA_MINISIGN_KEY=/abs/path/minisign.key npm run manifest
 *   → writes update.json.minisig next to update.json
 *
 * Verifying (consumer): set `trustedManifestKey` on the dsh-rea row to the
 * public key text; manifest sources are then required to carry a valid
 * `.minisig` or they are rejected.
 *
 * @module dsh-rea/lib/manifest-signature
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function minisignAvailable() {
  const result = spawnSync('minisign', ['-v'], { encoding: 'utf8', timeout: 5_000, windowsHide: true });
  return result.error === undefined;
}

/** Sign a manifest file. Returns {signed, reason, signaturePath}. */
export function signManifest({ manifestPath, keyPath, signaturePath = `${manifestPath}.minisig` }) {
  if (!minisignAvailable()) return { signed: false, reason: 'minisign is not installed', signaturePath: null };
  const result = spawnSync('minisign', ['-S', '-s', keyPath, '-m', manifestPath, '-x', signaturePath], {
    encoding: 'utf8', timeout: 30_000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) {
    const reason = result.error?.message ?? `${result.stdout ?? ''}${result.stderr ?? ''}`.trim().slice(0, 200);
    return { signed: false, reason: `minisign -S failed: ${reason}. An unencrypted secret key is required for non-interactive signing.`, signaturePath: null };
  }
  return { signed: true, reason: null, signaturePath };
}

/** Verify manifest text against a detached signature and a public key. */
export function verifyManifestText({ manifestText, signatureText, publicKey }) {
  if (!publicKey || !/minisign public key/i.test(String(publicKey))) {
    throw new Error('trustedManifestKey must contain a minisign public key (the line starting with "minisign public key")');
  }
  if (!minisignAvailable()) throw new Error('trustedManifestKey is set but minisign is not installed on this host');
  const dir = mkdtempSync(join(tmpdir(), 'dsh-rea-sig-'));
  try {
    const manifest = join(dir, 'update.json');
    const signature = join(dir, 'update.json.minisig');
    const key = join(dir, 'public.key');
    writeFileSync(manifest, manifestText, 'utf8');
    writeFileSync(signature, signatureText, 'utf8');
    writeFileSync(key, String(publicKey).trim(), 'utf8');
    const result = spawnSync('minisign', ['-V', '-p', key, '-m', manifest, '-x', signature], {
      encoding: 'utf8', timeout: 15_000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (result.error || result.status !== 0) {
      throw new Error(`manifest signature verification failed: ${(result.error?.message ?? `${result.stdout ?? ''}${result.stderr ?? ''}`).trim().slice(0, 200)}`);
    }
    return true;
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}
