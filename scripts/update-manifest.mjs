/**
 * Regenerate `update.json` - the metadata fallback the plugin uses when
 * `api.github.com` is unreachable.
 *
 * Run this after `npm run pack` and before publishing the release. It reads the
 * packed archive so the digest is always the one that was actually uploaded.
 */
import { createHash } from 'node:crypto';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const archive = join(root, 'dist', `dsh-rea-${pkg.version}.tgz`);

let digest = '';
let size = 0;
try {
  const bytes = readFileSync(archive);
  digest = createHash('sha256').update(bytes).digest('hex');
  size = statSync(archive).size;
} catch {
  console.error(`missing ${archive}; run "npm run pack" first`);
  process.exit(1);
}

const manifest = {
  version: pkg.version,
  tag: `v${pkg.version}`,
  asset_url: `https://github.com/xiaobaga281/dsh-rea/releases/download/v${pkg.version}/dsh-rea-${pkg.version}.tgz`,
  release_url: `https://github.com/xiaobaga281/dsh-rea/releases/tag/v${pkg.version}`,
  sha256: digest,
  size,
  published_at: new Date().toISOString(),
};

writeFileSync(join(root, 'update.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`update.json -> ${pkg.version} (${size} bytes, ${digest.slice(0, 16)}…)`);
