/**
 * Run the release checks in the one order that keeps a failed gate from making
 * a later artifact look publishable. The manifest is generated from the tarball
 * that `npm pack` just produced and then verified against those same bytes.
 *
 * @module dsh-rea-restore/scripts/release/release-gate
 */
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const RELEASE_STEPS = Object.freeze([
  { label: 'default suite', args: ['test'] },
  { label: 'behaviour ladder', args: ['run', 'recon', '--', '--behavior'] },
  { label: 'engine ladder', args: ['run', 'recon', '--', '--engine'] },
  { label: 'real restore suite', args: ['run', 'test:restore-real'] },
  { label: 'static corpus gate', args: ['run', 'corpus-scan', '--', '--gate'] },
  { label: 'real corpus inventory', args: ['run', 'recon', '--', '--corpus', 'dist/corpus', '--functions', '200'] },
  { label: 'host matrix', args: ['run', 'host-matrix'] },
  { label: 'structure check', args: ['run', 'structure', '--', '--check'] },
  { label: 'pack', args: ['run', 'pack'] },
  { label: 'manifest', args: ['run', 'manifest'] },
]);

async function main() {
  const root = join(import.meta.dirname, '../..');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  for (const { label, args } of RELEASE_STEPS) {
    console.log(`\n=== ${label} ===`);
    const result = spawnSync(npm, args, {
      cwd: root,
      stdio: 'inherit',
      shell: process.platform === 'win32',
    });
    if (result.error) {
      console.error(`release gate stopped at ${label}: ${result.error.message}`);
      return 1;
    }
    if (result.status !== 0) {
      console.error(`release gate stopped at ${label} (exit ${result.status})`);
      return result.status ?? 1;
    }
  }

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const archive = join(root, 'dist', `${pkg.name}-${pkg.version}.tgz`);
  const manifest = JSON.parse(readFileSync(join(root, 'update.json'), 'utf8'));
  const bytes = readFileSync(archive);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const size = statSync(archive).size;
  if (manifest.version !== pkg.version || manifest.sha256 !== sha256 || manifest.size !== size) {
    console.error(`manifest does not describe ${archive}: expected ${sha256}/${size}, wrote ${manifest.sha256}/${manifest.size}`);
    return 1;
  }
  console.log(`\nrelease gate passed: ${archive} (${size} bytes, ${sha256.slice(0, 16)}…)`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exitCode = await main();
}