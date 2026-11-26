/**
 * Fetch the pinned real-world corpus and verify every byte against the
 * checked-in size/SHA pins before writing it under `dist/corpus`.
 *
 * @module dsh-rea-restore/scripts/corpus/fetch
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DIR = join('dist', 'corpus');
const MANIFEST = join(DIR, 'manifest.json');

/**
 * Pinned observations for the reviewed corpus. These are not upstream
 * signatures; a changed mirror or release fails closed instead of silently
 * redefining the expected bytes.
 */
export const SOURCES = [
  {
    name: '7zr.exe',
    url: 'https://www.7-zip.org/a/7zr.exe',
    project: '7-Zip standalone console',
    license: 'LGPL-2.1',
    bytes: 602624,
    sha256: '256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282',
    note: 'small C++ PE32, rich literal strings, no network code',
  },
  {
    name: 'putty.exe',
    url: 'https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe',
    project: 'PuTTY 64-bit',
    license: 'MIT',
    bytes: 1706136,
    sha256: 'd01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87',
    note: 'PE32+ with crypto constants and thousands of protocol literals',
  },
  {
    name: 'sqlite3.dll',
    url: 'https://www.sqlite.org/2024/sqlite-dll-win-x64-3460000.zip',
    project: 'SQLite library',
    license: 'Public domain',
    bytes: 3181056,
    sha256: '579fe388f0b930225492c18669f4930c00e3abef515a6328f29f8c2bc5eceefe',
    note: 'PE32+ DLL, C, exported symbols instead of an entry point',
    member: 'sqlite3.dll',
  },
];

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

export function verifyCorpusBuffer(source, buffer) {
  const digest = sha256(buffer);
  if (buffer.toString('latin1', 0, 2) !== 'MZ') return { ok: false, reason: 'not a PE file', bytes: buffer.length, sha256: digest };
  if (buffer.length !== source.bytes) return { ok: false, reason: `size ${buffer.length} != pinned ${source.bytes}`, bytes: buffer.length, sha256: digest };
  if (digest !== source.sha256) return { ok: false, reason: `SHA-256 ${digest} != pinned ${source.sha256}`, bytes: buffer.length, sha256: digest };
  return { ok: true, reason: null, bytes: buffer.length, sha256: digest };
}

function download(url, target) {
  execFileSync('curl', ['-sS', '-L', '--max-time', '180', '--retry', '2', '-o', target, url], { stdio: 'inherit' });
  const buffer = readFileSync(target);
  if (buffer.length < 1024) throw new Error(`suspiciously small download: ${buffer.length} bytes`);
  return buffer;
}

function extractMember(archivePath, member, target) {
  execFileSync('unzip', ['-o', '-j', archivePath, member, '-d', DIR], { stdio: 'ignore' });
  const produced = join(DIR, basename(member));
  if (produced !== target) execFileSync('mv', [produced, target]);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--clean')) {
    rmSync(DIR, { recursive: true, force: true });
    console.log(`removed ${DIR}`);
    return 0;
  }
  if (args.includes('--list')) {
    if (!existsSync(MANIFEST)) {
      console.log('no corpus yet; run without --list first');
      return 0;
    }
    const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
    for (const entry of manifest.files) {
      console.log(`${entry.name.padEnd(14)}${String(entry.bytes).padStart(10)}  ${entry.sha256.slice(0, 16)}  ${entry.project}`);
    }
    console.log(`${manifest.files.length} files, ${manifest.totalBytes} bytes total`);
    return 0;
  }

  mkdirSync(DIR, { recursive: true });
  const files = [];
  for (const source of SOURCES) {
    const target = join(DIR, source.name);
    if (existsSync(target)) {
      const verified = verifyCorpusBuffer(source, readFileSync(target));
      if (!verified.ok) throw new Error(`cached ${source.name} rejected: ${verified.reason}; remove the corrupt cache before fetching`);
      files.push({ ...source, cached: true });
      console.log(`cached  ${source.name.padEnd(12)} ${verified.bytes} bytes  ${verified.sha256.slice(0, 16)}`);
      continue;
    }
    process.stdout.write(`fetch   ${source.name.padEnd(12)} ${source.url}\n`);
    if (source.member) {
      const archive = join(DIR, basename(new URL(source.url).pathname));
      download(source.url, archive);
      extractMember(archive, source.member, target);
      rmSync(archive, { force: true });
    } else {
      download(source.url, target);
    }
    const verified = verifyCorpusBuffer(source, readFileSync(target));
    if (!verified.ok) throw new Error(`${source.name} rejected: ${verified.reason}`);
    files.push({ ...source, cached: false });
    console.log(`ok      ${source.name.padEnd(12)} ${verified.bytes} bytes  ${verified.sha256.slice(0, 16)}`);
  }

  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    note: 'Benign real-world binaries for a capability test. Size and SHA-256 are pinned to the reviewed local observations, not upstream signatures.',
    files: files.map(({ name, url, project, license, bytes, sha256: digest, note }) => ({ name, url, project, license, bytes, sha256: digest, note })),
    totalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
  };
  writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`\n${files.length} files, ${manifest.totalBytes} bytes -> ${DIR}`);
  console.log(`manifest ${MANIFEST}`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    process.exit(await main());
  } catch (error) {
    console.error(`corpus fetch failed: ${error?.message ?? error}`);
    process.exit(1);
  }
}
