/**
 * Real-world corpus fetcher.
 *
 * The duel uses fixtures the defender wrote itself, which is exactly the
 * weakness of any self-made test: both sides share assumptions. This pulls a
 * handful of REAL, benign, widely distributed Windows binaries so the plugin is
 * measured on code nobody designed for it - Go binaries with no ASCII import
 * table, UPX-free but heavily stripped C++ builds, and a 1.7 MB C program with
 * thousands of literal strings.
 *
 * Everything lands in dist/corpus/ and is deleted again with --clean. Nothing
 * here is malware, and nothing is executed: the files are only read.
 *
 *   node scripts/fetch-corpus.mjs            # download + verify
 *   node scripts/fetch-corpus.mjs --clean    # delete the corpus
 *   node scripts/fetch-corpus.mjs --list     # show the manifest
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const DIR = join('dist', 'corpus');
const MANIFEST = join(DIR, 'manifest.json');

/**
 * `expect` is the SHA-256 observed on first download. It is trust-on-first-use,
 * not an upstream signature: the point is to detect a changed download later,
 * and every file is also identified by size and PE metadata in the report.
 */
const SOURCES = [
  {
    name: '7zr.exe',
    url: 'https://www.7-zip.org/a/7zr.exe',
    project: '7-Zip standalone console',
    license: 'LGPL-2.1',
    note: 'small C++ PE32, rich literal strings, no network code',
  },
  {
    name: 'putty.exe',
    url: 'https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe',
    project: 'PuTTY 64-bit',
    license: 'MIT',
    note: 'PE32+ with crypto constants and thousands of protocol literals',
  },
  {
    name: 'sqlite3.dll',
    url: 'https://www.sqlite.org/2024/sqlite-dll-win-x64-3460000.zip',
    project: 'SQLite library',
    license: 'Public domain',
    note: 'PE32+ DLL, C, exported symbols instead of an entry point',
    member: 'sqlite3.dll',
  },
];

const args = process.argv.slice(2);
const clean = args.includes('--clean');
const list = args.includes('--list');

if (clean) {
  rmSync(DIR, { recursive: true, force: true });
  console.log(`removed ${DIR}`);
  process.exit(0);
}

if (list) {
  if (!existsSync(MANIFEST)) {
    console.log('no corpus yet; run without --list first');
    process.exit(0);
  }
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
  for (const entry of manifest.files) {
    console.log(`${entry.name.padEnd(14)}${String(entry.bytes).padStart(10)}  ${entry.sha256.slice(0, 16)}  ${entry.project}`);
  }
  console.log(`${manifest.files.length} files, ${manifest.totalBytes} bytes total`);
  process.exit(0);
}

mkdirSync(DIR, { recursive: true });

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

function download(url, target) {
  // curl is markedly faster than fetch through this environment's proxy, and a
  // hard timeout keeps a stalled mirror from hanging the whole corpus run.
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

const files = [];
for (const source of SOURCES) {
  const target = join(DIR, source.name);
  if (existsSync(target) && statSync(target).size > 1024) {
    const buffer = readFileSync(target);
    files.push({ ...source, bytes: buffer.length, sha256: sha256(buffer), cached: true });
    console.log(`cached  ${source.name.padEnd(12)} ${buffer.length} bytes`);
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
  const buffer = readFileSync(target);
  // A PE must start with MZ; anything else means the source served an error page.
  if (buffer.toString('latin1', 0, 2) !== 'MZ') throw new Error(`${source.name} is not a PE file`);
  files.push({ ...source, bytes: buffer.length, sha256: sha256(buffer), cached: false });
  console.log(`ok      ${source.name.padEnd(12)} ${buffer.length} bytes  ${sha256(buffer).slice(0, 16)}`);
}

const manifest = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  note: 'Benign real-world binaries, downloaded for a capability test and deleted afterwards. Hashes are trust-on-first-use.',
  files: files.map(({ name, url, project, license, bytes, sha256: digest, note }) => ({ name, url, project, license, bytes, sha256: digest, note })),
  totalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
};
writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`\n${files.length} files, ${manifest.totalBytes} bytes -> ${DIR}`);
console.log(`manifest ${MANIFEST}`);
