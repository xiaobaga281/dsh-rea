import test from 'node:test';
import assert from 'node:assert/strict';
import { HASH_ALGORITHMS, resolveImports } from '../lib/api-hash.js';

/** A .rdata-shaped buffer holding a ROR13 table, padded so it starts aligned. */
function table(apis) {
  const buffer = Buffer.alloc(apis.length * 4 + 16);
  apis.forEach((api, index) => buffer.writeUInt32LE(HASH_ALGORITHMS.ror13(api), 8 + index * 4));
  return buffer;
}

const directory = (names) => ({
  dlls: [{ dll: 'KERNEL32.dll', functions: names }],
  apiFlat: [...names],
  ordinals: 0,
  truncated: false,
  empty: false,
});

test('a full import directory does not stop the hash scan', () => {
  // The old code returned early at 24 named imports, on the assumption that a
  // populated directory is a complete one. D10 is 26 unused exports beside the
  // real table, and the tool reported one of nine capabilities.
  const names = Array.from({ length: 26 }, (_, index) => `Api${index}`);
  const merged = resolveImports(
    table(['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread']),
    directory(names),
  );
  assert.ok(merged.apiFlat.includes('IsDebuggerPresent'), 'the hashed name must survive the merge');
  assert.ok(merged.apiFlat.includes('VirtualAllocEx'));
  assert.equal(merged.overlappingSources, true, 'both sources are populated, which is the finding');
  assert.equal(merged.hashed.length, 3);
});

test('a thin directory merges without claiming a conflict', () => {
  const merged = resolveImports(
    table(['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread']),
    directory(['Sleep', 'CloseHandle']),
  );
  assert.ok(merged.apiFlat.includes('IsDebuggerPresent'));
  assert.equal(merged.overlappingSources, undefined);
});

test('no hash table leaves the directory exactly as it was', () => {
  const names = Array.from({ length: 26 }, (_, index) => `Api${index}`);
  const original = directory(names);
  const merged = resolveImports(Buffer.alloc(64), original);
  assert.equal(merged, original, 'same object: nothing to merge, nothing to reallocate');
  assert.equal(merged.overlappingSources, undefined);
});

test('a directory that already names every hashed function is not a conflict', () => {
  const merged = resolveImports(
    table(['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread']),
    directory(['IsDebuggerPresent', 'VirtualAllocEx', 'CreateRemoteThread']),
  );
  assert.equal(merged.overlappingSources, undefined, 'nothing was added, so there is no second source');
});

test('scattered single matches are coincidence, not a hash table', () => {
  // A 28 MB installer produced five of these: dwords that happen to equal a
  // known hash and have no neighbours. A real table is an array.
  const api = 'IsDebuggerPresent';
  const buffer = Buffer.alloc(4096);
  for (const at of [0x100, 0x600, 0xa00]) buffer.writeUInt32LE(HASH_ALGORITHMS.ror13(api), at);
  const merged = resolveImports(buffer, directory(['Sleep']));
  assert.equal(merged.apiFlat.includes(api), false, 'three isolated hits are still not a table');
});
