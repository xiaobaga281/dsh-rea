/** Two cold Ghidra probes at once: before the queue this failed one of them. */
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { probeWithGhidra, ghidraLocalReadiness } from '../lib/ghidra-local.js';

const readiness = await ghidraLocalReadiness();
console.log('readiness:', readiness.ready, readiness.reason ?? '');
if (!readiness.ready) process.exit(0);

const dir = join(process.env.TEMP ?? '.', 'rea-concurrency');
mkdirSync(dir, { recursive: true });
const source = process.argv[2];
if (!existsSync(source)) throw new Error(`missing source ${source}`);
const a = join(dir, `cold-a-${Date.now()}.exe`);
const b = join(dir, `cold-b-${Date.now()}.exe`);
copyFileSync(source, a);
copyFileSync(source, b);

const started = Date.now();
const [first, second] = await Promise.all([
  probeWithGhidra(a, { rva: 0x1cb0, kind: 'code' }),
  probeWithGhidra(b, { rva: 0x1cb0, kind: 'code' }),
]);
console.log(`elapsed ${((Date.now() - started) / 1000).toFixed(1)}s`);
for (const [label, result] of [['a', first], ['b', second]]) {
  console.log(`${label}: ok=${result.ok} name=${result.name ?? '-'} reason=${(result.reason ?? '').slice(0, 80)}`);
}
process.exit(first.ok && second.ok ? 0 : 1);
