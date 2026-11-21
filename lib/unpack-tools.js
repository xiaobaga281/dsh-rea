/**
 * The static unpack tool.
 *
 * Writes a new file; it never runs the sample and never modifies the source.
 * The output must not already exist unless `force` is set, so a mistyped path
 * cannot clobber an unrelated file.
 *
 * @module dsh-rea/lib/unpack-tools
 */

import { existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';

import { unpackReadiness, unpackWithUpx } from './unpack.js';

export function buildUnpackTool({ store } = {}) {
  return {
    name: 'rea_unpack',
    description: 'Unpack a UPX-packed PE into a new file with the UPX binary (never runs the sample). Refuses when the target is not packed by UPX, so "unpack failed" is a precise statement about the packer, not a copy. Requires UPX on PATH or at .tools/upx; the output file must not exist unless force=true.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: {
        source: { type: 'string', description: 'Absolute path of the packed sample.' },
        output: { type: 'string', description: 'Absolute path for the unpacked file.' },
        force: { type: 'boolean', description: 'Overwrite an existing output file. Defaults to false.' },
      },
      required: ['source', 'output'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no unpack result)' }]; },
    },
    async execute(args) {
      for (const key of ['source', 'output']) {
        if (!isAbsolute(String(args?.[key] ?? ''))) return { text: `rea_unpack: ${key} must be an absolute path` };
      }
      if (!existsSync(args.source)) return { text: `rea_unpack: source does not exist: ${args.source}` };
      if (existsSync(args.output) && args.force !== true) {
        return { text: `rea_unpack: output already exists (${args.output}); pass force=true to overwrite it` };
      }
      const readiness = unpackReadiness();
      if (!readiness.ready) return { text: `rea_unpack: ${readiness.reason}` };
      const result = await unpackWithUpx({ source: args.source, output: args.output });
      if (!result.ok) return { text: `rea_unpack: ${result.reason}` };
      let size = null;
      try { size = statSync(args.output).size; } catch { /* the file is reported by path regardless */ }
      const text = [
        `unpacked: ${args.source} -> ${args.output}`,
        `size: ${size ?? 'unknown'} bytes | upx: ${result.tool} | ${result.elapsedMs} ms`,
        'the sample was not executed; run rea_triage on the output before any deep pass',
      ].join('\n');
      if (store?.write) {
        try {
          const saved = await store.write('unpack.json', JSON.stringify({ source: args.source, output: args.output, size, ...result }, null, 2));
          return { text: `${text}\n\nfull JSON: ${saved}` };
        } catch (error) {
          return { text: `${text}\n\nfull JSON: not saved (${error?.message ?? error})` };
        }
      }
      return { text };
    },
    isConcurrencySafe: () => false,
  };
}