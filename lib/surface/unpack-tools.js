/**
 * The static unpack tool.
 *
 * Writes a new file; it never runs the sample and never modifies the source.
 * The output must not already exist unless `force` is set, so a mistyped path
 * cannot clobber an unrelated file.
 *
 * @module dsh-rea-restore/lib/unpack-tools
 */

import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';

import { unpackReadiness, unpackWithUpx } from '../dynamic/unpack.js';
import { evidenceProducer, identifyFile } from '../infra/evidence.js';

export function buildUnpackTool({ store, readiness = unpackReadiness, unpack = unpackWithUpx } = {}) {
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
      let sourceIdentity;
      try { sourceIdentity = await identifyFile(args.source); }
      catch (error) { return { text: `rea_unpack: cannot bind source bytes (${error?.message ?? error})` }; }
      const readinessState = readiness();
      if (!readinessState.ready) return { text: `rea_unpack: ${readinessState.reason}` };
      const result = await unpack({ source: args.source, output: args.output });
      if (!result.ok) return { text: `rea_unpack: ${result.reason}` };
      let artifact;
      try {
        artifact = await identifyFile(args.output);
        const sourceAfter = await identifyFile(args.source);
        if (sourceAfter.sha256 !== sourceIdentity.sha256) throw new Error('source bytes changed during unpacking');
      } catch (error) { return { text: `rea_unpack: cannot bind output bytes (${error?.message ?? error})` }; }
      const size = artifact.size;
      const text = [
        `unpacked: ${args.source} -> ${args.output}`,
        `size: ${size ?? 'unknown'} bytes | upx: ${result.version ?? result.tool} | ${result.elapsedMs} ms`,
        'the sample was not executed; run rea_triage on the output before any deep pass',
      ].join('\n');
      if (store?.write) {
        try {
          const saved = await store.write('unpack.json', JSON.stringify({ source: args.source, sourceSha256: sourceIdentity.sha256, output: args.output, size, ...result }, null, 2));
          if (!store?.writeEvidence) return { text: `${text}\n\nfull JSON: ${saved}\nreceipt: unavailable; this output cannot be applied` };
          const receipt = await store.writeEvidence({
            type: 'unpack', status: 'success', producer: evidenceProducer('rea_unpack'),
            targetSha256: sourceIdentity.sha256, artifact,
            details: { sourceSha256: sourceIdentity.sha256, upxVersion: result.version ?? null, upxPath: result.tool },
            limitations: ['static UPX unpacking does not execute the sample', 'the output is a derived PE, not the original source'],
          });
          return { text: `${text}\n\nfull JSON: ${saved}\nevidence receipt: ${receipt.receiptPath}\nevidenceId: ${receipt.evidenceId}` };
        } catch (error) {
          return { text: `${text}\n\nreceipt: not saved; this output cannot be applied (${error?.message ?? error})` };
        }
      }
      return { text: `${text}\n\nreceipt: unavailable; this output cannot be applied` };
    },
    isConcurrencySafe: () => false,
  };
}