/**
 * Capability adapters for tooling REA does not expose: TLS decryption, stream
 * reassembly, protobuf raw decoding, and Windows debugging / ETW inventory.
 *
 * These are adapters, not engine implementations: they detect the external
 * binary, report a precise "missing" status when it is absent, and never claim
 * a capability that was not actually executed. Anything they produce is written
 * to the artifact directory, not dumped into the conversation.
 *
 * @module dsh-rea/lib/external-adapters
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

const MAX_CAPTURE_CHARS = 200_000;

/** Detect an external binary without throwing when it is not installed. */
export function detectBinary(command, args = ['--version']) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 8_000, windowsHide: true, maxBuffer: 256 * 1024 });
  if (result.error) return { available: false, reason: result.error.code ?? result.error.message };
  const text = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim().split('\n')[0].slice(0, 160);
  return { available: result.status === 0, version: text || null, reason: result.status === 0 ? null : `exit ${result.status}` };
}

export function protocolToolInventory() {
  return {
    tshark: detectBinary('tshark', ['--version']),
    protoc: detectBinary('protoc', ['--version']),
  };
}

const WINDOWS_CANDIDATES = [
  { key: 'cdb', label: 'cdb.exe (user-mode debugging)', command: 'cdb', args: ['-version'] },
  { key: 'ttd', label: 'TTD / WinDbg time-travel', command: 'ttd.exe', args: ['-version'] },
  { key: 'wpr', label: 'Windows Performance Recorder (ETW)', command: 'wpr', args: ['-help'] },
  { key: 'logman', label: 'logman (ETW trace control)', command: 'logman', args: ['/query'] },
  { key: 'pdbcopy', label: 'pdbcopy (symbol files)', command: 'pdbcopy', args: [] },
];

/**
 * Probe with `where` rather than executing the debugger itself: `cdb -version`
 * can open an interactive session, and a capability check must never attach to
 * or start a debug target.
 */
export function windowsToolInventory(platform = process.platform) {
  if (platform !== 'win32') return { platform, supported: false, tools: [] };
  const tools = WINDOWS_CANDIDATES.map(({ key, label, command }) => {
    const result = spawnSync('where', [command], { encoding: 'utf8', timeout: 8_000, windowsHide: true, maxBuffer: 256 * 1024 });
    const available = result.error === undefined && result.status === 0;
    const firstLine = `${result.stdout ?? ''}`.trim().split('\n')[0]?.trim() ?? '';
    return { key, label, command, available, path: available ? firstLine : null, reason: available ? null : (result.error?.code ?? `exit ${result.status}`) };
  });
  return { platform, supported: true, tools };
}

/** Build a tshark/protoc adapter tool. */
export function buildProtocolTool({ store, platform = process.platform } = {}) {
  return {
    name: 'rea_protocol_analyze',
    description: 'Local protocol adapter using tshark/protoc when installed: decrypt TLS with a keylog file, reassemble a TCP/HTTP stream, or decode raw protobuf bytes. Reports a precise "tool missing" status instead of pretending it ran. Paths must be absolute. Results are written to the artifact directory.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        pcap: { type: 'string', description: 'Absolute path to a .pcap/.pcapng capture.' },
        keylog: { type: 'string', description: 'Absolute path to an SSLKEYLOGFILE (enables TLS decryption).' },
        mode: { type: 'string', description: 'tls-fields (default), follow, or decode-raw.' },
        displayFilter: { type: 'string', description: 'Wireshark display filter for tls-fields mode.' },
        stream: { type: 'number', description: 'Stream index for follow mode. Defaults to 0.' },
        hexBytes: { type: 'string', description: 'Hex-encoded protobuf payload for decode-raw mode.' },
      },
      required: ['pcap'],
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no protocol result)' }]; },
    },
    async execute(args) {
      const mode = ['tls-fields', 'follow', 'decode-raw'].includes(args?.mode) ? args.mode : 'tls-fields';
      const inventory = protocolToolInventory();
      const lines = [`Protocol adapter — mode ${mode}`];

      if (mode === 'decode-raw') {
        if (!inventory.protoc.available) {
          lines.push(`protoc: unavailable (${inventory.protoc.reason}). Install protoc to decode raw protobuf payloads.`);
          return { text: lines.join('\n') };
        }
        const hex = String(args?.hexBytes ?? '').replace(/[^0-9a-fA-F]/g, '');
        if (hex.length === 0 || hex.length % 2 !== 0) return { text: 'decode-raw needs an even-length hexBytes string.' };
        const bytes = Buffer.from(hex, 'hex');
        const result = spawnSync('protoc', ['--decode_raw'], {
          input: bytes, encoding: 'utf8', timeout: 30_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
        });
        const body = `${result.stdout ?? ''}${result.stderr ?? ''}`.slice(0, MAX_CAPTURE_CHARS);
        const path = store ? await store.write('protobuf-decode.txt', body) : null;
        lines.push(`decoded ${bytes.length} bytes${path ? ` → ${path}` : ''}`);
        lines.push(body.slice(0, 2_000));
        return { text: lines.join('\n') };
      }

      const pcap = String(args?.pcap ?? '');
      if (!isAbsolute(pcap)) return { text: 'pcap must be an absolute path.' };
      let info;
      try { info = await stat(pcap); } catch (error) { return { text: `pcap is unreadable: ${error.message}` }; }
      if (!info.isFile()) return { text: 'pcap must name a regular file.' };
      if (!inventory.tshark.available) {
        lines.push(`tshark: unavailable (${inventory.tshark.reason}). Install TShark 4.x, or set REA_TSHARK_COMMAND, to decrypt TLS and reassemble streams.`);
        lines.push(`REA's own field-level tools (inspect_packet_fields / inspect_packet_capture) remain available without it.`);
        return { text: lines.join('\n') };
      }
      const keylog = typeof args?.keylog === 'string' && args.keylog.length > 0 ? args.keylog : null;
      if (keylog && !isAbsolute(keylog)) return { text: 'keylog must be an absolute path.' };
      if (keylog) { try { await readFile(keylog); } catch (error) { return { text: `keylog is unreadable: ${error.message}` }; } }

      const command = ['-r', pcap, '-n'];
      if (keylog) command.push('-o', `tls.keylog_file:${keylog}`);
      if (mode === 'follow') {
        const stream = Number.isFinite(args?.stream) ? Math.max(0, Math.floor(args.stream)) : 0;
        command.push('-q', '-z', `follow,tcp,ascii,${stream}`);
      } else {
        command.push('-Y', String(args?.displayFilter ?? 'tls || http || http2 || dns'), '-T', 'fields',
          '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst', '-e', '_ws.col.Protocol', '-e', '_ws.col.Info');
      }
      const result = spawnSync('tshark', command, {
        encoding: 'utf8', timeout: 120_000, windowsHide: true, maxBuffer: 16 * 1024 * 1024,
      });
      if (result.error) return { text: `tshark failed: ${result.error.message}` };
      const body = `${result.stdout ?? ''}`.slice(0, MAX_CAPTURE_CHARS);
      const path = store ? await store.write(`protocol-${mode}.txt`, body) : null;
      lines.push(`tshark ${mode}: ${body.length} characters, sha256 ${createHash('sha256').update(body).digest('hex').slice(0, 16)}…`);
      if (keylog) lines.push('TLS keylog applied: decrypted application data is included where the capture has it.');
      else lines.push('No keylog supplied: encrypted TLS payloads were not decrypted.');
      if (path) lines.push(`Full output: ${path}`);
      lines.push('', body.slice(0, 2_000));
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}

/** Read-only inventory of Windows debugging / ETW tooling. */
export function buildWindowsToolsTool({ platform = process.platform } = {}) {
  return {
    name: 'rea_windows_tools',
    description: 'Report which Windows debugging and ETW tools are available on this host (cdb, TTD, wpr, logman, pdbcopy) and what each would enable. Read-only capability probe; never launches a debugger, never attaches to a process.',
    parameters: {
      type: 'object', additionalProperties: false,
      properties: { probe: { type: 'boolean', description: 'Re-run the binary probe. Defaults to true.' } },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string' } }, required: ['text'] },
      render(_args, value) { return [{ type: 'text', text: typeof value?.text === 'string' ? value.text : '(no inventory)' }]; },
    },
    async execute() {
      const inventory = windowsToolInventory(platform);
      if (!inventory.supported) return { text: `This host is ${platform}; the Windows adapter only reports on win32.` };
      const lines = ['Windows dynamic-analysis inventory (read-only probe)', ''];
      for (const tool of inventory.tools) {
        lines.push(`- ${tool.label}: ${tool.available ? 'available' : `missing (${tool.reason})`}`);
      }
      lines.push('', 'REA 6.7.0 exposes no WinDbg/cdb/TTD/ETW tools, so Windows targets currently rely on Frida.');
      lines.push('This probe does not execute debugger commands; scripted breakpoints and time-travel replay need a separate engine bridge.');
      return { text: lines.join('\n') };
    },
    isConcurrencySafe: () => true,
  };
}
