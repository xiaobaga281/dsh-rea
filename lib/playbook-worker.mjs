/**
 * Playbook worker. Runs in a child process with IPC only; every `rea.call`
 * is a request to the parent, which applies the normal tool guard.
 * This file is loaded by `lib/playbook.js`, never by the host directly.
 */
const scriptUrl = process.argv[2];
const input = (() => { try { return JSON.parse(process.argv[3] ?? '{}'); } catch { return {}; } })();
const pending = new Map();
let nextId = 1;

process.on('message', (message) => {
  if (message?.type !== 'result') return;
  const entry = pending.get(message.id);
  if (!entry) return;
  pending.delete(message.id);
  if (message.ok) entry.resolve(message.value);
  else entry.reject(new Error(String(message.error ?? 'rea.call failed')));
});

globalThis.rea = {
  call(tool, args = {}) {
    return new Promise((resolvePromise, rejectPromise) => {
      const id = nextId += 1;
      pending.set(id, { resolve: resolvePromise, reject: rejectPromise });
      process.send({ type: 'call', id, tool: String(tool).replace(/^mcp__rea__/, ''), args });
    });
  },
  log(...parts) {
    process.send({ type: 'log', text: parts.map((part) => (typeof part === 'string' ? part : JSON.stringify(part))).join(' ') });
  },
};
globalThis.artifact = {
  log: globalThis.rea.log,
};

try {
  const module = await import(scriptUrl);
  const run = typeof module.default === 'function' ? module.default
    : typeof module.run === 'function' ? module.run : null;
  if (!run) throw new Error('playbook must export a default function or a named "run" function');
  const result = await run({ rea: globalThis.rea, artifact: globalThis.artifact, input });
  process.send({ type: 'done', result: result === undefined ? null : result });
} catch (error) {
  process.send({ type: 'failed', error: error?.message ?? String(error) });
}
