/**
 * A stdio MCP client for one REA child process.
 *
 * The transport is hand-written on purpose: MCP stdio framing here is
 * line-delimited JSON, the catalog is large, and the whole point of the plugin
 * is that nothing stands between a tool call and the server.
 *
 * Three properties matter more than features:
 *
 *   - a call is cancellable. `tools/call` on a native binary can run for
 *     minutes; when the person stops the turn the request must be withdrawn
 *     (`notifications/cancelled`) and the waiter released, not left hanging
 *     until the timeout;
 *   - a write to a dead child cannot crash the process. `stdin` emits `EPIPE`
 *     asynchronously, and an unhandled stream error takes the Host down;
 *   - framing is bounded, so one absurd line cannot grow the buffer forever.
 *
 * @module dsh-rea/lib/mcp-client
 */

import { spawn } from 'node:child_process';

/** Default per-call budget; REA's native providers can take minutes. */
export const DEFAULT_TOOL_CALL_TIMEOUT_MS = 900_000;

/**
 * REA's own minimum stdio receive-buffer size. A value below it makes REA exit
 * with `REA_MCP_MAX_RESPONSE_BYTES: Too small` before it serves anything, so the
 * floor is asserted by the caller rather than discovered through a dead child.
 */
export const REA_MIN_MAX_RESPONSE_BYTES = 10_485_760;
export const DEFAULT_MAX_BUFFER_BYTES = REA_MIN_MAX_RESPONSE_BYTES;

const STDERR_BUDGET = 64 * 1024;
const MAX_LINE_CHARS = 64 * 1024 * 1024;
const MAX_LIST_PAGES = 50;
const DEFAULT_INITIALIZE_TIMEOUT_MS = 60_000;
const MCP_PROTOCOL_VERSION = '2025-06-18';

/** An error the caller can tell apart from a protocol failure. */
function abortError(message) {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

/**
 * Newline framing for a byte stream.
 *
 * Exported because it is the one piece of the transport that is pure logic and
 * therefore worth testing directly: chunk boundaries land anywhere, and CRLF
 * and blank lines both show up in practice.
 */
export class LineFramer {
  constructor(onLine, { maxLineChars = MAX_LINE_CHARS, onOverflow } = {}) {
    this.onLine = onLine;
    this.maxLineChars = maxLineChars;
    this.onOverflow = onOverflow;
    this.buffer = '';
  }

  push(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (line.length > 0) this.onLine(line);
    }
    if (this.buffer.length > this.maxLineChars) {
      const dropped = this.buffer.length;
      this.buffer = '';
      this.onOverflow?.(dropped);
    }
  }
}

/**
 * One REA MCP child with a JSON-RPC client over its stdio.
 *
 * Requests are matched by id, notifications are consumed, and stderr is kept
 * bounded for diagnostics after a failure.
 */
export class ReaMcpClient {
  constructor({ command, args, env, cwd, version = '0.0.0', toolCallTimeoutMs = DEFAULT_TOOL_CALL_TIMEOUT_MS, initializeTimeoutMs = DEFAULT_INITIALIZE_TIMEOUT_MS, log }) {
    this.command = command;
    this.args = args;
    this.env = env;
    this.cwd = cwd;
    this.version = version;
    this.toolCallTimeoutMs = toolCallTimeoutMs;
    this.initializeTimeoutMs = initializeTimeoutMs;
    this.log = typeof log === 'function' ? log : () => {};
    this.child = undefined;
    this.stderr = '';
    this.nextId = 1;
    this.pending = new Map();
    this.disposed = false;
    this.supervised = false;
    this.ready = this.#start();
    // A rejected `ready` is observed by the caller; this keeps Node from
    // reporting it as unhandled while activation is still unwinding.
    this.ready.catch(() => {});
  }

  /** Spawn the child, wire stdio, and complete the MCP handshake. */
  async #start() {
    this.child = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: this.env,
      cwd: this.cwd,
      windowsHide: true,
    });
    const framer = new LineFramer(
      (line) => this.#onLine(line),
      { onOverflow: (dropped) => this.log(`rea: dropped ${dropped} buffered characters that never formed a line`) },
    );
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => framer.push(chunk));
    // EPIPE arrives asynchronously after the child dies; without a listener it
    // is an unhandled 'error' event and the Host exits with it.
    this.child.stdin.on('error', (error) => this.log(`rea: child stdin error: ${error.message}`));
    let stderrBytes = 0;
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk) => {
      if (stderrBytes >= STDERR_BUDGET) return;
      this.stderr += chunk;
      stderrBytes += chunk.length;
      if (stderrBytes > STDERR_BUDGET) this.stderr = `${this.stderr.slice(0, STDERR_BUDGET)}\n[stderr truncated]`;
    });
    this.child.on('error', (error) => {
      this.log(`rea: child process error: ${error.message}`);
      this.#failAll(new Error(`the REA child process could not be started: ${error.message}`));
    });
    this.child.on('exit', (code, signal) => {
      if (this.disposed) return;
      this.#failAll(new Error(`the REA child process exited (code ${code}, signal ${signal ?? 'none'})`));
    });

    await this.request('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'dsh-rea', version: this.version },
    }, { timeoutMs: this.initializeTimeoutMs, label: 'initialize' });
    this.notify('notifications/initialized', {});
  }

  /** Parse one JSON-RPC line: answer a matching waiter, consume a notification. */
  #onLine(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      this.log(`rea: ignoring a non-JSON child line (${line.length} bytes)`);
      return;
    }
    if (typeof message.id !== 'number') return;
    const waiter = this.pending.get(message.id);
    if (waiter === undefined) return;
    this.pending.delete(message.id);
    clearTimeout(waiter.timer);
    waiter.cleanup?.();
    if (message.error !== undefined) {
      waiter.reject(new Error(message.error.message ?? JSON.stringify(message.error)));
    } else {
      waiter.resolve(message.result);
    }
  }

  /** Reject every waiter; used when the child dies or the client is disposed. */
  #failAll(error) {
    for (const waiter of this.pending.values()) {
      clearTimeout(waiter.timer);
      waiter.cleanup?.();
      waiter.reject(error);
    }
    this.pending.clear();
  }

  /**
   * Withdraw one outstanding request.
   *
   * The waiter is released locally first, so a cancel is immediate even if the
   * child never answers the notification - which is exactly the case when it is
   * busy inside a long analysis.
   */
  #withdraw(id, reason) {
    const waiter = this.pending.get(id);
    if (waiter === undefined) return;
    this.pending.delete(id);
    clearTimeout(waiter.timer);
    waiter.cleanup?.();
    this.notify('notifications/cancelled', { requestId: id, reason });
  }

  /** Send a request and await its result with a timeout; the timeout rejects. */
  request(method, params, { timeoutMs = this.toolCallTimeoutMs, signal, label } = {}) {
    if (this.disposed) return Promise.reject(new Error('the REA client is disposed'));
    if (signal?.aborted) return Promise.reject(abortError(`the ${label ?? method} call was canceled before REA received it`));
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#withdraw(id, 'timeout');
        reject(new Error(`${label ?? method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      timer.unref?.();
      const onAbort = () => {
        this.#withdraw(id, 'canceled');
        reject(abortError(`the ${label ?? method} call was canceled`));
      };
      this.pending.set(id, {
        resolve,
        reject,
        timer,
        cleanup: () => { try { signal?.removeEventListener('abort', onAbort); } catch {} },
      });
      // Registered after the waiter exists: a signal that is already aborted
      // when the listener is attached would otherwise withdraw nothing and
      // leave the waiter behind until its timeout.
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted === true) { onAbort(); return; }
      try {
        this.child.stdin.write(`${payload}\n`);
      } catch (error) {
        this.pending.delete(id);
        clearTimeout(timer);
        try { signal?.removeEventListener('abort', onAbort); } catch {}
        reject(new Error(`${label ?? method} could not be written to the REA child: ${error.message}`));
      }
    });
  }

  /** Send a notification; the child does not answer it. */
  notify(method, params) {
    if (this.disposed || this.child === undefined) return;
    try {
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
    } catch {
      // A dead child has nothing to tell; the callers see the exit path.
    }
  }

  /** `tools/list`, following the pagination cursor the protocol allows. */
  async listTools() {
    const tools = [];
    let cursor;
    for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
      const result = await this.request('tools/list', cursor === undefined ? {} : { cursor }, { timeoutMs: 180_000, label: 'tools/list' });
      if (Array.isArray(result?.tools)) tools.push(...result.tools);
      cursor = result?.nextCursor;
      if (typeof cursor !== 'string' || cursor.length === 0) break;
    }
    return tools;
  }

  /** `tools/call`; an abort withdraws the request instead of waiting it out. */
  callTool(name, args, signal) {
    return this.request('tools/call', { name, arguments: args ?? {} }, { signal, label: `tools/call ${name}` });
  }

  /** Close stdin, wait briefly, then force-kill. */
  async dispose() {
    this.disposed = true;
    this.#failAll(new Error('the REA client is disposed'));
    const child = this.child;
    if (child === undefined) return;
    try { child.stdin.end(); } catch {}
    await new Promise((resolveExit) => {
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} resolveExit(); }, 5_000);
      timer.unref?.();
      child.once('exit', () => { clearTimeout(timer); resolveExit(); });
      try { child.kill('SIGTERM'); } catch {}
    });
  }
}
