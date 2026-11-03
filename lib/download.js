/**
 * HTTP downloads and archive extraction.
 *
 * Four large artifacts are fetched (Ghidra is about 543 MB), so this module is
 * deliberately defensive: a bounded idle timeout instead of an unbounded hang,
 * a redirect cap, retries only for failures that can actually be retried, and a
 * `.part` file that is renamed into place only after the body is complete. A
 * failed download therefore never leaves a truncated archive behind for the
 * checksum step to trip over.
 *
 * Requests honour `HTTPS_PROXY` / `HTTP_PROXY` through a CONNECT tunnel. Node's
 * http client ignores those variables on its own, and a user behind a local
 * proxy would otherwise see every download - including this plugin's own
 * updates - fail with a connection reset while `curl` works fine.
 *
 * @module dsh-rea/lib/download
 */

import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { rename, rm } from 'node:fs/promises';
import { extname } from 'node:path';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

const USER_AGENT = 'dsh-rea';
const MAX_REDIRECTS = 5;
/** A stalled socket is the failure mode that matters: bytes stop arriving. */
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_RETRIES = 2;
const EXTRACT_TIMEOUT_MS = 30 * 60_000;

const delay = (ms) => new Promise((done) => setTimeout(done, ms));

/** The proxy for this request, honouring `NO_PROXY`, or `undefined` for direct. */
export function proxyFor(parsed, env = process.env) {
  const host = parsed.hostname;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return undefined;
  const noProxy = env.NO_PROXY || env.no_proxy;
  if (typeof noProxy === 'string' && noProxy.length > 0) {
    for (const entry of noProxy.split(',').map((part) => part.trim()).filter(Boolean)) {
      if (entry === '*' || host === entry || host.endsWith(`.${entry.replace(/^\./, '')}`)) return undefined;
    }
  }
  const value = parsed.protocol === 'https:'
    ? env.HTTPS_PROXY || env.https_proxy
    : env.HTTP_PROXY || env.http_proxy;
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * GET a URL and resolve with the response stream.
 *
 * Direct connections behave exactly as before; a proxy is only consulted when
 * one is configured, using CONNECT so HTTPS keeps its end-to-end TLS.
 */
export function getResponse(parsed, { headers = {}, timeoutMs = DEFAULT_IDLE_TIMEOUT_MS, proxy = proxyFor(parsed) } = {}) {
  return new Promise((resolveResponse, rejectResponse) => {
    if (!proxy) {
      const transport = parsed.protocol === 'http:' ? http : https;
      const request = transport.get(parsed, { headers }, resolveResponse);
      request.setTimeout(timeoutMs, () => request.destroy(Object.assign(
        new Error(`request to ${parsed.hostname} timed out after ${timeoutMs}ms`), { transient: true },
      )));
      request.on('error', rejectResponse);
      return;
    }

    let proxyUrl;
    try {
      proxyUrl = new URL(proxy);
    } catch {
      rejectResponse(new Error(`invalid proxy URL: ${proxy}`));
      return;
    }
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    const authority = `${parsed.hostname}:${port}`;
    const connectHeaders = { host: authority };
    if (proxyUrl.username) {
      const credentials = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password ?? '')}`;
      connectHeaders['proxy-authorization'] = `Basic ${Buffer.from(credentials).toString('base64')}`;
    }
    const tunnel = http.request({
      host: proxyUrl.hostname,
      port: Number(proxyUrl.port || 80),
      method: 'CONNECT',
      path: authority,
      headers: connectHeaders,
      timeout: timeoutMs,
    });
    tunnel.once('connect', (response, socket) => {
      if (response.statusCode !== 200) {
        socket.destroy();
        rejectResponse(new Error(`proxy CONNECT to ${authority} failed with HTTP ${response.statusCode}`));
        return;
      }
      const send = (connection) => {
        const request = (parsed.protocol === 'http:' ? http : https).request({
          host: parsed.hostname,
          port: Number(port),
          path: `${parsed.pathname}${parsed.search}`,
          method: 'GET',
          headers,
          agent: false,
          createConnection: () => connection,
        });
        request.setTimeout(timeoutMs, () => request.destroy(Object.assign(
          new Error(`request to ${parsed.hostname} timed out after ${timeoutMs}ms`), { transient: true },
        )));
        request.once('response', resolveResponse);
        request.once('error', rejectResponse);
        request.end();
      };
      if (parsed.protocol === 'http:') {
        send(socket);
        return;
      }
      const secured = tls.connect({ socket, servername: parsed.hostname }, () => send(secured));
      secured.once('error', rejectResponse);
    });
    tunnel.once('timeout', () => tunnel.destroy(Object.assign(
      new Error(`proxy connect to ${authority} timed out after ${timeoutMs}ms`), { transient: true },
    )));
    tunnel.once('error', rejectResponse);
    tunnel.end();
  });
}

/** Parse a URL and reject anything that is not http/https. */
function parseTarget(url, reject) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    reject(new Error(`invalid URL: ${url}`));
    return undefined;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    reject(new Error(`refusing ${parsed.protocol}: only http/https are allowed`));
    return undefined;
  }
  return parsed;
}

/**
 * One GET, one response, written to `target`.
 *
 * `onProgress` sees every chunk so a caller can publish a byte counter. HTTP
 * errors carry `transient` when a retry is worth attempting; network errors
 * carry no flag, and the caller treats those as retryable by default.
 */
function fetchToFile(url, target, { onProgress, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, redirects = 0 } = {}) {
  return new Promise((resolveDownload, rejectDownload) => {
    const parsed = parseTarget(url, rejectDownload);
    if (parsed === undefined) return;

    getResponse(parsed, { headers: { 'user-agent': USER_AGENT, accept: '*/*' }, timeoutMs: idleTimeoutMs }).then((response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        if (redirects >= MAX_REDIRECTS) {
          rejectDownload(new Error(`too many redirects while downloading ${url}`));
          return;
        }
        const next = new URL(response.headers.location, parsed).toString();
        fetchToFile(next, target, { onProgress, idleTimeoutMs, redirects: redirects + 1 }).then(resolveDownload, rejectDownload);
        return;
      }
      if (status !== 200) {
        response.resume();
        const error = new Error(`download returned HTTP ${status}`);
        error.transient = status === 408 || status === 425 || status === 429 || status >= 500;
        rejectDownload(error);
        return;
      }
      const total = Number(response.headers['content-length'] ?? 0) || 0;
      let received = 0;
      let settled = false;
      const output = createWriteStream(target);
      const fail = (error) => {
        if (settled) return;
        settled = true;
        response.destroy();
        output.destroy();
        rejectDownload(error);
      };
      output.on('error', fail);
      output.on('finish', () => {
        if (settled) return;
        settled = true;
        output.close(() => resolveDownload({ bytes: received, total }));
      });
      response.on('error', fail);
      response.on('aborted', () => fail(new Error('the download was aborted')));
      response.setTimeout(idleTimeoutMs, () => {
        fail(Object.assign(new Error(`the download stalled for ${idleTimeoutMs}ms`), { transient: true }));
      });
      response.on('data', (chunk) => {
        received += chunk.length;
        onProgress?.(received, total);
      });
      response.pipe(output);
    }, rejectDownload);
  });
}

/**
 * Download `url` to `target`, retrying transient failures.
 *
 * The body lands in `<target>.part` and is only renamed after the stream
 * finishes, so `target` is either absent, the previous complete file, or the
 * new complete file - never a half-written one.
 */
export async function downloadFile(url, target, { onProgress, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, retries = DEFAULT_RETRIES, log } = {}) {
  const part = `${target}.part`;
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      await rm(part, { force: true });
      const result = await fetchToFile(url, part, { onProgress, idleTimeoutMs });
      await rm(target, { force: true });
      await rename(part, target);
      return result;
    } catch (error) {
      lastError = error;
      await rm(part, { force: true }).catch(() => {});
      const retryable = error?.transient !== false;
      if (attempt === retries || !retryable) break;
      log?.(`dsh-rea: download attempt ${attempt + 1} failed (${error.message}); retrying`);
      await delay(500 * (attempt + 1));
    }
  }
  throw lastError ?? new Error('download failed');
}

/**
 * Fetch a small text document - release metadata or a manifest.
 *
 * Deliberately separate from `downloadFile`: these responses are a few KB, must
 * not touch the disk, and a mirror that returns an HTML error page is a failure
 * the caller wants to hear about immediately rather than after a 30 MB write.
 */
export async function fetchText(url, { timeoutMs = 15_000, maxBytes = 512 * 1024, redirects = 0 } = {}) {
  return new Promise((resolveText, rejectText) => {
    const parsed = parseTarget(url, rejectText);
    if (parsed === undefined) return;

    getResponse(parsed, {
      headers: { 'user-agent': USER_AGENT, accept: 'application/json, text/plain, */*' },
      timeoutMs,
    }).then((response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        if (redirects >= MAX_REDIRECTS) {
          rejectText(new Error(`too many redirects while fetching ${url}`));
          return;
        }
        const next = new URL(response.headers.location, parsed).toString();
        fetchText(next, { timeoutMs, maxBytes, redirects: redirects + 1 }).then(resolveText, rejectText);
        return;
      }
      if (status !== 200) {
        response.resume();
        rejectText(new Error(`HTTP ${status} for ${url}`));
        return;
      }
      response.setEncoding('utf8');
      let text = '';
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += Buffer.byteLength(chunk);
        if (bytes > maxBytes) {
          response.destroy();
          rejectText(new Error(`response from ${url} exceeded ${maxBytes} bytes`));
          return;
        }
        text += chunk;
      });
      response.on('end', () => resolveText(text));
      response.on('error', rejectText);
    }, rejectText);
  });
}

/**
 * Run a helper process to completion, capturing a bounded amount of stderr.
 * Never rejects: a missing binary and a non-zero exit both surface as a code.
 */
export function run(command, args, { timeoutMs } = {}) {
  return new Promise((resolveRun) => {
    let child;
    try {
      child = spawn(command, args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
    } catch (error) {
      resolveRun({ code: -1, stderr: String(error?.message ?? error) });
      return;
    }
    let stderr = '';
    let timer;
    let settled = false;
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveRun({ code, stderr });
    };
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk) => { if (stderr.length < 8 * 1024) stderr += chunk; });
    if (timeoutMs) {
      timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
      timer.unref?.();
    }
    child.once('error', (error) => { stderr += String(error?.message ?? error); finish(-1); });
    child.once('exit', (code) => finish(code ?? -1));
  });
}

/**
 * Extract an archive into `target`.
 *
 * `.zip` is tried with `tar` first because Windows ships bsdtar, which reads
 * zip; GNU tar on Linux does not, so `unzip` is the fallback there. Failure
 * names both attempts, because "tar exited 2" alone is not actionable.
 *
 * `--force-local` is retried automatically: GNU tar (the one Git for Windows
 * puts first on PATH) reads the drive colon in `C:\...` as a remote host and
 * fails with "Cannot connect to C". bsdtar does not accept the flag, so it is
 * only ever added after a plain attempt has already failed.
 */
export async function extractArchive(archive, target, { log } = {}) {
  const extension = extname(archive).toLowerCase();
  if (extension === '.zip') {
    const viaTar = await runTar(['-xf', tarPath(archive), '-C', tarPath(target)]);
    if (viaTar.code === 0) return 'tar';
    log?.(`dsh-rea: tar could not read ${archive} (exit ${viaTar.code}); trying unzip`);
    const viaUnzip = await run('unzip', ['-q', '-o', archive, '-d', target], { timeoutMs: EXTRACT_TIMEOUT_MS });
    if (viaUnzip.code === 0) return 'unzip';
    throw new Error(
      `could not extract ${archive}: tar said "${viaTar.stderr.slice(0, 200).trim()}", unzip said "${viaUnzip.stderr.slice(0, 200).trim()}". Install unzip (or extract the archive by hand into ${target}).`,
    );
  }
  if (extension === '.gz' || extension === '.tgz') {
    const result = await extractTarball(archive, target);
    if (result.code === 0) return 'tar';
    throw new Error(`could not extract ${archive} (tar exit ${result.code}): ${result.stderr.slice(0, 300).trim()}`);
  }
  throw new Error(`unsupported archive type: ${archive}`);
}

/** GNU tar misreads a Windows drive letter as a host; retry with `--force-local`. */
const needsForceLocal = (stderr) => /Cannot connect to|resolve failed/i.test(stderr ?? '');

/** tar on Windows is MSYS-aware: forward slashes work, backslashes do not. */
const tarPath = (value) => (process.platform === 'win32' ? String(value).replace(/\\/g, '/') : value);

async function runTar(args, { timeoutMs = EXTRACT_TIMEOUT_MS, log } = {}) {
  const first = await run('tar', args, { timeoutMs });
  if (first.code === 0 || !needsForceLocal(first.stderr)) return first;
  log?.(`dsh-rea: tar treated the drive letter as a remote host; retrying with --force-local`);
  return run('tar', ['--force-local', ...args], { timeoutMs });
}

/** `tar -xzf` with the same GNU-tar fallback; used for the vendored runtime too. */
export function extractTarball(archive, target, { timeoutMs = EXTRACT_TIMEOUT_MS, log } = {}) {
  return runTar(['-xzf', tarPath(archive), '-C', tarPath(target)], { timeoutMs, log });
}
