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
 * @module dsh-rea/lib/download
 */

import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { rename, rm } from 'node:fs/promises';
import { extname } from 'node:path';
import http from 'node:http';
import https from 'node:https';

const USER_AGENT = 'dsh-rea';
const MAX_REDIRECTS = 5;
/** A stalled socket is the failure mode that matters: bytes stop arriving. */
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_RETRIES = 2;
const EXTRACT_TIMEOUT_MS = 30 * 60_000;

const delay = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * One GET, one response, written to `target`.
 *
 * `onProgress` sees every chunk so a caller can publish a byte counter. HTTP
 * errors carry `transient` when a retry is worth attempting; network errors
 * carry no flag, and the caller treats those as retryable by default.
 */
function fetchToFile(url, target, { onProgress, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, redirects = 0 } = {}) {
  return new Promise((resolveDownload, rejectDownload) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      rejectDownload(new Error(`invalid download URL: ${url}`));
      return;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      rejectDownload(new Error(`refusing to download from ${parsed.protocol} (only http/https are allowed)`));
      return;
    }
    const transport = parsed.protocol === 'http:' ? http : https;
    const request = transport.get(parsed, { headers: { 'user-agent': USER_AGENT, accept: '*/*' } }, (response) => {
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
      response.on('data', (chunk) => {
        received += chunk.length;
        onProgress?.(received, total);
      });
      response.pipe(output);
    });
    request.setTimeout(idleTimeoutMs, () => {
      const error = new Error(`the download stalled for ${idleTimeoutMs}ms`);
      error.transient = true;
      request.destroy(error);
    });
    request.on('error', (error) => rejectDownload(error));
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
 */
export async function extractArchive(archive, target, { log } = {}) {
  const extension = extname(archive).toLowerCase();
  if (extension === '.zip') {
    const viaTar = await run('tar', ['-xf', archive, '-C', target], { timeoutMs: EXTRACT_TIMEOUT_MS });
    if (viaTar.code === 0) return 'tar';
    log?.(`dsh-rea: tar could not read ${archive} (exit ${viaTar.code}); trying unzip`);
    const viaUnzip = await run('unzip', ['-q', '-o', archive, '-d', target], { timeoutMs: EXTRACT_TIMEOUT_MS });
    if (viaUnzip.code === 0) return 'unzip';
    throw new Error(
      `could not extract ${archive}: tar said "${viaTar.stderr.slice(0, 200).trim()}", unzip said "${viaUnzip.stderr.slice(0, 200).trim()}". Install unzip (or extract the archive by hand into ${target}).`,
    );
  }
  if (extension === '.gz' || extension === '.tgz') {
    const result = await run('tar', ['-xzf', archive, '-C', target], { timeoutMs: EXTRACT_TIMEOUT_MS });
    if (result.code === 0) return 'tar';
    throw new Error(`could not extract ${archive} (tar exit ${result.code}): ${result.stderr.slice(0, 300).trim()}`);
  }
  throw new Error(`unsupported archive type: ${archive}`);
}
