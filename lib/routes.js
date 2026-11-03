/**
 * The sidebar's HTTP surface.
 *
 * These routes let a web page change engine paths and start multi-hundred-MB
 * downloads, so they are treated as state-changing endpoints rather than as
 * read-only helpers:
 *
 *   - the method must match, and a body must be `application/json`, which a
 *     cross-site `<form>` or `text/plain` fetch cannot produce without a
 *     preflight;
 *   - a browser-supplied `Origin` must match the Host header, and
 *     `Sec-Fetch-Site` must be `same-origin` or `none`;
 *   - errors carry a real status code instead of a 200 with `ok: false`, so a
 *     failure is visible to anything that is not this sidebar.
 *
 * The last point matters beyond tidiness: `REA_APKTOOL_COMMAND` is a command
 * REA executes, so a cross-site write to it would turn one tool call into
 * running an arbitrary executable that is already on disk.
 *
 * @module dsh-rea/lib/routes
 */

const MAX_BODY_BYTES = 64 * 1024;
/** Tools the sidebar can prepare by itself. Rizin/Kuna and the commercial ones are user-supplied. */
const PREPARABLE_TOOLS = new Set(['jadx', 'apktool', 'wabt']);

function respond(response, status, payload) {
  if (!response || response.writableEnded === true) return;
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(JSON.stringify(payload));
}

/**
 * Decide whether a request may reach a handler.
 *
 * Returns `null` when it may, or `{ status, error }` when it may not. Requests
 * without an `Origin` header (curl, a test, a native client) are allowed: the
 * header is a browser-enforced signal, and demanding it would break every
 * non-browser caller while adding no protection against a browser.
 */
export function guardRequest(request, method) {
  if ((request?.method ?? 'GET') !== method) return { status: 405, error: 'method-not-allowed' };
  if (method === 'GET') return null;

  const headers = request?.headers ?? {};
  const contentType = String(headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return { status: 415, error: 'content-type must be application/json' };
  }

  const fetchSite = headers['sec-fetch-site'];
  if (typeof fetchSite === 'string' && fetchSite.length > 0 && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return { status: 403, error: 'cross-origin request refused' };
  }

  const origin = headers.origin;
  if (typeof origin === 'string' && origin.length > 0) {
    // A page loaded from `file://` reports an opaque `null` origin, and a
    // desktop shell may use its own scheme. Neither can be compared to the Host
    // header, so those fall back to the Sec-Fetch-Site check above. An http(s)
    // origin, which is what a hostile web page has, must match exactly.
    if (origin === 'null') return null;
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      return { status: 403, error: 'unparseable Origin header' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    const host = headers.host;
    if (typeof host !== 'string' || host.length === 0 || parsed.host !== host) {
      return { status: 403, error: 'cross-origin request refused' };
    }
  }
  return null;
}

/** Read a small JSON body; a parse failure is the caller's fault, so 400. */
export async function readRequestJson(request) {
  if (!request || typeof request[Symbol.asyncIterator] !== 'function') return {};
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      const error = new Error('request body too large');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0 || bytes === 0) return {};
  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('request body is not valid JSON');
    error.statusCode = 400;
    throw error;
  }
  return value && typeof value === 'object' ? value : {};
}

/**
 * Mount `/rea/*`.
 *
 * @param {object} ctx host context (only `webServer.register` is used)
 * @param {{
 *   status: () => Promise<object>,
 *   installGhidra: () => Promise<object>,
 *   installTool: (tool: string) => Promise<object>,
 *   saveConfig: (body: object) => Promise<{ changed: boolean }>,
 *   restart: (reason: string) => Promise<boolean>,
 *   log?: { warn?: (message: string) => void },
 * }} handlers
 * @returns {() => void} disposer
 */
export function mountEnvironmentRoutes(ctx, handlers) {
  if (!ctx?.webServer?.register) return () => {};

  const safeStatus = async () => {
    try {
      return await handlers.status();
    } catch (error) {
      handlers.log?.warn?.(`dsh-rea: could not read the environment status: ${error?.message ?? error}`);
      return { ok: false };
    }
  };

  const restart = async (reason) => {
    try {
      return await handlers.restart(reason);
    } catch (error) {
      handlers.log?.warn?.(`dsh-rea: restarting the REA child failed (${reason}): ${error?.message ?? error}`);
      return false;
    }
  };

  const routes = [
    {
      path: '/rea/environment',
      method: 'GET',
      async handler(_request, response) {
        respond(response, 200, await safeStatus());
      },
    },
    {
      path: '/rea/ghidra/install',
      method: 'POST',
      async handler(_request, response) {
        const installed = await handlers.installGhidra();
        const restarted = await restart('after Ghidra preparation');
        respond(response, 200, { ...(await safeStatus()), installed: installed?.path ?? null, restarted });
      },
    },
    {
      path: '/rea/engine/config',
      method: 'POST',
      async handler(request, response) {
        const body = await readRequestJson(request);
        const result = await handlers.saveConfig(body);
        // A save that changed nothing must not tear down a running analysis.
        const restarted = result.changed ? await restart('after the engine paths changed') : false;
        respond(response, 200, { ...(await safeStatus()), restarted });
      },
    },
    {
      path: '/rea/engine/install',
      method: 'POST',
      async handler(request, response) {
        const body = await readRequestJson(request);
        const tool = String(body.tool ?? '').toLowerCase();
        if (!PREPARABLE_TOOLS.has(tool)) {
          const error = new Error(`tool must be one of ${[...PREPARABLE_TOOLS].join(', ')}`);
          error.statusCode = 400;
          throw error;
        }
        const installed = await handlers.installTool(tool);
        const restarted = await restart(`after ${tool} preparation`);
        respond(response, 200, { ...(await safeStatus()), installed: tool, path: installed?.path ?? null, restarted });
      },
    },
  ];

  const disposers = routes.map(({ path, method, handler }) => ctx.webServer.register({
    kind: 'exact',
    path,
    async handler(request, response) {
      const rejection = guardRequest(request, method);
      if (rejection) {
        respond(response, rejection.status, { ok: false, error: rejection.error });
        return;
      }
      try {
        await handler(request, response);
      } catch (error) {
        const status = Number(error?.statusCode) || 500;
        const message = String(error?.message ?? error);
        handlers.log?.warn?.(`dsh-rea: ${method} ${path} failed: ${message}`);
        respond(response, status, { ok: false, ...(await safeStatus()), error: message });
      }
    },
  }));

  return () => { for (const dispose of disposers) { try { dispose?.(); } catch {} } };
}
