/**
 * Host half of `dsh-rea`.
 *
 * REA (github.com/morluto/rea, npm package `rea-agents`, MIT) ships a stdio MCP
 * server (`rea mcp`) carrying a very large tool catalog - roughly 207 tools for
 * native binaries, archives, JavaScript/Electron, APKs, browsers, packets,
 * firmware and static-artifact inspection. This package wires that server into
 * the Harness itself rather than through an MCP bridge row, because a bridge row
 * has to state the child's command in YAML, while here the path is resolved once
 * from the vendored package beside this file.
 *
 * What is registered:
 *
 *   - tools: every REA tool as `mcp__rea__<tool>`, with the server's own input
 *     schema. The public-name contract (64 chars, [A-Za-z0-9_-], lossy-change
 *     hash) is the same one the shipped MCP bridge uses, so a name registered
 *     here can never collide with one registered through a bridge row.
 *   - skills: the upstream `reverse-engineer-anything` skill and its reference
 *     documents, installed into the user DSH skills directory so the
 *     filesystem skill provider discovers them.
 *   - one own tool: `rea_doctor`, a read-only readiness report from REA itself,
 *     plus `rea_catalog`, the index for the deferred catalog.
 *
 * The runtime is shipped as a compressed archive and unpacked on first
 * activation into the DSH home, so the bundle itself stays small while the
 * closure of REA's dependencies - which lazy `require`s several packages only
 * on specific code paths - stays complete.
 *
 * The child runs on the Harness's own node with absolute paths: no npx, no
 * network, no npm cache at call time. It is spawned once and supervised: if it
 * exits, the catalog is re-synced after a bounded backoff while the tools stay
 * registered (calls fail loudly meanwhile), and disposal closes the transport.
 *
 * @module dsh-rea
 */

import { readFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

import { DESTRUCTIVE_TOOLS, MUTATING_TOOLS, createArtifactStore, sessionArtifactRoot } from './lib/artifacts.js';
import { childEnvironment, resolveConfig } from './lib/config.js';
import {
  ENGINE_ENV_OVERRIDES, applyGhidraEnvironment, detectGhidra, engineConfigSignature,
  environmentStatus, installExternalTool, installGhidra, saveEnginePaths,
} from './lib/engines.js';
import { ReaMcpClient } from './lib/mcp-client.js';
import { DSH_HOME, PLUGIN_ROOT, WORKSPACE_DIR } from './lib/paths.js';
import { createToolRegistry } from './lib/registry.js';
import { mountEnvironmentRoutes } from './lib/routes.js';
import { installSkill, resolveReaPackage } from './lib/runtime.js';
import { buildCatalogTool, buildDoctorTool, buildReadArtifactTool, buildStatusTool, buildTool, publicToolName, textOf } from './lib/tools.js';
import { checkForUpdate, configureMirrors, installUpdate, updateStatus } from './lib/update.js';

/** Services this plugin needs; `tools` is the registry REA's catalog lands in. */
export const inject = ['tools', 'webServer'];

/** How long to wait between respawns, and how many attempts before stopping. */
const RECONNECT_DELAY_MS = 2_000;
const RECONNECT_MAX_ATTEMPTS = 5;

const PLUGIN_VERSION = (() => {
  try {
    return JSON.parse(readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8')).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

/**
 * A locale lookup, when the Host exposes one.
 *
 * Guarded rather than injected: declaring `locale` in `inject` would make the
 * whole plugin fail to activate on a Host that does not provide it, and the
 * fallback string is already correct English.
 */
function translator(ctx) {
  return (key, fallback) => {
    try {
      const locale = typeof ctx?.get === 'function' ? ctx.get('locale') : undefined;
      const value = typeof locale?.t === 'function' ? locale.t(key) : undefined;
      return typeof value === 'string' && value.length > 0 ? value : fallback;
    } catch {
      return fallback;
    }
  };
}

/**
 * Plugin entry: connect one REA MCP child and register its tools.
 *
 * Startup is awaited, so a broken runtime is visible immediately instead of
 * failing on the first model call. The child is supervised for the lifetime of
 * the plugin: if it exits, the catalog is re-synced after a bounded backoff
 * while the tools stay listed; disposal closes the transport.
 */
export async function apply(ctx, rawConfig = {}) {
  const config = resolveConfig(rawConfig);
  const log = {
    info: (message) => { try { ctx.logger?.info?.(message); } catch {} },
    warn: (message) => { try { ctx.logger?.warn?.(message); } catch {} },
    error: (message) => { try { ctx.logger?.error?.(message); } catch {} },
  };

  // The runtime is resolved (and unpacked, on first activation) before anything
  // else, so every later step can rely on its absolute entrypoint.
  const reaPackage = await resolveReaPackage(log);
  const REA_ENTRY = reaPackage ? join(reaPackage, 'scripts', 'rea.mjs') : undefined;
  const REA_VERSION = (() => {
    try {
      return JSON.parse(readFileSync(join(reaPackage, 'package.json'), 'utf8')).version ?? 'unknown';
    } catch {
      return 'unknown';
    }
  })();
  const REA_SKILL_DIR = reaPackage ? join(reaPackage, 'skills', 'reverse-engineer-anything') : undefined;
  config.reaVersion = REA_VERSION;
  configureMirrors(config.updateMirrors);

  // Results that do not fit the budget are written here and paged on demand;
  // the same directory carries the audit trail for state-changing calls.
  const artifacts = createArtifactStore({
    root: sessionArtifactRoot(join(DSH_HOME, 'rea-artifacts')),
    maxChars: config.maxResultChars,
  });

  const statusPayload = async () => ({
    ...(await environmentStatus()),
    version: PLUGIN_VERSION,
    update: updateStatus(PLUGIN_VERSION),
  });

  /**
   * Refuse the four operations that remove or overwrite something on a device
   * unless the row opts in, and record every state-changing call.
   */
  const guardTool = (name, args) => {
    if (DESTRUCTIVE_TOOLS.has(name) && !config.allowDeviceMutations) {
      return `${name} changes the attached device and is disabled. Set "allowDeviceMutations: true" on the dsh-rea row if that is intended.`;
    }
    if (MUTATING_TOOLS.has(name)) void artifacts.audit({ tool: name, args: Object.keys(args ?? {}) });
    return undefined;
  };

  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildDoctorTool({ config, entry: REA_ENTRY, translate: translator(ctx) }));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: doctor tool');

  // The discovery index, populated by the first sync and replaced on every
  // re-sync, so it always names the tools the server actually advertises.
  const catalog = { entries: () => [] };
  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildCatalogTool(catalog));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: catalog tool');

  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildReadArtifactTool(artifacts));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: artifact reader');

  // Declared before the status tool so it can close over the live client: the
  // tool is advertised from the first turn, while the connection may still be
  // starting, failing, or being replaced.
  let client;
  const clientFacade = {
    callTool: (...args) => (client === undefined
      ? Promise.reject(new Error('the REA child is not connected'))
      : client.callTool(...args)),
  };
  ctx.effect(() => {
    const dispose = ctx.tools?.register(buildStatusTool({ client: clientFacade, engines: statusPayload, version: PLUGIN_VERSION }));
    return () => { try { dispose?.(); } catch {} };
  }, 'dsh-rea: status tool');

  if (REA_ENTRY === undefined || !config.enabled) {
    log.warn(`dsh-rea: ${REA_ENTRY === undefined ? 'the rea-agents runtime could not be resolved (the archive is missing or failed to unpack)' : 'disabled by config'}; no REA tools registered (rea_doctor still reports the state).`);
    return;
  }

  const spawnChild = () => new ReaMcpClient({
    command: process.execPath,
    args: [REA_ENTRY, 'mcp'],
    env: childEnvironment(config, process.env),
    cwd: WORKSPACE_DIR,
    version: PLUGIN_VERSION,
    toolCallTimeoutMs: config.toolCallTimeoutMs,
    log: (message) => log.warn(message),
  });

  // The child writes nothing to the workspace it inherited before: it gets its
  // own directory, so an analysis cannot dirty the project being analysed.
  await mkdir(WORKSPACE_DIR, { recursive: true }).catch(() => {});

  // If a user already has a valid Ghidra/JDK pair, use it immediately without
  // changing their process environment; only the child receives the overrides.
  applyGhidraEnvironment(await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES }));

  // The skill is installed before the connection, so a first session has both
  // halves even if the MCP handshake later fails.
  const skillPath = await installSkill({ log, skillDir: REA_SKILL_DIR, version: REA_VERSION });
  if (skillPath !== undefined) log.info(`dsh-rea: installed the reverse-engineer-anything skill at ${skillPath}`);

  const registry = createToolRegistry((definition) => ctx.tools.register(definition), {
    onError: (message) => log.warn(message),
  });

  try {
    client = spawnChild();
    await client.ready;
  } catch (error) {
    log.error(`dsh-rea: the REA MCP server did not start (${error.message}); no REA tools registered.${client?.stderr ? `\nchild stderr:\n${client.stderr}` : ''}`);
    try { await client?.dispose(); } catch {}
    return;
  }

  let syncing = false;
  let restarting;
  let attempts = 0;
  let reconnectTimer;

  async function sync() {
    const entries = await client.listTools();
    const definitions = [];
    const index = [];
    for (const entry of entries) {
      if (typeof entry?.name !== 'string') continue;
      const definition = buildTool(client, entry, config.deferCatalog, {
        spill: (name, text) => artifacts.maybeSpill(name, text),
        guard: (name, args) => guardTool(name, args),
      });
      definitions.push(definition);
      index.push({
        name: definition.name,
        description: typeof entry.description === 'string' ? entry.description : entry.name,
        parameters: definition.parameters,
      });
    }
    // The index is swapped only after the definitions exist, so a failed
    // listing cannot leave the catalog naming tools that were not registered.
    const result = registry.apply(definitions);
    catalog.entries = () => index;
    attempts = 0;
    log.info(`dsh-rea: ${result.size} REA tools registered${config.deferCatalog ? ' (deferred)' : ''}${result.failed > 0 ? `, ${result.failed} failed` : ''}`);
  }

  async function resync(reason) {
    if (syncing) return;
    syncing = true;
    try {
      await sync();
    } catch (error) {
      log.warn(`dsh-rea: tool sync failed (${reason}): ${error.message}`);
    } finally {
      syncing = false;
    }
  }

  /**
   * Replace the child, keeping the old one alive until the new one handshakes.
   *
   * The old implementation disposed first, so a failed restart left the plugin
   * with no server at all; it also never re-attached supervision, which meant a
   * child started here was never respawned again. Serialized, because two
   * concurrent sidebar actions used to spawn two children and leak one.
   */
  function restart(reason) {
    if (restarting !== undefined) return restarting;
    restarting = (async () => {
      const next = spawnChild();
      try {
        await next.ready;
      } catch (error) {
        try { await next.dispose(); } catch {}
        throw error;
      }
      const previous = client;
      client = next;
      supervise(next);
      try { await previous?.dispose(); } catch {}
      await resync(reason);
      log.info(`dsh-rea: the REA child restarted (${reason})`);
      return true;
    })().finally(() => { restarting = undefined; });
    return restarting;
  }

  if (ctx.webServer?.register) {
    const routeDispose = mountEnvironmentRoutes(ctx, {
      status: statusPayload,
      checkUpdate: () => checkForUpdate(log, { current: PLUGIN_VERSION }),
      installUpdate: () => installUpdate(log),
      installGhidra: async () => {
        const detected = await installGhidra(log);
        applyGhidraEnvironment(detected);
        return detected;
      },
      installTool: (tool) => installExternalTool(tool, log),
      saveConfig: async (body) => {
        const before = engineConfigSignature();
        const result = await saveEnginePaths(body);
        applyGhidraEnvironment(await detectGhidra({ ...process.env, ...ENGINE_ENV_OVERRIDES }));
        // Detecting after the save can add GHIDRA_INSTALL_DIR/JAVA_HOME, which
        // the running child does not have; that counts as a change.
        return { changed: result.changed || engineConfigSignature() !== before };
      },
      restart,
      log,
    });
    ctx.effect(() => routeDispose, 'dsh-rea: environment routes');
  }

  try {
    await sync();
  } catch (error) {
    log.error(`dsh-rea: the first tool sync failed: ${error.message}; no REA tools registered.`);
    try { await client.dispose(); } catch {}
    return;
  }

  /**
   * The child exiting after registration is recoverable: the tools stay listed
   * (calls fail loudly), and a fresh child replaces this one on a bounded
   * backoff. Giving up is logged explicitly so the remedy is visible.
   */
  function supervise(current) {
    if (current.supervised === true) return;
    current.supervised = true;
    current.child?.on('exit', () => {
      if (current.disposed || client !== current) return;
      if (attempts >= RECONNECT_MAX_ATTEMPTS) {
        log.error(`dsh-rea: the REA child kept exiting after ${RECONNECT_MAX_ATTEMPTS} attempts; reconnect stopped. Restart the session to try again.`);
        return;
      }
      attempts += 1;
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(() => {
        void (async () => {
          try {
            const next = spawnChild();
            await next.ready;
            client = next;
            supervise(next);
            await resync('after reconnect');
          } catch (error) {
            log.warn(`dsh-rea: reconnect attempt ${attempts} failed: ${error.message}`);
          }
        })();
      }, RECONNECT_DELAY_MS * attempts);
      reconnectTimer.unref?.();
    });
  }
  supervise(client);

  ctx.effect(() => () => {
    clearTimeout(reconnectTimer);
    registry.disposeAll();
    void client.dispose();
  }, 'dsh-rea: connection');
}

export { ReaMcpClient, buildTool, childEnvironment, publicToolName, resolveConfig, textOf };
