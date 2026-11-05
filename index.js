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

import { classifyTool, createArtifactStore, pathOutsideScope, sessionArtifactRoot } from './lib/artifacts.js';
import { buildExportReportTool, buildProbeAddressTool, buildPurgeArtifactsTool, buildTriageTool } from './lib/analysis-tools.js';
import { childEnvironment, resolveConfig } from './lib/config.js';
import { createLimiter } from './lib/concurrency.js';
import {
  ENGINE_ENV_OVERRIDES, applyGhidraEnvironment, detectGhidra, engineConfigSignature,
  environmentStatus, installExternalTool, installGhidra, providerReadiness, saveEnginePaths,
} from './lib/engines.js';
import { listDirectories } from './lib/fs-browse.js';
import { ReaMcpClient } from './lib/mcp-client.js';
import { DSH_HOME, PLUGIN_ROOT, WORKSPACE_DIR } from './lib/paths.js';
import {
  applyPolicyPatch, describePolicy, normalizePolicyPatch, readPolicyOverrides, writePolicyOverrides,
} from './lib/policy-store.js';
import { buildPlaybookTool, buildProtocolTool, buildWindowsToolsTool, buildWorkflowTools } from './lib/workflow-tools.js';
import { buildIntelTools } from './lib/intel-tools.js';
import { createToolRegistry } from './lib/registry.js';
import { mountEnvironmentRoutes } from './lib/routes.js';
import { createResultIndex, snapshotMeta } from './lib/result-index.js';
import { installSkill, resolveReaPackage } from './lib/runtime.js';
import { createSchemaCache, probeFullCatalog } from './lib/schema-cache.js';
import { buildCatalogTool, buildDescribeArtifactTool, buildDoctorTool, buildReadArtifactTool, buildStatusTool, buildTool, publicToolName, textOf } from './lib/tools.js';
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
  // The sidebar owns five security settings in its own file. Reading it before
  // `resolveConfig` means the panel and the guard agree from the first call,
  // instead of the panel showing a value the guard never saw.
  const policyFile = await readPolicyOverrides();
  const config = resolveConfig(rawConfig, policyFile.values);
  config.policySource = policyFile.error ? 'row' : (Object.keys(policyFile.values).length > 0 ? 'panel' : 'row');
  config.policyError = policyFile.error;
  let policyUpdatedAt = policyFile.updatedAt ?? null;
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
  const artifactBase = join(DSH_HOME, 'rea-artifacts');
  const artifacts = createArtifactStore({
    root: sessionArtifactRoot(artifactBase),
    base: artifactBase,
    maxChars: config.maxResultChars,
    retentionDays: config.artifactRetentionDays,
    maxBytes: config.artifactMaxBytes,
    sensitive: config.sensitiveArtifacts,
  });
  // Retention is enforced on activation, not only on demand: a session that
  // never calls rea_purge_artifacts still expires yesterday's decompiler output.
  void artifacts.purge().catch(() => {});

  // Full catalog definitions are ~2.9 MB; they live here in host memory, never
  // in the model's context, and are served one JSON path at a time.
  const schemaCache = createSchemaCache();
  // Result anchors survive the session directory's retention window.
  const resultIndex = createResultIndex({
    base: artifactBase,
    maxBytes: config.resultIndexMaxBytes,
    retentionDays: config.artifactRetentionDays,
  });

  let externalToolCount = 0;
  const statusPayload = async () => ({
    ...(await environmentStatus()),
    version: PLUGIN_VERSION,
    update: updateStatus(PLUGIN_VERSION),
    policy: {
      // Counts keep the old shape working; `values` is what the sidebar edits.
      allowedTargets: config.allowedTargets.length,
      targets: [...config.allowedTargets],
      allowDeviceMutations: config.allowDeviceMutations,
      sensitiveArtifacts: config.sensitiveArtifacts,
      artifactRetentionDays: config.artifactRetentionDays,
      networkEgressPolicy: config.networkEgressPolicy,
      pinnedSha256: config.pinnedSha256,
      catalogProbe: config.catalogProbe,
      imageCapture: config.imageCapture,
      playbookDir: config.playbookDir,
      externalToolCount,
      editable: true,
      source: config.policySource,
      updatedAt: policyUpdatedAt,
      error: config.policyError ?? null,
      values: describePolicy(config),
    },
  });

  /**
   * Change control. The classification is fail-closed rather than a hardcoded
   * list: a tool added by a future REA release that is not clearly read-only is
   * audited, and one that removes/overwrites device state is refused. A session
   * scope, when configured, rejects any absolute path outside its roots.
   */
  const guardTool = (name, args, entry) => {
    const outside = pathOutsideScope(args, config.allowedTargets);
    if (outside) {
      return `${name}: ${outside.key} "${outside.path}" is outside this session's allowedTargets. Add its root to the dsh-rea row if that is intended.`;
    }
    const { mutating, destructive, inferred, external, verb } = classifyTool(name, entry);
    if (destructive && !config.allowDeviceMutations) {
      return `${name} removes or overwrites something on the attached device and is disabled. Set "allowDeviceMutations: true" on the dsh-rea row if that is intended.`;
    }
    // Optional analyst-side exposure control: upstream marks 108 tools as
    // openWorld/destructive. "deny" is opt-in because it also blocks harmless
    // tools; "warn" (default) only records the call.
    if (external && config.networkEgressPolicy === 'deny') {
      return `${name} is marked openWorldHint/destructiveHint by upstream and networkEgressPolicy is "deny". Set it to "warn" if this call is intended.`;
    }
    if (mutating) {
      void artifacts.audit({ tool: name, args: Object.keys(args ?? {}), policy: inferred ? `inferred:${verb}` : 'known' });
    } else if (external && entry?.annotations?.destructiveHint === true) {
      // Upstream's destructiveHint is a conservative signal, not an authority:
      // it is true for 31 tools including harmless exports. Record it without
      // refusing the call and without claiming the call mutated anything.
      void artifacts.audit({ tool: name, args: Object.keys(args ?? {}), policy: 'upstream-destructiveHint' });
    }
    return undefined;
  };

  /**
   * The seven plugin-owned tools must obey the same session scope as the 207
   * bridged ones. In 1.3.0 the guard was only passed to buildTool(), so a
   * configured allowedTargets could be bypassed with rea_triage({path}).
   * Paths inside our own artifact directory are always in scope (that is where
   * spilled results and reports live), and write-ish own tools are audited.
   */
  const OWN_WRITE_TOOLS = new Set(['rea_purge_artifacts', 'rea_export_report', 'rea_run_playbook']);
  const ownGuard = (name, args) => {
    // Same value-shape check as the bridged tools: no parameter-name whitelist,
    // so an own tool cannot become a path-scope bypass through a nested input.
    const outside = pathOutsideScope(args, config.allowedTargets, {
      // The sanitizer's whole purpose is to receive text containing local
      // absolute paths; treating that text as a path argument would make the
      // tool unable to do its job in a scoped session.
      exempt: (path, key) => artifacts.inside(path)
        || (name === 'rea_sanitize_report' && /^(text|report)$/.test(key ?? '')),
    });
    if (outside) {
      return `${name}: ${outside.key} "${outside.path}" is outside this session's allowedTargets.`;
    }
    if (OWN_WRITE_TOOLS.has(name)) {
      void artifacts.audit({ tool: name, args: Object.keys(args ?? {}), policy: 'own-tool-write' });
    }
    return undefined;
  };

  const register = (definition, label) => {
    const original = definition.execute;
    const guarded = {
      ...definition,
      async execute(args, exec) {
        const refusal = ownGuard(definition.name, args);
        if (refusal) throw new Error(refusal);
        return original(args, exec);
      },
    };
    const dispose = ctx.tools?.register(guarded);
    return () => { try { dispose?.(); } catch {} };
  };

  ctx.effect(() => register(buildDoctorTool({ config, entry: REA_ENTRY, translate: translator(ctx) })), 'dsh-rea: doctor tool');

  // The discovery index, populated by the first sync and replaced on every
  // re-sync, so it always names the tools the server actually advertises.
  const catalog = { entries: () => [] };
  ctx.effect(() => register(buildCatalogTool(catalog, schemaCache)), 'dsh-rea: catalog tool');

  ctx.effect(() => register(buildReadArtifactTool(artifacts)), 'dsh-rea: artifact reader');
  ctx.effect(() => register(buildDescribeArtifactTool(artifacts)), 'dsh-rea: binary evidence describe');

  // Declared before the status tool so it can close over the live client: the
  // tool is advertised from the first turn, while the connection may still be
  // starting, failing, or being replaced.
  let client;
  const clientFacade = {
    callTool: (...args) => (client === undefined
      ? Promise.reject(new Error('the REA child is not connected'))
      : client.callTool(...args)),
  };
  ctx.effect(() => register(buildStatusTool({ client: clientFacade, engines: statusPayload, version: PLUGIN_VERSION })), 'dsh-rea: status tool');

  // These three do not need a live REA child: triage reads a file locally,
  // export works on a supplied bundle, and purge only touches artifact files.
  // Registering them before the connection also means they are available when
  // the runtime fails to unpack (rea_triage still helps decide what to do).
  const triageOptions = {
    maxBytes: config.triageMaxBytes,
    yaraRulesDir: config.yaraRulesDir,
    availableTools: null,
    // Probed per call rather than once at activation: a session that installs
    // Ghidra half-way must stop being told the confirm path is unavailable.
    // The probe only locates binaries, it never starts an engine.
    providers: async () => {
      try {
        return await providerReadiness();
      } catch {
        return null;
      }
    },
  };
  ctx.effect(() => register(buildTriageTool(triageOptions)), 'dsh-rea: triage tool');
  // The fallback for `verify` when no analyzer can start: it reads the file
  // the report describes, so an uninstalled engine no longer makes a correct
  // plan unscorable.
  ctx.effect(() => register(buildProbeAddressTool()), 'dsh-rea: address probe tool');

  ctx.effect(() => register(buildExportReportTool({ client: clientFacade, store: artifacts, toolVersion: PLUGIN_VERSION })), 'dsh-rea: export report tool');

  ctx.effect(() => register(buildPurgeArtifactsTool(artifacts)), 'dsh-rea: artifact purge tool');

  // Workflow layer: cross-session result index, corpus triage, local diff hints.
  for (const [definition, label] of buildWorkflowTools({
    resultIndex,
    triageOptions,
    maxBatch: config.batchTriageLimit,
    store: artifacts,
  })) {
    ctx.effect(() => register(definition), label);
  }

  // Static intelligence: indicators, tracking surface, anti-analysis matrix
  // and analyst-side report sanitisation. All local, no execution/network.
  for (const [definition, label] of buildIntelTools({
    store: artifacts,
    maxBytes: config.triageMaxBytes,
    triageOptions,
    env: process.env,
  })) {
    ctx.effect(() => register(definition), label);
  }

  // Optional adapters. They report a missing external binary rather than
  // pretending the capability exists, so they are safe to register everywhere.
  ctx.effect(() => register(buildProtocolTool({ store: artifacts })), 'dsh-rea: protocol adapter');
  ctx.effect(() => register(buildWindowsToolsTool()), 'dsh-rea: windows tool probe');
  ctx.effect(() => register(buildPlaybookTool({
    dir: config.playbookDir,
    timeoutMs: config.playbookTimeoutMs,
    maxCalls: config.playbookMaxCalls,
    callTool: (name, args, signal) => {
      const refusal = guardTool(name, args, schemaCache.entry(name) ?? {});
      if (refusal) throw new Error(refusal);
      return clientFacade.callTool(name, args, signal);
    },
    toolNames: () => catalog.entries().map((entry) => entry.name),
    store: artifacts,
  })), 'dsh-rea: playbook runner');

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
  const readLimiter = createLimiter(config.maxConcurrentReadTools);
  let restarting;
  let attempts = 0;
  let reconnectTimer;

  async function sync() {
    const entries = await client.listTools();
    schemaCache.prime(entries, client.serverInfo?.version ?? null);
    externalToolCount = entries.filter((entry) => classifyTool(entry?.name ?? '', entry).external).length;
    // Triage's next steps name only tools the server actually advertises.
    triageOptions.availableTools = new Set(entries.map((entry) => entry?.name).filter((name) => typeof name === 'string'));
    const definitions = [];
    const index = [];
    for (const entry of entries) {
      if (typeof entry?.name !== 'string') continue;
      const definition = buildTool(client, entry, config.deferCatalog, {
        spill: (name, text) => artifacts.maybeSpill(name, text),
        guard: (name, args, schemaEntry) => guardTool(name, args, schemaEntry),
        limiter: readLimiter,
        metadata: (name, result, text) => {
          const meta = snapshotMeta(name, result, text);
          void resultIndex.record(meta);
        },
        binary: config.imageCapture
          ? (name, record) => artifacts.writeBinary(name, record.mimeType, record.data)
          : undefined,
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
      checkUpdate: () => checkForUpdate(log, { current: PLUGIN_VERSION, pinnedSha256: config.pinnedSha256, trustedManifestKey: config.trustedManifestKey }),
      installUpdate: () => installUpdate(log, { pinnedSha256: config.pinnedSha256, maxBackups: config.maxBackups }),
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
      // Directory names only. The panel needs them to offer a picker; nothing
      // in this handler can read a file.
      listDirectories: (path) => listDirectories(path),
      /**
       * The sidebar's security switches.
       *
       * Applied in place, never by rebuilding the config: `guardTool` closes
       * over this object and reads it on every call, so a replaced object would
       * leave the guard enforcing yesterday's policy until the next session.
       * Nothing restarts - a scope or egress change is checked per call.
       */
      applyPolicy: async (body) => {
        const { reset, patch } = normalizePolicyPatch(body);
        applyPolicyPatch(config, patch);
        artifacts.configure({
          retentionDays: config.artifactRetentionDays,
          sensitive: config.sensitiveArtifacts,
        });
        const saved = await writePolicyOverrides(reset ? { ...patch } : patch);
        policyUpdatedAt = saved.updatedAt;
        config.policySource = 'panel';
        config.policyError = null;
        void artifacts.audit({
          tool: 'rea_policy',
          args: Object.keys(patch),
          policy: reset ? 'reset' : 'update',
        });
        return { changed: true };
      },
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

  // Fetch the complete catalog once, in the background. It never blocks
  // activation and never touches the model context; failure merely leaves
  // rea_catalog in compact mode.
  if (config.catalogProbe && REA_ENTRY !== undefined) {
    void (async () => {
      try {
        const { entries: full, serverVersion } = await probeFullCatalog({
          ReaMcpClient, childEnvironment, config,
          entry: REA_ENTRY, cwd: WORKSPACE_DIR, version: PLUGIN_VERSION,
          log: (message) => log.warn(`dsh-rea: catalog probe: ${message}`),
        });
        const count = schemaCache.primeFull(full, serverVersion);
        log.info(`dsh-rea: full catalog cached (${count} tools, ${Math.round(schemaCache.memoryBytes / 1024)} KB in memory, live/probe versions ${schemaCache.versionConsistent === false ? 'MISMATCH' : 'match'})`);
      } catch (error) {
        schemaCache.markProbeFailed(error?.message ?? error);
        log.warn(`dsh-rea: full catalog probe failed; rea_catalog stays compact: ${error?.message ?? error}`);
      }
    })();
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
