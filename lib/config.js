/**
 * Config resolution and the child's environment.
 *
 * Two things live here because they are the same decision: what the Host's
 * config row means, and what the REA child is allowed to see.
 *
 * The child gets a *narrowed* environment rather than a copy of the Host's.
 * The Host's environment holds API keys and session tokens that a
 * third-party analysis server has no business reading, and the previous
 * implementation handed it all over. The names that are passed through are the
 * ones REA documents for provider discovery, plus what Node and Java need to
 * start on each platform.
 *
 * @module dsh-rea/lib/config
 */

import { join } from 'node:path';

import { DEFAULT_MAX_BUFFER_BYTES, DEFAULT_TOOL_CALL_TIMEOUT_MS, REA_MIN_MAX_RESPONSE_BYTES } from './mcp-client.js';
import { ENGINE_ENV_OVERRIDES } from './engines.js';
import { DSH_HOME } from './paths.js';

/**
 * Resolve the row's config into the shape the client wants.
 *
 * REA's own parser bounds both profiles (`compact`|`full` input, `full`|`off`
 * output), so anything else is refused here with the boundary named instead of
 * being handed to a child that would die on it.
 */
export function resolveConfig(config = {}) {
  const schemaProfile = config.schemaProfile === 'full' ? 'full' : 'compact';
  const outputSchemaProfile = config.outputSchemaProfile === 'full' ? 'full' : 'off';
  const toolCallTimeoutMs = Number.isFinite(config.toolCallTimeoutMs) && config.toolCallTimeoutMs > 0
    ? Math.floor(config.toolCallTimeoutMs)
    : DEFAULT_TOOL_CALL_TIMEOUT_MS;
  const maxBufferBytes = Number.isFinite(config.maxBufferBytes) && config.maxBufferBytes >= REA_MIN_MAX_RESPONSE_BYTES
    ? Math.floor(config.maxBufferBytes)
    : DEFAULT_MAX_BUFFER_BYTES;
  // A single REA result can be tens of kilobytes and is paid again on every
  // later turn. Past this budget the text goes to disk and the model gets a head
  // plus a handle.
  const maxResultChars = Number.isFinite(config.maxResultChars) && config.maxResultChars > 0
    ? Math.min(Math.max(Math.floor(config.maxResultChars), 4_000), 200_000)
    : 24_000;
  // Artifacts hold full decompiler output. They expire and are size-capped,
  // and `sensitiveArtifacts` keeps the full text out of the filesystem entirely.
  const retentionDays = Number.isFinite(config.artifactRetentionDays)
    ? Math.min(Math.max(Math.floor(config.artifactRetentionDays), 1), 365)
    : 7;
  const artifactMaxBytes = Number.isFinite(config.artifactMaxBytes) && config.artifactMaxBytes >= 1024 * 1024
    ? Math.floor(config.artifactMaxBytes)
    : 256 * 1024 * 1024;
  const triageMaxBytes = Number.isFinite(config.triageMaxBytes)
    ? Math.min(Math.max(Math.floor(config.triageMaxBytes), 1024 * 1024), 512 * 1024 * 1024)
    : 64 * 1024 * 1024;
  const maxBackups = Number.isFinite(config.maxBackups)
    ? Math.min(Math.max(Math.floor(config.maxBackups), 0), 10)
    : 2;
  // Trusted playbooks live in one directory; a name (not inline code) is the
  // only way to run one, so installing a script is an explicit act of trust.
  const playbookTimeoutMs = Number.isFinite(config.playbookTimeoutMs)
    ? Math.min(Math.max(Math.floor(config.playbookTimeoutMs), 1_000), 600_000) : 120_000;
  const playbookMaxCalls = Number.isFinite(config.playbookMaxCalls)
    ? Math.min(Math.max(Math.floor(config.playbookMaxCalls), 1), 2_000) : 200;
  const batchTriageLimit = Number.isFinite(config.batchTriageLimit)
    ? Math.min(Math.max(Math.floor(config.batchTriageLimit), 1), 500) : 50;
  const pinnedSha256 = typeof config.pinnedSha256 === 'string' && /^[0-9a-f]{64}$/i.test(config.pinnedSha256)
    ? config.pinnedSha256.toLowerCase()
    : null;
  // Optional independent trust anchor for the update manifest. When set,
  // every manifest source must also serve a valid update.json.minisig.
  const trustedManifestKey = typeof config.trustedManifestKey === 'string'
    && /minisign public key/i.test(config.trustedManifestKey)
    ? config.trustedManifestKey.trim() : null;
  return {
    schemaProfile,
    outputSchemaProfile,
    toolCallTimeoutMs,
    maxBufferBytes,
    maxResultChars,
    logLevel: typeof config.logLevel === 'string' ? config.logLevel : 'info',
    enabled: config.enabled !== false,
    // Deferring the catalog is what makes a 207-tool bridge affordable: the
    // schemas stay out of the request payload until a tool is actually asked
    // for. `false` restores the always-advertised behaviour.
    deferCatalog: config.deferCatalog !== false,
    // Installing an APK, pushing a file to a device or force-stopping a package
    // removes or overwrites something. Those four stay off until asked for.
    allowDeviceMutations: config.allowDeviceMutations === true,
    // Empty = unrestricted. When set, every absolute path argument of a tool
    // call must sit under one of these roots.
    allowedTargets: Array.isArray(config.allowedTargets)
      ? config.allowedTargets.filter((entry) => typeof entry === 'string' && entry.length > 0)
      : [],
    sensitiveArtifacts: config.sensitiveArtifacts === true,
    artifactRetentionDays: retentionDays,
    artifactMaxBytes,
    triageMaxBytes,
    yaraRulesDir: typeof config.yaraRulesDir === 'string' && config.yaraRulesDir.length > 0
      ? config.yaraRulesDir : null,
    trustedManifestKey,
    pinnedSha256,
    maxBackups,
    // A short-lived second child fetches complete input/output schemas once,
    // so rea_catalog can expand a 165 KB definition one field at a time.
    catalogProbe: config.catalogProbe !== false,
    // Persist image / binary MCP blocks instead of replacing them with a note.
    imageCapture: config.imageCapture !== false,
    playbookDir: typeof config.playbookDir === 'string' && config.playbookDir.length > 0
      ? config.playbookDir : join(DSH_HOME, 'rea-playbooks'),
    playbookTimeoutMs,
    playbookMaxCalls,
    batchTriageLimit,
    updateMirrors: Array.isArray(config.updateMirrors)
      ? config.updateMirrors.filter((entry) => typeof entry === 'string' && /^https?:\/\//.test(entry))
      : [],
  };
}

/** Provider settings REA reads, passed through from this process when present. */
export const PASSTHROUGH_ENV_NAMES = [
  'GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_GHIDRA_STARTUP_TIMEOUT_MS',
  'REA_HOPPER_STARTUP_TIMEOUT_MS', 'REA_GHIDRA_LANGUAGE_ID',
  'REA_GHIDRA_COMPILER_SPEC_ID', 'REA_GHIDRA_DISABLED_ANALYZERS',
  'REA_GHIDRA_NATIVEAOT_JAR', 'REA_GHIDRA_SEED_FILE', 'REA_IDA_MCP_CONFIG',
  'REA_JEB_MCP_TIMEOUT_MS', 'REA_KUNA_COMMAND', 'REA_ILSPY_CMD_PATH',
  'REA_ANALYSIS_PROVIDER', 'REA_JADX_MCP_JAR', 'REA_JADX_OPERATION_TIMEOUT_MS',
  'REA_APKTOOL_COMMAND', 'REA_WABT_BIN_DIRECTORY', 'REA_TSHARK_COMMAND',
  'REA_SIGROK_COMMAND', 'REA_SWIFTC_COMPILE_TIMEOUT_MS',
  'REA_PWNTOOLS_PYTHON', 'HOPPER_LAUNCHER_PATH', 'HOPPER_TARGET_PATH',
  'HOPPER_TARGET_KIND', 'HOPPER_LOADER_ARGS_JSON', 'TMP', 'TEMP',
];

/**
 * Environment variables a child process needs to start and find its tools.
 * Deliberately excludes anything that names a secret.
 */
const BASE_ENV_NAMES = [
  'PATH', 'Path', 'PATHEXT', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'NUMBER_OF_PROCESSORS',
  'PROCESSOR_ARCHITECTURE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
  'PROGRAMFILES', 'PROGRAMFILES(X86)', 'TEMP', 'TMP', 'TMPDIR',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'SHELL', 'USER', 'LOGNAME',
  'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
];

/**
 * The environment the REA child runs with.
 *
 * This plugin's settings are written in, and every provider path the person has
 * configured in the session is passed through: REA never installs an engine, so
 * the only way it can use one is for its path to reach the child.
 */
export function childEnvironment(config, base = process.env) {
  const env = {};
  for (const name of BASE_ENV_NAMES) {
    const value = base[name];
    if (typeof value === 'string' && value.length > 0) env[name] = value;
  }
  for (const [name, value] of Object.entries(ENGINE_ENV_OVERRIDES)) {
    if (typeof value === 'string' && value.length > 0) env[name] = value;
  }
  for (const name of PASSTHROUGH_ENV_NAMES) {
    const value = base[name];
    if (typeof value === 'string' && value.length > 0) env[name] = value;
  }
  env.REA_MCP_INPUT_SCHEMA_PROFILE = config.schemaProfile;
  env.REA_MCP_OUTPUT_SCHEMA_PROFILE = config.outputSchemaProfile;
  env.REA_MCP_MAX_RESPONSE_BYTES = String(config.maxBufferBytes);
  env.REA_LOG_LEVEL = config.logLevel;
  env.REA_PACKAGE_VERSION = config.reaVersion ?? 'unknown';
  // The Desktop Host is the Electron executable running as plain Node
  // (ELECTRON_RUN_AS_NODE=1), and the child is spawned with that same
  // executable. An explicit env object does not inherit the parent's
  // environment, so without this flag the child would boot as a GUI
  // application and exit immediately with code 0. Plain Node ignores it.
  env.ELECTRON_RUN_AS_NODE = '1';
  return env;
}
