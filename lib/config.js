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

import { DEFAULT_MAX_BUFFER_BYTES, DEFAULT_TOOL_CALL_TIMEOUT_MS, REA_MIN_MAX_RESPONSE_BYTES } from './mcp-client.js';
import { ENGINE_ENV_OVERRIDES } from './engines.js';

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
  return env;
}
