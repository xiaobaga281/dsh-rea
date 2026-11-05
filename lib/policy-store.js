/**
 * The security policy the sidebar is allowed to change.
 *
 * Five settings used to be read-only in the panel because they live in the
 * Host's plugin config row, and the plugin has no way to write that row. The
 * panel therefore showed a posture ("device mutations: off") that the analyst
 * could see but not act on - the switch existed, it just was not wired to
 * anything the panel could reach.
 *
 * This module is that missing half: a small, validated override file the plugin
 * owns. Precedence is deliberate - an override beats the config row, because
 * the row is a file a person edits by hand and the panel is where they look;
 * when the two disagree, the more recent, more visible act should win.
 *
 * Everything here is fail-closed. A value that cannot be parsed is refused with
 * the field name, never silently coerced, so a typo in the panel cannot quietly
 * turn a restriction off.
 *
 * @module dsh-rea/lib/policy-store
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';

import { DSH_HOME } from './paths.js';

/** Overrides live beside the engine config: one directory, one backup story. */
export const POLICY_FILE = join(DSH_HOME, 'rea-engines', 'policy.json');

/** The fields the panel may change. Anything else is refused. */
export const POLICY_KEYS = [
  'allowedTargets',
  'allowDeviceMutations',
  'sensitiveArtifacts',
  'artifactRetentionDays',
  'networkEgressPolicy',
];

export const EGRESS_POLICIES = ['allow', 'warn', 'deny'];

/** What the plugin behaves like when neither the row nor the panel says otherwise. */
export const POLICY_DEFAULTS = {
  allowedTargets: [],
  allowDeviceMutations: false,
  sensitiveArtifacts: false,
  artifactRetentionDays: 7,
  networkEgressPolicy: 'warn',
};

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
    this.statusCode = 400;
  }
}

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Turn one panel submission into a patch of known keys.
 *
 * Accepts the textarea form (`allowedTargets` as newline-separated text) as well
 * as the array form, because the two callers - the sidebar and a test - should
 * not have to agree on which one is canonical.
 */
export function normalizePolicyPatch(input) {
  if (!isPlainObject(input)) throw new PolicyError('policy patch must be a JSON object');
  const reset = input.reset === true;
  const patch = {};
  const unknown = Object.keys(input).filter((key) => key !== 'reset' && !POLICY_KEYS.includes(key));
  if (unknown.length > 0) {
    throw new PolicyError(`unknown policy field${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}; allowed: ${POLICY_KEYS.join(', ')}`);
  }
  if (reset && Object.keys(input).length > 1) {
    throw new PolicyError('reset cannot be combined with other fields');
  }
  if (reset) return { reset: true, patch: { ...POLICY_DEFAULTS } };

  if ('allowedTargets' in input) {
    const raw = input.allowedTargets;
    const list = Array.isArray(raw)
      ? raw
      : typeof raw === 'string'
        ? raw.split(/\r?\n/)
        : null;
    if (list === null) throw new PolicyError('allowedTargets must be an array or newline-separated text');
    const targets = [];
    for (const entry of list) {
      if (typeof entry !== 'string') throw new PolicyError('allowedTargets entries must be strings');
      const value = entry.trim();
      if (value.length === 0) continue;
      if (!isAbsolute(value)) throw new PolicyError(`allowedTargets entry "${value}" is not an absolute path`);
      if (!targets.includes(value)) targets.push(value);
    }
    if (targets.length > 32) throw new PolicyError('allowedTargets holds at most 32 roots; a longer list is not a scope, it is a wish');
    patch.allowedTargets = targets;
  }

  for (const key of ['allowDeviceMutations', 'sensitiveArtifacts']) {
    if (!(key in input)) continue;
    if (typeof input[key] !== 'boolean') throw new PolicyError(`${key} must be true or false`);
    patch[key] = input[key];
  }

  if ('artifactRetentionDays' in input) {
    const value = Number(input.artifactRetentionDays);
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new PolicyError('artifactRetentionDays must be a whole number of days');
    }
    if (value < 1 || value > 365) throw new PolicyError('artifactRetentionDays must be between 1 and 365');
    patch.artifactRetentionDays = value;
  }

  if ('networkEgressPolicy' in input) {
    const value = String(input.networkEgressPolicy);
    if (!EGRESS_POLICIES.includes(value)) {
      throw new PolicyError(`networkEgressPolicy must be one of ${EGRESS_POLICIES.join(', ')}`);
    }
    patch.networkEgressPolicy = value;
  }

  return { reset: false, patch };
}

/**
 * Read the override file.
 *
 * A corrupt file is reported, not fatal: blocking activation because one JSON
 * byte was lost would take the whole panel down with it, and the panel is how
 * the person would fix the file. The caller decides whether to surface it.
 */
export async function readPolicyOverrides(file = POLICY_FILE) {
  let text;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return { values: {}, error: null, path: file };
    return { values: {}, error: `could not read ${file}: ${error?.message ?? error}`, path: file };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { values: {}, error: `${file} is not valid JSON (${error.message}); the config row's values apply`, path: file };
  }
  if (!isPlainObject(parsed)) return { values: {}, error: `${file} must contain a JSON object`, path: file };
  // Re-validate what was written: the file is editable by hand, and a stale
  // version of this plugin may have written a field this one no longer knows.
  const { values } = parsed;
  const candidate = isPlainObject(values)
    ? values
    : Object.fromEntries(Object.entries(parsed).filter(([key]) => !['schemaVersion', 'updatedAt'].includes(key)));
  try {
    const { patch } = normalizePolicyPatch(candidate);
    return { values: patch, error: null, path: file, updatedAt: parsed.updatedAt ?? null };
  } catch (error) {
    return { values: {}, error: `${file}: ${error.message}; the config row's values apply`, path: file };
  }
}

/**
 * Persist a patch. Written through a temporary file so a crash mid-write cannot
 * leave a half-parsed policy that would silently fall back to "unrestricted".
 */
export async function writePolicyOverrides(patch, { file = POLICY_FILE, now = new Date() } = {}) {
  const payload = {
    schemaVersion: 1,
    updatedAt: now.toISOString(),
    values: patch,
  };
  await mkdir(dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  await rename(temporary, file);
  return payload;
}

/** The five fields, in the order the panel shows them. */
export function describePolicy(config) {
  return {
    allowedTargets: Array.isArray(config.allowedTargets) ? [...config.allowedTargets] : [],
    allowDeviceMutations: config.allowDeviceMutations === true,
    sensitiveArtifacts: config.sensitiveArtifacts === true,
    artifactRetentionDays: config.artifactRetentionDays,
    networkEgressPolicy: config.networkEgressPolicy,
  };
}

/**
 * Apply a patch to a live config object in place.
 *
 * In place matters: the tool guard closes over `config` and reads it on every
 * call, so replacing the object would leave the guard enforcing the old values
 * until the next session.
 */
export function applyPolicyPatch(config, patch) {
  for (const key of Object.keys(patch)) {
    if (key === 'allowedTargets') config.allowedTargets = [...patch.allowedTargets];
    else config[key] = patch[key];
  }
  return config;
}
