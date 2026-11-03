/**
 * Every filesystem location `dsh-rea` owns, in one place.
 *
 * The runtime and the engines live in the DSH home rather than beside the
 * bundle: a profile links the bundle in, and a workspace sandbox has been
 * observed reverting large trees written beside it, which would silently break
 * the plugin a session later. Keeping the paths in one module also means the
 * tests can reason about them without importing the plugin entry.
 *
 * @module dsh-rea/lib/paths
 */

import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Package root: `lib/` sits one level below it. */
export const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** The DSH home; everything this plugin installs is rooted here. */
export const DSH_HOME = join(homedir(), '.dsh');

/* Runtime: the vendored archive and its unpacked tree. */
export const RUNTIME_DIR = join(DSH_HOME, 'rea-runtime');
export const RUNTIME_ARCHIVE = join(PLUGIN_ROOT, 'vendor', 'rea-runtime.tgz');
export const RUNTIME_DIGEST = join(PLUGIN_ROOT, 'vendor', 'rea-runtime.sha256');
export const RUNTIME_MARKER = join(RUNTIME_DIR, '.installed.json');
export const RUNTIME_ENTRY = join(RUNTIME_DIR, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs');

/* Engines: Ghidra, JADX, Apktool and their saved absolute paths. */
export const ENGINE_ROOT = join(DSH_HOME, 'rea-engines');
export const ENGINE_CONFIG_FILE = join(ENGINE_ROOT, 'config.json');
export const GHIDRA_ROOT = join(ENGINE_ROOT, 'ghidra');

/** Dedicated working directory for the REA child, so it cannot write into a workspace. */
export const WORKSPACE_DIR = join(DSH_HOME, 'rea-workspace');

/** Where the filesystem skill provider looks for skills. */
export const SKILLS_ROOT = join(DSH_HOME, 'skills');

/** Skill this plugin installs, by the name the provider derives from the directory. */
export const SKILL_NAME = 'reverse-engineer-anything';
