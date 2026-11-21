/**
 * Prepare one engine from the pinned release list, the same path the sidebar
 * uses. Run: node scripts/install-engine.mjs gcc
 */
import { GCC_RELEASE, JADX_RELEASE, APKTOOL_RELEASE, WABT_RELEASE, ZIG_RELEASE, installExternalTool } from '../lib/engines.js';

const tool = (process.argv[2] ?? '').trim();
const versions = { gcc: GCC_RELEASE, zig: ZIG_RELEASE, jadx: JADX_RELEASE, apktool: APKTOOL_RELEASE, wabt: WABT_RELEASE };
if (!(tool in versions)) {
  console.error(`usage: node scripts/install-engine.mjs <${Object.keys(versions).join('|')}>`);
  process.exit(2);
}
const log = { info: (message) => console.log(message), warn: (message) => console.warn(message) };
try {
  const state = await installExternalTool(tool, log);
  console.log(`${tool} ${versions[tool].version}: ${state.phase}${state.path ? ` at ${state.path}` : ''}`);
} catch (error) {
  console.error(`${tool}: ${error.message}`);
  process.exit(1);
}
