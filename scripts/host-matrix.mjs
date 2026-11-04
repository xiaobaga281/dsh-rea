/**
 * Host compatibility gate.
 *
 * 1.3.1 shipped a plugin that was perfectly healthy under a plain-Node fake
 * host but completely inert inside the Electron desktop host. This script
 * runs the real `apply()` in both host modes, with the real REA child, and
 * fails when either one cannot register tools and routes.
 *
 * Run before publishing: `npm run host-matrix`.
 * A CI job on Linux should run the same script there; platform-dependent
 * paths (tar, drive letters, where/cdb) cannot be exercised on Windows alone.
 *
 * This is intentionally a script rather than part of `npm test`: it starts
 * real child processes and needs the unpacked runtime.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
const { apply } = await import(new URL('index.js', ROOT).href);
const { childEnvironment, resolveConfig } = await import(new URL('lib/config.js', ROOT).href);
const { classifyTool } = await import(new URL('lib/artifacts.js', ROOT).href);

const MODES = [
  { name: 'plain-node', electron: false, config: {} },
  { name: 'electron-run-as-node', electron: true, config: {} },
  { name: 'scoped-session', electron: false, scoped: true, config: { allowedTargets: ['C:\\Users\\25616\\.dsh'] } },
];

function makeHost() {
  const tools = [];
  const routes = [];
  const disposes = [];
  const warnings = [];
  const ctx = {
    logger: {
      info: () => {},
      warn: (m) => warnings.push(m),
      error: (m) => warnings.push(m),
    },
    tools: {
      register(definition) {
        tools.push(definition);
        return () => {};
      },
    },
    webServer: {
      register(route) {
        routes.push(route);
        return () => {};
      },
    },
    effect(fn, label) {
      const dispose = fn();
      if (typeof dispose === 'function') disposes.push(dispose);
      return dispose;
    },
  };
  return { ctx, tools, routes, disposes, warnings };
}

const results = [];
let classification = null;
for (const mode of MODES) {
  if (mode.electron) process.env.ELECTRON_RUN_AS_NODE = '1';
  else delete process.env.ELECTRON_RUN_AS_NODE;
  const host = makeHost();
  const started = Date.now();
  try {
    // The full-catalog probe is a separate, optional child; it is not what this
    // gate is testing, so keep the run short and deterministic.
    await apply(host.ctx, { catalogProbe: false, ...mode.config });
    const env = childEnvironment(resolveConfig({}), process.env);
    const failures = [];
    if (env.ELECTRON_RUN_AS_NODE !== '1') failures.push('child env lost ELECTRON_RUN_AS_NODE');
    if (host.tools.length < 210) failures.push(`only ${host.tools.length} tools registered (expected >= 210)`);
    if (host.routes.length < 6) failures.push(`only ${host.routes.length} routes registered (expected >= 6)`);
    const catalog = host.tools.find((tool) => tool.name === 'rea_catalog');
    if (!catalog) failures.push('rea_catalog missing');
    else {
      const answer = await catalog.execute({});
      if (!String(answer?.text ?? '').includes('REA tool catalog')) failures.push('rea_catalog returned no index');
    }
    // An allowedTargets scope must also cover plugin-owned tools. In 1.3.0 the
    // guard was only attached to bridged tools, so rea_triage could read any
    // absolute path even in a scoped session.
    if (mode.scoped) {
      const triage = host.tools.find((tool) => tool.name === 'rea_triage');
      try {
        await triage.execute({ path: 'C:\\Windows\\System32\\kernel32.dll' });
        failures.push('rea_triage bypassed allowedTargets');
      } catch (error) {
        if (!/allowedTargets/.test(error?.message ?? '')) failures.push(`unexpected triage refusal: ${error?.message}`);
      }
      // A bridged tool with a path parameter outside the old 14-key whitelist.
      const bridged = host.tools.find((tool) => tool.name === 'mcp__rea__extract_firmware');
      if (!bridged) failures.push('extract_firmware missing; cannot verify value-shape scope');
      else {
        try {
          await bridged.execute({ output_directory: 'C:\\Windows\\Temp\\rea-scope-check' });
          failures.push('output_directory bypassed allowedTargets');
        } catch (error) {
          if (!/allowedTargets/.test(error?.message ?? '')) failures.push(`unexpected bridged refusal: ${error?.message}`);
        }
      }
    }
    results.push({
      mode: mode.name, ok: failures.length === 0, tools: host.tools.length,
      routes: host.routes.length, ms: Date.now() - started, failures,
      warnings: host.warnings.slice(0, 3),
    });
    if (classification === null) {
      const bridged = host.tools.filter((tool) => tool.name.startsWith('mcp__rea__'));
      classification = bridged.reduce((acc, tool) => {
        const verdict = classifyTool(tool.name.replace(/^mcp__rea__/, ''), { description: tool.description });
        if (verdict.destructive) acc.destructive += 1;
        if (verdict.mutating) acc.mutating += 1; else acc.readOnly += 1;
        return acc;
      }, { bridged: bridged.length, readOnly: 0, mutating: 0, destructive: 0, ownTools: host.tools.length - bridged.length });
    }
  } catch (error) {
    results.push({ mode: mode.name, ok: false, tools: host.tools.length, routes: host.routes.length, ms: Date.now() - started, failures: [error.message], warnings: host.warnings.slice(0, 3) });
  } finally {
    for (const dispose of host.disposes.reverse()) { try { dispose(); } catch {} }
  }
}

delete process.env.ELECTRON_RUN_AS_NODE;
console.log(`Host matrix (${process.platform}, node ${process.version})`);
for (const result of results) {
  console.log(`  ${result.ok ? 'PASS' : 'FAIL'} ${result.mode.padEnd(22)} tools=${result.tools} routes=${result.routes} ${result.ms} ms`);
  for (const failure of result.failures) console.log(`       - ${failure}`);
  for (const warning of result.warnings) console.log(`       ! ${warning}`);
}
if (process.platform === 'win32') {
  console.log('  NOTE  Linux path/tar behaviour is not covered on Windows; run this script on a Linux CI job too.');
}

// Machine-readable facts for release notes and documentation claims. Handwritten
// numbers drifted three times (e.g. "162 read-only tools" when the real count
// was 157); a gate that publishes its own numbers makes that impossible.
const facts = {
  generatedAt: new Date().toISOString(),
  platform: process.platform,
  node: process.version,
  tools: results[0]?.tools ?? 0,
  routes: results[0]?.routes ?? 0,
  ...(classification ?? { bridged: 0, readOnly: 0, mutating: 0, destructive: 0, ownTools: 0 }),
  hostModes: results.map(({ mode, ok, tools, routes }) => ({ mode, ok, tools, routes })),
};
const dist = join(ROOT_PATH, 'dist');
mkdirSync(dist, { recursive: true });
writeFileSync(join(dist, 'host-matrix.json'), `${JSON.stringify(facts, null, 2)}\n`);

const claimFailures = [];
try {
  const readme = readFileSync(join(ROOT_PATH, 'README.md'), 'utf8');
  if (!readme.includes(`${facts.readOnly} 个只读工具`)) claimFailures.push(`README says a different read-only count than ${facts.readOnly}`);
  if (!readme.includes(`${facts.tools} 工具`)) claimFailures.push(`README does not state the registered tool count ${facts.tools}`);
} catch (error) {
  claimFailures.push(`cannot read README.md: ${error.message}`);
}
for (const failure of claimFailures) console.log(`  FAIL claim ${failure}`);
console.log(`  facts tools=${facts.tools} routes=${facts.routes} readOnly=${facts.readOnly} mutating=${facts.mutating} destructive=${facts.destructive} -> dist/host-matrix.json`);

process.exit(results.every((result) => result.ok) && claimFailures.length === 0 ? 0 : 1);
