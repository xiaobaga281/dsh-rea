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
const ROOT = new URL('../', import.meta.url);
const { apply } = await import(new URL('index.js', ROOT).href);
const { childEnvironment, resolveConfig } = await import(new URL('lib/config.js', ROOT).href);

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
    }
    results.push({
      mode: mode.name, ok: failures.length === 0, tools: host.tools.length,
      routes: host.routes.length, ms: Date.now() - started, failures,
      warnings: host.warnings.slice(0, 3),
    });
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
process.exit(results.every((result) => result.ok) ? 0 : 1);
