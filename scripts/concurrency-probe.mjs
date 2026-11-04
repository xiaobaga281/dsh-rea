/**
 * Real-child concurrency evidence for the 157 read-only tools.
 *
 * 1.4.0 allowed read-only calls to overlap without ever measuring whether
 * REA's single framed stdout channel survives a burst. This probe fires the
 * same read-only batch twice - once unbounded, once through the plugin's
 * limiter - and prints the failure rate and latency distribution.
 *
 * It is a report, not a pass/fail unit test: a missing Ghidra document makes
 * some calls fail legitimately. Run before publishing: `npm run concurrency`.
 */
const ROOT = new URL('../', import.meta.url);
const { resolveConfig, childEnvironment } = await import(new URL('lib/config.js', ROOT).href);
const { ReaMcpClient } = await import(new URL('lib/mcp-client.js', ROOT).href);
const { classifyTool } = await import(new URL('lib/artifacts.js', ROOT).href);
const { createLimiter } = await import(new URL('lib/concurrency.js', ROOT).href);
const { existsSync, readFileSync } = await import('node:fs');

const HOME = process.env.USERPROFILE ?? process.env.HOME ?? 'C:/Users/25616';
const ENTRY = `${HOME}/.dsh/rea-runtime/node_modules/rea-agents/scripts/rea.mjs`;
const CWD = `${HOME}/.dsh/rea-workspace`;
if (!existsSync(ENTRY)) {
  console.error(`REA runtime not found at ${ENTRY}; activate the plugin once or adjust the path.`);
  process.exit(2);
}
const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const config = resolveConfig({});
const client = new ReaMcpClient({
  command: process.execPath,
  args: [ENTRY, 'mcp'],
  env: childEnvironment(config, process.env),
  cwd: CWD,
  version,
  log: () => {},
});

const TOTAL = 30;
const percentile = (values, q) => {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))];
};

async function round(label, limiter) {
  const tasks = [];
  for (let i = 0; i < TOTAL; i += 1) {
    const name = candidates[i % candidates.length];
    const started = Date.now();
    const call = () => client.callTool(name, {}).then(
      () => ({ ok: true, ms: Date.now() - started }),
      (error) => ({ ok: false, ms: Date.now() - started, reason: error?.message ?? String(error) }),
    );
    tasks.push(limiter ? limiter.run(call) : call());
  }
  const began = Date.now();
  const results = await Promise.all(tasks);
  const ok = results.filter((r) => r.ok);
  const failed = results.filter((r) => !r.ok);
  const times = results.map((r) => r.ms);
  console.log(`  ${label.padEnd(14)} ok=${String(ok.length).padStart(2)}/${TOTAL} failed=${String(failed.length).padStart(2)} total=${Date.now() - began}ms p50=${percentile(times, 0.5)}ms p95=${percentile(times, 0.95)}ms`);
  if (failed.length > 0) console.log(`    sample error: ${failed[0].reason.slice(0, 160)}`);
  return failed.length;
}

let candidates = [];
try {
  await client.ready;
  const tools = await client.listTools();
  candidates = tools
    .filter((entry) => typeof entry?.name === 'string')
    .filter((entry) => (entry.inputSchema?.required ?? []).length === 0)
    .filter((entry) => !classifyTool(entry.name, entry).mutating)
    .filter((entry) => /^(list_|get_|rea_)/.test(entry.name))
    .slice(0, 6)
    .map((entry) => entry.name);
  console.log(`Concurrency probe (${process.platform}, node ${process.version}, ${tools.length} tools)`);
  console.log(`  read-only no-required candidates: ${candidates.join(', ') || '(none)'}`);
  if (candidates.length === 0) {
    console.log('  no safe read-only tool with an empty required list; nothing to probe');
  } else {
    const unbounded = await round('unbounded', null);
    await round('limited(6)', createLimiter(6));
    console.log(`  note: failures may be legitimate (no open document / no attached target). Compare the two rates, not the absolute number.`);
    console.log(`  unbounded failures: ${unbounded}`);
  }
} finally {
  try { await client.dispose(); } catch {}
}
