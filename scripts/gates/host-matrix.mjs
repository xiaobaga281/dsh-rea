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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../../', import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
// The gate must not depend on the operator's saved panel policy. A policy file
// with an empty allowedTargets overrides the row by design, which would turn
// the scoped mode into an unrestricted one and make its assertion vacuous.
process.env.DSH_REA_POLICY_FILE = join(ROOT_PATH, 'dist', '.gate-policy-absent.json');
const { apply, OWN_TOOL_AUDIT } = await import(new URL('index.js', ROOT).href);
const { childEnvironment, resolveConfig } = await import(new URL('lib/infra/config.js', ROOT).href);
const { classifyTool, sessionArtifactRoot, COMMAND_ESCAPE_TOOLS, DESTRUCTIVE_TOOLS } = await import(new URL('lib/infra/artifacts.js', ROOT).href);
const { DSH_HOME } = await import(new URL('lib/infra/paths.js', ROOT).href);
const { GAP_EXECUTABLES } = await import(new URL('lib/restore/recon.js', ROOT).href);
const { RECONSTRUCT_ACTIONS } = await import(new URL('lib/restore/recon-actions.js', ROOT).href);
const { validateDocReferences } = await import(new URL('scripts/gates/doc-references.mjs', ROOT).href);

const EXPECTED = {
  tools: 237,
  ownTools: 30,
  bridged: 207,
  routeObjects: 8,
  routePairs: 9,
  confirmMappings: 13,
  gapExecutables: 23,
};
const EXPECTED_ROUTES = [
  'GET /rea/environment',
  'GET /rea/fs/list',
  'POST /rea/engine/config',
  'POST /rea/engine/install',
  'POST /rea/fs/list',
  'POST /rea/ghidra/install',
  'POST /rea/policy',
  'POST /rea/update/check',
  'POST /rea/update/install',
].sort();

const MODES = [
  { name: 'plain-node', electron: false, config: {} },
  { name: 'electron-run-as-node', electron: true, config: {} },
  { name: 'scoped-session', electron: false, scoped: true, config: { allowedTargets: ['C:\\Users\\25616\\.dsh'] } },
];

function routePairs(routes) {
  return routes.flatMap((route) => {
    const methods = Array.isArray(route?.methods) ? route.methods : route?.method ? [route.method] : [];
    // /rea/fs/list is one registration serving both methods, deliberately with
    // no host-level method filter. The registered object therefore carries no
    // method marker; that one documented exception expands to its two pairs.
    if (methods.length === 0 && route?.path === '/rea/fs/list') return ['GET /rea/fs/list', 'POST /rea/fs/list'];
    return methods.map((method) => `${String(method).toUpperCase()} ${route.path}`);
  }).sort();
}

function toolFingerprint(tool) {
  return JSON.stringify({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters ?? null,
    annotations: tool.annotations ?? null,
    deferLoading: tool.deferLoading === true,
    outputSchema: tool.output?.schema ?? null,
  });
}

function validateGapExecutables(tools) {
  const failures = [];
  if (Object.keys(GAP_EXECUTABLES).length !== EXPECTED.gapExecutables) {
    failures.push(`gap executable mappings ${Object.keys(GAP_EXECUTABLES).length} != ${EXPECTED.gapExecutables}`);
  }
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  for (const [id, spec] of Object.entries(GAP_EXECUTABLES)) {
    const tool = byName.get(spec.tool);
    if (!tool) {
      failures.push(`gap ${id} names missing tool ${spec.tool}`);
      continue;
    }
    if (OWN_TOOL_AUDIT[spec.tool] !== spec.policy) {
      failures.push(`gap ${id} policy ${spec.policy} != ${OWN_TOOL_AUDIT[spec.tool] ?? 'unclassified'} for ${spec.tool}`);
    }
    const properties = tool.parameters?.properties ?? {};
    for (const name of spec.requiredArgs) {
      if (!Object.prototype.hasOwnProperty.call(properties, name)) {
        failures.push(`gap ${id} requires unknown ${spec.tool}.${name}`);
      }
    }
    if (typeof spec.confirm !== 'boolean') failures.push(`gap ${id} confirm is not a boolean`);
    if (spec.blockedReason !== null && typeof spec.blockedReason !== 'string') failures.push(`gap ${id} blockedReason is neither null nor text`);
    if (spec.action !== null) {
      if (spec.tool !== 'rea_reconstruct') failures.push(`gap ${id} names action ${spec.action} on non-action tool ${spec.tool}`);
      else if (!RECONSTRUCT_ACTIONS.includes(spec.action)) failures.push(`gap ${id} uses illegal reconstruct action ${spec.action}`);
    }
  }
  return failures;
}

function classificationOf(tools) {
  const bridged = tools.filter((tool) => tool.name.startsWith('mcp__rea__'));
  const own = tools.filter((tool) => !tool.name.startsWith('mcp__rea__'));
  const stats = {
    bridged: bridged.length,
    ownTools: own.length,
    readOnly: 0,
    mutating: 0,
    destructive: 0,
    commandEscape: 0,
    annotationExternal: 0,
    external: 0,
    derivedExternal: 0,
    annotationsPreserved: 0,
    ownDestructive: own.filter((tool) => DESTRUCTIVE_TOOLS.has(tool.name)).length,
  };
  for (const tool of bridged) {
    const raw = tool.name.replace(/^mcp__rea__/, '');
    const verdict = classifyTool(raw, tool);
    if (verdict.mutating) stats.mutating += 1; else stats.readOnly += 1;
    if (verdict.destructive) stats.destructive += 1;
    if (COMMAND_ESCAPE_TOOLS.has(raw)) stats.commandEscape += 1;
    if (verdict.external) stats.external += 1;
    const annotationHint = tool.annotations?.destructiveHint === true || tool.annotations?.openWorldHint === true;
    if (annotationHint) stats.annotationExternal += 1;
    if (verdict.external && !annotationHint) stats.derivedExternal += 1;
    if (tool.annotations && typeof tool.annotations === 'object') stats.annotationsPreserved += 1;
  }
  return stats;
}

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
const snapshots = [];
const matrixFailures = [];
const registeredNames = [];
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
    if (registeredNames.length === 0) registeredNames.push(...host.tools.map((tool) => tool.name));
    const env = childEnvironment(resolveConfig({}), process.env);
    const failures = [];
    const toolNames = host.tools.map((tool) => tool.name).sort();
    const canonicalRoutes = routePairs(host.routes);
    const ownTools = toolNames.filter((name) => !name.startsWith('mcp__rea__'));
    const bridgedTools = toolNames.filter((name) => name.startsWith('mcp__rea__'));
    if (env.ELECTRON_RUN_AS_NODE !== '1') failures.push('child env lost ELECTRON_RUN_AS_NODE');
    if (host.tools.length !== EXPECTED.tools) failures.push(`tools ${host.tools.length} != ${EXPECTED.tools}`);
    if (ownTools.length !== EXPECTED.ownTools) failures.push(`own tools ${ownTools.length} != ${EXPECTED.ownTools}`);
    if (bridgedTools.length !== EXPECTED.bridged) failures.push(`bridged tools ${bridgedTools.length} != ${EXPECTED.bridged}`);
    if (new Set(toolNames).size !== toolNames.length) failures.push('duplicate registered tool name');
    if (host.routes.length !== EXPECTED.routeObjects) failures.push(`route objects ${host.routes.length} != ${EXPECTED.routeObjects}`);
    if (canonicalRoutes.length !== EXPECTED.routePairs) failures.push(`route/method pairs ${canonicalRoutes.length} != ${EXPECTED.routePairs}`);
    if (new Set(host.routes.map((route) => route.path)).size !== host.routes.length) failures.push('duplicate registered route path');
    if (JSON.stringify(canonicalRoutes) !== JSON.stringify(EXPECTED_ROUTES)) {
      failures.push(`route set differs: ${canonicalRoutes.join(', ')}`);
    }
    const recon = host.tools.find((tool) => tool.name === 'rea_reconstruct');
    const actionEnum = recon?.parameters?.properties?.action?.enum;
    if (JSON.stringify(actionEnum) !== JSON.stringify([...RECONSTRUCT_ACTIONS])) {
      failures.push('rea_reconstruct schema action enum differs from RECONSTRUCT_ACTIONS');
    }
    failures.push(...validateGapExecutables(host.tools));
    snapshots.push({
      mode: mode.name,
      tools: toolNames,
      routes: canonicalRoutes,
      fingerprints: host.tools.map(toolFingerprint).sort(),
    });
    const catalog = host.tools.find((tool) => tool.name === 'rea_catalog');
    if (!catalog) failures.push('rea_catalog missing');
    else {
      const answer = await catalog.execute({});
      if (!String(answer?.text ?? '').includes('REA tool catalog')) failures.push('rea_catalog returned no index');
    if (!mode.scoped) {
      const auditCalls = [
        ['rea_reconstruct', { action: 'status', target: join(ROOT_PATH, 'package.json') }, 'own-tool-compile'],
        ['rea_unpack', { target: join(ROOT_PATH, 'package.json') }, 'own-tool-write'],
        ['rea_dynamic_probe', {}, 'own-tool-execute'],
      ];
      for (const [name, args, policy] of auditCalls) {
        const tool = host.tools.find((entry) => entry.name === name);
        if (!tool) failures.push(`${name} missing; cannot verify audit records`);
        else {
          try { await tool.execute(args); } catch {}
          const auditPath = join(sessionArtifactRoot(join(DSH_HOME, 'rea-artifacts')), 'audit.jsonl');
          const records = existsSync(auditPath)
            ? readFileSync(auditPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line))
            : [];
          if (!records.some((record) => record.tool === name && record.policy === policy)) {
            failures.push(`${name} produced no ${policy} audit record`);
          }
        }
      }
    }
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
      // Every plugin-owned tool that takes paths must obey the same scope; a new
      // tool that forgets the guard is exactly what this check exists to catch.
      const compare = host.tools.find((tool) => tool.name === 'rea_compare_build');
      if (!compare) failures.push('rea_compare_build missing; cannot verify own-tool scope');
      else {
        try {
          await compare.execute({ target: 'C:\\Windows\\System32\\kernel32.dll', rebuilt: 'C:\\Windows\\System32\\kernel32.dll', engine: false });
          failures.push('rea_compare_build bypassed allowedTargets');
        } catch (error) {
          if (!/allowedTargets/.test(error?.message ?? '')) failures.push(`unexpected compare refusal: ${error?.message}`);
        }
      }
      const reconstruct = host.tools.find((tool) => tool.name === 'rea_reconstruct');
      if (!reconstruct) failures.push('rea_reconstruct missing; cannot verify loop scope');
      else {
        try {
          await reconstruct.execute({ action: 'start', target: 'C:\\Windows\\System32\\kernel32.dll' });
          failures.push('rea_reconstruct bypassed allowedTargets');
        } catch (error) {
          if (!/allowedTargets/.test(error?.message ?? '')) failures.push(`unexpected reconstruct refusal: ${error?.message}`);
        }
      }
    }
    results.push({
      mode: mode.name, ok: failures.length === 0, tools: host.tools.length,
      routes: host.routes.length, ms: Date.now() - started, failures,
      warnings: host.warnings.slice(0, 3),
    });
    if (classification === null) classification = classificationOf(host.tools);
  } catch (error) {
    results.push({ mode: mode.name, ok: false, tools: host.tools.length, routes: host.routes.length, ms: Date.now() - started, failures: [error.message], warnings: host.warnings.slice(0, 3) });
  } finally {
    for (const dispose of host.disposes.reverse()) { try { dispose(); } catch {} }
  }
}

if (snapshots.length !== MODES.length) {
  matrixFailures.push(`cross-mode comparison has ${snapshots.length}/${MODES.length} snapshots`);
} else {
  const base = snapshots[0];
  for (const snapshot of snapshots.slice(1)) {
    if (JSON.stringify(snapshot.tools) !== JSON.stringify(base.tools)) {
      matrixFailures.push(`${snapshot.mode} tool names differ from ${base.mode}`);
    }
    if (JSON.stringify(snapshot.routes) !== JSON.stringify(base.routes)) {
      matrixFailures.push(`${snapshot.mode} route set differs from ${base.mode}`);
    }
    if (JSON.stringify(snapshot.fingerprints) !== JSON.stringify(base.fingerprints)) {
      matrixFailures.push(`${snapshot.mode} tool metadata fingerprints differ from ${base.mode}`);
    }
  }
}

delete process.env.ELECTRON_RUN_AS_NODE;
console.log(`Host matrix (${process.platform}, node ${process.version})`);
for (const result of results) {
  console.log(`  ${result.ok ? 'PASS' : 'FAIL'} ${result.mode.padEnd(22)} tools=${result.tools} routes=${result.routes} ${result.ms} ms`);
  for (const failure of result.failures) console.log(`       - ${failure}`);
  for (const warning of result.warnings) console.log(`       ! ${warning}`);
}
for (const failure of matrixFailures) console.log(`  FAIL cross-mode ${failure}`);
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
  routeMethods: snapshots[0]?.routes.length ?? 0,
  ...(classification ?? {}),
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
  if (!readme.includes(`${facts.routes} 路由`)) claimFailures.push(`README does not state the route count ${facts.routes}`);
} catch (error) {
  claimFailures.push(`cannot read README.md: ${error.message}`);
}
for (const failure of claimFailures) console.log(`  FAIL claim ${failure}`);

// Structural gate: a module nobody imports is dead code, a script entry that
// points nowhere is a broken command, a plan that names an unregistered tool
// is advice nobody can follow, and a stale structure block is documentation
// drift. All four are checked here so they fail the release instead of aging.
const structureGate = [];
let confirmCount = 0;
{
  const structure = await import(new URL('scripts/gates/update-code-structure.mjs', ROOT).href);
  const reach = structure.moduleReachability(ROOT_PATH);
  if (reach.unreachable.length > 0) {
    structureGate.push(`lib modules with no consumer: ${reach.unreachable.join(', ')}`);
  }
  const readmeStatus = structure.readmeStructureStatus(join(ROOT_PATH, 'README.md'));
  if (!readmeStatus.ok) structureGate.push(readmeStatus.reason);
  const docReferences = validateDocReferences(ROOT_PATH, ['docs/detection-surface.md', 'docs/reconstruction-plan.md']);
  structureGate.push(...docReferences.failures.map((failure) => `doc reference ${failure}`));

  const pkg = JSON.parse(readFileSync(join(ROOT_PATH, 'package.json'), 'utf8'));
  for (const [name, command] of Object.entries(pkg.scripts ?? {})) {
    const tokens = String(command).trim().split(/\s+/);
    if (tokens[0] !== 'node') continue;
    const file = tokens.slice(1).find((token) => !token.startsWith('-'));
    if (file && /\.(?:mjs|js)$/.test(file) && !existsSync(join(ROOT_PATH, file))) {
      structureGate.push(`npm script "${name}" points at missing ${file}`);
    }
  }

  if (registeredNames.length > 0) {
    const { PROVIDER_OF_CONFIRM } = await import(new URL('lib/static/plan.js', ROOT).href);
    const confirmTools = Object.keys(PROVIDER_OF_CONFIRM);
    confirmCount = confirmTools.length;
    if (confirmCount !== EXPECTED.confirmMappings) {
      structureGate.push(`plan confirm mappings ${confirmCount} != ${EXPECTED.confirmMappings}`);
    }
    for (const tool of confirmTools) {
      if (!registeredNames.includes(tool) && !registeredNames.includes(`mcp__rea__${tool}`)) {
        structureGate.push(`plan confirm tool "${tool}" is registered under neither name`);
      }
    }
  }
}
for (const failure of structureGate) console.log(`  FAIL structure ${failure}`);
if (structureGate.length === 0) console.log(`  structure OK (module graph, scripts, ${confirmCount} confirm mappings, README block)`);

console.log(`  facts tools=${facts.tools} routes=${facts.routes}/${facts.routeMethods} readOnly=${facts.readOnly} mutating=${facts.mutating} destructive=${facts.destructive} external=${facts.external} -> dist/host-matrix.json`);

process.exit(
  results.every((result) => result.ok)
  && matrixFailures.length === 0
  && claimFailures.length === 0
  && structureGate.length === 0 ? 0 : 1,
);
