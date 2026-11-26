import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createArtifactStore } from '../lib/infra/artifacts.js';
import { buildReadiness, compileC } from '../lib/restore/build.js';
import { compareTraces, runTrace } from '../lib/dynamic/trace.js';
import { buildTraceBehaviorTool } from '../lib/surface/trace-tools.js';

const sourceThatWrites = [
  '#include <stdio.h>',
  'int main(void) {',
  '  FILE *f = fopen("state.dat", "wb");',
  '  if (f) { fputs("one", f); fclose(f); }',
  '  printf("alpha\\n");',
  '  return 3;',
  '}',
].join('\n');

const sourceThatDoesNot = [
  '#include <stdio.h>',
  'int main(void) { printf("beta\\n"); return 0; }',
].join('\n');

test('a trace captures exit code, output and the files a run left behind', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const workDir = join(dir, 'run');
    // Run a shell-free command that exists on every supported host instead of a
    // compiled binary: node itself, with an inline script that writes a file.
    const node = process.execPath;
    const script = 'const fs=require("fs");fs.writeFileSync("state.dat","one");console.log("alpha");process.exit(3)';
    const trace = await runTrace({ exePath: node, args: ['-e', script], workDir });
    assert.equal(trace.ok, true, trace.reason);
    assert.equal(trace.exitCode, 3);
    assert.match(trace.stdout, /alpha/);
    assert.ok(trace.files.some((file) => file.path === 'state.dat' && file.sha256));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an identical run scores 1.0 and a different output or file lowers the trace score', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const node = process.execPath;
    const a = join(dir, 'a');
    const b = join(dir, 'b');
    const alpha = 'const fs=require("fs");fs.writeFileSync("state.dat","one");console.log("alpha");process.exit(3)';
    const beta = 'console.log("beta")';
    const target = await runTrace({ exePath: node, args: ['-e', alpha], workDir: a });
    const same = await runTrace({ exePath: node, args: ['-e', alpha], workDir: join(a, '..', 'a2') });
    const different = await runTrace({ exePath: node, args: ['-e', beta], workDir: b });
    assert.equal(compareTraces(target, same).score, 1);
    const diff = compareTraces(target, different);
    assert.ok(diff.score < 1);
    assert.equal(diff.exit.same, false);
    assert.equal(diff.stdout.identical, false);
    assert.ok(diff.files.missing.includes('state.dat'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the trace tool refuses without the policy flag or the per-call confirmation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const store = createArtifactStore({ root: join(dir, 'artifacts'), base: dir });
    const disabled = buildTraceBehaviorTool({ config: {}, store });
    assert.match((await disabled.execute({ target: join(dir, 'a.exe'), rebuilt: join(dir, 'b.exe'), confirm: true })).text, /sample execution is disabled/);

    const unconfirmed = buildTraceBehaviorTool({ config: { allowSampleExecution: true }, store });
    assert.match((await unconfirmed.execute({ target: join(dir, 'a.exe'), rebuilt: join(dir, 'b.exe'), confirm: false })).text, /confirm must be true/);

    const enabled = buildTraceBehaviorTool({ config: { allowSampleExecution: true }, store });
    const missing = await enabled.execute({ target: join(dir, 'missing-a.exe'), rebuilt: join(dir, 'missing-b.exe'), confirm: true });
    assert.match(missing.text, /does not exist|cannot be started|must be an absolute path/);
    assert.ok(!existsSync(join(dir, 'missing-a.exe')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a sandbox launch failure stops after the target and cannot produce a success receipt', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-sandbox-fail-'));
  try {
    const target = join(dir, 'target.exe');
    const rebuilt = join(dir, 'rebuilt.exe');
    await writeFile(target, 'MZ target fixture');
    await writeFile(rebuilt, 'MZ rebuilt fixture');
    const calls = [];
    let evidenceWrites = 0;
    const store = {
      statePath: () => join(dir, 'state.json'),
      write: async () => { throw new Error('a failed trace must not be persisted as a success'); },
      writeEvidence: async () => { evidenceWrites += 1; },
    };
    const tool = buildTraceBehaviorTool({
      config: { allowSampleExecution: true, sandboxSampleExecution: true },
      store,
      run: async (input) => {
        calls.push(input);
        return {
          ok: false, reason: 'sandbox launch failed: assign-job', exitCode: null,
          timedOut: false, durationMs: 1, stdout: '', stderr: '', files: [],
          sandbox: { enabled: true, ran: false, jobEnforced: false },
        };
      },
    });
    const result = await tool.execute({ target, rebuilt, confirm: true, sandbox: true });
    assert.equal(calls.length, 1, 'the rebuilt binary must not run after the target failed to start');
    assert.equal(calls[0].sandbox, true);
    assert.match(result.text, /sandbox launch failed/);
    assert.doesNotMatch(result.text, /evidenceId:|receipt:/);
    assert.equal(evidenceWrites, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the trace tool compares two compiled programs end to end', async (t) => {
  const readiness = await buildReadiness();
  if (!readiness.ready) {
    t.skip(`no build engine (${readiness.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const a = await compileC({ sourceText: sourceThatWrites, workDir: join(dir, 'a'), name: 'a' });
    const b = await compileC({ sourceText: sourceThatDoesNot, workDir: join(dir, 'b'), name: 'b' });
    assert.equal(a.ok, true, a.reason);
    assert.equal(b.ok, true, b.reason);
    const store = createArtifactStore({ root: join(dir, 'artifacts'), base: dir });
    const tool = buildTraceBehaviorTool({ config: { allowSampleExecution: true }, store });
    const answer = await tool.execute({ target: a.outPath, rebuilt: b.outPath, confirm: true, timeoutMs: 10_000 });
    assert.match(answer.text, /runtime behaviour:/);
    assert.match(answer.text, /missing files: state.dat/);
    assert.match(answer.text, /no sandbox/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('profile and temp are redirected so state outside the working directory is observable', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const node = process.execPath;
    const script = 'const fs=require("fs"),p=require("path");fs.writeFileSync(p.join(process.env.TEMP,"cached.dat"),"v");console.log("ok")';
    const first = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'one') });
    const second = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'two') });
    assert.equal(first.profileIsolated, true);
    assert.ok(first.files.some((file) => file.path === 'profile/temp/cached.dat'), 'TEMP is inside the run directory');
    assert.equal(compareTraces(first, second).score, 1, 'two isolated runs compare on the same relative paths');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('identity env vars are masked to neutral values, identically for both sides, and can be turned off', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const node = process.execPath;
    const script = 'console.log([process.env.COMPUTERNAME, process.env.USERNAME, process.env.USERDOMAIN].join(" "))';
    const masked = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'one') });
    assert.equal(masked.ok, true, masked.reason);
    assert.equal(masked.identityMasked, true);
    assert.match(masked.stdout, /rea-sandbox analyst REAGROUP/);
    assert.ok(!masked.stdout.includes(hostname()), 'the real machine name must not reach the sample environment');
    // The per-call option restores the inherited environment (the config-level
    // switch is redactIdentity; runTrace stays explicit for tests).
    const raw = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'two'), maskIdentity: false });
    assert.equal(raw.identityMasked, false);
    assert.ok(raw.stdout.includes(hostname()));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a sample that prints its own pid does not cap the comparison: pids are masked to [PID]', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-trace-'));
  try {
    const node = process.execPath;
    const script = 'console.log("pid", process.pid)';
    const a = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'a') });
    const b = await runTrace({ exePath: node, args: ['-e', script], workDir: join(dir, 'b') });
    assert.equal(a.stdout, 'pid [PID]\n');
    assert.equal(b.stdout, 'pid [PID]\n');
    assert.equal(compareTraces(a, b).score, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
