/**
 * Detection-surface matrix (A round, 2026-11-20): documentation, wording and
 * default pins. Pure file/config assertions - zero execution, zero network,
 * no fixture compile. The heavier guarantees are reused, not rewritten here:
 * gate/identity/interception behaviour lives in test/trace.test.js,
 * test/observe.test.js, test/capability-hardening.test.js and
 * test/sandbox.test.js (including the orphan + external-kill job cleanup
 * measurements), and the tool-count claim is pinned by the host-matrix README
 * claims gate (scripts/host-matrix.mjs).
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';

import { resolveConfig } from '../lib/config.js';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..');
const read = (relative) => readFile(join(ROOT, relative), 'utf8');

const BANNED_WORDS = ['任何', '保证', '全部', '不惊动', 'undetectable'];

/** The 措辞纪律 line itself lists the banned words - skip it. */
const lintAbsolutized = (text) => text
  .split(/\r?\n/)
  .filter((line) => !/措辞纪律/.test(line))
  .filter((line) => BANNED_WORDS.some((word) => line.includes(word)));

const README_SECTION = (() => {
  const start = '### 检测面与静默姿态';
  const next = '\n### ';
  return { start, next };
})();

test('the detection-surface matrix exists with the baseline row and all DS rows, each citing code', async () => {
  const doc = await read('docs/detection-surface.md');
  // Baseline row: zero target execution = zero target-side detection surface.
  assert.match(doc, /基线行：目标零执行 = 目标侧零检测面/);
  assert.match(doc, /lib\/recon-tools\.js:\d+/);
  assert.match(doc, /lib\/ghidra-local\.js:\d+/);
  assert.match(doc, /lib\/unpack\.js:\d+/);
  // Six columns + every dynamic row, with code citations per row.
  for (const column of ['目标进程存在', '被注入', '被调试通道', '环境异样', '令牌特殊', '行为差异']) {
    assert.ok(doc.includes(column), `missing matrix column: ${column}`);
  }
  for (const row of ['DS-1', "DS-1'", 'DS-2', 'DS-3', 'DS-4', 'DS-5']) {
    assert.ok(doc.includes(row), `missing matrix row: ${row}`);
  }
  // DS-1' records the post-fix job state (LimitFlags actually assigned +
  // the external-kill re-qualification), not the pre-2026-11-20 narrative.
  assert.match(doc, /LimitFlags/);
  assert.match(doc, /勘误注记/);
  // Each dynamic row section carries at least one file:line citation.
  for (const heading of ['### DS-1 rea_trace_behavior', "### DS-1' rea_trace_behavior", '### DS-2 rea_dynamic_probe', '### DS-3 rea_memory_dump', '### DS-4 rea_side_effects', '### DS-5 宿主侧痕迹行']) {
    const index = doc.indexOf(heading);
    assert.ok(index >= 0, `missing row heading: ${heading}`);
    const body = doc.slice(index, doc.indexOf('\n### ', index) === -1 ? doc.length : doc.indexOf('\n### ', index));
    assert.match(body, /\[代码 [^\n]*?[\w./-]+:\d+/, `row ${heading} has no [代码] file:line citation`);
    assert.match(body, /\[(?:实测引用|分析，未实测)/, `row ${heading} has no evidence-grade tag`);
  }
  // The declared blind-spot footer quotes the existing statements.
  assert.match(doc, /lib\/sandbox\.js:\d+/);
  assert.match(doc, /UDP sendto/);
  assert.match(doc, /VMProtect/);
});

test('wording lint: the matrix doc and the README subsection contain no absolutized claims', async () => {
  const doc = await read('docs/detection-surface.md');
  assert.deepEqual(lintAbsolutized(doc), [], `absolutized wording in docs/detection-surface.md`);
  const readme = await read('README.md');
  const start = readme.indexOf(README_SECTION.start);
  assert.ok(start >= 0, 'README lacks the 检测面与静默姿态 subsection');
  const rest = readme.slice(start + README_SECTION.start.length);
  const end = rest.indexOf(README_SECTION.next);
  const section = end === -1 ? rest : rest.slice(0, end);
  assert.deepEqual(lintAbsolutized(section), [], 'absolutized wording in the README detection-surface subsection');
  // The boundary statement itself must be present in both.
  assert.match(doc, /不做主动规避反逆向\/反调试机制的工具/);
  assert.match(section, /不做主动规避反逆向\/反调试机制的工具/);
  assert.match(section, /docs\/detection-surface\.md/);
});

test('static-first defaults are pinned: sample execution off, host protection on', () => {
  const config = resolveConfig({});
  assert.equal(config.allowSampleExecution, false, 'sample execution must stay off by default (config.js:115)');
  assert.equal(config.sandboxSampleExecution, false, 'kernel containment must be its own opt-in (config.js:120)');
  assert.equal(config.blockSampleEgress, true, 'egress blocking is opt-out (config.js:125)');
  assert.equal(config.redactIdentity, true, 'identity redaction is opt-out (config.js:126)');
});

test('the dynamic.js wording contradiction is fixed and the four execution tools point at the matrix', async () => {
  const dynamic = await read('lib/dynamic.js');
  assert.ok(!dynamic.includes('does not patch, inject or persist anything'),
    'the old claim contradicted probe.py Interceptor.attach and observe.py "patches the export address itself"');
  assert.match(dynamic, /docs\/detection-surface\.md/);
  assert.match(dynamic, /inject a Frida agent/);
  for (const file of ['lib/trace-tools.js', 'lib/dynamic-tools.js', 'lib/memdump-tools.js', 'lib/observe-tools.js']) {
    const source = await read(file);
    assert.match(source, /docs\/detection-surface\.md/, `${file} does not point at the matrix`);
  }
});

test('the boundary statement landed in all three documented locations', async () => {
  const plan = await read('docs/reconstruction-plan.md');
  // §11 诚实边界 carries the full statement; §13 执行安全边界 references the matrix.
  assert.ok(plan.includes('## 11. 诚实边界（明确不承诺）'));
  assert.match(plan, /不做主动规避反逆向\/反调试机制的工具[\s\S]*?docs\/detection-surface\.md/);
  assert.match(plan, /### 执行安全边界[\s\S]*?docs\/detection-surface\.md/);
  const readme = await read('README.md');
  assert.ok(readme.includes('### 检测面与静默姿态'), 'README 已知边界 lacks the detection-surface subsection');
});

test('the live guarantees are reused from the existing suites, not duplicated here', async () => {
  const sandboxTests = await read('test/sandbox.test.js');
  assert.match(sandboxTests, /an orphaned grandchild is reaped when the launcher exits/);
  assert.match(sandboxTests, /killing the launcher externally reaps the job tree/);
  // The matrix doc names the gates that keep its numbers honest.
  const doc = await read('docs/detection-surface.md');
  assert.match(doc, /test\/detection-surface\.test\.js/);
  assert.match(doc, /host-matrix/);
});
