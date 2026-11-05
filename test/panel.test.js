/**
 * The sidebar's security section used to be five read-only rows. These tests
 * exist because that is exactly the kind of defect a screenshot catches and a
 * unit test does not: nothing was broken, the controls simply were not there.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

// React puts positional children on `props.children`, and the panel's Section
// reads them from there; the fake has to do the same or nothing renders.
const element = (type, props, ...children) => {
  const filtered = children.flat(Infinity).filter((child) => child !== null && child !== undefined && child !== false);
  const merged = { ...(props ?? {}) };
  if (filtered.length === 1) merged.children = filtered[0];
  else if (filtered.length > 1) merged.children = filtered;
  return { type, props: merged, children: filtered };
};

const React = {
  createElement: element,
  useState: (initial) => [typeof initial === 'function' ? initial() : initial, () => {}],
  useRef: (initial) => ({ current: initial }),
  useCallback: (fn) => fn,
  useEffect: () => {},
  Fragment: 'Fragment',
};

const modules = { react: React, 'react/jsx-runtime': {} };

globalThis.window = {
  __ModuleLoader__: {
    load({ factory }) {
      globalThis.__dshReaClient = factory((name) => {
        if (!(name in modules)) throw new Error(`unexpected require: ${name}`);
        return modules[name];
      });
    },
  },
};

await import('../client.js');
const client = globalThis.__dshReaClient;

const t = (key, ...args) => (typeof args[0] === 'string' ? `${key}:${args.join(',')}` : key);

const status = {
  policy: {
    allowedTargets: 1,
    externalToolCount: 108,
    source: 'row',
    updatedAt: null,
    values: {
      allowedTargets: ['C:\\samples'],
      allowDeviceMutations: false,
      sensitiveArtifacts: false,
      artifactRetentionDays: 7,
      networkEgressPolicy: 'warn',
    },
  },
};

/** Depth-first walk over the vnode tree, expanding function components. */
function walk(node, visit) {
  if (node === null || node === undefined || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const child of node) walk(child, visit); return; }
  if (typeof node.type === 'function') { walk(node.type(node.props), visit); return; }
  visit(node);
  for (const child of node.children ?? []) walk(child, visit);
}

const collect = (tree, predicate) => {
  const found = [];
  walk(tree, (node) => { if (predicate(node)) found.push(node); });
  return found;
};

const render = (overrides = {}) => client.__test.PolicySection({
  t,
  status,
  busy: false,
  draft: null,
  setDraft: () => {},
  onSave: () => {},
  onReset: () => {},
  saved: false,
  dirty: false,
  ...overrides,
});

const renderScope = (overrides = {}) => client.__test.ScopePicker({
  t,
  targets: [],
  onChange: () => {},
  disabled: false,
  ...overrides,
});

test('the security section renders a control for every row it shows', () => {
  const tree = render();
  const rows = collect(tree, (node) => typeof node.props?.className === 'string' && node.props.className.includes('rea-policy-row'));
  assert.equal(rows.length, 5, 'scope, devices, sensitive, retention, egress');
  assert.equal(collect(tree, (node) => node.type === 'input').length, 1);
  assert.equal(collect(tree, (node) => node.type === 'select').length, 0, 'no native dropdown');
  assert.equal(collect(tree, (node) => node.props?.role === 'switch').length, 2);
  assert.equal(collect(tree, (node) => node.props?.role === 'radiogroup').length, 1);
  // The scope is a picker, not a text field.
  assert.equal(collect(tree, (node) => node.type === 'textarea').length, 0);
});

test('the two switches report the value the person clicked, not the current one', () => {
  const seen = [];
  const tree = render({ setDraft: (next) => seen.push(next) });
  const switches = collect(tree, (node) => node.props?.role === 'switch');
  switches[0].props.onClick();
  switches[1].props.onClick();
  assert.equal(seen.length, 2);
  assert.equal(seen[0].allowDeviceMutations, true);
  assert.equal(seen[1].sensitiveArtifacts, true);
  // Each click starts from the same rendered draft, so the second one must not
  // silently carry the first toggle's value.
  assert.equal(seen[1].allowDeviceMutations, false);
  assert.equal(switches[0].props['aria-checked'], 'false');
});

test('the toggles and save button are disabled while a request is in flight', () => {
  const tree = render({ busy: true, dirty: true });
  for (const node of collect(tree, (entry) => entry.props?.role === 'switch')) {
    assert.equal(node.props.disabled, true);
  }
});

test('a green dot means the switch is on, a grey dot means it is off', () => {
  // The earlier build turned the dot amber when a switch was enabled, which
  // read as "the green light died". Green now means on/configured, nothing else.
  const on = render({ draft: { ...status.policy.values, allowDeviceMutations: true, sensitiveArtifacts: true } });
  const onDots = collect(on, (node) => String(node.props?.className ?? '').includes('rea-dot'));
  assert.equal(onDots.filter((node) => node.props.className.includes('rea-ok')).length >= 3, true);
  const off = render();
  const offDots = collect(off, (node) => String(node.props?.className ?? '').includes('rea-dot'));
  assert.ok(offDots.some((node) => node.props.className.includes('rea-off')), 'an off row needs a grey dot');
});

test('the section carries no explanatory prose beyond the labels', () => {
  // Every extra sentence in the sidebar competes with the controls.
  const tree = render();
  assert.equal(collect(tree, (node) => node.props?.className === 'rea-policy-note').length, 0);
  const texts = collect(tree, (node) => typeof node.children?.[0] === 'string').map((node) => node.children[0]);
  assert.ok(texts.every((text) => text.length <= 40));
});

test('the label column is a fixed width so the controls line up', () => {
  assert.ok(client.__test.styles.includes('.rea-policy-row .rea-status-label{width:145px'));
});

test('an empty scope says "unrestricted" instead of showing an empty box', () => {
  const tree = render({ draft: { ...status.policy.values, allowedTargets: [] } });
  const empty = collect(tree, (node) => node.props?.className === 'rea-scope-empty');
  assert.equal(empty.length, 1);
  assert.match(String(empty[0].children[0]), /policyUnrestricted/);
});

test('a scope root can be removed without touching the others', () => {
  const seen = [];
  const draft = { ...status.policy.values, allowedTargets: ['C:\\a', 'D:\\b'] };
  const tree = render({ draft, setDraft: (next) => seen.push(next) });
  const chips = collect(tree, (node) => node.props?.className === 'rea-scope-chip');
  assert.equal(chips.length, 2);
  const remove = collect(chips[0], (node) => node.props?.className === 'rea-scope-x')[0];
  remove.props.onClick();
  assert.deepEqual(seen[0].allowedTargets, ['D:\\b']);
});

test('the scope chip shows the full path, not a basename', () => {
  const tree = render();
  const path = collect(tree, (node) => node.props?.className === 'rea-scope-path')[0];
  assert.equal(path.children[0], 'C:\\samples');
});

test('the picker offers a folder button and an empty state', () => {
  const tree = renderScope();
  const empty = collect(tree, (node) => node.props?.className === 'rea-scope-empty');
  assert.equal(empty.length, 1);
  const buttons = collect(tree, (node) => node.type === 'button');
  assert.ok(buttons.some((node) => node.props.className === 'rea-config'));
  // Nothing is listed until the person opens the picker; that click is the
  // only path to the filesystem, so it must not happen on render.
  assert.equal(collect(tree, (node) => node.props?.className === 'rea-browser').length, 0);
});

test('retention is a bounded number input', () => {
  const tree = render();
  const input = collect(tree, (node) => node.type === 'input')[0];
  assert.equal(input.props.type, 'number');
  assert.equal(input.props.min, 1);
  assert.equal(input.props.max, 365);
  assert.equal(input.props.value, 7);
});

test('egress is a segmented control, not a native dropdown', () => {
  // A <select> renders with the OS chrome, which is why it looked borrowed from
  // another application in a dark panel.
  const tree = render();
  const group = collect(tree, (node) => node.props?.role === 'radiogroup')[0];
  const options = collect(group, (node) => node.props?.role === 'radio');
  assert.deepEqual(options.map((node) => node.props['aria-checked']), ['true', 'false', 'false']);
  const labels = options.map((node) => String(node.children[0]));
  assert.deepEqual(labels, ['egressWarn', 'egressAllow', 'egressDeny']);
});

test('picking an egress value reports the policy name, not the label', () => {
  const seen = [];
  const tree = render({ setDraft: (next) => seen.push(next) });
  const options = collect(tree, (node) => node.props?.role === 'radio');
  options[2].props.onClick();
  assert.equal(seen[0].networkEgressPolicy, 'deny');
});

test('the save button reflects whether anything actually changed', () => {
  const clean = collect(render(), (node) => node.type === 'button' && node.props.className === 'rea-primary')[0];
  assert.equal(clean.props.disabled, true, 'nothing to save on an untouched panel');
  const dirty = collect(render({ dirty: true }), (node) => node.type === 'button' && node.props.className === 'rea-primary')[0];
  assert.equal(dirty.props.disabled, false);
});

test('a policy file that failed validation is shown, not swallowed', () => {
  const broken = { policy: { ...status.policy, error: 'policy.json is not valid JSON' } };
  const tree = render({ status: broken });
  const notes = collect(tree, (node) => node.props?.className === 'rea-policy-note').map((node) => node.children[0]);
  assert.ok(notes.some((text) => String(text).includes('policy.json is not valid JSON')));
});

test('every class the policy section uses is actually styled', () => {
  // A class name with no rule is invisible in review and in the panel: the
  // element renders, it just looks like plain text. This is the check that
  // would have caught the amber dot falling back to no background at all.
  const used = new Set();
  walk(render(), (node) => {
    const value = node.props?.className;
    if (typeof value !== 'string') return;
    for (const name of value.split(/\s+/)) if (name.startsWith('rea-')) used.add(name);
  });
  walk(renderScope(), (node) => {
    const value = node.props?.className;
    if (typeof value !== 'string') return;
    for (const name of value.split(/\s+/)) if (name.startsWith('rea-')) used.add(name);
  });
  const styles = client.__test.styles;
  const missing = [...used].filter((name) => !styles.includes(`.${name}`));
  assert.deepEqual(missing, [], `unstyled classes: ${missing.join(', ')}`);
});
