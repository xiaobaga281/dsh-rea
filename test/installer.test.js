import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGeneration } from '../scripts/duel/defender.mjs';
import { detectToolchain, identifyOverlay } from '../lib/installer.js';
import { triageBuffer } from '../lib/triage.js';

test('an Inno Setup payload is named, with its version', () => {
  // Real case: a 28 MB installer whose overlay starts with "zlb\x1a". The
  // report used to call this "likely packed" and tell the analyst to find an
  // OEP that does not exist.
  const body = Buffer.alloc(0x4000, 0);
  const overlay = Buffer.concat([Buffer.from('zlb\x1a', 'latin1'), Buffer.alloc(0x2000, 7)]);
  const file = Buffer.concat([body, overlay]);
  file.write('Inno Setup Setup Data (6.7.0)', 0x80, 'latin1');
  const found = identifyOverlay(file, { overlayOffset: body.length });
  assert.equal(found.id, 'inno-setup');
  assert.equal(found.kind, 'installer');
  assert.equal(found.version, '6.7.0');
  assert.equal(found.payloadBytes, overlay.length);
});

test('the other common installers are recognised from their tail markers', () => {
  const tail = (marker) => {
    const file = Buffer.concat([Buffer.alloc(0x4000, 0), Buffer.alloc(0x4000, 1), Buffer.from(marker, 'latin1')]);
    return identifyOverlay(file, { overlayOffset: 0x4000 });
  };
  assert.equal(tail('NullsoftInst').id, 'nsis');
  assert.equal(tail('MEI\x0c\x0b\x0a\x0b\x0e').id, 'pyinstaller');
  assert.equal(tail('app.asar').id, 'electron');
});

test('an unidentified overlay is reported as bytes, not as a format', () => {
  const file = Buffer.concat([Buffer.alloc(0x1000, 0), Buffer.alloc(0x800, 0xaa)]);
  const found = identifyOverlay(file, { overlayOffset: 0x1000 });
  assert.equal(found.id, null);
  assert.equal(found.kind, 'unknown');
  assert.equal(found.payloadBytes, 0x800);
});

test('a file with nothing appended has no container', () => {
  assert.equal(identifyOverlay(Buffer.alloc(0x1000, 0), { overlayOffset: null }), null);
});

test('the toolchain is read from section names before any string search', () => {
  const delphi = detectToolchain(Buffer.alloc(0), {
    sections: [{ name: '.text' }, { name: '.itext' }, { name: '.didata' }, { name: '.edata' }],
  });
  assert.equal(delphi.id, 'delphi');
  const go = detectToolchain(Buffer.alloc(0), { sections: [{ name: '.text' }, { name: '.gopclntab' }] });
  assert.equal(go.id, 'go');
  assert.equal(detectToolchain(Buffer.from('Go build ID: abc', 'latin1'), {}).id, 'go');
  assert.equal(detectToolchain(Buffer.from('nothing to see', 'latin1'), { sections: [{ name: '.text' }] }), null);
});

test('an installer is not reported as packed code', () => {
  // End to end: take a real generation, append an Inno overlay, and check the
  // verdict, the experiment list and the entropy split.
  const base = buildGeneration('D0').buffer;
  const overlay = Buffer.concat([Buffer.from('zlb\x1a', 'latin1'), Buffer.alloc(0x8000, 0x5a)]);
  const file = Buffer.concat([base, overlay]);
  const report = triageBuffer(file, { name: 'setup.exe' });
  assert.equal(report.verdict, 'installer-with-payload');
  assert.equal(report.container.id, 'inno-setup');
  assert.ok(report.entropy.image, 'the mapped image needs its own entropy');
  assert.ok(report.entropy.image.bytes < file.length, 'the payload is not part of the image');
  assert.equal(report.plan[0].action.startsWith('Extract the'), true);
  assert.ok(!report.plan.some((step) => /walk the call graph/.test(step.action)), 'stub analysis is not the next step');
  assert.ok(report.nextSteps[0].includes('container, not a protected binary'));
});
