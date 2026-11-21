import assert from 'node:assert/strict';
import test from 'node:test';

import { compareInteractionContracts, factIsLocatable, interactionContractFrom, interactionLimitations } from '../lib/static/interaction.js';
import { readPeLayout } from '../lib/static/structure.js';

const IMAGE_BASE = 0x140000000;

const layout = {
  plus: true,
  imageBase: IMAGE_BASE,
  entryRva: 0x1000,
  dataDirs: [],
  sections: [{ name: '.text', virtualAddress: 0x1000, virtualSize: 0x2000, rawPointer: 0x400, rawSize: 0x2000 }],
};

// Synthetic Ghidra output in the shapes measured on the project's gcc 16.2.0
// -O0 builds: decimal comparisons for small message values, hex case labels
// for the 0x111 family, and the wndproc as a plain name assigned to a
// code-pointer local.
const winMainBody = [
  'int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)',
  '{',
  '  local_68._0_4_ = 0x50;',
  '  pcStack_60 = WndProc;',
  '  local_28 = ZEXT816(0x14000506c);',
  '  AVar1 = RegisterClassExW((WNDCLASSEXW *)local_68);',
  '  if (AVar1 == 0) { iVar2 = 1; }',
  '  else {',
  '    local_10 = CreateWindowExW(0,(LPCWSTR)local_28._0_8_,L"rea-gui",0x10cf0000,0,0,0x140,0xf0,(HWND)0x0,(HMENU)0x0,hInstance,(LPVOID)0x0);',
  '    CreateWindowExW(0,L"BUTTON",L"click",0x50000000,0x14,0x14,0x78,0x20,local_10,(HMENU)0x65,hInstance,(LPVOID)0x0);',
  '    while( true ) {',
  '      BVar3 = GetMessageW(&local_98,(HWND)0x0,0,0);',
  '      if (BVar3 < 1) break;',
  '      TranslateMessage(&local_98);',
  '      DispatchMessageW(&local_98);',
  '    }',
  '  }',
  '  return iVar2;',
  '}',
].join('\n');

const wndProcBody = [
  'undefined8 WndProc(longlong param_1,uint param_2,ulonglong param_3,longlong param_4)',
  '{',
  '  if (param_2 < 0x114) {',
  '    if (param_2 == 0x111) {',
  '      if ((short)param_3 == 0x65) { WriteFile(0,"x",1,0,0); }',
  '      return 0;',
  '    }',
  '    if (param_2 < 0x112) {',
  '      if (param_2 == 1) { SetTimer(param_1,1,1000,(TIMERPROC)0x0); return 0; }',
  '      if (param_2 == 2) { PostQuitMessage(0); return 0; }',
  '    }',
  '  }',
  '  if (param_2 == 0x113) { KillTimer(param_1,1); return 0; }',
  '  return DefWindowProcW(param_1,param_2,param_3,param_4);',
  '}',
].join('\n');

const functions = [
  { name: 'WinMain', rva: '0x1000', body: winMainBody },
  { name: 'WndProc', rva: '0x1760', body: wndProcBody },
];

const baseImports = { apiFlat: ['RegisterClassExW', 'CreateWindowExW', 'GetMessageW', 'SetTimer', 'CreateFileA', 'WriteFile', 'CloseHandle'] };

function targetContract() {
  return interactionContractFrom({ buffer: Buffer.alloc(0x100), layout, imports: baseImports, functions });
}

test('decimal and hex message constants normalise into one token set', () => {
  const contract = targetContract();
  assert.deepEqual([...contract.messages], ['msg:0x1', 'msg:0x111', 'msg:0x113', 'msg:0x2']);
});

test('the window procedure is resolved from a name reference in WinMain', () => {
  const contract = targetContract();
  assert.ok(contract.windows.has('win:wndproc=WndProc'));
  assert.ok(contract.windows.has('win:class-register'));
  assert.ok(contract.windows.has('win:create'));
});

test('an address constant in image range resolves through the inventory', () => {
  const stripped = [
    'int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)',
    '{',
    '  pcStack_60 = ZEXT816(0x140001760);',
    '  AVar1 = RegisterClassExW((WNDCLASSEXW *)local_68);',
    '  return AVar1;',
    '}',
  ].join('\n');
  const contract = interactionContractFrom({
    buffer: Buffer.alloc(0x100), layout, imports: { apiFlat: ['RegisterClassExW'] },
    functions: [{ name: 'WinMain', rva: '0x1000', body: stripped }, { name: 'FUN_140001760', rva: '0x1760', body: 'undefined8 FUN_140001760(void) { return 0; }' }],
  });
  assert.ok(contract.windows.has('win:wndproc=FUN_140001760'));
  const fact = contract.facts.find((item) => item.token === 'win:wndproc=FUN_140001760');
  assert.equal(fact.via, 'address');
});

test('a direct &Function reference resolves by name', () => {
  const source = [
    'int WINAPI WinMain(HINSTANCE a, HINSTANCE b, char *c, int d) {',
    '  wc.lpfnWndProc = (WNDPROC)&MyProc;',
    '  RegisterClassExW(&wc);',
    '  return 0;',
    '}',
  ].join('\n');
  const contract = interactionContractFrom({
    buffer: Buffer.alloc(0x10), layout, imports: { apiFlat: [] },
    functions: [{ name: 'WinMain', rva: '0x1000', body: source }, { name: 'MyProc', rva: '0x1800', body: 'longlong MyProc(void) { return 0; }' }],
  });
  assert.ok(contract.windows.has('win:wndproc=MyProc'));
});

test('an in-range address with no inventory counterpart is recorded unresolved, never invented', () => {
  const stripped = [
    'int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)',
    '{',
    '  pcStack_60 = ZEXT816(0x140002000);',
    '  RegisterClassExW((WNDCLASSEXW *)local_68);',
    '  return 0;',
    '}',
  ].join('\n');
  const contract = interactionContractFrom({
    buffer: Buffer.alloc(0x100), layout, imports: { apiFlat: ['RegisterClassExW'] },
    functions: [{ name: 'WinMain', rva: '0x1000', body: stripped }],
  });
  assert.ok(![...contract.windows].some((token) => token.startsWith('win:wndproc=')));
  const unresolved = contract.facts.find((item) => item.kind === 'wndproc' && item.token === null);
  assert.ok(unresolved, 'the unresolved reference stays on record');
  assert.equal(unresolved.locatable, false);
  assert.equal(unresolved.address, '0x140002000');
});

test('control ids come from hmenu arguments, timers from SetTimer', () => {
  const contract = targetContract();
  assert.deepEqual([...contract.controls], ['ctl:0x65', 'timer:0x1']);
});

test('WM_NOTIFY is tokenised at its standard value 0x4e', () => {
  const body = [
    'undefined8 DlgProc(longlong param_1,uint param_2,ulonglong param_3,longlong param_4) {',
    '  switch (param_2) {',
    '    case 0x4e: return 1;',
    '    default: return 0;',
    '  }',
    '}',
  ].join('\n');
  const caller = [
    'void OpenDialog(HINSTANCE inst, HWND parent) {',
    '  DialogBoxParamW(inst, 0x65, parent, DlgProc, 0);',
    '}',
  ].join('\n');
  const contract = interactionContractFrom({
    buffer: Buffer.alloc(0x10), layout, imports: { apiFlat: [] },
    functions: [
      { name: 'DlgProc', rva: '0x2000', body },
      { name: 'OpenDialog', rva: '0x2100', body: caller },
    ],
  });
  assert.ok(contract.messages.has('msg:0x4e'));
  assert.ok(contract.windows.has('win:dlgproc=DlgProc'));
  assert.ok(contract.resources.has('res:dialog:0x65'), 'the dialog template id is a resource fact');
});

test('every decompile-channel quote is greppable in the cited body', () => {
  const contract = targetContract();
  assert.ok(contract.facts.length >= 6);
  for (const fact of contract.facts) {
    assert.equal(factIsLocatable(fact, functions), true, `quote must locate: ${fact.quote}`);
  }
  const quote = contract.facts.find((item) => item.token === 'msg:0x111').quote;
  assert.match(quote, /0x111/);
});

test('switch-lowering sentinels and out-of-range constants stay out of the message set', () => {
  const contract = targetContract();
  assert.ok(!contract.messages.has('msg:0x114'));
  assert.ok(!contract.messages.has('msg:0x112'));
  assert.ok(!contract.messages.has('msg:0x50'), 'cbSize-style constants are not messages');
  assert.ok(interactionLimitations().some((line) => line.includes('sentinel')));
});

test('empty measurement is empty/null, and a one-sided surface scores on the existing side', () => {
  const empty = interactionContractFrom({ imports: { apiFlat: [] }, functions: [], buffer: null, layout: null });
  assert.equal(empty.messages.size, 0);
  const none = compareInteractionContracts(empty, empty);
  assert.equal(none.status, 'empty');
  assert.equal(none.score, null);

  // A draft whose window procedure kept only WM_CREATE: every dropped handler
  // lowers message recall, and nothing it lacks is silently forgiven.
  const partialBody = [
    'undefined8 WndProc(longlong param_1,uint param_2,ulonglong param_3,longlong param_4)',
    '{',
    '  if (param_2 == 1) { SetTimer(param_1,1,1000,(TIMERPROC)0x0); return 0; }',
    '  return DefWindowProcW(param_1,param_2,param_3,param_4);',
    '}',
  ].join('\n');
  const rebuilt = interactionContractFrom({
    buffer: Buffer.alloc(0x100), layout, imports: baseImports,
    functions: [functions[0], { name: 'WndProc', rva: '0x1760', body: partialBody }],
  });
  const partial = compareInteractionContracts(targetContract(), rebuilt);
  assert.equal(partial.status, 'ran');
  assert.equal(partial.messages.recall, 0.25, 'three of four message handlers are missing');
  assert.equal(partial.messages.precision, 1, 'nothing invented');
  assert.ok(partial.messages.missing.includes('msg:0x111'));
  assert.equal(partial.windows.recall, 1, 'the window class and wndproc reference are intact');
  assert.ok(partial.score < 1);

  const inverted = compareInteractionContracts(empty, targetContract());
  assert.equal(inverted.status, 'ran');
  assert.equal(inverted.messages.recall, null, 'no target messages means no recall denominator');
  assert.equal(inverted.messages.precision, 0, 'invented messages are imprecise');
  assert.equal(inverted.messages.score, 0);
});

test('identical contracts score 1.0 on all four dimensions', () => {
  const cmp = compareInteractionContracts(targetContract(), targetContract());
  assert.equal(cmp.status, 'ran');
  assert.equal(cmp.score, 1);
  assert.equal(cmp.windows.recall, 1);
  assert.equal(cmp.messages.precision, 1);
  assert.equal(cmp.controls.recall, 1);
  assert.equal(cmp.resources.recall, null, 'no resources declared on either side');
});

test('resource ids are read from the .rsrc directory', () => {
  const buffer = Buffer.alloc(0x800);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write('PE\0\0', 0x80, 'latin1');
  buffer.writeUInt16LE(1, 0x86);
  buffer.writeUInt16LE(0xe0, 0x94);
  const opt = 0x98;
  buffer.writeUInt16LE(0x10b, opt);
  buffer.writeUInt32LE(0x1000, opt + 16);
  buffer.writeUInt32LE(16, opt + 92);
  const dd = opt + 96;
  buffer.writeUInt32LE(0x2000, dd + 2 * 8); // data directory 2 = resource table
  buffer.writeUInt32LE(0x100, dd + 2 * 8 + 4);
  const section = opt + 0xe0;
  buffer.write('.rsrc\0\0\0', section, 'latin1');
  buffer.writeUInt32LE(0x400, section + 8);
  buffer.writeUInt32LE(0x2000, section + 12);
  buffer.writeUInt32LE(0x400, section + 16);
  buffer.writeUInt32LE(0x400, section + 20);
  // Resource directory at RVA 0x2000 -> file 0x400: root with one id entry
  // (type RT_DIALOG=5) pointing at a subdirectory with id 0x65.
  buffer.writeUInt16LE(1, 0x40e);
  buffer.writeUInt32LE(5, 0x410);
  buffer.writeUInt32LE(0x80000010, 0x414);
  buffer.writeUInt16LE(1, 0x41e);
  buffer.writeUInt32LE(0x65, 0x420);
  buffer.writeUInt32LE(0x20, 0x424);
  buffer.writeUInt32LE(0x2100, 0x440);
  buffer.writeUInt32LE(0x10, 0x444);

  const peLayout = readPeLayout(buffer);
  assert.ok(peLayout, 'the synthetic PE must parse');
  const contract = interactionContractFrom({ buffer, layout: peLayout, imports: { apiFlat: [] }, functions: [] });
  assert.ok(contract.resources.has('res:dialog:0x65'), `resources: ${[...contract.resources].join(', ')}`);
  const fact = contract.facts.find((item) => item.token === 'res:dialog:0x65');
  assert.equal(fact.channel, 'pe-resources');
});

test('limitations state the heuristic boundary honestly', () => {
  const lines = interactionLimitations();
  assert.ok(lines.some((line) => line.includes('user32/kernel32')));
  assert.ok(lines.some((line) => line.includes('Qt, WebView, Electron')));
  assert.ok(lines.some((line) => line.includes('WM_USER + n')));
  assert.ok(lines.some((line) => line.includes('opt-in')));
  assert.ok(lines.some((line) => line.includes('truncated inventory')));
});
