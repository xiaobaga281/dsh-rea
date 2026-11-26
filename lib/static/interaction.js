/**
 * GUI interaction surface: what a binary's window layer declares it handles.
 *
 * A rebuild can match every import and every literal and still differ where the
 * analyst actually sees the program: which window class it registers, which
 * window/dialog procedure backs it, which messages that procedure handles,
 * which control and timer ids it addresses, and which dialog resources ship in
 * .rsrc. This module turns that surface into four comparable token sets so the
 * loop can score it on recall and precision without ever creating a window:
 *
 *   windows    - win:class-register, win:create, win:dialog, win:wndproc=<fn>,
 *                win:dlgproc=<fn>
 *   messages   - msg:0x1 (WM_CREATE), msg:0x2 (WM_DESTROY), msg:0x111
 *                (WM_COMMAND), msg:0x113 (WM_TIMER), msg:0x4e (WM_NOTIFY), ...
 *   controls   - ctl:0x65 (button id from an hmenu/GetDlgItem argument),
 *                timer:0x1 (SetTimer id)
 *   resources  - res:dialog:0x65 (a .rsrc directory entry of type RT_DIALOG)
 *
 * Every fact carries a `quote` that is greppable in the evidence it came from
 * (the decompiled body for ghidra-decompile facts, the import table for
 * pe-imports facts), so a claimed message constant can be checked against the
 * listing instead of taken on faith. The extraction is deliberately heuristic
 * and its blind spots are printed, not hidden - see `interactionLimitations`.
 *
 * The message-parameter convention below is the one Ghidra emits for the
 * standard Win32 signatures: for both WndProc(HWND, UINT msg, WPARAM, LPARAM)
 * and DialogProc(HWND, UINT msg, WPARAM, LPARAM) the message arrives in
 * `param_2` and wParam in `param_3`. At -O0 gcc emits decimal comparisons
 * (`if (param_2 == 1)` for WM_CREATE) while jump-table switches keep hex case
 * labels (`case 0x111:`), so both forms are normalised to the same token.
 *
 * @module dsh-rea-restore/lib/interaction
 */

import { diffDimension } from './behavior.js';
import { findListedFunction, normalizeQuote, toRvaNumber } from './function-matching.js';
import { rvaToOffset } from './structure.js';

const MAX_FACTS = 400;
const MAX_TOKENS = 250;
// Window messages and control ids live below 64 KiB; this keeps ordinary
// pointer-sized constants out of both sets.
const MAX_MESSAGE_ID = 0xffff;

/**
 * Standard window messages (winuser.h). Annotation only: the scored token is
 * the normalised number, because a decompiler prints either the decimal or the
 * hex form depending on how the compiler lowered the comparison.
 */
const WM_NAMES = new Map([
  [0x0000, 'WM_NULL'],
  [0x0001, 'WM_CREATE'],
  [0x0002, 'WM_DESTROY'],
  [0x0003, 'WM_MOVE'],
  [0x0005, 'WM_SIZE'],
  [0x0006, 'WM_ACTIVATE'],
  [0x0007, 'WM_SETFOCUS'],
  [0x0008, 'WM_KILLFOCUS'],
  [0x000a, 'WM_ENABLE'],
  [0x000c, 'WM_SETTEXT'],
  [0x000f, 'WM_PAINT'],
  [0x0010, 'WM_CLOSE'],
  [0x0011, 'WM_QUERYENDSESSION'],
  [0x0012, 'WM_QUIT'],
  [0x0013, 'WM_QUERYOPEN'],
  [0x0016, 'WM_ACTIVATEAPP'],
  [0x001c, 'WM_POWERBROADCAST'],
  [0x0021, 'WM_MOUSEACTIVATE'],
  [0x0024, 'WM_GETMINMAXINFO'],
  [0x0046, 'WM_WINDOWPOSCHANGING'],
  [0x0047, 'WM_WINDOWPOSCHANGED'],
  [0x004e, 'WM_NOTIFY'],
  [0x0085, 'WM_NCPAINT'],
  [0x0086, 'WM_NCACTIVATE'],
  [0x0100, 'WM_KEYDOWN'],
  [0x0101, 'WM_KEYUP'],
  [0x0102, 'WM_CHAR'],
  [0x0104, 'WM_SYSKEYDOWN'],
  [0x0106, 'WM_SYSCHAR'],
  [0x0111, 'WM_COMMAND'],
  [0x0112, 'WM_SYSCOMMAND'],
  [0x0113, 'WM_TIMER'],
  [0x0114, 'WM_HSCROLL'],
  [0x0115, 'WM_VSCROLL'],
  [0x0116, 'WM_INITMENU'],
  [0x0200, 'WM_MOUSEMOVE'],
  [0x0201, 'WM_LBUTTONDOWN'],
  [0x0202, 'WM_LBUTTONUP'],
  [0x0203, 'WM_LBUTTONDBLCLK'],
  [0x0204, 'WM_RBUTTONDOWN'],
  [0x0205, 'WM_RBUTTONUP'],
  [0x020a, 'WM_MOUSEWHEEL'],
  [0x02a1, 'WM_MOUSEHOVER'],
  [0x02a3, 'WM_MOUSELEAVE'],
  [0x02b1, 'WM_DPICHANGED'],
]);

/** Standard .rsrc type ids (winuser.h RT_*). */
const RESOURCE_TYPES = new Map([
  [1, 'cursor'], [2, 'bitmap'], [3, 'icon'], [4, 'menu'], [5, 'dialog'],
  [6, 'string'], [7, 'fontdir'], [8, 'font'], [9, 'accelerator'], [10, 'rcdata'],
  [11, 'messagetable'], [12, 'groupcursor'], [14, 'groupicon'], [16, 'version'],
  [23, 'plugplay'], [24, 'manifest'], [42, 'tlstable'],
]);

const WINDOW_CALL = /\b(?:RegisterClassEx?[WA]|CreateWindowEx?[WA]|DialogBox(?:Param)?[WA]|CreateDialog(?:Param)?[WA])\s*\(/;
const CREATE_WINDOW = /\bCreateWindowEx?[WA]\s*\(/;
const DIALOG_CALL = /\b(?:DialogBox|CreateDialog)(?:Param)?[WA]?\s*\(/;
const GETDLGITEM = /\bGetDlgItem(?:[WAI]|Text[WA])?\s*\(/;
const SETTIMER = /\bSetTimer\s*\(/;
const SENDMESSAGE = /\b(?:SendMessage|PostMessage)[WA]?\s*\(/;
const HMENU_CAST = /\(\s*HMENU\s*\)\s*(?:\(\s*[\w ]+\s*\)\s*)?(0x[0-9a-fA-F]+|\d+)/;
const WNDPROC_ASSIGN = /\blpfnWndProc\b|\(\s*(?:WNDPROC|DLGPROC|FARPROC)\s*\)/;
// Measured on the R5 specimen (gcc 16.2.0 -O0): Ghidra spills the wndproc into
// a code-pointer local, so the reference line reads `pcStack_60 = WndProc;` -
// no window API on it. The line is a proc-reference context when it names a
// wndproc/dialogproc, casts to a proc pointer type, or assigns a Ghidra
// code-pointer local (pc-prefixed / `code *`).
const PROC_LINE = /wndproc|dialogproc|dlgproc|(?:\bcode\s*\*)|\bpc[A-Z_]/i;

const parseId = (text) => {
  const value = toRvaNumber(text);
  return value !== null && value > 0 && value <= MAX_MESSAGE_ID ? value : null;
};

const hex = (value) => `0x${value.toString(16)}`;

/** Image extent from the layout, used to tell a code VA from a plain constant. */
function imageExtent(layout, fallbackBytes = 0) {
  if (!layout || !Number.isFinite(layout.imageBase)) return { base: null, end: null };
  let end = layout.imageBase + Math.max(fallbackBytes, 0x1000);
  for (const section of layout.sections ?? []) {
    const span = Math.max(section.virtualSize ?? 0, section.rawSize ?? 0);
    end = Math.max(end, layout.imageBase + section.virtualAddress + span);
  }
  return { base: layout.imageBase, end };
}

/**
 * Resolve one window-procedure reference in a decompiled line. Three forms are
 * handled, in decreasing order of trust:
 *   1. a named reference: `&WndProc` or `(WNDPROC)WndProc`;
 *   2. a bare identifier that names an inventoried function (`..., WndProc)`);
 *   3. an address constant in image range (`ZEXT816(0x140001760)`): the value
 *      is converted VA -> RVA with the layout's image base and matched against
 *      the function inventory.
 * A name/address that resolves is returned with its function; an in-range
 * address with no inventory counterpart is returned unresolved so the caller
 * can record the fact without inventing a name.
 */
function resolveProcFromLine(line, functions, extent) {
  for (const match of String(line).matchAll(/(?:&\s*|\(\s*(?:WNDPROC|DLGPROC|FARPROC)\s*\)\s*)([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const fn = findListedFunction(functions, null, match[1]);
    if (fn) return { fn, via: 'name' };
  }
  for (const match of String(line).matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
    const fn = findListedFunction(functions, null, match[1]);
    if (fn && fn.name === match[1]) return { fn, via: 'name' };
  }
  if (extent.base !== null) {
    for (const match of String(line).matchAll(/0x([0-9a-fA-F]{6,16})/g)) {
      const va = Number.parseInt(match[1], 16);
      if (!Number.isFinite(va) || va < extent.base || va >= extent.end) continue;
      const fn = findListedFunction(functions, va - extent.base, null);
      return fn
        ? { fn, via: 'address' }
        : { address: hex(va), unresolved: true };
    }
  }
  return null;
}

class Contract {
  constructor() {
    this.windows = new Set();
    this.messages = new Set();
    this.controls = new Set();
    this.resources = new Set();
    this.facts = [];
    this.seen = new Set();
  }

  add(setName, kind, token, { quote = '', channel = 'ghidra-decompile', at = null, extra = null } = {}) {
    if (this.facts.length >= MAX_FACTS) return;
    const set = this[setName];
    if (token !== null && set.size < MAX_TOKENS) set.add(token);
    const key = `${kind}|${token ?? ''}|${at ?? ''}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const fact = { kind, token, quote: String(quote ?? '').trim(), channel, at };
    if (extra) Object.assign(fact, extra);
    this.facts.push(fact);
  }
}

/**
 * Window-procedure candidates. Primary: functions referenced from window
 * creation/registration call sites or lpfnWndProc assignments. Fallback:
 * functions that switch on their second parameter - the standard message
 * parameter of both WndProc and DialogProc. The fallback keeps the tier usable
 * when the reference travelled through a register the decompiler did not tie
 * back to a named function.
 */
function procedureCandidates(functions, extent, contract) {
  const primary = new Map();
  for (const fn of functions) {
    if (!fn || typeof fn.body !== 'string') continue;
    // pc-local lines are only trusted inside a function that actually calls a
    // window API - CRT startup code also assigns pc-prefixed pointers and must
    // not turn into phantom window procedures.
    const hasWindowCall = WINDOW_CALL.test(fn.body);
    for (const raw of fn.body.split(/\r?\n/)) {
      const isWindowLine = WINDOW_CALL.test(raw) || WNDPROC_ASSIGN.test(raw) || (hasWindowCall && PROC_LINE.test(raw));
      if (!isWindowLine) continue;
      const resolved = resolveProcFromLine(raw, functions, extent);
      if (resolved?.fn && !primary.has(resolved.fn.name)) {
        primary.set(resolved.fn.name, resolved.fn);
        const isDialog = /DialogBox|CreateDialog|DLGPROC/i.test(raw);
        contract.add('windows', isDialog ? 'dialogproc' : 'wndproc', `win:${isDialog ? 'dlgproc' : 'wndproc'}=${resolved.fn.name}`, {
          quote: raw, at: fn.name, extra: { via: resolved.via },
        });
      } else if (resolved?.unresolved) {
        contract.add('windows', 'wndproc', null, {
          quote: raw, at: fn.name,
          extra: { locatable: false, address: resolved.address, note: 'address is in image range but has no counterpart in the function inventory' },
        });
      }
    }
  }
  const candidates = new Map(primary);
  for (const fn of functions) {
    if (!fn || typeof fn.body !== 'string' || candidates.has(fn.name)) continue;
    if (/\bswitch\s*\(\s*param_2\s*\)/.test(fn.body)) candidates.set(fn.name, fn);
  }
  return candidates;
}

/**
 * Message constants inside one window/dialog procedure body: switch cases and
 * equality comparisons on the message parameter (param_2 for both WndProc and
 * DialogProc), plus messages sent by name from the procedure itself. Range
 * checks (the switch-lowering sentinels) are not comparisons, so they stay out.
 */
function extractProcedureMessages(fn, contract) {
  const lines = String(fn.body ?? '').split(/\r?\n/);
  let switchSubject = null;
  for (const raw of lines) {
    const switchMatch = raw.match(/\bswitch\s*\(\s*(param_\d+|[A-Za-z_][A-Za-z0-9_]*)\s*\)/);
    if (switchMatch) switchSubject = switchMatch[1];

    const caseMatch = raw.match(/\bcase\s+(0x[0-9a-fA-F]+|\d+)\s*:/);
    if (caseMatch && switchSubject === 'param_2') {
      const value = parseId(caseMatch[1]);
      if (value !== null) {
        contract.add('messages', 'message', `msg:${hex(value)}`, {
          quote: raw, at: fn.name, extra: { name: WM_NAMES.get(value) ?? null },
        });
      }
    }

    for (const match of raw.matchAll(/\bparam_2\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|\d+)/g)) {
      const value = parseId(match[1]);
      if (value !== null) {
        contract.add('messages', 'message', `msg:${hex(value)}`, {
          quote: raw, at: fn.name, extra: { name: WM_NAMES.get(value) ?? null },
        });
      }
    }
    for (const match of raw.matchAll(/\b(0x[0-9a-fA-F]+|\d+)\s*(?:==|!=)\s*param_2\b/g)) {
      const value = parseId(match[1]);
      if (value !== null) {
        contract.add('messages', 'message', `msg:${hex(value)}`, {
          quote: raw, at: fn.name, extra: { name: WM_NAMES.get(value) ?? null },
        });
      }
    }

    if (SENDMESSAGE.test(raw)) {
      const match = raw.match(/\b(?:SendMessage|PostMessage)[WA]?\s*\([^,()]+,\s*(0x[0-9a-fA-F]+|\d+)/);
      const value = match === null ? null : parseId(match[1]);
      if (value !== null) {
        contract.add('messages', 'message', `msg:${hex(value)}`, {
          quote: raw, at: fn.name, extra: { name: WM_NAMES.get(value) ?? null },
        });
      }
    }
  }
}

/**
 * Control/timer/dialog-resource id constants at their call sites. These live
 * in whatever function builds the UI (WinMain in the R5 specimen), so they are
 * scanned across the whole inventory, not only procedure candidates.
 */
function extractCallSites(fn, contract) {
  const lines = String(fn.body ?? '').split(/\r?\n/);
  for (const raw of lines) {
    if (GETDLGITEM.test(raw)) {
      for (const match of raw.matchAll(/GetDlgItem(?:[WAI]|Text[WA])?\s*\([^,()]+,\s*(0x[0-9a-fA-F]+|\d+)/g)) {
        const value = parseId(match[1]);
        if (value !== null) contract.add('controls', 'control', `ctl:${hex(value)}`, { quote: raw, at: fn.name });
      }
    }
    if (CREATE_WINDOW.test(raw)) {
      const match = raw.match(HMENU_CAST);
      const value = match === null ? null : parseId(match[1]);
      if (value !== null) contract.add('controls', 'control', `ctl:${hex(value)}`, { quote: raw, at: fn.name });
    }
    if (SETTIMER.test(raw)) {
      const match = raw.match(/SetTimer\s*\([^,()]+,\s*(0x[0-9a-fA-F]+|\d+)/);
      const value = match === null ? null : parseId(match[1]);
      if (value !== null) {
        contract.add('controls', 'timer', `timer:${hex(value)}`, { quote: raw, at: fn.name });
      }
    }
    if (DIALOG_CALL.test(raw)) {
      const match = raw.match(/\b(?:DialogBox|CreateDialog)(?:Param)?[WA]?\s*\([^,()]+,\s*(?:MAKEINTRESOURCE[WA]?\s*\(\s*)?(0x[0-9a-fA-F]+|\d+)/);
      const value = match === null ? null : parseId(match[1]);
      if (value !== null) {
        contract.add('resources', 'resource', `res:dialog:${hex(value)}`, { quote: raw, at: fn.name });
      }
    }
  }
}

/**
 * .rsrc directory entries: type and id presence only. A full DLGTEMPLATE walk
 * (control class/id layout) is deliberately out of scope for this version.
 */
function extractResources(buffer, layout, contract) {
  const directory = layout?.dataDirs?.[2];
  if (!directory || !directory.rva || !directory.size) return;
  const base = rvaToOffset(layout, directory.rva);
  if (base === null || base + 16 > buffer.length) return;
  const walk = (at, depth, typeId) => {
    if (at + 16 > buffer.length || depth > 3 || contract.facts.length >= MAX_FACTS) return;
    const named = buffer.readUInt16LE(at + 12);
    const ids = buffer.readUInt16LE(at + 14);
    let entryAt = at + 16;
    const count = Math.min(named + ids, 64);
    for (let index = 0; index < count; index += 1) {
      if (entryAt + 8 > buffer.length) return;
      const nameOrId = buffer.readUInt32LE(entryAt);
      const offset = buffer.readUInt32LE(entryAt + 4);
      const isDirectory = (offset & 0x80000000) !== 0;
      const id = (nameOrId & 0x80000000) === 0 ? nameOrId : null;
      if (depth === 0) {
        if (isDirectory) walk(base + (offset & 0x7fffffff), depth + 1, id);
      } else if (id !== null && typeId !== null) {
        const type = RESOURCE_TYPES.get(typeId) ?? `type${typeId}`;
        contract.add('resources', 'resource', `res:${type}:${hex(id)}`, {
          channel: 'pe-resources', at: `rsrc@${hex(directory.rva)}`, quote: `${type} id=${hex(id)}`,
        });
      }
      entryAt += 8;
    }
  };
  walk(base, 0, null);
}

/**
 * Build the interaction contract for one binary.
 *
 * `imports` is a parsePEImports result (or an apiFlat array), `functions` is
 * the Ghidra function inventory with bodies (may be empty - the contract is
 * then built from imports and resources alone), `layout` and `buffer` feed the
 * .rsrc walk and the VA -> RVA window-procedure resolution.
 */
export function interactionContractFrom({ buffer = null, layout = null, imports = null, functions = [] } = {}) {
  const contract = new Contract();
  const apiNames = Array.isArray(imports)
    ? imports
    : (imports?.apiFlat ?? []);

  for (const raw of apiNames) {
    const name = String(raw ?? '').trim().toLowerCase();
    if (name.length === 0) continue;
    if (/registerclass/.test(name)) {
      contract.add('windows', 'window-class', 'win:class-register', { channel: 'pe-imports', at: 'import-table', quote: name });
    } else if (/createwindow/.test(name)) {
      contract.add('windows', 'window-create', 'win:create', { channel: 'pe-imports', at: 'import-table', quote: name });
    } else if (/dialogbox|createdialog/.test(name)) {
      contract.add('windows', 'dialog-call', 'win:dialog', { channel: 'pe-imports', at: 'import-table', quote: name });
    }
  }

  const list = Array.isArray(functions) ? functions : [];
  const extent = imageExtent(layout, buffer?.length ?? 0);
  const candidates = procedureCandidates(list, extent, contract);
  for (const fn of candidates.values()) {
    extractProcedureMessages(fn, contract);
    extractCallSites(fn, contract);
  }
  for (const fn of list) {
    if (!fn || candidates.has(fn.name)) continue;
    extractCallSites(fn, contract);
  }

  if (buffer !== null && layout !== null) extractResources(buffer, layout, contract);

  return {
    windows: new Set([...contract.windows].sort()),
    messages: new Set([...contract.messages].sort()),
    controls: new Set([...contract.controls].sort()),
    resources: new Set([...contract.resources].sort()),
    facts: contract.facts,
  };
}

/**
 * Compare two interaction contracts. Each dimension is scored on recall and
 * precision with the shared diffDimension rule (a one-sided dimension scores
 * on the side that exists; a dimension with nothing on either side is null and
 * does not drag the average down). An entirely empty comparison is `empty`,
 * never 1.0.
 */
export function compareInteractionContracts(target, rebuilt) {
  const windows = diffDimension(target.windows, rebuilt.windows);
  const messages = diffDimension(target.messages, rebuilt.messages);
  const controls = diffDimension(target.controls, rebuilt.controls);
  const resources = diffDimension(target.resources, rebuilt.resources);
  const scores = [windows.score, messages.score, controls.score, resources.score].filter((value) => value !== null);
  const score = scores.length === 0 ? null : scores.reduce((sum, value) => sum + value, 0) / scores.length;
  return {
    status: score === null ? 'empty' : 'ran',
    score,
    reason: score === null ? 'neither side declares a window, message, control or resource surface' : null,
    windows,
    messages,
    controls,
    resources,
  };
}

export function interactionLimitations() {
  return [
    'T5 is a static, heuristic reading of decompiled window procedures: an optimiser may rewrite the comparisons, and message constants built by arithmetic (WM_USER + n) are not resolved.',
    'T5 sees user32/kernel32-level evidence only: Qt, WebView, Electron and self-drawn frameworks do not surface as window messages here.',
    'GCC switch lowering can leave range-check sentinel constants near the real message values in a jump-table body; both sides are read with the same extractor, so the noise is symmetric, but individual message tokens may include such sentinels.',
    'Resource facts come from the .rsrc directory (type and id presence); DLGTEMPLATE control layouts are not parsed in this version, and named (string-keyed) resource entries are skipped.',
    'Import and call-site presence is not a trace: a registered class, a declared message or a control id may never be used on any path that runs.',
    'T5 depends on the engine function inventory: a truncated inventory can miss the window procedure entirely, which is reported as blocked or flagged rather than scored as an empty surface.',
    'T5 is opt-in (interaction=true); enabling it renormalises the tier weights and changes the overall number.',
  ];
}

/** Greppability check for one fact, mirroring compare.js's evidence gate. */
export function factIsLocatable(fact, functions) {
  if (!fact || fact.channel !== 'ghidra-decompile') return fact?.channel === 'pe-imports' || fact?.channel === 'pe-resources';
  const fn = findListedFunction(functions, null, fact.at);
  return fn !== null && normalizeQuote(fn.body).includes(normalizeQuote(fact.quote));
}
