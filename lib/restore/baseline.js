/**
 * Mechanical baseline: turn a decompiled function inventory into compilable C.
 *
 * The loop's "replication" step has always needed a model. This module is the
 * floor: translate Ghidra pseudocode directly, compile it, and measure how far
 * that gets. It is deliberately not clever - no type inference, no data
 * recovery - because the number it produces is the answer to "what can a
 * decompiler alone reproduce", and a clever translator would hide that.
 *
 * The compile is the arbiter. A function whose body does not compile is
 * replaced by a stub and counted; the source keeps a marker per function so a
 * compiler error line can be traced back to the function that caused it.
 * Remaining functions are retried until the file compiles or the round budget
 * is spent.
 *
 * Data is the known hard boundary: string and global contents live in .rdata
 * and are referenced through pointers. The baseline reproduces control flow and
 * imports, not those values, and the comparison reports exactly that.
 *
 * @module dsh-rea-restore/lib/baseline
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { compileC } from './build.js';

const TYPE_MAP = [
  [/\bundefined8\b/g, 'unsigned long long'],
  [/\bundefined6\b/g, 'unsigned long long'],
  [/\bundefined4\b/g, 'unsigned int'],
  [/\bundefined3\b/g, 'unsigned int'],
  [/\bundefined2\b/g, 'unsigned short'],
  [/\bundefined1\b/g, 'unsigned char'],
  [/\bundefined\b/g, 'unsigned char'],
  [/\bulonglong\b/g, 'unsigned long long'],
  [/\bulong64\b/g, 'unsigned long long'],
  [/\blonglong\b/g, 'long long'],
  [/\blong64\b/g, 'long long'],
  [/\bulong\b/g, 'unsigned long'],
  [/\buint\b/g, 'unsigned int'],
  [/\bushort\b/g, 'unsigned short'],
  [/\buchar\b/g, 'unsigned char'],
  [/\bsbyte\b/g, 'signed char'],
  [/\bqword\b/g, 'unsigned long long'],
  [/\bdword\b/g, 'unsigned int'],
  [/\bword\b/g, 'unsigned short'],
  [/\bbyte\b/g, 'unsigned char'],
  [/\bfloat10\b/g, 'double'],
  [/\bbool\b/g, 'unsigned char'],
  [/\bint3\b/g, 'unsigned int'],
  [/\buint3\b/g, 'unsigned int'],
  [/\bchar16_t\b/g, 'unsigned short'],
  [/\bwchar_t\b/g, 'unsigned short'],
  [/\bcode\b/g, 'dsh_code'],
  [/\b_EXCEPTION_POINTERS\b/g, 'struct _EXCEPTION_POINTERS'],
  [/\b_CONTEXT\b/g, 'CONTEXT'],
  [/\b_MEMORY_BASIC_INFORMATION\b/g, 'MEMORY_BASIC_INFORMATION'],
  [/\b_RTL_CRITICAL_SECTION\b/g, 'CRITICAL_SECTION'],
];

const PROLOGUE = `/* mechanical baseline: Ghidra pseudocode, translated without a model */
#include <windows.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef void (*dsh_code)(void);
`;

const INTRINSICS = [
  'LOCK', 'UNLOCK', 'typeMismatch', 'pointerOverflow', 'fastMemset', '__chk_fail',
  '__stack_chk_fail', 'halt_baddata', '__main', '_amsg_exit', 'Self', 'sizeOfTypedValue',
];

const LIBC_NAMES = new Set([
  'memcpy', 'memset', 'memmove', 'memcmp', 'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy',
  'strcat', 'strchr', 'strrchr', 'malloc', 'calloc', 'realloc', 'free', 'printf', 'fprintf',
  'sprintf', 'snprintf', 'vsnprintf', 'vfprintf', 'vsprintf', 'atoi', 'atol', 'atof', 'strtol',
  'strtoul', 'strtod', 'exit', 'abort', 'qsort', 'abs', 'puts', 'putchar', 'getchar', 'fputc',
  'fgetc', 'fputs', 'fgets', 'fflush', 'fopen', 'fclose', 'fread', 'fwrite', 'perror', 'atexit',
  'time', 'clock', 'rand', 'srand', 'signal', 'raise', 'toupper', 'tolower', 'isalpha', 'isdigit',
]);

/** Header macros/globals that must not be redeclared with a guessed type. */
const HEADER_SYMBOLS = new Set(['stdin', 'stdout', 'stderr', 'errno']);

const GLOBAL_PATTERNS = [
  { re: /^(?:_refptr_[A-Za-z0-9_]+|DAT_[0-9a-f]+|PTR_[A-Za-z0-9_]+|Self|stack0x[0-9a-f]+|in_[A-Z0-9]+|unaff_[A-Z0-9]+|extraout_[A-Z0-9]+)$/, decl: (name) => `static unsigned long long ${name};` },
  { re: /^(?:s_[A-Za-z0-9_]+|u_[A-Za-z0-9_]+)$/, decl: (name) => `static char ${name}[512];` },
];

const C_KEYWORDS = new Set([
  'if', 'while', 'for', 'switch', 'return', 'sizeof', 'case', 'do', 'else', 'goto', 'break', 'continue', 'typedef',
]);

const NEVER_RETURN_CALLS = ['typeMismatch', 'pointerOverflow', '__chk_fail', 'halt_baddata'];

/**
 * Remove sanity calls the compiler cannot type-check (UBSan hooks, stack-chk
 * failure). They never return; a baseline that cannot name their argument types
 * should drop the call, not stub the function that contains it.
 */
function stripNeverReturnCalls(text) {
  let out = '';
  let index = 0;
  while (index < text.length) {
    let matched = null;
    for (const name of NEVER_RETURN_CALLS) {
      if (!text.startsWith(name, index)) continue;
      const before = text[index - 1] ?? '';
      if (/[A-Za-z0-9_]/.test(before)) continue;
      if (!/^\s*\(/.test(text.slice(index + name.length, index + name.length + 4))) continue;
      matched = name;
      break;
    }
    if (matched === null) {
      out += text[index];
      index += 1;
      continue;
    }
    let at = index + matched.length;
    while (at < text.length && text[at] !== '(') at += 1;
    let depth = 0;
    for (; at < text.length; at += 1) {
      if (text[at] === '(') depth += 1;
      else if (text[at] === ')') {
        depth -= 1;
        if (depth === 0) { at += 1; break; }
      }
    }
    out += '((void)0)';
    index = at;
  }
  return out;
}

/** Strip annotations and map Ghidra's type vocabulary onto C. */
export function normalizeBody(body) {
  let text = String(body ?? '');
  text = text.replace(/\/\*[\s\S]*?\*\//g, ' ');
  text = text.replace(/\b(?:__cdecl|__stdcall|__fastcall|__thiscall|__vectorcall)\b/g, '');
  for (const [pattern, replacement] of TYPE_MAP) text = text.replace(pattern, replacement);
  text = stripNeverReturnCalls(text);
  return text.replace(/[ \t]+$/gm, '');
}

/** Parse `ret name(args)` from the first line of a decompiled body. */
export function parseSignature(body) {
  const normalized = normalizeBody(body);
  const firstLine = normalized.split(/\r?\n/).map((line) => line.trim()).find((line) => line.length > 0) ?? '';
  // Ghidra puts the brace on its own line; a one-line body keeps its code after
  // the brace, so the match must not be anchored to the end of the line.
  const match = /^([A-Za-z_][\w \t*]*?)\s+([A-Za-z_]\w*)\(([^)]*)\)\s*\{?/.exec(firstLine);
  if (!match) return null;
  const name = match[2];
  if (C_KEYWORDS.has(name)) return null;
  const parameters = match[3].trim();
  return {
    name,
    returnType: match[1].trim(),
    signature: `${match[1].trim()} ${name}(${parameters});`,
    header: `${match[1].trim()} ${name}(${parameters})`,
  };
}

function collectGlobals(text) {
  const declarations = new Map();
  for (const match of text.matchAll(/\b([A-Za-z_]\w*)\b/g)) {
    const name = match[1];
    if (HEADER_SYMBOLS.has(name)) continue;
    for (const { re, decl } of GLOBAL_PATTERNS) {
      if (re.test(name) && !declarations.has(name)) declarations.set(name, decl(name));
    }
  }
  return [...declarations.values()];
}

function collectDeclarations(text, definedNames) {
  const declarations = new Map();
  for (const match of text.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) {
    const name = match[1];
    if (C_KEYWORDS.has(name) || definedNames.has(name) || declarations.has(name)) continue;
    if (INTRINSICS.includes(name) || LIBC_NAMES.has(name)) continue;
    // Windows and CRT headers already declare the CamelCase API surface; a
    // second prototype with a guessed signature would conflict with the real
    // one. Unknown lowercase helpers are declared here.
    if (/^[A-Z]/.test(name)) continue;
    declarations.set(name, `long ${name}();`);
  }
  for (const name of INTRINSICS) {
    if (text.includes(`${name}(`) && !definedNames.has(name) && !declarations.has(name)) {
      declarations.set(name, `long ${name}();`);
    }
  }
  return [...declarations.values()];
}

/**
 * One stub definition; used when a body cannot be compiled in the round.
 *
 * `prefix` renames the stub (`dsh_stub_foo`) for the all-stub floor build: the
 * floor binary must not carry the target's own function names, or a function
 * inventory of the floor would match the target by name and a deduction keyed
 * on those names would eat user functions. `main` keeps its name so the floor
 * binary still has an entry point.
 */
function stubFor(name, prefix = '') {
  if (name === 'main') return 'int main(void) { return 0; } /* stub: the body did not compile */';
  if (LIBC_NAMES.has(name)) return `/* ${name}: target body did not compile; the C library provides it */`;
  return `long ${prefix}${name}() { return 0; } /* stub: the body did not compile */`;
}

/** CRT/runtime symbols already linked by the compiler; defining them duplicates. */
const runtimeProvided = (name) => /^(?:__|_|[A-Za-z]+CRTStartup$)/.test(name) || LIBC_NAMES.has(name);

/**
 * Build the first draft: every signature and body, plus the declarations the
 * bodies reference. `stubbed` names are emitted as stubs instead of bodies.
 */
export function synthesizeDraft(functions, { stubbed = new Set(), extraDecls = [], extraDefs = [], stubPrefix = '' } = {}) {
  const translated = [];
  const unusable = new Set();
  const omitted = [];
  const header = [];
  const bodies = [];
  const seen = new Set();
  const defined = new Set(functions.map((item) => item.name));
  for (const item of functions) {
    const signature = parseSignature(item.body)
      ?? { name: item.name, signature: `long ${item.name}();`, header: `long ${item.name}()` };
    // Ghidra can carry the same symbol name at two addresses (thunks, aliases).
    // One C function may exist per name; the later occurrence cannot be a
    // second definition.
    if (seen.has(signature.name)) {
      omitted.push(signature.name);
      continue;
    }
    seen.add(signature.name);
    // The CRT and the C library already provide these at link time; a local
    // definition is a duplicate symbol, not a reconstruction.
    if (runtimeProvided(signature.name) && signature.name !== 'main') {
      omitted.push(signature.name);
      continue;
    }
    if (stubbed.has(item.name)) {
      // A prototype before use: without it the call compiles as an implicit
      // `int` declaration and the stub definition later is a conflicting type,
      // which turns a repairable identifier error into a stubbed function.
      // With stubPrefix the definition is renamed too, so the prototype must
      // follow or every call site would link against a missing symbol.
      if (signature.name === 'main') header.push('int main(void);');
      else if (!LIBC_NAMES.has(signature.name)) header.push(`long ${stubPrefix}${signature.name}();`);
      bodies.push(stubFor(signature.name, stubPrefix));
      continue;
    }
    // Keep the body but drop the warning-only comment blocks that the type
    // normalizer already replaced with whitespace.
    const bodyText = normalizeBody(item.body).trim();
    if (!bodyText.includes('{') || bodyText.length < 12) {
      bodies.push(stubFor(signature.name, stubPrefix));
      unusable.add(item.name);
      continue;
    }
    header.push(signature.signature);
    bodies.push(`/* @fn ${signature.name} */\n${bodyText}`);
    translated.push(signature.name);
  }
  const bodyText = bodies.join('\n\n');
  const globals = collectGlobals(bodyText);
  // Renamed stubs must count as defined, or the declaration collector would
  // re-declare every `dsh_stub_*` body as a missing helper.
  const definedNames = new Set([
    ...translated,
    ...stubbed,
    ...unusable,
    ...(stubPrefix ? [...stubbed, ...unusable].map((name) => `${stubPrefix}${name}`) : []),
  ]);
  const callees = collectDeclarations(bodyText, definedNames);
  // A unit test or a DLL export list may not carry an entry symbol; the linker
  // still needs one to produce a PE.
  const hasEntry = [...defined].some((name) => name === 'main' || name === 'WinMain' || name === 'wWinMain');
  const entry = hasEntry ? [] : ['int main(void) { return 0; } /* baseline entry */'];
  const source = [
    PROLOGUE,
    ...globals,
    ...callees,
    ...extraDecls,
    ...header,
    ...bodies,
    ...entry,
    ...extraDefs,
    '',
  ].join('\n');
  return { source, translated, stubbed: [...stubbed, ...unusable], unusable, omitted, defined };
}

function functionsAtErrorLines(source, diagnostics) {
  const markerLines = [];
  source.split(/\r?\n/).forEach((line, index) => {
    const match = /\/\* @fn ([A-Za-z_]\w*) \*\//.exec(line);
    if (match) markerLines.push({ line: index + 1, name: match[1] });
  });
  const names = new Set();
  for (const match of String(diagnostics ?? '').matchAll(/[^\s:]+\.c:(\d+):\d+:\s*error:/g)) {
    const line = Number(match[1]);
    let owner = null;
    for (const marker of markerLines) {
      if (marker.line <= line) owner = marker.name;
      else break;
    }
    if (owner) names.add(owner);
  }
  return names;
}

/**
 * Compile each candidate in isolation (every other function stubbed) so a
 * failure is attributed to exactly one function. This is what lets the cap rise
 * from the first dozen: whole-file error attribution tends to stub neighbours.
 */
async function screenFunctions(functions, { workDir, name, extraArgs }) {
  const kept = new Set();
  const failed = new Map();
  let index = 0;
  for (const candidate of functions) {
    if (runtimeProvided(candidate.name) && candidate.name !== 'main') continue;
    index += 1;
    const others = new Set(functions.filter((item) => item.name !== candidate.name).map((item) => item.name));
    const draft = synthesizeDraft(functions, { stubbed: others });
    const outcome = await compileC({ sourceText: draft.source, workDir, name: `${name}-screen-${index}`, extraArgs });
    if (outcome.ok) {
      kept.add(candidate.name);
      continue;
    }
    // A failure made only of "undeclared identifier / unknown type / undeclared
    // function" is repairable by the whole-file loop; do not stub a function
    // for a declaration the next round would have added anyway.
    const diagnostics = String(outcome.stderr ?? outcome.reason ?? '');
    const errors = (diagnostics.match(/error:/g) ?? []).length;
    const repairable = (diagnostics.match(/use of undeclared identifier|'[A-Za-z_]\w*' undeclared|unknown type name|call to undeclared function|implicit declaration of function/g) ?? []).length;
    if (errors > 0 && repairable >= errors) kept.add(candidate.name);
    else failed.set(candidate.name, String(outcome.reason ?? '').slice(0, 240));
  }
  return { kept, failed };
}

/**
 * Compile the draft, repairing what the compiler names (an undeclared
 * identifier, an undeclared helper) and stubbing the functions a real type or
 * syntax error points at, until it builds or the round budget is spent.
 */
export async function buildBaseline({ functions, workDir, name = 'baseline', maxRounds = 30, extraArgs = [], screen = true } = {}) {
  const stubbed = new Set();
  const extraDecls = [];
  const extraDefs = [];
  // Decompiler output loses types: a pointer arrives as an integer. The
  // baseline knowingly relaxes those conversions - it is measuring control-flow
  // recovery, not type reconstruction - and says so in its report.
  const relaxed = ['-Wno-int-conversion', '-Wno-incompatible-pointer-types', ...extraArgs];
  const screening = screen && functions.length > 1
    ? await screenFunctions(functions, { workDir, name, extraArgs: relaxed })
    : null;
  if (screening) {
    for (const [failedName] of screening.failed) stubbed.add(failedName);
  }
  let draft = synthesizeDraft(functions, { stubbed, extraDecls });
  let outcome = null;
  let rounds = 0;
  while (rounds < maxRounds) {
    rounds += 1;
    const sourcePath = join(workDir, `${name}.c`);
    await mkdir(workDir, { recursive: true });
    await writeFile(sourcePath, draft.source, 'utf8');
    outcome = await compileC({ sourceText: draft.source, workDir, name, extraArgs: relaxed });
    if (outcome.ok) {
      return {
        ok: true,
        rounds,
        sourceText: draft.source,
        built: outcome,
        translated: draft.translated,
        stubbed: draft.stubbed,
        omitted: draft.omitted,
        screened: screening ? { kept: screening.kept.size, failed: screening.failed.size } : null,
      };
    }
    const diagnostics = String(outcome.stderr ?? outcome.reason ?? '');
    let repaired = false;
    for (const match of diagnostics.matchAll(/unknown type name '([A-Za-z_]\w*)'/g)) {
      const declaration = `typedef unsigned long long ${match[1]};`;
      if (!extraDecls.includes(declaration)) { extraDecls.push(declaration); repaired = true; }
    }
    for (const match of diagnostics.matchAll(/use of undeclared identifier '([A-Za-z_]\w*)'/g)) {
      const declaration = `static unsigned long long ${match[1]};`;
      if (!extraDecls.includes(declaration)) { extraDecls.push(declaration); repaired = true; }
    }
    // GCC phrases the same diagnostic as `'name' undeclared (first use ...)`.
    for (const match of diagnostics.matchAll(/'([A-Za-z_]\w*)' undeclared/g)) {
      const declaration = `static unsigned long long ${match[1]};`;
      if (!extraDecls.includes(declaration)) { extraDecls.push(declaration); repaired = true; }
    }
    for (const match of diagnostics.matchAll(/(?:call to undeclared function|implicit declaration of function) '([A-Za-z_]\w*)'/g)) {
      const declaration = `long ${match[1]}();`;
      if (!extraDecls.includes(declaration)) { extraDecls.push(declaration); repaired = true; }
    }
    for (const match of diagnostics.matchAll(/undefined symbol:\s*([A-Za-z_]\w*)/g)) {
      const name = match[1];
      // Linker messages mention attributes and import pointers too; a stub for
      // `__declspec` or `__imp_x` is not a function and does not compile.
      if (/^(?:__declspec|__attribute__|__asm__|__inline|__restrict|__stdcall|__cdecl|__fastcall|__thiscall|__vectorcall|__extension__|__imp_\w+)$/.test(name)) continue;
      if (C_KEYWORDS.has(name)) continue;
      const definition = `long ${name}() { return 0; } /* baseline helper for a linker-unknown call */`;
      if (!extraDefs.includes(definition)) { extraDefs.push(definition); repaired = true; }
    }
    // GNU ld phrases the same thing as "undefined reference to `name'".
    for (const match of diagnostics.matchAll(/undefined reference to [`']([^`']+)[`']/g)) {
      const name = match[1];
      if (!/^[A-Za-z_]\w*$/.test(name) || C_KEYWORDS.has(name)) continue;
      const definition = `long ${name}() { return 0; } /* baseline helper for a linker-unknown call */`;
      if (!extraDefs.includes(definition)) { extraDefs.push(definition); repaired = true; }
    }
    if (!repaired) {
      const offenders = functionsAtErrorLines(draft.source, diagnostics);
      const fresh = [...offenders].filter((item) => !stubbed.has(item));
      if (fresh.length === 0) break;
      for (const offender of fresh) stubbed.add(offender);
    }
    draft = synthesizeDraft(functions, { stubbed, extraDecls, extraDefs });
  }

  // Last resort: a baseline that cannot compile is not a floor, it is a missing
  // measurement. Stub the translated half repeatedly until the file builds; the
  // report then says how much survived, possibly zero.
  let degraded = false;
  let guard = 0;
  while (!outcome?.ok && guard < 8) {
    guard += 1;
    const remaining = draft.translated.filter((name) => !stubbed.has(name));
    if (remaining.length === 0) break;
    const take = Math.max(1, Math.ceil(remaining.length / 2));
    for (const name of remaining.slice(0, take)) stubbed.add(name);
    extraDecls.length = 0;
    extraDefs.length = 0;
    draft = synthesizeDraft(functions, { stubbed, extraDecls, extraDefs });
    outcome = await compileC({ sourceText: draft.source, workDir, name, extraArgs: relaxed });
    degraded = true;
  }
  if (outcome?.ok) {
    return {
      ok: true,
      rounds,
      degraded,
      sourceText: draft.source,
      built: outcome,
      translated: draft.translated,
      stubbed: draft.stubbed,
      omitted: draft.omitted,
      screened: screening ? { kept: screening.kept.size, failed: screening.failed.size } : null,
    };
  }
  return {
    ok: false,
    rounds,
    degraded,
    sourceText: draft.source,
    built: outcome,
    translated: draft.translated,
    stubbed: draft.stubbed,
    omitted: draft.omitted,
    screened: screening ? { kept: screening.kept.size, failed: screening.failed.size } : null,
    reason: outcome?.reason ?? 'the baseline did not compile',
  };
}
