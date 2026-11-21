/**
 * R0–R5 specimens: real compiled targets with a source-level truth.
 *
 * The duel's D0 controls the ceiling because the attacker's own plaintext run
 * defines what is reachable. The reconstruction loop controls it the same way:
 * R0 is plaintext C, and every later tier adds one protection while the source
 * truth stays known. A score is always "recovered / what R0 says is reachable".
 *
 * These are compiled with the plugin's own build engine, so "restored source"
 * means a source that compiles and compares - not a pseudocode listing. The
 * sealed tier (R4) cannot be recovered statically by construction; its correct
 * outcome is a converged draft plus an explicit statement about the sealed
 * values, never a guessed secret. R5 adds a Win32 GUI surface (window class,
 * window procedure, control id, timer, dialog-free message loop) so the
 * opt-in interaction tier has a real target; it is scored statically and never
 * creates a window.
 *
 * Run through `scripts/recon.mjs`; nothing here executes a sample.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { compileC } from '../../lib/restore/build.js';

export const TIERS = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5'];

const XOR1 = 0x5a;
const XOR4 = [0x13, 0x37, 0xc0, 0xde];

export const LITERALS = {
  endpoint: 'https://telemetry.example.test/v1/collect',
  backup: 'https://backup.example.test/beacon',
  tag: 'orbit-7f3a91c2d8e4',
};

/**
 * The mutation is a fabrication, not a payload change: an extra plaintext URL
 * and an extra API call the target does not contain. A same-length change to an
 * encoded config is invisible to every static tier (identical structure,
 * identical lengths, no plaintext anywhere), so it proves nothing about the
 * scorer; a fabricated claim is exactly what the precision dimension exists to
 * catch.
 */
const FABRICATED_URL = 'https://fabricated.example.test/never';
function fabricate(source) {
  return source.replace('int main(void) {', `int main(void) {
  volatile int fabricated = (int)mix("${FABRICATED_URL}") + MessageBoxA(0, "fabricated", "fabricated", 0);
  (void)fabricated;`);
}

const ror13 = (name) => {
  let hash = 0;
  for (const byte of Buffer.from(name, 'latin1')) {
    hash = ((hash >>> 13) | (hash << 19)) >>> 0;
    hash = (hash + byte) >>> 0;
  }
  return hash >>> 0;
};

const machineKey = (machine = process.env.COMPUTERNAME ?? 'analysis-host') => {
  let hash = 5381;
  for (const byte of Buffer.from(machine, 'latin1')) hash = (((hash << 5) + hash) ^ byte) >>> 0;
  return hash & 0xff;
};

const arr = (bytes) => bytes.map((byte) => `0x${byte.toString(16).padStart(2, '0')}`).join(', ');
const xor = (text, key) => [...Buffer.from(text, 'latin1')].map((byte) => byte ^ key);
const xor4 = (text) => [...Buffer.from(text, 'latin1')].map((byte, index) => byte ^ XOR4[index % 4]);

const MIX = `static unsigned long mix(const char *s) { unsigned long h = 5381; while (*s) { h = ((h << 5) + h) ^ (unsigned char)*s++; } return h; }`;

function plain() {
  const lit = LITERALS;
  return `#include <windows.h>
static const char *ep = "${lit.endpoint}";
static const char *tag = "${lit.tag}";
${MIX}
int main(void) {
  char name[64] = {0}; DWORD n = sizeof(name);
  GetComputerNameA(name, &n);
  return (int)(mix(ep) + mix(tag));
}
`;
}

function singleXor() {
  const lit = LITERALS;
  return `#include <windows.h>
static const unsigned char ep[] = { ${arr(xor(lit.endpoint, XOR1))}, 0 };
static const unsigned char tag[] = { ${arr(xor(lit.tag, XOR1))}, 0 };
static void unxor(char *dst, const unsigned char *src) { while (*src) *dst++ = (char)(*src++ ^ 0x${XOR1.toString(16)}); *dst = 0; }
${MIX}
int main(void) {
  char a[96], b[64], name[64] = {0}; DWORD n = sizeof(name);
  unxor(a, ep); unxor(b, tag); GetComputerNameA(name, &n);
  return (int)(mix(a) + mix(b));
}
`;
}

function repeatingXor() {
  const lit = LITERALS;
  const plaintext = `${lit.endpoint}\n${lit.backup}`;
  return `#include <windows.h>
static const unsigned char cfg[] = { ${arr(xor4(plaintext))}, 0 };
static void unxor4(char *dst, const unsigned char *src, int n) {
  static const unsigned char k[4] = { 0x13, 0x37, 0xc0, 0xde };
  for (int i = 0; i < n; i++) dst[i] = (char)(src[i] ^ k[i % 4]);
  dst[n] = 0;
}
${MIX}
int main(void) {
  char out[160];
  unxor4(out, cfg, (int)sizeof(cfg) - 1);
  return (int)mix(out);
}
`;
}

function hashedApis() {
  const lit = LITERALS;
  const apis = ['GetComputerNameA', 'RegSetValueExA', 'InternetConnectA', 'CryptEncrypt'];
  return {
    source: `#include <windows.h>
static const unsigned int hashes[] = { ${apis.map((name) => `0x${ror13(name).toString(16)}u`).join(', ')} };
static const char *tag = "${lit.tag}";
${MIX}
int main(void) {
  unsigned long h = 0;
  for (unsigned i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) h += hashes[i];
  return (int)(mix(tag) ^ h);
}
`,
    apiNames: apis,
  };
}

function sealed() {
  const lit = LITERALS;
  const secret = `${lit.endpoint}|${lit.tag}`;
  const key = machineKey();
  const encrypted = xor(secret, key);
  // Pad to a region large enough to register as high-entropy: a 60-byte blob
  // is below the detector's window and would make "no unresolved region" look
  // like an analysis success instead of a specimen that never tested it.
  const padding = Array.from({ length: 1_500 }, (_, index) => (index * 73 + 41) & 0xff);
  return {
    source: `#include <windows.h>
static const unsigned char sealed[] = { ${arr([...encrypted, ...padding])} };
static unsigned char machineKey(void) {
  char n[64] = {0}; DWORD c = sizeof(n); GetComputerNameA(n, &c);
  unsigned long h = 5381;
  for (const char *p = n; *p; p++) h = ((h << 5) + h) ^ (unsigned char)*p;
  return (unsigned char)h;
}
static void unseal(char *dst, const unsigned char *src, int n) {
  unsigned char k = machineKey();
  for (int i = 0; i < n; i++) dst[i] = (char)(src[i] ^ k);
  dst[n] = 0;
}
${MIX}
int main(void) {
  char out[96];
  unseal(out, sealed, ${encrypted.length});
  return (int)mix(out);
}
`,
    sealedValues: [lit.endpoint, lit.tag],
    note: `sealed with a key derived from this machine's COMPUTERNAME at build time; the key exists nowhere in the file, so the values are restorable only through the decoder's logic, never from the bytes`,
  };
}

/**
 * R5: a minimal but complete Win32 GUI program. The window procedure handles
 * WM_CREATE (starts timer 1), WM_COMMAND (button 0x65 appends to a file),
 * WM_TIMER and WM_DESTROY; WinMain registers the class, creates the window and
 * the button with hmenu 0x65, and pumps messages. `command: false` removes the
 * whole WM_COMMAND branch - the R5 mutation, so the mutated rebuild is missing
 * msg:0x111 rather than merely stubbing it (the case label itself must go).
 *
 * Pure static extraction needs no window: the interaction tier reads the
 * decompiled procedures, never a desktop session.
 */
function guiWindow({ command = true } = {}) {
  const commandCase = command
    ? [
      '    case WM_COMMAND: {',
      '      if (LOWORD(wp) == 0x65) {',
      '        HANDLE f = CreateFileA("rea-gui.txt", FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);',
      '        if (f != INVALID_HANDLE_VALUE) {',
      '          DWORD written = 0;',
      '          WriteFile(f, "button clicked", 13, &written, 0);',
      '          CloseHandle(f);',
      '        }',
      '      }',
      '      return 0;',
      '    }',
    ]
    : [];
  return [
    '#include <windows.h>',
    '',
    'static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {',
    '  switch (msg) {',
    '    case WM_CREATE:',
    '      SetTimer(hwnd, 1, 1000, 0);',
    '      return 0;',
    ...commandCase,
    '    case WM_TIMER:',
    '      KillTimer(hwnd, 1);',
    '      return 0;',
    '    case WM_DESTROY:',
    '      PostQuitMessage(0);',
    '      return 0;',
    '    default:',
    '      return DefWindowProcA(hwnd, msg, wp, lp);',
    '  }',
    '}',
    '',
    'int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, char *cmd, int show) {',
    '  WNDCLASSEXA wc = {0};',
    '  wc.cbSize = sizeof(wc);',
    '  wc.lpfnWndProc = WndProc;',
    '  wc.hInstance = inst;',
    '  wc.lpszClassName = "ReaGuiWindow";',
    '  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);',
    '  if (RegisterClassExA(&wc) == 0) return 1;',
    '  HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "rea-gui", WS_OVERLAPPEDWINDOW | WS_VISIBLE,',
    '                              0, 0, 320, 240, 0, 0, inst, 0);',
    '  if (hwnd == 0) return 2;',
    '  CreateWindowExA(0, "BUTTON", "click", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,',
    '                  20, 20, 120, 32, hwnd, (HMENU)0x65, inst, 0);',
    '  MSG m;',
    '  while (GetMessageA(&m, 0, 0, 0) > 0) {',
    '    TranslateMessage(&m);',
    '    DispatchMessageA(&m);',
    '  }',
    '  return (int)m.wParam;',
    '}',
    '',
  ].join('\n');
}

/**
 * The R5 interaction truth is measured, not asserted: the sets below are the
 * extractor's own output on the compiled specimen (gcc 16.2.0, -O0, -mwindows,
 * Ghidra 12.1.4 inventory), frozen here so the truth file names the surface
 * the binary actually carries. Re-measure and update if the toolchain changes.
 */
export const R5_INTERACTION = {
  note: 'measured with lib/interaction.js on the compiled specimen (gcc 16.2.0 -O0 -mwindows, Ghidra 12.1.4 inventory, 48-function cap); the manifest resource is a toolchain default both sides carry',
  windows: ['win:class-register', 'win:create', 'win:wndproc=WndProc'],
  messages: ['msg:0x1', 'msg:0x2', 'msg:0x111', 'msg:0x113'],
  controls: ['ctl:0x65', 'timer:0x1'],
  resources: ['res:manifest:0x1'],
};

/** The truth source (or its mutation) for one tier. */
export function tierSource(tier, { mutate = false } = {}) {
  const lit = LITERALS;
  let built;
  switch (tier) {
    case 'R0':
      built = { source: plain(), literals: [lit.endpoint, lit.tag], apiNames: ['GetComputerNameA'], sealed: false, extraArgs: [] };
      break;
    case 'R1':
      built = { source: singleXor(), literals: [lit.endpoint, lit.tag], apiNames: ['GetComputerNameA'], sealed: false, extraArgs: ['-s'] };
      break;
    case 'R2':
      built = { source: repeatingXor(), literals: [lit.endpoint, lit.backup], apiNames: [], sealed: false, extraArgs: ['-s'] };
      break;
    case 'R3': {
      const hashed = hashedApis();
      built = { source: hashed.source, literals: [lit.tag], apiNames: hashed.apiNames, sealed: false, extraArgs: ['-s'] };
      break;
    }
    case 'R4': {
      const sealedTier = sealed();
      built = {
        source: sealedTier.source,
        literals: [],
        apiNames: ['GetComputerNameA'],
        sealed: true,
        sealedValues: sealedTier.sealedValues,
        note: sealedTier.note,
        extraArgs: ['-s'],
      };
      break;
    }
    case 'R5':
      built = {
        source: guiWindow({ command: !mutate }),
        literals: ['rea-gui.txt'],
        apiNames: ['RegisterClassExA', 'CreateWindowExA', 'GetMessageA', 'SetTimer', 'CreateFileA', 'WriteFile', 'CloseHandle'],
        sealed: false,
        interaction: R5_INTERACTION,
        extraArgs: ['-mwindows'],
      };
      break;
    default:
      throw new Error(`unknown tier ${tier}`);
  }
  if (!mutate) return built;
  // R5's mutation is the dedicated WM_COMMAND-branch removal; the generic
  // fabricate() only matches `int main(void) {` and would leave WinMain untouched.
  if (tier === 'R5') return built;
  return { ...built, source: fabricate(built.source) };
}

/**
 * Compile one specimen and write its truth beside it.
 *
 * The truth file is the scorer's input, not the analyst's: it names the
 * decoded literals and API names the binary is supposed to hide.
 */
export async function generateSpecimen({ tier, outDir, mutate = false }) {
  const built = tierSource(tier, { mutate });
  const dir = join(outDir, tier);
  await mkdir(dir, { recursive: true });
  const label = mutate ? `${tier}-mut` : tier;
  const outcome = await compileC({
    sourceText: built.source,
    workDir: dir,
    name: label,
    extraArgs: built.extraArgs,
  });
  if (!outcome.ok) {
    return { tier, label, ok: false, build: outcome };
  }
  const truth = {
    tier,
    mutate,
    targetPath: outcome.outPath,
    source: built.source,
    literals: built.literals,
    apiNames: built.apiNames,
    sealed: built.sealed,
    sealedValues: built.sealedValues ?? [],
    note: built.note ?? null,
    extraArgs: built.extraArgs,
    compiler: outcome.compiler,
  };
  const truthPath = join(dir, `${label}.truth.json`);
  await writeFile(truthPath, `${JSON.stringify(truth, null, 2)}\n`, 'utf8');
  return { tier, label, ok: true, truth, truthPath, build: outcome };
}
