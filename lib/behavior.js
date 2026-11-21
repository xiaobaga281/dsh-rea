/**
 * Behaviour contract: what a binary declares it writes, keeps and touches.
 *
 * A rebuild can reproduce every import and every literal and still behave
 * differently, because behaviour is a relation between those facts: which
 * family of side effects the code reaches for, which state it persists, which
 * messages it emits. This module turns a binary's static surface into three
 * comparable sets so the loop can score that relation without executing
 * anything:
 *
 *   outputs  - format strings and message literals the program can print
 *   state    - registry paths, mutexes, file paths and environment names it
 *              can persist or observe
 *   effects  - import-derived family:operation tokens (network:connect,
 *              registry:set, process:execute, ...)
 *
 * The contract is deliberately coarse. It is a claim about the declared
 * surface, not a trace: a program that imports `connect` may never call it.
 * That is why the tier is opt-in, why it is scored as recall *and* precision,
 * and why every report carries the limitation text below. It is still the only
 * measurement in this plugin that answers "does it do the same kind of thing",
 * and it is falsifiable in both directions: a dropped message lowers recall, an
 * invented capability lowers precision.
 *
 * @module dsh-rea/lib/behavior
 */

const MAX_OUTPUTS = 250;
const MAX_STATE = 250;

/**
 * Family keyword tables. Order matters: the first family that matches wins, so
 * `writeprocessmemory` is a process write (injection) rather than a memory
 * write. Names arrive lowercased from the import parser.
 */
const FAMILIES = [
  {
    name: 'network',
    keywords: [
      'wsastartup', 'wsasocket', 'socket', 'connect', 'send', 'recv', 'gethostbyname',
      'getaddrinfo', 'inet_addr', 'inet_ntoa', 'urldownloadtofile', 'internetopen',
      'internetreadfile', 'internetconnect', 'httpopenrequest', 'httpsendrequest',
      'winhttpopen', 'winhttpconnect', 'winhttpopenrequest', 'winhttpsendrequest',
      'dnsquery', 'netusergetinfo',
    ],
  },
  {
    name: 'registry',
    keywords: [
      'regopenkey', 'regcreatekey', 'regsetvalue', 'regqueryvalue', 'regdeletekey',
      'regdeletevalue', 'regenumkey', 'regclosekey', 'regsavekey', 'regloadkey',
    ],
  },
  {
    name: 'file',
    keywords: [
      'createfile', 'readfile', 'writefile', 'deletefile', 'copyfile', 'movefile',
      'findfirstfile', 'findnextfile', 'setfilepointer', 'createfilemapping',
      'gettemppath', 'getmodulefilename', 'setfileattributes', 'lockfile',
    ],
  },
  {
    name: 'process',
    keywords: [
      'createprocess', 'shellexecute', 'winexec', 'openprocess', 'createthread',
      'createtoolhelp32snapshot', 'process32first', 'process32next', 'terminateprocess',
      'loadlibrary', 'getprocaddress', 'writeprocessmemory', 'readprocessmemory',
      'virtualallocex', 'createremotethread', 'queueuserapc', 'setwindowshookex',
    ],
  },
  {
    name: 'crypto',
    keywords: [
      'cryptencrypt', 'cryptdecrypt', 'cryptacquirecontext', 'cryptgenrandom',
      'cryptcreatehash', 'crypthashdata', 'bcryptencrypt', 'bcryptdecrypt',
      'bcryptgeneratesymmetrickey', 'bcryptopenalgorithmprovider', 'ncryptopenstorageprovider',
    ],
  },
  {
    name: 'memory',
    keywords: ['virtualalloc', 'virtualprotect', 'virtualfree', 'heapalloc', 'heapcreate', 'heapfree', 'localfree', 'globalalloc'],
  },
  {
    name: 'ui',
    keywords: ['messagebox', 'createwindow', 'showwindow', 'dialogbox', 'setwindowtext', 'createwindowex', 'shellnotifyicon'],
  },
  {
    name: 'service',
    keywords: ['createservice', 'openscmanager', 'openservice', 'startservice', 'changeserviceconfig', 'deleteservice'],
  },
];

const OPERATIONS = [
  'delete', 'remove', 'write', 'read', 'execute', 'create', 'open', 'query', 'set',
  'load', 'protect', 'encrypt', 'decrypt', 'send', 'recv', 'connect', 'listen',
  'accept', 'alloc', 'free', 'copy', 'move', 'find',
];

const FORMAT_SPECIFIER = /%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGaAcspn%]/;

const normalizeApi = (name) => String(name ?? '').trim().toLowerCase();

export function operationOf(name) {
  const api = normalizeApi(name);
  for (const operation of OPERATIONS) {
    if (api.includes(operation)) return operation;
  }
  return 'call';
}

/**
 * Classify one imported API into `{ family, operation, token }`, or null when
 * the import says nothing about side effects (CRT helpers, math, locale).
 */
export function classifyApi(name) {
  const api = normalizeApi(name);
  if (api.length === 0) return null;
  for (const family of FAMILIES) {
    for (const keyword of family.keywords) {
      if (api.includes(keyword)) {
        const operation = operationOf(api);
        return { family: family.name, operation, token: `${family.name}:${operation}` };
      }
    }
  }
  return null;
}

function isFormatOrMessage(value) {
  if (value.length < 4) return false;
  if (FORMAT_SPECIFIER.test(value)) return true;
  if (value.length < 8) return false;
  // A URL is payload evidence, not program output; a path is state.
  if (/https?:\/\//i.test(value) || /[\\/]/.test(value)) return false;
  if (!/\s/.test(value)) return false;
  // Messages start with a capital, end like a sentence, or read as a usage /
  // diagnostic line ("usage: tool <path>").
  return /^[A-Z]/.test(value) || /[.!?]$/.test(value) || /^[a-z][a-z0-9 _-]{1,20}:\s/.test(value);
}

function isStateLiteral(value) {
  if (/^(?:HKEY_|HKLM|HKCU|HKCR|HKCC|HKU)/i.test(value)) return true;
  // A hive-relative key carries no HKEY prefix when it is passed to a helper.
  if (/^(?:SOFTWARE|SYSTEM|HARDWARE|SAM|SECURITY)\\/i.test(value)) return true;
  if (/^(?:Global|Local)\\/i.test(value)) return true;
  if (/^[A-Za-z]:\\/.test(value)) return true;
  if (/\\(?:Software|System|CurrentControlSet|Classes)\\/i.test(value)) return true;
  if (/\.(?:dat|cfg|ini|json|log|db|sqlite|tmp|bin|xml|conf)$/i.test(value)) return true;
  // Environment variables and mutex-like names: uppercase with an underscore.
  if (/^[A-Z][A-Z0-9]*_[A-Z0-9_]{2,}$/.test(value)) return true;
  return false;
}

const normalizeOutput = (value) => value.trim().replace(/\s+/g, ' ');
const takeStrings = (strings) => (strings ?? [])
  .map((entry) => (typeof entry === 'string' ? entry : entry?.value))
  .filter((value) => typeof value === 'string' && value.length > 0);

/**
 * Build the contract for one binary.
 *
 * `imports` is a list of API names (already floor-subtracted by the caller),
 * `strings` is the deep-string list (plain strings or `{ value }` entries) and
 * `floorStrings` is the toolchain vocabulary that must not count as behaviour.
 */
export function contractFrom({ imports = [], strings = [], floorStrings = null } = {}) {
  const effects = new Set();
  const families = {};
  for (const name of imports) {
    const hit = classifyApi(name);
    if (!hit) continue;
    effects.add(hit.token);
    families[hit.family] = (families[hit.family] ?? 0) + 1;
  }

  const outputs = new Set();
  const state = new Set();
  for (const raw of takeStrings(strings)) {
    const value = raw.trim();
    if (value.length === 0) continue;
    if (floorStrings?.has?.(value)) continue;
    if (isStateLiteral(value)) {
      if (state.size < MAX_STATE) state.add(value);
      continue;
    }
    if (isFormatOrMessage(value) && outputs.size < MAX_OUTPUTS) {
      outputs.add(normalizeOutput(value));
    }
  }

  return {
    effects: new Set([...effects].sort()),
    outputs: new Set([...outputs].sort()),
    state: new Set([...state].sort()),
    families,
  };
}

/** Shared set-diff scoring; also reused by the T5 interaction tier. */
export function diffDimension(target, rebuilt) {
  const missing = [...target].filter((value) => !rebuilt.has(value));
  const added = [...rebuilt].filter((value) => !target.has(value));
  const recall = target.size === 0 ? null : (target.size - missing.length) / target.size;
  const precision = rebuilt.size === 0 ? null : (rebuilt.size - added.length) / rebuilt.size;
  // A one-sided dimension is scored on the side that exists. Treating a missing
  // denominator as 1.0 credited an invented surface; treating it as 0 punished a
  // target that simply declares nothing.
  const score = recall === null && precision === null
    ? null
    : recall === null
      ? precision
      : precision === null
        ? recall
        : (recall + precision) / 2;
  return {
    score,
    recall,
    precision,
    targetSize: target.size,
    rebuiltSize: rebuilt.size,
    missing: missing.slice(0, 12),
    added: added.slice(0, 12),
  };
}

/**
 * Compare two contracts. Each dimension is scored on recall and precision; a
 * dimension with nothing on either side is null (not applicable) and does not
 * drag the average down. An entirely empty comparison is `empty`, never 1.0.
 */
export function compareBehaviorContracts(target, rebuilt) {
  const outputs = diffDimension(target.outputs, rebuilt.outputs);
  const state = diffDimension(target.state, rebuilt.state);
  const effects = diffDimension(target.effects, rebuilt.effects);
  const scores = [outputs.score, state.score, effects.score].filter((value) => value !== null);
  const score = scores.length === 0 ? null : scores.reduce((sum, value) => sum + value, 0) / scores.length;
  return {
    status: score === null ? 'empty' : 'ran',
    score,
    reason: score === null ? 'neither side declares an output, state or effect surface' : null,
    outputs,
    state,
    effects,
    families: { target: target.families, rebuilt: rebuilt.families },
  };
}

export function behaviorLimitations() {
  return [
    'T4 compares a declared behaviour surface, not a trace: an imported family may never be called on any path, and inline syscalls or dynamically resolved APIs are invisible to it.',
    'T4 is only meaningful with the toolchain floor applied: without it both sides carry the CRT\'s own messages and imports, and the tier scores the runtime instead of the code.',
    'A rebuild that keeps the same imports but no data can still score high on effects while failing the payload tier; T4 measures the declared surface, not the values on it.',
    'T4 is opt-in (behavior=true) because it is a second reading of the same bytes as T1/payload; enabling it renormalises the tier weights and changes the overall number.',
  ];
}
