/**
 * API-hash recovery.
 *
 * The hardening ladder's L4 tier removed every imported API name and kept only
 * ordinals plus a table of 32-bit hashes. The import table then says nothing,
 * so capability and tracking analysis go blind. Resolving those hashes against
 * a known-name dictionary is a bounded table lookup, not brute force: build
 * hash -> name once, then scan 4-byte aligned dwords.
 *
 * Five algorithms cover the overwhelming majority of real code (Metasploit's
 * ROR13, the classic CRC32, djb2, FNV-1a and sdbm). A hit is evidence that a
 * name appears in the table, not that the API is called - callers must keep
 * the "resolved, unverified" label.
 *
 * @module dsh-rea/lib/api-hash
 */

/** APIs worth naming. Kept flat and lowercase-insensitive for hashing. */
export const API_DICTIONARY = [
  // Memory / injection
  'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory',
  'ReadProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx',
  'RtlCreateUserThread', 'QueueUserAPC', 'SetThreadContext', 'GetThreadContext',
  'NtMapViewOfSection', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'OpenProcess',
  'NtOpenProcess', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtProtectVirtualMemory',
  'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'GetProcAddress', 'GetModuleHandleA',
  'GetModuleHandleW', 'FreeLibrary', 'LdrLoadDll', 'LdrGetProcedureAddress',
  // Debugger / anti-analysis
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'OutputDebugStringA', 'OutputDebugStringW', 'DebugActiveProcess', 'NtSetInformationThread',
  'NtQuerySystemInformation', 'GetThreadContext', 'NtGetContextThread', 'Process32First',
  'Process32Next', 'CreateToolhelp32Snapshot', 'EnumProcesses', 'EnumProcessModules',
  'QueryPerformanceCounter', 'GetTickCount', 'GetTickCount64', 'timeGetTime', 'Sleep',
  'NtDelayExecution', 'GetSystemTimeAsFileTime', 'GetCursorPos', 'GetForegroundWindow',
  'GetSystemMetrics', 'GlobalMemoryStatusEx', 'GetDiskFreeSpaceA', 'GetDiskFreeSpaceExA',
  'GetVolumeInformationA', 'GetVolumeInformationW', 'GetComputerNameA', 'GetComputerNameW',
  'GetUserNameA', 'GetUserNameW', 'GetAdaptersInfo', 'GetAdaptersAddresses', 'GetMacAddress',
  'gethostname', 'gethostbyname', 'GetSystemInfo', 'IsProcessorFeaturePresent',
  // Crypto / encoding
  'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptImportKey', 'CryptAcquireContextA',
  'CryptCreateHash', 'CryptHashData', 'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom',
  'RtlDecompressBuffer', 'RtlCompressBuffer', 'MapFileAndCheckSumA', 'CheckSumMappedFile',
  // Network
  'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW', 'HttpOpenRequestA',
  'HttpSendRequestA', 'HttpSendRequestW', 'InternetReadFile', 'InternetCrackUrlA',
  'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest',
  'WinHttpReceiveResponse', 'WSAStartup', 'socket', 'connect', 'send', 'recv', 'getaddrinfo',
  'URLDownloadToFileA', 'URLDownloadToFileW', 'ShellExecuteA', 'ShellExecuteW',
  // Registry / persistence / services
  'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA',
  'RegQueryValueExA', 'RegDeleteValueA', 'RegEnumKeyExA', 'CreateServiceA', 'OpenServiceA',
  'StartServiceA', 'ChangeServiceConfigA', 'CreateProcessA', 'CreateProcessW',
  'ShellExecuteExA', 'WinExec', 'SchTasksCreate',
  // File / system
  'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle', 'DeleteFileA',
  'CopyFileA', 'MoveFileA', 'GetTempPathA', 'GetModuleFileNameA', 'GetModuleFileNameW',
  'FindFirstFileA', 'FindNextFileA', 'GetFileSize', 'SetFilePointer', 'CreateDirectoryA',
  'GetWindowsDirectoryA', 'GetSystemDirectoryA', 'ExpandEnvironmentStringsA',
  // UI / capture / input
  'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'BitBlt',
  'GetDC', 'CreateCompatibleBitmap', 'CreateCompatibleDC', 'SelectObject', 'PrintWindow',
  'GetWindowDC', 'RegisterHotKey', 'GetClipboardData', 'OpenClipboard',
  // Process / thread / module
  'CreateThread', 'ResumeThread', 'SuspendThread', 'OpenThread', 'TerminateProcess',
  'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThreadId', 'DuplicateHandle',
  'SetUnhandledExceptionFilter', 'AddVectoredExceptionHandler', 'UnhandledExceptionFilter',
  'RtlAddVectoredExceptionHandler', 'GetStartupInfoA', 'GetCommandLineA', 'GetEnvironmentVariableA',
];

const ror32 = (value, bits) => ((value >>> bits) | (value << (32 - bits))) >>> 0;

/**
 * Parameterised family.
 *
 * Five named algorithms cover the common case, but loaders routinely use the
 * same loop with a different multiplier or seed - `imul eax, 0x1f; xor` is not
 * FNV, it is FNV-shaped. A real analyst reads the resolver and names the
 * constant; this approximates that by trying the small Cartesian product that
 * real code actually uses (BKDR 31/33/131/1313/65599, add or xor, four seeds).
 *
 * 80 variants is not a brute force over 2^32: every variant is still matched by
 * one table lookup per dword, and the collision budget stays far below one
 * false name per megabyte.
 */
const variantHash = (multiplier, operation, seed) => (name) => {
  let hash = seed >>> 0;
  for (const byte of Buffer.from(name, 'latin1')) {
    hash = Math.imul(hash, multiplier) >>> 0;
    hash = operation === 'xor' ? (hash ^ byte) >>> 0 : (hash + byte) >>> 0;
  }
  return hash >>> 0;
};

const PARAMETERISED = {};
for (const multiplier of [31, 33, 131, 1313, 65599]) {
  for (const operation of ['xor', 'add']) {
    for (const seed of [0, 5381, 0x811c9dc5, 0x2f]) {
      PARAMETERISED[`mul${multiplier}-${operation}-${seed.toString(16)}`] = variantHash(multiplier, operation, seed);
    }
  }
}

export const HASH_ALGORITHMS = {
  ...PARAMETERISED,
  ror13(name) {
    let hash = 0;
    for (const byte of Buffer.from(name, 'latin1')) {
      hash = ror32(hash, 13);
      hash = (hash + byte) >>> 0;
    }
    return hash >>> 0;
  },
  crc32(name) {
    let crc = 0xffffffff;
    for (const byte of Buffer.from(name, 'latin1')) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return (crc ^ 0xffffffff) >>> 0;
  },
  djb2(name) {
    let hash = 5381;
    for (const byte of Buffer.from(name, 'latin1')) hash = ((hash * 33) + byte) >>> 0;
    return hash >>> 0;
  },
  fnv1a(name) {
    let hash = 0x811c9dc5;
    for (const byte of Buffer.from(name, 'latin1')) {
      hash ^= byte;
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash >>> 0;
  },
  sdbm(name) {
    let hash = 0;
    for (const byte of Buffer.from(name, 'latin1')) hash = (byte + (hash << 6) + (hash << 16) - hash) >>> 0;
    return hash >>> 0;
  },
};

/**
 * hash -> [{ api, algorithm }]. The default index is built from a fixed
 * dictionary and a fixed algorithm set, so it is identical on every call;
 * rebuilding it per triage meant 27k hash computations twice over, once for
 * import recovery and once for the structural profile.
 */
let DEFAULT_INDEX = null;

/** Salted indexes are per-sample; keep a small cache so the dictionary is built once. */
const SALTED_INDEXES = new Map();

/**
 * Build `hash -> [{ api, algorithm }]`.
 *
 * `salt` adds a second entry per name: `hash ^ salt`. A salted loop is the same
 * loop with one extra XOR, so a table built that way is invisible to every
 * unsalted variant while still being trivially resolvable *if* the salt is
 * known. The salt usually lives in the config the sample decrypts at run time,
 * which is why recovering it is worth a separate step.
 */
export function buildHashIndex({ dictionary = API_DICTIONARY, algorithms = HASH_ALGORITHMS, salt = null } = {}) {
  const isDefault = dictionary === API_DICTIONARY && algorithms === HASH_ALGORITHMS;
  const salted = Number.isInteger(salt) && salt !== 0;
  if (isDefault && !salted && DEFAULT_INDEX) return DEFAULT_INDEX;
  if (isDefault && salted && SALTED_INDEXES.has(salt)) return SALTED_INDEXES.get(salt);
  const index = new Map();
  const add = (hash, entry) => {
    const bucket = index.get(hash);
    if (!bucket) index.set(hash, [entry]);
    else if (!bucket.some((item) => item.api === entry.api && item.algorithm === entry.algorithm)) bucket.push(entry);
  };
  for (const api of dictionary) {
    for (const variant of new Set([api, api.toLowerCase()])) {
      for (const [algorithm, fn] of Object.entries(algorithms)) {
        const hash = fn(variant);
        add(hash, { api, algorithm });
        if (salted) add((hash ^ salt) >>> 0, { api, algorithm: `${algorithm}+salt` });
      }
    }
  }
  if (isDefault) {
    if (salted) {
      if (SALTED_INDEXES.size > 8) SALTED_INDEXES.clear();
      SALTED_INDEXES.set(salt, index);
    } else {
      DEFAULT_INDEX = index;
    }
  }
  return index;
}

/**
 * Scan 4-byte aligned dwords for values present in the hash index.
 * @returns {{apis: Array<{api:string, algorithm:string, at:number, hash:number}>, scanned:number, truncated:boolean}}
 */
export function recoverHashedApis(buffer, {
  index = null,
  scanBytes = 8 * 1024 * 1024,
  maxHits = 96,
  salt = null,
} = {}) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const table = index ?? buildHashIndex(Number.isInteger(salt) && salt !== 0 ? { salt } : {});
  const limit = Math.min(bytes.length - 4, scanBytes);
  const apis = [];
  const seen = new Set();
  for (let at = 0; at <= limit; at += 4) {
    const value = bytes.readUInt32LE(at);
    if (value < 0x10000) continue;              // nothing useful hashes that low
    const bucket = table.get(value);
    if (!bucket) continue;
    for (const entry of bucket) {
      const key = `${entry.algorithm}:${entry.api}`;
      if (seen.has(key)) continue;
      seen.add(key);
      apis.push({ ...entry, at, hash: value });
      if (apis.length >= maxHits) return { apis, scanned: at + 4, truncated: true };
    }
  }
  return { apis, scanned: limit, truncated: bytes.length - 4 > limit };
}

/** Merge recovered names into an import record without losing provenance. */
export function mergeHashedApis(imports, recovered) {
  if (!imports || recovered.length === 0) return imports;
  const named = new Set((imports.dlls ?? []).flatMap((entry) => entry.functions));
  const added = recovered.filter((item) => !named.has(item.api));
  if (added.length === 0) return imports;
  return {
    ...imports,
    hashed: added,
    apiFlat: [...imports.apiFlat, ...added.map((item) => item.api)],
    empty: false,
  };
}

/**
 * Merge the import directory with whatever the hash scan finds.
 *
 * `threshold` used to decide whether to look at all: a table with 24 or more
 * named imports short-circuited the hash scan, on the assumption that a named
 * import directory is a complete one. D10 is the generation that walks through
 * that assumption - 26 real kernel32/user32/advapi32 exports that the sample
 * never calls, sitting next to the ROR13 table it actually uses. The tool
 * reported one of the nine real capabilities and scored 84%.
 *
 * A populated directory is evidence that imports were named, not that they were
 * named completely. When both sources are present the scan runs anyway and the
 * two sets are kept apart, because a caller that does not separate them cannot
 * say which one the behaviour layer should trust.
 */
export function resolveImports(buffer, imports, { threshold = 24, salt = null } = {}) {
  if (!imports) return imports;
  const named = imports.apiFlat.filter((api) => !String(api).startsWith('#')).length;
  const dense = named >= threshold;
  const recovered = recoverHashedApis(buffer, { salt }).apis;
  if (recovered.length === 0) return imports;
  const merged = mergeHashedApis(imports, recovered);
  if (merged === imports) return imports;
  // `dense` is the interesting case: both sets are populated, and at most one of
  // them describes what the sample runs. Say so instead of presenting a union
  // as a single import list.
  return dense ? { ...merged, overlappingSources: true } : merged;
}
