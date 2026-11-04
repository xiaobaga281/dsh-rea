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

export const HASH_ALGORITHMS = {
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

/** hash -> [{ api, algorithm }]. Built once per call, small and cheap. */
export function buildHashIndex({ dictionary = API_DICTIONARY, algorithms = HASH_ALGORITHMS } = {}) {
  const index = new Map();
  for (const api of dictionary) {
    for (const variant of new Set([api, api.toLowerCase()])) {
      for (const [algorithm, fn] of Object.entries(algorithms)) {
        const hash = fn(variant);
        const bucket = index.get(hash);
        const entry = { api, algorithm };
        if (!bucket) index.set(hash, [entry]);
        else if (!bucket.some((item) => item.api === api && item.algorithm === algorithm)) bucket.push(entry);
      }
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
} = {}) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const table = index ?? buildHashIndex();
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
 * Convenience wrapper: only pay for the hash scan when the import table is
 * thin enough that names are actually missing.
 */
export function resolveImports(buffer, imports, { threshold = 24 } = {}) {
  if (!imports) return imports;
  const named = imports.apiFlat.filter((api) => !String(api).startsWith('#')).length;
  if (named >= threshold) return imports;
  return mergeHashedApis(imports, recoverHashedApis(buffer).apis);
}
