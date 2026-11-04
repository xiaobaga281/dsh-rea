/**
 * Static intelligence over a sample: imports, indicators, tracking surface,
 * anti-analysis techniques, capability profiling, and report sanitisation.
 *
 * Everything here is pure local parsing. No sample is executed, no engine is
 * invoked, and no network request is made. Every finding carries the sample
 * string or imported API that produced it, so a conclusion can be checked
 * against the bytes rather than taken on faith.
 *
 * @module dsh-rea/lib/intel
 */

/**
 * Parse IMAGE_IMPORT_DESCRIPTOR chains straight from a PE file.
 * This is the single biggest static-analysis gain over entropy-based triage:
 * imports name what a sample is *able* to do before a single instruction runs.
 */
export function parsePEImports(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length < 64 || buf.toString('latin1', 0, 2) !== 'MZ') return null;
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 > buf.length || buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
  const coff = pe + 4;
  const sectionCount = buf.readUInt16LE(coff + 2);
  const optionalSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  if (opt + 2 > buf.length) return null;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const directories = opt + (is64 ? 112 : 96);
  if (directories + 16 > buf.length) return null;
  const importRva = buf.readUInt32LE(directories + 8);
  const importSize = buf.readUInt32LE(directories + 12);
  if (importRva === 0 || importSize === 0) return { dlls: [], apiFlat: [], ordinals: 0, empty: true };

  const sectionTable = opt + optionalSize;
  const sections = [];
  for (let i = 0; i < Math.min(sectionCount, 96); i += 1) {
    const at = sectionTable + i * 40;
    if (at + 40 > buf.length) break;
    sections.push({
      name: buf.toString('latin1', at, at + 8).replace(/\0/g, '').trim(),
      virtualSize: buf.readUInt32LE(at + 8),
      virtualAddress: buf.readUInt32LE(at + 12),
      rawSize: buf.readUInt32LE(at + 16),
      rawOffset: buf.readUInt32LE(at + 20),
    });
  }
  const rvaToOffset = (rva) => {
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
        const delta = rva - section.virtualAddress;
        return delta < section.rawSize ? section.rawOffset + delta : null;
      }
    }
    return null;
  };
  const cString = (offset, max = 256) => {
    if (offset === null || offset < 0 || offset >= buf.length) return null;
    let end = offset;
    while (end < buf.length && end - offset < max && buf[end] >= 0x20 && buf[end] <= 0x7e) end += 1;
    return end > offset ? buf.toString('latin1', offset, end) : null;
  };
  const thunkSize = is64 ? 8 : 4;

  const dlls = [];
  let ordinals = 0;
  let truncated = false;
  for (let index = 0; index < 256; index += 1) {
    const descriptor = rvaToOffset(importRva + index * 20);
    if (descriptor === null || descriptor + 20 > buf.length) { truncated = true; break; }
    const originalThunk = buf.readUInt32LE(descriptor);
    const nameRva = buf.readUInt32LE(descriptor + 12);
    const firstThunk = buf.readUInt32LE(descriptor + 16);
    if (originalThunk === 0 && nameRva === 0 && firstThunk === 0) break;
    const dllName = cString(rvaToOffset(nameRva)) ?? `unknown-${index}`;
    let thunk = rvaToOffset(originalThunk || firstThunk);
    const functions = [];
    for (let slot = 0; slot < 512 && thunk !== null && thunk + thunkSize <= buf.length; slot += 1) {
      const entry = is64 ? Number(buf.readBigUInt64LE(thunk)) : buf.readUInt32LE(thunk);
      if (entry === 0) break;
      const ordinalBit = is64 ? (entry >= 0x8000000000000000 ? 1 : 0) : ((entry >>> 31) & 1);
      if (ordinalBit) {
        functions.push(`#${entry & 0xffff}`);
        ordinals += 1;
      } else {
        const nameOffset = rvaToOffset(entry);
        const name = cString(nameOffset === null ? null : nameOffset + 2);
        functions.push(name ?? `#${entry}`);
      }
      thunk += thunkSize;
    }
    if (functions.length >= 512) truncated = true;
    dlls.push({ name: dllName, functions });
  }
  return {
    dlls,
    apiFlat: [...new Set(dlls.flatMap((entry) => entry.functions))],
    ordinals,
    truncated,
    empty: dlls.length === 0,
  };
}

const IOC_RULES = [
  { type: 'url', re: /https?:\/\/[^\s"'`\\|<>]{4,200}/gi },
  { type: 'ipv4', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { type: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: 'domain', re: /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|me|tk|su|pw|onion|dev|app|cloud)\b/gi },
  { type: 'registry', re: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"']{2,120}/gi },
  { type: 'pdb', re: /[A-Za-z0-9_\\/. -]{0,120}\.pdb/gi },
  { type: 'winpath', re: /\b[A-Za-z]:\\(?:[^\s"<>|:*?]{1,80}\\)*[^\s"<>|:*?]{1,80}/g },
  { type: 'pipe', re: /\\\\\.\\pipe\\[^\s"']{2,80}/g },
  { type: 'useragent', re: /Mozilla\/[\d.]+[^\s"']{0,120}/g },
  { type: 'bitcoin', re: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g },
  { type: 'ethereum', re: /\b0x[a-fA-F0-9]{40}\b/g },
];

/** Pull typed indicators from sampled strings, deduplicated and offset-tagged. */
export function extractIocs(strings) {
  const seen = new Map();
  for (const item of Array.isArray(strings) ? strings : []) {
    const value = typeof item === 'string' ? item : item?.value;
    if (typeof value !== 'string') continue;
    for (const rule of IOC_RULES) {
      rule.re.lastIndex = 0;
      let match;
      while ((match = rule.re.exec(value)) !== null) {
        const found = match[0].replace(/[.,;:)\]]+$/, '');
        const key = `${rule.type}:${found.toLowerCase()}`;
        if (!seen.has(key)) {
          const derived = item?.derived === true || /^(?:xor-|base64)/.test(String(item?.encoding ?? ''));
          seen.set(key, {
            type: rule.type, value: found.slice(0, 300),
            at: item?.offset ?? null, encoding: item?.encoding ?? null, derived,
          });
        }
        if (match[0].length === 0) rule.re.lastIndex += 1;
      }
    }
  }
  return [...seen.values()];
}

export function summarizeIocs(iocs) {
  const byType = {};
  const confirmedByType = {};
  let derived = 0;
  for (const ioc of iocs) {
    byType[ioc.type] = (byType[ioc.type] ?? 0) + 1;
    if (ioc.derived) derived += 1;
    else confirmedByType[ioc.type] = (confirmedByType[ioc.type] ?? 0) + 1;
  }
  return { total: iocs.length, byType, confirmedByType, derived };
}

/**
 * Tracking / fingerprinting surface. Each rule is a family of strings that
 * indicates the sample can identify a device, a person, or a session. This is
 * what "anti-tracking analysis" needs to see before any dynamic work starts.
 */
export const TRACKING_RULES = [
  { id: 'analytics-sdk', category: 'telemetry', label: 'Analytics / telemetry SDK', severity: 'medium', markers: ['google-analytics', 'app-measurement', 'firebaseanalytics', 'firebase', 'mixpanel', 'amplitude', 'flurry', 'segment.io', 'sentry.io', 'bugly', 'crashlytics', 'umeng', 'talkingdata', 'appsflyer', 'adjust.com', 'branch.io', 'onesignal', 'matomo', 'posthog', 'telemetry', '/v1/track', '/collect?', 'batch/v1/events'] },
  { id: 'ad-id', category: 'identity', label: 'Advertising / device identifier', severity: 'high', markers: ['advertisingidclient', 'advertising_id', 'getIdfa', 'idfa', 'gaid', 'google advertising id', 'oaid', 'imei', 'getDeviceId', 'TelephonyManager', 'getSubscriberId', 'getSimSerialNumber', 'android_id', 'ANDROID_ID', 'serial_number', 'ro.serialno'] },
  { id: 'device-fingerprint', category: 'fingerprint', label: 'Device / host fingerprint APIs', severity: 'high', markers: ['GetComputerName', 'GetVolumeInformation', 'GetSystemInfo', 'GetAdaptersInfo', 'GetMacAddress', 'GetUserName', 'gethostbyname', 'uname(', 'sysctlbyname', 'Build.FINGERPRINT', 'Build.MODEL', 'Build.MANUFACTURER', 'SystemProperties.get', 'dmidecode', 'wmic ', 'Win32_ComputerSystem', 'MachineGuid'] },
  { id: 'browser-fingerprint', category: 'fingerprint', label: 'Browser fingerprinting', severity: 'high', markers: ['canvas.toDataURL', 'toDataURL(', 'WebGLRenderingContext', 'WEBGL_debug_renderer_info', 'getParameter(UNMASKED', 'navigator.userAgent', 'navigator.plugins', 'navigator.languages', 'navigator.hardwareConcurrency', 'devicePixelRatio', 'screen.width', 'Intl.DateTimeFormat', 'resolvedOptions().timeZone', 'AudioContext', 'getBattery', 'font fingerprint'] },
  { id: 'geo', category: 'location', label: 'Location collection', severity: 'high', markers: ['getLastKnownLocation', 'LocationManager', 'requestLocationUpdates', 'CLLocationManager', 'geolocation.getCurrentPosition', 'navigator.geolocation', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'geoip', 'ip-api.com', 'ipinfo.io'] },
  { id: 'identity-gen', category: 'identity', label: 'Unique identifier generation', severity: 'medium', markers: ['CoCreateGuid', 'UUIDCreate', 'UUID:', 'java.util.UUID', 'SecureRandom', 'getRandomValues', 'installation_id', 'device_token', 'client_id=', 'visitor_id', 'session_id', 'fingerprintjs'] },
  { id: 'storage-tracking', category: 'storage', label: 'Persistent tracking state', severity: 'medium', markers: ['document.cookie', 'localStorage.setItem', 'sessionStorage', 'SharedPreferences', 'NSUserDefaults', 'getSharedPreferences', 'CookieManager', 'indexedDB', 'evercookie'] },
  { id: 'clipboard-contacts', category: 'collection', label: 'Clipboard / contacts / SMS access', severity: 'high', markers: ['ClipboardManager', 'getPrimaryClip', 'ContactsContract', 'READ_CONTACTS', 'READ_SMS', 'RECEIVE_SMS', 'content://sms', 'UIPasteboard', 'NSPasteboard'] },
  { id: 'network-id', category: 'network', label: 'Network identity / egress endpoints', severity: 'medium', markers: ['stun:', 'stunserver', 'turn:', 'X-Forwarded-For', 'X-Real-IP', 'doh.', 'dns.google', 'cloudflare-dns', 'User-Agent:', 'Referer', 'tracking pixel', 'pixel.gif', 'beacon', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org/bot'] },
  { id: 'attribution', category: 'telemetry', label: 'Attribution / install referrer', severity: 'medium', markers: ['INSTALL_REFERRER', 'referrer', 'utm_source', 'utm_campaign', 'campaign_id', 'deep_link', 'deferred deep link', 'attribution'] },
  // These families answer a different question: which values could let the
  // app's owner link this analysis session back to a real person.
  { id: 'account-linkage', category: 'identity-link', label: 'Account / login identity linkage', severity: 'high', markers: ['login', 'signIn', 'OAuth', 'openid', 'unionid', 'user_id', 'userId', 'account_id', 'email', 'phone_number', 'Authorization:', 'Bearer ', 'id_token', 'refresh_token', 'session_token', 'JWT', '/oauth/token'] },
  { id: 'push-token', category: 'identity-link', label: 'Push notification token', severity: 'high', markers: ['FCM', 'FirebaseInstanceId', 'getToken()', 'APNs', 'deviceToken', 'device_token', 'push_token', 'instance_id', 'OneSignal', 'notification_permission'] },
  { id: 'crash-identity', category: 'identity-link', label: 'Crash / analytics installation identity', severity: 'high', markers: ['Crashlytics', 'setUserIdentifier', 'setUserId', 'installation_id', 'installId', 'app_instance_id', 'Bugly', 'Sentry', 'session_id', 'visitor_id', 'distinct_id'] },
  { id: 'network-identity', category: 'identity-link', label: 'Network identity and egress correlation', severity: 'high', markers: ['X-Forwarded-For', 'X-Real-IP', 'User-Agent:', 'Referer', 'stun:', 'STUN', 'RTCPeerConnection', 'getPublicIp', 'ipify', 'ip-api.com', 'ipinfo.io', 'DOH', 'dns.google', 'cf-ray'] },
  { id: 'behaviour-telemetry', category: 'behaviour', label: 'Behavioural event and session replay telemetry', severity: 'medium', markers: ['logEvent', 'trackEvent', 'sessionReplay', 'heatmap', 'clickstream', 'screen_view', 'page_view', 'autocapture', 'touch_event', 'recordSession', '/v1/events', '/batch/'] },
  { id: 'locale-time', category: 'fingerprint', label: 'Locale / timezone / display fingerprint', severity: 'medium', markers: ['resolvedOptions().timeZone', 'Intl.DateTimeFormat', 'navigator.language', 'navigator.languages', 'screen.width', 'devicePixelRatio', 'getBattery', 'navigator.hardwareConcurrency', 'timezone_offset'] },
];

/** Match tracking families against sampled strings and imported APIs. */
export function trackingSurface(strings, imports = null) {
  const haystack = (Array.isArray(strings) ? strings : []).map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n');
  const apis = imports?.apiFlat ?? [];
  const lower = `${haystack}\n${apis.join('\n')}`.toLowerCase();
  const findings = [];
  for (const rule of TRACKING_RULES) {
    const matched = rule.markers.filter((marker) => lower.includes(marker.toLowerCase()));
    if (matched.length === 0) continue;
    findings.push({
      id: rule.id, category: rule.category, label: rule.label, severity: rule.severity,
      evidence: matched.slice(0, 8), markerCount: matched.length,
    });
  }
  const weight = { high: 3, medium: 2, low: 1 };
  const score = findings.reduce((sum, item) => sum + (weight[item.severity] ?? 1) * Math.min(item.markerCount, 4), 0);
  const level = score >= 18 ? 'high' : score >= 8 ? 'medium' : score > 0 ? 'low' : 'none';
  return {
    findings, score, level,
    categories: [...new Set(findings.map((item) => item.category))],
    limitations: 'Static string/import evidence only. A marker may come from an unused SDK or a benign library; absence proves nothing about encrypted or dynamically resolved indicators.',
  };
}

/**
 * Anti-analysis technique matrix. `tools` are suggested analysis steps, never
 * evasion or stealth capabilities, and are filtered to tools the server
 * actually advertises by the caller.
 */
export const ANTI_TECHNIQUES = [
  { id: 'debugger-api', category: 'debugger', technique: 'Debugger presence APIs', markers: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'ProcessDebugPort', 'OutputDebugString', 'DebugActiveProcess', 'ptrace', 'PT_DENY_ATTACH', 'sysctl(KERN_PROC'], countermeasure: 'Resolve the check statically, then confirm with a hardware-breakpoint-free session; prefer an offline core over a live attach.', tools: ['inspect_native_instruction', 'start_gdb_session', 'start_rizin_debug_session', 'inspect_recorded_crash'] },
  { id: 'debug-registers', category: 'debugger', technique: 'Hardware breakpoint / DR register checks', markers: ['GetThreadContext', 'CONTEXT_DEBUG_REGISTERS', 'Dr0', 'Dr7', 'NtGetContextThread'], countermeasure: 'Inspect the context read and the comparison target; use a trace that does not set debug registers.', tools: ['inspect_native_instruction', 'trace_native_values', 'observe_native_calls'] },
  { id: 'timing', category: 'timing', technique: 'Timing and execution-delay checks', markers: ['rdtsc', 'QueryPerformanceCounter', 'GetTickCount', 'timeGetTime', 'Sleep(', 'NtDelayExecution', 'clock_gettime'], countermeasure: 'Locate the delta comparison; a recorded trace is more reliable than stepping through a timing loop.', tools: ['inspect_native_instruction', 'trace_native_values', 'observe_native_calls'] },
  { id: 'cpu-hypervisor', category: 'vm', technique: 'CPUID / hypervisor detection', markers: ['cpuid', '__cpuid', 'HypervisorPresent', 'VMXh', 'KVMKVMKVM', 'Microsoft Hv', 'XenVMM', 'bhyve'], countermeasure: 'Identify the CPUID leaf and branch; compare against the disassembly rather than trusting the decompiler.', tools: ['inspect_native_instruction', 'procedure_assembly', 'batch_decompile'] },
  { id: 'vm-artifacts', category: 'vm', technique: 'VM registry / driver / device artifacts', markers: ['VMware', 'VBox', 'VBOX', 'QEMU', 'VirtualBox Guest Additions', 'vmhgfs', 'vmmouse', '\\\\.\\VBoxMiniRdrDN', 'HARDWARE\\DEVICEMAP\\Scsi', 'Xen', 'Parallels'], countermeasure: 'Treat as triage hints; enumerate referenced strings and their xrefs to separate decoys from real checks.', tools: ['search_strings', 'find_xrefs_to_name', 'inspect_analysis_view'] },
  { id: 'sandbox-env', category: 'sandbox', technique: 'Sandbox / analysis-environment heuristics', markers: ['Sandboxie', 'Cuckoo', 'JoeBox', 'sample.exe', 'malware', 'virus', 'ANALYST', 'JohnDoe', 'CurrentUser', 'GetCursorPos', 'GetForegroundWindow', 'GetSystemMetrics', 'GlobalMemoryStatusEx', 'GetDiskFreeSpace', 'NumberOfProcessors', 'Process32First'], countermeasure: 'List the thresholds and referenced APIs; a recorded scenario is useful when the check depends on wall-clock or UI state.', tools: ['search_strings', 'capture_process_scenario', 'observe_native_calls'] },
  { id: 'hook-detection', category: 'hook', technique: 'Inline hook / instrumentation detection', markers: ['frida', 'gum-js-loop', 'gadget', 'libfrida', 'FridaGadget', 'Xposed', 'Substrate', 'Magisk', 'libsubstrate', 'InlineHook', 'E9 ', 'VirtualProtect', 'mprotect', 'memcmp'], countermeasure: 'Check the prologue bytes at the compared address and enumerate loaded modules before attaching a script.', tools: ['inspect_native_load_image', 'inspect_native_instruction', 'list_segments', 'inspect_analysis_view'] },
  { id: 'anti-dump', category: 'anti-dump', technique: 'Anti-dump / memory protection', markers: ['VirtualProtect', 'NtProtectVirtualMemory', 'SetProcessDEPPolicy', 'EraseSection', 'Section', 'ZwUnmapViewOfSection', 'MmCopyVirtualMemory'], countermeasure: 'Note that no process-dump tool exists in this tool surface; use a live Frida observation or an out-of-band image.', tools: ['load_frida_script', 'observe_native_calls', 'inspect_binary_layout'] },
  { id: 'integrity', category: 'integrity', technique: 'Self-integrity / checksum validation', markers: ['MapFileAndCheckSum', 'ImageGetDigestStream', 'CheckSumMappedFile', 'CreateFileHash', 'CRC32', 'sha256', 'VerifySignature', 'WinVerifyTrust'], countermeasure: 'Find the checksum region and whether it covers the code being patched; confirm in disassembly.', tools: ['inspect_binary_layout', 'inspect_native_instruction', 'procedure_assembly'] },
  { id: 'tls-callback', category: 'debugger', technique: 'TLS callback / early execution', markers: ['TLS', 'TlsCallback', '.tls', 'IMAGE_TLS_DIRECTORY'], countermeasure: 'Inspect TLS directory entries before entry-point analysis; code there runs before main.', tools: ['inspect_binary_layout', 'inspect_native_instruction', 'procedure_assembly'] },
];

/** Match anti-analysis techniques and attach only real, advertised tool names. */
export function antiAnalysisMatrix(strings, imports = null, availableTools = null) {
  const haystack = (Array.isArray(strings) ? strings : []).map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n');
  const lower = `${haystack}\n${(imports?.apiFlat ?? []).join('\n')}`.toLowerCase();
  const known = (name) => availableTools === null || availableTools.has(name);
  const techniques = [];
  for (const rule of ANTI_TECHNIQUES) {
    const matched = rule.markers.filter((marker) => lower.includes(marker.toLowerCase()));
    if (matched.length === 0) continue;
    techniques.push({
      id: rule.id, category: rule.category, technique: rule.technique,
      evidence: matched.slice(0, 6),
      countermeasure: rule.countermeasure,
      nextTools: rule.tools.filter(known),
    });
  }
  return {
    techniques,
    categories: [...new Set(techniques.map((item) => item.category))],
    limitations: 'String/import matches are hints, not proof of an active check. Packed samples hide markers; benign software may link the same APIs. This tool suggests analysis steps, never evasion or stealth.',
  };
}

/** Local ATT&CK-style capability hints derived from imports and tracking evidence. */
export const CAPABILITY_RULES = [
  { id: 'T1055', tactic: 'defense-evasion / privilege-escalation', name: 'Process injection', markers: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext', 'NtMapViewOfSection', 'RtlCreateUserThread'] },
  { id: 'T1059', tactic: 'execution', name: 'Command and scripting interpreter', markers: ['CreateProcess', 'ShellExecute', 'WinExec', 'system(', 'execve', 'popen', 'cmd.exe', '/bin/sh', 'powershell'] },
  { id: 'T1547', tactic: 'persistence', name: 'Boot or logon autostart', markers: ['RegSetValue', 'RegCreateKey', 'CreateService', 'StartService', 'schtasks', 'CurrentVersion\\Run', 'LaunchAgents', 'crontab', 'systemd'] },
  { id: 'T1071', tactic: 'command-and-control', name: 'Application layer protocol', markers: ['WinHttpConnect', 'InternetConnect', 'HttpSendRequest', 'WSAConnect', 'connect(', 'URLDownloadToFile', 'WinHttpOpenRequest', 'curl_easy_perform', 'socket('] },
  { id: 'T1082', tactic: 'discovery', name: 'System information discovery', markers: ['GetSystemInfo', 'GetComputerName', 'GetUserName', 'EnumProcesses', 'GetAdaptersInfo', 'GetVolumeInformation', 'sysctl', 'uname'] },
  { id: 'T1113', tactic: 'collection', name: 'Screen capture', markers: ['BitBlt', 'GetDC', 'CreateCompatibleBitmap', 'CreateDC', 'XGetImage', 'CGDisplayCreateImage'] },
  { id: 'T1056', tactic: 'collection / credential-access', name: 'Input capture', markers: ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow', 'GetKeyState', 'RawInput', 'CGEventTap'] },
  { id: 'T1573', tactic: 'command-and-control', name: 'Encrypted channel', markers: ['SslHandshake', 'Schannel', 'SSL_connect', 'OPENSSL_init_ssl', 'BCryptEncrypt', 'CryptEncrypt', 'EVP_EncryptInit'] },
  { id: 'T1486', tactic: 'impact', name: 'Data encrypted for impact', markers: ['CryptEncrypt', 'BCryptEncrypt', 'CryptGenKey', 'CryptImportKey', 'EVP_EncryptUpdate', 'ransom'] },
  { id: 'T1027', tactic: 'defense-evasion', name: 'Obfuscated files or information', markers: ['VirtualProtect', 'RtlDecompressBuffer', 'CryptDecrypt', 'Base64', 'IsBadReadPtr', 'HeapAlloc'] },
  { id: 'T1140', tactic: 'defense-evasion', name: 'Deobfuscate / decode at runtime', markers: ['CryptDecrypt', 'RtlDecompressBuffer', 'VirtualAlloc', 'LoadLibrary', 'GetProcAddress'] },
];

/** Map imports + tracking findings to capability hints with explicit evidence. */
export function capabilityProfile({ imports = null, strings = [], tracking = null } = {}) {
  const api = (imports?.apiFlat ?? []).map((name) => String(name));
  const text = (Array.isArray(strings) ? strings : []).map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n');
  const lower = `${api.join('\n')}\n${text}`.toLowerCase();
  const capabilities = [];
  for (const rule of CAPABILITY_RULES) {
    const hits = rule.markers.filter((marker) => lower.includes(marker.toLowerCase()));
    if (hits.length === 0) continue;
    capabilities.push({
      id: rule.id, tactic: rule.tactic, name: rule.name,
      evidence: hits.slice(0, 6),
      confidence: hits.length >= 3 ? 'medium' : 'low',
    });
  }
  if (tracking && tracking.level !== 'none') {
    capabilities.push({
      id: 'T1537', tactic: 'collection / exfiltration', name: 'Tracking and device fingerprinting surface',
      evidence: tracking.findings.slice(0, 4).map((item) => item.label),
      confidence: tracking.level === 'high' ? 'medium' : 'low',
    });
  }
  return {
    capabilities,
    limitations: 'Capability hints, not observed behaviour. An imported API can be unused, and dynamic resolution hides imports entirely. Verify each hint against disassembly or a runtime trace.',
  };
}

/** Environment strings that must never leave the analyst's machine in a report. */
export function collectEnvTokens(env = process.env) {
  const user = String(env.USERNAME ?? env.USER ?? '').trim();
  const home = String(env.USERPROFILE ?? env.HOME ?? '').trim();
  const host = String(env.COMPUTERNAME ?? env.HOSTNAME ?? '').trim();
  return { user, home, host };
}

const LEAK_PATTERNS = [
  { kind: 'bearer-token', re: /(?:Bearer|token|api[_-]?key|secret|password)\s*[:=]?\s+[A-Za-z0-9._\-]{12,}/gi },
  { kind: 'github-pat', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { kind: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { kind: 'mac-address', re: /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g },
  { kind: 'ipv4', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { kind: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: 'windows-path', re: /\b[A-Za-z]:\\[^\s"'<>,;)]{2,180}/g },
  { kind: 'unix-home', re: /\/(?:Users|home)\/[A-Za-z0-9._-]+\/[^\s"'<>,;)]{1,160}/g },
  { kind: 'proxy-url', re: /\bhttps?:\/\/[^\s"'<>]*@[^\s"'<>]+/gi },
];

/** Count leaks without changing the text (for check mode). */
export function detectLeaks(text, tokens = collectEnvTokens()) {
  const body = String(text ?? '');
  const leaks = [];
  const add = (kind, value, count = 1) => {
    const found = leaks.find((item) => item.kind === kind && item.sample === value);
    if (found) found.count += count;
    else leaks.push({ kind, sample: String(value).slice(0, 120), count });
  };
  for (const [key, label] of [['user', 'analyst-username'], ['host', 'analyst-hostname'], ['home', 'analyst-home-path']]) {
    const token = tokens[key];
    if (!token || token.length < 3) continue;
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const matches = body.match(new RegExp(escaped, 'gi'));
    if (matches) add(label, token, matches.length);
  }
  for (const rule of LEAK_PATTERNS) {
    rule.re.lastIndex = 0;
    const matches = body.match(rule.re);
    if (matches) for (const value of new Set(matches)) add(rule.kind, value, 1);
  }
  return leaks;
}

/**
 * Some samples resolve APIs at runtime through GetProcAddress/dlsym, so the
 * import table alone understates capability. Recover names from recovered
 * strings and mark them explicitly as dynamically resolved hints.
 */
export function resolveDynamicApis(imports = null, strings = []) {
  const flat = imports?.apiFlat ?? [];
  const loader = flat.some((api) => /GetProcAddress|LoadLibrary|dlsym|dlopen|GetModuleHandle/i.test(api));
  if (!loader) return [];
  const known = new Set([
    ...CAPABILITY_RULES.flatMap((rule) => rule.markers),
    ...ANTI_TECHNIQUES.flatMap((rule) => rule.markers),
  ]);
  const text = (Array.isArray(strings) ? strings : []).map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n');
  return [...known].filter((api) => /^[A-Za-z][A-Za-z0-9_]{4,}$/.test(api) && new RegExp(`\\b${api}\\b`, 'i').test(text));
}

const EXPOSURE_CHAINS = [
  { identifier: 'Account / login identity', severity: 'critical', families: ['account-linkage'], risk: 'A signed-in account, email, phone or OAuth token ties the session directly to a person.', mitigation: 'Never sign in with a real account. Use a throwaway identity created inside the isolated lab, or none at all.' },
  { identifier: 'Device / advertising identifiers', severity: 'high', families: ['ad-id', 'install-id', 'crash-identity'], risk: 'A stable install ID, GAID/IDFA or crash SDK user ID persists across sessions and correlates every analysis run.', mitigation: 'Use a fresh snapshot per run; wipe app data between runs; do not reuse a device profile.' },
  { identifier: 'Push / crash instance tokens', severity: 'high', families: ['push-token', 'crash-identity'], risk: 'FCM/APNs tokens and crash installation IDs are long-lived device identifiers owned by the app publisher.', mitigation: 'Deny notification permission in the lab; block the crash/telemetry endpoints listed below.' },
  { identifier: 'Network egress identity', severity: 'high', families: ['network-identity', 'network-id'], risk: 'Source IP, User-Agent, WebRTC/STUN local IP and proxy headers reveal the analyst network and can be logged by the app owner.', mitigation: 'Use a dedicated egress (lab VPN/proxy) that is not your home or corporate IP; set networkEgressPolicy=deny for static work.' },
  { identifier: 'Browser / host / locale fingerprint', severity: 'medium', families: ['device-fingerprint', 'browser-fingerprint', 'locale-time'], risk: 'Timezone, language, fonts, screen size, CPU count and canvas/WebGL values form a quasi-unique fingerprint even without an account.', mitigation: 'Keep timezone/language/screen/fonts consistent across the lab image; avoid a contradictory "VM-only" combination.' },
  { identifier: 'Behavioural telemetry / session replay', severity: 'medium', families: ['behaviour-telemetry', 'analytics-sdk'], risk: 'Click streams and session replays record *how* the analysis was performed, not just who.', mitigation: 'Block event endpoints before any dynamic work; prefer offline/static analysis for the first pass.' },
  { identifier: 'Location and local data', severity: 'high', families: ['geo', 'clipboard-contacts', 'storage-tracking'], risk: 'Real location, clipboard and contacts can identify the analyst directly; the app owner receives them with the event batch.', mitigation: 'Use synthetic location and an empty clipboard/contacts store inside the lab image.' },
];

const PREFLIGHT = [
  'Run the sample only in an isolated, revertible lab (dedicated VM/sandbox, no personal files, no saved browser profile).',
  'Never sign in with a real account, phone number, email, or reuse an advertising/push/crash identifier.',
  'Use a dedicated network egress; do not expose your home or corporate IP. Set networkEgressPolicy=deny when static analysis is enough.',
  'Before any dynamic run, block the endpoints below in the lab hosts file / firewall (this tool only prints rules, it never modifies your system).',
  'Keep timezone, language, screen resolution, fonts and hardware counts consistent with the lab image; contradictory VM fingerprints are themselves identifying.',
  'Do not place the sample under a path containing your username or personal directories: PDB paths, caches and crash dumps leak that path to the publisher.',
  'Capture traffic during the run to catch endpoints that are not visible statically (encrypted config, dynamic DNS, fallback C2).',
  'Before sharing any finding, run rea_sanitize_report to strip local paths, hostnames, IPs and tokens.',
];

/**
 * Anti-tracking in the sense that matters here: when an analyst examines an
 * app, the app's owner can collect identifiers that link the session back to
 * that analyst. This maps the linkage chain and produces a defensive preflight
 * checklist plus printable block rules. It never changes system state and is
 * not evasion, impersonation or licence circumvention guidance.
 */
export function analystExposure({ tracking = null, iocs = [], imports = null, strings = [] } = {}) {
  const findings = new Map((tracking?.findings ?? []).map((item) => [item.id, item]));
  const chains = [];
  for (const chain of EXPOSURE_CHAINS) {
    const matched = chain.families.map((id) => findings.get(id)).filter(Boolean);
    if (matched.length === 0) continue;
    chains.push({
      identifier: chain.identifier,
      severity: chain.severity,
      risk: chain.risk,
      mitigation: chain.mitigation,
      families: matched.map((item) => item.id),
      evidence: matched.flatMap((item) => item.evidence).slice(0, 8),
    });
  }
  const endpointItems = (Array.isArray(iocs) ? iocs : []).filter((item) => ['url', 'domain', 'ipv4'].includes(item.type));
  const endpoints = [...new Set(endpointItems.map((item) => item.value))];
  const recoveredEndpoints = [...new Set(endpointItems.filter((item) => item.derived).map((item) => item.value))];
  const hosts = [...new Set(endpoints.map((value) => {
    try { return new URL(value.includes('://') ? value : `http://${value}`).hostname; }
    catch { return value.replace(/^https?:\/\//, '').split('/')[0]; }
  }).filter(Boolean))];
  const dynamicApis = resolveDynamicApis(imports, strings);
  const level = chains.some((item) => item.severity === 'critical') ? 'critical'
    : chains.length >= 4 ? 'high' : chains.length > 0 ? 'medium' : 'low';
  return {
    level,
    chains,
    endpoints,
    recoveredEndpoints,
    hosts,
    blockRules: hosts.map((host) => `0.0.0.0 ${host}`),
    dynamicApis,
    preflight: PREFLIGHT,
    limitations: 'Static evidence only. The publisher may collect identifiers through encrypted config, native code or a server-side lookup that never appears as a string here. This is a privacy/OPSEC aid, not evasion, impersonation, or licence circumvention; it never modifies system state.',
  };
}

/** Replace environment identifiers and secrets with stable, obvious placeholders. */
export function sanitizeText(text, tokens = collectEnvTokens()) {
  let body = String(text ?? '');
  const before = detectLeaks(body, tokens);
  const replacements = [];
  const swap = (kind, pattern, placeholder, flags = 'gi') => {
    const re = new RegExp(pattern, flags);
    const count = (body.match(re) ?? []).length;
    if (count === 0) return;
    body = body.replace(re, placeholder);
    replacements.push({ kind, placeholder, count });
  };
  if (tokens.home && tokens.home.length >= 3) {
    swap('analyst-home-path', tokens.home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), '<ANALYST_HOME>');
  }
  // Longest identifiers first: replacing the short username before the host
  // would turn "ALICE-PC" into "<ANALYST_USER>-PC" and lose the hostname.
  if (tokens.host && tokens.host.length >= 3) swap('analyst-hostname', tokens.host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), '<ANALYST_HOST>');
  if (tokens.user && tokens.user.length >= 3) swap('analyst-username', tokens.user.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), '<ANALYST_USER>');
  for (const rule of LEAK_PATTERNS) {
    rule.re.lastIndex = 0;
    const placeholder = `<REDACTED_${rule.kind.toUpperCase().replace(/-/g, '_')}>`;
    const count = (body.match(rule.re) ?? []).length;
    if (count === 0) continue;
    body = body.replace(rule.re, placeholder);
    replacements.push({ kind: rule.kind, placeholder, count });
  }
  return { text: body, replacements, leaks: before };
}
