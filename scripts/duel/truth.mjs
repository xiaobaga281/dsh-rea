/**
 * Shared ground truth for the duel.
 *
 * The defender hides these strings; the attacker never reads this file's
 * ordering or the generator - it only receives a file path and re-derives what
 * it can from the bytes. Both sides share the same literal list on purpose:
 * the point of the duel is packaging, not new content.
 *
 * The control generation (D0) stores every string as plaintext. Whatever the
 * analyser finds in D0 becomes the reachable ceiling for later generations, so
 * no expected-result list has to be maintained by hand.
 */

export const ENDPOINTS = [
  'https://telemetry.orbit-app.example/v1/collect',
  'https://api.orbit-app.example/device/register',
  'https://relay.orbit-app.example/gate.php',
  'https://backup.orbit-app.example/beacon',
  'https://pixel.orbit-app.example/t.gif',
];

export const MARKERS = [
  'FirebaseAnalytics', 'AppsFlyer', 'Crashlytics', 'utm_source=orbit',
  'setUserIdentifier', 'android_id', 'getSubscriberId', 'AdvertisingIdClient',
  'getLastKnownLocation', 'canvas.toDataURL', 'devicePixelRatio',
  'navigator.hardwareConcurrency', 'Intl.DateTimeFormat', 'X-Forwarded-For',
  'RTCPeerConnection', 'deviceToken', 'installation_id', 'document.cookie',
  'OAuth', 'user_id', 'localStorage.setItem', 'logEvent',
];

export const ANTI = [
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'rdtsc', 'QueryPerformanceCounter', 'cpuid', 'VMXh', 'VMware', 'VBox',
  'Sandboxie', 'frida', 'gum-js-loop', 'TlsCallback', 'GetThreadContext',
];

export const IOC_TEXT = [
  '203.0.113.77',
  'analytics@orbit-app.example',
  'HKLM\\SOFTWARE\\OrbitApp\\InstallId',
  'C:\\build\\orbit\\Release\\orbit_app.pdb',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) orbit/3.0',
  'update.orbit-app.example',
  '198.51.100.23',
];

/** Per-build attribution watermark: identifies which analyst copy leaked. */
export const CANARY = ['orbit-4d81f0c3a7e2', '7c93e1ab'];

export const ALL_STRINGS = [...ENDPOINTS, ...MARKERS, ...ANTI, ...IOC_TEXT];
