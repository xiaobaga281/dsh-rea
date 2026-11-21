import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildReadiness, compileC } from '../lib/build.js';
import { dynamicReadiness } from '../lib/dynamic.js';
import { compareEventSets, summarizeEvents } from '../lib/observe.js';
import { buildSideEffectsTool } from '../lib/observe-tools.js';

test('event sets are compared on recall and precision, and an empty pair is empty', () => {
  const comparison = compareEventSets(
    ['registry:set hkcu\\software\\x\\y', 'pipe:create \\\\.\\pipe\\a'],
    ['pipe:create \\\\.\\pipe\\a', 'network:connect 127.0.0.1:9'],
  );
  assert.equal(comparison.status, 'ran');
  assert.equal(comparison.recall, 0.5);
  assert.equal(comparison.precision, 0.5);
  assert.deepEqual(comparison.missing, ['registry:set hkcu\\software\\x\\y']);
  assert.deepEqual(comparison.added, ['network:connect 127.0.0.1:9']);
  assert.deepEqual(comparison.groups.target, { registry: 1, pipe: 1, network: 0, dns: 0, service: 0, other: 0 });

  const empty = compareEventSets([], []);
  assert.equal(empty.status, 'empty');
  assert.equal(empty.score, null);

  assert.deepEqual(summarizeEvents(['service:create x', 'other']), { registry: 0, pipe: 0, network: 0, dns: 0, service: 1, other: 1 });
});

test('IPv6 connects and DNS lookups score in the same event sets without new plumbing', () => {
  const absent = compareEventSets(['dns:resolve localhost', 'network:connect [::1]:9'], []);
  assert.equal(absent.status, 'ran');
  assert.equal(absent.recall, 0);
  assert.equal(absent.precision, null);
  assert.equal(absent.score, 0);
  assert.deepEqual(absent.missing, ['dns:resolve localhost', 'network:connect [::1]:9']);
  assert.deepEqual(absent.added, []);
  assert.deepEqual(absent.groups.target, { registry: 0, pipe: 0, network: 1, dns: 1, service: 0, other: 0 });

  const mirrored = compareEventSets(
    ['dns:resolve localhost', 'network:connect [::1]:9'],
    ['dns:resolve localhost', 'network:connect [::1]:9'],
  );
  assert.equal(mirrored.recall, 1);
  assert.equal(mirrored.precision, 1);
  assert.equal(mirrored.score, 1);
  assert.deepEqual(mirrored.groups.rebuilt, { registry: 0, pipe: 0, network: 1, dns: 1, service: 0, other: 0 });
});

test('the side-effect tool refuses without the policy flag or confirmation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-observe-'));
  try {
    const disabled = buildSideEffectsTool({ config: {} });
    assert.match((await disabled.execute({ target: join(dir, 'a.exe'), rebuilt: join(dir, 'b.exe'), confirm: true })).text, /sample execution is disabled/);
    const unconfirmed = buildSideEffectsTool({ config: { allowSampleExecution: true } });
    assert.match((await unconfirmed.execute({ target: join(dir, 'a.exe'), rebuilt: join(dir, 'b.exe'), confirm: false })).text, /confirm must be true/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a named pipe and an outbound connect are observed on the target and missing from a quiet rebuild', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-observe-'));
  try {
    const noisy = [
      '#include <winsock2.h>',
      '#include <windows.h>',
      'int main(void) {',
      String.raw`  CreateNamedPipeW(L"\\\\.\\pipe\\rea-observe-test", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 0, 0, 0, 0);`,
      '  WSADATA data; WSAStartup(MAKEWORD(2, 2), &data);',
      '  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);',
      '  struct sockaddr_in addr; ZeroMemory(&addr, sizeof(addr));',
      '  addr.sin_family = AF_INET; addr.sin_port = htons(9);',
      '  addr.sin_addr.s_addr = inet_addr("127.0.0.1");',
      '  connect(s, (struct sockaddr *)&addr, sizeof(addr));',
      '  Sleep(2500);',
      '  return 0;',
      '}',
    ].join('\n');
    const quiet = '#include <windows.h>\nint main(void) { Sleep(2500); return 0; }\n';
    const a = await compileC({ sourceText: noisy, workDir: join(dir, 'a'), name: 'a', extraArgs: ['-lws2_32'] });
    const b = await compileC({ sourceText: quiet, workDir: join(dir, 'b'), name: 'b' });
    assert.equal(a.ok, true, a.reason);
    assert.equal(b.ok, true, b.reason);
    const store = {
      async write(name, body) {
        const path = join(dir, name);
        await writeFile(path, body, 'utf8');
        return path;
      },
    };
    const tool = buildSideEffectsTool({ config: { allowSampleExecution: true }, store });
    const answer = await tool.execute({ target: a.outPath, rebuilt: b.outPath, confirm: true, durationMs: 900 });
    assert.match(answer.text, /pipe:create/);
    assert.match(answer.text, /network:connect 127\.0\.0\.1:9/);
    assert.match(answer.text, /missing from the rebuild/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a local DNS resolve and a single IPv6 loopback connect are observed on the target and missing from a quiet rebuild', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-observe-'));
  try {
    // Fixture discipline (measured on frida 17.26.3 / Win11 26300):
    // - the sample prints nothing: runSideEffectObserver parses the LAST stdout
    //   line of observe.py as the JSON report, sample output would corrupt that;
    // - the DNS lookups run BEFORE the first connect-family call, because the
    //   observation window ends at that first call - later events go silent;
    // - exactly ONE connect-family call: an IPv4+IPv6 double connect would fake
    //   a negative - the second call and everything after it are invisible;
    // - GetAddrInfoW (chained inside getaddrinfo) must receive a valid
    //   PADDRINFOW and a FreeAddrInfoW, never a NULL ppResult (that segfaults
    //   inside ws2_32 and the tool would just report a broken observer).
    // Zero external traffic: only "localhost" and the machine's own hostname
    // are resolved (an API-level probe measured no winsock sends for either),
    // and the connect targets the IPv6 loopback [::1]:9. The resolved
    // addresses are freed, never connected to.
    const v6 = [
      '#include <winsock2.h>',
      '#include <ws2tcpip.h>',
      '#include <windows.h>',
      '#include <string.h>',
      'int main(void) {',
      '  WSADATA data; WSAStartup(MAKEWORD(2, 2), &data);',
      '  char host[256] = {0};',
      '  if (gethostname(host, sizeof(host)) == 0) {',
      '    struct addrinfo *hres = NULL;',
      '    getaddrinfo(host, NULL, NULL, &hres);',
      '    if (hres != NULL) freeaddrinfo(hres);',
      '  }',
      '  struct addrinfo *res = NULL;',
      '  getaddrinfo("localhost", NULL, NULL, &res);',
      '  if (res != NULL) freeaddrinfo(res);',
      '  SOCKET s = socket(AF_INET6, SOCK_STREAM, 0);',
      '  struct sockaddr_in6 addr; ZeroMemory(&addr, sizeof(addr));',
      '  addr.sin6_family = AF_INET6; addr.sin6_port = htons(9);',
      '  const unsigned char loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};',
      '  memcpy(&addr.sin6_addr, loopback, sizeof(loopback));',
      '  connect(s, (struct sockaddr *)&addr, sizeof(addr));',
      '  Sleep(2500);',
      '  return 0;',
      '}',
    ].join('\n');
    const quiet = '#include <windows.h>\nint main(void) { Sleep(2500); return 0; }\n';
    const a = await compileC({ sourceText: v6, workDir: join(dir, 'a'), name: 'a', extraArgs: ['-lws2_32'] });
    const b = await compileC({ sourceText: quiet, workDir: join(dir, 'b'), name: 'b' });
    assert.equal(a.ok, true, a.reason);
    assert.equal(b.ok, true, b.reason);
    const store = {
      async write(name, body) {
        const path = join(dir, name);
        await writeFile(path, body, 'utf8');
        return path;
      },
    };
    const tool = buildSideEffectsTool({ config: { allowSampleExecution: true }, store });
    const answer = await tool.execute({ target: a.outPath, rebuilt: b.outPath, confirm: true, durationMs: 900 });
    assert.match(answer.text, /dns:resolve/);
    assert.match(answer.text, /network:connect \[::1\]:9/);
    assert.match(answer.text, /missing from the rebuild/);
    // Egress blocking is on by default and must not touch the loopback: no
    // EVENT carries the blocked marker (the limitations text mentions the
    // event name, so anchor on the address form).
    assert.doesNotMatch(answer.text, /network:connect-blocked \d/);
    // Host privacy: the rendered report carries placeholders, never the real
    // machine name or home path; the disk JSON below keeps the raw values
    // because it is a local file under the artifact directory.
    assert.ok(!answer.text.includes(hostname()), `rendered text named the real host: ${answer.text}`);
    assert.match(answer.text, /\[HOSTNAME\]/);
    assert.match(answer.text, /\[USERPROFILE\]/);
    const saved = JSON.parse(await readFile(join(dir, 'side-effects.json'), 'utf8'));
    const resolves = saved.target.events.filter((event) => event.startsWith('dns:resolve'));
    assert.ok(resolves.includes('dns:resolve localhost'), `localhost resolve missing: ${JSON.stringify(saved.target.events)}`);
    assert.ok(resolves.some((event) => event !== 'dns:resolve localhost'), `machine-hostname resolve missing: ${JSON.stringify(saved.target.events)}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('registry events carry full key paths, including handles from unhooked opens', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-observe-'));
  try {
    // Three resolution paths in one specimen, all under HKCU\\Software\\dsh-rea-observe:
    // 1. hooked RegCreateKeyExW -> handle->path map;
    // 2. RegOpenKeyTransactedW (NOT hooked) -> the set on that handle must be
    //    resolved by the NtQueryKey(KeyNameInformation) fallback, proving a
    //    handle from an unhooked API still yields a full path;
    // 3. RegQueryValueExW on the mapped handle -> registry:query with a path.
    // The transaction is never committed, so the transacted write rolls back;
    // the plain key is deleted by the sample itself. No stdout (the observer
    // parses the last stdout line as JSON).
    const specimen = [
      '#define _WIN32_WINNT 0x0600',
      '#include <windows.h>',
      '#include <ktmw32.h>',
      'int main(void) {',
      '  HKEY mapped = NULL;',
      '  RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\\\dsh-rea-observe", 0, NULL, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &mapped, NULL);',
      '  RegSetValueExW(mapped, L"marker", 0, REG_SZ, (const BYTE *)L"1", 8);',
      '  HANDLE tx = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);',
      '  HKEY transacted = NULL;',
      '  RegOpenKeyTransactedW(HKEY_CURRENT_USER, L"Software\\\\dsh-rea-observe", 0, KEY_SET_VALUE | KEY_READ, &transacted, tx, 0);',
      '  RegSetValueExW(transacted, L"txn", 0, REG_SZ, (const BYTE *)L"1", 8);',
      '  DWORD type = 0; BYTE buf[64]; DWORD len = sizeof(buf);',
      '  RegQueryValueExW(mapped, L"marker", NULL, &type, buf, &len);',
      '  RegCloseKey(mapped);',
      '  RegCloseKey(transacted);',
      '  if (tx) CloseHandle(tx);',
      '  RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\\\dsh-rea-observe");',
      '  Sleep(2500);',
      '  return 0;',
      '}',
    ].join('\n');
    const a = await compileC({ sourceText: specimen, workDir: join(dir, 'a'), name: 'a', extraArgs: ['-ladvapi32', '-lktmw32'] });
    assert.equal(a.ok, true, a.reason);
    const store = {
      async write(name, body) {
        const path = join(dir, name);
        await writeFile(path, body, 'utf8');
        return path;
      },
    };
    const tool = buildSideEffectsTool({ config: { allowSampleExecution: true }, store });
    // Same binary on both sides: the rendered excerpt compares sets and shows
    // no missing/added lines, so the event assertions run on the disk JSON.
    await tool.execute({ target: a.outPath, rebuilt: a.outPath, confirm: true, durationMs: 900 });
    const saved = JSON.parse(await readFile(join(dir, 'side-effects.json'), 'utf8'));
    const events = saved.target.events;
    assert.ok(events.includes('registry:set hkcu\\software\\dsh-rea-observe\\marker'), JSON.stringify(events));
    // The transacted handle never passed through a hooked open: only the
    // NtQueryKey fallback can name it. It resolves to the kernel path
    // \\REGISTRY\\USER\\<sid>\\..., normalized to the hku shorthand (the
    // account SID is host identity and stays out of the event text).
    assert.ok(events.includes('registry:set hku\\software\\dsh-rea-observe\\txn'), JSON.stringify(events));
    assert.ok(events.includes('registry:query hkcu\\software\\dsh-rea-observe\\marker'), JSON.stringify(events));
    // No registry event may fall back to a raw handle value.
    assert.ok(!events.some((event) => /^registry:\w+ 0x[0-9a-f]/.test(event)), JSON.stringify(events));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a non-loopback connect is blocked before any packet; the raw attempt is kept on disk', async (t) => {
  const readiness = await dynamicReadiness();
  if (!readiness.ready) {
    t.skip(`no Frida (${readiness.reason})`);
    return;
  }
  const builder = await buildReadiness();
  if (!builder.ready) {
    t.skip(`no build engine (${builder.reason})`);
    return;
  }
  const dir = await mkdtemp(join(tmpdir(), 'dsh-rea-observe-'));
  try {
    // Same fixture discipline as above: no sample stdout, exactly ONE
    // connect-family call. The target 192.0.2.1 is RFC 5737 TEST-NET
    // (non-routable, zero external traffic); with blockSampleEgress the
    // observer invalidates the sockaddr family on entry, so connect fails
    // with WSAEAFNOSUPPORT before any packet is sent - that synchronous
    // failure at the API layer is the "no egress" evidence, together with the
    // unreachable TEST-NET address.
    const probe = [
      '#include <winsock2.h>',
      '#include <windows.h>',
      'int main(void) {',
      '  WSADATA data; WSAStartup(MAKEWORD(2, 2), &data);',
      '  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);',
      '  struct sockaddr_in addr; ZeroMemory(&addr, sizeof(addr));',
      '  addr.sin_family = AF_INET; addr.sin_port = htons(9);',
      '  addr.sin_addr.s_addr = inet_addr("192.0.2.1");',
      '  connect(s, (struct sockaddr *)&addr, sizeof(addr));',
      '  Sleep(2500);',
      '  return 0;',
      '}',
    ].join('\n');
    const quiet = '#include <windows.h>\nint main(void) { Sleep(2500); return 0; }\n';
    const a = await compileC({ sourceText: probe, workDir: join(dir, 'a'), name: 'a', extraArgs: ['-lws2_32'] });
    const b = await compileC({ sourceText: quiet, workDir: join(dir, 'b'), name: 'b' });
    assert.equal(a.ok, true, a.reason);
    assert.equal(b.ok, true, b.reason);
    const store = {
      async write(name, body) {
        const path = join(dir, name);
        await writeFile(path, body, 'utf8');
        return path;
      },
    };
    const tool = buildSideEffectsTool({ config: { allowSampleExecution: true }, store });
    const answer = await tool.execute({ target: a.outPath, rebuilt: b.outPath, confirm: true, durationMs: 900 });
    assert.match(answer.text, /network:connect-blocked 192\.0\.2\.1:9/);
    assert.doesNotMatch(answer.text, /network:connect 192\.0\.2\.1:9/);
    const saved = JSON.parse(await readFile(join(dir, 'side-effects.json'), 'utf8'));
    assert.ok(saved.target.events.includes('network:connect-blocked 192.0.2.1:9'), JSON.stringify(saved.target.events));
    assert.ok(!saved.target.events.includes('network:connect 192.0.2.1:9'), JSON.stringify(saved.target.events));
    // The switch travels with the record so a report can state the posture.
    assert.equal(saved.blockEgress, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
