r"""Observe the side effects a sample attempts, through API hooks.

Usage:
    python observe.py <target> <duration-ms> <timeout-ms> [block-egress] [--pid N] [--tid N]

Spawn mode (default, no --pid): the process is spawned suspended by Frida, the
script loads before the first user-code instruction, then the process is
resumed for `duration-ms` and killed.

Attach mode (--pid N, with the sandbox launcher): the sample was already
created suspended inside the kernel sandbox (AppContainer + Job Object) by
scripts/rea-sandbox.ps1, which passed -Suspend. This helper attaches to the
existing pid, installs the same hooks BEFORE the first user-code instruction,
then resumes the suspended main thread via --tid (Win32 OpenThread/ResumeThread
- device.resume only covers Frida-spawned processes) and cleans the child up
with TerminateProcess when the window closes. The launcher's -TimeoutMs
watchdog and the caller's taskkill fallback remain the containment backstops.

Hooks (best effort, each failure is reported as a warning rather than aborting):
    registry  RegCreateKeyExW/A / RegOpenKeyExW/A / RegQueryValueExW/A /
              RegSetValueExW/A / RegDeleteValueW/A / RegCloseKey (both
              character sets: MinGW-built samples commonly call the A exports,
              which never pass through the W hooks). Every handle is resolved
              to a full key path: opens seen through the hooks build a
              handle->path map, and any other handle falls back to
              NtQueryKey(KeyNameInformation), so a handle obtained through an
              unhooked API (transactional opens, ntdll-direct opens) still
              reports a \REGISTRY\... path instead of a raw number. Failed
              resolutions fall back to the raw handle value - declared, not
              hidden. RegCloseKey drops the mapping so a reused handle value
              cannot inherit the previous key's path.
    pipe      CreateNamedPipeW
    network   connect / WSAConnect (ws2_32), IPv4 and IPv6 sockaddr parsing
    dns       getaddrinfo / GetAddrInfoW / GetAddrInfoExW (ws2_32) and
              DnsQuery_W (dnsapi), recording the queried name
    service   CreateServiceW

Host protection (block-egress, enabled unless the 4th argument is "0"): on
entry to connect/WSAConnect the sockaddr of a NON-loopback target has its
address family invalidated, so the call fails (WSAEAFNOSUPPORT) before any
packet can leave the host, and the attempt is recorded as
`network:connect-blocked <addr>` instead of `network:connect`. Loopback
(127.0.0.0/8 and ::1) is allowed through and observed normally. This is
user-mode best effort: direct syscalls, raw sockets, ConnectEx and UDP sendto
traffic are not stopped, and AF_UNIX/unknown families count as non-loopback.
Both sides of a comparison run under the same switch, so a blocked attempt is
a property of the harness, not a behavioural difference.

ws2_32 and dnsapi exports are mounted at script load when the module is already
loaded, and through Process.attachModuleObserver plus a 250 ms module poll
otherwise; load-time mounts are remembered so nothing attaches twice. Mount
failures and watched modules that never load surface as warnings, never
silently dropped.

Measured boundary (frida 17.26.3 / Win11 26300, root cause unknown): after the
first connect-family call the observer goes silent for the rest of that process
- only that first call and the hooked attempts made before it are reported, so
this never claims continuous observation. Everything up to the first connect
stays visible, including calls resolved at runtime through GetProcAddress or
the IAT, because Interceptor.attach patches the export address itself. The
egress block mutates the sockaddr inside that same attach callback, so this
window is unchanged by it.

The process is spawned suspended, the script loads before the first
user-code instruction, then the process is resumed for `duration-ms` and
killed. Events are normalised to lowercase `family:operation detail` lines so
two runs can be compared as sets. Within the window above this observes
attempts, not success: a call that failed still appears. That is deliberate - a
rebuild that never attempts the call is the difference worth catching.

Output:
    {"ok": true, "events": ["registry:set hkcu\\software\\x\\y", ...],
     "warnings": ["..."]}
"""

import json
import sys
import time

import frida


def emit(value):
    print(json.dumps(value), flush=True)
    sys.exit(0)


def parse_options(argv):
    """Split trailing flags (--pid N / --tid N) from positional arguments."""
    opts = {'pid': None, 'tid': None}
    positional = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == '--pid' and index + 1 < len(argv):
            opts['pid'] = int(argv[index + 1])
            index += 2
        elif arg == '--tid' and index + 1 < len(argv):
            opts['tid'] = int(argv[index + 1])
            index += 2
        else:
            positional.append(arg)
            index += 1
    return opts, positional


def resume_thread(tid):
    """Resume the sandbox launcher's suspended main thread from outside.

    device.resume() only covers Frida-spawned processes; an attached child
    needs OpenThread(THREAD_SUSPEND_RESUME) + ResumeThread.
    """
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenThread(0x0002, False, tid)
    if not handle:
        return False
    try:
        kernel32.ResumeThread(handle)
        return True
    finally:
        kernel32.CloseHandle(handle)


def terminate_process(pid):
    """Terminate an attached (not spawned) process; device.kill is not
    guaranteed for pids Frida did not spawn."""
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if not handle:
        return False
    try:
        return bool(kernel32.TerminateProcess(handle, 1))
    finally:
        kernel32.CloseHandle(handle)


def main():
    if len(sys.argv) < 4:
        emit({"error": "usage: observe.py <target> <duration-ms> <timeout-ms> [block-egress] [--pid N] [--tid N]"})
    target = sys.argv[1]
    try:
        duration_ms = max(200, min(30000, int(sys.argv[2])))
        timeout_ms = max(1000, min(120000, int(sys.argv[3])))
    except ValueError:
        emit({"error": "duration and timeout must be numbers"})
    opts, positional = parse_options(sys.argv[4:])
    attach_pid = opts['pid']
    attach_tid = opts['tid']
    # Host protection switch: any value other than "0" keeps the default-on
    # non-loopback connect block (observe.js passes "1" or "0").
    block_egress = not (positional and positional[0] == '0')

    source = r"""
    const BLOCK_EGRESS = __BLOCK_EGRESS__;  // host protection switch (argv 4)
    const events = [];
    const warnings = [];
    const keyPaths = new Map();
    // Predefined handle values (winreg.h). The previous table mislabeled
    // HKEY_USERS (0x80000003) as hkcr and missed HKEY_CLASSES_ROOT
    // (0x80000000) entirely - measured and fixed here.
    const HIVES = {
      '0x80000000': 'hkcr',
      '0x80000001': 'hkcu',
      '0x80000002': 'hklm',
      '0x80000003': 'hku',
      '0x80000004': 'hkpd',
      '0x80000005': 'hkcc'
    };
    // Registry handles are 32-bit values even on x64, but the predefined
    // constants reach the hooks sign-extended (HKEY_LOCAL_MACHINE arrives as
    // 0xffffffff80000002 - measured), so every map key is normalized to the
    // low 32 bits before lookup.
    function handleKey(pointer) {
      try {
        return '0x' + BigInt.asUintN(32, BigInt(pointer.toString())).toString(16);
      } catch (error) { return pointer.toString().toLowerCase(); }
    }
    // Full-path resolution for handles the open/create hooks never saw
    // (transactional opens, ntdll-direct opens, inherited handles):
    // NtQueryKey(KeyNameInformation) returns the kernel path, e.g.
    // \REGISTRY\MACHINE\SOFTWARE\..., normalized to the same hk* shorthand
    // the hooked opens produce so event sets stay comparable.
    let ntQueryKey = null;
    try {
      const ntQueryKeyAddress = findExport('NtQueryKey');
      if (ntQueryKeyAddress !== null) ntQueryKey = new NativeFunction(ntQueryKeyAddress, 'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']);
    } catch (error) { ntQueryKey = null; }
    function ntKeyPath(handle) {
      if (ntQueryKey === null || handle.isNull()) return null;
      try {
        const buffer = Memory.alloc(1024);
        const needed = Memory.alloc(4);
        const status = ntQueryKey(handle, 3, buffer, 1024, needed); // 3 = KeyNameInformation
        if (status !== 0) return null;
        const chars = buffer.readU32() / 2;
        if (chars <= 0 || chars > 500) return null;
        return buffer.add(4).readUtf16String(chars);
      } catch (error) { return null; }
    }
    function normalizeNtPath(path) {
      let text = String(path || '').toLowerCase();
      if (text.charAt(0) === '\\') text = text.slice(1);
      if (text.indexOf('registry\\machine\\') === 0) return 'hklm\\' + text.slice(17);
      if (text.indexOf('registry\\machine') === 0) return 'hklm';
      if (text.indexOf('registry\\user\\') === 0) {
        const rest = text.slice(14);
        const slash = rest.indexOf('\\');
        const hive = slash === -1 ? rest : rest.slice(0, slash);
        const tail = slash === -1 ? '' : rest.slice(slash + 1);
        // <sid>_classes is the per-user HKCR view; the SID itself is host
        // identity, so events keep the hive shorthand without it.
        if (hive.lastIndexOf('_classes') === hive.length - 8) return tail ? 'hkcr\\' + tail : 'hkcr';
        return tail ? 'hku\\' + tail : 'hku';
      }
      if (text.indexOf('registry\\user') === 0) return 'hku';
      if (text.indexOf('registry\\') === 0) return text.slice(9);
      return text;
    }
    function resolveKeyPath(pointer) {
      const key = handleKey(pointer);
      if (HIVES[key]) return HIVES[key];
      const mapped = keyPaths.get(key);
      if (mapped !== undefined) return mapped;
      const resolved = normalizeNtPath(ntKeyPath(pointer) || '');
      if (resolved) {
        keyPaths.set(key, resolved);
        return resolved;
      }
      return key; // raw handle value, last resort - never invented
    }
    function readWide(pointer) {
      try { return pointer.isNull() ? null : pointer.readUtf16String(); } catch (error) { return null; }
    }
    function readAnsi(pointer) {
      try { return pointer.isNull() ? null : pointer.readAnsiString(); } catch (error) { return null; }
    }
    function add(kind, detail) {
      if (events.length >= 200) return;
      const line = (kind + ' ' + String(detail || '')).toLowerCase().replace(/\s+/g, ' ').trim();
      if (line.length > 1 && events.indexOf(line) === -1) {
        events.push(line);
        // Stream every event as it happens: a sample that exits within the
        // observation window unloads the agent before any report round-trip
        // (measured in the sandbox attach path), and the streamed lines are
        // the only record that survives.
        try { send({ event: 'ev', line: line }); } catch (error) { /* dying process */ }
      }
    }
    function findExport(name) {
      try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (error) { /* next */ }
      try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (error) { /* next */ }
      return null;
    }
    function hook(name, handlers) {
      try {
        const address = findExport(name);
        if (address === null) { warnings.push(name + ': export not found'); return; }
        Interceptor.attach(address, handlers);
      } catch (error) {
        warnings.push(name + ': ' + String(error));
      }
    }

    // IPv4/IPv6 sockaddr parsing. sockaddr_in6 layout (x64, field-checked):
    // family@0 (AF_INET=2, AF_INET6=23), port@2 big-endian, flowinfo@4, the 16
    // address bytes @8 in network order, scope id @24. The scope is reported as
    // a number; interface-name lookup is not attempted.
    function formatIpv6(groups, scope) {
      let bestStart = -1; let bestLength = 0; let runStart = -1; let runLength = 0;
      for (let i = 0; i < 8; i++) {
        if (groups[i] === 0) {
          if (runStart === -1) { runStart = i; runLength = 1; } else { runLength += 1; }
          if (runLength > bestLength) { bestStart = runStart; bestLength = runLength; }
        } else { runStart = -1; runLength = 0; }
      }
      let text;
      if (bestLength < 2) {
        text = groups.map((word) => word.toString(16)).join(':');
      } else {
        const head = groups.slice(0, bestStart).map((word) => word.toString(16)).join(':');
        const tail = groups.slice(bestStart + bestLength).map((word) => word.toString(16)).join(':');
        text = head + '::' + tail;
      }
      if (scope !== 0) text += '%' + scope;
      return text;
    }
    function formatSockaddr(pointer) {
      const family = pointer.readU16();
      if (family === 2) {
        const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
        const raw = pointer.add(4);
        const ip = [raw.readU8(), raw.add(1).readU8(), raw.add(2).readU8(), raw.add(3).readU8()].join('.');
        return ip + ':' + port;
      }
      if (family === 23) {
        const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
        const groups = [];
        for (let i = 0; i < 8; i++) {
          groups.push((pointer.add(8 + i * 2).readU8() << 8) | pointer.add(9 + i * 2).readU8());
        }
        const scope = pointer.add(24).readU32();
        return '[' + formatIpv6(groups, scope) + ']:' + port;
      }
      return 'family-' + family;
    }
    // Loopback decision at the sockaddr level: AF_INET (2) is loopback when
    // the first address byte is 127; AF_INET6 (23) is loopback only for ::1.
    // Every other family (AF_UNIX, unknown) counts as non-loopback - this can
    // block legitimate local IPC and is declared as a limitation.
    function isLoopbackSockaddr(pointer, family) {
      if (family === 2) return pointer.add(4).readU8() === 127;
      if (family === 23) {
        for (let i = 0; i < 15; i++) {
          if (pointer.add(8 + i).readU8() !== 0) return false;
        }
        return pointer.add(23).readU8() === 1;
      }
      return false;
    }
    function connectHandlers() {
      return {
        onEnter(args) {
          try {
            const pointer = args[1];
            const detail = formatSockaddr(pointer);
            if (BLOCK_EGRESS && !isLoopbackSockaddr(pointer, pointer.readU16())) {
              add('network:connect-blocked', detail);
              // Invalidate the address family so connect fails
              // (WSAEAFNOSUPPORT) before any packet can be sent. This stays
              // an attach callback, so the measured first-connect
              // observation window is unchanged.
              pointer.writeU16(0xffff);
              return;
            }
            add('network:connect', detail);
          }
          catch (error) { add('network:connect', 'unreadable'); }
        }
      };
    }
    function resolveHandlers(readName) {
      return { onEnter(args) { add('dns:resolve', readName(args[0])); } };
    }
    function dnsQueryHandlers() {
      return { onEnter(args) { add('dns:query', readWide(args[0])); } };
    }

    // Exports watched for mounting. ws2_32 is usually in the sample's import
    // table (already loaded at script load); a sample that loads it later is
    // covered by the module observer and the poll below. dnsapi is reached only
    // by samples that query DNS through it directly, and that path can produce
    // real outbound traffic, so coverage here is best effort by design.
    const EXPORT_HOOKS = {
      connect: connectHandlers,
      WSAConnect: connectHandlers,
      getaddrinfo: () => resolveHandlers(readAnsi),
      GetAddrInfoW: () => resolveHandlers(readWide),
      GetAddrInfoExW: () => resolveHandlers(readWide),
      DnsQuery_W: dnsQueryHandlers
    };
    const WATCHED_MODULES = {
      'ws2_32.dll': ['connect', 'WSAConnect', 'getaddrinfo', 'GetAddrInfoW', 'GetAddrInfoExW'],
      'dnsapi.dll': ['DnsQuery_W']
    };
    const hooked = new Set();  // exports successfully attached
    const failed = new Set();  // exports whose mount errored; never retried
    function watchKey(moduleName, exportName) { return moduleName.toLowerCase() + '!' + exportName; }
    function mountExport(moduleName, exportName) {
      const key = watchKey(moduleName, exportName);
      if (hooked.has(key) || failed.has(key)) return;
      try {
        const module = Process.findModuleByName(moduleName);
        if (module === null) return;  // not loaded yet; the deferred paths retry
        const address = module.getExportByName(exportName);
        if (address === null || address.isNull()) { warnings.push(key + ': export not found'); failed.add(key); return; }
        Interceptor.attach(address, EXPORT_HOOKS[exportName]());
        hooked.add(key);
      } catch (error) {
        warnings.push(key + ': ' + String(error));
        failed.add(key);
      }
    }
    function mountWatched() {
      for (const moduleName of Object.keys(WATCHED_MODULES)) {
        for (const exportName of WATCHED_MODULES[moduleName]) mountExport(moduleName, exportName);
      }
    }
    mountWatched();
    try {
      if (typeof Process.attachModuleObserver === 'function') {
        Process.attachModuleObserver({
          onAdded(module) {
            try {
              const watched = WATCHED_MODULES[String(module.name).toLowerCase()];
              if (watched) for (const exportName of watched) mountExport(module.name, exportName);
            } catch (error) { warnings.push('module observer: ' + String(error)); }
          }
        });
      } else {
        warnings.push('Process.attachModuleObserver unavailable; only the polling fallback covers late-loaded modules');
      }
    } catch (error) {
      warnings.push('attachModuleObserver failed: ' + String(error));
    }
    const pollTimer = setInterval(() => {
      try { mountWatched(); } catch (error) { warnings.push('module poll: ' + String(error)); }
    }, 250);

    // Registry hooks in BOTH character sets: MinGW-built samples commonly call
    // the A variants (RegCreateKeyExA/RegSetValueExA), which are separate
    // exports that never pass through the hooked W exports (measured: an
    // A-only caller produced no events with W-only hooks).
    function registryCreateHandlers(read) {
      return {
        onEnter(args) {
          const sub = read(args[1]);
          const parent = resolveKeyPath(args[0]);
          this.path = sub ? (parent + '\\' + sub) : parent;
          this.result = args[7];
          add('registry:create', this.path);
        },
        onLeave() {
          try {
            if (!this.result.isNull()) {
              const handle = this.result.readPointer();
              if (!handle.isNull()) keyPaths.set(handleKey(handle), this.path);
            }
          } catch (error) { /* handle mapping is best effort */ }
        }
      };
    }
    function registryOpenHandlers(read) {
      return {
        onEnter(args) {
          const sub = read(args[1]);
          const parent = resolveKeyPath(args[0]);
          this.path = sub ? (parent + '\\' + sub) : parent;
          this.result = args[4];
        },
        onLeave() {
          try {
            if (!this.result.isNull()) {
              const handle = this.result.readPointer();
              if (!handle.isNull()) keyPaths.set(handleKey(handle), this.path);
            }
          } catch (error) { /* handle mapping is best effort */ }
        }
      };
    }
    function registryQueryHandlers(read) {
      return {
        onEnter(args) {
          const name = read(args[1]);
          add('registry:query', resolveKeyPath(args[0]) + (name ? '\\' + name : ''));
        }
      };
    }
    function registrySetHandlers(read) {
      return {
        onEnter(args) {
          const name = read(args[1]);
          add('registry:set', resolveKeyPath(args[0]) + (name ? '\\' + name : ''));
        }
      };
    }
    function registryDeleteHandlers(read) {
      return {
        onEnter(args) {
          const name = read(args[1]);
          add('registry:delete', resolveKeyPath(args[0]) + (name ? '\\' + name : ''));
        }
      };
    }
    hook('RegCreateKeyExW', registryCreateHandlers(readWide));
    hook('RegCreateKeyExA', registryCreateHandlers(readAnsi));
    hook('RegOpenKeyExW', registryOpenHandlers(readWide));
    hook('RegOpenKeyExA', registryOpenHandlers(readAnsi));
    hook('RegQueryValueExW', registryQueryHandlers(readWide));
    hook('RegQueryValueExA', registryQueryHandlers(readAnsi));
    hook('RegSetValueExW', registrySetHandlers(readWide));
    hook('RegSetValueExA', registrySetHandlers(readAnsi));
    hook('RegDeleteValueW', registryDeleteHandlers(readWide));
    hook('RegDeleteValueA', registryDeleteHandlers(readAnsi));
    // Dropping the mapping on close keeps a reused handle value from
    // inheriting the previous key's path.
    hook('RegCloseKey', {
      onEnter(args) { keyPaths.delete(handleKey(args[0])); }
    });
    hook('CreateNamedPipeW', {
      onEnter(args) { add('pipe:create', readWide(args[0])); }
    });
    hook('CreateServiceW', {
      onEnter(args) { add('service:create', readWide(args[1])); }
    });

    recv('report', function () {
      clearInterval(pollTimer);
      clearInterval(flushTimer);
      try {
        for (const moduleName of Object.keys(WATCHED_MODULES)) {
          for (const exportName of WATCHED_MODULES[moduleName]) {
            const key = watchKey(moduleName, exportName);
            if (!hooked.has(key) && !failed.has(key)) {
              warnings.push(key + ': module never loaded before the report, hook not installed');
            }
          }
        }
      } catch (error) { /* the coverage sweep is best effort */ }
      send({ event: 'report', events: events, warnings: warnings });
    });
    // Periodic flush: a sample that exits before the caller's report request
    // would take its events with it (measured in the sandbox attach path: a
    // fast-exiting child unloaded the agent before script.post arrived). The
    // latest periodic report is a valid substitute; the module-coverage sweep
    // above only runs on the live-process path.
    const flushTimer = setInterval(() => {
      try { send({ event: 'report', events: events, warnings: warnings, periodic: true }); } catch (error) { /* dying process */ }
    }, 100);
    """
    # Inject the switch without f-string braces clashing with the JavaScript.
    source = source.replace('__BLOCK_EGRESS__', 'true' if block_egress else 'false')

    resumed = False
    try:
        device = frida.get_local_device()
        if attach_pid:
            # Attach mode: the sandbox launcher already created the child
            # suspended (and only resumes it itself when -Suspend is absent).
            pid = attach_pid
            session = device.attach(pid)
            script = session.create_script(source)
            messages = []
            script.on('message', lambda message, data: messages.append((message, data)))
            script.load()
            if attach_tid:
                resumed = resume_thread(attach_tid)
        else:
            pid = device.spawn([target])
            session = device.attach(pid)
            script = session.create_script(source)
            messages = []
            script.on('message', lambda message, data: messages.append((message, data)))
            script.load()
            device.resume(pid)
            resumed = True
    except Exception as error:  # noqa: BLE001
        emit({"error": f"spawn/attach failed: {error}"})

    time.sleep(duration_ms / 1000.0)
    try:
        script.post({'type': 'report'})
    except Exception:  # noqa: BLE001 - the process may have exited
        pass

    deadline = time.time() + min(5.0, timeout_ms / 1000.0)
    report = None
    periodic = None
    streamed = []
    seen_warnings = []
    while time.time() < deadline:
        for message, _blob in list(messages):
            payload = message.get('payload') if message.get('type') == 'send' else None
            if not isinstance(payload, dict):
                continue
            if payload.get('event') == 'report':
                if payload.get('periodic'):
                    periodic = payload  # latest periodic flush wins
                else:
                    report = payload  # the live-process report with the coverage sweep
                    break
            elif payload.get('event') == 'ev':
                line = payload.get('line')
                if line and line not in streamed:
                    streamed.append(line)
            elif payload.get('event') == 'warn':
                text = payload.get('text')
                if text and text not in seen_warnings:
                    seen_warnings.append(text)
        if report is not None:
            break
        time.sleep(0.05)
    if report is None:
        # Merge the streamed captures with the last periodic snapshot: a
        # sample that exits inside the same 100ms window as its events would
        # otherwise lose them (the periodic snapshot can lag the final events).
        merged = list(streamed)
        for event in (periodic or {}).get('events', []):
            if event not in merged:
                merged.append(event)
        if merged:
            merged_warnings = list(seen_warnings)
            for warning in (periodic or {}).get('warnings', []):
                if warning not in merged_warnings:
                    merged_warnings.append(warning)
            report = {
                'events': merged,
                'warnings': merged_warnings + ['the sample exited before the report round-trip; events merge the streamed hook captures with the last periodic snapshot and the module-coverage sweep did not run'],
            }
    if report is None and streamed:
        # The sample exited before any report could round-trip; the streamed
        # per-event captures are the observation. The module-coverage sweep
        # never ran, so that warning would be missing - say so instead of
        # pretending the sweep happened.
        report = {
            'events': streamed,
            'warnings': seen_warnings + ['the sample exited before the report round-trip; events are the streamed hook captures and the module-coverage sweep did not run'],
        }

    try:
        if attach_pid:
            # Plain TerminateProcess, no session.detach(): detaching from a
            # terminated container child's agent can hang (measured), and the
            # report must go out - the caller reaps this helper once it sees
            # the answer line. Process exit closes the session either way.
            terminate_process(pid)
        else:
            device.kill(pid)
            session.detach()
    except Exception:  # noqa: BLE001
        pass

    if report is None:
        emit({"error": "the observer produced no report"})
    warnings = report.get('warnings', [])
    if attach_pid and not resumed:
        warnings = list(warnings) + [f'resume of the suspended main thread (tid={attach_tid}) failed; the child likely produced no events because it never ran']
    emit({"ok": True, "events": report.get('events', []), "warnings": warnings})


if __name__ == '__main__':
    main()
