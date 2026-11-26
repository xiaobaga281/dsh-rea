"""Dump the main module's memory image of a running process.

Usage:
    python dump.py <target> <raw-output> <size-of-image> <delay-ms> <timeout-ms> [wait-for-exec] [--pid N] [--tid N]

Attach mode (--pid N): the target was already created suspended inside the
kernel sandbox (scripts/runtime/rea-sandbox.ps1 -Suspend). This helper attaches to the
existing pid, installs the kernel32 hooks before the first user-code
instruction, and resumes the suspended main thread via --tid (Win32
OpenThread/ResumeThread - device.resume only covers Frida-spawned processes)
only when a delay or wait-for-exec was requested; a delay-0 dump reads the
image while the child is still suspended at its entry point. Cleanup uses
TerminateProcess; the launcher's -TimeoutMs watchdog stays the backstop.

`wait-for-exec` (1/0) resumes the process and waits for the first executable
memory marking seen through two hook layers: kernel32!VirtualAlloc/VirtualProtect
and ntdll!NtAllocateVirtualMemory/NtProtectVirtualMemory (for packers that call
ntdll directly; source attribution keeps kernel32 callers booked by the kernel32
layer, and pure direct syscalls that bypass every export stay invisible). The
mark alone is a heuristic, not a real OEP finder, so on the first
marking the helper also arms a Stalker watch across the process's threads:
the marking thread, every thread alive at the mark, and threads created
afterwards (NtCreateThreadEx onLeave, start-address filtered against Frida's
own modules, capped at 16 threads). The first basic block executed inside the
marked region on ANY followed thread is reported as `execEntry` (hit address,
instruction text, raw bytes, hitting thread). Two
measured Frida 17.26.3 behaviours shape the injected script:
`Script.setExceptionHandler` does not exist there (each callback guards itself
with try/catch and script faults surface as `type == 'error'` messages), and
NativePointer values created in hook context read back as 0x0 inside a Stalker
transform callback, so the region and main-module bounds are stored as plain
JS numbers and compared numerically.

The wait phase and the dump phase share one deadline that starts before the
resume (no second full timeout), and the dump phase always keeps a floor
budget (`DUMP_MIN_BUDGET_S`) so a dump still happens after a timed-out wait -
the caller can then report an explicit `entry: none`. If the process dies
while waiting, the helper reports an explicit error instead of a generic
timeout, because the image is gone with the process. Death is detected two
ways: the session's detached signal (fires for real terminations with or
without hooks - measured on 17.26.3) plus a low-rate poll of the device's
process list as belt-and-braces (get_process() matches by name, not pid).
Note the measured failure mode that is NOT death: with a kernel32 VirtualAlloc
hook installed, some samples never exit at all - the process stays alive and
the agent stops answering even a dump request - which surfaces as the generic
timeout with the helper's warnings attached.

Output:
    {"ok": true, "bytes": 1234, "base": "0x...", "size": 1234, "delayMs": 0,
     "oepSignal": {"addr": "0x...", "size": 4096, "prot": 64,
                   "kind": "VirtualAlloc", "layer": "kernel32"} | null,
     "execEntry": {"hit": "0x...", "instruction": "mov ...", "bytes": "...",
                   "insideMainModule": false, "inRegion": true} | null,
     "entryWatch": "armed" | "partial" | "unavailable" | "off",
     "entryWatchReason": "..." | null, "watchThread": 1234 | null,
     "watchThreads": [1234, ...], "followedCount": 3,
     "warnings": [...]}
    {"error": "...", "warnings": [...]}
"""

import json
import sys
import time

import frida

DUMP_MIN_BUDGET_S = 10.0
POLL_S = 0.05
SETTLE_S = 0.15


def emit(value):
    print(json.dumps(value), flush=True)
    sys.exit(0)


def parse_pid_tid(argv):
    pid = None
    tid = None
    index = 0
    while index < len(argv):
        if argv[index] == '--pid' and index + 1 < len(argv):
            pid = int(argv[index + 1])
            index += 2
        elif argv[index] == '--tid' and index + 1 < len(argv):
            tid = int(argv[index + 1])
            index += 2
        else:
            index += 1
    return pid, tid


def resume_thread(tid):
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenThread(0x0002, False, tid)  # THREAD_SUSPEND_RESUME
    if not handle:
        return False
    try:
        kernel32.ResumeThread(handle)
        return True
    finally:
        kernel32.CloseHandle(handle)


def terminate_process(pid):
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
    if len(sys.argv) < 6:
        emit({"error": "usage: dump.py <target> <out> <size> <delay-ms> <timeout-ms> [--pid N] [--tid N]"})
    target = sys.argv[1]
    out_path = sys.argv[2]
    extra = sys.argv[6:]
    attach_pid, attach_tid = parse_pid_tid(extra)
    # wait-for-exec stays a positional token: skip the flag pairs first.
    positional_extra = []
    index = 0
    while index < len(extra):
        if extra[index] in ('--pid', '--tid'):
            index += 2
            continue
        positional_extra.append(extra[index])
        index += 1
    try:
        size = int(sys.argv[3])
        delay_ms = max(0, int(sys.argv[4]))
        timeout_ms = max(1000, int(sys.argv[5]))
        wait_for_exec = len(positional_extra) > 0 and positional_extra[0] == '1'
    except ValueError:
        emit({"error": "size, delay and timeout must be numbers"})

    source = """
    const mainModule = Process.enumerateModules()[0];
    // Stalker transform callbacks cannot see NativePointers created in hook
    // context (they read back as 0x0), so every bound below is a plain number.
    // x64 user-space addresses are far below 2^53, so Number() is lossless.
    const mainLo = Number(mainModule.base);
    const mainHi = Number(mainModule.base.add(mainModule.size));
    const execMask = 0x10 | 0x20 | 0x40 | 0x80;
    let oepSignal = null;
    let regionLo = 0;
    let regionHi = 0;
    let watchThread = 0;
    let watchArmed = false;
    let watchError = null;
    let entrySent = false;
    // Process-wide watch (W1): the thread that marks memory executable is not
    // always the thread that first executes the marked region - multi-threaded
    // packers mark in a worker and jump from another thread. On the mark, every
    // thread alive at that moment is followed, plus threads created afterwards
    // (via the NtCreateThreadEx onLeave hook), until the first region entry.
    // Frida's own modules are excluded from Stalker BEFORE any follow so agent
    // code is never rewritten (no self-instrumentation overhead) and agent
    // return addresses stay inside frida ranges instead of drifting into
    // Stalker's anonymous code cache.
    const MAX_WATCH_THREADS = 16;
    const fridaRanges = [];
    const followedTids = [];
    let watchScopePartial = false;
    let queryThreadAddress = null;
    try {
      for (const module of Process.enumerateModules()) {
        if (/frida|gum/i.test(module.name)) {
          fridaRanges.push({ name: module.name, base: module.base, size: module.size,
                             lo: Number(module.base), hi: Number(module.base.add(module.size)) });
        }
      }
    } catch (rangeError) { /* without the table the start-address filter is simply off */ }
    for (const range of fridaRanges) {
      try { Stalker.exclude({ base: range.base, size: range.size }); } catch (excludeError) { /* keep going */ }
    }
    try { queryThreadAddress = findExport('NtQueryInformationThread'); } catch (queryError) { queryThreadAddress = null; }
    function isFridaAddress(value) {
      for (const range of fridaRanges) {
        if (value >= range.lo && value < range.hi) return true;
      }
      return false;
    }
    // System wrapper layer (W2 source attribution): kernel32!VirtualAlloc/
    // VirtualProtect are the primary accounting hooks, but on some Windows
    // versions they are forwarders into kernelbase, so BOTH module ranges
    // count as the wrapper layer. An ntdll hook whose returnAddress lands in
    // a wrapper range is the SAME allocation/protection the kernel32 hook
    // already booked - the ntdll hook skips it, so kernel32 callers keep
    // kind='VirtualAlloc'/'VirtualProtect' and only true direct ntdll calls
    // are recorded with layer='ntdll'.
    const wrapperRanges = [];
    try {
      for (const module of Process.enumerateModules()) {
        if (/^(?:kernel32|kernelbase)\\.dll$/i.test(module.name)) {
          wrapperRanges.push({ name: module.name, lo: Number(module.base), hi: Number(module.base.add(module.size)) });
        }
      }
    } catch (wrapperError) { /* without the table only exact direct calls are attributed */ }
    function isWrapperAddress(value) {
      for (const range of wrapperRanges) {
        if (value >= range.lo && value < range.hi) return true;
      }
      return false;
    }
    function followThread(tid, why, critical) {
      if (entrySent) return false;
      if (followedTids.indexOf(tid) !== -1) return true;
      if (followedTids.length >= MAX_WATCH_THREADS) {
        if (!watchScopePartial) {
          watchScopePartial = true;
          send({ event: 'watch-scope', warning: 'thread watch cap (' + MAX_WATCH_THREADS + ') reached; threads beyond it are not followed (coverage is partial)' });
        }
        return false;
      }
      try {
        Stalker.follow(tid, { transform: onTransform });
        followedTids.push(tid);
        return true;
      } catch (error) {
        const text = 'Stalker.follow(' + tid + ',' + (why || '?') + '): ' + String(error);
        if (critical) {
          watchError = text;
          watchArmed = false;
          send({ event: 'watch-error', error: text });
        } else {
          send({ event: 'watch-scope', warning: text });
        }
        return false;
      }
    }
    function followAllThreads() {
      let threads = [];
      try { threads = Process.enumerateThreads(); } catch (error) {
        send({ event: 'watch-scope', warning: 'enumerateThreads: ' + String(error) });
        return;
      }
      for (const thread of threads) followThread(thread.id, 'mark-time', false);
    }
    function unfollowAll() {
      for (const tid of followedTids.slice()) {
        try { Stalker.unfollow(tid); } catch (unfollowError) { /* best effort per thread */ }
      }
      followedTids.length = 0;
      try { Stalker.flush(); } catch (flushError) { /* best effort */ }
    }
    // Thread handle -> tid via NtQueryInformationThread(ThreadBasicInformation):
    // the struct's CLIENT_ID.UniqueThread sits at offset 24 on x64.
    function tidFromHandle(handle) {
      if (!queryThreadAddress) return 0;
      try {
        const query = new NativeFunction(queryThreadAddress, 'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']);
        const info = Memory.alloc(64);
        const status = query(handle, 0, info, 48, ptr(0));
        if (status !== 0) return 0;
        return info.add(24).readU32();
      } catch (queryError) { return 0; }
    }
    // Threads created AFTER the mark are filtered by start address
    // (NtCreateThreadEx arg 4 = StartRoutine): frida-range starts are the
    // agent's own JS/worker threads and must never be followed - they would
    // burn the cap and make the agent instrument itself. Hardcoded-syscall
    // thread creation bypasses this export and stays a declared blind spot,
    // as does the race window between thread creation and this onLeave.
    function attachThreadCreateHook() {
      let createAddress = null;
      try { createAddress = findExport('NtCreateThreadEx'); } catch (hookError) { createAddress = null; }
      if (!createAddress) {
        send({ event: 'watch-scope', warning: 'NtCreateThreadEx not found; threads created after the mark are not followed' });
        return;
      }
      try {
        Interceptor.attach(createAddress, {
          onEnter(args) { this.handlePtr = args[0]; this.startRoutine = args[4]; },
          onLeave(retval) {
            try {
              if (entrySent) return;
              if (retval.toInt32() !== 0) return;
              if (isFridaAddress(Number(this.startRoutine))) return;
              const tid = tidFromHandle(this.handlePtr);
              if (tid > 0) followThread(tid, 'post-mark-thread', false);
            } catch (followError) {
              send({ event: 'watch-scope', warning: 'post-mark thread follow: ' + String(followError) });
            }
          }
        });
      } catch (error) {
        send({ event: 'watch-scope', warning: 'NtCreateThreadEx hook: ' + String(error) });
      }
    }
    function toHex(raw) {
      if (raw === null) return null;
      const view = new Uint8Array(raw);
      let text = '';
      for (let i = 0; i < view.length; i += 1) {
        const digit = view[i].toString(16);
        text += (digit.length < 2 ? '0' : '') + digit + (i < view.length - 1 ? ' ' : '');
      }
      return text;
    }
    function onRegionEntry(context) {
      if (entrySent) return;
      entrySent = true;
      try {
        const hit = context.pc;
        const hitNum = Number(hit);
        // The callout runs on the traced thread itself, so this is the thread
        // whose execution first entered the marked region - with the
        // process-wide watch it can differ from the marking thread.
        const hitThread = Process.getCurrentThreadId();
        let instruction = null;
        try {
          const parsed = Instruction.parse(hit);
          instruction = parsed.mnemonic + ' ' + parsed.opStr;
        } catch (parseError) { instruction = null; }
        let bytesText = null;
        try { bytesText = toHex(hit.readByteArray(16)); } catch (readError) { bytesText = null; }
        const insideMain = hitNum >= mainLo && hitNum < mainHi;
        const inRegion = hitNum >= regionLo && hitNum < regionHi;
        send({ event: 'exec-entry', hit: hit.toString(), instruction: instruction,
               bytes: bytesText, insideMainModule: insideMain, inRegion: inRegion,
               threadId: hitThread, followedCount: followedTids.length });
        // Unfollowing from inside the callout is safe here: measured on
        // 17.26.3, unfollow takes effect at the end of the current compiled
        // block, so the entry block's own instructions still run (verified by
        // the acceptance sample's marker landing in the dumped image).
        // First hit wins process-wide (entrySent), so every followed thread
        // is released here - no new follows start after this point either.
        unfollowAll();
      } catch (error) {
        send({ event: 'script-error', where: 'callout', description: String(error) });
      }
    }
    function onTransform(iterator) {
      try {
        let insn = iterator.next();
        // A control-flow transfer into the marked region lands on a new basic
        // block whose first instruction is inside the region, so only the
        // block head is checked. putCallout inserts the callout; the current
        // instruction must still be kept explicitly, and every instruction
        // this callback does not keep is dropped - a dropped head instruction
        // corrupts the traced thread, hence keep() for every next().
        if (insn !== null && regionLo !== 0 &&
            Number(insn.address) >= regionLo && Number(insn.address) < regionHi) {
          iterator.putCallout(onRegionEntry);
        }
        while (insn !== null) {
          iterator.keep();
          insn = iterator.next();
        }
      } catch (error) {
        send({ event: 'script-error', where: 'transform', description: String(error) });
      }
    }
    function armWatch(address, size) {
      try {
        regionLo = Number(address);
        regionHi = Number(address.add(size));
        watchThread = Process.getCurrentThreadId();
        // The marking thread first (a failure here means no watch at all),
        // then every thread alive at the mark, then post-mark creations.
        if (followThread(watchThread, 'marking-thread', true)) {
          followAllThreads();
          attachThreadCreateHook();
        }
        watchArmed = followedTids.length > 0;
      } catch (error) {
        watchError = 'Stalker.follow: ' + String(error);
        watchArmed = false;
        send({ event: 'watch-error', error: watchError });
      }
    }
    function note(address, size, prot, kind, context, layer) {
      // Double gate (W2): agent-originated calls never reach the bookkeeping.
      // (1) caller gate - the agent's own RWX allocations (Interceptor
      // trampoline slabs, Stalker code caches) are anonymous pages no region
      // filter can see, but their returnAddress is always inside a frida
      // module (Stalker.exclude keeps it from drifting into the code cache);
      // (2) region gate - an EXEC page inside a frida module is agent-owned.
      if (context && isFridaAddress(Number(context.returnAddress))) return;
      if (isFridaAddress(Number(address))) return;
      if ((prot & execMask) === 0) return;
      // One page is the smallest meaningful unpacking unit. Smaller flips are
      // loader/CRT fixups and would fire before the packer does anything.
      if (size < 0x1000) return;
      if (oepSignal !== null) {
        // First-come-first-served stands: a second EXEC marking (the same
        // region re-marked, another worker's page, or the same allocation
        // seen through both hook layers) is recorded, never overwrites.
        send({ event: 'exec-mark-duplicate', kind: kind, layer: layer, addr: address.toString() });
        return;
      }
      oepSignal = { addr: address.toString(), size: size, prot: prot, kind: kind, layer: layer };
      armWatch(address, size);
      send({ event: 'exec-mark', signal: oepSignal, watch: watchArmed ? 'armed' : 'unavailable',
             watchThread: watchThread, watchError: watchError,
             watchThreads: followedTids.slice(), followedCount: followedTids.length,
             watchScope: watchScopePartial ? 'partial' : 'full' });
    }
    function findExport(name) {
      try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (error) { /* try next */ }
      try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (error) { /* try next */ }
      try { return Process.getModuleByName('ntdll.dll').getExportByName(name); } catch (error) { /* try next */ }
      return Process.getModuleByName('kernel32.dll').getExportByName(name);
    }
    try {
      const vp = findExport('VirtualProtect');
      Interceptor.attach(vp, {
        onEnter(args) { this.addr = args[0]; this.size = args[1].toInt32(); this.prot = args[2].toInt32(); },
        onLeave(retval) { if (retval.toInt32() !== 0) note(this.addr, this.size, this.prot, 'VirtualProtect', this, 'kernel32'); }
      });
    } catch (error) { send({ event: 'hook-error', error: 'VirtualProtect: ' + String(error) }); }
    try {
      const va = findExport('VirtualAlloc');
      Interceptor.attach(va, {
        onEnter(args) { this.prot = args[3].toInt32(); this.size = args[1].toInt32(); },
        onLeave(ret) { if (!ret.isNull()) note(ret, this.size, this.prot, 'VirtualAlloc', this, 'kernel32'); }
      });
    } catch (error) { send({ event: 'hook-error', error: 'VirtualAlloc: ' + String(error) }); }
    // W2: the ntdll export layer. Packers that resolve NtAllocateVirtualMemory
    // / NtProtectVirtualMemory via GetProcAddress (or call the exports
    // directly) never touch the kernel32 hooks above; these hooks share the
    // same note() pathway with layer='ntdll'. The returnAddress attribution
    // below keeps the double accounting away: a kernel32/kernelbase caller is
    // the same allocation the kernel32 hook already booked, so only a TRUE
    // direct ntdll call is recorded here. Pure shellcode that issues the
    // syscalls without going through any ntdll export stays invisible - a
    // declared blind spot, never claimed as covered.
    try {
      const nta = findExport('NtAllocateVirtualMemory');
      Interceptor.attach(nta, {
        onEnter(args) { this.basePtr = args[1]; this.sizePtr = args[3]; this.prot = args[5].toInt32(); },
        onLeave(retval) {
          if (retval.toInt32() !== 0) return; // STATUS_SUCCESS only
          if (isWrapperAddress(Number(this.returnAddress))) return; // kernel32 layer books this allocation
          const base = this.basePtr.readPointer();
          if (base.isNull()) return;
          note(base, this.sizePtr.readPointer().toInt32(), this.prot, 'NtAllocateVirtualMemory', this, 'ntdll');
        }
      });
    } catch (error) { send({ event: 'hook-error', error: 'NtAllocateVirtualMemory: ' + String(error) }); }
    try {
      const ntp = findExport('NtProtectVirtualMemory');
      Interceptor.attach(ntp, {
        onEnter(args) { this.basePtr = args[1]; this.sizePtr = args[2]; this.prot = args[3].toInt32(); },
        onLeave(retval) {
          if (retval.toInt32() !== 0) return; // STATUS_SUCCESS only
          if (isWrapperAddress(Number(this.returnAddress))) return; // kernel32 layer books this protection
          const base = this.basePtr.readPointer();
          if (base.isNull()) return;
          note(base, this.sizePtr.readPointer().toInt32(), this.prot, 'NtProtectVirtualMemory', this, 'ntdll');
        }
      });
    } catch (error) { send({ event: 'hook-error', error: 'NtProtectVirtualMemory: ' + String(error) }); }
    recv('dump', function () {
      try {
        const bytes = mainModule.base.readByteArray(SIZE);
        if (bytes === null) { send({ error: 'readByteArray returned null' }); return; }
        send({ ok: true, base: mainModule.base.toString(), size: SIZE }, bytes);
      } catch (error) {
        send({ error: String(error) });
      }
    });
    """.replace('SIZE', str(size))

    def kill_child():
        # Attach mode (sandbox): device.kill is not guaranteed for pids Frida
        # did not spawn, so use TerminateProcess - and SKIP session.detach():
        # detaching from a terminated container child's agent can hang
        # (measured), which would stall the answer; process exit closes the
        # session either way. Spawn mode keeps device.kill + detach.
        try:
            if attach_pid:
                terminate_process(pid)
            else:
                device.kill(pid)
                session.detach()
        except Exception:  # noqa: BLE001
            pass

    try:
        device = frida.get_local_device()
        if attach_pid:
            pid = attach_pid
            session = device.attach(pid)
        else:
            pid = device.spawn([target])
            session = device.attach(pid)
        # get_process() matches by name, not pid, so the low-rate process-list
        # poll in process_gone() is the belt-and-braces death check; the
        # detached signal fires reliably for real terminations (hooks or not).
        detached_reasons = []
        session.on('detached', lambda *args: detached_reasons.append(args[0] if args else 'unknown'))
        script = session.create_script(source)
        messages = []
        script.on('message', lambda message, data: messages.append((message, data)))
        script.load()
    except Exception as error:  # noqa: BLE001 - the helper reports the reason
        emit({"error": f"spawn/attach failed: {error}"})

    # One deadline for the whole run: the wait phase and the dump phase share
    # it, so the wall clock stays inside the outer kill timer (timeout + 30 s)
    # and the second phase can never double the wait.
    t0 = time.time()
    deadline = t0 + timeout_ms / 1000.0

    signal = None
    exec_entry = None
    entry_watch = 'armed' if wait_for_exec else 'off'
    entry_watch_reason = None
    watch_thread = None
    watch_threads = []
    followed_count = 0
    warnings = []
    # The wait loop below reuses this verdict after breaking; when the deadline
    # is already spent before the first poll (delay_ms >= the remaining budget)
    # the loop body never runs, so the death verdict must exist up front.
    gone = False

    def remember_warning(text):
        if text and text not in warnings:
            warnings.append(text)

    def mark_entry_unavailable(text):
        nonlocal entry_watch, entry_watch_reason
        if exec_entry is not None:
            return
        entry_watch = 'unavailable'
        if entry_watch_reason is None and text:
            entry_watch_reason = text

    # Death detector for the wait and dump loops: the detached signal for real
    # terminations, plus a low-rate poll of the device's process list (once a
    # second, not once per 50 ms poll tick) as belt-and-braces. It deliberately
    # does NOT treat "agent stopped answering" as death - that state keeps the
    # process alive (see the VirtualAlloc-hook failure mode in the header).
    last_liveness_poll = 0.0

    def process_gone():
        nonlocal last_liveness_poll
        if detached_reasons:
            return True
        now = time.time()
        if now - last_liveness_poll < 1.0:
            return False
        last_liveness_poll = now
        try:
            return pid not in {entry.pid for entry in device.enumerate_processes()}
        except Exception:  # noqa: BLE001 - enumeration unavailable: the shared deadline still bounds the run
            return False

    if delay_ms > 0 or wait_for_exec:
        try:
            if attach_pid:
                if not attach_tid or not resume_thread(attach_tid):
                    kill_child()
                    emit({"error": f"resume failed: cannot resume the sandbox child's main thread (tid={attach_tid})", "warnings": warnings})
            else:
                device.resume(pid)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        except Exception as error:  # noqa: BLE001
            kill_child()
            emit({"error": f"resume failed: {error}", "warnings": warnings})

    if wait_for_exec:
        # The mark alone is not the evidence: keep waiting until control flow
        # is actually observed inside the marked region (or the watch dies, or
        # the deadline runs out - never silently substituting the mark).
        while time.time() < deadline:
            for message, _blob in list(messages):
                mtype = message.get('type')
                if mtype == 'error':
                    description = message.get('description') or 'the Frida script raised an error'
                    remember_warning(description)
                    mark_entry_unavailable(description)
                    continue
                if mtype != 'send':
                    continue
                candidate = message.get('payload') or {}
                event = candidate.get('event')
                if event == 'exec-mark':
                    if signal is None:
                        signal = candidate.get('signal')
                        watch_thread = candidate.get('watchThread')
                        watch_threads = candidate.get('watchThreads') or []
                        followed_count = candidate.get('followedCount') or 0
                        if candidate.get('watch') == 'unavailable':
                            mark_entry_unavailable(candidate.get('watchError') or 'the Stalker watch could not be armed')
                        elif candidate.get('watchScope') == 'partial' and entry_watch == 'armed':
                            entry_watch = 'partial'
                            entry_watch_reason = 'the thread watch cap was reached before the whole process was covered'
                elif event == 'exec-entry':
                    if exec_entry is None:
                        exec_entry = candidate
                        # The hitting thread is the watchThread the report names.
                        hit_thread = candidate.get('threadId')
                        if isinstance(hit_thread, int) and hit_thread > 0:
                            watch_thread = hit_thread
                        break
                elif event == 'hook-error':
                    remember_warning(candidate.get('error'))
                elif event == 'watch-scope':
                    remember_warning(candidate.get('warning'))
                elif event == 'exec-mark-duplicate':
                    remember_warning('duplicate exec-mark: {0} ({1}) at {2} - the first mark stands'.format(
                        candidate.get('kind'), candidate.get('layer'), candidate.get('addr')))
                elif event in ('script-error', 'watch-error'):
                    description = candidate.get('description') or candidate.get('error') or 'unknown script error'
                    remember_warning(description)
                    mark_entry_unavailable(description)
            gone = process_gone()
            if exec_entry is not None or gone:
                break
            time.sleep(POLL_S)
        # Reuse the loop's last death verdict: calling process_gone() again
        # here could be throttled (1 s between polls) and would miss a death
        # that the loop itself just discovered via the process list.
        if gone:
            # The image is gone with the process; posting the dump request
            # would only stall until some deadline and then read as a generic
            # timeout. Report what was and was not observed instead.
            kill_child()
            death_reason = detached_reasons[0] if detached_reasons else "process no longer in the device's process list"
            mark_text = f"exec-mark at {signal.get('addr')}" if signal else 'no exec-mark observed'
            entry_text = f"entry at {exec_entry.get('hit')}" if exec_entry else 'entry: none'
            emit({"error": f"the process exited before the dump ({death_reason}; {mark_text}; {entry_text})", "warnings": warnings})
        # Let the packer finish writing the region it just made executable
        # (and, after an entry hit, the landing code that just started).
        if exec_entry is not None or signal is not None:
            time.sleep(SETTLE_S)

    try:
        script.post({'type': 'dump'})
    except Exception as error:  # noqa: BLE001
        kill_child()
        emit({"error": f"post failed: {error}", "warnings": warnings})

    # The dump phase keeps at least DUMP_MIN_BUDGET_S even when the shared
    # deadline has already been spent waiting: a zero budget would turn a
    # timed-out wait into "no dump before the timeout" and hide the explicit
    # "entry: none" report the caller is promised.
    dump_deadline = time.time() + max(deadline - time.time(), DUMP_MIN_BUDGET_S)
    payload = None
    data = None
    while time.time() < dump_deadline:
        if process_gone():
            kill_child()
            death_reason = detached_reasons[0] if detached_reasons else "process no longer in the device's process list"
            mark_text = f"exec-mark at {signal.get('addr')}" if signal else 'no exec-mark observed'
            entry_text = f"entry at {exec_entry.get('hit')}" if exec_entry else 'entry: none'
            emit({"error": f"the process exited before the dump could be read ({death_reason}; {mark_text}; {entry_text})", "warnings": warnings})
        for message, blob in list(messages):
            mtype = message.get('type')
            if mtype == 'error':
                description = message.get('description') or 'the Frida script raised an error'
                remember_warning(description)
                mark_entry_unavailable(description)
                continue
            if mtype != 'send':
                continue
            candidate = message.get('payload') or {}
            event = candidate.get('event')
            if event == 'hook-error':
                remember_warning(candidate.get('error'))
                continue
            if event == 'watch-scope':
                remember_warning(candidate.get('warning'))
                continue
            if event == 'exec-mark-duplicate':
                remember_warning('duplicate exec-mark: {0} ({1}) at {2} - the first mark stands'.format(
                    candidate.get('kind'), candidate.get('layer'), candidate.get('addr')))
                continue
            if event == 'exec-mark':
                if signal is None:
                    signal = candidate.get('signal')
                    watch_thread = candidate.get('watchThread')
                    watch_threads = candidate.get('watchThreads') or []
                    followed_count = candidate.get('followedCount') or 0
                continue
            if event == 'exec-entry':
                if exec_entry is None:
                    exec_entry = candidate
                    hit_thread = candidate.get('threadId')
                    if isinstance(hit_thread, int) and hit_thread > 0:
                        watch_thread = hit_thread
                continue
            if event in ('script-error', 'watch-error'):
                description = candidate.get('description') or candidate.get('error') or 'unknown script error'
                remember_warning(description)
                mark_entry_unavailable(description)
                continue
            if candidate.get('ok') and blob:
                payload, data = candidate, blob
                break
            if candidate.get('error'):
                payload = candidate
                break
        if payload is not None:
            break
        time.sleep(POLL_S)

    kill_child()

    if payload is None:
        emit({"error": "no dump before the timeout", "warnings": warnings})
    if payload.get('error'):
        emit({"error": payload['error'], "warnings": warnings})
    try:
        with open(out_path, 'wb') as handle:
            handle.write(data)
    except Exception as error:  # noqa: BLE001
        emit({"error": f"cannot write the raw image: {error}", "warnings": warnings})
    emit({"ok": True, "bytes": len(data), "base": payload.get('base'), "size": size, "delayMs": delay_ms,
          "oepSignal": signal, "execEntry": exec_entry, "entryWatch": entry_watch,
          "entryWatchReason": entry_watch_reason, "watchThread": watch_thread,
          "watchThreads": watch_threads, "followedCount": followed_count, "warnings": warnings})


if __name__ == '__main__':
    main()
