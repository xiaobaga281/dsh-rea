"""Opt-in Frida probe: run one sample, hook one function by RVA, dump a buffer.

The plugin reads bytes by default. This helper exists for the opt-in execution
path: it spawns the target under Frida, attaches to the function at

    module_base + rva

and, on function return, reads `length` bytes from the pointer passed in
argument `arg_index`. The dumped bytes are printed as one JSON line. The sample
executes, so the caller must have passed the explicit policy gate.

Usage:
    python probe.py <target> <rva-hex> <arg-index> <length> <timeout-ms> [--pid N] [--tid N]

Attach mode (--pid N): the target was already created suspended inside the
kernel sandbox (scripts/runtime/rea-sandbox.ps1 -Suspend). This helper attaches to the
existing pid, installs the hook before the first user-code instruction, then
resumes the suspended main thread via --tid with Win32 OpenThread/ResumeThread
(device.resume only covers Frida-spawned processes) and terminates the child
with TerminateProcess afterwards; the launcher's watchdog stays the backstop.

Output:
    {"hex": "...", "ascii": "...", "count": 1}
    {"error": "..."}
"""

import json
import sys
import time

import frida


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
        emit({"error": "usage: probe.py <target> <rva-hex> <arg-index> <length> <timeout-ms> [--pid N] [--tid N]"})
    target = sys.argv[1]
    attach_pid, attach_tid = parse_pid_tid(sys.argv[6:])
    try:
        rva = int(sys.argv[2], 16)
        arg_index = int(sys.argv[3])
        length = max(1, min(4096, int(sys.argv[4])))
        timeout_ms = max(1000, min(120000, int(sys.argv[5])))
    except ValueError:
        emit({"error": "rva, arg-index, length and timeout must be numbers"})

    source = """
    const module = Process.enumerateModules()[0];
    const address = module.base.add(RVA);
    let hits = 0;
    try {
      Interceptor.attach(address, {
        onEnter(args) {
          this.buffer = args[ARG_INDEX];
        },
        onLeave() {
          hits += 1;
          try {
            const pointer = this.buffer;
            const bytes = new Uint8Array(pointer.readByteArray(LENGTH));
            let hex = '';
            let ascii = '';
            for (const byte of bytes) {
              hex += byte.toString(16).padStart(2, '0');
              ascii += (byte >= 32 && byte < 127) ? String.fromCharCode(byte) : '.';
            }
            send({ hex, ascii, count: hits, module: module.name });
          } catch (error) {
            send({ error: String(error), count: hits });
          }
        }
      });
      send({ ready: true, module: module.name, address: address.toString() });
    } catch (error) {
      send({ error: 'attach failed: ' + String(error) });
    }
    """.replace('RVA', hex(rva)).replace('ARG_INDEX', str(arg_index)).replace('LENGTH', str(length))

    messages = []
    try:
        device = frida.get_local_device()
        if attach_pid:
            pid = attach_pid
            session = device.attach(pid)
            script = session.create_script(source)
            script.on('message', lambda message, data: messages.append(message))
            script.load()
            if attach_tid and not resume_thread(attach_tid):
                emit({"error": f"cannot resume the sandbox child's main thread (tid={attach_tid})"})
        else:
            pid = device.spawn([target])
            session = device.attach(pid)
            script = session.create_script(source)
            script.on('message', lambda message, data: messages.append(message))
            script.load()
            device.resume(pid)
    except Exception as error:  # noqa: BLE001 - the probe reports the reason
        emit({"error": f"spawn/attach failed: {error}"})

    deadline = time.time() + timeout_ms / 1000.0
    result = None
    while time.time() < deadline:
        for message in list(messages):
            payload = message.get('payload') if message.get('type') == 'send' else None
            if isinstance(payload, dict) and ('hex' in payload or 'error' in payload):
                result = payload
                break
        if result is not None:
            break
        time.sleep(0.05)
    try:
        if attach_pid:
            # Plain TerminateProcess: session.detach() against a terminated
            # container child's agent can hang (measured), and the answer must
            # go out first - the caller reaps this helper once it sees the
            # answer line. Process exit closes the session either way.
            terminate_process(pid)
        else:
            device.kill(pid)
            session.detach()
    except Exception:  # noqa: BLE001 - cleanup is best effort
        pass
    if result is None:
        emit({"error": "no hit before the timeout", "messages": len(messages)})
    emit(result)


if __name__ == '__main__':
    main()
