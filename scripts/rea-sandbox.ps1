<#
rea-sandbox.ps1 - start a process inside a no-VM, kernel-enforced sandbox.

Container: an AppContainer token (S-1-15-2-... SID derived from the container
name by the OS via CreateAppContainerProfile) with an EMPTY capability list
(no internetClient, no anything). On this OS build (Win11 26300) the
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES route is rejected by
UpdateProcThreadAttribute (ERROR_BAD_LENGTH at every cbSize), so the token is
built explicitly: DuplicateTokenEx(primary token) -> NtCreateLowBoxToken ->
CreateProcessAsUserW. Verified: child reports TokenIsAppContainer=1 and
integrity level 0x1000 (Low).

Job: KILL_ON_JOB_CLOSE (LimitFlags is assigned explicitly before
SetInformationJobObject) ; explicit and silent breakaway are NOT permitted (the
flags are simply not set), so the child and all descendants stay in the job.
The child is ALWAYS created CREATE_SUSPENDED, then assigned to the job, and
only then resumed - the job assignment lands before the first instruction, so
no descendant can escape the window. The launcher holds the job handle for the
child's whole lifetime, and before closing it terminates the job if any
process is still inside (orphan descendants - the wait only covers the direct
child). ERRATA 2026-11-20: the launcher previously passed a zero-initialised
JOBOBJECT_EXTENDED_LIMIT_INFORMATION, so KILL_ON_JOB_CLOSE was never actually
enabled and the "killing the launcher externally does not reliably terminate
the job's processes" record (measured 2026-11-19) described a mechanism that
did not exist - a launcher bug, not OS behaviour. With the flag set, an
external launcher kill is measured to reap the job tree within the 5 s
assertion window (test/sandbox.test.js "killing the launcher externally",
2026-11-20). The -TimeoutMs watchdog (TerminateJobObject inside the launcher)
and the caller's taskkill /PID <child> /T fallback remain the primary cleanup
paths.

Environment: neutral identity (matches lib/trace.js IDENTITY_MASK values) plus
the TEMP/APPDATA/HOME redirection trace.js applies, pointed at
<WorkDir>\profile\* so the child's writes land in the run directory.

File access: an AppContainer can only open objects whose DACL grants access to
ALL APPLICATION PACKAGES (S-1-15-2-1) or to its own package SID, and its low
integrity level blocks writes to medium-IL objects. The launcher therefore
grants RX on the executable, Modify on the work directory, and sets the work
directory integrity level to Low.

Network: with no capabilities, the container's outbound TCP is kernel-denied
(WSAEACCES 10013 at 0 ms for 192.0.2.1:9, measured 2026-11-19; host-normal
contrast is a 21 s WSAETIMEDOUT). Loopback is ALSO denied by default (measured:
::1 to a live listener silently drops, 21 s timeout, listener accepts nothing).
The launcher attempts this profile's CheckNetIsolation loopback exemption,
which would restore ::1/127.0.0.1 - but the add is administrator-only on this
build (measured err=5 for a non-admin caller), so on a non-admin host loopback
stays blocked and a warn= line lands in the diagnostics. UDP sendto is NOT
blocked by this isolation on this build (measured: sendto to 192.0.2.1 reports
success) - that blind spot is stated, not hidden.

GUI: the default desktop's DACL does not admit a profile-derived package SID
(user32 init fails with 0xC0000602), so -Desktop creates a dedicated desktop
whose DACL admits the package SID, ALL APPLICATION PACKAGES and this user.

FAIL-CLOSED: a launch-phase failure (bad path, profile/token/job/desktop
creation error, CreateProcess error, OR a job-assignment failure) exits
non-zero with an "error=..." line in the diagnostics and never starts the
sample; callers must treat that as "the sample did NOT run" and report it,
never fall back to an unsandboxed spawn. An assign-job failure is fail-closed
too (since 2026-11-20): the child was created suspended and has executed no
sample instruction, so the launcher terminates it before any ResumeThread and
exits non-zero - there is no token-only degraded-but-ran outcome. A child that
DID start (job enforced) is not an error even when it exits non-zero or is
terminated by the -TimeoutMs watchdog: those are results (exitCode /
timedOut), classified by the diagnostics contract below.

Diagnostics contract: every diagnostics line has the prefix "rea-sandbox: "
followed by key=value pairs. Launch markers: container-sid=<sid>,
job-handle=0x<hex>, job-limit-flags=<hex> (the limits READ BACK from the OS
job after SetInformationJobObject - expected 0x2000, KILL_ON_JOB_CLOSE),
desktop=<name>, job-enforced=true|false, pid=<n> tid=<n>,
child-exit=<n>, timeout=<ms> action=terminate-job, optional
action=terminate-job reason=orphan-descendants processes=<n|unknown> (a
descendant was still living when the direct child exited) and
action=terminate-process reason=assign-failed fail-closed=true. Launch-phase
failures use error=<what> (err=/hr=/nt= detail). Warnings use warn=<what>
msg=.... A run that produced pid= and child-exit= with job-enforced=true ran
the sample; a run without pid=, with error= before pid=, or with
job-enforced=false did not. Diagnostics go to -DiagFile when given (keeps the
child's stdout/stderr clean for trace comparison), otherwise to stderr.

PID handoff: the child PID is written to -OutPid (one decimal number) and the
"pid=<n> tid=<n>" line goes to the diagnostics sink, so a caller (node or
python) can attach Frida to the child and resume its main thread.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/rea-sandbox.ps1 `
    -Executable <path> [-Arguments "args"] [-WorkDir <dir>] [-OutPid <file>] `
    [-DiagFile <file>] [-TimeoutMs <ms>] [-Suspend] [-NoMask] [-NoContainer] [-Desktop]

Switches:
  -TimeoutMs    kill the whole job (TerminateJobObject) if the child runs
                longer than this; 0 (default) waits forever. This stays the
                primary in-launcher enforcement path, so callers should keep
                the launcher alive for the child's whole lifetime; since the
                2026-11-20 LimitFlags fix, KILL_ON_JOB_CLOSE is an additional
                kernel-side net (see the Job paragraph errata) rather than an
                untested hope.
  -Suspend      leave the child's main thread suspended (Frida-style: the
                caller resumes via the tid from the diagnostics)
  -NoMask       do not rewrite COMPUTERNAME/USERNAME/... in the child env
  -NoContainer  ablation mode: keep job + env + ACLs but drop the AppContainer
                token, to isolate what the container itself denies
  -Desktop      run the child on a dedicated, per-run desktop
#>
param(
  [Parameter(Mandatory = $true)] [string]$Executable,
  [string]$Arguments = '',
  [string]$WorkDir = '',
  [string]$OutPid = '',
  [string]$DiagFile = '',
  [string]$TimeoutMs = '0',
  [switch]$Suspend,
  [switch]$NoMask,
  [switch]$NoContainer,
  [switch]$Desktop
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Executable)) {
  Write-Error "rea-sandbox: executable not found: $Executable"
  exit 2
}
$exePath = (Resolve-Path -LiteralPath $Executable).Path
if ($WorkDir -eq '') { $WorkDir = Split-Path -Parent $exePath }
[void](New-Item -ItemType Directory -Force -Path $WorkDir)
$workDirFull = (Resolve-Path -LiteralPath $WorkDir).Path

$source = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Rea {
public static class Sandbox {
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFOW {
    public uint cb;
    public string lpReserved; public string lpDesktop; public string lpTitle;
    public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
    public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags;
    public ushort wShowWindow; public ushort cbReserved2; public IntPtr lpReserved2;
    public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
    public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct IO_COUNTERS {
    public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
    public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
  }

  [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr sid);
  [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern int DeleteAppContainerProfile(string name);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CreateProcessW(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFOW startupInfo, out PROCESS_INFORMATION processInformation);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attrs, int level, int type, out IntPtr dup);
  [DllImport("ntdll.dll")]
  public static extern int NtCreateLowBoxToken(out IntPtr token, IntPtr existing, uint access, IntPtr objAttributes, IntPtr packageSid, uint capabilityCount, IntPtr capabilities, uint handleCount, IntPtr handles);
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, uint len, out uint retLen);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);
  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_ATTRIBUTES { public uint nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr CreateDesktopW(string name, string device, IntPtr deviceMode, uint flags, uint access, ref SECURITY_ATTRIBUTES sa);
  [DllImport("user32.dll", SetLastError = true)]
  public static extern bool CloseDesktop(IntPtr h);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint size);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint size, out uint returnLength);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool TerminateJobObject(IntPtr job, int exitCode);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool TerminateProcess(IntPtr process, int exitCode);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool SetHandleInformation(IntPtr obj, uint mask, uint flags);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr GetStdHandle(int which);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern uint ResumeThread(IntPtr thread);

  const uint CREATE_SUSPENDED = 0x00000004;
  const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
  const uint STARTF_USESTDHANDLES = 0x00000100;
  const int JobObjectExtendedLimitInformation = 9;
  const int JobObjectBasicProcessIdList = 3;
  const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
  const uint HANDLE_FLAG_INHERIT = 0x00000001;

  static System.IO.StreamWriter diag = null;
  static void Diag(string line) {
    if (diag != null) { diag.WriteLine(line); diag.Flush(); }
    else Console.Error.WriteLine(line);
  }

  static Dictionary<string, string> BuildEnv(string workDir, bool mask) {
    Dictionary<string, string> env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (DictionaryEntry e in Environment.GetEnvironmentVariables()) env[(string)e.Key] = (string)e.Value;
    string temp = System.IO.Path.Combine(workDir, "profile", "temp");
    string appdata = System.IO.Path.Combine(workDir, "profile", "appdata");
    string local = System.IO.Path.Combine(workDir, "profile", "localappdata");
    string home = System.IO.Path.Combine(workDir, "profile", "home");
    System.IO.Directory.CreateDirectory(temp);
    System.IO.Directory.CreateDirectory(appdata);
    System.IO.Directory.CreateDirectory(local);
    System.IO.Directory.CreateDirectory(home);
    env["TEMP"] = temp; env["TMP"] = temp;
    env["APPDATA"] = appdata; env["LOCALAPPDATA"] = local;
    env["USERPROFILE"] = home; env["HOME"] = home;
    if (mask) {
      env["COMPUTERNAME"] = "rea-sandbox";
      env["USERNAME"] = "analyst";
      env["USERDOMAIN"] = "REAGROUP";
      env["HOMEDRIVE"] = "C:";
      env["HOMEPATH"] = "\\Users\\analyst";
    }
    return env;
  }

  static IntPtr BuildEnvironmentBlock(Dictionary<string, string> env) {
    List<string> keys = new List<string>(env.Keys);
    keys.Sort(StringComparer.OrdinalIgnoreCase);
    StringBuilder sb = new StringBuilder();
    foreach (string k in keys) sb.Append(k).Append('=').Append(env[k]).Append('\0');
    sb.Append('\0');
    return Marshal.StringToHGlobalUni(sb.ToString());
  }

  // An AppContainer token only opens objects whose DACL grants access to
  // ALL APPLICATION PACKAGES (S-1-15-2-1) or to the package SID itself.
  static void GrantDacl(string path, string packageSid, string rights, bool directory) {
    string[] sids = new string[] { "S-1-15-2-1", packageSid };
    System.Security.AccessControl.FileSystemRights right =
      (System.Security.AccessControl.FileSystemRights)System.Enum.Parse(typeof(System.Security.AccessControl.FileSystemRights), rights);
    if (directory) {
      System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(path);
      System.Security.AccessControl.DirectorySecurity acl = di.GetAccessControl();
      foreach (string s in sids) {
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
          new System.Security.Principal.SecurityIdentifier(s), right,
          System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
          System.Security.AccessControl.PropagationFlags.None,
          System.Security.AccessControl.AccessControlType.Allow));
      }
      di.SetAccessControl(acl);
    } else {
      System.IO.FileInfo fi = new System.IO.FileInfo(path);
      System.Security.AccessControl.FileSecurity acl = fi.GetAccessControl();
      foreach (string s in sids) {
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
          new System.Security.Principal.SecurityIdentifier(s), right,
          System.Security.AccessControl.AccessControlType.Allow));
      }
      fi.SetAccessControl(acl);
    }
  }

  // Low integrity on the work directory so the low-IL container child may
  // write there (NoWriteUp would otherwise deny writes to medium-IL files).
  static void SetLowIntegrity(string path) {
    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
    psi.FileName = Environment.ExpandEnvironmentVariables("%SystemRoot%\\System32\\icacls.exe");
    psi.Arguments = "\"" + path + "\" /setintegritylevel (CI)(OI)L";
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi);
    p.WaitForExit(5000);
  }

  // Loopback parity with the documented observer policy (loopback allowed,
  // everything else denied). A no-capability AppContainer denies ALL outbound
  // including loopback: measured 2026-11-19, ::1 to a LIVE listener silently
  // drops the SYN (blocking connect 21 s -> WSAETIMEDOUT 10060, listener
  // accepts nothing) while host-normal connects in 0 ms. The per-profile
  // loopback exemption restores ::1/127.0.0.1 while every non-loopback
  // destination stays kernel-denied (192.0.2.1:9 -> WSAEACCES 10013 at 0 ms,
  // measured). The exemption is keyed to this profile's SID and dies with the
  // profile at launcher exit. Output is redirected: the launcher's stdout IS
  // the child's stdout in trace mode.
  static void GrantLoopbackExemption(string packageSid, System.Action<string> warn) {
    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
    psi.FileName = Environment.ExpandEnvironmentVariables("%SystemRoot%\\System32\\CheckNetIsolation.exe");
    psi.Arguments = "LoopbackExempt -a -p=" + packageSid;
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi);
    p.WaitForExit(5000);
    // The add is administrator-only on this build (measured: err=5 for a
    // non-admin caller). Without it the container blocks loopback too - a
    // stated limitation, not a silent one.
    if (p.ExitCode != 0) warn("loopback-exempt exit=" + p.ExitCode + " (administrator required; loopback stays blocked)");
  }

  // How many processes are still living in the job right now. Returns -1 when
  // the query itself fails; the caller then degrades to an unconditional
  // terminate (containment never depends on the query succeeding).
  static int CountJobProcesses(IntPtr job) {
    IntPtr buf = Marshal.AllocHGlobal(4096);
    try {
      uint returnLength;
      if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buf, 4096, out returnLength)) return -1;
      return Marshal.ReadInt32(buf, 4); // NumberOfProcessIdsInList
    } finally { Marshal.FreeHGlobal(buf); }
  }

  public static int Run(string exe, string args, string workDir, string outPidPath, bool suspend, bool mask, bool noContainer, bool useDesktop, string diagFile, int timeoutMs) {
    if (diagFile != null && diagFile.Length > 0) diag = new System.IO.StreamWriter(diagFile, false, new System.Text.UTF8Encoding(false));
    // Per-run unique names: concurrent launchers never share a profile or desktop.
    string containerName = "dsh.rea.sb." + System.Diagnostics.Process.GetCurrentProcess().Id + "." + Environment.TickCount;
    string desktopName = "rea-sb-" + System.Diagnostics.Process.GetCurrentProcess().Id + "-" + Environment.TickCount;
    IntPtr sid = IntPtr.Zero;
    if (!noContainer) {
      int hr = CreateAppContainerProfile(containerName, "dsh-rea sandbox", "dsh-rea sample execution container", IntPtr.Zero, 0, out sid);
      if (hr != 0) {
        Diag("rea-sandbox: warn=create-appcontainer-profile-retry hr=0x" + hr.ToString("X8"));
        try { DeleteAppContainerProfile(containerName); } catch {}
        hr = CreateAppContainerProfile(containerName, "dsh-rea sandbox", "dsh-rea sample execution container", IntPtr.Zero, 0, out sid);
        if (hr != 0) { Diag("rea-sandbox: error=create-appcontainer-profile hr=0x" + hr.ToString("X8")); return 3; }
      }
      Diag("rea-sandbox: container-sid=" + new System.Security.Principal.SecurityIdentifier(sid).Value);
      try { GrantLoopbackExemption(new System.Security.Principal.SecurityIdentifier(sid).Value, (msg) => Diag("rea-sandbox: warn=" + msg)); } catch (Exception ex) { Diag("rea-sandbox: warn=loopback-exempt msg=" + ex.Message); }
    }
    IntPtr desktop = IntPtr.Zero;
    IntPtr dup = IntPtr.Zero;
    IntPtr lowbox = IntPtr.Zero;
    try {
      string sidString = sid == IntPtr.Zero ? "S-1-15-2-1" : new System.Security.Principal.SecurityIdentifier(sid).Value;
      try { GrantDacl(workDir, sidString, "Modify", true); } catch (Exception ex) { Diag("rea-sandbox: warn=grant-dacl-workdir msg=" + ex.Message); }
      try { GrantDacl(exe, sidString, "ReadAndExecute", false); } catch (Exception ex) { Diag("rea-sandbox: warn=grant-dacl-exe msg=" + ex.Message); }
      try { SetLowIntegrity(workDir); } catch (Exception ex) { Diag("rea-sandbox: warn=set-low-integrity msg=" + ex.Message); }

      // GUI support: a dedicated desktop whose DACL admits the container SID,
      // ALL APPLICATION PACKAGES and this user. The default desktop's ACL does
      // not admit a profile-derived package SID, so user32 init fails with
      // 0xC0000602 (the measured value on this build; not 0xC0000142) without
      // this.
      if (useDesktop) {
        string userSid = "";
        IntPtr hTok2 = IntPtr.Zero;
        if (OpenProcessToken(GetCurrentProcess(), 0x00000008, out hTok2)) {
          IntPtr buf = Marshal.AllocHGlobal(72);
          uint rl;
          if (GetTokenInformation(hTok2, 1, buf, 72, out rl)) {
            IntPtr sidPtr = Marshal.ReadIntPtr(buf);
            IntPtr s;
            if (ConvertSidToStringSidW(sidPtr, out s)) userSid = Marshal.PtrToStringUni(s);
          }
          Marshal.FreeHGlobal(buf);
          CloseHandle(hTok2);
        }
        string sddl = "D:(A;;GA;;;" + sidString + ")(A;;GA;;;S-1-15-2-1)";
        if (userSid.Length > 0) sddl += "(A;;GA;;;" + userSid + ")";
        IntPtr sd;
        uint sdSize;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out sdSize)) {
          Diag("rea-sandbox: error=sddl err=" + Marshal.GetLastWin32Error());
          return 4;
        }
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = false;
        desktop = CreateDesktopW(desktopName, null, IntPtr.Zero, 0, 0x000001FF, ref sa);
        if (desktop == IntPtr.Zero) {
          Diag("rea-sandbox: error=create-desktop err=" + Marshal.GetLastWin32Error());
          return 4;
        }
        Diag("rea-sandbox: desktop=" + desktopName);
      }

      IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
      // Keep the job handle NON-inheritable. CreateProcessAsUserW below is
      // called with bInheritHandles=true (stdio redirection), so any
      // inheritable handle in this process reaches the whole sample tree - an
      // inherited job handle would let a job member keep the job object alive
      // past this launcher's death and silence KILL_ON_JOB_CLOSE (measured in
      // the 2026-11-20 job-semantics A/B repro: flags=0x2000 with an
      // inheritable handle left the orphan alive to its own natural exit,
      // while flags=0x2000 alone reaped it in 128 ms). CreateJobObjectW with
      // NULL attributes already returns a non-inheritable handle; this call
      // makes the invariant explicit and refactor-proof. Best-effort: a
      // failure is a warn, not a launch failure (the construction above
      // already guarantees the default).
      if (!SetHandleInformation(job, HANDLE_FLAG_INHERIT, 0)) {
        Diag("rea-sandbox: warn=set-handle-information err=" + Marshal.GetLastWin32Error());
      }
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      // KILL_ON_JOB_CLOSE must be ASSIGNED here - the struct is zero-initialised,
      // and a pre-2026-11-20 build passed it unchanged, so the flag was never
      // enabled and the "unreliable on this OS build" narrative measured a
      // mechanism that did not exist (errata 2026-11-20, see the header).
      // BREAKAWAY_OK and SILENT_BREAKAWAY_OK stay unset, so the child and every
      // descendant are locked in this job.
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))) {
        Diag("rea-sandbox: error=set-job-limits err=" + Marshal.GetLastWin32Error());
        return 4;
      }
      Diag("rea-sandbox: job-handle=0x" + job.ToString("x"));
      // In-situ proof the OS actually holds the flag (the 2026-11-19
      // "KILL_ON_JOB_CLOSE unreliable" narrative existed because a
      // zero-initialised limit struct was passed unchecked, so nobody ever
      // read back what the job really carried): query the limits and print
      // them. Expected 0x2000 (KILL_ON_JOB_CLOSE); tests pin this line.
      {
        IntPtr qbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
        try {
          uint qret;
          if (QueryInformationJobObject(job, JobObjectExtendedLimitInformation, qbuf, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)), out qret)) {
            Diag("rea-sandbox: job-limit-flags=0x" + Marshal.ReadInt32(qbuf, 16).ToString("x4"));
          } else {
            Diag("rea-sandbox: warn=query-job-limits err=" + Marshal.GetLastWin32Error());
          }
        } finally { Marshal.FreeHGlobal(qbuf); }
      }

      // Build the AppContainer token explicitly (see header comment).
      if (!noContainer) {
        IntPtr hTok = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), 0x000F01FF, out hTok)) {
          Diag("rea-sandbox: error=open-process-token err=" + Marshal.GetLastWin32Error());
          return 4;
        }
        bool dupOk = DuplicateTokenEx(hTok, 0x000F01FF, IntPtr.Zero, 2, 1, out dup);
        CloseHandle(hTok);
        if (!dupOk) {
          Diag("rea-sandbox: error=duplicate-token err=" + Marshal.GetLastWin32Error());
          return 4;
        }
        int nt = NtCreateLowBoxToken(out lowbox, dup, 0x000F01FF, IntPtr.Zero, sid, 0, IntPtr.Zero, 0, IntPtr.Zero);
        if (nt != 0) {
          Diag("rea-sandbox: error=ntcreate-lowbox nt=0x" + nt.ToString("X8"));
          return 4;
        }
      }

      IntPtr envPtr = BuildEnvironmentBlock(BuildEnv(workDir, mask));

      // Always create CREATE_SUSPENDED so the job assignment lands before the
      // child's first instruction; the caller's -Suspend only decides who
      // resumes the main thread.
      uint flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
      string commandLine = "\"" + exe + "\"" + (args == null || args.Length == 0 ? "" : " " + args);
      PROCESS_INFORMATION pi;
      bool created;
      if (noContainer) {
        STARTUPINFOW si = new STARTUPINFOW();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(-10);
        si.hStdOutput = GetStdHandle(-11);
        si.hStdError = GetStdHandle(-12);
        si.lpDesktop = useDesktop ? desktopName : null;
        created = CreateProcessW(exe, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags, envPtr, workDir, ref si, out pi);
      } else {
        STARTUPINFOW si = new STARTUPINFOW();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(-10);
        si.hStdOutput = GetStdHandle(-11);
        si.hStdError = GetStdHandle(-12);
        si.lpDesktop = useDesktop ? desktopName : null;
        created = CreateProcessAsUserW(lowbox, exe, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags, envPtr, workDir, ref si, out pi);
      }
      if (!created) {
        Diag("rea-sandbox: error=create-process err=" + Marshal.GetLastWin32Error());
        return 5;
      }
      Diag("rea-sandbox: pid=" + pi.dwProcessId + " tid=" + pi.dwThreadId);
      if (outPidPath != null && outPidPath.Length > 0) System.IO.File.WriteAllText(outPidPath, pi.dwProcessId.ToString());
      // Job first, resume second: no instruction runs outside the job.
      // FAIL-CLOSED: a job-assignment failure is a launch failure, not a
      // degraded-but-ran result - the child was created suspended and has not
      // executed a single sample instruction, so it is terminated here (before
      // any ResumeThread) and the run reports "the sample did NOT run".
      // Callers classify job-enforced=false as ran=false (lib/sandbox.js).
      if (!AssignProcessToJobObject(job, pi.hProcess)) {
        Diag("rea-sandbox: error=assign-job err=" + Marshal.GetLastWin32Error());
        Diag("rea-sandbox: job-enforced=false");
        Diag("rea-sandbox: action=terminate-process reason=assign-failed fail-closed=true");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 6;
      } else {
        Diag("rea-sandbox: job-enforced=true");
      }
      if (!suspend) ResumeThread(pi.hThread);
      CloseHandle(pi.hThread);
      uint waitMs = timeoutMs > 0 ? (uint)timeoutMs : 0xFFFFFFFF;
      uint waitResult = WaitForSingleObject(pi.hProcess, waitMs);
      if (waitResult == 0x00000102) {
        // Timeout watchdog: terminate the whole job (child + descendants). The
        // KILL_ON_JOB_CLOSE flag is now actually set (errata 2026-11-20: the
        // pre-fix launcher never assigned LimitFlags, so the external-kill
        // unreliability measured that day described a disabled mechanism), but
        // the timeout stays the primary in-launcher enforcement path.
        Diag("rea-sandbox: timeout=" + timeoutMs + " action=terminate-job");
        TerminateJobObject(job, 1);
        WaitForSingleObject(pi.hProcess, 5000);
      }
      uint exitCode = 0;
      GetExitCodeProcess(pi.hProcess, out exitCode);
      // Orphan containment: the wait only covered the DIRECT child. If the
      // child died first, descendants may still be living in the job - without
      // this close of the last job handle would only trigger KILL_ON_JOB_CLOSE
      // if every other handle is gone, and a harness crash could leave the
      // orphan running unmanaged. Kill the job explicitly, AFTER the exit code
      // is read (TerminateJobObject's code must not pollute the reported one),
      // and only on the normal wait-return path: the timeout terminate above
      // already covered the whole job.
      if (waitResult != 0x00000102) {
        int orphans = CountJobProcesses(job);
        if (orphans != 0) {
          Diag("rea-sandbox: action=terminate-job reason=orphan-descendants processes=" + (orphans > 0 ? orphans.ToString() : "unknown"));
          TerminateJobObject(job, 1);
        }
      }
      CloseHandle(pi.hProcess);
      CloseHandle(job);
      Diag("rea-sandbox: child-exit=" + exitCode);
      // Bit-preserving exit code: 0xC0000142 stays 0xC0000142 (as a negative
      // int) instead of being masked into a fake small success-looking code.
      return unchecked((int)exitCode);
    } finally {
      if (lowbox != IntPtr.Zero) CloseHandle(lowbox);
      if (dup != IntPtr.Zero) CloseHandle(dup);
      if (desktop != IntPtr.Zero) CloseDesktop(desktop);
      if (!noContainer) { try { DeleteAppContainerProfile(containerName); } catch {} }
      if (diag != null) { diag.Flush(); diag.Dispose(); diag = null; }
    }
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CreateProcessAsUserW(IntPtr token, string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFOW startupInfo, out PROCESS_INFORMATION processInformation);
}
}
'@

Add-Type -TypeDefinition $source -Language CSharp
$code = [Rea.Sandbox]::Run($exePath, $Arguments, $workDirFull, $OutPid, [bool]$Suspend, [bool](-not $NoMask), [bool]$NoContainer, [bool]$Desktop, $DiagFile, [int]$TimeoutMs)
exit $code
