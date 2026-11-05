/**
 * What the plugin remembers about its engines.
 *
 * `providerReadiness()` answers a question about files: is there a Ghidra
 * directory, is there a JDK new enough. That answer was correct and useless at
 * the same time - on this machine a launch dies inside Ghidra's JVM with
 * "Failed to create directory: ...\tmp\<user>-ghidra", and the panel still said
 * "ready" because every file was in place.
 *
 * Readiness is a claim. This module is the evidence ledger behind it: every
 * provider failure observed in this session is recorded with a short code and a
 * timestamp, and readiness is downgraded until the child restarts. Successes are
 * not recorded, because a REA success payload does not name the provider - and
 * an invented success is worse than a missing one.
 *
 * In-memory on purpose. A persisted failure would outlive the fix that resolved
 * it, and a stale red light is the same lie as a stale green one.
 *
 * @module dsh-rea/lib/engine-health
 */

/** provider -> { at, code, reason, message } */
const failures = new Map();

/**
 * Compress an upstream failure into something a person can act on.
 *
 * The raw message for a failed Ghidra launch is 1.5 KB of Java stack trace. The
 * report cannot carry that, and it does not need to: three of these signatures
 * cover every launch failure this plugin has actually seen.
 */
export function classifyEngineFailure(message) {
  const text = String(message ?? '');
  // REA's Windows private runtime lets the owning process create directories
  // but not the child JVM. Ghidra asks for four separate locations, and the
  // failure moves to the next one as each is fixed - so name the one that
  // actually failed instead of reporting "a directory problem".
  const scratch = /Failed to create directory:.*[\\/](tmp|cache|config)[\\/][^\r\n]*$/im.exec(text);
  if (scratch) {
    const where = scratch[1].toLowerCase();
    return {
      code: 'jvm-scratch-denied',
      directory: where,
      reason: `Ghidra 的 JVM 无法在 REA 的私有运行目录里创建 ${where}/<user>-ghidra（上游 Windows 限制；不是 JDK 版本或安装问题）`,
    };
  }
  if (/Failed to create directory/i.test(text)) {
    return { code: 'jvm-scratch-denied', directory: 'unknown', reason: 'Ghidra 无法创建运行时目录；检查临时目录权限' };
  }
  if (/Unable to create file .*(?:ghidra|script)\.log/i.test(text)) {
    return {
      code: 'jvm-log-denied',
      directory: 'log',
      reason: 'Ghidra 无法把 ghidra.log / script.log 写进 REA 的私有运行目录（REA 用 -log 指定该路径，JVM 无写权限）',
    };
  }
  // The last gate, and the one no launch.properties can move: REA passes
  // -projectPath inside the same private runtime, and Ghidra has to create the
  // .gpr/.rep there before it can import anything.
  if (/DefaultProjectData\.init|DefaultProjectManager\.createProject|HeadlessAnalyzer\.processLocal/i.test(text)) {
    return {
      code: 'project-dir-denied',
      directory: 'project',
      reason: 'Ghidra 无法在 REA 的私有项目目录里创建 .gpr/.rep（-projectPath 由 REA 指定，JVM 无写权限；这一层无法用 launch.properties 绕过）',
    };
  }
  if (/java_home|JDK 21|jdk 21|could not be found and must be manually chosen/i.test(text)) {
    return { code: 'jdk', reason: 'Ghidra 找不到可用的 JDK 21+；在面板里填写完整 JDK 的 JAVA_HOME' };
  }
  if (/timed out|startup timeout|deadline exceeded/i.test(text)) {
    return { code: 'timeout', reason: '引擎启动超时；首次分析大文件时常见，可重试一次' };
  }
  if (/ERR_REA_WINDOWS_NATIVE/.test(text)) {
    return { code: 'native-unsupported', reason: 'REA 的 Windows 私有运行时不可用，该 provider 在此主机上不受支持' };
  }
  const first = text.replace(/^Error:\s*/, '').split(/\r?\n/)[0] ?? '';
  return { code: 'unknown', reason: first.length > 160 ? `${first.slice(0, 157)}…` : first || '未知错误' };
}

/** Record one failure. Repeated failures keep the first timestamp and the latest code. */
export function recordEngineFailure(provider, message, { now = new Date() } = {}) {
  const key = String(provider ?? '').toLowerCase();
  if (key.length === 0) return null;
  const classified = classifyEngineFailure(message);
  const previous = failures.get(key);
  const record = {
    at: previous?.at ?? now.toISOString(),
    lastAt: now.toISOString(),
    count: (previous?.count ?? 0) + 1,
    ...classified,
  };
  failures.set(key, record);
  return record;
}

export function engineHealth(provider) {
  return failures.get(String(provider ?? '').toLowerCase()) ?? null;
}

export function clearEngineHealth(provider) {
  if (provider === undefined) failures.clear();
  else failures.delete(String(provider).toLowerCase());
}

/** Test seam: the ledger is process-global, so a test must be able to empty it. */
export function resetEngineHealth() {
  failures.clear();
}

/**
 * Pull a provider id out of an upstream error message.
 *
 * REA returns its failures as a JSON envelope in the message text, and the
 * provider is only in `details.provider_id`. A tool that fails for a non-engine
 * reason simply has no id here, and is not recorded.
 */
export function providerFromError(message) {
  const match = /"provider_id"\s*:\s*"([a-z0-9_-]+)"/i.exec(String(message ?? ''));
  return match ? match[1].toLowerCase() : null;
}
