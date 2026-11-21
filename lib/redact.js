/**
 * Reversible redaction of this host's identity from tool output text.
 *
 * Tool output is read by a model that may be logging to a third party, and the
 * plugin's own render paths are full of absolute paths: the artifact store, the
 * run directories, the state sidecars and the work-root candidates all sit under
 * the user's home, and the side-effect observer even prints the machine's own
 * hostname (a `gethostname` → `getaddrinfo` probe shows up as a DNS event).
 * This module replaces exactly three identity strings - the hostname, the
 * account name and the home directory prefix - with stable placeholders, so the
 * rendering paths can stay readable without naming the analyst's machine.
 *
 * Redaction is deliberately *not* a C:\\Users\\* wildcard: a sample's own PDB
 * path (C:\\Users\\builder\\x.pdb), another account's directory or any other
 * embedded path is evidence and must survive verbatim. Only the exact strings
 * observed on this host are replaced, whole-token and case-insensitive, with
 * separators normalised for the home prefix so `/` and `\` both match.
 *
 * Every placeholder is reversible in-session: `restore` maps the placeholders
 * back to the real values, which is what keeps functional handles working after
 * the model copies a redacted artifact path out of a rendered report. Restore
 * runs *before* every scope/inside() check, so authorisation always sees the
 * real path. A placeholder written somewhere this session cannot reach (an
 * external file) simply stops restoring - such handles are session-scoped by
 * design, and that is stated in the limitations rather than papered over.
 *
 * @module dsh-rea/lib/redact
 */

import { homedir, hostname, userInfo } from 'node:os';

export const HOSTNAME_PLACEHOLDER = '[HOSTNAME]';
export const USERNAME_PLACEHOLDER = '[USERNAME]';
export const USERPROFILE_PLACEHOLDER = '[USERPROFILE]';

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Whole-token match: the character before/after must not extend the token.
 * `desktop-1` matches in "dns:resolve desktop-1" and in an FQDN
 * ("desktop-1.corp" → "[HOSTNAME].corp") but not inside "mydesktop-12".
 */
function tokenRegex(value) {
  return new RegExp(`(?<![A-Za-z0-9_])${escapeRegExp(value)}(?![A-Za-z0-9_])`, 'gi');
}

/**
 * Home-directory prefix: same string with `/` and `\` treated as equivalent,
 * so `C:\Users\alice`, `c:/users/alice` and mixed forms all collapse to
 * `[USERPROFILE]`. A trailing alphanumeric is excluded so `C:\Users\alice2`
 * (a different account) is never eaten.
 */
function homeRegex(homePath) {
  const parts = String(homePath).split(/[\\/]+/).filter((part) => part.length > 0).map(escapeRegExp);
  if (parts.length === 0) return null;
  return new RegExp(`${parts.join('[\\\\/]+')}(?![A-Za-z0-9])`, 'gi');
}

function safeUserName() {
  try {
    const name = userInfo().username;
    return typeof name === 'string' && name.length > 0 ? name : null;
  } catch {
    return null;
  }
}

/**
 * Build one redactor. All three identities are optional; an empty host (bare
 * containers) simply yields fewer rules. `hostname`/`username`/`homePath` are
 * injectable so tests can be hermetic instead of depending on the real box.
 */
export function createRedactor({ hostname: host, username, homePath } = {}) {
  // An explicitly empty string disables that rule (bare containers); only a
  // missing option falls back to the real host value.
  const pick = (value, fallback) => (value === undefined || value === null ? fallback : String(value));
  const hostName = pick(host, hostname());
  const userName = pick(username, safeUserName());
  const home = pick(homePath, homedir());

  // Longest / most specific first: the home prefix contains the username, so it
  // must win over the bare token, and both are applied before the hostname.
  const rules = [];
  const homePattern = home ? homeRegex(home) : null;
  if (homePattern) rules.push({ pattern: homePattern, placeholder: USERPROFILE_PLACEHOLDER });
  if (hostName) rules.push({ pattern: tokenRegex(hostName), placeholder: HOSTNAME_PLACEHOLDER });
  if (userName) rules.push({ pattern: tokenRegex(userName), placeholder: USERNAME_PLACEHOLDER });

  // Placeholder → real value, used by restore. First definition wins, so the
  // canonical spellings this session produced are what come back.
  const originals = new Map();
  if (home) originals.set(USERPROFILE_PLACEHOLDER, home);
  if (hostName) originals.set(HOSTNAME_PLACEHOLDER, hostName);
  if (userName) originals.set(USERNAME_PLACEHOLDER, userName);

  const redactText = (text) => {
    let out = text;
    for (const rule of rules) out = out.replace(rule.pattern, rule.placeholder);
    return out;
  };

  const restoreText = (text) => {
    let out = text;
    for (const [placeholder, original] of originals) {
      if (text.includes(placeholder)) out = out.split(placeholder).join(original);
    }
    return out;
  };

  /** Deep walk so nested argument objects and arrays are covered too. */
  const walk = (value, transform) => {
    if (typeof value === 'string') return transform(value);
    if (Array.isArray(value)) return value.map((item) => walk(item, transform));
    if (value !== null && typeof value === 'object') {
      const out = {};
      for (const [key, item] of Object.entries(value)) out[key] = walk(item, transform);
      return out;
    }
    return value;
  };

  return {
    /** Replace this host's identity strings with placeholders. */
    redact: (value) => walk(value, redactText),
    /** Map placeholders back to the real values (session-scoped reversibility). */
    restore: (value) => walk(value, restoreText),
    /** True when at least one identity rule is active. */
    enabled: rules.length > 0,
    identity: { hostname: hostName || null, username: userName, homePath: home || null },
  };
}

/**
 * The process-wide redactor, built from this host's real identity once.
 *
 * A module singleton is enough: identity does not change within a process, the
 * mapping is stateless, and every export path (own tools, the bridged-tool
 * choke point, artifact paging) must agree on the same placeholders for
 * restore to round-trip.
 */
const shared = createRedactor({});

/** Redact one text (or deep structure) with the shared host identity. */
export function redactSensitive(value) {
  return shared.redact(value);
}

/** Restore placeholders replaced by `redactSensitive` (shared session). */
export function restoreSensitive(value) {
  return shared.restore(value);
}

/** The shared redactor, for callers that need `enabled`/`identity` too. */
export function sharedRedactor() {
  return shared;
}
