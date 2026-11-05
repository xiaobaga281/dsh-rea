/**
 * From evidence to a plan.
 *
 * A crime-scene technician hands over a bag of exhibits. An analyst hands over
 * the same exhibits plus the sentence "here is what it does, here is what is
 * still unknown, and here is the cheapest experiment that would settle it".
 *
 * Both halves live here because they share one input - the evidence - and one
 * rule: never state a conclusion without naming what produced it. A behaviour
 * with no evidence is a guess; a next step with no expected result is a chore.
 *
 * @module dsh-rea/lib/plan
 */

// --------------------------------------------------------------- behaviour --

const BEHAVIOUR_RULES = [
  {
    id: 'device-identifier',
    label: 'collects stable device identifiers',
    apis: ['getvolumeinformation', 'getcomputername', 'getusername', 'getadaptersinfo', 'gethostbyname'],
    strings: ['android_id', 'advertisingidclient', 'getsubscriberid', 'device_token', 'installation_id', 'serial_number', 'machineguid'],
  },
  {
    id: 'telemetry',
    label: 'reports to a remote endpoint',
    apis: ['internetconnect', 'httpsendrequest', 'winhttpconnect', 'winhttpsendrequest', 'urldownloadtofile', 'wsastartup'],
    strings: ['telemetry', '/collect', '/register', 'firebase', 'analytics', 'crashlytics', 'logevent', 'beacon', 'gate.php'],
  },
  {
    id: 'persistence',
    label: 'writes persistent state',
    apis: ['regsetvalueex', 'regcreatekeyex', 'createservicea', 'changeserviceconfig'],
    strings: ['hklm\\software', 'hkcu\\software', '\\run', 'installid'],
  },
  {
    id: 'anti-debug',
    label: 'checks for a debugger or a sandbox',
    apis: ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'ntsetinformationthread'],
    strings: ['rdtsc', 'cpuid', 'vmware', 'vbox', 'sandboxie', 'frida', 'gum-js-loop'],
  },
  {
    id: 'injection',
    label: 'can write into another process',
    apis: ['virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'setwindowshookexa'],
    strings: [],
  },
  {
    id: 'crypto',
    label: 'encrypts or derives keys',
    apis: ['cryptencrypt', 'cryptdecrypt', 'cryptderivekey', 'cryptgenrandom'],
    strings: [],
  },
  {
    id: 'collection',
    label: 'reads clipboard or user input',
    apis: ['openclipboard', 'getclipboarddata', 'getasynckeystate', 'getkeystate'],
    strings: [],
  },
];

/**
 * Turn imported and hash-recovered names into behaviours.
 *
 * Evidence source is tracked per hit: an import table proves a name is bound; a
 * hash table only proves the sample carries the name. Both are worth reporting,
 * but they are not the same claim.
 *
 * The ATT&CK capability hints in the triage report are deliberately not an input
 * here. They say what a literal *mentions*; these rules say what the binary can
 * *do*, and mixing the two produced reports whose summary and family list
 * disagreed with each other.
 */
export function assessBehavior({ imports = null, hashed = [], strings = [], iocs = [] } = {}) {
  const imported = new Set((imports?.apiFlat ?? []).map((name) => String(name).toLowerCase()));
  const recovered = new Set((hashed ?? []).map((item) => String(item.api).toLowerCase()));
  const text = (Array.isArray(strings) ? strings : [])
    .map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n').toLowerCase();

  const findings = [];
  // Import names carry their calling convention suffix (GetVolumeInformationA vs
  // ...W), so a marker must match on prefix, not equality. Capability rules in
  // intel.js already search the joined text this way; behaviour should agree.
  const importedNames = [...imported];
  const recoveredNames = [...recovered];
  const hit = (marker) => importedNames.find((name) => name === marker || name.startsWith(marker));
  const hitRecovered = (marker) => recoveredNames.find((name) => name === marker || name.startsWith(marker));

  for (const rule of BEHAVIOUR_RULES) {
    const evidence = [];
    let source = null;
    for (const marker of rule.apis) {
      const direct = hit(marker);
      if (direct) {
        evidence.push(direct);
        source = source ?? 'import-table';
        continue;
      }
      const hashedName = hitRecovered(marker);
      if (hashedName) {
        evidence.push(`${hashedName} (hash)`);
        source = source ?? 'api-hash';
      }
    }
    for (const marker of rule.strings) {
      if (text.includes(marker)) {
        evidence.push(marker);
        source = source ?? 'string';
      }
    }
    if (evidence.length === 0) continue;
    const direct = evidence.filter((item) => !item.includes('(hash)')).length;
    findings.push({
      id: rule.id,
      label: rule.label,
      evidence: evidence.slice(0, 6),
      source,
      // One hashed name is a hint; several independent ones are a claim.
      confidence: direct >= 2 ? 'medium' : direct === 1 ? 'low' : 'low',
    });
  }

  const endpoints = (iocs ?? []).filter((item) => item.type === 'url').map((item) => item.value);
  // Families come from the findings, not from the capability hints: a hint is a
  // candidate technique the file merely mentions, and listing T-codes next to a
  // summary that says "nothing attributable" reads as a claim the evidence does
  // not support. The hints remain in the report under their own name.
  const families = [...new Set(findings.map((finding) => finding.id))];

  const clauses = [];
  for (const finding of findings) {
    const target = finding.id === 'telemetry' && endpoints.length > 0 ? ` (${endpoints[0]})` : '';
    clauses.push(`${finding.label}${target}`);
  }
  const summary = clauses.length === 0
    ? 'No behaviour can be attributed from static evidence alone; the sample is either empty of these signals or hides them behind a run-time decoder.'
    : `Statically attributable: ${clauses.join('; ')}.`;

  return {
    findings,
    families,
    summary,
    limitations: 'Behaviour inferred from names and literals, never from execution. An imported API can be unused; a hash may be a collision. Confirm each finding on the call graph or in a trace before it goes into a report.',
  };
}

// -------------------------------------------------------------- next steps --

const DERIVE_PATTERN = /derive\(\s*([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z0-9_]+))?\s*\)/i;

function sectionString(profile, rva) {
  if (!profile) return 'an uninitialised region';
  const section = profile.sections.find((item) => rva >= item.virtualAddress
    && rva < item.virtualAddress + Math.max(item.virtualSize, item.rawSize));
  return section ? section.name : 'an unmapped region';
}

/**
 * Build ranked experiments.
 *
 * Priority is "expected information per unit of effort", not severity: opening
 * the sealed config explains the most while costing one breakpoint, which is why
 * it comes first. Each step names the API or RVA to use, because "go dynamic"
 * is not an instruction anyone can follow.
 *
 * Each step also names the REA tool that would confirm it. The local layer only
 * produces hypotheses - it has no disassembler and executes nothing - so a step
 * without a confirmation path would be advice the analyst cannot check.
 */
export function planNextSteps({
  structure = null, unresolved = [], strings = [], imports = null, behavior = null,
  hashed = [], entry = null, providers = null,
} = {}) {
  const steps = [];
  const decoded = (Array.isArray(strings) ? strings : [])
    .map((item) => (typeof item === 'string' ? item : item?.value ?? '')).join('\n');
  const derive = decoded.match(DERIVE_PATTERN);

  if (unresolved.length > 0) {
    const first = unresolved[0];
    const size = Math.max(0, first.end - first.start);
    const where = sectionString(structure, first.rva ?? first.start);
    const rva = first.rva === null || first.rva === undefined ? null : ` at RVA 0x${(first.rva >>> 0).toString(16)}`;
    const others = unresolved.length > 1 ? ` (${unresolved.length} high-entropy regions in total; start with this one)` : '';
    if (derive) {
      steps.push({
        priority: 1,
        action: `Break on ${derive[1]}${derive[2] ? ` and read ${derive[2]}` : ''}, dump the buffer it fills, then decrypt the ${size}-byte region${rva} in ${where} with RC4 using that value`,
        why: `the config header names ${derive[1]} as the key source, and the region is high-entropy with no recoverable key inside the file${others}`,
        expect: 'plaintext beginning with https:// or a JSON object, which turns the sealed region into ordinary indicators',
        resolves: `${size} bytes currently reported as unresolved`,
        confirm: 'load_frida_script (break on the API, dump the buffer) - or start_gdb_session when Frida is unavailable',
      });
    } else {
      steps.push({
        priority: 1,
        action: `Set a write breakpoint on the ${size}-byte region${rva} in ${where} and dump it after the unpacking stub returns`,
        why: `high-entropy region with no key material in the file; either a runtime-derived key or a decoy${others}`,
        expect: 'plaintext, or a second high-entropy layer that proves the region is padding',
        resolves: `${size} bytes currently reported as unresolved`,
        confirm: 'load_frida_script (write breakpoint on the region) - the dump is the proof, not the entropy',
      });
    }
  }

  if (structure?.tls?.present && structure.tls.callbacks.length > 0) {
    const first = structure.tls.callbacks[0];
    steps.push({
      priority: 2,
      action: `Break in the TLS callback at RVA 0x${(first.rva >>> 0).toString(16)} (${first.section ?? 'unknown section'}) before the entry point`,
      why: 'TLS callbacks run before the entry point, so an anti-debug or unpacking check placed there fires first and can explain later failures',
      expect: 'the process exits, or a flag is written that the entry point reads',
      resolves: 'whether the first instruction executed is the one the disassembler shows',
      confirm: `inspect_address_context at RVA 0x${(first.rva >>> 0).toString(16)} - Ghidra resolves the callback's name from the TLS directory but does not create a function for it, so batch_decompile alone fails with "no procedure exists"; define the function first if you need pseudocode`,
      // The previous wording named batch_decompile here, and on a real Ghidra
      // run that call returns invalid_request: TLS callbacks are reached
      // through a data pointer, so the analyzer never made them procedures.
      probe: { tool: 'inspect_address_context', rva: first.rva, expectName: 'tls_callback' },
    });
  }

  if (structure?.dispatchTables?.length > 0) {
    const table = structure.dispatchTables[0];
    steps.push({
      priority: 3,
      action: `Log the index passed to the indirect jump at RVA 0x${(table.rva >>> 0).toString(16)} (${table.entries} code pointers in ${table.section})`,
      why: 'a run of code pointers in a read-only section is what control-flow flattening looks like, but a compiler switch table has the same shape; only the decoder loop separates them, which is why this is a hypothesis to check and not a finding',
      expect: 'a short repeating sequence that maps states to basic blocks, or a single jump into a dense case range - the second means it was a switch statement',
      resolves: table.confidence === 'low'
        ? 'whether the table is a state machine or ordinary switch dispatch, before any time is spent on block reordering'
        : 'the original block order, which a decompiler alone cannot recover',
      confirm: `inspect_address_context at RVA 0x${(table.rva >>> 0).toString(16)} - this is a run of pointers, not a procedure, so the address has to be read as data before any decoder loop can be named`,
      probe: { tool: 'inspect_address_context', rva: table.rva, expectName: null },
    });
  }

  const hashedInfo = structure?.hashedApis ?? null;
  const recovered = hashed.length;
  if (!structure?.importsPresent && hashedInfo?.count > 0) {
    const algorithms = hashedInfo.algorithms ?? [];
    // A real loader walks ONE table with ONE algorithm. When several algorithms
    // match, saying "<first> fits those" is simply false: the bytes are either
    // a concatenation of tables or a planted decoy. 1.8.4's D9 put a CRC32
    // decoy table next to a ROR13 one and the report claimed ROR13 explained
    // all 19 names.
    const mixed = algorithms.length > 1;
    const salt = Number.isInteger(hashedInfo.salt) ? hashedInfo.salt >>> 0 : null;
    // "+salt" is this module's marker for the salted variant, not part of the
    // algorithm's name; keep it out of the sentence and name the salt instead.
    const base = (algorithms[0] ?? 'an unknown algorithm').replace(/\+salt$/, '');
    const algorithm = mixed
      ? `several algorithms (${algorithms.slice(0, 4).join('/')})`
      : (salt !== null ? `${base} with salt 0x${salt.toString(16)}` : base);
    const truncated = hashedInfo.truncated ? ' (the scan stopped early, so this is a lower bound)' : '';
    steps.push({
      priority: 4,
      action: mixed
        ? `Separate the ${recovered} recovered hash names by algorithm - ${algorithms.slice(0, 4).join('/')} all matched${truncated}, which is what concatenated or planted decoy tables look like; find which table the loader actually walks before naming a capability`
        : `Resolve the remaining hash entries offline against a wider export list - ${recovered} names matched${truncated}, and ${algorithm} fits those`,
      why: mixed
        ? 'the import directory is absent and the matches span more than one algorithm, so at most one group can be the real import table'
        : salt !== null
          ? 'the import directory is absent, and the table only opened because the sample hands over its own salt in the config header; the algorithm alone would have looked unknown'
          : 'the import directory is absent, so the hash table is the only import evidence and any unmatched entry is an unknown capability',
      expect: mixed
        ? 'two address-contiguous groups with different algorithms, one of which the code never references'
        : 'a complete API set, or a small unmatched set that points at a custom or salted hash',
      resolves: 'which capabilities the sample actually links against',
      confirm: 'inspect_with_objdump on the table section - no engine state is needed, this one is decided offline',
    });
  }

  if (steps.length === 0) {
    steps.push({
      priority: 4,
      action: `Open the target${entry ? ` at entry RVA 0x${(entry >>> 0).toString(16)}` : ''} and walk the call graph against the ${behavior?.findings?.length ?? 0} behaviour findings`,
      why: 'no structural obstacle was found, so the remaining work is confirmation rather than recovery',
      expect: 'each behaviour tied to a function address and an evidence ID',
      resolves: 'whether the inferred behaviours are actually reachable',
      confirm: 'batch_decompile plus inspect_analysis_view on the call graph',
    });
  }

  return tagProviders(steps, providers).sort((a, b) => a.priority - b.priority);
}

/**
 * Map the tool named at the start of `confirm` to the engine that has to exist.
 *
 * Every step already ends with the REA tool that would settle it, which is only
 * an honest instruction if that tool can actually run. 1.8.0 wrote the tool name
 * and stopped there; on a host with no engines installed, all five confirm paths
 * pointed into nothing. Attaching readiness makes the seam visible instead of
 * leaving the analyst to discover it when the call fails.
 */
const PROVIDER_OF_CONFIRM = {
  load_frida_script: 'frida',
  instrument_with_frida: 'frida',
  start_frida_session: 'frida',
  batch_decompile: 'ghidra',
  inspect_analysis_view: 'ghidra',
  // The probe emitted for a TLS callback or a dispatch table runs through this
  // one. It was missing from the map, so those steps were never tagged and
  // their probes survived even when Ghidra could not start.
  inspect_address_context: 'ghidra',
  start_gdb_session: 'gdb',
  start_gdb_decompile: 'gdb',
  gdb_console: 'gdb',
  execute_rizin_command: 'rizin',
  rizin_debug_command: 'rizin',
  start_rizin_debug_session: 'rizin',
  inspect_with_objdump: 'objdump',
  decompile_jeb_item: 'jadx',
};

function tagProviders(steps, providers = null) {
  if (!providers?.providers) return steps;
  for (const step of steps) {
    const tool = String(step.confirm ?? '').match(/^([a-z][a-z0-9_]*)/)?.[1];
    const key = tool ? PROVIDER_OF_CONFIRM[tool] : undefined;
    if (!key) continue;
    const state = providers.providers[key];
    if (!state) continue;
    step.provider = { key, ready: state.ready === true, reason: state.reason ?? null };
    if (state.ready === true) continue;
    // A probe that names an engine which cannot start is not a plan, it is a
    // promise the report cannot keep: 1.8.2 emitted it anyway, and every
    // affected generation lost the `verify` points for an engine that died
    // before it read a byte. Drop the executable anchor and say why.
    if (step.probe) {
      delete step.probe;
      step.blocked = state.reason ?? `provider ${key} is unavailable`;
    }
  }
  return steps;
}
