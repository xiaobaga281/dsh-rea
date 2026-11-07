/** Regression check for the red-team findings, against the changed modules. */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { extractDeepStrings, channelSummary } from '../../../lib/strings.js';
import { extractIocs, antiAnalysisMatrix, sanitizeText, detectLeaks, parsePEImports } from '../../../lib/intel.js';
import { peTlsDirectory } from '../../../lib/containers.js';
import { assessBehavior } from '../../../lib/plan.js';

// The shell's TEMP is a session-scoped directory; files written by hand live in
// the user's own TEMP. Accept either.
const CANDIDATES = [
  join(process.env.TEMP ?? '.', 'rea-spec'),
  join(process.env.USERPROFILE ?? '.', 'AppData', 'Local', 'Temp', 'rea-spec'),
];
const SPEC = CANDIDATES.find((dir) => existsSync(dir)) ?? CANDIDATES[0];
const read = (name) => {
  for (const dir of CANDIDATES) {
    const path = join(dir, name);
    if (existsSync(path)) return readFileSync(path);
  }
  throw new Error(`missing specimen ${name} in ${CANDIDATES.join(' | ')}`);
};

function analyse(name) {
  const bytes = read(name);
  const report = {};
  const strings = extractDeepStrings(bytes, { minLength: 5, maxStrings: 4000, report });
  const iocs = extractIocs(strings);
  return { bytes, strings, iocs, report };
}

const expectations = [
  { file: 'P4-hex-url.exe', want: 'https://cdn-sync.example-corp.net/v3/poll', label: 'hex channel' },
  { file: 'P7-json-uescape.exe', want: 'https://cdn-sync.example-corp.net/v3/poll', label: 'json escape' },
  { file: 'P10-gzip-json.exe', want: 'https://cdn-sync.example-corp.net/v3/poll', label: 'gzip container' },
  { file: 'S1-composite.exe', want: 'https://api.example-corp.net/v1/collect', label: 'S1 hex C2' },
  { file: 'S1-composite.exe', want: 'https://ops.example-corp.net/ping', label: 'S1 escaped C2' },
  { file: 'S1-composite.exe', want: '7482916350:AAH', label: 'telegram token' },
  { file: 'S1-composite.exe', want: 'Global\\OBS-9f3c2a', label: 'mutex' },
];
for (const check of expectations) {
  const { iocs, strings, report } = analyse(check.file);
  const hit = iocs.some((item) => item.value.includes(check.want) || String(item.value).toLowerCase().includes(check.want.toLowerCase()));
  console.log(`${hit ? 'PASS' : 'FAIL'}  ${check.label.padEnd(18)} ${check.file}  channels=${JSON.stringify(channelSummary(strings))}`);
  if (!hit) console.log('      iocs:', iocs.map((i) => `${i.type}=${i.value}`).slice(0, 12).join(' | '));
}

// gzip must no longer be reported as an unresolved (encrypted) region
{
  const { report, strings } = analyse('P10-gzip-json.exe');
  const containers = (report.containers ?? []).map((c) => c.kind).join(',');
  console.log(`gzip containers=${containers} strings=${strings.length}`);
}

// taxonomy
{
  const { iocs } = analyse('T1-ioc-taxonomy.txt');
  const types = [...new Set(iocs.map((i) => i.type))].sort().join(',');
  console.log(`taxonomy types=${types}`);
  for (const want of ['2606:4700:4700::1111', 'AKIAIOSFODNN7EXAMPLE', 'evil.example.com']) {
    console.log(`  ${iocs.some((i) => String(i.value).includes(want)) ? 'PASS' : 'FAIL'} ${want}`);
  }
}

// anti-analysis TLS false positive on a clean signed binary
{
  const bytes = readFileSync('C:\\Windows\\System32\\whoami.exe');
  const report = {};
  const strings = extractDeepStrings(bytes, { minLength: 5, maxStrings: 4000, report });
  const tls = peTlsDirectory(bytes);
  const matrix = antiAnalysisMatrix(strings, parsePEImports(bytes), null, { tls });
  const hasTls = matrix.techniques.some((t) => t.id === 'tls-callback');
  console.log(`whoami tls.directory=${JSON.stringify(tls)} tls-technique=${hasTls ? 'PRESENT (bug)' : 'absent (fixed)'}`);
}

// sanitize AWS / Slack
{
  const text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nhttps://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX\n';
  const leaks = detectLeaks(text, { user: 'nobody', host: 'nohost', home: 'C:\\nowhere' });
  const clean = sanitizeText(text, { user: 'nobody', host: 'nohost', home: 'C:\\nowhere' });
  console.log(`sanitize kinds=${leaks.map((l) => l.kind).sort().join(',')}`);
  console.log(`  AKIA ${clean.text.includes('AKIAIOSFODNN7EXAMPLE') ? 'LEAKED' : 'redacted'}  slack ${clean.text.includes('hooks.slack.com') ? 'LEAKED' : 'redacted'}`);
}

// decoy behaviour attribution
{
  const { strings, iocs } = analyse('S1-composite.exe');
  const behaviour = assessBehavior({ imports: null, strings, iocs });
  const line = behaviour.summary.split('\n')[0];
  console.log(`behaviour: ${line}`);
}
