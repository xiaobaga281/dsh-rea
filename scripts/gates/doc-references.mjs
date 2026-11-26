/**
 * Resolve code citations in documentation to real files and line ranges.
 *
 * A citation gate that only checks `path:number` shape still passes after the
 * code moves. This parser extracts full citations and the shorthand `:528/:539`
 * form used inside `[代码 ...]` tags, then validates both the file and the range
 * against the file's current line count.
 *
 * @module dsh-rea-restore/scripts/gates/doc-references
 */
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';

const FULL = /((?:[\w.-]+\/)+[\w.-]+\.(?:js|mjs|py|ps1|md)):(\d+)(?:-(\d+))?/g;
const SHORTHAND = /:\s*(\d+)(?:-(\d+))?/g;
const CITATION = /\[代码\s+([^\]]+)\]/g;

export function findDocReferences(markdown) {
  const found = [];
  const seen = new Set();
  const add = (file, start, end, line) => {
    const key = `${file}:${start}-${end}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ file, start, end, line });
  };
  String(markdown ?? '').split(/\r?\n/).forEach((text, index) => {
    const full = [...text.matchAll(FULL)].map((match) => {
      const start = Number(match[2]);
      const end = match[3] ? Number(match[3]) : start;
      return { file: match[1], start, end, at: match.index, raw: match[0] };
    });
    for (const ref of full) add(ref.file, ref.start, ref.end, index + 1);
    for (const citation of text.matchAll(CITATION)) {
      const content = citation[1];
      const base = citation.index + citation[0].indexOf(content);
      const local = full.filter((ref) => ref.at >= base && ref.at < base + content.length);
      for (const match of content.matchAll(SHORTHAND)) {
        const absolute = base + match.index;
        if (local.some((ref) => absolute >= ref.at && absolute < ref.at + ref.raw.length)) continue;
        const previous = [...local].reverse().find((ref) => ref.at < absolute);
        if (!previous) continue;
        const start = Number(match[1]);
        const end = match[2] ? Number(match[2]) : start;
        add(previous.file, start, end, index + 1);
      }
    }
  });
  return found;
}

export function validateDocReferences(root, documents) {
  const failures = [];
  let checked = 0;
  for (const document of documents) {
    const docPath = join(root, document);
    if (!existsSync(docPath)) {
      failures.push(`${document}: document is missing`);
      continue;
    }
    const references = findDocReferences(readFileSync(docPath, 'utf8'));
    checked += references.length;
    for (const ref of references) {
      const absolute = resolve(root, ref.file);
      const rel = relative(root, absolute);
      if (rel.startsWith('..') || isAbsolute(rel)) {
        failures.push(`${document}:${ref.line}: ${ref.file} escapes the repository`);
        continue;
      }
      if (!existsSync(absolute)) {
        failures.push(`${document}:${ref.line}: missing ${ref.file}:${ref.start}`);
        continue;
      }
      const lineCount = readFileSync(absolute, 'utf8').split(/\r?\n/).length;
      if (ref.start < 1 || ref.end < ref.start || ref.end > lineCount) {
        failures.push(`${document}:${ref.line}: ${ref.file}:${ref.start}${ref.end === ref.start ? '' : `-${ref.end}`} outside 1-${lineCount}`);
      }
    }
  }
  return { checked, failures };
}