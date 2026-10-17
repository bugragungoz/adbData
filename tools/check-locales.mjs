#!/usr/bin/env node
// Fails when a locale file drifts from English: a missing or extra key, other {placeholders}, a
// plural form the language needs but does not have, typographic characters the Bugra content rules
// forbid ("..." not the ellipsis character, "-" not dashes), or a t('key') in the code that English
// does not define.   npm run check:locales
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = path.join(root, 'src/locales');
const FORMS = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
const isPlural = (v) => v && typeof v === 'object' && Object.keys(v).length > 0 && Object.keys(v).every((k) => FORMS.has(k)) && 'other' in v;

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string' || isPlural(v)) out[key] = v;
    else if (v && typeof v === 'object') flatten(v, key, out);
    else out[key] = v;
  }
  return out;
}
const placeholders = (v) => {
  const texts = typeof v === 'string' ? [v] : Object.values(v);
  return [...new Set(texts.flatMap((s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1])))].sort().join(',');
};

const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
const load = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
const en = flatten(load('en.json'));
const errors = [];

for (const f of files) {
  const code = f.replace(/\.json$/, '');
  const msgs = flatten(load(f));
  const needed = new Intl.PluralRules(code).resolvedOptions().pluralCategories;
  for (const key of Object.keys(en)) {
    if (!(key in msgs)) {
      errors.push(`${f}: missing ${key}`);
      continue;
    }
    const v = msgs[key];
    if (typeof v !== 'string' && !isPlural(v)) {
      errors.push(`${f}: ${key} is neither text nor a plural object`);
      continue;
    }
    if (isPlural(en[key]) !== isPlural(v)) errors.push(`${f}: ${key} must ${isPlural(en[key]) ? '' : 'not '}be a plural object`);
    if (isPlural(v)) {
      for (const form of needed) if (!(form in v)) errors.push(`${f}: ${key} lacks the "${form}" form ${code} needs`);
    }
    if (placeholders(v) !== placeholders(en[key])) errors.push(`${f}: ${key} uses {${placeholders(v)}}, English uses {${placeholders(en[key])}}`);
    const texts = typeof v === 'string' ? [v] : Object.values(v);
    for (const s of texts) {
      if (!String(s).trim()) errors.push(`${f}: ${key} is empty`);
      if (/[…–—]/.test(s)) errors.push(`${f}: ${key} uses a typographic ellipsis or dash; write "..." and "-"`);
      if (s !== String(s).trim()) errors.push(`${f}: ${key} starts or ends with a space`);
    }
  }
  for (const key of Object.keys(msgs)) if (!(key in en)) errors.push(`${f}: extra key ${key}`);
}

// Keys used in the code.
const used = new Set();
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(tsx?|mjs)$/.test(e.name) && !/\.test\./.test(e.name)) {
      const src = fs.readFileSync(p, 'utf8');
      for (const m of src.matchAll(/\bt\(\s*'([a-zA-Z0-9_.-]+)'/g)) used.add(`${path.relative(root, p)}|${m[1]}`);
    }
  }
};
walk(path.join(root, 'src'));
for (const entry of used) {
  const [file, key] = entry.split('|');
  if (!(key in en)) errors.push(`${file}: t('${key}') is not in en.json`);
}

if (errors.length) {
  console.error(errors.join('\n'));
  console.error(`\n${errors.length} problem(s) in ${files.length} locale files`);
  process.exit(1);
}
console.log(`${files.length} locale files, ${Object.keys(en).length} messages each: consistent`);
