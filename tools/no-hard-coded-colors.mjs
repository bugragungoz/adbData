// Fails when a color is written outside the design tokens. Colors come from src/styles/tokens.css
// (the Bugra tokens); everything else uses var(--token).   npm run check:colors
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const SKIP = new Set(['src/styles/tokens.css']);
const COLOR = /#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g;

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(css|ts|tsx|js|mjs|html)$/.test(e.name)) out.push(p);
  }
  return out;
}

const problems = [];
for (const file of walk(path.join(root, 'src'))) {
  const rel = path.relative(root, file).split(path.sep).join('/');
  if (SKIP.has(rel) || rel.endsWith('.test.ts')) continue;
  fs.readFileSync(file, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      // URL fragments and element ids are not colors.
      const scrubbed = line.replace(/href="#[^"]*"/g, '').replace(/url\(#[^)]*\)/g, '').replace(/['"`]#[a-z][\w-]*['"`]/gi, '');
      for (const m of scrubbed.matchAll(COLOR)) problems.push(`${rel}:${i + 1}: ${m[0]}`);
    });
}
if (problems.length) {
  console.error(`Colors outside the design tokens (use var(--...)):\n${problems.join('\n')}`);
  process.exit(1);
}
console.log('no hard-coded colors');
