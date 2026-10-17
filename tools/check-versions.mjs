// One version everywhere: package.json, the Cargo workspace and tauri.conf.json; the release job
// tags what package.json says. The Tauri JavaScript packages match the Rust crates they talk to.
//   npm run check:versions
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const pkg = JSON.parse(read('package.json'));
const found = {
  'package.json': pkg.version,
  'Cargo.toml': /\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"/s.exec(read('Cargo.toml'))?.[1],
  'src-tauri/tauri.conf.json': JSON.parse(read('src-tauri/tauri.conf.json')).version,
};

const problems = [];
const want = found['package.json'];
if (!/^\d+\.\d+\.\d+$/.test(want ?? '')) problems.push(`package.json version "${want}" is not X.Y.Z (MSI takes numbers only)`);
for (const [file, v] of Object.entries(found)) if (v !== want) problems.push(`${file} has ${v}, package.json has ${want}`);

// Cargo.lock pins the crates; the JavaScript side must speak the same minor version.
const lock = read('Cargo.lock');
const crate = (name) => new RegExp(`\\[\\[package\\]\\]\\nname = "${name}"\\nversion = "([^"]+)"`).exec(lock)?.[1];
const minor = (v) => v?.split('.').slice(0, 2).join('.');
const pairs = [
  ['@tauri-apps/api', 'tauri'],
  ['@tauri-apps/plugin-opener', 'tauri-plugin-opener'],
];
for (const [js, rust] of pairs) {
  const a = pkg.dependencies[js];
  const b = crate(rust);
  if (!b) problems.push(`Cargo.lock has no ${rust}`);
  else if (minor(a) !== minor(b)) problems.push(`${js} ${a} does not match the ${rust} crate ${b}`);
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`version ${want} everywhere; Tauri packages match the crates`);
