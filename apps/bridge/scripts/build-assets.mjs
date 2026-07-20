// Post-`tsc` build step for the renderer. Run by `npm run build` in this package.
//
// WHY THIS EXISTS INSTEAD OF A BUNDLER
//
// `tsc` is a compiler, not a bundler. It leaves two things broken that only show up at RUNTIME,
// in the packaged app, as a blank window:
//
//   1. `index.html` and `styles.css` are not TypeScript, so `tsc` never copies them to `dist/`.
//      `electron-builder.yml` ships `files: dist/**/*` — so the packaged app shipped a renderer
//      with no page to load and no styles to load it with.
//   2. The renderer imports `@tally-bridge/viewmodel`, a BARE specifier. Node resolves those via
//      `node_modules`; a browser does not resolve them at all. `tsc` emits the specifier
//      verbatim, so the module graph dead-ends on the first import and nothing paints.
//
// The honest fix is a bundler. There is none in this repo's `node_modules` (no esbuild, no
// rollup, no vite) and adding one means an install this task is not allowed to do. So this does
// the two things a bundler would have done for us, and nothing else:
//
//   * copies the static assets, and
//   * copies the workspace packages the renderer actually reaches into `dist/renderer/vendor/`,
//     rewriting every `@tally-bridge/*` specifier to the relative path of the copy.
//
// The output is plain ES modules the browser loads directly — no import map (which would need a
// CSP hash for an inline <script>, i.e. a hole in the renderer's policy for a build convenience).
// No minification, no tree-shaking, no code splitting. If a real bundler ever lands, delete this
// file: it is a stand-in, not an architecture.
//
// SAFE TO RUN CONCURRENTLY: this only ever reads from `packages/*/dist` and writes inside
// `apps/bridge/dist`. It never touches `node_modules`.

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BRIDGE = resolve(fileURLToPath(import.meta.url), '../..');
const REPO = resolve(BRIDGE, '../..');
const DIST_RENDERER = join(BRIDGE, 'dist/renderer');
const VENDOR = join(DIST_RENDERER, 'vendor');

const SCOPE = '@tally-bridge/';
/** Matches the specifier of a static import/export, which is the only form the renderer uses. */
const SPECIFIER = /(\bfrom\s*|\bimport\s*\(?\s*)(['"])(@tally-bridge\/[^'"]+)\2/g;

if (!existsSync(DIST_RENDERER)) {
  throw new Error(`no ${DIST_RENDERER} — run \`tsc -p tsconfig.json\` before this script`);
}

// ---------------------------------------------------------------- static assets

for (const asset of ['index.html', 'styles.css', 'wizard.css']) {
  const from = join(BRIDGE, 'src/renderer', asset);
  if (!existsSync(from)) throw new Error(`missing renderer asset: ${from}`);
  cpSync(from, join(DIST_RENDERER, asset));
}

// ---------------------------------------------------------------- workspace packages

/** Where a workspace package's entry lives on disk, honouring `exports` then `main`. */
function entryOf(pkgDir) {
  const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
  const entry = pkg.exports?.['.']?.default ?? pkg.exports?.['.'] ?? pkg.main;
  if (typeof entry !== 'string') {
    throw new Error(`cannot resolve an entry point for ${pkgDir}`);
  }
  return resolve(pkgDir, entry);
}

/**
 * Copy a workspace package's built output into `vendor/<name>/`.
 *
 * The whole `dist` goes, not just the entry: these packages are small, and walking the graph to
 * copy only reachable files is the part of a bundler worth not reimplementing badly.
 */
const copied = new Map(); // bare name -> absolute path of the vendored entry file

function vendor(name) {
  const already = copied.get(name);
  if (already) return already;

  const pkgDir = join(REPO, 'packages', name.slice(SCOPE.length));
  if (!existsSync(pkgDir)) throw new Error(`${name} is not a workspace package under packages/`);

  const entry = entryOf(pkgDir);
  const srcDist = dirname(entry);
  if (!existsSync(entry)) {
    throw new Error(
      `${name} has no build output at ${entry} — build it first (\`npm run build -w ${name}\`)`,
    );
  }

  const destDist = join(VENDOR, name.slice(SCOPE.length));
  mkdirSync(destDist, { recursive: true });
  // .js only: .d.ts is for the compiler and .map points at sources that are not shipped.
  for (const f of readdirSync(srcDist)) {
    if (f.endsWith('.js')) cpSync(join(srcDist, f), join(destDist, f));
  }

  const vendoredEntry = join(destDist, relative(srcDist, entry));
  copied.set(name, vendoredEntry);

  // Recurse: the vendored files may themselves import other workspace packages.
  for (const f of readdirSync(destDist)) rewrite(join(destDist, f));
  return vendoredEntry;
}

/** Rewrite every `@tally-bridge/*` specifier in one emitted file to its vendored copy. */
function rewrite(file) {
  const before = readFileSync(file, 'utf8');
  const after = before
    // The maps are not shipped; the comment would just 404 in devtools.
    .replace(/^\/\/# sourceMappingURL=.*$/gm, '')
    .replace(SPECIFIER, (whole, head, quote, spec) => {
      if (!spec.startsWith(SCOPE)) return whole;
      // Subpath imports would need real `exports` resolution. Nothing does this today, and
      // guessing would produce a path that 404s at runtime instead of failing here.
      if (spec.slice(SCOPE.length).includes('/')) {
        throw new Error(`subpath import is not supported by this build step: ${spec} in ${file}`);
      }
      const target = vendor(spec);
      let rel = relative(dirname(file), target).replaceAll('\\', '/');
      if (!rel.startsWith('.')) rel = `./${rel}`;
      return `${head}${quote}${rel}${quote}`;
    });
  if (after !== before) writeFileSync(file, after);
}

for (const f of readdirSync(DIST_RENDERER)) {
  if (f.endsWith('.js')) rewrite(join(DIST_RENDERER, f));
}

// A bare specifier left anywhere under dist/renderer is a blank window at runtime. Fail the
// BUILD instead — this check is the whole reason to prefer rewriting over an import map.
for (const file of walk(DIST_RENDERER)) {
  if (!file.endsWith('.js')) continue;
  const m = readFileSync(file, 'utf8').match(SPECIFIER);
  if (m) throw new Error(`unresolved bare specifier(s) in ${file}: ${m.join(', ')}`);
}

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else yield p;
  }
}

const names = [...copied.keys()];
console.log(
  `[build-assets] renderer assets copied; vendored ${names.length}: ${names.join(', ') || '(none)'}`,
);
