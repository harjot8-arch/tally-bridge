// Browser build for the web data layer.
//
// The UI author writes plain HTML/CSS/JS and calls this bundle — they do not run a TypeScript
// toolchain, and they must not have to. So this produces two self-contained browser ES modules:
//
//   dist/tally-data.js    the public API (unlock, loadDashboard, lockSession, …) — see README.md
//   dist/tally-worker.js  the unlock worker (Argon2id off the main thread) — see README.md
//
// Both are `platform: browser`, so esbuild resolves `node:*` and `Buffer` as errors rather than
// silently shipping something that dies at runtime — which is exactly the check we want: the
// data layer CLAIMS to be browser-clean (HKDF via WebCrypto, gzip via DecompressionStream,
// base64 via atob/btoa), and a failed build is the honest way to catch a Node-only import
// sneaking in through the crypto barrel.
//
// libsodium's wasm embeds as base64 inside its own JS (verified for the server bundle), so there
// is no external .wasm to serve and no fetch at load.
//
// CORRECTION: an earlier version of this comment claimed "the CSP forbids remote fetches anyway".
// That was FALSE — the Vercel deployment sets no headers at all (config.json has no `headers`
// block); the only CSP in this repo is the Electron window's. The embedded wasm is therefore a
// property of libsodium, not something a policy is enforcing. Adding real headers is tracked.
//
// Run: `npm run build` in apps/web (or `node build.mjs`). Requires esbuild (already a devDep).

import { build } from 'esbuild';
import { copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'dist');

const common = {
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  // Minify would obscure a security review of what actually ships to the browser. This is the
  // security boundary the whole product rests on; readable output is worth the bytes, and gzip
  // on the wire recovers most of them.
  minify: false,
  sourcemap: true,
  // A Node-only import reaching the browser is a BUILD FAILURE, not a warning. That is the point.
  logLevel: 'info',
};

const [dataOut, workerOut, viewmapOut] = await Promise.all([
  build({
    ...common,
    // ui/entry.ts = the data layer barrel + the viewmodel formatters the UI needs
    // (formatMoney/formatDelta — Intl.NumberFormat('en-IN') is banned, see ARCHITECTURE.md).
    entryPoints: [join(HERE, 'ui/entry.ts')],
    outfile: join(OUT, 'tally-data.js'),
  }),
  build({
    ...common,
    entryPoints: [join(HERE, 'src/worker-entry.ts')],
    outfile: join(OUT, 'tally-worker.js'),
  }),
  build({
    ...common,
    entryPoints: [join(HERE, 'ui/viewmap.ts')],
    outfile: join(OUT, 'viewmap.js'),
  }),
]);

for (const [name, res] of [
  ['tally-data.js', dataOut],
  ['tally-worker.js', workerOut],
  ['viewmap.js', viewmapOut],
]) {
  if (res.errors.length) {
    console.error(`${name}: ${res.errors.length} error(s)`);
    process.exit(1);
  }
}

// The UI itself — plain HTML/JS, no build step, copied verbatim so dist/ is the complete
// flat set the deploy bundle ships into static/ (index.html imports ./app.js, which imports
// ./tally-data.js and ./viewmap.js from beside it).
for (const f of ['index.html', 'app.js']) copyFileSync(join(HERE, 'ui', f), join(OUT, f));

console.log('web dashboard built → apps/web/dist/{index.html, app.js, viewmap.js, tally-data.js, tally-worker.js}');
