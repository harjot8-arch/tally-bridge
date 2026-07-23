// Frontend build for the Tauri shell. Bundles the REAL Electron renderer (apps/bridge/src/renderer)
// through the Tauri-backed window.bridge shim, so the SAME dashboard UI renders in the WebView.
//
// platform: 'browser' is the honest check the renderer claims to pass: a node:* import is a BUILD
// FAILURE here, not a shimmed-around warning. If that happens, STOP and report it.
import { build } from 'esbuild';
import { copyFileSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'frontend');
const RENDERER = join(HERE, '..', 'bridge', 'src', 'renderer');

mkdirSync(OUT, { recursive: true });

const res = await build({
  entryPoints: [join(HERE, 'src', 'tauri-entry.ts')],
  outfile: join(OUT, 'app.js'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  minify: false,
  sourcemap: true,
  logLevel: 'info',
});

if (res.errors.length) {
  console.error(`build failed: ${res.errors.length} error(s)`);
  process.exit(1);
}

// The renderer ships its stylesheets as plain files; copy them beside app.js.
for (const f of ['styles.css', 'wizard.css']) copyFileSync(join(RENDERER, f), join(OUT, f));

// index.html, adapted from the renderer's: drop the Electron CSP <meta> (Tauri owns CSP via
// tauri.conf.json; the Electron `connect-src 'none'` would block the invoke bridge) and point the
// script at the bundled app.js. Both edits FAIL LOUD if their target isn't found exactly once — a
// silent no-op would smuggle `connect-src 'none'` into the bundle and break invoke while still
// printing success (the brittle-regex bug the reviewer caught).
const src = readFileSync(join(RENDERER, 'index.html'), 'utf8');
let html = src;

const CSP_META = /\s*<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?\/>/g;
const cspHits = html.match(CSP_META);
if (!cspHits || cspHits.length !== 1) {
  console.error(`expected exactly one CSP <meta> to strip, found ${cspHits ? cspHits.length : 0}`);
  process.exit(1);
}
html = html.replace(CSP_META, '');
// The now-orphaned explanatory comment that referenced the CSP (cosmetic; independent of the meta).
html = html.replace(/\s*<!--[\s\S]*?Content-Security-Policy[\s\S]*?-->/g, '');

const SCRIPT_FROM = '<script type="module" src="./main.js"></script>';
if (!html.includes(SCRIPT_FROM)) {
  console.error('renderer index.html no longer has the expected <script src="./main.js">');
  process.exit(1);
}
html = html.replace(SCRIPT_FROM, '<script type="module" src="./app.js"></script>');
writeFileSync(join(OUT, 'index.html'), html);

console.log('tauri frontend built → apps/bridge-tauri/frontend/{index.html, app.js, styles.css, wizard.css}');
