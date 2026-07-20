// OPT-IN VISUAL HARNESS for the WEB dashboard. Nothing runs this for you.
//
//   npm run visual        (in apps/web)   → PNGs in apps/web/.visual/
//   npm run visual -- --show              → leaves the windows open
//
// Same idea as apps/bridge/scripts/visual-harness.mjs, one seam lower down. That harness stubs
// `window.bridge` in a preload; this page has no preload — its seam is the ES-module import
// `./tally-data.js`. So the harness copies the REAL dist/{index.html, app.js, viewmap.js} into a
// temp directory and drops a stub `tally-data.js` beside them (scripts/visual-stub.ts): real
// formatters, real card layer, fake unlock/loadDashboard. dist/ and ui/ are never touched.
//
// Served over http://127.0.0.1 rather than file://, because a file:// page has a null origin and
// the page's own CSP (`default-src 'self'`) plus `<script type="module">` would block its own
// scripts — the harness must not have to weaken the thing it is inspecting.
//
// PROVES: real Chromium layout, real fonts, real clamp()/grid/flex at a real viewport, real
// overflow and wrapping of real Indian money strings. Anything visible in the PNG is real.
// DOES NOT PROVE: anything about crypto, the network, or that the server returns this shape.

import { app, BrowserWindow } from 'electron';
import { build } from 'esbuild';
import { createServer } from 'node:http';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const DIST = join(HERE, '../dist');
const OUT = join(HERE, '../.visual');
const SHOW = process.argv.includes('--show');

/** iPhone 14, a 2019-era Android tablet, and the laptop the accountant uses. */
const SHOTS = [
  { name: 'desktop-1440x900', width: 1440, height: 900, mobile: false, only: 0 },
  { name: 'tablet-834x1112', width: 834, height: 1112, mobile: true, only: 0 },
  { name: 'phone-390x844', width: 390, height: 844, mobile: true, only: 0 },
  { name: 'partial-phone-390x844', width: 390, height: 844, mobile: true, only: 1 },
  { name: 'partial-desktop-1440x900', width: 1440, height: 900, mobile: false, only: 1 },
  { name: 'login-phone-390x844', width: 390, height: 844, mobile: true, only: 0, login: true },
];

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json' };

// --------------------------------------------------------------------------- the temp site

const site = mkdtempSync(join(tmpdir(), 'tally-web-visual-'));
for (const f of ['index.html', 'app.js', 'viewmap.js']) copyFileSync(join(DIST, f), join(site, f));
// app.js constructs a Worker before it ever calls unlock; the stub's seams ignore it, but the
// file must exist or Chromium logs a 404 that looks like a real failure.
writeFileSync(join(site, 'tally-worker.js'), '');

const res = await build({
  entryPoints: [join(HERE, 'visual-stub.ts')],
  outfile: join(site, 'tally-data.js'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  logLevel: 'info',
});
if (res.errors.length) process.exit(1);

const server = createServer((req, out) => {
  const name = (req.url ?? '/').split('?')[0].replace(/^\/+/, '') || 'index.html';
  try {
    const body = readFileSync(join(site, name));
    out.writeHead(200, { 'content-type': MIME[extname(name)] ?? 'application/octet-stream' });
    out.end(body);
  } catch {
    out.writeHead(404).end('not found');
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;
console.log(`serving ${site} at ${ORIGIN}`);

// --------------------------------------------------------------------------- capture

async function shoot(win, name) {
  const img = await win.webContents.capturePage();
  writeFileSync(join(OUT, `${name}.png`), img.toPNG());
  console.log(`  wrote .visual/${name}.png`);
}

const settle = (win) =>
  win.webContents.executeJavaScript(`
    Promise.race([
      Promise.all(document.getAnimations().map((a) => a.finished.catch(() => {}))),
      new Promise((r) => setTimeout(r, 5000)),
    ]).then(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))))
  `);

/** Ask the page — not me squinting at a PNG — what is off-screen. */
const OVERFLOW_PROBE = `
  ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
    scrollHeight: document.documentElement.scrollHeight,
    offenders: [...document.querySelectorAll('body *')]
      .filter((e) => !e.closest('#cursor, #cursor-follower'))
      .map((e) => ({ e, r: e.getBoundingClientRect() }))
      .filter(({ r }) => r.width > 0 && (r.right > innerWidth + 1 || r.left < -1))
      .slice(0, 12)
      .map(({ e, r }) => e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).trim().split(/\\s+/).join('.') : '')
        + ' [' + Math.round(r.left) + '…' + Math.round(r.right) + '] "' + e.textContent.trim().slice(0, 28) + '"'),
    clipped: [...document.querySelectorAll('.ds-val, .val-hero, .val-primary, .micro-heading')]
      .filter((e) => e.scrollWidth > e.clientWidth + 1)
      .slice(0, 12)
      .map((e) => (e.getAttribute('data-key') ?? e.className) + ': "' + e.textContent.trim().slice(0, 30) + '" ' + e.clientWidth + '<' + e.scrollWidth),
  })
`;

app.whenReady().then(async () => {
  mkdirSync(OUT, { recursive: true });

  for (const s of SHOTS) {
    const win = new BrowserWindow({
      width: s.width,
      height: s.height,
      useContentSize: true,
      show: SHOW,
      webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
    });
    win.webContents.on('console-message', (_e, level, message, line, source) => {
      if (level >= 1) console.log(`  [page:${level}] ${message} (${source}:${line})`);
    });

    // A phone reports `pointer: coarse`, and the page has a whole block keyed on it (it restores
    // the real cursor and kills the custom one). Sizing the window small does NOT flip that —
    // Chromium still reports a mouse — so a "phone" screenshot without this is a desktop
    // screenshot in a narrow window. CDP is the only switch for it.
    //
    // NON-FATAL, and that matters: this hung the whole run at the first mobile shot, so the
    // phone — the viewport this dashboard exists for — was the one never captured. A cosmetic
    // emulation must never be able to block the capture it is decorating. Layout, wrapping and
    // overflow all come from the window WIDTH, which is set regardless; losing the pointer
    // emulation costs only the custom-cursor branch.
    if (s.mobile) {
      try {
        win.webContents.debugger.attach('1.3');
        await Promise.race([
          win.webContents.debugger.sendCommand('Emulation.setEmulatedMedia', {
            features: [
              { name: 'pointer', value: 'coarse' },
              { name: 'any-pointer', value: 'coarse' },
              { name: 'hover', value: 'none' },
              { name: 'any-hover', value: 'none' },
            ],
          }),
          new Promise((_r, rej) => setTimeout(() => rej(new Error('CDP timeout')), 5000)),
        ]);
      } catch (e) {
        console.log(`  [warn] pointer emulation unavailable (${e.message}) — layout still real`);
      }
    }

    await win.loadURL(`${ORIGIN}/index.html?only=${s.only}`);

    if (s.login) {
      await win.webContents.executeJavaScript(`
        document.getElementById('tenant-id').value = 'ganesh-steel';
        document.getElementById('passphrase').value = 'correct horse battery staple';
        true
      `);
    } else {
      // Drive the product's own path — submit the real form, so `reveal()` and every animation
      // run exactly as they do for an owner.
      await win.webContents.executeJavaScript(`
        document.getElementById('tenant-id').value = 'ganesh-steel';
        document.getElementById('passphrase').value = 'x';
        document.getElementById('auth-btn').click();
        new Promise((resolve, reject) => {
          const t0 = Date.now();
          (function poll() {
            if (document.getElementById('dashboard-wrapper').classList.contains('on')) return resolve(true);
            if (Date.now() - t0 > 10000) return reject(new Error('the dashboard never revealed: ' + document.getElementById('auth-error').textContent));
            setTimeout(poll, 20);
          })();
        })
      `);
    }
    await settle(win);

    const probe = await win.webContents.executeJavaScript(OVERFLOW_PROBE);
    console.log(`\n${s.name}: scrollWidth ${probe.scrollWidth} vs clientWidth ${probe.clientWidth}, page height ${probe.scrollHeight}`);
    if (probe.offenders.length) console.log(`  OFF-SCREEN:\n    ${probe.offenders.join('\n    ')}`);
    if (probe.clipped.length) console.log(`  CLIPPED TEXT:\n    ${probe.clipped.join('\n    ')}`);

    await shoot(win, s.name);

    if (!s.login && probe.scrollHeight > s.height) {
      win.setContentSize(s.width, Math.min(probe.scrollHeight, 6000));
      await settle(win);
      await shoot(win, `${s.name}-full`);
    }
    if (!SHOW) win.hide();
  }

  if (!SHOW) {
    server.close();
    app.quit();
  }
});
