// OPT-IN VISUAL HARNESS. Nothing runs this for you.
//
// Renders the REAL renderer — real dist/renderer/*.js, real styles.css, real Chromium layout —
// in a real Electron window against a STUBBED `window.bridge`, and writes PNGs.
//
// ---------------------------------------------------------------------------------------------
// WHY THIS EXISTS
//
// Nobody had ever LOOKED at this product. Every card, every chart and every wizard screen was
// written and tested against a fake DOM (test/dashboard.dom.ts), which can prove that the right
// text lands in the right node and cannot say a single thing about whether the result is legible
// on the ₹25k 1366×768 PC it will actually run on. Layout, wrapping, overflow, contrast, and
// "does the number the owner came for dominate the screen" are invisible to those tests.
//
// It does NOT need better-sqlite3, and that is the whole point of the design. The app's real
// entry point boots the SQLite-backed sync store, which is compiled against Node's ABI (127) and
// dies under Electron's (148) — see scripts/rebuild-native-for-electron.mjs. Flipping that is a
// GLOBAL toggle that breaks `npm test` for the whole workspace. This harness sidesteps it
// entirely by stubbing at the `window.bridge` seam, which is exactly the seam the renderer was
// designed against: it reads nothing else.
//
// ---------------------------------------------------------------------------------------------
// WHAT IT DOES AND DOES NOT PROVE
//
// PROVES: real CSS cascade, real fonts, real flexbox/grid, real SVG rasterisation, real overflow
// and wrapping at a real viewport size. Anything you can see is real.
//
// DOES NOT PROVE: that the main process supplies data of this shape (that is the IPC contract's
// job, and reader.test.ts's), nor anything about SQLite, Tally, or the network. The fixtures
// below are hand-written to the CompanyCards type; if that type changes, this file must too, and
// the typecheck will not tell you — nothing imports it.
//
//   node scripts/visual-harness.mjs           # writes PNGs to .visual/
//   node scripts/visual-harness.mjs --show    # opens the window and leaves it open
//
// Requires: `npm run build` first (it renders dist/, not src/).

import { app, BrowserWindow } from 'electron';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const RENDERER = join(HERE, '../dist/renderer');
const OUT = join(HERE, '../.visual');

const SHOW = process.argv.includes('--show');

/**
 * The viewport that matters.
 *
 * 1366×768 is the single most common laptop resolution in the Indian SMB market and is what a
 * ₹25k shop PC ships with. Designing on a 1512×982 Mac and shipping to 768px of height is how a
 * dashboard's most important number ends up below the fold. If it does not work here, it does
 * not work.
 */
const VIEWPORTS = [
  { name: 'shop-pc-1366x768', width: 1366, height: 768 },
  { name: 'narrow-1024x768', width: 1024, height: 768 },
  // A 1080p shop PC at Windows 150% display scaling — the single most common real config, and
  // the one an owner reported numbers running "off the screen and sticking together" on. At 150%
  // the app sees ~853 effective CSS px, which is where a card that refuses to shrink pushes its
  // number past the window edge. If it reads here, it reads everywhere.
  { name: 'scaled-150pct-1280x720', width: 1280, height: 720, zoom: 1.5 },
];

/**
 * The setup screens, and why they get their own pass.
 *
 * These had NEVER been looked at, and they are the highest-stakes UI in the product: the
 * passphrase screen is where an owner picks the thing that protects every number they have, and
 * the recovery sheet is the only way back if they forget it. `visual-wizard-stub.cjs` drives the
 * REAL state machine to each of these, so every one is a state the product can genuinely be in.
 *
 * The wizard owns the whole window during setup (see main.ts) — there is no status strip — so
 * these render against `isProvisioned: false`.
 */
const WIZARD_SCREENS = ['findTally', 'pickCompany', 'connectCloud', 'setPassphrase', 'sheet', 'verify'];

async function shoot(win, name) {
  const img = await win.webContents.capturePage();
  const file = join(OUT, `${name}.png`);
  writeFileSync(file, img.toPNG());
  console.log(`  wrote ${file}`);
}

app.whenReady().then(async () => {
  mkdirSync(OUT, { recursive: true });

  for (const vp of VIEWPORTS) {
    const win = new BrowserWindow({
      width: vp.width,
      height: vp.height,
      show: SHOW,
      webPreferences: {
        // The stub has to exist BEFORE main.js runs, and main.js is a module that boots on load.
        // A preload is the only place that is reliably earlier. `contextIsolation: false` is
        // acceptable HERE and nowhere else: this window loads no remote content, and the point
        // is to inject a fake bridge, which is precisely what isolation exists to prevent.
        contextIsolation: false,
        nodeIntegration: false,
        // `sandbox: false` because a SANDBOXED preload gets a cut-down `require` that resolves
        // only electron and a few Node builtins — it cannot require a relative file, so the stub
        // module was "module not found" and the page booted with no bridge at all. (Which the
        // app then handled correctly, showing its "did not load correctly" screen: the harness
        // caught its own misconfiguration through the product's real error path.)
        //
        // The app's own windows keep `sandbox: true` and are tested for it (hardening.test.ts).
        // Nothing here changes that; this window loads a local file and exists to be lied to.
        sandbox: false,
        preload: join(HERE, 'visual-preload.cjs'),
        // Emulate Windows display scaling: zoomFactor 1.5 = 150%, shrinking the effective CSS
        // viewport exactly as a high-DPI shop PC does.
        zoomFactor: vp.zoom ?? 1,
      },
    });

    // Forward everything the page says. Without this a failure to paint is a silent black box:
    // the renderer routes every error to console.error by design (see `ask`), so the console IS
    // the diagnosis.
    win.webContents.on('console-message', (_e, level, message, line, source) => {
      console.log(`  [page:${level}] ${message}  (${source}:${line})`);
    });
    win.webContents.on('preload-error', (_e, path, error) => {
      console.log(`  [preload-error] ${path}: ${error.message}`);
    });

    await win.loadFile(join(RENDERER, 'index.html'));

    console.log(
      '  bridge installed:',
      await win.webContents.executeJavaScript('typeof window.bridge'),
    );
    // The renderer's boot() is async (it awaits isProvisioned, then getCards, then paints).
    // Rather than sleep and hope — the same mistake the wizard tests made — wait for the grid
    // to actually exist, and fail loudly if it never does.
    await win.webContents.executeJavaScript(`
      new Promise((resolve, reject) => {
        const t0 = Date.now();
        (function poll() {
          if (document.querySelector('.grid')) return resolve(true);
          if (Date.now() - t0 > 10000) return reject(new Error('no .grid after 10s — the dashboard never painted'));
          setTimeout(poll, 20);
        })();
      })
    `);
    // The DOM having a `.grid` is not the same as Chromium having DRAWN it. `capturePage`
    // returns whatever the compositor has, and the first attempt at this captured the
    // "Starting Tally Bridge…" placeholder while the grid already existed in the tree — a
    // screenshot of the past. Two rAFs put us after a committed frame.
    await win.webContents.executeJavaScript(`
      new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))
    `);

    // Say what is actually on screen, so a wrong screenshot is caught here rather than by me
    // squinting at a PNG.
    const seen = await win.webContents.executeJavaScript(`
      ({
        cards: [...document.querySelectorAll('.card h2, .card h3')].map(n => n.textContent),
        big: [...document.querySelectorAll('.big')].map(n => n.textContent),
        placeholder: document.body.textContent.includes('Starting Tally Bridge'),
      })
    `);
    console.log(`${vp.name}: cards = ${JSON.stringify(seen.cards)}`);
    console.log(`${vp.name}: headline numbers = ${JSON.stringify(seen.big)}`);
    if (seen.placeholder) throw new Error('the boot placeholder is still on screen');

    await shoot(win, `dashboard-${vp.name}`);
    // Full-page too: 768px of viewport cannot show a dashboard that scrolls, and "what is below
    // the fold" is a question only a full capture answers.
    const full = await win.webContents.executeJavaScript(
      `({ h: document.documentElement.scrollHeight })`,
    );
    if (full.h > vp.height) {
      win.setContentSize(vp.width, Math.min(full.h, 4000));
      await win.webContents.executeJavaScript(
        `new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`,
      );
      await shoot(win, `dashboard-${vp.name}-full`);
    }

    // `win.destroy()` tears the WebContents down synchronously, and the NEXT loadFile then races
    // it — the second viewport failed with ERR_FAILED (-2) every time. Closing after the loop,
    // once, is enough; these windows are hidden anyway.
    if (!SHOW) win.hide();
  }

  // ---- the setup wizard ----------------------------------------------------------------
  for (const screen of WIZARD_SCREENS) {
    const win = new BrowserWindow({
      width: 1366,
      height: 768,
      show: SHOW,
      webPreferences: {
        contextIsolation: false,
        nodeIntegration: false,
        sandbox: false,
        preload: join(HERE, 'visual-preload.cjs'),
        // The preload reads this to choose which stub to install; a preload has no argv.
        additionalArguments: [],
      },
    });
    process.env.TB_VISUAL_SCREEN = screen;

    win.webContents.on('console-message', (_e, level, message) => {
      if (level >= 2) console.log(`  [page:${level}] ${message}`);
    });
    await win.loadFile(join(RENDERER, 'index.html'));
    await win.webContents.executeJavaScript(`
      new Promise((resolve, reject) => {
        const t0 = Date.now();
        (function poll() {
          // The wizard paints a .wz-card. Waiting on the thing itself, not on a duration.
          // (No backticks in this comment: it lives INSIDE a template literal, and a stray pair
          // closed the literal early and made ".wz-card" evaluate as code — "card is not
          // defined". A comment that breaks the program is a fine reminder to read what you
          // paste into a string.)
          if (document.querySelector('.wz-card')) return resolve(true);
          if (Date.now() - t0 > 10000) return reject(new Error('the wizard never painted: ' + document.body.textContent.slice(0, 200)));
          setTimeout(poll, 20);
        })();
      })
    `);
    await win.webContents.executeJavaScript(
      `new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`,
    );
    const text = await win.webContents.executeJavaScript(`document.body.textContent.slice(0, 90)`);
    console.log(`wizard/${screen}: ${JSON.stringify(text)}`);
    await shoot(win, `wizard-${screen}`);
    if (!SHOW) win.hide();
  }
  delete process.env.TB_VISUAL_SCREEN;

  if (!SHOW) app.quit();
});
