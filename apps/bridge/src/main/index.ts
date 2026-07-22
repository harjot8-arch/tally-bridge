import { app, BrowserWindow, Menu, Tray, ipcMain, nativeImage, powerMonitor, safeStorage, shell } from 'electron';
import { basename, join } from 'node:path';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { SyncStore } from '@tally-bridge/sync';
import { SeqCounter } from '@tally-bridge/sync';
import { TallyTransport } from '@tally-bridge/tally';
import { Keystore, KeystoreUnavailableError, type KeystoreBackend } from './keystore.ts';
import { Scheduler, describeStatus, type SyncStatus } from './scheduler.ts';
import { humanError } from './errors.ts';
import { buildCycle } from './cycle.ts';
import { createSecureWindow, hardenApp } from './window.ts';
import { safeExternalUrl } from './urls.ts';
import { CHANNELS, type GetCardsResult, type MobileAccess } from './ipc.ts';
import { CapturingSyncStore, RosterMarkStore, SnapshotStore } from './snapshots.ts';
import { UnlockSession } from './session.ts';
import { buildCards } from './reader.ts';
import { detectTally } from './detect.ts';
import { WizardHostMain } from './wizard-host.ts';
import { createWizardEffects } from './wizard-effects.ts';
import QRCode from 'qrcode';

/**
 * The Electron shell.
 *
 * Deliberately thin. Everything with a failure mode worth testing — the keystore, the
 * scheduler, the sync cycle, the crypto, the Tally transport — lives in modules that do not
 * import Electron and are covered by tests that run in milliseconds. This file is wiring, and
 * wiring is what you want to be boring.
 */

// ---------------------------------------------------------------- single instance

/**
 * A second copy of this app would mean two schedulers hammering one single-threaded Tally, and
 * two writers to one SQLite file. Refuse, and surface the existing window instead — the owner
 * double-clicking the icon again means "show me", not "run another one".
 *
 * THE SHAPE HERE IS THE POINT, and it used to be wrong.
 *
 * `app.quit()` is ASYNCHRONOUS. It asks for a quit; it does not stop the current script. The
 * previous version called it and then fell through into the rest of this module, so a second
 * instance still registered `whenReady`, and — because quitting means closing windows and
 * unwinding, not halting — that callback could still fire before the process died. The second
 * instance would then open the SAME SQLite file with a second writer, start a second scheduler
 * against the single-threaded Tally, and rewrite the login item: exactly the three things this
 * lock exists to prevent, only now intermittently and only on slow machines.
 *
 * `return` cannot save us either — this is an ES module, and there is no function to return
 * from. So the bootstrap is a function, called on ONE branch of an if/else, at the BOTTOM of
 * this file (`main()`). Nothing here runs unless we hold the lock.
 *
 * The placement at the bottom is not stylistic. `bootstrap` reads module-level `let` state, and
 * those bindings are in the temporal dead zone until their declaration is evaluated — calling it
 * from the top works only for as long as it touches nothing, which is not a property anyone will
 * remember to preserve. Called last, the module is fully initialized and the hazard is gone.
 */

let tray: Tray | undefined;
let mainWindow: BrowserWindow | undefined;
let scheduler: Scheduler | undefined;
let keystore: Keystore | undefined;
let store: SyncStore | undefined;
let transport: TallyTransport | undefined;
let snapshots: SnapshotStore | undefined;
let session: UnlockSession | undefined;
let wizardHost: WizardHostMain | undefined;
let lastError: string | undefined;
let tallyReachable = false;

/** Started hidden by the auto-start entry; the owner sees a tray icon, not a window. */
const startedHidden = process.argv.includes('--hidden');

// ---------------------------------------------------------------- keystore backend

/**
 * File-backed keystore.
 *
 * The FILES are not the protection — safeStorage is. These blobs are ciphertext sealed to the
 * OS keychain; this backend only decides where they sit.
 *
 * WHICH IS WHY `mode: 0o600` BELOW BEING A NO-OP ON WINDOWS DOES NOT MATTER — and it is worth
 * saying out loud, because it looks like a bug. Node maps `mode` onto the read-only attribute on
 * Windows and nothing else; there is no ACL applied. What actually protects these files there is
 * that `%APPDATA%` is already user-scoped by its inherited ACL, and — the real answer — that
 * their CONTENTS are DPAPI ciphertext. The threat this design accepts is a process running as
 * the same Windows user, and that process can call CryptUnprotectData no matter what the file
 * mode says. See the header of keystore.ts: only revocable secrets are kept here, precisely
 * because file permissions were never the control.
 *
 * The mode is set anyway: it is a real control on macOS/Linux and free on Windows.
 */
function fileBackend(dir: string): KeystoreBackend {
  mkdirSync(dir, { recursive: true });

  /**
   * Key -> path.
   *
   * `encodeURIComponent` escapes `/` and `\` but NOT `.`, so it alone does not stop `..`. Every
   * key today is a compile-time constant from `K` in keystore.ts and none is attacker-reachable,
   * so this is not currently exploitable — which is exactly why it is worth pinning now, while
   * that is still true. The day someone keys a blob by company GUID or server-supplied device
   * id, the traversal is silent and the review that would have caught it is years in the past.
   */
  const p = (k: string) => {
    const name = `${encodeURIComponent(k)}.bin`;
    const full = join(dir, name);
    // Belt and braces: the encoded name must survive path resolution unchanged.
    if (basename(full) !== name || join(dir, basename(full)) !== full) {
      throw new Error('refusing to use an unsafe keystore key');
    }
    return full;
  };
  return {
    read: (k) => (existsSync(p(k)) ? readFileSync(p(k)) : undefined),
    write: (k, v) => writeFileSync(p(k), v, { mode: 0o600 }),
    delete: (k) => {
      if (existsSync(p(k))) rmSync(p(k));
    },
    has: (k) => existsSync(p(k)),
  };
}

// ---------------------------------------------------------------- lifecycle

function bootstrap(): void {
  // CHROMIUM'S SANDBOX, AND WHY THIS LINE IS NOT INSIDE whenReady.
  //
  // `app.enableSandbox()` THROWS if the app is already ready — Electron's own message is
  // "app.enableSandbox() can only be called before app is ready". It used to be the first
  // statement inside the `whenReady` callback, where that condition is true by definition. The
  // throw rejected the whenReady promise, so nothing after it ever ran: no keystore, no
  // scheduler, no tray, no window. The Bridge did not start at all, and because the rejection
  // surfaced as an unhandled promise rather than a crash at the failing line, it pointed
  // nowhere near this call.
  app.enableSandbox();

  // Session/app-wide hardening, before any window can exist. See window.ts.
  app.whenReady().then(onReady).catch(onFatalStartup);

  app.on('second-instance', () => {
    showMainWindow();
  });

  /**
   * Do NOT quit when the last window closes — on any platform.
   *
   * This inverts the usual Electron idiom on purpose. The Bridge's job is to keep syncing; the
   * window is just a viewer. An owner who closes the window means "hide this", not "stop
   * collecting my data". Quitting here would silently end sync and the dashboard would go stale
   * with no indication why.
   */
  app.on('window-all-closed', () => {
    // Intentionally empty. Quit is only ever via the tray menu.
  });

  app.on('before-quit', () => {
    session?.lock(); // zero the identity secret before anything else winds down
    wizardHost?.dispose(); // and the onboarding copy, if setup was mid-flight
    scheduler?.stop();
    store?.close();
  });
}

/**
 * Anything thrown out of startup lands here rather than in an unhandled rejection.
 *
 * An unhandled rejection in the main process is a silent death on some platforms and a Node
 * abort on others; either way the owner sees an app that "just doesn't open" and support has
 * nothing to go on. A window that names the problem is the minimum.
 */
function onFatalStartup(e: unknown): void {
  console.error('[bridge] fatal during startup:', e);
  showFatal(humanError(e));
}

function onReady(): void {
  hardenApp();

  try {
    keystore = new Keystore(safeStorage, fileBackend(join(app.getPath('userData'), 'keys')));
  } catch (e) {
    if (e instanceof KeystoreUnavailableError) {
      // Refuse to run rather than silently storing the device key in the clear. This is the
      // one startup failure worth blocking on — see keystore.ts.
      showFatal(e.message);
      return;
    }
    throw e;
  }

  // The reader's storage: sealed snapshots the outbox drain never touches, plus the roster
  // high-water mark. See snapshots.ts for why the dashboard cannot read the outbox itself.
  const readerDir = join(app.getPath('userData'), 'reader');
  snapshots = new SnapshotStore(readerDir);
  const rosterMarks = new RosterMarkStore(readerDir);

  // Same SyncStore, same sync.db — it additionally mirrors every enqueued envelope into the
  // snapshot store so the local dashboard survives the outbox draining.
  store = new CapturingSyncStore(join(app.getPath('userData'), 'sync.db'), snapshots);
  transport = new TallyTransport();

  // The unlock session. Note the shape of what it is given: it can READ the wrapped blob and
  // the high-water mark, and the only thing it can WRITE anywhere is a version number. There is
  // no path from this object to persisting key material.
  session = new UnlockSession({
    loadWrappedIdentity: () => keystore?.getWrappedIdentityForPassphrase(),
    loadMemory: () => rosterMarks.load(requireIdentityPkB64()),
    saveMemory: (v) => rosterMarks.save(requireIdentityPkB64(), v),
  });

  // A closing laptop lid or a sleeping office PC is the owner walking away: lock immediately
  // rather than letting the idle timer resume a stale countdown on wake.
  powerMonitor.on('suspend', () => session?.lock());

  scheduler = new Scheduler({
    runCycle: async () => {
      // Until setup completes there is nothing to sync — but the scheduler still ticks, so
      // that the moment onboarding finishes the first cycle is at most one interval away.
      const cycle = currentCycle();
      if (!cycle) return;
      await cycle();
      lastError = undefined;
      pushStatus();
    },
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (h) => clearInterval(h as NodeJS.Timeout),
    powerMonitor,
    now: () => Date.now(),
    onError: (e) => {
      // Never show a raw throw. Tally failures already carry a human sentence; anything else
      // gets a generic one, because an owner cannot act on a stack trace.
      lastError = humanError(e);
      pushStatus();
    },
  });

  registerIpc();
  createTray();
  scheduler.start();

  if (!startedHidden) showMainWindow();

  // AUTO-START.
  //
  // HKCU\...\Run via setLoginItemSettings — no admin rights, no installer, no service. See
  // scheduler.ts for why a Windows Service would be actively wrong here.
  app.setLoginItemSettings({
    openAtLogin: true,
    args: ['--hidden'],
  });
}

// ---------------------------------------------------------------- the cycle

/**
 * Build the sync cycle from whatever the keystore currently holds.
 *
 * Rebuilt each tick rather than cached, and deliberately: onboarding, a device re-pair, or a
 * "reset dashboard" all change these values mid-session, and a cycle closed over stale keys
 * would keep signing with a revoked device or sealing to a discarded identity — failing every
 * upload with a 401 that points nowhere. Rebuilding costs a few keystore reads per 15 minutes.
 */
function currentCycle(): (() => Promise<void>) | undefined {
  if (!keystore?.isProvisioned() || !store || !transport) return undefined;

  const identityPublicKey = keystore.getIdentityPublicKey();
  const deviceSecretKey = keystore.getDeviceSecretKey();
  const deviceId = keystore.getDeviceId();
  const tenantId = keystore.getTenantId();
  const serverUrl = keystore.getServerUrl();

  if (!identityPublicKey || !deviceSecretKey || !deviceId || !tenantId || !serverUrl) {
    return undefined;
  }

  // Persist `seq` across restarts. It is bound into the AAD so gaps are visible to the server;
  // it is NOT a nonce (the AEAD nonce is 192 random bits), so a rollback is an audit signal
  // rather than a break.
  const seq = new SeqCounter(keystore.getSeq());

  const cycle = buildCycle({
    transport,
    store,
    identityPublicKey,
    deviceSecretKey,
    deviceId,
    tenantId,
    serverUrl,
    seq,
    log: (e) => {
      if (e.kind === 'tally_unavailable') tallyReachable = false;
      if (e.kind === 'gate' || e.kind === 'uploaded') tallyReachable = true;
    },
  });

  return async () => {
    try {
      await cycle();
    } finally {
      // Persist even on failure: a cycle that sealed sections and then failed to upload has
      // already consumed those numbers, and reusing them would look like a replay to the
      // server. `current` reads without consuming — `next()` here would burn one per cycle.
      keystore?.setSeq(seq.current);
    }
  };
}

// ---------------------------------------------------------------- wizard wiring

/**
 * The setup wizard's main-process host, created on first use. The state machine and its trust
 * boundary live in wizard-host.ts; the real-world effects in wizard-effects.ts; the two
 * Electron-only effects (QR raster, print window) are the closures below.
 */
function ensureWizardHost(): WizardHostMain {
  if (wizardHost) return wizardHost;
  if (!keystore || !transport) throw new Error('bridge is still starting up');

  // A local diagnostic file for cloud setup — the owner sees a calm generic message, but the real
  // step + Vercel status lands here so a failed deployment is debuggable. Path is shown to the
  // user in the docs: %APPDATA%\Tally Bridge\logs\setup.log (Windows).
  const logDir = join(app.getPath('userData'), 'logs');
  const setupLog = join(logDir, 'setup.log');
  const debugLog = (line: string): void => {
    try {
      mkdirSync(logDir, { recursive: true });
      appendFileSync(setupLog, `${new Date().toISOString()} ${line}\n`);
    } catch {
      // Diagnostics must never take setup down.
    }
  };

  const effects = createWizardEffects({
    transport,
    keystore,
    debugLog,
    // PNG only. An SVG QR inside an <img> on the page that carries the bridge is a document,
    // not an image, and the renderer refuses it — see isQrDataUrl in the wizard renderer.
    qrPngDataUrl: (text) => QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 512 }),
    printHtml: (html) => printHtmlPage(html),
  });
  effects.onDone = () => {
    // Setup just committed the keystore: the next cycle has everything it needs, so it runs
    // now rather than up to fifteen minutes from now, and the tray flips out of "not set up".
    pushStatus();
    void scheduler?.syncNow().then(pushStatus, () => pushStatus());
  };

  wizardHost = new WizardHostMain(effects);
  wizardHost.subscribe((s) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(CHANNELS.wizardStateChanged, s);
    }
  });
  return wizardHost;
}

/**
 * Render trusted, self-generated HTML in a hidden window and open the print dialog.
 *
 * Its own session for the same reason the fatal window has one: the shared session's CSP would
 * intersect the sheet's inline styles away. No preload — the page needs no IPC, so it gets none.
 * The window is destroyed whatever happens; the sheet must not linger offscreen holding the
 * recovery key after the dialog closes.
 */
async function printHtmlPage(html: string): Promise<void> {
  const win = createSecureWindow({
    width: 840,
    height: 1100,
    show: false,
    noPreload: true,
    isolatedSession: 'print-sheet',
  });
  try {
    await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    await new Promise<void>((resolve, reject) => {
      win.webContents.print({ printBackground: true }, (success, failureReason) => {
        if (success) resolve();
        else reject(new Error(failureReason || 'printing was cancelled'));
      });
    });
  } finally {
    if (!win.isDestroyed()) win.destroy();
  }
}

// ---------------------------------------------------------------- reader wiring

/**
 * The identity public key as base64, for keying the roster high-water mark.
 *
 * Throws when absent rather than returning a sentinel: the mark store must never file a mark
 * under an empty key, and the session maps this throw to a fail-closed unlock. In practice the
 * unlock never gets this far unprovisioned — the wrapped blob is checked first — so this firing
 * means a half-written keystore, which deserves a refusal, not a default.
 */
function requireIdentityPkB64(): string {
  const pk = keystore?.getIdentityPublicKey();
  if (!pk) throw new Error('no identity public key in the keystore');
  return Buffer.from(pk).toString('base64');
}

// ---------------------------------------------------------------- tray

function createTray(): void {
  // An empty image is a valid placeholder; a real icon ships with the packaged app.
  tray = new Tray(nativeImage.createEmpty());
  tray.setToolTip('Tally Bridge');
  refreshTrayMenu();
  tray.on('click', showMainWindow);
}

function refreshTrayMenu(): void {
  if (!tray) return;
  const status = currentStatus();
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: statusLabel(status), enabled: false },
      { type: 'separator' },
      { label: 'Open dashboard', click: showMainWindow },
      { label: 'Sync now', click: () => void scheduler?.syncNow() },
      { type: 'separator' },
      { label: 'Quit Tally Bridge', click: () => app.quit() },
    ]),
  );
}

function statusLabel(s: SyncStatus): string {
  switch (s.state) {
    case 'ok':
      return 'Synced';
    case 'waiting':
      return 'Waiting for Tally';
    case 'error':
      return s.message;
    case 'never':
      return 'Not synced yet';
  }
}

// ---------------------------------------------------------------- windows

function showMainWindow(): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    return;
  }
  mainWindow = createSecureWindow({ preloadPath: join(import.meta.dirname, '../preload/index.cjs') });
  void mainWindow.loadFile(join(import.meta.dirname, '../renderer/index.html'));
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => {
    mainWindow = undefined;
  });
}

/**
 * The one window that must render when everything else is broken.
 *
 * A data: URL rather than a file, so this works even if the renderer bundle is what broke. Two
 * things about that choice were wrong and are fixed here:
 *
 *  1. NO PRELOAD. `createSecureWindow` attaches the bridge by default, so this window — the one
 *     showing an unstyled constant, needing no IPC at all — was carrying the full main-process
 *     API. Nothing needs it; nothing gets it.
 *  2. AN INLINE CSP, ON ITS OWN SESSION. The previous version of this comment claimed
 *     `onHeadersReceived` "fires for network responses [and] a data: URL is not a network
 *     response, so this window was the ONE page with no policy attached". That is FALSE, and it
 *     was measured: the listener DOES fire for data: URLs. Which made this page the one window
 *     carrying TWO policies — and CSP policies INTERSECT, so the <meta> tag's `style-src
 *     'unsafe-inline'` could not grant back what the session's `style-src 'self'` denied. The
 *     body background computed to rgba(0,0,0,0) instead of #0b0f14: the page a user only ever
 *     sees when something is already broken was rendering unstyled.
 *
 *     `isolatedSession` puts it on its own session so the <meta> policy really is the only one in
 *     force — which is what the old comment believed was already true. See window.ts for why the
 *     alternatives (loosening the shared CSP; linking a stylesheet) are worse.
 *
 * `message` should be one of our own sentences (`humanError` guarantees that), but it is escaped
 * regardless: "the input is trusted" is a claim that decays, and this is the error path, which is
 * where trusted inputs go to become untrusted ones.
 */
function showFatal(message: string): void {
  const win = createSecureWindow({
    width: 620,
    height: 320,
    show: true,
    noPreload: true,
    isolatedSession: 'fatal-error',
  });
  const csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'";
  void win.loadURL(
    'data:text/html;charset=utf-8,' +
      encodeURIComponent(
        `<html><head><meta charset="utf-8">` +
          `<meta http-equiv="Content-Security-Policy" content="${csp}"></head>` +
          `<body style="font:15px system-ui;padding:36px;background:#0b0f14;color:#e6edf3">
           <h2 style="margin:0 0 12px">Tally Bridge cannot start</h2>
           <p style="color:#9fb0c0;line-height:1.5">${escapeHtml(message)}</p>
         </body></html>`,
      ),
  );
}

/**
 * Escape for an HTML text node.
 *
 * `&<>"'` is the correct set for text-node and quoted-attribute contexts, and everything
 * interpolated here is a text node. It is NOT sufficient for an unquoted attribute (where space
 * and backtick matter) or inside a <script>/<style> — so do not reuse this without checking the
 * context. The numeric form `&#38;` is used because it needs no named-entity table to be right.
 */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

// ---------------------------------------------------------------- status

function currentStatus(): SyncStatus {
  return describeStatus({
    lastRun: scheduler?.lastRun ?? 0,
    lastError,
    tallyReachable,
    now: Date.now(),
  });
}

function pushStatus(): void {
  refreshTrayMenu();
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(CHANNELS.statusChanged, currentStatus());
  }
}

// ---------------------------------------------------------------- ipc

function registerIpc(): void {
  ipcMain.handle(CHANNELS.getStatus, () => currentStatus());
  ipcMain.handle(CHANNELS.isProvisioned, () => keystore?.isProvisioned() ?? false);

  ipcMain.handle(CHANNELS.syncNow, async () => {
    await scheduler?.syncNow();
    pushStatus();
  });

  ipcMain.handle(CHANNELS.detectTally, async () => {
    if (!transport) {
      return { reachable: false, message: 'Tally Bridge is still starting up. Try again.', companies: [] };
    }
    // The transport serialises requests process-wide, so this probe queues politely behind any
    // in-flight sync cycle rather than doubling up on a single-threaded Tally.
    return detectTally(transport);
  });

  ipcMain.handle(CHANNELS.getCards, async (): Promise<GetCardsResult> => {
    // `current()` is also the activity signal: reading cards re-arms the auto-lock timer.
    const open = session?.current();
    if (!open) {
      const problem = session?.problem;
      return problem === undefined ? { state: 'locked' } : { state: 'locked', problem };
    }

    const tenantId = keystore?.getTenantId();
    const identityPublicKey = keystore?.getIdentityPublicKey();
    if (!tenantId || !identityPublicKey || !snapshots) {
      // Unlocked but the install is half-provisioned. Nothing to decrypt yet.
      return { state: 'empty' };
    }

    try {
      const { slots, unreadable } = snapshots.list();
      return await buildCards({
        slots,
        unreadable,
        tenantId,
        identityPublicKey,
        identitySecretKey: open.identitySecretKey,
        roster: open.roster,
        log: (m) => console.error(m),
      });
    } catch (e) {
      // Nothing thrown by the reader may cross to the renderer: an IPC rejection carries the
      // raw message into renderer devtools, and stack traces are not a UI.
      console.error('[bridge] getCards failed:', e);
      return { state: 'error', message: 'Your saved dashboard data could not be read on this computer.' };
    }
  });

  /**
   * unlock: false for EVERY failure, with no distinction the renderer could relay. The one
   * deliberate exception — "your passphrase was right but the key bundle is not safe to use",
   * which must never be misreported as a typo — travels as the `problem` sentence on the locked
   * getCards state, written for the owner.
   */
  ipcMain.handle(CHANNELS.unlock, async (_e, passphrase: unknown) => {
    if (!session) return false;
    const result = await session.unlock(passphrase);
    return result.ok;
  });

  ipcMain.handle(CHANNELS.lock, async () => {
    session?.lock();
  });

  // The forgotten-passphrase reset. Lock FIRST (zero any live key), then wipe ALL of this
  // machine's local state, because a partial wipe is worse than none: keeping the old snapshots
  // (sealed to the DISCARDED identity) makes the new identity's dashboard read "data could not be
  // read", and keeping the sync watermarks makes the next sync report "nothing changed" and write
  // no fresh snapshots — so the dashboard never recovers. Clear the keystore (→ isProvisioned()
  // false → route() shows the wizard), the snapshot store, and the sync watermarks/hashes/outbox.
  // Destructive and irreversible on this machine; the renderer gates it behind a confirmation.
  ipcMain.handle(CHANNELS.resetDashboard, async () => {
    session?.lock();
    keystore?.wipe();
    snapshots?.clear();
    store?.reset();
  });

  // ---- Setup wizard. The machine is the authority; these verbs are its only doorway. ----

  ipcMain.handle(CHANNELS.getWizardState, async () => ensureWizardHost().getState());

  // The payload is UNTRUSTED renderer input. `sendFromRenderer` validates it against the
  // machine's own union, accepts intent events only, and drops driver facts — see wizard-host.ts
  // for why a renderer that could assert facts could jump the recovery-verification gate.
  ipcMain.handle(CHANNELS.sendWizardEvent, async (_e, event: unknown) =>
    ensureWizardHost().sendFromRenderer(event),
  );

  ipcMain.handle(CHANNELS.recoveryQr, async () => ensureWizardHost().recoveryQr());

  ipcMain.handle(CHANNELS.printRecoverySheet, async () => ensureWizardHost().printRecoverySheet());

  /**
   * openExternal is validated HERE, in the main process — never trusted from the renderer.
   *
   * `shell.openExternal` executes whatever protocol handler the URL names, so an unvalidated
   * URL from a compromised renderer is a code-execution primitive on Windows, not a
   * convenience.
   *
   * This used to be a hand-copied second version of the allowlist in window.ts. Two copies of a
   * security control is one control and one liability: they were identical on the day they were
   * written and nothing made them stay that way, so hardening one (as this audit did) would
   * silently leave the other — the one a compromised renderer actually calls — behind. There is
   * now exactly one implementation, in urls.ts, and both call sites import it.
   */
  ipcMain.handle(CHANNELS.openExternal, async (_e, url: unknown) => {
    if (typeof url !== 'string') return;
    const safe = safeExternalUrl(url);
    if (!safe) return;
    await shell.openExternal(safe);
  });

  /**
   * The details for opening this dashboard on a phone. Nothing secret: the deployment URL is
   * public and the Tally ID is a login handle, not a key — the passphrase is never involved and
   * never crosses. Returns null until the deployment exists. The QR encodes the URL only.
   */
  ipcMain.handle(CHANNELS.getMobileAccess, async (): Promise<MobileAccess | null> => {
    const url = keystore?.getServerUrl();
    const tenantId = keystore?.getTenantId();
    if (!url || !tenantId) return null;
    const qr = await QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 2, width: 512 });
    return { url, tenantId, qr };
  });
}

// ---------------------------------------------------------------- entry point

/**
 * The only statement in this module that RUNS at import time. See the single-instance note at
 * the top for why the losing instance must not fall through into `bootstrap`.
 */
function main(): void {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return;
  }
  bootstrap();
}

main();
