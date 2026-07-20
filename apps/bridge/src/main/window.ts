import { app, BrowserWindow, session, shell, type BrowserWindowConstructorOptions } from 'electron';
import { join, resolve } from 'node:path';
import { CSP, isLocalAsset, safeExternalUrl } from './urls.ts';

/**
 * Electron hardening.
 *
 * Electron's secure configuration is OPT-IN, which is its central weakness versus Tauri: a
 * misconfigured Electron app hands a renderer XSS full Node.js access, and that is how the
 * Discord and Element RCE chains worked. This file is the whole hardening checklist in one
 * place so that it cannot be half-applied to a new window someone adds later.
 *
 * Two entry points, and BOTH are mandatory:
 *
 *   `hardenApp()`  — once, before any window exists. Everything here is enforced per-SESSION or
 *                    per-APP, so it covers webContents this file never sees: a window someone
 *                    adds in six months, a <webview>, a devtools pane, an OAuth popup.
 *   `createSecureWindow()` — every window in this app.
 *
 * The split matters. `createSecureWindow` alone is a convention, and conventions are what get
 * skipped at 5pm on a Friday. `hardenApp` is the backstop that holds when the convention fails.
 */

/** The directory the app's own assets live in. Nothing outside it is navigable. */
const APP_ROOT = resolve(import.meta.dirname, '..');

export interface SecureWindowOptions {
  width?: number;
  height?: number;
  show?: boolean;
  preloadPath?: string;
  /**
   * Attach NO preload. For windows that render a trusted constant and need no IPC — the fatal
   * error window in particular. A bridge that nothing calls is a bridge that cannot be abused.
   */
  noPreload?: boolean;
  /**
   * Run this window in its own session, so the session-wide CSP injected by `hardenApp` does not
   * reach it and the page's own <meta> policy is the only one in force.
   *
   * This exists for exactly one window — the fatal-error page — and the reason is CSP INTERSECTION.
   * When two policies cover a page, BOTH must allow: a <meta> tag granting `style-src
   * 'unsafe-inline'` cannot grant back what the session's `style-src 'self'` denies. Measured, not
   * assumed: with the shared session the fatal window's body background computes to
   * `rgba(0, 0, 0, 0)` instead of `rgb(11, 15, 20)` — i.e. the page a user only ever sees when
   * something is ALREADY broken was rendering unstyled.
   *
   * Why not the alternatives:
   *   - Loosening the session CSP to `'unsafe-inline'` would weaken every real window to style one
   *     error page. Backwards.
   *   - Serving the page from a file with a linked stylesheet would satisfy `style-src 'self'` —
   *     but a missing/corrupt `dist` is one of the very failures this window exists to REPORT, so
   *     it must not depend on the assets. It stays a self-contained data: URL.
   *
   * The isolated session is not a hole: the page carries `default-src 'none'` in its own <meta>,
   * has no preload, and renders a string this process wrote.
   */
  isolatedSession?: string;
}

export function createSecureWindow(opts: SecureWindowOptions = {}): BrowserWindow {
  const webPreferences: NonNullable<BrowserWindowConstructorOptions['webPreferences']> = {
    // Without this, a renderer XSS becomes `require('child_process')` — full RCE as the user.
    nodeIntegration: false,
    // nodeIntegration:false alone is NOT enough. Without contextIsolation the preload script
    // and the page share a JS context, so the page can reach through the preload's prototypes
    // to Node primitives. Both are required; neither is sufficient.
    contextIsolation: true,
    // OS-level sandbox on the renderer process. Limits the blast radius of a Chromium
    // 0-day to something the OS can contain.
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    // Deprecated but explicit: the remote module is arbitrary main-process access from the
    // renderer, which is the whole thing we are preventing.
    // @ts-expect-error removed in modern Electron; asserted for defence in depth if it returns
    enableRemoteModule: false,
    // Blocks <webview>, which would otherwise be a second, unhardened renderer.
    webviewTag: false,
    // Deny getUserMedia/geolocation/etc. by default — this app needs none of it.
    // (Enforced again via setPermissionRequestHandler below, which is what actually runs.)
    spellcheck: false,
    // DEVTOOLS OFF IN A PACKAGED BUILD.
    //
    // Not because devtools are an RCE — they are not. Because this window is a financial
    // dashboard on a shared business PC, and Ctrl+Shift+I is otherwise a live console over the
    // owner's receivables for whoever walks up to the machine. It stays on in development,
    // where the threat model is a developer.
    devTools: !app.isPackaged,
    ...(opts.noPreload
      ? {}
      // `.cjs`, not `.js`: a sandboxed preload must be CommonJS, and this package is ESM.
      // See the header of preload/index.cts.
      : { preload: opts.preloadPath ?? join(import.meta.dirname, '../preload/index.cjs') }),
    // In-memory (no `persist:` prefix): this session must not outlive the window or write to disk.
    ...(opts.isolatedSession ? { partition: opts.isolatedSession } : {}),
  };

  const win = new BrowserWindow({
    width: opts.width ?? 1180,
    height: opts.height ?? 820,
    minWidth: 900,
    minHeight: 640,
    show: opts.show ?? false,
    backgroundColor: '#0b0f14',
    // A frameless/hidden-until-ready window avoids the white flash that makes desktop apps
    // feel cheap on a slow machine — which is most of this market's hardware.
    titleBarStyle: 'default',
    webPreferences,
  });

  hardenWindow(win);
  return win;
}

/**
 * App-wide and session-wide hardening. Call ONCE, before any window is created.
 *
 * Everything in here is deliberately NOT per-window: these are the controls that must hold for
 * webContents that never went through `createSecureWindow`.
 */
export function hardenApp(): void {
  const ses = session.defaultSession;

  // Inject CSP on every response, rather than relying on a <meta> tag the renderer could be
  // tricked into not having. Registered on the SESSION, once — `onHeadersReceived` keeps only
  // the most recent listener, so calling this per-window (as this file used to) was one window
  // silently unregistering the previous window's policy.
  ses.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [CSP],
        'X-Content-Type-Options': ['nosniff'],
      },
    });
  });

  // This app needs no camera, microphone, geolocation, notifications, or clipboard-read.
  // Denying by default means a future feature has to ask deliberately.
  ses.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);

  // WebUSB / WebHID / Web Serial are a separate consent track from the permission handlers
  // above — denying "media" does not deny "hand me a USB device". This app talks to Tally over
  // HTTP and to nothing else, ever.
  ses.setDevicePermissionHandler(() => false);

  // The device CHOOSERS, which are a different gate again from the permission handler. Note the
  // documented trap: for these events, adding a listener that does NOT call preventDefault makes
  // Electron auto-select the first available device — i.e. a naive handler is WORSE than no
  // handler. preventDefault, then cancel with an empty selection.
  ses.on('select-usb-device', (event, _details, callback) => {
    event.preventDefault();
    callback(undefined);
  });
  ses.on('select-hid-device', (event, _details, callback) => {
    event.preventDefault();
    callback(null);
  });
  ses.on('select-serial-port', (event, _ports, _wc, callback) => {
    event.preventDefault();
    callback('');
  });

  // WEB-CONTENTS-CREATED IS THE BACKSTOP.
  //
  // Fires for EVERY webContents: windows added later that forget createSecureWindow, <webview>
  // tags, devtools panes. The per-window handlers below are applied here so that "someone added
  // a window and skipped the helper" is a bug, not a vulnerability.
  app.on('web-contents-created', (_event, contents) => {
    hardenContents(contents);

    // <webview> is a second renderer, and its webPreferences are set by the PAGE — an attacker
    // with XSS writes `<webview nodeintegration>` and has Node. `webviewTag: false` already
    // blocks the tag; this strips the dangerous attributes if it is ever turned on.
    contents.on('will-attach-webview', (event, webPreferences, params) => {
      delete webPreferences.preload;
      webPreferences.nodeIntegration = false;
      webPreferences.contextIsolation = true;
      if (!isLocalAsset(String(params.src ?? ''), APP_ROOT)) event.preventDefault();
    });
  });
}

/**
 * Apply the runtime half of the hardening to one webContents.
 *
 * The webPreferences above are the static half. These handlers are the half that stops a
 * COMPROMISED renderer from reaching outward.
 */
export function hardenWindow(win: BrowserWindow): void {
  hardenContents(win.webContents);
}

/**
 * Every webContents is hardened exactly once, however many times we are asked.
 *
 * Both paths legitimately fire for the same contents: `web-contents-created` during
 * `new BrowserWindow()`, then `hardenWindow` immediately after. Without this guard the
 * `select-*-device` handlers would each call their callback twice for one request, which
 * Electron does not expect, and the navigation handlers would stack duplicates.
 */
const hardened = new WeakSet<Electron.WebContents>();

function hardenContents(contents: Electron.WebContents): void {
  if (hardened.has(contents)) return;
  hardened.add(contents);

  // NAVIGATION LOCKDOWN.
  //
  // If a renderer is ever compromised, the first thing an attacker does is navigate it to a
  // page they control — which then inherits the preload bridge. This app is a local UI; it has
  // no legitimate reason to navigate anywhere outside its own bundle.
  contents.on('will-navigate', (event, url) => {
    if (!isLocalAsset(url, APP_ROOT)) event.preventDefault();
  });

  // `will-navigate` does NOT fire for subframes, and `default-src 'none'` blocks frames only
  // while the CSP is actually attached — which it is not on a data: URL. Belt and braces.
  contents.on('will-frame-navigate', (event) => {
    if (!isLocalAsset(event.url, APP_ROOT)) event.preventDefault();
  });

  // A 30x is a SECOND navigation that `will-navigate` never sees: it fired for the URL we
  // allowed, and the redirect target is chosen by whoever answered. Without this, one allowed
  // request is an open redirect into an attacker's page, in a window holding the bridge.
  contents.on('will-redirect', (event, url) => {
    if (!isLocalAsset(url, APP_ROOT)) event.preventDefault();
  });

  // Same for window.open / target=_blank. Anything genuinely external goes to the real browser,
  // where it lands in a normal sandbox with no bridge attached.
  contents.setWindowOpenHandler(({ url }) => {
    // Hand the OS the string we VALIDATED, not the one we were given.
    const safe = safeExternalUrl(url);
    if (safe) void shell.openExternal(safe);
    return { action: 'deny' };
  });

  // Web Bluetooth's chooser is per-webContents rather than per-session. Same trap as the device
  // choosers in hardenApp: no listener means "cancel", but a listener without preventDefault
  // means "silently pair with the first thing in radio range".
  contents.on('select-bluetooth-device', (event, _devices, callback) => {
    event.preventDefault();
    callback('');
  });

  // A renderer that crashes should not take the sync process with it — the Bridge's job is to
  // keep syncing even with no window open.
  contents.on('render-process-gone', (_e, details) => {
    console.error('[bridge] renderer gone:', details.reason);
  });
}
