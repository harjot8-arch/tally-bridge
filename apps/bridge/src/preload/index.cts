import { contextBridge, ipcRenderer } from 'electron';
import type { CHANNELS as MainChannels, BridgeApi } from '../main/ipc.ts';
import type { SyncStatus } from '../main/scheduler.ts';

/**
 * The preload bridge.
 *
 * This file runs with access to Node primitives and shares a window with untrusted-ish page
 * code, which makes it the single highest-value target in the app. Two rules keep it safe:
 *
 *   1. Expose FUNCTIONS, never OBJECTS. `contextBridge` deep-clones across the boundary, so
 *      handing over an object with methods can leak prototypes; a flat record of closures
 *      cannot.
 *   2. NO GENERIC PASSTHROUGH. There is no `invoke(channel, ...args)` here. Every verb is
 *      enumerated and its channel is a compile-time constant, so a renderer cannot pick the
 *      channel — which is what stops an XSS from calling arbitrary main-process handlers.
 *
 * WHY THIS FILE IS `.cts`, AND WHY IT IMPORTS NOTHING BUT `electron`.
 *
 * `sandbox: true` (window.ts) is not just a renderer control — it changes how THIS file is
 * loaded. A sandboxed preload is not run through Node's module loader at all: Electron reads it
 * and executes it in the sandboxed context behind a CommonJS wrapper, where `require` is a
 * limited polyfill that resolves `electron` and a handful of builtins AND NOTHING ELSE. Two
 * consequences, both of which this app got wrong and neither of which fails loudly:
 *
 *   1. IT MUST BE COMMONJS. This package is `"type": "module"`, so a `.ts` file emits ESM and
 *      the preload dies on its `import` statement — `contextBridge.exposeInMainWorld` never
 *      runs, `window.bridge` is `undefined`, and the entire IPC bridge is unreachable while the
 *      app otherwise looks fine. The `.cts` extension is what makes `tsc` emit `index.cjs` as
 *      CommonJS under `module: nodenext`, in a package that is ESM everywhere else.
 *   2. IT MUST NOT REQUIRE LOCAL FILES. `require('../main/ipc.js')` is not resolvable by that
 *      polyfill, and it would be an ESM file besides. So the channel names below are a LOCAL
 *      copy, not an import.
 *
 * That copy is the one duplicated fact in the bridge, so it is checked by the compiler rather
 * than by review: `satisfies typeof MainChannels` fails the build if a channel is added,
 * removed, renamed, or given a different string in `main/ipc.ts`. A drifted channel would
 * otherwise be a silent dead verb — `invoke` on a channel with no handler rejects at runtime,
 * in production, on someone else's machine.
 */

const CHANNELS = {
  getStatus: 'bridge:getStatus',
  syncNow: 'bridge:syncNow',
  getCards: 'bridge:getCards',
  unlock: 'bridge:unlock',
  lock: 'bridge:lock',
  isProvisioned: 'bridge:isProvisioned',
  detectTally: 'bridge:detectTally',
  listCompanies: 'bridge:listCompanies',
  openExternal: 'bridge:openExternal',
  statusChanged: 'bridge:statusChanged',
  getWizardState: 'bridge:getWizardState',
  sendWizardEvent: 'bridge:sendWizardEvent',
  wizardStateChanged: 'bridge:wizardStateChanged',
  recoveryQr: 'bridge:recoveryQr',
  printRecoverySheet: 'bridge:printRecoverySheet',
} as const satisfies typeof MainChannels;

/** The app needs one. The margin is for a hot-reload during development, not for page code. */
const MAX_STATUS_LISTENERS = 8;

/**
 * Subscribe to a push channel, with the same two protections as onStatusChanged: the raw
 * IpcRendererEvent (whose `sender` is a live handle into the main process) never reaches page
 * code, and the subscription count is bounded so page code cannot pin callbacks in a loop.
 */
function subscribe<T>(channel: string, cb: (value: T) => void): () => void {
  const listener = (_e: unknown, value: T) => cb(value);
  if (ipcRenderer.listenerCount(channel) >= MAX_STATUS_LISTENERS) {
    throw new Error('too many listeners');
  }
  ipcRenderer.on(channel, listener);
  let removed = false;
  return () => {
    // Idempotent: a double-unsubscribe must not remove a LATER subscriber's listener.
    if (removed) return;
    removed = true;
    ipcRenderer.removeListener(channel, listener);
  };
}

const api: BridgeApi = {
  getStatus: () => ipcRenderer.invoke(CHANNELS.getStatus),
  syncNow: () => ipcRenderer.invoke(CHANNELS.syncNow),
  isProvisioned: () => ipcRenderer.invoke(CHANNELS.isProvisioned),
  detectTally: () => ipcRenderer.invoke(CHANNELS.detectTally),
  // The passphrase crosses this boundary once, is used to derive a key in the main process,
  // and is never persisted anywhere. It must not be logged, and it must not be echoed back.
  unlock: (passphrase: string) => ipcRenderer.invoke(CHANNELS.unlock, passphrase),
  lock: () => ipcRenderer.invoke(CHANNELS.lock),
  getCards: () => ipcRenderer.invoke(CHANNELS.getCards),
  openExternal: (url: string) => ipcRenderer.invoke(CHANNELS.openExternal, url),

  onStatusChanged: (cb: (s: SyncStatus) => void) => subscribe(CHANNELS.statusChanged, cb),

  // ---- Setup wizard. Enumerated verbs, like everything else — the machine runs in main. ----
  getWizardState: () => ipcRenderer.invoke(CHANNELS.getWizardState),
  // The event may carry a token or passphrase the user just typed: it crosses once, is
  // validated and consumed in the main process, and is never echoed back or logged.
  sendWizardEvent: (event) => ipcRenderer.invoke(CHANNELS.sendWizardEvent, event),
  onWizardStateChanged: (cb) => subscribe(CHANNELS.wizardStateChanged, cb),
  recoveryQr: () => ipcRenderer.invoke(CHANNELS.recoveryQr),
  printRecoverySheet: () => ipcRenderer.invoke(CHANNELS.printRecoverySheet),
};

contextBridge.exposeInMainWorld('bridge', api);
