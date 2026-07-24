// Milestone 1: back window.bridge with Tauri instead of Electron's ipcRenderer.
//
// The renderer reads only window.bridge (BridgeApi in apps/bridge/src/main/ipc.ts). This maps
// each verb to the matching snake_case Rust command via invoke(), and the two push subscriptions
// to listen(). Setting the global is the whole job — tauri-entry.ts imports this for its side
// effect BEFORE the renderer boots.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { detectTallyViaBridge } from './tally-detect.ts';

// listen() resolves to an UnlistenFn. BridgeApi wants a SYNCHRONOUS unsubscribe, so we hand back
// a closure that awaits the pending registration and then calls it. In Milestone 1 these events
// never fire; the plumbing just has to be shaped right.
function subscribe(event: string, cb: (payload: unknown) => void): () => void {
  const pending = listen<unknown>(event, (e) => cb(e.payload));
  return () => {
    void pending.then((unlisten) => unlisten());
  };
}

(window as any).bridge = {
  getStatus: () => invoke('get_status'),
  syncNow: () => invoke('sync_now'),
  getCards: () => invoke('get_cards'),
  unlock: (passphrase: string) => invoke('unlock', { passphrase }),
  lock: () => invoke('lock'),
  resetDashboard: () => invoke('reset_dashboard'),
  rebuildFromTally: () => invoke('rebuild_from_tally'),
  isProvisioned: () => invoke('is_provisioned'),
  // M3: real company enumeration — encode the request, POST via the Rust byte-pipe, parse with the
  // reused codec. (Rust's detect_tally remains as a reachability-only fallback.)
  detectTally: () => detectTallyViaBridge(invoke),
  openExternal: (url: string) => invoke('open_external', { url }),
  getMobileAccess: () => invoke('get_mobile_access'),
  getWizardState: () => invoke('get_wizard_state'),
  sendWizardEvent: (event: unknown) => invoke('send_wizard_event', { event }),
  recoveryQr: () => invoke('recovery_qr'),
  printRecoverySheet: () => invoke('print_recovery_sheet'),
  onStatusChanged: (cb: (s: unknown) => void) => subscribe('status_changed', cb),
  onWizardStateChanged: (cb: (s: unknown) => void) => subscribe('wizard_state_changed', cb),
};
