import type { KdfParams, WrappedKey } from '@tally-bridge/core';
import { deriveAuthTokenInline, openPassIdentityInline } from './data/unlock.ts';

/**
 * The unlock worker: the two Argon2id-bearing operations, off the main thread.
 *
 * Argon2id at m=64MiB is measured at ~0.5s per run on this dev machine, twice per unlock
 * (see unlock.ts). Run on the main thread, that freezes rendering — the status line cannot even
 * paint, which is precisely the "looks frozen" failure the unlock UI must not have. The owner's
 * UI should load `worker-entry.ts` as a Web Worker and pass the seams from
 * `data/workerClient.ts` into `unlock()`; when `Worker` is unavailable, omit them and unlock
 * runs inline (and blocks whatever thread it runs on). NOTE: nothing in src creates a Worker —
 * this package has no entry point by design (the owner's UI is the caller), so the worker path
 * only runs if the UI wires it. README.md states this obligation.
 *
 * WHAT DOES **NOT** RUN HERE, on purpose: the rollback decision (`acceptRosterVersion` + the
 * mark) stays in unlock.ts, outside the injectable seam — so wiring this worker in or out
 * cannot remove that check. This file only computes; it decides nothing.
 *
 * The protocol is structured-clone-friendly: Uint8Arrays cross intact. Errors cross as
 * `{ name, message }` and are rebuilt with the name preserved — unlock.ts distinguishes
 * `RosterError` by name to avoid calling an attack a typo, and that must survive the boundary.
 */

export type WorkerRequest =
  | { id: number; op: 'derive-auth'; passphrase: string; kdf: KdfParams }
  | { id: number; op: 'open-pass'; blob: WrappedKey; passphrase: string };

export type WorkerResponse =
  | { id: number; ok: true; value: unknown }
  | { id: number; ok: false; name: string; message: string };

export interface WorkerScopeLike {
  onmessage: ((ev: { data: WorkerRequest }) => void) | null;
  postMessage(msg: WorkerResponse): void;
}

export function startWorker(scope: WorkerScopeLike): void {
  scope.onmessage = (ev) => {
    const req = ev.data;
    void (async () => {
      try {
        const value =
          req.op === 'derive-auth'
            ? await deriveAuthTokenInline(req.passphrase, req.kdf)
            : await openPassIdentityInline(req.blob, req.passphrase);
        scope.postMessage({ id: req.id, ok: true, value });
      } catch (e) {
        const err = e as Error;
        scope.postMessage({ id: req.id, ok: false, name: err.name || 'Error', message: err.message });
      }
    })();
  };
}
