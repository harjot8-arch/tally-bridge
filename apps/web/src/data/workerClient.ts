import type { WorkerRequest, WorkerResponse } from '../worker.ts';
import type { OpenedPass, UnlockDeps } from './unlock.ts';

/**
 * The MAIN-THREAD half of the unlock worker seam. `worker.ts` is the half that runs inside the
 * Worker; this half turns a Worker handle into the two injectable functions `unlock()` accepts.
 * Without it the worker protocol has no client, and the ~1s of Argon2id (x2) runs on the main
 * thread, freezing paint for the whole unlock.
 *
 * Deliberately typed against a MINIMAL structural interface rather than the DOM `Worker` class,
 * for the same reason `unlock()` takes `FetchLike`: the entire request/response protocol —
 * including the error-name rebuild that keeps a RosterError recognisable as an attack rather
 * than a typo — is then testable in Node against a real second thread (worker_threads uses the
 * same structured-clone algorithm as Web Workers), instead of being the one untested file in
 * the security path.
 *
 * WHAT CROSSES THE BOUNDARY, stated because it is key material: the passphrase goes IN (the
 * worker must run Argon2id over it — there is no way to keep it on one thread), and the
 * identity secret key comes OUT as a structured-clone copy. Both threads therefore hold key
 * material during unlock; `unlock()` wipes what it is given, and the worker's copies are
 * wiped by the inline implementations it delegates to. Same exposure as running inline, minus
 * the frozen page.
 */

/** `Omit` does not distribute over a union; this does — a request minus its correlation id. */
type WorkerRequestBody = WorkerRequest extends infer R
  ? R extends { id: number }
    ? Omit<R, 'id'>
    : never
  : never;

/** The subset of the Web Worker interface this client needs. A real `Worker` satisfies it. */
export interface WorkerLike {
  postMessage(msg: WorkerRequest): void;
  addEventListener(type: 'message', listener: (ev: { data: WorkerResponse }) => void): void;
}

/**
 * Wrap a Worker running `worker-entry.ts` into the `deriveAuthToken` / `openPassIdentity`
 * seams of `UnlockDeps`. Call once per Worker; requests are correlated by id, so concurrent
 * calls are safe.
 *
 * Note what is NOT here: no rollback logic, no storage, no decision of any kind. Those live in
 * `unlock()` outside the seam, precisely so that wiring this in or out cannot remove a check
 * (unlock.ts documents that placement).
 */
export function workerUnlockSeams(
  worker: WorkerLike,
): Required<Pick<UnlockDeps, 'deriveAuthToken' | 'openPassIdentity'>> {
  let nextId = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  worker.addEventListener('message', (ev) => {
    const res = ev.data as Partial<WorkerResponse> | null;
    if (typeof res !== 'object' || res === null || typeof res.id !== 'number') return;
    const p = pending.get(res.id);
    if (!p) return;
    pending.delete(res.id);
    if (res.ok === true) {
      p.resolve((res as { value: unknown }).value);
      return;
    }
    // Rebuilt with the NAME preserved. unlock.ts distinguishes `RosterError` by name to avoid
    // reporting an attack ("this bundle carries no roster / a rolled-back roster") as a typo'd
    // passphrase; that distinction must survive the thread boundary or the worker path would
    // be strictly less honest than the inline path.
    const failed = res as { name?: unknown; message?: unknown };
    const err = new Error(
      typeof failed.message === 'string' ? failed.message : 'the unlock worker failed',
    );
    err.name = typeof failed.name === 'string' && failed.name.length > 0 ? failed.name : 'Error';
    p.reject(err);
  });

  const call = (req: WorkerRequestBody): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ ...req, id } as WorkerRequest);
    });

  return {
    deriveAuthToken: async (passphrase, kdf) => {
      const v = await call({ op: 'derive-auth', passphrase, kdf });
      if (!(v instanceof Uint8Array)) {
        throw new Error('the unlock worker returned a non-binary auth token');
      }
      return v;
    },
    openPassIdentity: async (blob, passphrase) => {
      const v = await call({ op: 'open-pass', blob, passphrase });
      // Shape-checked rather than cast: the value crossed a structured-clone boundary, and a
      // malformed result must fail here with a named reason, not deep in openSection.
      const o = v as Partial<OpenedPass> | null;
      if (
        typeof o !== 'object' ||
        o === null ||
        !(o.identitySecretKey instanceof Uint8Array) ||
        !Array.isArray(o.roster) ||
        typeof o.rosterVersion !== 'number'
      ) {
        throw new Error('the unlock worker returned a malformed identity');
      }
      return { identitySecretKey: o.identitySecretKey, roster: o.roster, rosterVersion: o.rosterVersion };
    },
  };
}
