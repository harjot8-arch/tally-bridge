import type { KdfParams, WrappedKey } from '@tally-bridge/core';
import {
  KDF_INFO,
  RosterError,
  acceptRosterVersion,
  deriveRoot,
  hkdf,
  openIdentity,
  publicKeyFromSecret,
  sodiumReady,
  toBase64,
  wipe,
  type DeviceRoster,
} from '@tally-bridge/crypto';
import { ApiError, login, prelogin, wrappedKeys, type FetchLike } from './api.ts';
import { loadRosterMemory, saveRosterMark, type KV } from './marks.ts';

/**
 * The unlock flow: passphrase → session. Every step is the one the backend contracts dictate:
 *
 *   1. GET /api/prelogin?tenant=…      → Argon2id params (salt inside, base64)
 *   2. deriveRoot(passphrase, params)  → root                          [Argon2id run #1]
 *   3. hkdf(root, KDF_INFO.auth)       → authToken → POST /api/login   → HttpOnly cookie
 *   4. GET /api/wrapped-keys           → the 'pass' blob
 *   5. openIdentity(blob, passphrase)  → idSK + pinned roster          [Argon2id run #2]
 *   6. acceptRosterVersion + persist the high-water mark, THEN report unlocked.
 *
 * TWO ARGON2ID RUNS, measured and stated rather than hidden: step 2 derives from prelogin's
 * params to make the auth token, and step 5 re-derives inside `openIdentity` from the blob's own
 * embedded params — the only exported way to obtain a roster (trust.ts: that exclusivity is the
 * point, so it is not worked around here). The two parameter sets are the same value by server
 * construction (`storeWrappedKeys` writes the login credential's kdf from the pass blob itself),
 * which means the browser pays the derive cost twice for one unlock: ~0.95s measured on this
 * dev machine, and plausibly 4–8s on a mid-range Android — NOT measured, no such device here.
 * Halving it would need packages/crypto to export an `openIdentity` variant that accepts a
 * precomputed root; noted for that package's owner, not worked around by reimplementing the
 * unwrap out here (a second implementation of the trust chain is how it gets got wrong).
 *
 * THE ROLLBACK CHECK LIVES HERE, IN UNSEAMED CODE, and the placement is an argument, not an
 * accident. The desktop knows its idPK from the keystore BEFORE unlocking, so it can load the
 * idPK-scoped mark first and hand `openIdentity` real memory. The web cannot — the identity
 * public key is itself inside the sealed bundle, and scoping the mark by anything else (say,
 * tenantId) would make a legitimate "reset dashboard" on the Bridge — new identity, roster
 * honestly restarting at version 1 — indistinguishable from an attack, bricking the dashboard
 * until the owner clears site data. So the sequence is: open with `{ kind: 'first-use' }` (the
 * typed admission that THAT call performs no rollback check), compute idPK from the unwrapped
 * secret, load the idPK-scoped mark, and run `acceptRosterVersion` OURSELVES — before anything
 * is returned, before any envelope is opened. A rollback refuses the unlock with a sentence
 * that is deliberately NOT "wrong passphrase": misreporting an attack as a typo is the failure
 * mode the Bridge's session.ts documents, and it applies here verbatim.
 *
 * The mark is persisted BEFORE the session is reported unlocked, and a mark that cannot be
 * persisted to real storage FAILS the unlock (same rule as the desktop session) — with one
 * disclosed exception: a browser with NO storage at all runs on `memoryKV()`, whose
 * `persistent: false` the UI must surface as "no rollback protection in this browser". That is
 * the trust.ts fresh-reader residual made visible instead of silent.
 *
 * `deriveAuthToken` / `openPassIdentity` are injectable for exactly one reason: the entry point
 * runs them in a Web Worker so a multi-second Argon2id does not freeze the page (a frozen page
 * IS the dishonest unlock UI). The rollback decision is deliberately NOT inside those seams —
 * swapping the worker implementation in or out cannot remove the check.
 */

export type UnlockStage =
  | 'contacting'
  | 'deriving' // Argon2id #1 — the long one to warn about
  | 'signing-in'
  | 'fetching-keys'
  | 'opening' // Argon2id #2 + AEAD open
  | 'verifying';

/** What failed, for the UI to say one plain sentence about. Never a stack, never a status code. */
export type UnlockFailure =
  | 'credentials' // wrong tenant id or passphrase — deliberately indistinguishable
  | 'rate-limited'
  | 'not-set-up' // no deployment credential / no pass blob yet
  | 'rollback' // the server offered an OLDER roster than this browser has seen
  | 'damaged-memory' // this browser's saved safety mark is unreadable
  | 'no-storage' // the mark could not be persisted
  | 'network'
  | 'server';

export class UnlockError extends Error {
  readonly failure: UnlockFailure;
  constructor(failure: UnlockFailure, message: string) {
    super(message);
    this.name = 'UnlockError';
    this.failure = failure;
  }
}

export interface UnlockedSession {
  tenantId: string;
  identitySecretKey: Uint8Array;
  identityPublicKeyB64: string;
  /** From inside the sealed bundle via `openIdentity`. Feed to `openSection` and nothing else. */
  roster: DeviceRoster;
  rosterVersion: number;
  /** True when this browser had no memory for this identity — the fresh-reader residual. */
  firstUse: boolean;
  /** False when the mark lives in memoryKV(): rollback protection lasts this session only. */
  persistentMemory: boolean;
}

export interface OpenedPass {
  identitySecretKey: Uint8Array;
  roster: DeviceRoster;
  rosterVersion: number;
}

export interface UnlockDeps {
  fetch: FetchLike;
  storage: KV;
  onStage?: ((stage: UnlockStage) => void) | undefined;
  /** Worker seam. Default runs inline (and blocks the thread it runs on). */
  deriveAuthToken?: ((passphrase: string, kdf: KdfParams) => Promise<Uint8Array>) | undefined;
  /** Worker seam. MUST be `openIdentity` with `{ kind: 'first-use' }` — nothing else. */
  openPassIdentity?: ((blob: WrappedKey, passphrase: string) => Promise<OpenedPass>) | undefined;
}

/** Inline implementation of the auth-token derivation. Also what the worker runs. */
export async function deriveAuthTokenInline(passphrase: string, kdf: KdfParams): Promise<Uint8Array> {
  const root = await deriveRoot(passphrase, kdf);
  try {
    return await hkdf(root, KDF_INFO.auth);
  } finally {
    wipe(await sodiumReady(), root);
  }
}

/**
 * Inline implementation of the identity open. Also what the worker runs.
 *
 * `{ kind: 'first-use' }` is not this module skipping the rollback check — it is the check
 * being RELOCATED to `unlock()`, which cannot know the idPK-scoped memory until this returns.
 * See the header. `unlock()` calls `acceptRosterVersion` unconditionally on the result.
 */
export async function openPassIdentityInline(blob: WrappedKey, passphrase: string): Promise<OpenedPass> {
  const opened = await openIdentity(blob, { kind: 'pass', passphrase }, { kind: 'first-use' });
  return {
    identitySecretKey: opened.identitySecretKey,
    roster: opened.roster,
    rosterVersion: opened.rosterVersion,
  };
}

export async function unlock(deps: UnlockDeps, tenantId: string, passphrase: string): Promise<UnlockedSession> {
  const stage = deps.onStage ?? (() => {});
  const deriveAuth = deps.deriveAuthToken ?? deriveAuthTokenInline;
  const openPass = deps.openPassIdentity ?? openPassIdentityInline;

  const cleanTenant = tenantId.trim();
  if (cleanTenant.length === 0 || passphrase.length === 0) {
    throw new UnlockError('credentials', 'a Tally ID and a passphrase are both needed');
  }

  // 1. Params. Unknown tenants get a stable decoy (server's anti-enumeration), so a typo'd
  // tenant id surfaces later as a login failure, indistinguishable from a wrong passphrase —
  // which is the server's deliberate design, honoured here by mapping both to 'credentials'.
  stage('contacting');
  const params = await mapApi(prelogin(deps.fetch, cleanTenant), 'prelogin');

  // 2–3. The expensive derive, then login. A failure HERE is never a wrong passphrase — the
  // derive does not check the passphrase, it only runs Argon2id — so a throw means the crypto
  // engine (libsodium wasm in the worker) could not run. Surface that as its own fault, not as
  // "something went wrong": on a deployment whose CSP forgot 'wasm-unsafe-eval' this is exactly
  // where sign-in dies, and the owner needs a message that points at the engine, not their memory.
  stage('deriving');
  let authToken: Uint8Array;
  try {
    authToken = await deriveAuth(passphrase, params);
  } catch (e) {
    throw engineFault(e, 'deriving your key');
  }
  let authTokenB64: string;
  try {
    authTokenB64 = toBase64(authToken);
  } finally {
    wipe(await sodiumReady(), authToken);
  }

  stage('signing-in');
  try {
    await login(deps.fetch, cleanTenant, authTokenB64);
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      throw new UnlockError('credentials', 'that Tally ID and passphrase were not accepted');
    }
    throw mapApiError(e, 'login');
  }

  // 4. The pass blob.
  stage('fetching-keys');
  const keys = await mapApi(wrappedKeys(deps.fetch), 'wrapped-keys');
  const pass = keys.find((k) => k.kind === 'pass');
  if (!pass || !pass.kdf) {
    throw new UnlockError(
      'not-set-up',
      'this deployment has no passphrase-locked key yet — finish setup in the desktop app',
    );
  }

  // 5. Open. `openIdentity` derives from the BLOB'S OWN kdf params (they can legitimately
  // differ from prelogin's after a partially-failed re-wrap; the blob's are authoritative).
  stage('opening');
  let opened: OpenedPass;
  try {
    opened = await openPass(pass, passphrase);
  } catch (e) {
    if (e instanceof RosterError || (e as Error).name === 'RosterError') {
      // The AEAD tag verified and THEN the bundle was refused (no roster / malformed roster).
      // That is a setup or attack condition, never a typo — do not call it one.
      throw new UnlockError('not-set-up', (e as Error).message);
    }
    if ((e as Error).name === 'WorkerError') {
      // The worker died (wasm refused, worker load failed) mid-open. That is an engine fault, not
      // a wrong passphrase — mapping it to 'credentials' would send the owner chasing a typo that
      // does not exist. This is the mislabel the openPass default below would otherwise produce.
      throw engineFault(e, 'opening your identity');
    }
    // AEAD failure: login succeeded under prelogin's salt but the blob's own params disagree —
    // the one state where a wrong passphrase surfaces here rather than at login.
    throw new UnlockError('credentials', 'that Tally ID and passphrase were not accepted');
  }

  // 6. THE ROLLBACK DECISION. Unconditional, before anything is returned.
  stage('verifying');
  const idPkB64 = toBase64(await publicKeyFromSecret(opened.identitySecretKey));

  let memory;
  try {
    memory = loadRosterMemory(deps.storage, idPkB64);
  } catch {
    throw new UnlockError(
      'damaged-memory',
      'the safety record this browser keeps could not be read — clearing this site’s data resets it, which also resets rollback protection',
    );
  }

  let highWater: number;
  try {
    highWater = acceptRosterVersion(memory, opened.rosterVersion);
  } catch {
    throw new UnlockError(
      'rollback',
      'the server offered an older device list than this browser has already seen — someone may be replaying old data; do not trust this dashboard until the desktop app has synced again',
    );
  }

  try {
    saveRosterMark(deps.storage, idPkB64, highWater);
  } catch {
    // An unlock whose mark did not persist must not quietly mean "no rollback protection next
    // time" — the desktop fails closed here and so does this.
    throw new UnlockError('no-storage', 'this browser could not save its safety record');
  }

  return {
    tenantId: cleanTenant,
    identitySecretKey: opened.identitySecretKey,
    identityPublicKeyB64: idPkB64,
    roster: opened.roster,
    rosterVersion: opened.rosterVersion,
    firstUse: memory.kind === 'first-use',
    persistentMemory: deps.storage.persistent,
  };
}

/** Zero the secret key. Best-effort, same honesty as crypto's `wipe`. */
export async function lockSession(session: UnlockedSession): Promise<void> {
  wipe(await sodiumReady(), session.identitySecretKey);
}

async function mapApi<T>(p: Promise<T>, what: string): Promise<T> {
  try {
    return await p;
  } catch (e) {
    throw mapApiError(e, what);
  }
}

/**
 * A crypto-engine failure (worker died, wasm refused to instantiate) → a plain sentence that
 * points at the engine, NOT at the passphrase. Reuses 'server' (the UI switches on the message,
 * not the kind) and appends the short underlying reason so a deployment problem is diagnosable
 * without a stack trace ever reaching the owner.
 */
function engineFault(e: unknown, step: string): UnlockError {
  if (e instanceof UnlockError) return e;
  const detail = e instanceof Error && e.message ? ` (${e.message})` : '';
  return new UnlockError('server', `the sign-in engine could not start while ${step}${detail}`);
}

function mapApiError(e: unknown, what: string): UnlockError {
  if (e instanceof UnlockError) return e;
  if (e instanceof ApiError) {
    if (e.status === 0) return new UnlockError('network', 'the server could not be reached');
    if (e.status === 429) return new UnlockError('rate-limited', 'too many attempts — wait a while and try again');
    if (e.status === 503) return new UnlockError('not-set-up', 'the server is not set up yet — finish setup in the desktop app');
    if (e.status === 401) return new UnlockError('credentials', 'the session was not accepted');
    return new UnlockError('server', `the server refused the ${what} step`);
  }
  return new UnlockError('server', `the ${what} step failed`);
}
