import type { WrappedKey } from '@tally-bridge/core';
import {
  RosterError,
  openIdentity,
  type DeviceRoster,
  type RosterMemory,
  type UnwrappedIdentity,
} from '@tally-bridge/crypto';

/**
 * The unlock session — the ONLY place in the Bridge where the identity secret key exists.
 *
 * The Bridge's standing state holds the identity PUBLIC key and nothing that reads data; that is
 * the product's core property and it is not weakened here. What this class adds is the READER
 * path: the owner types the passphrase, `openIdentity` unwraps idSK plus the pinned roster, and
 * both live in THIS PROCESS'S MEMORY for the session and nowhere else.
 *
 * The rules, each enforced below rather than merely stated:
 *
 *   - idSK is NEVER PERSISTED. The session's dependencies make that structural: the only write
 *     capability injected is `saveMemory(version: number)` — a number, not bytes. There is no
 *     keystore handle in here to misuse, and the keystore itself has no secret-key setter
 *     (hardening.test.ts fails the build if one appears).
 *   - LOCK ZEROES. `lock()` overwrites the key bytes before dropping the reference. Best-effort,
 *     honestly stated: it narrows the heap-dump window; it cannot reach the immutable base64
 *     string that briefly existed inside `openIdentity`.
 *   - AUTO-LOCK. This is a financial dashboard on a shared office PC. An idle session relocks
 *     after IDLE_MS (15 minutes): long enough that the owner reading cards over chai is not
 *     nagged, short enough that the machine left unlocked over lunch is not an open ledger.
 *     Re-unlocking costs one passphrase entry and ~half a second of Argon2id — cheap. The app
 *     additionally locks on quit and on machine suspend (wired in index.ts), because a laptop
 *     lid closing IS the owner walking away.
 *   - GUESSING IS THROTTLED. Argon2id already prices a guess at ~460ms, but that is a floor an
 *     attacker with renderer-XSS could still script. After MAX_FAILURES consecutive failures the
 *     session refuses attempts for COOLDOWN_MS without spending a derive. The counter resets on
 *     success. This is deliberately mild — the person typing is almost always the owner with a
 *     typo — but it turns "unlimited tries at 2/sec" into "20 tries a minute, forever loud".
 *   - THE ROLLBACK MEMORY IS CONSULTED AND ADVANCED ON EVERY UNLOCK. `loadMemory` runs before
 *     the derive; `saveMemory` runs after `openIdentity` succeeds and BEFORE the session is
 *     considered unlocked. An unlock whose mark cannot be persisted fails closed — otherwise
 *     "unlocked" could quietly mean "unlocked with no rollback protection next time".
 *
 * WRONG PASSPHRASE vs EVERYTHING ELSE. The IPC contract says unlock() returns false and never
 * says which part was wrong — right for a wrong passphrase, catastrophically wrong for a roster
 * rollback, which is an attack being misreported as a typo. So the session keeps `problem`: a
 * single owner-readable sentence, set ONLY for failures that are provably not the passphrase
 * (RosterError fires after the AEAD tag verified). It is exposed through getCards' locked state.
 * A wrong passphrase sets no problem, and no message anywhere reveals which check failed.
 */

/** 15 minutes of inactivity. See the header for the defence. */
export const IDLE_MS = 15 * 60 * 1000;

export const MAX_FAILURES = 5;
export const COOLDOWN_MS = 15_000;

/** Longest passphrase we will feed Argon2id. Real passphrases are sentences, not payloads. */
const MAX_PASSPHRASE_LENGTH = 1024;

export interface OpenSession {
  /** X25519 identity secret key. Owned by the session — do not store, do not persist. */
  identitySecretKey: Uint8Array;
  /** The pinned roster from inside the sealed bundle. Feed to `openSection` and nothing else. */
  roster: DeviceRoster;
  rosterVersion: number;
}

export type UnlockResult = { ok: true } | { ok: false };

export interface SessionDeps {
  /**
   * The passphrase-wrapped identity blob, as JSON, from the local keystore. This is ciphertext
   * under an Argon2id-derived KEK — the same blob the server stores — so holding a copy locally
   * adds no exposure and removes the network from the unlock path.
   */
  loadWrappedIdentity: () => string | undefined;
  /** The persisted roster high-water mark. MUST throw (not default) on corrupt storage. */
  loadMemory: () => RosterMemory;
  /** Persist the new high-water mark. Called before the session unlocks; a throw fails the unlock. */
  saveMemory: (highestVersionSeen: number) => void;
  now?: () => number;
  idleMs?: number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  /** Test seam only. Production uses the real openIdentity. */
  open?: typeof openIdentity;
}

export class UnlockSession {
  private readonly deps: SessionDeps;
  private readonly now: () => number;
  private readonly idleMs: number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private readonly open: typeof openIdentity;

  private state: OpenSession | undefined;
  private idleHandle: unknown;
  private failures = 0;
  private cooldownUntil = 0;
  /**
   * One plain sentence for the owner when the last unlock failed for a NON-passphrase reason.
   * `undefined` after a wrong passphrase — that case must stay indistinguishable.
   */
  private lastProblem: string | undefined;
  /** Serialises unlock attempts: concurrent IPC calls must not pile up Argon2id derives. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(deps: SessionDeps) {
    this.deps = deps;
    this.now = deps.now ?? (() => Date.now());
    this.idleMs = deps.idleMs ?? IDLE_MS;
    // `unref` so the idle timer never holds the process open on its own: locking an already
    // otherwise-dead process is work with no audience. Electron's main loop keeps the app
    // alive regardless, so in production this changes nothing about when the lock fires.
    this.setTimer =
      deps.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        t.unref?.();
        return t;
      });
    this.clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as NodeJS.Timeout));
    this.open = deps.open ?? openIdentity;
  }

  /**
   * Attempt an unlock. Resolves `{ ok: false }` for every failure — wrong passphrase, missing
   * blob, rollback, cooldown — and never throws: a throw across IPC carries internals to the
   * renderer console, and the renderer must not be able to distinguish failure modes that the
   * `problem` sentence does not deliberately name.
   */
  unlock(passphrase: unknown): Promise<UnlockResult> {
    const run = this.queue.then(() => this.unlockNow(passphrase));
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    // The chain above swallows rejections for the queue's sake; the caller still needs one
    // resolved value, so map any unexpected throw to a plain failure here.
    return run.catch(() => ({ ok: false as const }));
  }

  private async unlockNow(passphrase: unknown): Promise<UnlockResult> {
    // Idempotent-by-refusal: an unlock while unlocked is a no-op success. Re-deriving to replace
    // a live key buys nothing and doubles the window where two copies of idSK exist.
    if (this.state) return { ok: true };

    if (this.now() < this.cooldownUntil) {
      this.lastProblem = 'Too many attempts. Wait a few seconds and try again.';
      return { ok: false };
    }

    // Shape before cost. A non-string or absurd length never reaches the KDF.
    if (typeof passphrase !== 'string' || passphrase.length === 0 || passphrase.length > MAX_PASSPHRASE_LENGTH) {
      return this.fail(undefined);
    }

    const blobJson = this.deps.loadWrappedIdentity();
    if (blobJson === undefined) {
      // Not a wrong passphrase and not an attack: setup never stored the blob here. Say so —
      // the alternative is an owner re-typing a correct passphrase forever.
      return this.fail('This computer does not have a dashboard key yet. Finish setup first.');
    }

    let blob: WrappedKey;
    try {
      const parsed: unknown = JSON.parse(blobJson);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('not an object');
      }
      blob = parsed as WrappedKey;
    } catch {
      return this.fail('The saved dashboard key on this computer is damaged. Set the dashboard up again.');
    }

    // The rollback memory, BEFORE the derive: corrupt memory must refuse the unlock without
    // burning half a second, and must never be read as "no memory" (see RosterMarkStore).
    let memory: RosterMemory;
    try {
      memory = this.deps.loadMemory();
    } catch {
      return this.fail(
        'This computer’s dashboard memory looks damaged, so the dashboard will not open. Please get in touch.',
      );
    }

    let opened: UnwrappedIdentity;
    try {
      opened = await this.open(blob, { kind: 'pass', passphrase }, memory);
    } catch (e) {
      if (e instanceof RosterError || (e as Error | undefined)?.name === 'RosterError') {
        // The AEAD tag verified — the passphrase was RIGHT — and what came back is unusable or
        // OLDER THAN THIS MACHINE HAS ALREADY SEEN. That is a rollback signal or a real bug,
        // and reporting it as a typo would hide an attack behind "check your spelling".
        return this.fail(
          'Your passphrase is correct, but the dashboard key that came back with it is not safe to use. Please get in touch.',
        );
      }
      // Wrong passphrase (or an unwrap failure indistinguishable from one). No sentence: the
      // renderer says "wrong passphrase" and nothing here contradicts or narrows that.
      return this.fail(undefined);
    }

    // Persist the high-water mark BEFORE declaring the session open. If this write fails, the
    // next unlock would silently run with yesterday's memory — so the unlock fails instead,
    // loudly, and the key material is destroyed on the way out.
    try {
      this.deps.saveMemory(opened.highestVersionSeen);
    } catch {
      opened.identitySecretKey.fill(0);
      return this.fail(
        'This computer could not save its dashboard memory, so the dashboard will not open. Please get in touch.',
      );
    }

    this.state = {
      identitySecretKey: opened.identitySecretKey,
      roster: opened.roster,
      rosterVersion: opened.rosterVersion,
    };
    this.failures = 0;
    this.cooldownUntil = 0;
    this.lastProblem = undefined;
    this.armIdleTimer();
    return { ok: true };
  }

  private fail(problem: string | undefined): UnlockResult {
    this.lastProblem = problem;
    this.failures += 1;
    if (this.failures >= MAX_FAILURES) {
      this.cooldownUntil = this.now() + COOLDOWN_MS;
      this.failures = 0;
    }
    return { ok: false };
  }

  /**
   * The open session, or undefined while locked. Touching it counts as activity and re-arms the
   * idle timer — reading cards is exactly the activity the timeout measures.
   */
  current(): OpenSession | undefined {
    if (!this.state) return undefined;
    this.armIdleTimer();
    return this.state;
  }

  get isUnlocked(): boolean {
    return this.state !== undefined;
  }

  /** See `lastProblem`. Cleared by a successful unlock. */
  get problem(): string | undefined {
    return this.lastProblem;
  }

  /**
   * Wipe the session. Zeroes the secret key bytes in place — every holder of the reference
   * (including a card build that is somehow still in flight) sees zeros from this line on.
   */
  lock(): void {
    if (this.idleHandle !== undefined) {
      this.clearTimer(this.idleHandle);
      this.idleHandle = undefined;
    }
    if (!this.state) return;
    this.state.identitySecretKey.fill(0);
    this.state = undefined;
  }

  private armIdleTimer(): void {
    if (this.idleHandle !== undefined) this.clearTimer(this.idleHandle);
    this.idleHandle = this.setTimer(() => this.lock(), this.idleMs);
  }
}
