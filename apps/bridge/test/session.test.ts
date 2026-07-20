import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateIdentity,
  generateRecoveryKey,
  sodiumReady,
  wrapIdentity,
  type RosterMemory,
  type UnwrappedIdentity,
} from '@tally-bridge/crypto';
import { initialRoster } from '../src/onboarding/pairing.ts';
import { COOLDOWN_MS, MAX_FAILURES, UnlockSession, type SessionDeps } from '../src/main/session.ts';
import { RosterMarkStore } from '../src/main/snapshots.ts';

/**
 * The unlock session, tested against REAL crypto where the claim is cryptographic (a wrong
 * passphrase fails; a rolled-back bundle is refused) and against injected fakes where the claim
 * is about the session's own logic (cooldown, idle lock, zeroisation) — each Argon2id derive
 * costs ~half a second, so the derives are spent only where they prove something.
 */

const PASS = 'correct horse battery staple';

// One fixture set for the whole file: two wraps of the SAME identity, roster v1 and roster v2.
// v2 is what a machine that saw a revocation has already accepted; v1 is the stale bundle a
// malicious server would like to serve back.
const fixtures = await (async () => {
  const sodium = await sodiumReady();
  const identity = await generateIdentity();
  const device = sodium.crypto_sign_keypair();
  const rosterV1 = initialRoster({ deviceId: 'dev_001', publicKey: device.publicKey });
  const rosterV2 = { version: 2, devices: rosterV1.devices };
  const recoveryKey = await generateRecoveryKey();
  const wrapsV1 = await wrapIdentity(identity.secretKey, rosterV1, { passphrase: PASS, recoveryKey });
  const wrapsV2 = await wrapIdentity(identity.secretKey, rosterV2, { passphrase: PASS, recoveryKey });
  return { identity, blobV1: JSON.stringify(wrapsV1.pass), blobV2: JSON.stringify(wrapsV2.pass) };
})();

/** In-memory rollback mark with the same contract as RosterMarkStore. */
function memoryStore(initial?: number) {
  let mark = initial;
  return {
    load: (): RosterMemory =>
      mark === undefined ? { kind: 'first-use' } : { kind: 'seen', highestVersionSeen: mark },
    save: (v: number): void => {
      mark = v;
    },
    get mark() {
      return mark;
    },
  };
}

function makeSession(over: Partial<SessionDeps> & { blob?: string | undefined } = {}) {
  const mem = memoryStore();
  const session = new UnlockSession({
    loadWrappedIdentity: () => over.blob ?? fixtures.blobV1,
    loadMemory: mem.load,
    saveMemory: mem.save,
    // Fake timers by default: a real 15-minute idle timeout left armed by an unlocked session
    // is a hung `node --test` process (found the hard way — it wedged the whole suite).
    setTimer: () => ({}),
    clearTimer: () => {},
    ...over,
  });
  return { session, mem };
}

/** A fake openIdentity for logic tests: no derive, controllable outcome. */
function fakeOpen(result: () => UnwrappedIdentity | Error) {
  let calls = 0;
  const open: NonNullable<SessionDeps['open']> = async () => {
    calls++;
    const r = result();
    if (r instanceof Error) throw r;
    return r;
  };
  return { open, count: () => calls };
}

const fakeIdentity = (): UnwrappedIdentity => ({
  identitySecretKey: new Uint8Array(32).fill(7),
  roster: [{ deviceId: 'dev_001', publicKey: new Uint8Array(32) }],
  rosterVersion: 1,
  highestVersionSeen: 1,
});

// ---------------------------------------------------------------- the real crypto claims

test('the right passphrase unlocks: idSK and the sealed roster come out, the mark is persisted, and lock() zeroes', async () => {
  const { session, mem } = makeSession();
  const r = await session.unlock(PASS);
  assert.equal(r.ok, true);

  const open = session.current();
  assert.ok(open, 'session must be open');
  assert.deepEqual(open.identitySecretKey, fixtures.identity.secretKey, 'the identity round-trips');
  assert.equal(open.roster.length, 1);
  assert.equal(open.roster[0]!.deviceId, 'dev_001');
  assert.equal(open.rosterVersion, 1);
  assert.equal(mem.mark, 1, 'the high-water mark was persisted during unlock, not left for later');

  // Lock actually zeroes: the same buffer every holder saw is destroyed in place.
  const key = open.identitySecretKey;
  assert.ok(key.some((b) => b !== 0), 'precondition: the key was not already zero');
  session.lock();
  assert.ok(key.every((b) => b === 0), 'lock() must overwrite the key bytes');
  assert.equal(session.current(), undefined);
  assert.equal(session.isUnlocked, false);
});

test('a wrong passphrase fails, leaks nothing, and does not touch the persisted mark', async () => {
  const { session, mem } = makeSession();
  const r = await session.unlock('not the passphrase, definitely');
  assert.equal(r.ok, false);
  assert.equal(session.problem, undefined, 'a wrong passphrase must produce NO sentence — nothing to distinguish it');
  assert.equal(session.isUnlocked, false);
  assert.equal(mem.mark, undefined, 'a failed unlock must not advance the mark');
});

test('THE ROLLBACK GATE, END TO END: a bundle this machine has outgrown is refused and is not called a typo', async () => {
  // Real disk, real mark store, and a NEW store instance for the second unlock — the property
  // is that the refusal survives a process restart, not that one object remembers.
  const dir = mkdtempSync(join(tmpdir(), 'bridge-mark-'));
  const idPk = 'idpk-fixture';

  const first = new UnlockSession({
    loadWrappedIdentity: () => fixtures.blobV2,
    loadMemory: () => new RosterMarkStore(dir).load(idPk),
    saveMemory: (v) => new RosterMarkStore(dir).save(idPk, v),
  });
  assert.equal((await first.unlock(PASS)).ok, true, 'roster v2 opens on first use');
  first.lock();

  // "Restart": fresh session, fresh store instances, and the server serves the OLD bundle.
  const second = new UnlockSession({
    loadWrappedIdentity: () => fixtures.blobV1,
    loadMemory: () => new RosterMarkStore(dir).load(idPk),
    saveMemory: (v) => new RosterMarkStore(dir).save(idPk, v),
  });
  const r = await second.unlock(PASS);
  assert.equal(r.ok, false, 'the stale bundle must be refused');
  assert.equal(second.isUnlocked, false);
  // The owner typed the RIGHT passphrase. Telling them to check their spelling would bury an
  // attack signal, so the problem sentence must exist and must say the passphrase was right.
  assert.ok(second.problem, 'a rollback must carry a sentence — it is not a typo');
  assert.match(second.problem!, /passphrase is correct/);
  // And the mark did not regress.
  assert.deepEqual(new RosterMarkStore(dir).load(idPk), { kind: 'seen', highestVersionSeen: 2 });
});

// ---------------------------------------------------------------- session logic (no derives)

test('after MAX_FAILURES the session cools down without spending a derive', async () => {
  let now = 1_000_000;
  const fake = fakeOpen(() => new Error('wrong'));
  const { session } = makeSession({ open: fake.open, now: () => now });

  for (let i = 0; i < MAX_FAILURES; i++) {
    assert.equal((await session.unlock('guess')).ok, false);
  }
  assert.equal(fake.count(), MAX_FAILURES);

  // Inside the cooldown: refused BEFORE the KDF would run.
  assert.equal((await session.unlock('guess')).ok, false);
  assert.equal(fake.count(), MAX_FAILURES, 'no derive may be spent during cooldown');
  assert.match(session.problem ?? '', /Too many attempts/);

  // After it: attempts flow again.
  now += COOLDOWN_MS + 1;
  await session.unlock('guess');
  assert.equal(fake.count(), MAX_FAILURES + 1);
});

test('a successful unlock resets the failure count', async () => {
  let outcome: UnwrappedIdentity | Error = new Error('wrong');
  const fake = fakeOpen(() => outcome);
  const { session } = makeSession({ open: fake.open });

  for (let i = 0; i < MAX_FAILURES - 1; i++) await session.unlock('guess');
  outcome = fakeIdentity();
  assert.equal((await session.unlock(PASS)).ok, true);
  session.lock();

  // The near-tripped counter must be gone: the next failures start from zero. Without the
  // reset, the counter would cross MAX_FAILURES partway through this loop and the cooldown
  // would start refusing attempts before they reach the KDF.
  outcome = new Error('wrong');
  for (let i = 0; i < MAX_FAILURES - 1; i++) {
    assert.equal((await session.unlock('guess')).ok, false);
  }
  // (MAX_FAILURES - 1) failures + 1 success + (MAX_FAILURES - 1) failures.
  assert.equal(fake.count(), 2 * MAX_FAILURES - 1, 'every one of these attempts reached the KDF');
});

test('the idle timer locks and zeroes; touching the session re-arms it', async () => {
  const timers: Array<{ fn: () => void; ms: number; cleared: boolean }> = [];
  const fake = fakeOpen(fakeIdentity);
  const { session } = makeSession({
    open: fake.open,
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (h) => {
      (h as { cleared: boolean }).cleared = true;
    },
  });

  await session.unlock(PASS);
  assert.equal(timers.length, 1, 'unlock arms the idle timer');
  assert.equal(timers[0]!.ms, 15 * 60 * 1000, 'fifteen minutes of idle, per the header');

  const key = session.current()!.identitySecretKey;
  assert.equal(timers.length, 2, 'reading the session is activity: the timer re-arms');
  assert.equal(timers[0]!.cleared, true, 'the previous timer was cancelled, not stacked');

  // The machine sits idle: the live timer fires.
  timers.at(-1)!.fn();
  assert.equal(session.isUnlocked, false, 'idle must lock');
  assert.ok(key.every((b) => b === 0), 'idle lock must zero the key, not just forget it');
});

test('garbage passphrases are refused before the KDF: non-strings, empty, oversized', async () => {
  const fake = fakeOpen(fakeIdentity);
  const { session } = makeSession({ open: fake.open });
  for (const bad of [undefined, null, 42, { pass: 'x' }, '', 'x'.repeat(2000)]) {
    assert.equal((await session.unlock(bad)).ok, false);
  }
  assert.equal(fake.count(), 0, 'none of these may reach the KDF');
});

test('a missing wrapped blob is named as a setup problem, not a wrong passphrase', async () => {
  const fake = fakeOpen(fakeIdentity);
  const { session } = makeSession({ open: fake.open, loadWrappedIdentity: () => undefined });
  assert.equal((await session.unlock(PASS)).ok, false);
  assert.match(session.problem ?? '', /setup/i);
  assert.equal(fake.count(), 0);
});

test('corrupt rollback memory fails the unlock closed, before the derive', async () => {
  const fake = fakeOpen(fakeIdentity);
  const { session } = makeSession({
    open: fake.open,
    loadMemory: () => {
      throw new Error('mark file is garbage');
    },
  });
  assert.equal((await session.unlock(PASS)).ok, false);
  assert.equal(session.isUnlocked, false);
  assert.ok(session.problem, 'this is not a typo and must say so');
  assert.equal(fake.count(), 0, 'unreadable memory refuses before spending the derive');
});

test('an unlock whose mark cannot be persisted fails closed and destroys the key', async () => {
  const opened = fakeIdentity();
  const fake = fakeOpen(() => opened);
  const { session } = makeSession({
    open: fake.open,
    saveMemory: () => {
      throw new Error('disk full');
    },
  });
  assert.equal((await session.unlock(PASS)).ok, false);
  assert.equal(session.isUnlocked, false, 'no persistence, no session — otherwise the next unlock runs unprotected');
  assert.ok(opened.identitySecretKey.every((b) => b === 0), 'the unwrapped key must not outlive the failed unlock');
});

test('unlock while unlocked is a no-op success, not a second derive', async () => {
  const fake = fakeOpen(fakeIdentity);
  const { session } = makeSession({ open: fake.open });
  assert.equal((await session.unlock(PASS)).ok, true);
  assert.equal((await session.unlock(PASS)).ok, true);
  assert.equal(fake.count(), 1);
});

test('unlock NEVER rejects, whatever its dependencies do', async () => {
  const { session } = makeSession({
    loadWrappedIdentity: () => {
      throw new Error('backend exploded');
    },
  });
  const r = await session.unlock(PASS); // a rejection here would fail the test run
  assert.equal(r.ok, false);
});

test('concurrent unlock attempts are serialised, not raced', async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const open: SessionDeps['open'] = async () => {
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    throw new Error('wrong');
  };
  const { session } = makeSession({ open });
  await Promise.all([session.unlock('a'), session.unlock('b'), session.unlock('c')]);
  assert.equal(maxInFlight, 1, 'the KDF must never run twice at once');
});
