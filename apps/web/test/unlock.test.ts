import { test } from 'node:test';
import assert from 'node:assert/strict';
import { unlock, lockSession, UnlockError } from '../src/data/unlock.ts';
import { saveRosterMark, loadRosterMemory } from '../src/data/marks.ts';
import { toBase64 } from '@tally-bridge/crypto';
import {
  makeFixture,
  rewrapAtVersion,
  fakeServer,
  spyKV,
  TENANT,
  PASSPHRASE,
  type Fixture,
} from './helpers.ts';

/**
 * THE UNLOCK PATH — the crypto core of the web dashboard.
 *
 * Every test here drives the REAL chain: real prelogin params, a real Argon2id derivation (twice,
 * as the flow documents — slow, so these tests are slow, and that is the honest cost of testing
 * the real thing rather than a mock of it), a real login against a fake server that checks the
 * real auth token, a real `openIdentity` unwrap, and the real rollback decision.
 *
 * The point of proof is that unlock's SECURITY behaviours — the rollback refusal, the
 * fail-closed persistence, the never-call-an-attack-a-typo error mapping — actually fire. A mock
 * of `deriveRoot` would make all of this vacuous, so nothing here mocks the crypto.
 */

async function goodUnlock(fx: Fixture, storage = spyKV()) {
  return unlock({ fetch: fakeServer(fx), storage }, TENANT, PASSPHRASE);
}

test('a correct passphrase unlocks and yields the roster from inside the sealed bundle', async () => {
  const fx = await makeFixture();
  const session = await goodUnlock(fx);

  assert.equal(session.tenantId, TENANT);
  assert.equal(session.identityPublicKeyB64, fx.idPkB64);
  // The roster came out of the passphrase-sealed bundle — it names the real device, and the
  // server never supplied it.
  assert.equal(session.roster.length, 1);
  assert.equal(session.roster[0]?.deviceId, 'dev_001');
  assert.equal(session.rosterVersion, 1);
  assert.equal(session.firstUse, true);
  assert.equal(session.persistentMemory, true);
  await lockSession(session);
});

test('a WRONG passphrase is refused as credentials — never as anything more specific', async () => {
  const fx = await makeFixture();
  // The fake server checks the REAL auth token, so a wrong passphrase derives a wrong token and
  // login returns 401 — exactly as production does.
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx), storage: spyKV() }, TENANT, 'the wrong passphrase'),
    (e: unknown) => e instanceof UnlockError && e.failure === 'credentials',
  );
});

test('an unknown tenant surfaces as credentials, indistinguishable from a wrong passphrase', async () => {
  const fx = await makeFixture();
  // The real server serves a decoy for unknown tenants; login then fails. Both map to
  // 'credentials' on purpose — a distinguishable "no such tenant" is an enumeration oracle.
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx), storage: spyKV() }, 'no_such_tenant', PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'credentials',
  );
});

test('an empty tenant or passphrase fails BEFORE any network call or Argon2id', async () => {
  const fx = await makeFixture();
  let called = false;
  const spyFetch = ((path: string, init?: RequestInit) => {
    called = true;
    return fakeServer(fx)(path, init);
  }) as typeof fetch;

  await assert.rejects(
    () => unlock({ fetch: spyFetch, storage: spyKV() }, '  ', PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'credentials',
  );
  assert.equal(called, false, 'no request should be made for an empty credential');
});

test('ROLLBACK: a server offering an OLDER roster version than this browser has seen is refused', async () => {
  const fx = await makeFixture(3); // the browser will first see version 3
  const storage = spyKV();

  // First unlock at version 3 — records the high-water mark for this identity.
  const first = await unlock({ fetch: fakeServer(fx), storage }, TENANT, PASSPHRASE);
  assert.equal(first.rosterVersion, 3);

  // The server now serves a re-wrap of the SAME identity at version 1 — perfectly authentic,
  // just old (it could contain a since-revoked device). The persisted mark refuses it, and NOT
  // as a wrong passphrase.
  const oldBlob = await rewrapAtVersion(fx, 1);
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx, { wrappedKeys: [oldBlob] }), storage }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'rollback',
  );
});

test('a NEWER roster version is accepted and advances the mark', async () => {
  const fx = await makeFixture(1);
  const storage = spyKV();

  const first = await unlock({ fetch: fakeServer(fx), storage }, TENANT, PASSPHRASE);
  assert.equal(first.rosterVersion, 1);

  const newBlob = await rewrapAtVersion(fx, 5);
  const second = await unlock({ fetch: fakeServer(fx, { wrappedKeys: [newBlob] }), storage }, TENANT, PASSPHRASE);
  assert.equal(second.rosterVersion, 5);

  // The mark advanced: a subsequent version-1 replay is now refused.
  const oldBlob = await rewrapAtVersion(fx, 1);
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx, { wrappedKeys: [oldBlob] }), storage }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'rollback',
  );
});

test('FAIL CLOSED: an unlock whose mark cannot be PERSISTED is refused, not waved through', async () => {
  const fx = await makeFixture();
  // Storage that reads fine but throws on write. Losing rollback protection silently is the
  // failure this guards — so the unlock must fail rather than return a session with no memory.
  const storage = {
    get: () => undefined,
    set: () => {
      throw new Error('quota exceeded');
    },
    persistent: true,
  };
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx), storage }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'no-storage',
  );
});

test('DAMAGED MEMORY: an unreadable safety mark is its own error, never "wrong passphrase"', async () => {
  const fx = await makeFixture();
  const storage = spyKV();
  // Corrupt the roster memory for this identity to non-JSON. It must surface as 'damaged-memory'
  // — a repairable local condition — not as a credential failure that sends the owner chasing a
  // passphrase that is perfectly correct.
  const first = await goodUnlock(fx, storage);
  // Find the mark key and corrupt it.
  const markKey = [...storage.map.keys()].find((k) => k.includes('roster'));
  assert.ok(markKey, 'a roster mark should have been written');
  storage.map.set(markKey, '}{ not json');

  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx), storage }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'damaged-memory',
  );
});

test('a deployment with NO pass blob is "not set up", not a credential failure', async () => {
  const fx = await makeFixture();
  // Login succeeds (auth token is correct) but wrapped-keys returns no 'pass' kind. That is a
  // half-finished setup, and telling the owner "wrong passphrase" would be a lie.
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx, { wrappedKeys: [] }), storage: spyKV() }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'not-set-up',
  );
});

test('a 429 from the server maps to rate-limited, not a generic failure', async () => {
  const fx = await makeFixture();
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx, { loginStatus: 429 }), storage: spyKV() }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'rate-limited',
  );
});

test('a 503 (server not set up) is reported as such, not as bad credentials', async () => {
  const fx = await makeFixture();
  await assert.rejects(
    () => unlock({ fetch: fakeServer(fx, { loginStatus: 503 }), storage: spyKV() }, TENANT, PASSPHRASE),
    (e: unknown) => e instanceof UnlockError && e.failure === 'not-set-up',
  );
});

test('the STAGE callback fires the expensive steps in order, so the UI can warn about the wait', async () => {
  const fx = await makeFixture();
  const stages: string[] = [];
  await unlock(
    { fetch: fakeServer(fx), storage: spyKV(), onStage: (s) => stages.push(s) },
    TENANT,
    PASSPHRASE,
  );
  // 'deriving' (Argon2id #1) and 'opening' (Argon2id #2) are the multi-second steps a phone UI
  // must show a spinner for. Both must be announced, and deriving before opening.
  assert.ok(stages.includes('deriving'), stages.join(','));
  assert.ok(stages.includes('opening'), stages.join(','));
  assert.ok(stages.indexOf('deriving') < stages.indexOf('opening'));
});

test('memoryKV storage reports persistentMemory:false so the UI can disclose weaker protection', async () => {
  const fx = await makeFixture();
  // A browser with no durable storage runs on an in-memory KV. Rollback protection then lasts
  // only this session — a real weakening the UI must surface rather than hide.
  const ephemeral = { get: () => undefined, set: () => {}, persistent: false };
  const session = await unlock({ fetch: fakeServer(fx), storage: ephemeral }, TENANT, PASSPHRASE);
  assert.equal(session.persistentMemory, false);
});
