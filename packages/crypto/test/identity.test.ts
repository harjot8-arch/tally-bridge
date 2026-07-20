import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { KdfParams } from '@tally-bridge/core';
import {
  generateIdentity,
  generateRecoveryKey,
  publicKeyFromSecret,
  unwrapWithDeviceKey,
  unwrapWithPassphrase,
  unwrapWithRecoveryKey,
  wrapIdentity,
  wrapUnderDeviceKey,
  wrapUnderPassphrase,
  wrapUnderRecoveryKey,
  type IdentityWraps,
} from '../src/identity.ts';
import {
  ARGON2ID_MEMLIMIT_BYTES,
  ARGON2ID_OPSLIMIT,
  KDF_INFO,
  deriveRoot,
  fromBase64,
  hkdf,
} from '../src/kdf.ts';
import { sodiumReady } from '../src/sodium.ts';
import { sealSection, makeAad, openSection } from '../src/envelope.ts';

// Argon2id is ~460ms per derive by design, so passphrase tests are deliberately few.

test('passphrase wrap/unwrap round-trips', async () => {
  const id = await generateIdentity();
  const blob = await wrapUnderPassphrase(id.secretKey, 'Ramesh@1985');
  const out = await unwrapWithPassphrase(blob, 'Ramesh@1985');
  assert.deepEqual(out, id.secretKey);
});

test('the wrong passphrase fails and does not leak a partial key', async () => {
  const id = await generateIdentity();
  const blob = await wrapUnderPassphrase(id.secretKey, 'correct horse');
  await assert.rejects(
    () => unwrapWithPassphrase(blob, 'wrong horse'),
    /cannot be decrypted/i,
  );
});

test('the wrapped blob carries its own KDF params', async () => {
  const id = await generateIdentity();
  const blob = await wrapUnderPassphrase(id.secretKey, 'pw');
  assert.equal(blob.kdf?.kdf, 'argon2id');
  assert.equal(blob.kdf?.m, ARGON2ID_MEMLIMIT_BYTES);
  assert.equal(blob.kdf?.t, ARGON2ID_OPSLIMIT);
  assert.equal(blob.kdf?.p, 1);
  assert.ok(blob.kdf!.salt.length > 0);
});

test('params are read from the blob, not from compiled-in defaults', async () => {
  // This is what makes it possible to RAISE Argon2id params later without orphaning every
  // existing key. Derive at params that differ from this module's constants and confirm the
  // blob's values are the ones used.
  //
  // Both param sets here sit inside the honoured band (see ARGON2ID_MIN_*/MAX_* in kdf.ts).
  // This test previously used m=8MiB/t=1 to make the point, which is below the floor a blob is
  // now allowed to ask for — the property under test is "the blob's params are used", not "any
  // params whatsoever are used", so demonstrating it with weak-but-rejected values only
  // coupled the test to a hole. `kdf.test.ts` covers the rejection of out-of-band params.
  const lower: KdfParams = {
    v: 1,
    kdf: 'argon2id',
    m: 32 * 1024 * 1024,
    t: 2,
    p: 1,
    salt: Buffer.alloc(16, 9).toString('base64'),
  };
  const a = await deriveRoot('pw', lower);
  const b = await deriveRoot('pw', lower);
  assert.deepEqual(a, b, 'same params -> same key');

  const higher: KdfParams = { ...lower, t: 3 };
  const c = await deriveRoot('pw', higher);
  assert.notDeepEqual(a, c, 'different params -> different key, so params must be stored');

  // And neither is the compiled-in default, so a passing test cannot be explained by the
  // defaults being used regardless.
  assert.notEqual(lower.m, ARGON2ID_MEMLIMIT_BYTES);
});

test('a salt of the wrong length is rejected rather than silently padded', async () => {
  // Params are in-band on purpose: this test is about the SALT check, and out-of-band params
  // would short-circuit it and make it pass for the wrong reason.
  const bad: KdfParams = {
    v: 1,
    kdf: 'argon2id',
    m: ARGON2ID_MEMLIMIT_BYTES,
    t: ARGON2ID_OPSLIMIT,
    p: 1,
    salt: Buffer.alloc(8).toString('base64'),
  };
  await assert.rejects(() => deriveRoot('pw', bad), /bad salt length/);
});

test('a blob asking for unsupported parallelism is refused, not downgraded', async () => {
  // In-band params, so the parallelism check is unambiguously what rejects this.
  const bad = {
    v: 1,
    kdf: 'argon2id',
    m: ARGON2ID_MEMLIMIT_BYTES,
    t: ARGON2ID_OPSLIMIT,
    p: 4,
    salt: Buffer.alloc(16).toString('base64'),
  } as unknown as KdfParams;
  // libsodium pins p=1 internally; honouring this blob is impossible, and silently
  // downgrading it would produce a key the writer could never reproduce.
  await assert.rejects(() => deriveRoot('pw', bad), /parallelism/);
});

test('recovery key wrap/unwrap round-trips', async () => {
  const id = await generateIdentity();
  const rk = await generateRecoveryKey();
  assert.equal(rk.length, 32, 'recovery key must be 256 bits of real entropy');

  const blob = await wrapUnderRecoveryKey(id.secretKey, rk);
  assert.equal(blob.kind, 'recovery');
  // No Argon2id params: a full-entropy key has no guess space to slow down.
  assert.equal(blob.kdf, undefined);
  assert.deepEqual(await unwrapWithRecoveryKey(blob, rk), id.secretKey);
});

test('the wrong recovery key fails', async () => {
  const id = await generateIdentity();
  const blob = await wrapUnderRecoveryKey(id.secretKey, await generateRecoveryKey());
  const otherKey = await generateRecoveryKey();
  await assert.rejects(() => unwrapWithRecoveryKey(blob, otherKey));
});

test('a short recovery key is rejected', async () => {
  const id = await generateIdentity();
  await assert.rejects(
    () => wrapUnderRecoveryKey(id.secretKey, new Uint8Array(16)),
    /must be 32 bytes/,
  );
});

test('device key wrap/unwrap round-trips', async () => {
  const id = await generateIdentity();
  const deviceKey = crypto.getRandomValues(new Uint8Array(32));
  const blob = await wrapUnderDeviceKey(id.secretKey, deviceKey);
  assert.deepEqual(await unwrapWithDeviceKey(blob, deviceKey), id.secretKey);
});

test('wrap kinds are bound — a blob cannot be opened as the wrong kind', async () => {
  const id = await generateIdentity();
  const key = crypto.getRandomValues(new Uint8Array(32));

  const deviceBlob = await wrapUnderDeviceKey(id.secretKey, key);
  const recoveryBlob = await wrapUnderRecoveryKey(id.secretKey, key);

  // Type-level guards first...
  await assert.rejects(() => unwrapWithRecoveryKey(deviceBlob, key), /not a recovery-wrapped/);
  await assert.rejects(() => unwrapWithDeviceKey(recoveryBlob, key), /not a device-wrapped/);

  // ...and the cryptographic guard underneath: relabel the blob to defeat the type check
  // and the AEAD still refuses, because `kind` is bound as associated data.
  const relabelled = { ...deviceBlob, kind: 'recovery' as const };
  await assert.rejects(() => unwrapWithRecoveryKey(relabelled, key), /cannot be decrypted/i);
});

test('an unwrapped secret key still matches its public key', async () => {
  const id = await generateIdentity();
  const blob = await wrapUnderPassphrase(id.secretKey, 'pw');
  const recovered = await unwrapWithPassphrase(blob, 'pw');
  assert.deepEqual(await publicKeyFromSecret(recovered), id.publicKey);
});

test('end to end: Bridge seals with the public key, dashboard opens after passphrase unlock', async () => {
  // The whole product in one test.
  const id = await generateIdentity();

  // --- Setup: passphrase and recovery paths are both established, then idSK is discarded.
  const passBlob = await wrapUnderPassphrase(id.secretKey, 'Ramesh@1985');
  const rk = await generateRecoveryKey();
  const recoveryBlob = await wrapUnderRecoveryKey(id.secretKey, rk);

  // --- Bridge: holds the identity PUBLIC key and its own SIGNING key. Neither reads anything.
  //     Runs unattended, no passphrase, forever.
  const sodium = await sodiumReady();
  const deviceKp = sodium.crypto_sign_keypair();
  const bridgeKeystore = { identityPublicKey: id.publicKey, deviceSecretKey: deviceKp.privateKey };
  const env = await sealSection(
    { rows: [{ party: 'A & B Traders <Mumbai>', amount: '125000.00' }] },
    makeAad({
      tenantId: 't',
      deviceId: 'd',
      companyGuid: 'g',
      section: 'ageing_receivable',
      asOf: '2026-07-16',
      snapshotTs: 1,
      seq: 1,
    }),
    bridgeKeystore.identityPublicKey,
    bridgeKeystore.deviceSecretKey,
  );

  // --- Dashboard: user types the passphrase eight months later.
  //
  // The roster is pinned material, NOT something fetched from the server — see trust.ts. If it
  // were fetched, the signature would prove only that the server signed it.
  const reader = {
    expect: { tenantId: 't', companyGuid: 'g', section: 'ageing_receivable' as const, asOf: '2026-07-16' },
    trustedDevices: [{ deviceId: 'd', publicKey: deviceKp.publicKey }],
  };
  const sk = await unwrapWithPassphrase(passBlob, 'Ramesh@1985');
  const viaPass = await openSection(env, {
    ...reader,
    identityPublicKey: id.publicKey,
    identitySecretKey: sk,
  });
  assert.deepEqual(viaPass, { rows: [{ party: 'A & B Traders <Mumbai>', amount: '125000.00' }] });

  // --- Recovery: passphrase forgotten, the printed sheet still works.
  const sk2 = await unwrapWithRecoveryKey(recoveryBlob, rk);
  assert.deepEqual(
    await openSection(env, { ...reader, identityPublicKey: id.publicKey, identitySecretKey: sk2 }),
    viaPass,
  );
});

/* ------------------------------------------------------------------ the login auth token */

// One wrapIdentity fixture shared by the auth-token tests: every Argon2id run is ~half a second
// by design, and these tests interrogate a single result from different angles.
let authFixture: Promise<{ wraps: IdentityWraps }> | undefined;
function authTokenFixture(): Promise<{ wraps: IdentityWraps }> {
  return (authFixture ??= (async () => {
    const id = await generateIdentity();
    const sodium = await sodiumReady();
    const kp = sodium.crypto_sign_keypair();
    const recoveryKey = await generateRecoveryKey();
    const wraps = await wrapIdentity(
      id.secretKey,
      { version: 1, devices: [{ deviceId: 'dev_001', publicKey: kp.publicKey }] },
      { passphrase: 'Ramesh@1985', recoveryKey },
    );
    return { wraps };
  })());
}

test("wrapIdentity returns the auth token: HKDF-auth of the pass wrap's own root", async () => {
  const { wraps } = await authTokenFixture();
  // Recomputed independently from the params sealed in the blob — the exact derivation a
  // browser performs after prelogin serves those params back. If these two ever disagree,
  // login fails for every owner while the unwrap keeps working, which is the silent kind of
  // total failure this assertion exists to catch.
  const root = await deriveRoot('Ramesh@1985', wraps.pass.kdf!);
  assert.deepEqual(wraps.authToken, await hkdf(root, KDF_INFO.auth));
  assert.equal(wraps.authToken.length, 32);
});

test('the auth token opens nothing: it cannot decrypt the pass wrap it travelled with', async () => {
  // The server stores SHA-256 of this value, so "what does holding it buy an attacker" must be
  // answered by arithmetic, not policy: it is the KEK's HKDF sibling, not the KEK. Try to use
  // it as the wrapping key and the AEAD refuses. If someone ever derives the token under the
  // kek label by mistake, this decryption SUCCEEDS and the test fails.
  const { wraps } = await authTokenFixture();
  const sodium = await sodiumReady();
  assert.throws(() =>
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(wraps.pass.ciphertext),
      'pass',
      fromBase64(wraps.pass.nonce),
      wraps.authToken,
    ),
  );
});
