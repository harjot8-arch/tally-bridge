import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { KdfParams } from '@tally-bridge/core';
import {
  ARGON2ID_MAX_MEMLIMIT_BYTES,
  ARGON2ID_MAX_OPSLIMIT,
  ARGON2ID_MEMLIMIT_BYTES,
  ARGON2ID_MIN_MEMLIMIT_BYTES,
  ARGON2ID_MIN_OPSLIMIT,
  ARGON2ID_OPSLIMIT,
  defaultKdfParams,
  deriveRoot,
  randomSalt,
  toBase64,
} from '../src/kdf.ts';
import { sodiumReady } from '../src/sodium.ts';

/**
 * Adversarial: the KDF parameters come from the BLOB, not from compiled-in defaults.
 *
 * That is a deliberate and correct design — it is what lets parameters be raised later without
 * orphaning existing wrapped keys. But it means the params are attacker-reachable input: the
 * blob arrives from a server we explicitly do not trust, and nothing in `WrappedKey` binds the
 * KDF descriptor to the ciphertext. So `deriveRoot` must treat them as hostile.
 */

async function params(over: Partial<KdfParams>): Promise<KdfParams> {
  return { ...defaultKdfParams(await randomSalt()), ...over } as KdfParams;
}

test('the compiled-in defaults sit inside the accepted band', async () => {
  // If this fails, a blob written by THIS build would be rejected by this build.
  assert.ok(ARGON2ID_MEMLIMIT_BYTES >= ARGON2ID_MIN_MEMLIMIT_BYTES);
  assert.ok(ARGON2ID_MEMLIMIT_BYTES <= ARGON2ID_MAX_MEMLIMIT_BYTES);
  assert.ok(ARGON2ID_OPSLIMIT >= ARGON2ID_MIN_OPSLIMIT);
  assert.ok(ARGON2ID_OPSLIMIT <= ARGON2ID_MAX_OPSLIMIT);
});

test('a malicious blob cannot force weak Argon2id memory', async () => {
  // libsodium's own floor is MEMLIMIT_MIN = 8192 bytes, which it accepts happily: measured at
  // ~10ms versus ~3000ms for our defaults. A ~300x speedup handed to an offline cracker
  // grinding "tally123" is the entire security margin of the passphrase path.
  const tiny = await params({ m: 8192 });
  const small = await params({ m: 1024 * 1024 });
  await assert.rejects(() => deriveRoot('tally123', tiny), /too weak/);
  await assert.rejects(() => deriveRoot('tally123', small), /too weak/);
});

test('a malicious blob cannot force weak Argon2id iterations', async () => {
  const p = await params({ t: 1 });
  await assert.rejects(() => deriveRoot('tally123', p), /too weak/);
});

test('a malicious blob cannot force an absurdly expensive derivation', async () => {
  // The DoS direction, and the one that actually reaches users: this dashboard is meant to be
  // opened on a phone, and the module's own comment notes that >256MiB risks OOM on iOS.
  // Measured unbounded: m=1GiB took 50s, m=64MiB/t=40 took 46s. Nothing stops m=16GiB/t=2^31.
  const huge = await params({ m: 1024 * 1024 * 1024 });
  const slow = await params({ t: 40 });
  await assert.rejects(() => deriveRoot('x', huge), /too expensive/);
  await assert.rejects(() => deriveRoot('x', slow), /too expensive/);
});

test('non-integer and negative Argon2id params are rejected as such', async () => {
  // libsodium happens to reject these itself, but with "opsLimit must be an unsigned integer",
  // which tells a support engineer nothing about WHERE the bad value came from.
  for (const bad of [1.5, -1, NaN, Infinity]) {
    const badT = await params({ t: bad });
    const badM = await params({ m: bad });
    await assert.rejects(() => deriveRoot('x', badT), /argon2id/i);
    await assert.rejects(() => deriveRoot('x', badM), /argon2id/i);
  }
});

test('the default params still derive, and derive the same root twice', async () => {
  const p = defaultKdfParams(await randomSalt());
  const a = await deriveRoot('correct horse battery staple', p);
  const b = await deriveRoot('correct horse battery staple', p);
  assert.equal(toBase64(a), toBase64(b));
  assert.equal(a.length, 32);
});

test('a raised-but-sane param set is still honoured', async () => {
  // The whole point of carrying params in the blob: a future build may raise them, and this
  // build must keep opening its own blobs while accepting stronger ones.
  const root = await deriveRoot('x', await params({ m: 96 * 1024 * 1024, t: 4 }));
  assert.equal(root.length, 32);
});

test('a bad salt length is still rejected', async () => {
  const sodium = await sodiumReady();
  const short = toBase64(new Uint8Array(sodium.crypto_pwhash_SALTBYTES - 1));
  const p = await params({ salt: short });
  await assert.rejects(() => deriveRoot('x', p), /salt length/);
});

test('a non-argon2id kdf is still rejected', async () => {
  const p = await params({ kdf: 'scrypt' as never });
  await assert.rejects(() => deriveRoot('x', p), /unsupported kdf/);
});
