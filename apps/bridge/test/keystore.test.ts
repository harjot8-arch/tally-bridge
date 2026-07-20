import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Keystore,
  KeystoreUnavailableError,
  type KeystoreBackend,
  type SafeStorageLike,
} from '../src/main/keystore.ts';

/** A safeStorage stand-in. "Encryption" is a reversible marker — we test wiring, not sodium. */
function fakeSafe(available = true): SafeStorageLike & { corrupt: boolean } {
  return {
    corrupt: false,
    isEncryptionAvailable: () => available,
    encryptString(s: string) {
      return Buffer.from('enc:' + s, 'utf8');
    },
    decryptString(b: Buffer) {
      const s = b.toString('utf8');
      if (this.corrupt) throw new Error('OS key changed');
      if (!s.startsWith('enc:')) throw new Error('not encrypted by us');
      return s.slice(4);
    },
  };
}

function memBackend(): KeystoreBackend & { store: Map<string, Buffer> } {
  const store = new Map<string, Buffer>();
  return {
    store,
    read: (k) => store.get(k),
    write: (k, v) => void store.set(k, v),
    delete: (k) => void store.delete(k),
    has: (k) => store.has(k),
  };
}

test('HARD-FAIL: an unavailable keystore refuses to start rather than degrading', () => {
  // The worst outcome would be a silent fallback to a plaintext file: the app keeps working,
  // nobody notices, and the device key sits unprotected on disk. Refusing is loud, and loud is
  // correct — a failed setup is a support call; a silently-unprotected key is a breach.
  assert.throws(() => new Keystore(fakeSafe(false), memBackend()), KeystoreUnavailableError);
});

test('the failure message is a sentence an owner can act on', () => {
  try {
    new Keystore(fakeSafe(false), memBackend());
    assert.fail('should have thrown');
  } catch (e) {
    const msg = (e as Error).message;
    assert.match(msg, /Credential Manager/, 'names the actual Windows cause');
    assert.doesNotMatch(msg, /safeStorage|isEncryptionAvailable|undefined/, 'no jargon');
  }
});

test('nothing is written in the clear', () => {
  const backend = memBackend();
  const ks = new Keystore(fakeSafe(), backend);
  ks.setDevice('dev_1', new Uint8Array([1, 2, 3]), new Uint8Array([9, 9, 9]));
  ks.setTenantId('tnt_secret');

  for (const [k, v] of backend.store) {
    assert.ok(v.toString('utf8').startsWith('enc:'), `${k} must go through safeStorage`);
  }
  const dump = [...backend.store.values()].map((v) => v.toString('utf8')).join('');
  assert.ok(!dump.includes('tnt_secret') || dump.includes('enc:tnt_secret'));
});

test('the device signing key round-trips', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  const sk = new Uint8Array([1, 2, 3, 4]);
  const pk = new Uint8Array([5, 6, 7, 8]);
  ks.setDevice('dev_1', pk, sk);
  assert.equal(ks.getDeviceId(), 'dev_1');
  assert.deepEqual(ks.getDeviceSecretKey(), sk);
  assert.deepEqual(ks.getDevicePublicKey(), pk);
});

test('THE SHAPE OF THE API IS THE SECURITY PROPERTY: there is no way to store an identity secret', () => {
  // The Bridge must never hold a key that decrypts its own uploads. That is enforced here by
  // absence — the wrong thing is unwritable, not merely discouraged.
  const ks = new Keystore(fakeSafe(), memBackend()) as unknown as Record<string, unknown>;
  assert.equal(typeof ks.setIdentityPublicKey, 'function');
  assert.equal(ks.setIdentitySecretKey, undefined, 'no such method may ever exist');
  assert.equal(ks.getIdentitySecretKey, undefined);
});

test('the identity public key round-trips', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  const pk = new Uint8Array(32).fill(7);
  ks.setIdentityPublicKey(pk);
  assert.deepEqual(ks.getIdentityPublicKey(), pk);
});

test('isProvisioned needs both the device key and the identity public key', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  assert.equal(ks.isProvisioned(), false);
  ks.setDevice('d', new Uint8Array([1]), new Uint8Array([2]));
  assert.equal(ks.isProvisioned(), false, 'a device key alone cannot seal anything');
  ks.setIdentityPublicKey(new Uint8Array(32));
  assert.equal(ks.isProvisioned(), true);
});

test('an undecryptable blob reads as absent instead of wedging the app', () => {
  // The OS key changes on a Windows profile reset or a restore to a different machine, making
  // the blob undecryptable FOREVER. Re-pairing is a 6-digit code; wedging is a dead install.
  const safe = fakeSafe();
  const ks = new Keystore(safe, memBackend());
  ks.setDevice('dev_1', new Uint8Array([1]), new Uint8Array([2]));
  assert.equal(ks.getDeviceId(), 'dev_1');

  safe.corrupt = true;
  assert.equal(ks.getDeviceId(), undefined, 'absent, not a thrown error');
  assert.equal(ks.getDeviceSecretKey(), undefined);
});

test('the opt-in device unlock blob round-trips and can be forgotten', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  assert.equal(ks.getWrappedIdentityForDevice(), undefined, 'off by default');
  ks.setWrappedIdentityForDevice('{"kind":"device"}');
  assert.equal(ks.getWrappedIdentityForDevice(), '{"kind":"device"}');
  ks.forgetWrappedIdentity();
  assert.equal(ks.getWrappedIdentityForDevice(), undefined, 'turning the toggle off must erase it');
});

test('seq persists and survives garbage', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  assert.equal(ks.getSeq(), 0);
  ks.setSeq(42);
  assert.equal(ks.getSeq(), 42);
});

test('a corrupted seq reads as 0 rather than NaN', () => {
  // seq is bound into the AAD. NaN there would fail canonicalization on every upload — a total
  // outage from one bad byte. A rollback to 0 is survivable: the AEAD nonce is random, so seq
  // is an audit signal, not a security-critical counter.
  const backend = memBackend();
  const safe = fakeSafe();
  const ks = new Keystore(safe, backend);
  backend.write('device.seq', safe.encryptString('not-a-number'));
  assert.equal(ks.getSeq(), 0);
  backend.write('device.seq', safe.encryptString('-5'));
  assert.equal(ks.getSeq(), 0, 'negative is nonsense too');
});

test('wipe clears everything, for the clean-reset recovery path', () => {
  const backend = memBackend();
  const ks = new Keystore(fakeSafe(), backend);
  ks.setDevice('d', new Uint8Array([1]), new Uint8Array([2]));
  ks.setIdentityPublicKey(new Uint8Array(32));
  ks.setTenantId('t');
  ks.setServerUrl('https://x.vercel.app');
  ks.setSeq(9);
  ks.setWrappedIdentityForDevice('{}');

  ks.wipe();

  assert.equal(backend.store.size, 0);
  assert.equal(ks.isProvisioned(), false);
});

test('PATH TRAVERSAL: every key the keystore uses is a safe filename', () => {
  // The file backend builds a path as `encodeURIComponent(key) + '.bin'`. encodeURIComponent
  // escapes '/' and '\' but NOT '.', so it is the KEY SET — not the encoding — that rules out
  // traversal. No key is attacker-controlled today; this pins that, because the day someone
  // keys a blob by company GUID or a server-supplied device id, the traversal is silent.
  const backend = memBackend();
  const ks = new Keystore(fakeSafe(), backend);
  ks.setDevice('dev_1', new Uint8Array([1]), new Uint8Array([2]));
  ks.setIdentityPublicKey(new Uint8Array(32));
  ks.setTenantId('t');
  ks.setServerUrl('https://x.vercel.app');
  ks.setSeq(1);
  ks.setWrappedIdentityForDevice('{}');

  assert.ok(backend.store.size > 0, 'must actually be exercising the key set');
  for (const key of backend.store.keys()) {
    // The property that matters: the encoded name cannot escape its directory or name a device.
    const encoded = encodeURIComponent(key);
    assert.equal(encoded, key, `${key} must need no escaping at all`);
    assert.match(key, /^[a-z]+(\.[a-z]+)*$/, `${key} must be a plain dotted constant`);
    assert.ok(!key.includes('..'), `${key} must not contain a traversal segment`);
    assert.ok(!/[/\\:*?"<>|\0]/.test(key), `${key} must contain no path or device characters`);
  }
});

test('the key set is fixed, and wipe covers all of it', () => {
  // wipe() iterates Object.values(K). A key written through some other path would survive a
  // "reset dashboard" and silently re-provision the next launch.
  const backend = memBackend();
  const ks = new Keystore(fakeSafe(), backend);
  ks.setDevice('d', new Uint8Array([1]), new Uint8Array([2]));
  ks.setIdentityPublicKey(new Uint8Array(32));
  ks.setTenantId('t');
  ks.setServerUrl('https://x.vercel.app');
  ks.setSeq(9);
  ks.setWrappedIdentityForDevice('{}');
  const written = [...backend.store.keys()].sort();

  ks.wipe();
  assert.equal(backend.store.size, 0, `wipe missed one of: ${written.join(', ')}`);
});

test('a cycle finishing after a wipe cannot re-provision the install', () => {
  // The real ordering: index.ts persists seq in a `finally`, so a "reset dashboard" during an
  // in-flight cycle is followed by a setSeq() that re-creates a key AFTER the wipe. That must
  // not be enough to look provisioned — otherwise a reset silently half-undoes itself.
  const backend = memBackend();
  const ks = new Keystore(fakeSafe(), backend);
  ks.setDevice('d', new Uint8Array([1]), new Uint8Array([2]));
  ks.setIdentityPublicKey(new Uint8Array(32));

  ks.wipe();
  ks.setSeq(7); // the in-flight cycle's finally block, landing late

  assert.equal(ks.isProvisioned(), false, 'a stray seq must never resurrect the install');
  assert.equal(ks.getDeviceSecretKey(), undefined);
  assert.equal(ks.getIdentityPublicKey(), undefined);
});

test('server url and tenant round-trip', () => {
  const ks = new Keystore(fakeSafe(), memBackend());
  ks.setServerUrl('https://acme.vercel.app');
  ks.setTenantId('tnt_1');
  assert.equal(ks.getServerUrl(), 'https://acme.vercel.app');
  assert.equal(ks.getTenantId(), 'tnt_1');
});
