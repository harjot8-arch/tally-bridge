import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalStringify } from '@tally-bridge/core';
import type { EnvelopeAad, RosterDoc, WrappedKey } from '@tally-bridge/core';
import { sodiumReady } from '../src/sodium.ts';
import {
  RosterError,
  acceptRosterVersion,
  decodeRoster,
  encodeRoster,
  deviceFingerprint,
  type SealedRoster,
} from '../src/trust.ts';
import {
  generateIdentity,
  generateRecoveryKey,
  openIdentity,
  wrapIdentity,
  wrapUnderPassphrase,
  wrapUnderRecoveryKey,
} from '../src/identity.ts';
import {
  ENVELOPE_SIG_VERSION,
  envelopeSigningBytes,
  makeAad,
  openSection,
  sealSection,
  type MaybeSignedEnvelope,
} from '../src/envelope.ts';
import { compress } from '../src/compress.ts';
import { pad } from '../src/padme.ts';
import { fromBase64, toBase64 } from '../src/kdf.ts';

const PASSPHRASE = 'Ramesh@1985';
const TENANT = 'tnt_abc';
const COMPANY = '4f9a1b2c-0000-1111-2222-333344445555';
const AS_OF = '2026-07-16';

const aad = (over: Partial<EnvelopeAad> = {}): EnvelopeAad =>
  makeAad({
    tenantId: TENANT,
    deviceId: 'dev_001',
    companyGuid: COMPANY,
    section: 'ageing_receivable',
    asOf: AS_OF,
    snapshotTs: 1_752_600_000_000,
    seq: 42,
    ...over,
  });

/** The FULL powers of a malicious server: idPK, every device PUBLIC key, every blob. */
async function serverMints(plaintext: Uint8Array, a: EnvelopeAad, idPK: Uint8Array) {
  const sodium = await sodiumReady();
  const cek = sodium.randombytes_buf(32);
  const nonce = sodium.randombytes_buf(24);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    pad(await compress(plaintext)),
    new TextEncoder().encode(canonicalStringify(a as never)),
    null,
    nonce,
    cek,
  );
  const contentHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', plaintext as BufferSource),
  );
  return {
    aad: a,
    nonce: toBase64(nonce),
    sealedCek: toBase64(sodium.crypto_box_seal(cek, idPK)),
    ciphertext: toBase64(ct),
    contentHash: toBase64(contentHash),
  };
}

async function fixture() {
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const honest = sodium.crypto_sign_keypair();
  const roster: SealedRoster = {
    version: 1,
    devices: [{ deviceId: 'dev_001', publicKey: honest.publicKey }],
  };
  const recoveryKey = await generateRecoveryKey();
  const wraps = await wrapIdentity(id.secretKey, roster, { passphrase: PASSPHRASE, recoveryKey });
  return { id, honest, roster, recoveryKey, wraps, sodium };
}

/* ================================================================== *
 * ATTACK 2 — the forgery, end to end, four ways.
 * ================================================================== */

test('ADV: server forgery, all four routes, against a roster from the intended path', async () => {
  const { id, honest, wraps, recoveryKey, sodium } = await fixture();

  // The reader gets its roster THE INTENDED WAY: out of the sealed bundle.
  const opened = await openIdentity(
    wraps.recovery,
    { kind: 'recovery', recoveryKey },
    { kind: 'first-use' },
  );
  const opts = {
    identityPublicKey: id.publicKey,
    identitySecretKey: opened.identitySecretKey,
    expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable' as const, asOf: AS_OF },
    trustedDevices: opened.roster,
  };

  const lie = new TextEncoder().encode(
    JSON.stringify({ rows: [{ party: 'FAKE DEBTOR', amount: '9999999.00' }] }),
  );
  const base = await serverMints(lie, aad(), id.publicKey);

  // (a) The server signs with ITS OWN Ed25519 key.
  const evil = sodium.crypto_sign_keypair();
  const evilSig = sodium.crypto_sign_detached(
    envelopeSigningBytes({
      sigVer: ENVELOPE_SIG_VERSION,
      alg: 'ed25519',
      aad: new TextEncoder().encode(canonicalStringify(aad() as never)),
      nonce: fromBase64(base.nonce),
      sealedCek: fromBase64(base.sealedCek),
      ciphertext: fromBase64(base.ciphertext),
      contentHash: fromBase64(base.contentHash),
    }),
    evil.privateKey,
  );
  await assert.rejects(
    openSection({ ...base, sig: { v: 1, alg: 'ed25519', sig: toBase64(evilSig) } } as MaybeSignedEnvelope, opts),
    /bad envelope signature/,
    '(a) server-key-signed forgery must be refused',
  );

  // (b) Replay a GENUINE signature onto fabricated ciphertext.
  const genuine = await sealSection({ rows: [] }, aad(), id.publicKey, honest.privateKey);
  await assert.rejects(
    openSection({ ...base, sig: genuine.sig } as MaybeSignedEnvelope, opts),
    /bad envelope signature/,
    '(b) lifted signature must not verify over different bytes',
  );

  // (c) Signature stripped.
  await assert.rejects(
    openSection(base as MaybeSignedEnvelope, opts),
    /not signed/,
    '(c) unsigned must be refused, not soft-landed',
  );

  // (d) alg: 'none'
  await assert.rejects(
    openSection({ ...base, sig: { v: 1, alg: 'none', sig: '' } } as unknown as MaybeSignedEnvelope, opts),
    /unsupported envelope signature algorithm/,
    "(d) alg:'none' must be compared, never dispatched on",
  );

  // Sanity: the honest envelope DOES open, so the refusals above are not vacuous.
  const ok = await sealSection({ rows: [{ party: 'REAL' }] }, aad(), id.publicKey, honest.privateKey);
  assert.deepEqual(await openSection(ok, opts), { rows: [{ party: 'REAL' }] });
});

test('ADV: sig object shenanigans — prototype alg, getter alg, array sig', async () => {
  const { id, honest, roster } = await fixture();
  const opts = {
    identityPublicKey: id.publicKey,
    identitySecretKey: id.secretKey,
    expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable' as const, asOf: AS_OF },
    trustedDevices: roster.devices,
  };
  const env = await sealSection({ rows: [] }, aad(), id.publicKey, honest.privateKey);

  // alg inherited from the prototype rather than own — `!==` still reads it, so this is only a
  // check that nothing does a hasOwnProperty-style gate.
  const protoSig = Object.create({ alg: 'ed25519' }) as Record<string, unknown>;
  protoSig.v = 1;
  protoSig.sig = env.sig.sig;
  assert.deepEqual(await openSection({ ...env, sig: protoSig } as never, opts), { rows: [] });

  // sig as an ARRAY of bytes rather than a base64 string: Buffer.from(array,'base64') ignores
  // the encoding. fromBase64 is atob-based, so this must throw rather than decode.
  await assert.rejects(
    openSection({ ...env, sig: { v: 1, alg: 'ed25519', sig: [1, 2, 3] } } as never, opts),
    /.*/,
  );

  // sig: null / sig: 'not-base64!!'
  await assert.rejects(openSection({ ...env, sig: null } as never, opts), /not signed/);
  await assert.rejects(
    openSection({ ...env, sig: { v: 1, alg: 'ed25519', sig: '!!!!' } } as never, opts),
    /not valid base64/,
  );
});

/* ================================================================== *
 * ATTACK 5 — version type confusion.
 * ================================================================== */

const KEY44 = 'A'.repeat(43) + '=';

const rosterDocWith = (version: unknown): unknown => ({
  v: 1,
  version,
  devices: [{ deviceId: 'dev_001', publicKey: KEY44 }],
});

test('ADV: every hostile roster.version shape is refused at decode', async () => {
  const hostile: [string, unknown][] = [
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-Infinity', -Infinity],
    ['-1', -1],
    ['0', 0],
    ['1.5', 1.5],
    ['2^53', 2 ** 53],
    ['2^53+1', 2 ** 53 + 1],
    ['string "2"', '2'],
    ['null', null],
    ['undefined', undefined],
    ['object', { valueOf: () => 5 }],
    ['array [5]', [5]],
    ['bigint', 5n],
    ['boolean true', true],
    ['-0', -0],
  ];
  for (const [name, version] of hostile) {
    assert.throws(
      () => decodeRoster(rosterDocWith(version)),
      RosterError,
      `roster.version = ${name} must be refused`,
    );
  }
  // And the only good one works.
  assert.equal(decodeRoster(rosterDocWith(1)).version, 1);
  assert.equal(decodeRoster(rosterDocWith(9007199254740991)).version, 9007199254740991);
});

test('ADV: acceptRosterVersion — NaN cannot pass in EITHER slot, and validation precedes compare', async () => {
  // NaN as the incoming version, against a remembering reader.
  assert.throws(() => acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, NaN), RosterError);
  // NaN as the incoming version, against a FRESH reader — the early-return path.
  assert.throws(() => acceptRosterVersion({ kind: 'first-use' }, NaN), RosterError);
  // NaN as the STORED high-water mark: must not read as "no memory".
  assert.throws(
    () => acceptRosterVersion({ kind: 'seen', highestVersionSeen: NaN }, 1),
    /unreadable memory/,
  );
  // Every other hostile hwm.
  for (const hwm of [Infinity, -1, 0, 1.5, '5' as never, null as never, undefined as never, {} as never]) {
    assert.throws(
      () => acceptRosterVersion({ kind: 'seen', highestVersionSeen: hwm }, 9),
      RosterError,
      `hwm ${String(hwm)} must not be treated as no memory`,
    );
  }
  // The honest paths.
  assert.equal(acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 5), 5);
  assert.equal(acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 6), 6);
  assert.throws(() => acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 4), /rolled back/);
});

test('ADV: acceptRosterVersion returns the NEW high-water mark, never a stale one', () => {
  // If it returned `seen` instead of `version`, the mark would never advance and rollback to
  // any version >= the first would be permanently accepted.
  assert.equal(acceptRosterVersion({ kind: 'seen', highestVersionSeen: 2 }, 7), 7);
});

/* ================================================================== *
 * ATTACK 3 — rollback against a REMEMBERING reader, end to end.
 * ================================================================== */

test('ADV: a remembering reader cannot be rolled back through ANY of the three wraps', async () => {
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const d1 = sodium.crypto_sign_keypair();
  const stolen = sodium.crypto_sign_keypair();
  const recoveryKey = await generateRecoveryKey();
  const deviceKey = sodium.randombytes_buf(32);

  // v1: dev_001 + the soon-to-be-revoked dev_002.
  const v1: SealedRoster = {
    version: 1,
    devices: [
      { deviceId: 'dev_001', publicKey: d1.publicKey },
      { deviceId: 'dev_002', publicKey: stolen.publicKey },
    ],
  };
  const old = await wrapIdentity(id.secretKey, v1, { passphrase: PASSPHRASE, recoveryKey, deviceKey });

  // v2: dev_002 revoked.
  const v2: SealedRoster = { version: 2, devices: [{ deviceId: 'dev_001', publicKey: d1.publicKey }] };
  const cur = await wrapIdentity(id.secretKey, v2, { passphrase: PASSPHRASE, recoveryKey, deviceKey });

  // The reader has seen v2.
  const seen = await openIdentity(cur.recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });
  assert.equal(seen.highestVersionSeen, 2);
  const memory = { kind: 'seen' as const, highestVersionSeen: seen.highestVersionSeen };

  // The server now serves the OLD blob. Every wrap must refuse.
  await assert.rejects(
    openIdentity(old.recovery, { kind: 'recovery', recoveryKey }, memory),
    /rolled back/,
    'recovery wrap must not be a rollback path',
  );
  await assert.rejects(
    openIdentity(old.device!, { kind: 'device', deviceKey }, memory),
    /rolled back/,
    'device wrap must not be a rollback path',
  );
  await assert.rejects(
    openIdentity(old.pass, { kind: 'pass', passphrase: PASSPHRASE }, memory),
    /rolled back/,
    'passphrase wrap must not be a rollback path',
  );

  // And the revoked key really would have been re-admitted, so the test is not vacuous.
  const fresh = await openIdentity(old.recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });
  assert.equal(fresh.roster.length, 2, 'THE RESIDUAL: a fresh reader takes the old roster');
  const forged = await sealSection(
    { rows: [{ party: 'FAKE', amount: '9999999.00' }] },
    aad({ deviceId: 'dev_002' }),
    id.publicKey,
    stolen.privateKey,
  );
  const opts = (r: typeof fresh.roster) => ({
    identityPublicKey: id.publicKey,
    identitySecretKey: id.secretKey,
    expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable' as const, asOf: AS_OF },
    trustedDevices: r,
  });
  // The rolled-back roster ACCEPTS the revoked device's forgery — that is exactly what the
  // version check exists to stop, and what a fresh reader still eats.
  assert.ok(await openSection(forged, opts(fresh.roster)));
  // The current roster refuses it.
  await assert.rejects(openSection(forged, opts(seen.roster)), /untrusted device dev_002/);
});

/* ================================================================== *
 * ATTACK 4 — can the three wraps be made to disagree?
 * ================================================================== */

test('ADV: the low-level primitives CAN mint disagreeing wraps — what stops the reader?', async () => {
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const d1 = sodium.crypto_sign_keypair();
  const evil = sodium.crypto_sign_keypair();
  const recoveryKey = await generateRecoveryKey();

  const good = encodeRoster({ version: 2, devices: [{ deviceId: 'dev_001', publicKey: d1.publicKey }] });
  const bad = encodeRoster({ version: 2, devices: [{ deviceId: 'dev_001', publicKey: evil.publicKey }] });

  // wrapUnderPassphrase / wrapUnderRecoveryKey take a roster each. Nothing cross-checks them.
  const pass = await wrapUnderPassphrase(id.secretKey, PASSPHRASE, good);
  const recovery = await wrapUnderRecoveryKey(id.secretKey, recoveryKey, bad);

  const viaPass = await openIdentity(pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });
  const viaRec = await openIdentity(recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });

  // DISAGREEMENT, CONSTRUCTED. Same version, different keys, and nothing anywhere notices.
  assert.equal(viaPass.rosterVersion, viaRec.rosterVersion);
  assert.notDeepEqual(viaPass.roster[0]!.publicKey, viaRec.roster[0]!.publicKey);
  // The recovery sheet now pins the attacker's key, at the SAME version, so the high-water
  // mark cannot see it.
  const forged = await sealSection({ rows: [{ party: 'FAKE' }] }, aad(), id.publicKey, evil.privateKey);
  assert.ok(
    await openSection(forged, {
      identityPublicKey: id.publicKey,
      identitySecretKey: id.secretKey,
      expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable' as const, asOf: AS_OF },
      trustedDevices: viaRec.roster,
    }),
    'a wrap minted by the primitives pins whatever it was handed',
  );
});

test('ADV: wrapIdentity itself cannot be talked into a per-wrap roster', async () => {
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const d1 = sodium.crypto_sign_keypair();
  const recoveryKey = await generateRecoveryKey();

  // A roster whose `devices` array MUTATES as it is read — encodeRoster maps it once, so this
  // is the seam a disagreement would come through if the roster were encoded per wrap.
  let reads = 0;
  const shifty = {
    version: 3,
    get devices() {
      reads += 1;
      const evil = sodium.crypto_sign_keypair();
      return reads > 1
        ? [{ deviceId: 'dev_001', publicKey: evil.publicKey }]
        : [{ deviceId: 'dev_001', publicKey: d1.publicKey }];
    },
  } as unknown as SealedRoster;

  const wraps = await wrapIdentity(id.secretKey, shifty, { passphrase: PASSPHRASE, recoveryKey });
  const a = await openIdentity(wraps.pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });
  const b = await openIdentity(wraps.recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });
  // THE PROPERTY THAT MATTERS: whatever it sealed, it sealed the SAME bytes into every wrap.
  // `wrapIdentity` encodes once into `doc` and hands that one object to every `wrap()` call, so
  // even a roster that changes under it cannot make two wraps disagree.
  assert.deepEqual(a.roster, b.roster, 'wrapIdentity must encode the roster exactly once');
  assert.equal(a.rosterVersion, b.rosterVersion);
  // NOTE: `encodeRoster` reads `roster.devices` twice (the emptiness check, then the map), so a
  // getter can make the SEALED key differ from the one that passed the emptiness check. Benign —
  // a `SealedRoster` only ever comes from `initialRoster`/`admitPairedDevice`/`revokeDevice`,
  // which return plain objects, and the server never supplies one. Recorded, not fixed: the
  // emitted doc is still self-consistent because it is built from a single read and then
  // re-validated by `decodeRoster`.
  assert.equal(reads, 2, 'encodeRoster reads .devices twice — see note above');
});

/* ================================================================== *
 * ATTACK 6 — base64.
 * ================================================================== */

test('ADV: no roster key is manufactured out of junk', async () => {
  const junk = [
    'WIFI:S:OfficeNet;T:WPA;P:hunter2;;',
    'A'.repeat(42) + '=',
    'A'.repeat(44) + '=',
    'A'.repeat(43) + '==',
    'A'.repeat(43),
    'A'.repeat(42) + '-=', // '-' is base64url, not base64
    'A'.repeat(42) + '_=',
    ' ' + 'A'.repeat(43) + '=',
    'A'.repeat(43) + '=\n',
    'AAAA AAAA' + 'A'.repeat(35) + '=',
    // Non-canonical: the trailing 6-bit group has 2 slack bits. 'B' and 'A' in the last payload
    // slot decode to the SAME 32 bytes. The round-trip check is the only thing that sees this.
    'A'.repeat(42) + 'B=',
    'A'.repeat(42) + 'C=',
  ];
  for (const publicKey of junk) {
    assert.throws(
      () => decodeRoster({ v: 1, version: 1, devices: [{ deviceId: 'dev_001', publicKey }] }),
      RosterError,
      `publicKey ${JSON.stringify(publicKey)} must not become a key`,
    );
  }
  // Prove the slack-bit claim: these two DO decode identically, so only the round-trip caught it.
  assert.deepEqual(fromBase64('A'.repeat(42) + 'B='), fromBase64('A'.repeat(42) + 'A='));
});

test('ADV: publicKey as a non-string, and deviceId as a non-string', () => {
  const shapes: unknown[] = [
    [1, 2, 3],
    new Uint8Array(32),
    null,
    undefined,
    42,
    { toString: () => KEY44 },
  ];
  for (const publicKey of shapes) {
    assert.throws(
      () => decodeRoster({ v: 1, version: 1, devices: [{ deviceId: 'dev_001', publicKey }] }),
      RosterError,
    );
  }
  for (const deviceId of [null, undefined, 42, '', ['dev_001']]) {
    assert.throws(
      () => decodeRoster({ v: 1, version: 1, devices: [{ deviceId, publicKey: KEY44 }] }),
      RosterError,
    );
  }
});

/* ================================================================== *
 * ATTACK 8 — empty / missing roster.
 * ================================================================== */

test('ADV: missing, empty, null and wrong-shaped rosters all fail LOUDLY', async () => {
  const id = await generateIdentity();

  // No roster at all (the primitive path).
  const bare = await wrapUnderPassphrase(id.secretKey, PASSPHRASE);
  await assert.rejects(
    openIdentity(bare, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' }),
    (e: Error) => e.name === 'RosterError' && /carries no device roster/.test(e.message),
    'a roster-less bundle must not open',
  );

  // Empty devices array.
  assert.throws(() => decodeRoster({ v: 1, version: 1, devices: [] }), /roster is empty/);
  assert.throws(
    () => encodeRoster({ version: 1, devices: [] }),
    /refusing to seal an empty roster/,
  );
  // Not an object / array / null.
  for (const doc of [null, undefined, 'roster', 42, [], [{ deviceId: 'x' }]]) {
    assert.throws(() => decodeRoster(doc), RosterError, `decodeRoster(${JSON.stringify(doc)})`);
  }
  // devices missing or not an array.
  assert.throws(() => decodeRoster({ v: 1, version: 1 }), /no devices array/);
  assert.throws(() => decodeRoster({ v: 1, version: 1, devices: {} }), /no devices array/);
  // wrong doc version.
  assert.throws(() => decodeRoster({ v: 2, version: 1, devices: [] }), /unsupported roster version/);
});

test('ADV: openSection refuses an empty roster rather than verifying against nothing', async () => {
  const { id, honest } = await fixture();
  const env = await sealSection({ rows: [] }, aad(), id.publicKey, honest.privateKey);
  await assert.rejects(
    openSection(env, {
      identityPublicKey: id.publicKey,
      identitySecretKey: id.secretKey,
      expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable' as const, asOf: AS_OF },
      trustedDevices: [],
    }),
    /refusing to verify against nothing/,
  );
});

/* ================================================================== *
 * ATTACK 7 — does the Bridge still hold no decryption key?
 * ================================================================== */

test('ADV: the Ed25519 device key converted to X25519 still cannot read an upload', async () => {
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const dev = sodium.crypto_sign_keypair();
  const env = await sealSection({ rows: [{ party: 'REAL' }] }, aad(), id.publicKey, dev.privateKey);

  // The strongest form of the attack: convert the SIGNING key the Bridge does hold into an
  // X25519 secret and try it against the sealed CEK.
  const xsk = sodium.crypto_sign_ed25519_sk_to_curve25519(dev.privateKey);
  const xpk = sodium.crypto_sign_ed25519_pk_to_curve25519(dev.publicKey);
  assert.throws(
    () => sodium.crypto_box_seal_open(fromBase64(env.sealedCek), xpk, xsk),
    'the device signing key must not open the sealed CEK',
  );
  // And the identity public key — the only other thing the Bridge holds — opens nothing.
  assert.throws(() => sodium.crypto_box_seal_open(fromBase64(env.sealedCek), id.publicKey, id.publicKey));
});

/* ================================================================== *
 * Fingerprint.
 * ================================================================== */

test('ADV: deviceFingerprint is injective in the key and rejects wrong lengths', async () => {
  const sodium = await sodiumReady();
  const a = sodium.crypto_sign_keypair().publicKey;
  const b = sodium.crypto_sign_keypair().publicKey;
  assert.notEqual(await deviceFingerprint(a), await deviceFingerprint(b));
  assert.match(await deviceFingerprint(a), /^([0-9A-F]{4} ){3}[0-9A-F]{4}$/);
  await assert.rejects(deviceFingerprint(new Uint8Array(31)));
  await assert.rejects(deviceFingerprint(new Uint8Array(33)));

  // Keys differing in only the FIRST byte must not collide — the domain tag is 34 bytes written
  // into a 64-byte buffer and then partly overwritten by the key at offset 32, so bytes 32-33 of
  // the tag are clobbered. Confirm the key still lands in full.
  const c = new Uint8Array(a);
  c[0] = a[0]! ^ 0xff;
  assert.notEqual(await deviceFingerprint(a), await deviceFingerprint(c));
  const d = new Uint8Array(a);
  d[31] = a[31]! ^ 0xff;
  assert.notEqual(await deviceFingerprint(a), await deviceFingerprint(d));
});
