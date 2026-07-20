import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { RosterDoc, WrappedKey } from '@tally-bridge/core';
import {
  ROSTER_FIRST_VERSION,
  RosterError,
  acceptRosterVersion,
  decodeRoster,
  deviceFingerprint,
  encodeRoster,
  type SealedRoster,
} from '../src/trust.ts';
import {
  generateIdentity,
  generateRecoveryKey,
  openIdentity,
  wrapIdentity,
  wrapUnderPassphrase,
  unwrapWithPassphrase,
} from '../src/identity.ts';
import { makeAad, openSection, sealSection } from '../src/envelope.ts';
import { sodiumReady } from '../src/sodium.ts';

/**
 * THE ROSTER DISTRIBUTION TESTS.
 *
 * The property under test is not "the crypto works" — libsodium's tests cover that. It is:
 * A MALICIOUS SERVER CANNOT CHOOSE WHICH DEVICE KEY THE READER TRUSTS. Every test below is an
 * attempt to make it choose one anyway.
 *
 * The server's powers, stated precisely, because a test against a weaker attacker proves
 * nothing. It holds: the identity PUBLIC key (onboarding sets it as an env var there), every
 * device PUBLIC key (it verifies RFC 9421 uploads with them), every sealed envelope, and every
 * WrappedKey blob. It can mint keypairs, fabricate envelopes, and return any stored blob it
 * likes, including an old one. It does NOT hold: the passphrase, the recovery key, or the
 * identity secret.
 */

const PASSPHRASE = 'Ramesh@1985';

async function deviceKeypair() {
  const sodium = await sodiumReady();
  return sodium.crypto_sign_keypair();
}

async function fixture() {
  const id = await generateIdentity();
  const honest = await deviceKeypair();
  const roster: SealedRoster = {
    version: 1,
    devices: [{ deviceId: 'dev_001', publicKey: honest.publicKey }],
  };
  const recoveryKey = await generateRecoveryKey();
  const wraps = await wrapIdentity(id.secretKey, roster, { passphrase: PASSPHRASE, recoveryKey });
  return { id, honest, roster, recoveryKey, wraps };
}

/* ------------------------------------------------------------------ *
 * The attack the whole file exists for
 * ------------------------------------------------------------------ */

test('THE ATTACK: a server-supplied roster cannot override the sealed one', async () => {
  const { id, wraps } = await fixture();

  // The malicious server mints its own device keypair and fabricates an envelope with it. Note
  // it needs nothing it does not have: the identity public key seals the CEK, and it invents
  // the plaintext and therefore the matching contentHash.
  const evil = await deviceKeypair();
  const forgery = await sealSection(
    { rows: [{ party: 'GHOST TRADERS', amount: '9999999.00' }] },
    makeAad({
      tenantId: 't',
      deviceId: 'dev_001', // it even claims to be the honest device
      companyGuid: 'g',
      section: 'ageing_receivable',
      asOf: '2026-07-16',
      snapshotTs: 2,
      seq: 2,
    }),
    id.publicKey,
    evil.privateKey,
  );

  // The reader unlocks with the passphrase. The roster it gets is the SEALED one — there is no
  // other source for it, which is the entire design: `WrappedKey` has no roster field to read
  // and `openIdentity` is the only producer of one.
  const opened = await openIdentity(
    wraps.pass,
    { kind: 'pass', passphrase: PASSPHRASE },
    { kind: 'first-use' },
  );

  await assert.rejects(
    () =>
      openSection(forgery, {
        identityPublicKey: id.publicKey,
        identitySecretKey: opened.identitySecretKey,
        expect: { tenantId: 't', companyGuid: 'g', section: 'ageing_receivable', asOf: '2026-07-16' },
        trustedDevices: opened.roster,
      }),
    /bad envelope signature/,
    'the server signed with its own key; the sealed roster does not list it',
  );
});

test('the roster is not reachable without the wrapping key: there is no field to read', async () => {
  const { wraps } = await fixture();

  // The blob as the server stores and serves it. If a roster could be plucked off this object
  // and passed to openSection, every other test in this file would be theatre.
  const onWire = JSON.parse(JSON.stringify(wraps.pass)) as Record<string, unknown>;
  assert.deepEqual(
    Object.keys(onWire).sort(),
    ['ciphertext', 'kdf', 'kind', 'nonce', 'v'],
    'WrappedKey must expose no roster field — see the comment on the type',
  );

  // And the device key is not recoverable from the bytes on the wire.
  const serialized = JSON.stringify(wraps.pass);
  assert.ok(!serialized.includes('dev_001'), 'the deviceId must be inside the ciphertext');
});

test('tampering with the sealed roster fails the AEAD tag', async () => {
  const { wraps } = await fixture();

  // The server flips a byte of the ciphertext, hoping to perturb the roster. Poly1305 is a MAC
  // over the whole thing; there is no "just the roster part" to reach.
  const ct = Buffer.from(wraps.pass.ciphertext, 'base64');
  const at = ct.length - 20;
  assert.ok(at >= 0, 'the ciphertext must be long enough for this to be a real tamper');
  ct[at] = ct[at]! ^ 0x01;
  const tampered: WrappedKey = { ...wraps.pass, ciphertext: ct.toString('base64') };

  await assert.rejects(
    () => openIdentity(tampered, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' }),
    /cannot be decrypted/i,
  );
});

test('a wrap with no roster is REFUSED, not defaulted to empty or to wildcard', async () => {
  // The low-level primitive can still write a roster-less blob (it is a primitive, and
  // apps/server's tests use it for exactly that). What must never happen is a reader treating
  // the absence as permission.
  const id = await generateIdentity();
  const bare = await wrapUnderPassphrase(id.secretKey, PASSPHRASE);

  // The secret key still comes out — that path is unchanged and other packages rely on it.
  assert.deepEqual(await unwrapWithPassphrase(bare, PASSPHRASE), id.secretKey);

  // But the identity does not.
  await assert.rejects(
    () => openIdentity(bare, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' }),
    (e: Error) => {
      assert.ok(e instanceof RosterError);
      assert.match(e.message, /carries no device roster: refusing/);
      return true;
    },
  );
});

/* ------------------------------------------------------------------ *
 * Rollback
 * ------------------------------------------------------------------ */

test('ROLLBACK: a reader that remembers refuses an older roster', async () => {
  const { id, honest, recoveryKey } = await fixture();
  const stolen = await deviceKeypair();

  // v1: the stolen laptop is legitimately paired.
  const v1: SealedRoster = {
    version: 1,
    devices: [
      { deviceId: 'dev_001', publicKey: honest.publicKey },
      { deviceId: 'dev_002', publicKey: stolen.publicKey },
    ],
  };
  const wrapsV1 = await wrapIdentity(id.secretKey, v1, { passphrase: PASSPHRASE, recoveryKey });

  // v2: the owner revokes it.
  const v2: SealedRoster = { version: 2, devices: [{ deviceId: 'dev_001', publicKey: honest.publicKey }] };
  const wrapsV2 = await wrapIdentity(id.secretKey, v2, { passphrase: PASSPHRASE, recoveryKey });

  // The reader opens v2 and remembers it.
  const seenV2 = await openIdentity(
    wrapsV2.pass,
    { kind: 'pass', passphrase: PASSPHRASE },
    { kind: 'first-use' },
  );
  assert.equal(seenV2.highestVersionSeen, 2);

  // The server now serves the OLD blob, which is perfectly authentic — it is one we wrote.
  // Without the high-water mark this unwraps happily and re-admits the stolen laptop.
  await assert.rejects(
    () =>
      openIdentity(
        wrapsV1.pass,
        { kind: 'pass', passphrase: PASSPHRASE },
        { kind: 'seen', highestVersionSeen: seenV2.highestVersionSeen },
      ),
    (e: Error) => {
      assert.ok(e instanceof RosterError);
      assert.match(e.message, /roster rolled back: this bundle carries version 1/);
      return true;
    },
  );
});

test('THE RESIDUAL, STATED HONESTLY: a fresh reader accepts the rollback', async () => {
  // This test documents a hole rather than a defence, and it must keep passing. If someone
  // "fixes" it, they have either found a way to give a memoryless reader freshness — which is
  // impossible from inside a blob the server chooses — or they have broken first unlock.
  const { id, honest, recoveryKey } = await fixture();
  const stolen = await deviceKeypair();

  const v1: SealedRoster = {
    version: 1,
    devices: [
      { deviceId: 'dev_001', publicKey: honest.publicKey },
      { deviceId: 'dev_002', publicKey: stolen.publicKey },
    ],
  };
  const wrapsV1 = await wrapIdentity(id.secretKey, v1, { passphrase: PASSPHRASE, recoveryKey });

  // A brand new phone. It has never seen v2 and nothing in the bytes says v2 exists.
  const opened = await openIdentity(
    wrapsV1.pass,
    { kind: 'pass', passphrase: PASSPHRASE },
    { kind: 'first-use' },
  );
  assert.equal(opened.rosterVersion, 1);
  assert.equal(opened.roster.length, 2, 'the revoked device IS trusted on a fresh reader');

  // The mitigation is human, and it needs the roster to be showable. Prove it is.
  const fingerprints = await Promise.all(opened.roster.map((d) => deviceFingerprint(d.publicKey)));
  assert.equal(fingerprints.length, 2);
  assert.match(fingerprints[0]!, /^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
});

test('a rolled-back roster is refused even one version back, and forward is fine', async () => {
  assert.equal(acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 5), 5, 'same is fine');
  assert.equal(acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 6), 6, 'newer advances');
  assert.throws(
    () => acceptRosterVersion({ kind: 'seen', highestVersionSeen: 5 }, 4),
    /rolled back/,
  );
});

test('NaN cannot slip through the rollback check', async () => {
  // Every comparison with NaN is false, so a `version < seen` check reached before validation
  // waves NaN straight through — and then poisons the high-water mark with it forever. This
  // repo has found that bug three times.
  for (const bad of [NaN, Infinity, -Infinity, 1.5, -1, 0, '3' as unknown as number]) {
    assert.throws(
      () => acceptRosterVersion({ kind: 'seen', highestVersionSeen: 2 }, bad),
      /roster version must be an integer/,
      `version ${String(bad)} must be refused`,
    );
    assert.throws(
      () => acceptRosterVersion({ kind: 'first-use' }, bad),
      /roster version must be an integer/,
      `version ${String(bad)} must be refused even on first use`,
    );
  }

  // And a corrupt memory must not read as "no memory, accept anything".
  assert.throws(
    () => acceptRosterVersion({ kind: 'seen', highestVersionSeen: NaN }, 3),
    /refusing to treat unreadable memory as no memory/,
  );
});

test('a NaN version sealed inside a bundle is caught at decode, before any comparison', async () => {
  const doc = { v: 1, version: NaN, devices: [{ deviceId: 'd', publicKey: 'A'.repeat(43) + '=' }] };
  assert.throws(() => decodeRoster(doc), /roster version must be an integer/);
});

/* ------------------------------------------------------------------ *
 * All three wraps, and disagreement
 * ------------------------------------------------------------------ */

test('all three wrap kinds round-trip the same roster', async () => {
  const id = await generateIdentity();
  const a = await deviceKeypair();
  const b = await deviceKeypair();
  const roster: SealedRoster = {
    version: 7,
    devices: [
      { deviceId: 'dev_001', publicKey: a.publicKey },
      { deviceId: 'dev_002', publicKey: b.publicKey },
    ],
  };
  const recoveryKey = await generateRecoveryKey();
  const deviceKey = crypto.getRandomValues(new Uint8Array(32));

  const wraps = await wrapIdentity(id.secretKey, roster, { passphrase: PASSPHRASE, recoveryKey, deviceKey });
  assert.ok(wraps.device, 'a device key was supplied, so a device wrap must exist');

  const viaPass = await openIdentity(wraps.pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });
  const viaRecovery = await openIdentity(wraps.recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });
  const viaDevice = await openIdentity(wraps.device!, { kind: 'device', deviceKey }, { kind: 'first-use' });

  for (const [name, opened] of [['pass', viaPass], ['recovery', viaRecovery], ['device', viaDevice]] as const) {
    assert.deepEqual(opened.identitySecretKey, id.secretKey, `${name}: identity key`);
    assert.equal(opened.rosterVersion, 7, `${name}: version`);
    assert.deepEqual(opened.roster, roster.devices, `${name}: roster`);
  }
});

test('a set of wraps is emitted whole, or not at all', async () => {
  // NOTE WHAT THIS DOES AND DOES NOT PROVE, because the honest scope is smaller than the
  // tempting name. The rule "the three wraps cannot disagree" is enforced by CONSTRUCTION —
  // `wrapIdentity` encodes the roster once and seals those same bytes three times — and the
  // test that actually demonstrates the outcome is 'all three wrap kinds round-trip the same
  // roster' above.
  //
  // The re-open self-check inside `wrapIdentity` is a net for a future refactor that
  // reintroduces per-wrap rosters. It cannot be driven from here — there is no seam to inject a
  // disagreement through without exporting internals purely to weaken them — so it was verified
  // by MUTATION: sabotaging `wrapIdentity` to seal a different roster into the recovery wrap
  // makes it throw, and every test here that builds an identity fails. Re-run that mutation if
  // you refactor it; this test does not cover it and does not claim to.
  //
  // What IS proven here: a roster that cannot be encoded stops the write BEFORE anything is
  // sealed, so a half-written set never reaches the server.
  const id = await generateIdentity();
  const a = await deviceKeypair();
  const roster: SealedRoster = { version: 1, devices: [{ deviceId: 'dev_001', publicKey: a.publicKey }] };
  const recoveryKey = await generateRecoveryKey();

  // Sanity: the honest path emits three agreeing wraps and its self-check passes.
  const ok = await wrapIdentity(id.secretKey, roster, { passphrase: PASSPHRASE, recoveryKey });
  assert.equal(ok.pass.kind, 'pass');
  assert.equal(ok.recovery.kind, 'recovery');

  // A roster that cannot be encoded is caught before anything is sealed, so no half-written set
  // ever reaches the server.
  await assert.rejects(
    () => wrapIdentity(id.secretKey, { version: 1, devices: [] }, { passphrase: PASSPHRASE, recoveryKey }),
    /refusing to seal an empty roster/,
  );
  await assert.rejects(
    () =>
      wrapIdentity(
        id.secretKey,
        { version: 0, devices: roster.devices },
        { passphrase: PASSPHRASE, recoveryKey },
      ),
    /roster version must be an integer >= 1/,
  );
});

test('wrapIdentity will not write a passphrase wrap without also writing the recovery wrap', async () => {
  // A recovery wrap left un-rewritten IS the disagreement: "recover with the sheet" becomes a
  // supported way to downgrade onto a stale roster, no database access required.
  const id = await generateIdentity();
  const a = await deviceKeypair();
  const roster: SealedRoster = { version: 1, devices: [{ deviceId: 'dev_001', publicKey: a.publicKey }] };

  await assert.rejects(
    () =>
      wrapIdentity(id.secretKey, roster, {
        passphrase: PASSPHRASE,
        recoveryKey: undefined as unknown as Uint8Array,
      }),
    /a 32-byte recovery key is required/,
  );
});

test('a wrap cannot be opened with the wrong kind of key', async () => {
  const { wraps, recoveryKey } = await fixture();
  await assert.rejects(
    () => openIdentity(wraps.pass, { kind: 'recovery', recoveryKey }, { kind: 'first-use' }),
    /cannot open a pass-wrapped blob/,
  );
});

/* ------------------------------------------------------------------ *
 * Roster decoding: fail closed on our own bugs
 * ------------------------------------------------------------------ */

test('an empty roster never means "verify nothing"', async () => {
  assert.throws(() => decodeRoster({ v: 1, version: 1, devices: [] }), /roster is empty: refusing/);
  assert.throws(
    () => encodeRoster({ version: 1, devices: [] }),
    /refusing to seal an empty roster/,
  );
});

test('decodeRoster rejects malformed keys rather than manufacturing 32 bytes', async () => {
  const a = await deviceKeypair();
  const good = Buffer.from(a.publicKey).toString('base64');

  const cases: Array<[string, unknown, RegExp]> = [
    ['not an object', 'nope', /roster is not an object/],
    ['null', null, /roster is not an object/],
    ['array', [], /roster is not an object/],
    ['bad version tag', { v: 2, version: 1, devices: [] }, /unsupported roster version/],
    ['no devices', { v: 1, version: 1 }, /no devices array/],
    ['device not object', { v: 1, version: 1, devices: ['x'] }, /is not an object/],
    ['no deviceId', { v: 1, version: 1, devices: [{ publicKey: good }] }, /has no deviceId/],
    ['empty deviceId', { v: 1, version: 1, devices: [{ deviceId: '', publicKey: good }] }, /has no deviceId/],
    // A WiFi QR decodes to a well-formed 32 bytes under Buffer.from(x,'base64'). It must not here.
    [
      'wifi qr as a key',
      { v: 1, version: 1, devices: [{ deviceId: 'd', publicKey: 'WIFI:T:WPA;S:OfficeNetwork;P:hunter2;;' }] },
      /32-byte base64 Ed25519 public key/,
    ],
    ['short key', { v: 1, version: 1, devices: [{ deviceId: 'd', publicKey: 'AAAA' }] }, /32-byte base64/],
    ['key not a string', { v: 1, version: 1, devices: [{ deviceId: 'd', publicKey: 42 }] }, /32-byte base64/],
    [
      'duplicate entry',
      { v: 1, version: 1, devices: [{ deviceId: 'd', publicKey: good }, { deviceId: 'd', publicKey: good }] },
      /the same key twice/,
    ],
  ];

  for (const [name, doc, re] of cases) {
    assert.throws(() => decodeRoster(doc), re, `must reject: ${name}`);
  }

  // ...and the honest one decodes.
  const ok = decodeRoster({ v: 1, version: 3, devices: [{ deviceId: 'd', publicKey: good }] } satisfies RosterDoc);
  assert.equal(ok.version, 3);
  assert.deepEqual(ok.devices[0]!.publicKey, a.publicKey);
});

test('encodeRoster refuses a key that is not 32 bytes, at build time', async () => {
  assert.throws(
    () => encodeRoster({ version: 1, devices: [{ deviceId: 'd', publicKey: new Uint8Array(16) }] }),
    /must carry a 32-byte Ed25519 public key, got 16 bytes/,
  );
});

test('encode/decode round-trips', async () => {
  const a = await deviceKeypair();
  const b = await deviceKeypair();
  const roster: SealedRoster = {
    version: ROSTER_FIRST_VERSION,
    // Two entries for one deviceId: key rotation, which is legitimate and must survive.
    devices: [
      { deviceId: 'dev_001', publicKey: a.publicKey },
      { deviceId: 'dev_001', publicKey: b.publicKey },
    ],
  };
  assert.deepEqual(decodeRoster(encodeRoster(roster)), roster);
});

/* ------------------------------------------------------------------ *
 * The core property must survive all of this
 * ------------------------------------------------------------------ */

test('THE CORE PROPERTY: sealing still needs no key that can read', async () => {
  // Adding a roster must not have handed the Bridge a decryption key. The Bridge holds the
  // identity PUBLIC key and its own Ed25519 SIGNING key; neither opens a sealed box.
  const { id, honest, wraps } = await fixture();

  const env = await sealSection(
    { rows: [{ party: 'A & B Traders', amount: '125000.00' }] },
    makeAad({
      tenantId: 't',
      deviceId: 'dev_001',
      companyGuid: 'g',
      section: 'ageing_receivable',
      asOf: '2026-07-16',
      snapshotTs: 1,
      seq: 1,
    }),
    id.publicKey,
    honest.privateKey,
  );

  // Everything the Bridge has, offered as an identity secret key. All 32 bytes, all wrong.
  const expect = {
    tenantId: 't',
    companyGuid: 'g',
    section: 'ageing_receivable' as const,
    asOf: '2026-07-16',
  };
  const opened = await openIdentity(wraps.pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });

  for (const [name, key] of [
    ['the identity public key', id.publicKey],
    ['its own device public key', honest.publicKey],
    ['the first 32 bytes of its device secret key', honest.privateKey.subarray(0, 32)],
  ] as const) {
    await assert.rejects(
      () =>
        openSection(env, {
          identityPublicKey: id.publicKey,
          identitySecretKey: key,
          expect,
          trustedDevices: opened.roster,
        }),
      `${name} must not open the envelope`,
    );
  }

  // Only the unwrapped identity secret does.
  const plaintext = await openSection(env, {
    identityPublicKey: id.publicKey,
    identitySecretKey: opened.identitySecretKey,
    expect,
    trustedDevices: opened.roster,
  });
  assert.deepEqual(plaintext, { rows: [{ party: 'A & B Traders', amount: '125000.00' }] });
});

test('END TO END: onboard, seal, unlock, verify — with the roster from the bundle alone', async () => {
  const { id, honest, wraps, recoveryKey } = await fixture();

  const env = await sealSection(
    { rows: [{ party: 'A & B Traders', amount: '125000.00' }] },
    makeAad({
      tenantId: 't',
      deviceId: 'dev_001',
      companyGuid: 'g',
      section: 'ageing_receivable',
      asOf: '2026-07-16',
      snapshotTs: 1,
      seq: 1,
    }),
    id.publicKey,
    honest.privateKey,
  );

  const expect = { tenantId: 't', companyGuid: 'g', section: 'ageing_receivable' as const, asOf: '2026-07-16' };

  // Passphrase path.
  const viaPass = await openIdentity(wraps.pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });
  const a = await openSection(env, {
    identityPublicKey: id.publicKey,
    identitySecretKey: viaPass.identitySecretKey,
    expect,
    trustedDevices: viaPass.roster,
  });

  // Recovery path — same roster, so recovery yields an identity that can verify, not just decrypt.
  const viaRecovery = await openIdentity(wraps.recovery, { kind: 'recovery', recoveryKey }, { kind: 'first-use' });
  const b = await openSection(env, {
    identityPublicKey: id.publicKey,
    identitySecretKey: viaRecovery.identitySecretKey,
    expect,
    trustedDevices: viaRecovery.roster,
  });

  assert.deepEqual(a, b);
  assert.deepEqual(a, { rows: [{ party: 'A & B Traders', amount: '125000.00' }] });
});
