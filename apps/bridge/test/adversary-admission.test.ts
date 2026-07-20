import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deviceFingerprint,
  sodiumReady,
  type SealedRoster,
} from '@tally-bridge/crypto';
import {
  PairingService,
  admitPairedDevice,
  initialRoster,
  revokeDevice,
  type CandidateDevice,
} from '../src/onboarding/pairing.ts';

async function deviceKeypair() {
  const sodium = await sodiumReady();
  return sodium.crypto_sign_keypair();
}

async function redeemedClaim(label: string) {
  const svc = new PairingService({ now: () => 1_700_000_000_000, generateCode: async () => '424242' });
  await svc.issue(label);
  const claim = await svc.claim('424242');
  assert.ok(claim.ok);
  return claim;
}

async function roster1() {
  const d1 = await deviceKeypair();
  return { d1, roster: initialRoster({ deviceId: 'dev_001', publicKey: d1.publicKey }) };
}

/* ================================================================== *
 * Can the fingerprint gate be bypassed?
 * ================================================================== */

test('ADV: no falsy/degenerate fingerprint opens the gate', async () => {
  const { roster } = await roster1();
  const d2 = await deviceKeypair();
  const claim = await redeemedClaim("Anil's PC");
  const candidate: CandidateDevice = { deviceId: 'dev_002', label: "Anil's PC", publicKey: d2.publicKey };

  // Every shape that has, historically, made an `x === y` gate pass by accident.
  const attempts: unknown[] = [
    '',
    '   ',
    undefined,
    null,
    0,
    NaN,
    [],
    {},
    { toString: () => '' },
    'undefined',
    '0000000000000000',
    'ffffffffffffffff',
    '................',
    'GGGG GGGG GGGG GGGG', // hex-shaped but not hex
    '0x' + '0'.repeat(14),
  ];
  for (const confirmedFingerprint of attempts) {
    const out = await admitPairedDevice({
      claim,
      candidate,
      confirmedFingerprint: confirmedFingerprint as string,
      current: roster,
    });
    assert.equal(out.ok, false, `fingerprint ${JSON.stringify(confirmedFingerprint)} must not admit`);
  }

  // And the honest one DOES admit, so the above is not vacuous.
  const good = await admitPairedDevice({
    claim,
    candidate,
    confirmedFingerprint: await deviceFingerprint(d2.publicKey),
    current: roster,
  });
  assert.equal(good.ok, true);
});

test('ADV: a fingerprint for a DIFFERENT key never admits, even one bit off', async () => {
  const { roster } = await roster1();
  const d2 = await deviceKeypair();
  const claim = await redeemedClaim("Anil's PC");

  // The server substitutes its own key but the owner reads the REAL fingerprint off device 2.
  const evil = await deviceKeypair();
  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: "Anil's PC", publicKey: evil.publicKey },
    confirmedFingerprint: await deviceFingerprint(d2.publicKey),
    current: roster,
  });
  assert.equal(out.ok, false);
  assert.equal((out as { reason: string }).reason, 'fingerprint_mismatch');

  // A single flipped hex character in the typed fingerprint is also refused.
  const fp = await deviceFingerprint(d2.publicKey);
  const flipped = (fp[0] === '0' ? '1' : '0') + fp.slice(1);
  const out2 = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: "Anil's PC", publicKey: d2.publicKey },
    confirmedFingerprint: flipped,
    current: roster,
  });
  assert.equal(out2.ok, false);
});

test('ADV: admission never silently drops or replaces an existing device', async () => {
  const { d1, roster } = await roster1();
  const d2 = await deviceKeypair();
  const claim = await redeemedClaim("Anil's PC");
  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: "Anil's PC", publicKey: d2.publicKey },
    confirmedFingerprint: await deviceFingerprint(d2.publicKey),
    current: roster,
  });
  assert.ok(out.ok);
  assert.equal(out.roster.devices.length, 2);
  assert.deepEqual(out.roster.devices[0]!.publicKey, d1.publicKey, 'device 1 must survive');
  assert.equal(out.roster.version, 2, 'the version must bump');

  // A candidate claiming dev_001's id with a NEW key is a key-rotation entry, not a takeover:
  // it is ADDED, and dev_001's original key remains pinned. Nothing is silently replaced.
  const rot = await deviceKeypair();
  const claim2 = await redeemedClaim('Rotate');
  const out2 = await admitPairedDevice({
    claim: claim2,
    candidate: { deviceId: 'dev_001', label: 'Rotate', publicKey: rot.publicKey },
    confirmedFingerprint: await deviceFingerprint(rot.publicKey),
    current: out.roster,
  });
  assert.ok(out2.ok);
  assert.equal(out2.roster.devices.filter((d) => d.deviceId === 'dev_001').length, 2);
  assert.deepEqual(out2.roster.devices[0]!.publicKey, d1.publicKey);
});

/* ================================================================== *
 * The `claim` is NOT what the type name implies.
 * ================================================================== */

test('ADV: admitPairedDevice checks the claim LABEL only — not that it is live or this service’s', async () => {
  const { roster } = await roster1();
  const d2 = await deviceKeypair();

  // A wholly FABRICATED claim — never issued, never redeemed, no PairingService involved.
  const fabricated = { ok: true as const, pairingId: 'pair_never_existed', label: "Anil's PC" };
  const out = await admitPairedDevice({
    claim: fabricated,
    candidate: { deviceId: 'dev_002', label: "Anil's PC", publicKey: d2.publicKey },
    confirmedFingerprint: await deviceFingerprint(d2.publicKey),
    current: roster,
  });
  // ADMITTED. The pairing code contributes NOTHING to roster safety — only the fingerprint
  // ceremony does. This is not a server-exploitable hole (the server cannot call this function,
  // and cannot produce a matching fingerprint), but the `claim` parameter's docstring — "Proof
  // the code was actually redeemed. An admission with no live claim behind it is not one." —
  // overstates what is enforced: nothing here binds the claim to an issued pairing.
  assert.equal(out.ok, true, 'documents that the claim is not verified against a live pairing');
});

/* ================================================================== *
 * Revocation.
 * ================================================================== */

test('ADV: revocation cannot empty the roster, and cannot be a no-op version bump', async () => {
  const { roster } = await roster1();
  assert.throws(() => revokeDevice(roster, 'dev_001'), /only device left/);
  assert.throws(() => revokeDevice(roster, 'dev_999'), /not in the roster/);

  const d2 = await deviceKeypair();
  const two: SealedRoster = {
    version: 2,
    devices: [...roster.devices, { deviceId: 'dev_002', publicKey: d2.publicKey }],
  };
  const after = revokeDevice(two, 'dev_002');
  assert.equal(after.version, 3);
  assert.equal(after.devices.length, 1);
});

test('ADV: initialRoster refuses anything but a real 32-byte key', () => {
  for (const publicKey of [new Uint8Array(31), new Uint8Array(33), undefined, null, 'AAAA', [1, 2]]) {
    assert.throws(
      () => initialRoster({ deviceId: 'dev_001', publicKey: publicKey as Uint8Array }),
      /32-byte Ed25519 public key/,
    );
  }
  for (const deviceId of ['', undefined, null, 42]) {
    assert.throws(
      () => initialRoster({ deviceId: deviceId as string, publicKey: new Uint8Array(32) }),
      /deviceId/,
    );
  }
});
