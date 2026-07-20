import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deviceFingerprint,
  generateIdentity,
  generateRecoveryKey,
  openIdentity,
  sodiumReady,
  wrapIdentity,
  type SealedRoster,
} from '@tally-bridge/crypto';
import { makeAad, openSection, sealSection } from '@tally-bridge/crypto';
import {
  PairingService,
  admitPairedDevice,
  describeAdmission,
  initialRoster,
  revokeDevice,
  type CandidateDevice,
} from '../src/onboarding/pairing.ts';

/**
 * ADMISSION — how a key gets INTO the roster.
 *
 * The sealed-roster mechanism (packages/crypto) answers "how does the roster reach the reader
 * without the server rewriting it". It says nothing about how the right key got into the roster
 * in the first place, and for every device after the first, the only available source of that
 * key is the server — because device 2 registers its public key there so its uploads can be
 * verified.
 *
 * So this is the soft spot, and these tests attack it: a malicious server offering its own key
 * as "device 2's key", hoping the owner's passphrase seals it into the bundle. If it succeeds,
 * everything downstream works perfectly and authenticates the attacker.
 */

const PASSPHRASE = 'Ramesh@1985';

async function deviceKeypair() {
  const sodium = await sodiumReady();
  return sodium.crypto_sign_keypair();
}

/** A live, redeemed pairing code — everything admission needs except the key question. */
async function redeemedClaim(label: string) {
  const svc = new PairingService({ now: () => 1_700_000_000_000, generateCode: async () => '424242' });
  await svc.issue(label);
  const claim = await svc.claim('424242');
  assert.ok(claim.ok);
  return claim;
}

test('the honest ceremony admits the device and bumps the version', async () => {
  const dev1 = await deviceKeypair();
  const dev2 = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  assert.equal(current.version, 1);

  const candidate: CandidateDevice = {
    deviceId: 'dev_002',
    label: "Anil's PC",
    publicKey: dev2.publicKey,
  };
  const claim = await redeemedClaim("Anil's PC");

  // The owner reads the fingerprint off device 2's OWN SCREEN. That is what this value stands
  // for here — not something an API returned.
  const readOutLoud = await deviceFingerprint(dev2.publicKey);

  const out = await admitPairedDevice({ claim, candidate, confirmedFingerprint: readOutLoud, current });
  assert.ok(out.ok);
  assert.equal(out.roster.version, 2, 'every roster change bumps the version');
  assert.deepEqual(
    out.roster.devices.map((d) => d.deviceId),
    ['dev_001', 'dev_002'],
  );
});

test('THE ATTACK: a server-substituted key is refused by the fingerprint check', async () => {
  const dev1 = await deviceKeypair();
  const dev2 = await deviceKeypair(); // the real accountant's PC
  const evil = await deviceKeypair(); // what a malicious server offers instead
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim("Anil's PC");

  // The server answers "device 2's public key is..." with a key it generated and holds the
  // secret for. Everything else about this pairing is genuine: the code was really issued by
  // the owner and really redeemed.
  const candidate: CandidateDevice = {
    deviceId: 'dev_002',
    label: "Anil's PC",
    publicKey: evil.publicKey,
  };

  // The owner reads out what is on the ACCOUNTANT'S SCREEN, which is device 2's real key.
  const readOutLoud = await deviceFingerprint(dev2.publicKey);

  const out = await admitPairedDevice({ claim, candidate, confirmedFingerprint: readOutLoud, current });
  assert.equal(out.ok, false);
  assert.ok(!out.ok);
  assert.equal(out.reason, 'fingerprint_mismatch');
  assert.match(out.message, /do not continue/i);
});

test('the fingerprint the owner types is compared against the key ACTUALLY being sealed', async () => {
  // The failure this guards: comparing the server's claimed fingerprint against the server's
  // claimed key. Both sides come from the attacker, both match, nothing is verified. So the
  // expected side must be DERIVED from `candidate.publicKey` — the bytes that go into the
  // roster — and this test proves it is, by confirming a fingerprint of the honest key does not
  // admit the evil key even when the evil key is self-consistent.
  const dev1 = await deviceKeypair();
  const evil = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim('PC');

  const described = await describeAdmission({ deviceId: 'dev_002', label: 'PC', publicKey: evil.publicKey });
  // The attacker's own fingerprint IS self-consistent — that is the point. It matches the key
  // it describes. It does not match the machine the owner is looking at.
  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: 'PC', publicKey: evil.publicKey },
    confirmedFingerprint: described.fingerprint,
    current,
  });
  assert.ok(out.ok, 'self-consistency is all this function can check; the HUMAN supplies the rest');

  // Which is exactly why the prompt must tell the owner not to read it off this screen.
  assert.match(described.prompt, /do not copy them from this screen/i);
});

test('a malformed or empty fingerprint never matches', async () => {
  const dev1 = await deviceKeypair();
  const dev2 = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim('PC');
  const candidate: CandidateDevice = { deviceId: 'dev_002', label: 'PC', publicKey: dev2.publicKey };

  // '' is the one that matters: `undefined === undefined` opening an unskippable gate is a bug
  // this codebase has already shipped once, in makeVerificationChallenge.
  for (const bad of ['', '   ', 'yes', 'ABCD', 'ZZZZ ZZZZ ZZZZ ZZZZ', '1234567890abcdef00']) {
    const out = await admitPairedDevice({ claim, candidate, confirmedFingerprint: bad, current });
    assert.equal(out.ok, false, `must refuse ${JSON.stringify(bad)}`);
  }

  // Formatting and case are noise, not signal: an owner typing it without spaces is right.
  const fp = await deviceFingerprint(dev2.publicKey);
  for (const ok of [fp, fp.toLowerCase(), fp.replace(/ /g, ''), `  ${fp}  `]) {
    const out = await admitPairedDevice({ claim, candidate, confirmedFingerprint: ok, current });
    assert.ok(out.ok, `must accept ${JSON.stringify(ok)}`);
  }
});

test('a key that is not 32 bytes is refused with a sentence, not a stack trace', async () => {
  const dev1 = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim('PC');

  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: 'PC', publicKey: new Uint8Array(16) },
    confirmedFingerprint: '0000 0000 0000 0000',
    current,
  });
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.reason === 'bad_key');
  assert.doesNotMatch(out.message, /Error|byte|Uint8/i);
});

test('a candidate that is not the device the owner started pairing is refused', async () => {
  const dev1 = await deviceKeypair();
  const dev2 = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim("Anil's PC");

  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: 'Someone Else PC', publicKey: dev2.publicKey },
    confirmedFingerprint: await deviceFingerprint(dev2.publicKey),
    current,
  });
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.reason === 'stale_claim');
});

test('re-admitting the same key does not bump the version', async () => {
  // A version bump with no change pushes every reader's high-water mark forward for nothing,
  // and the high-water mark is the entire rollback defence.
  const dev1 = await deviceKeypair();
  const current = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const claim = await redeemedClaim('PC');

  const out = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_001', label: 'PC', publicKey: dev1.publicKey },
    confirmedFingerprint: await deviceFingerprint(dev1.publicKey),
    current,
  });
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.reason === 'already_present');
});

test('revocation removes every key for a device, and bumps the version', async () => {
  const dev1 = await deviceKeypair();
  const dev2a = await deviceKeypair();
  const dev2b = await deviceKeypair();
  // dev_002 mid key-rotation: two entries, both pinned. Revoking the first and leaving the
  // second has revoked nothing.
  const current: SealedRoster = {
    version: 3,
    devices: [
      { deviceId: 'dev_001', publicKey: dev1.publicKey },
      { deviceId: 'dev_002', publicKey: dev2a.publicKey },
      { deviceId: 'dev_002', publicKey: dev2b.publicKey },
    ],
  };

  const next = revokeDevice(current, 'dev_002');
  assert.equal(next.version, 4);
  assert.deepEqual(next.devices.map((d) => d.deviceId), ['dev_001']);

  assert.throws(() => revokeDevice(next, 'dev_002'), /not in the roster/);
  assert.throws(() => revokeDevice(next, 'dev_001'), /it is the only device left/);
});

test('the first device needs no ceremony, and needs a real key', async () => {
  const dev1 = await deviceKeypair();
  const r = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  assert.equal(r.version, 1);
  assert.equal(r.devices.length, 1);

  assert.throws(() => initialRoster({ deviceId: 'dev_001', publicKey: new Uint8Array(31) }), /32-byte/);
  assert.throws(() => initialRoster({ deviceId: '', publicKey: dev1.publicKey }), /deviceId/);
});

/* ------------------------------------------------------------------ *
 * The whole flow, end to end
 * ------------------------------------------------------------------ */

test('END TO END: pair device 2, re-wrap, and the reader accepts BOTH devices', async () => {
  const id = await generateIdentity();
  const recoveryKey = await generateRecoveryKey();
  const dev1 = await deviceKeypair();
  const dev2 = await deviceKeypair();

  // --- Onboarding: device 1 only.
  const v1 = initialRoster({ deviceId: 'dev_001', publicKey: dev1.publicKey });
  const wrapsV1 = await wrapIdentity(id.secretKey, v1, { passphrase: PASSPHRASE, recoveryKey });

  // --- Device 2 uploads. A reader on the OLD bundle must refuse it: fail-closed, not a silent
  //     wrong number.
  const env2 = await sealSection(
    { rows: [{ party: 'Real Traders', amount: '4200.00' }] },
    makeAad({
      tenantId: 't',
      deviceId: 'dev_002',
      companyGuid: 'g',
      section: 'cash_bank',
      asOf: '2026-07-16',
      snapshotTs: 5,
      seq: 5,
    }),
    id.publicKey,
    dev2.privateKey,
  );
  const expect = { tenantId: 't', companyGuid: 'g', section: 'cash_bank' as const, asOf: '2026-07-16' };

  const oldReader = await openIdentity(
    wrapsV1.pass,
    { kind: 'pass', passphrase: PASSPHRASE },
    { kind: 'first-use' },
  );
  await assert.rejects(
    () =>
      openSection(env2, {
        identityPublicKey: id.publicKey,
        identitySecretKey: oldReader.identitySecretKey,
        expect,
        trustedDevices: oldReader.roster,
      }),
    /untrusted device dev_002/,
    'a reader holding a pre-pairing bundle refuses device 2 rather than trusting it',
  );

  // --- Pairing: the owner runs the ceremony on device 1.
  const claim = await redeemedClaim("Anil's PC");
  const admitted = await admitPairedDevice({
    claim,
    candidate: { deviceId: 'dev_002', label: "Anil's PC", publicKey: dev2.publicKey },
    confirmedFingerprint: await deviceFingerprint(dev2.publicKey), // read off device 2's screen
    current: oldReader.roster.length
      ? { version: oldReader.rosterVersion, devices: oldReader.roster }
      : v1,
  });
  assert.ok(admitted.ok);

  // --- Re-wrap. This NEEDS the passphrase: writing a new pass wrap means deriving the KEK, and
  //     nobody holds the KEK afterwards. It is arithmetic, not policy.
  const wrapsV2 = await wrapIdentity(oldReader.identitySecretKey, admitted.roster, {
    passphrase: PASSPHRASE,
    recoveryKey,
  });

  // --- The reader unlocks against the new bundle and now accepts device 2.
  const newReader = await openIdentity(
    wrapsV2.pass,
    { kind: 'pass', passphrase: PASSPHRASE },
    { kind: 'seen', highestVersionSeen: oldReader.highestVersionSeen },
  );
  assert.equal(newReader.rosterVersion, 2);

  const plaintext = await openSection(env2, {
    identityPublicKey: id.publicKey,
    identitySecretKey: newReader.identitySecretKey,
    expect,
    trustedDevices: newReader.roster,
  });
  assert.deepEqual(plaintext, { rows: [{ party: 'Real Traders', amount: '4200.00' }] });

  // --- And the recovery sheet agrees, so recovery does not downgrade the roster.
  const viaRecovery = await openIdentity(
    wrapsV2.recovery,
    { kind: 'recovery', recoveryKey },
    { kind: 'seen', highestVersionSeen: newReader.highestVersionSeen },
  );
  assert.deepEqual(viaRecovery.roster, newReader.roster);
});
