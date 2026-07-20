import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { EnvelopeAad } from '@tally-bridge/core';
import { canonicalAmount } from '@tally-bridge/core';
import { sodiumReady } from '../src/sodium.ts';
import { generateIdentity, type Identity } from '../src/identity.ts';
import type { TrustedDevice } from '../src/trust.ts';
import {
  ENVELOPE_SIG_VERSION,
  contentHashOf,
  envelopeSigningBytes,
  makeAad,
  openSection,
  sealSection,
  type AadExpectation,
  type EnvelopeSigParts,
  type MaybeSignedEnvelope,
  type OpenSectionOptions,
} from '../src/envelope.ts';
import { compress, decompress } from '../src/compress.ts';
import { pad, padmeLength, unpad } from '../src/padme.ts';

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

/**
 * The Bridge's Ed25519 device keypair.
 *
 * Generated here with libsodium directly rather than imported from @tally-bridge/protocol —
 * protocol depends on this package, so importing it back would be a cycle. It is the identical
 * key: `generateDeviceKeypair` is `crypto_sign_keypair` with a deviceId attached.
 */
async function makeDevice(deviceId = 'dev_001'): Promise<TrustedDevice & { secretKey: Uint8Array }> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_sign_keypair();
  return { deviceId, publicKey: kp.publicKey, secretKey: kp.privateKey };
}

/** A reader that pins the right key and asks for the slot the envelope actually holds. */
const opening = (
  id: Identity,
  dev: TrustedDevice,
  over: Partial<AadExpectation> = {},
): OpenSectionOptions => ({
  identityPublicKey: id.publicKey,
  identitySecretKey: id.secretKey,
  expect: {
    tenantId: TENANT,
    companyGuid: COMPANY,
    section: 'ageing_receivable',
    asOf: AS_OF,
    ...over,
  },
  trustedDevices: [{ deviceId: dev.deviceId, publicKey: dev.publicKey }],
});

const payload = () => ({
  rows: [
    { party: 'A & B Traders <Mumbai>', bucket: '0_30', amount: canonicalAmount(125000) },
    { party: 'Zed Enterprises', bucket: '91_180', amount: canonicalAmount(-3421.5) },
  ],
});

test('round-trips a section', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const out = await openSection(env, opening(id, dev));
  assert.deepEqual(out, payload());
});

test('THE core property: sealing needs no key that can DECRYPT', async () => {
  // The Bridge runs unattended and holds the identity PUBLIC key plus its own SIGNING key.
  // Neither reads anything back. If `sealSection` ever grows a parameter that can DECRYPT, the
  // entire threat model collapses — but a signing key is not that parameter, and conflating
  // "secret" with "can read the data" is what this test exists to keep straight.
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  assert.ok(env.ciphertext.length > 0);

  // Prove the negative: with everything the Bridge has, the ciphertext cannot be opened.
  // Both params are Uint8Array, so the type system cannot catch this — which is exactly why it
  // needs a runtime test.
  await assert.rejects(
    () => openSection(env, { ...opening(id, dev), identitySecretKey: id.publicKey }),
    /incorrect key pair|invalid input|wrong secret key|cannot be decrypted/i,
  );
});

test('the device SIGNING key cannot be turned into a decryption key for the envelope', async () => {
  // The sharpest version of the question above. Ed25519 and X25519 secrets ARE convertible
  // (crypto_sign_ed25519_sk_to_curve25519 is a real function), so "it's a signing key, it can't
  // decrypt" deserves a demonstration rather than an assurance. The conversion works fine; it
  // just yields a keypair unrelated to the identity the CEK was sealed to.
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  const x25519sk = sodium.crypto_sign_ed25519_sk_to_curve25519(dev.secretKey);
  const x25519pk = sodium.crypto_sign_ed25519_pk_to_curve25519(dev.publicKey);
  await assert.rejects(
    () =>
      openSection(env, {
        ...opening(id, dev),
        identityPublicKey: x25519pk,
        identitySecretKey: x25519sk,
      }),
    /incorrect key pair|invalid input|cannot be decrypted/i,
    'converting the device signing key must not open the envelope',
  );
});

test('sealSection refuses the identity secret key in the signing-key slot', async () => {
  // The mistake that would silently end the product: both parameters are Uint8Array. An X25519
  // secret is 32 bytes and an Ed25519 secret is 64, so the length check catches it.
  const id = await generateIdentity();
  await assert.rejects(
    () => sealSection(payload(), aad(), id.publicKey, id.secretKey),
    /device signing secret key must be 64 bytes, got 32/,
  );
});

test('a different identity cannot open the envelope', async () => {
  const alice = await generateIdentity();
  const mallory = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), alice.publicKey, dev.secretKey);
  await assert.rejects(() => openSection(env, opening(mallory, dev)));
});

test('every AAD field is bound — tampering with any of them fails the open', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();

  // The replay this prevents: a malicious server re-presenting last quarter's still-authentic
  // ciphertext as this quarter's, rendering stale numbers under a green checkmark.
  //
  // The AAD is now covered TWICE — by the AEAD tag and by the device signature — so tampering
  // is caught at the signature, which is strictly earlier and strictly stronger. The expected
  // error moved accordingly; the property did not.
  const tampers: Array<[string, Partial<EnvelopeAad>]> = [
    ['section', { section: 'ageing_payable' }],
    ['companyGuid', { companyGuid: '00000000-0000-0000-0000-000000000000' }],
    ['asOf', { asOf: '2026-07-15' }],
    ['snapshotTs', { snapshotTs: 1 }],
    ['tenantId', { tenantId: 'tnt_evil' }],
    ['deviceId', { deviceId: 'dev_evil' }],
    ['seq', { seq: 43 }],
  ];

  for (const [field, over] of tampers) {
    const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
    const tampered = { ...env, aad: { ...env.aad, ...over } };
    await assert.rejects(
      () => openSection(tampered, opening(id, dev)),
      /bad envelope signature|untrusted device/i,
      `tampering with aad.${field} must be caught`,
    );
  }
});

test('the AEAD still binds the AAD independently of the signature', async () => {
  // Belt and braces, and worth proving separately: if the signature check were ever removed or
  // bypassed, the AEAD must still refuse a re-slotted ciphertext. Verified by re-signing the
  // tampered AAD with the genuine device key — i.e. modelling a COMPROMISED BRIDGE rather than
  // a malicious server, which is the only actor that can get past the signature.
  const sodium = await sodiumReady();
  const id = await generateIdentity();
  const dev = await makeDevice();
  const { canonicalStringify } = await import('@tally-bridge/core');

  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const evilAad = { ...env.aad, companyGuid: '00000000-0000-0000-0000-000000000000' };
  const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
  const un = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

  const resigned = {
    ...env,
    aad: evilAad,
    sig: {
      v: ENVELOPE_SIG_VERSION,
      alg: 'ed25519' as const,
      sig: b64(
        sodium.crypto_sign_detached(
          envelopeSigningBytes({
            sigVer: ENVELOPE_SIG_VERSION,
            alg: 'ed25519',
            aad: new TextEncoder().encode(canonicalStringify(evilAad as never)),
            nonce: un(env.nonce),
            sealedCek: un(env.sealedCek),
            ciphertext: un(env.ciphertext),
            contentHash: un(env.contentHash),
          }),
          dev.secretKey,
        ),
      ),
    },
  };

  await assert.rejects(
    () =>
      openSection(resigned, opening(id, dev, { companyGuid: '00000000-0000-0000-0000-000000000000' })),
    /cannot be decrypted/i,
    'the AEAD must refuse a re-slotted ciphertext even when the signature is genuine',
  );
});

test('tampering with the ciphertext fails', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const raw = Buffer.from(env.ciphertext, 'base64');
  raw[10] = (raw[10] ?? 0) ^ 0xff;
  await assert.rejects(
    () => openSection({ ...env, ciphertext: raw.toString('base64') }, opening(id, dev)),
    /bad envelope signature/i,
    'a flipped ciphertext bit must break the signature, not merely the AEAD',
  );
});

test('a fresh nonce and CEK are used per seal', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const a = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const b = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.sealedCek, b.sealedCek);
  // Identical plaintext, different ciphertext — no deterministic leak.
  assert.notEqual(a.ciphertext, b.ciphertext);
  // And therefore a different signature, over different bytes.
  assert.notEqual(a.sig.sig, b.sig.sig);
});

test('contentHash is over plaintext and is stable across seals', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const a = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const b = await sealSection(payload(), aad({ seq: 99 }), id.publicKey, dev.secretKey);
  // Same data -> same hash, even though ciphertext differs. This is what gates re-upload.
  assert.equal(a.contentHash, b.contentHash);
  assert.equal(a.contentHash, await contentHashOf(payload()));
});

test('contentHash changes when the data changes', async () => {
  const h1 = await contentHashOf(payload());
  const h2 = await contentHashOf({ rows: [] });
  assert.notEqual(h1, h2);
});

test('survives the messy-real-company canary in the payload', async () => {
  // The party name that breaks naive XML parsers, carried end to end.
  const id = await generateIdentity();
  const dev = await makeDevice();
  const nasty = {
    rows: [
      { party: 'A & B Traders <Mumbai>', amount: canonicalAmount(1) },
      { party: 'M/s "Quotes" & <Angle>', amount: canonicalAmount(2) },
      { party: 'देवनागरी व्यापारी', amount: canonicalAmount(3) },
      { party: "O'Brien & Sons — Ltd.", amount: canonicalAmount(4) },
    ],
  };
  const env = await sealSection(nasty, aad(), id.publicKey, dev.secretKey);
  assert.deepEqual(await openSection(env, opening(id, dev)), nasty);
});

test('gzip round-trips, including empty and large payloads', async () => {
  // Incompressible data, chunked: crypto.getRandomValues throws QuotaExceededError above
  // 65536 bytes per call.
  const random = new Uint8Array(100_000);
  for (let i = 0; i < random.length; i += 65536) {
    crypto.getRandomValues(random.subarray(i, Math.min(i + 65536, random.length)));
  }

  for (const input of [
    new Uint8Array(0),
    new TextEncoder().encode('x'),
    new TextEncoder().encode('a'.repeat(200_000)),
    random,
  ]) {
    assert.deepEqual(await decompress(await compress(input)), input);
  }
});

test('compression actually compresses repetitive financial data', async () => {
  const rows = Array.from({ length: 500 }, (_, i) => ({
    party: `Party ${i}`,
    bucket: '0_30',
    amount: canonicalAmount(1000 + i),
  }));
  const raw = new TextEncoder().encode(JSON.stringify({ rows }));
  const gz = await compress(raw);
  assert.ok(gz.length < raw.length / 3, `expected >3x, got ${raw.length}->${gz.length}`);
});

test('padme pads to the documented lengths', async () => {
  // Worked examples from the design: overhead stays small and bounded.
  assert.equal(padmeLength(100), 104);
  assert.equal(padmeLength(1000), 1024);
  assert.equal(padmeLength(10000), 10240);
  // Small values are returned unchanged rather than blowing up on log2(0).
  assert.equal(padmeLength(0), 0);
  assert.equal(padmeLength(1), 1);
});

test('padme overhead never exceeds ~12%', async () => {
  for (let n = 2; n < 1_000_000; n = Math.ceil(n * 1.07)) {
    const p = padmeLength(n);
    assert.ok(p >= n, `padme(${n}) = ${p} must not shrink`);
    assert.ok(
      p <= n * 1.12 + 1,
      `padme(${n}) = ${p} exceeds the 12% overhead bound (${(p / n - 1) * 100}%)`,
    );
  }
});

test('padme is exact at powers of two (no float log2 drift)', async () => {
  // Math.log2 can land just below an integer at powers of two, silently changing the
  // padding class. clz32 cannot.
  for (let e = 2; e < 20; e++) {
    const n = 2 ** e;
    assert.equal(padmeLength(n), n, `padme(2^${e}) must be identity`);
  }
});

test('pad/unpad round-trips and hides the true length', async () => {
  const data = new TextEncoder().encode('x'.repeat(1000));
  const padded = pad(data);
  assert.ok(padded.length > data.length);
  assert.equal(padded.length, padmeLength(data.length + 4));
  assert.deepEqual(unpad(padded), data);
});

test('unpad refuses a length prefix that over-reads', async () => {
  const padded = pad(new TextEncoder().encode('short'));
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  view.setUint32(0, 999_999, false);
  // Unreachable for an authentic payload (the AEAD covers the prefix), so this is a
  // defence against our own bugs and against forced over-reads — refuse, never clamp.
  assert.throws(() => unpad(padded), /exceeds padded payload/);
});

test('payloads of different sizes collapse to the same padded length', async () => {
  // The actual point of padding: a Neon dump holder watching sizes over time should not be
  // able to distinguish these.
  const a = pad(new Uint8Array(1000));
  const b = pad(new Uint8Array(1010));
  assert.equal(a.length, b.length);
});

test('sodium is a singleton and ready() is idempotent', async () => {
  const a = await sodiumReady();
  const b = await sodiumReady();
  assert.equal(a, b);
});

// ===========================================================================================
// ADVERSARIAL: THE SERVER-FORGERY HOLE.
//
// The architecture's one property is "the server never holds a key that reads the data", and it
// holds — see the seal-asymmetry tests above. But the converse is easy to assume and was FALSE:
// sealed boxes give confidentiality, NOT authenticity. `crypto_box_seal` needs only idPK, and
// the server HAS idPK — it is the env var onboarding hands the Bridge. So the server could mint
// an envelope that passed every check in `openSection`, contentHash included, because the hash
// was computed over its own chosen plaintext. "The server can't read your numbers but can make
// them up" is not a product.
//
// These tests are the fix, attacked. Each one is an attack that USED to work.
// ===========================================================================================

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const un = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

/**
 * Forge an envelope with EXACTLY what a malicious server holds: the identity public key.
 *
 * No device secret. This is the attack from the report, verbatim, and it must now fail.
 */
async function forgeAsServer(
  plaintext: Uint8Array,
  a: EnvelopeAad,
  idPK: Uint8Array,
): Promise<MaybeSignedEnvelope> {
  const sodium = await sodiumReady();
  const { canonicalStringify } = await import('@tally-bridge/core');
  const cek = sodium.randombytes_buf(32);
  const nonce = sodium.randombytes_buf(24);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    pad(await compress(plaintext)),
    new TextEncoder().encode(canonicalStringify(a as never)),
    null,
    nonce,
    cek,
  );
  return {
    aad: a,
    nonce: b64(nonce),
    sealedCek: b64(sodium.crypto_box_seal(cek, idPK)),
    ciphertext: b64(ct),
    contentHash: b64(new Uint8Array(await crypto.subtle.digest('SHA-256', plaintext as BufferSource))),
  };
}

/**
 * Forge with a STOLEN DEVICE KEY — a strictly stronger attacker than the server.
 *
 * This one still succeeds, by design: a stolen signing key is a real and accepted risk (see
 * @tally-bridge/protocol — it lives in DPAPI, its theft is survivable precisely because it is
 * revocable). It exists here so the zip-bomb test below is exercising the decompression cap
 * rather than passing because the signature check ate the input first.
 */
async function forgeAsStolenDevice(
  plaintext: Uint8Array,
  a: EnvelopeAad,
  idPK: Uint8Array,
  deviceSK: Uint8Array,
): Promise<MaybeSignedEnvelope> {
  const sodium = await sodiumReady();
  const base = await forgeAsServer(plaintext, a, idPK);
  const { canonicalStringify } = await import('@tally-bridge/core');
  const sig = sodium.crypto_sign_detached(
    envelopeSigningBytes({
      sigVer: ENVELOPE_SIG_VERSION,
      alg: 'ed25519',
      aad: new TextEncoder().encode(canonicalStringify(a as never)),
      nonce: un(base.nonce),
      sealedCek: un(base.sealedCek),
      ciphertext: un(base.ciphertext),
      contentHash: un(base.contentHash),
    }),
    deviceSK,
  );
  return { ...base, sig: { v: ENVELOPE_SIG_VERSION, alg: 'ed25519', sig: b64(sig) } };
}

test('ATTACK 1: the server mints fabricated financial data — now REFUSED', async () => {
  // The exact forgery from the audit:
  //   const lie = await sealSection({rows:[{party:'FAKE DEBTOR', amount:'9999999.00'}]}, aad, id.publicKey);
  //   await openSection(lie, id.publicKey, id.secretKey)   // -> used to be ACCEPTED
  const id = await generateIdentity();
  const dev = await makeDevice();

  const lie = new TextEncoder().encode(
    JSON.stringify({ rows: [{ party: 'FAKE DEBTOR', amount: '9999999.00' }] }),
  );
  const forged = await forgeAsServer(lie, aad(), id.publicKey);

  // Everything the server could check about its own forgery is self-consistent. It simply
  // cannot produce the one field it has no key for.
  assert.equal(forged.sig, undefined);
  await assert.rejects(
    () => openSection(forged, opening(id, dev)),
    /envelope is not signed/i,
    'THE HOLE: a server holding only idPK must not be able to mint a readable envelope',
  );
});

test('ATTACK 1b: the server signs its forgery with a key it generated itself — REFUSED', async () => {
  // The obvious follow-up. The server has no shortage of Ed25519 keys; what it lacks is one the
  // reader has PINNED. This is the test that would fail if the reader ever learned the device
  // public key from the server, which is why trust.ts is written the way it is.
  const id = await generateIdentity();
  const realDev = await makeDevice('dev_001');
  const serversOwnKey = await makeDevice('dev_001'); // same deviceId, attacker's key

  const lie = new TextEncoder().encode(
    JSON.stringify({ rows: [{ party: 'FAKE DEBTOR', amount: '9999999.00' }] }),
  );
  const forged = await forgeAsStolenDevice(lie, aad(), id.publicKey, serversOwnKey.secretKey);

  await assert.rejects(
    () => openSection(forged, opening(id, realDev)),
    /bad envelope signature/i,
  );
});

test('ATTACK 2: an envelope for company A, returned for a company B request — REFUSED', async () => {
  // Wholly authentic: the real device signed it, the AEAD is intact, the contentHash matches.
  // It is simply not what was asked for. The server chooses WHICH authentic envelope to return,
  // and no signature covers that choice — so the reader has to state its question.
  const id = await generateIdentity();
  const dev = await makeDevice();

  const COMPANY_A = 'aaaaaaaa-0000-0000-0000-000000000000';
  const COMPANY_B = 'bbbbbbbb-0000-0000-0000-000000000000';

  const envA = await sealSection(
    { rows: [{ party: 'A-Corp Debtor', amount: '111.00' }] },
    aad({ companyGuid: COMPANY_A }),
    id.publicKey,
    dev.secretKey,
  );

  // Sanity: it opens fine when it IS the answer to the question.
  assert.deepEqual(await openSection(envA, opening(id, dev, { companyGuid: COMPANY_A })), {
    rows: [{ party: 'A-Corp Debtor', amount: '111.00' }],
  });

  // ...and is refused when it is not. Before the fix, this returned A's numbers to render
  // under B's name.
  await assert.rejects(
    () => openSection(envA, opening(id, dev, { companyGuid: COMPANY_B })),
    /does not match the request: companyGuid/,
  );
});

test('ATTACK 2b: every requested-slot field is checked, not just the company', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  const wrong: Array<[keyof AadExpectation, Partial<AadExpectation>]> = [
    ['tenantId', { tenantId: 'tnt_other' }],
    ['companyGuid', { companyGuid: '99999999-0000-0000-0000-000000000000' }],
    ['section', { section: 'ageing_payable' }],
    ['asOf', { asOf: '2026-07-15' }],
  ];

  for (const [field, over] of wrong) {
    await assert.rejects(
      () => openSection(env, opening(id, dev, over)),
      new RegExp(`does not match the request: ${field}`),
      `a mismatched ${field} must be refused`,
    );
  }
});

test('ATTACK 3: the signing-string ambiguity attack — boundaries cannot be shifted', async () => {
  // The bug this is inoculating against is REAL and was found in this codebase: fields
  // newline-joined with no length prefixes, so two different tuples serialised to identical
  // bytes and one signature authenticated both.
  //
  // Here the fields are arbitrary binary (ciphertext, sealedCek) — there is no delimiter that
  // could be reserved even in principle. So injectivity comes from u32be length prefixes, and
  // that claim is tested rather than asserted in a comment.
  const base = {
    sigVer: ENVELOPE_SIG_VERSION,
    alg: 'ed25519',
    aad: new Uint8Array([1, 2, 3]),
    nonce: new Uint8Array([4, 5]),
    sealedCek: new Uint8Array([6, 7]),
    ciphertext: new Uint8Array([8, 9]),
    contentHash: new Uint8Array([10]),
  };

  // Shift a byte across EVERY adjacent field boundary. Under a naive concatenation (or a
  // delimiter that can occur in the data) each pair produces identical bytes.
  const shifts: Array<[string, typeof base, typeof base]> = [
    [
      'aad/nonce',
      { ...base, aad: new Uint8Array([1, 2, 3, 4]), nonce: new Uint8Array([5]) },
      { ...base, aad: new Uint8Array([1, 2, 3]), nonce: new Uint8Array([4, 5]) },
    ],
    [
      'nonce/sealedCek',
      { ...base, nonce: new Uint8Array([4, 5, 6]), sealedCek: new Uint8Array([7]) },
      { ...base, nonce: new Uint8Array([4, 5]), sealedCek: new Uint8Array([6, 7]) },
    ],
    [
      'sealedCek/ciphertext',
      { ...base, sealedCek: new Uint8Array([6, 7, 8]), ciphertext: new Uint8Array([9]) },
      { ...base, sealedCek: new Uint8Array([6, 7]), ciphertext: new Uint8Array([8, 9]) },
    ],
    [
      'ciphertext/contentHash',
      { ...base, ciphertext: new Uint8Array([8, 9, 10]), contentHash: new Uint8Array([]) },
      { ...base, ciphertext: new Uint8Array([8, 9]), contentHash: new Uint8Array([10]) },
    ],
  ];

  for (const [boundary, left, right] of shifts) {
    // The premise: naively concatenated, these two ARE the same bytes. If this ever stops
    // holding, the test below has stopped testing anything.
    const naive = (p: typeof base) =>
      b64(
        new Uint8Array([...p.aad, ...p.nonce, ...p.sealedCek, ...p.ciphertext, ...p.contentHash]),
      );
    assert.equal(naive(left), naive(right), `${boundary}: the collision premise must hold`);

    // The framing: they are not.
    assert.notEqual(
      b64(envelopeSigningBytes(left)),
      b64(envelopeSigningBytes(right)),
      `${boundary}: two different tuples MUST NOT produce identical signing bytes`,
    );
  }
});

test('ATTACK 3b: the signing bytes are injective across a spread of distinct tuples', async () => {
  // The general claim, tested generally rather than only at the boundaries above: distinct
  // inputs, distinct signing bytes. No collisions.
  const seen = new Map<string, string>();
  const parts = (over: Partial<EnvelopeSigParts> = {}): EnvelopeSigParts => ({
    sigVer: ENVELOPE_SIG_VERSION,
    alg: 'ed25519',
    aad: new Uint8Array([1]),
    nonce: new Uint8Array([2]),
    sealedCek: new Uint8Array([3]),
    ciphertext: new Uint8Array([4]),
    contentHash: new Uint8Array([5]),
    ...over,
  });

  const cases: Array<[string, EnvelopeSigParts]> = [
    ['baseline', parts()],
    ['empty aad', parts({ aad: new Uint8Array([]) })],
    ['empty everything', parts({
      aad: new Uint8Array([]),
      nonce: new Uint8Array([]),
      sealedCek: new Uint8Array([]),
      ciphertext: new Uint8Array([]),
      contentHash: new Uint8Array([]),
    })],
    ['alg differs', parts({ alg: 'ed25519x' })],
    ['sigVer differs', parts({ sigVer: 2 })],
    ['aad has the domain tag inside it', parts({
      aad: new TextEncoder().encode('tally-bridge/envelope-signature/v1'),
    })],
    ['fields swapped', parts({ aad: new Uint8Array([2]), nonce: new Uint8Array([1]) })],
    ['all fields concatenated into aad', parts({
      aad: new Uint8Array([1, 2, 3, 4, 5]),
      nonce: new Uint8Array([]),
      sealedCek: new Uint8Array([]),
      ciphertext: new Uint8Array([]),
      contentHash: new Uint8Array([]),
    })],
  ];

  for (const [name, p] of cases) {
    const bytes = b64(envelopeSigningBytes(p));
    const clash = seen.get(bytes);
    assert.equal(clash, undefined, `"${name}" collides with "${clash}"`);
    seen.set(bytes, name);
  }
});

test('ATTACK 4: a signature lifted from another envelope — REFUSED', async () => {
  // The server holds every envelope ever uploaded, so it holds a large supply of VALID
  // signatures by the real device. Bolting one onto a different envelope must not work.
  const id = await generateIdentity();
  const dev = await makeDevice();

  const real = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);
  const other = await sealSection({ rows: [] }, aad({ seq: 43 }), id.publicKey, dev.secretKey);

  await assert.rejects(
    () => openSection({ ...real, sig: other.sig }, opening(id, dev)),
    /bad envelope signature/i,
    'a valid signature over a DIFFERENT envelope must not verify',
  );
});

test('ATTACK 4b: a zero-length and a garbage signature — REFUSED, not crashed', async () => {
  // libsodium throws on a wrong-length signature rather than returning false. An uncaught
  // throw here is a different bug wearing the same clothes.
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  for (const bad of ['', b64(new Uint8Array(0)), b64(new Uint8Array(63)), b64(new Uint8Array(64))]) {
    await assert.rejects(
      () => openSection({ ...env, sig: { ...env.sig, sig: bad } }, opening(id, dev)),
      /bad envelope signature/i,
      `signature "${bad.slice(0, 12)}..." must be refused cleanly`,
    );
  }
});

test('ATTACK 5: stripping the signature to force a downgrade — REFUSED', async () => {
  // If unsigned envelopes were tolerated "for compatibility", the entire fix would be one
  // `delete env.sig` away from undone. No data predates this format, so there is nothing to be
  // compatible WITH: a downgrade path we do not need is a downgrade attack we would have.
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  const stripped: MaybeSignedEnvelope = { ...env };
  delete stripped.sig;
  await assert.rejects(() => openSection(stripped, opening(id, dev)), /envelope is not signed/i);

  // And the same via the shapes a JSON body can actually take.
  for (const junk of [null, undefined, 'ed25519', 0]) {
    await assert.rejects(
      () => openSection({ ...env, sig: junk as never }, opening(id, dev)),
      /envelope is not signed|unsupported envelope signature version/i,
    );
  }
});

test('ATTACK 5b: alg confusion — an unknown or absent alg is refused, never dispatched on', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice();
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  for (const alg of ['none', 'None', '', 'hmac-sha256', 'ED25519']) {
    await assert.rejects(
      () => openSection({ ...env, sig: { ...env.sig, alg: alg as never } }, opening(id, dev)),
      /unsupported envelope signature algorithm/,
      `alg "${alg}" must be refused`,
    );
  }

  await assert.rejects(
    () => openSection({ ...env, sig: { ...env.sig, v: 2 as never } }, opening(id, dev)),
    /unsupported envelope signature version 2/,
  );
});

test('ATTACK 6: device B cannot sign as device A', async () => {
  // Both devices are legitimately pinned — the user owns two Bridges. The roster is keyed by
  // deviceId for this reason: "trusted" is not a global boolean.
  const id = await generateIdentity();
  const devA = await makeDevice('dev_A');
  const devB = await makeDevice('dev_B');

  const roster = [
    { deviceId: devA.deviceId, publicKey: devA.publicKey },
    { deviceId: devB.deviceId, publicKey: devB.publicKey },
  ];

  // B signs an envelope whose AAD claims to be from A.
  const lie = new TextEncoder().encode(JSON.stringify({ rows: [{ party: 'X', amount: '1.00' }] }));
  const forged = await forgeAsStolenDevice(
    lie,
    aad({ deviceId: 'dev_A' }),
    id.publicKey,
    devB.secretKey,
  );

  await assert.rejects(
    () =>
      openSection(forged, {
        identityPublicKey: id.publicKey,
        identitySecretKey: id.secretKey,
        expect: { tenantId: TENANT, companyGuid: COMPANY, section: 'ageing_receivable', asOf: AS_OF },
        trustedDevices: roster,
      }),
    /bad envelope signature/i,
  );
});

test('ATTACK 6b: an unknown device, and an empty roster, are both refused', async () => {
  const id = await generateIdentity();
  const dev = await makeDevice('dev_001');
  const env = await sealSection(payload(), aad(), id.publicKey, dev.secretKey);

  // Not in the roster at all.
  await assert.rejects(
    () =>
      openSection(env, {
        ...opening(id, dev),
        trustedDevices: [{ deviceId: 'dev_somebody_else', publicKey: dev.publicKey }],
      }),
    /untrusted device dev_001/,
  );

  // An empty roster is what a bug or a failed fetch produces. It must never mean "nothing to
  // check, so let it through" — which is the shape of the failure that turns a security control
  // into a no-op in production while every test still passes.
  await assert.rejects(
    () => openSection(env, { ...opening(id, dev), trustedDevices: [] }),
    /refusing to verify against nothing/,
  );
});

test('key rotation: two pinned keys for one device, either verifies', async () => {
  const id = await generateIdentity();
  const oldKey = await makeDevice('dev_001');
  const newKey = await makeDevice('dev_001');
  const roster = [
    { deviceId: 'dev_001', publicKey: oldKey.publicKey },
    { deviceId: 'dev_001', publicKey: newKey.publicKey },
  ];

  for (const signer of [oldKey, newKey]) {
    const env = await sealSection(payload(), aad(), id.publicKey, signer.secretKey);
    assert.deepEqual(
      await openSection(env, { ...opening(id, oldKey), trustedDevices: roster }),
      payload(),
    );
  }
});

test('a forged zip bomb is refused, not inflated into the dashboard', async () => {
  // Now strictly a STOLEN-DEVICE-KEY attack rather than a malicious-server one: the server can
  // no longer get a payload past the signature check at all. The cap still matters, because a
  // stolen device key is an accepted risk and revocation is not instantaneous.
  const id = await generateIdentity();
  const dev = await makeDevice();
  // 256MB of zeros: ~250KB on the wire at gzip's ~1000:1 ceiling. Measured before the cap in
  // compress.ts, an 80KB forgery of this shape inflated to 60MB inside openSection.
  const bomb = new Uint8Array(256 * 1024 * 1024);
  const env = await forgeAsStolenDevice(bomb, aad(), id.publicKey, dev.secretKey);
  assert.ok(
    env.ciphertext.length < 2 * 1024 * 1024,
    `forgery should be small on the wire, was ${env.ciphertext.length}`,
  );
  await assert.rejects(
    () => openSection(env, opening(id, dev)),
    /exceeds|zip bomb/i,
    'openSection must not decompress an unbounded payload',
  );
});

test('the zip-bomb forgery is otherwise valid — the cap is what stops it', async () => {
  // Guards against the bomb test passing for the wrong reason. If the forgery were rejected at
  // the signature, the rejection above would prove nothing about the decompression cap.
  const id = await generateIdentity();
  const dev = await makeDevice();
  const small = new TextEncoder().encode('{"rows":[]}');
  const env = await forgeAsStolenDevice(small, aad(), id.publicKey, dev.secretKey);
  assert.deepEqual(await openSection(env, opening(id, dev)), { rows: [] });
});
