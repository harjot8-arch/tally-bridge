import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_CLOCK_SKEW_MS,
  MAX_NONCE_LENGTH,
  bootstrapSecretMatches,
  buildSigningString,
  generateDeviceKeypair,
  signRequest,
  verifyRequest,
  type VerifyDeps,
} from '../src/signing.ts';

const NOW = 1_752_600_000_000;
const body = () => new TextEncoder().encode('{"ciphertext":"abc"}');

/** A nonce store with the UNIQUE-constraint semantics the real one must have. */
function nonceStore() {
  const seen = new Set<string>();
  const expiries: number[] = [];
  return {
    seen,
    expiries,
    remember: async (deviceId: string, nonce: string, expiresAt: number) => {
      const k = `${deviceId}|${nonce}`;
      if (seen.has(k)) return false;
      seen.add(k);
      expiries.push(expiresAt);
      return true;
    },
  };
}

async function deps(over: Partial<VerifyDeps> = {}): Promise<{ deps: VerifyDeps; kp: Awaited<ReturnType<typeof generateDeviceKeypair>>; nonces: ReturnType<typeof nonceStore> }> {
  const kp = await generateDeviceKeypair('dev_1');
  const nonces = nonceStore();
  return {
    kp,
    nonces,
    deps: {
      lookupDevice: async (id) => (id === 'dev_1' ? { publicKey: kp.publicKey, revoked: false } : undefined),
      rememberNonce: nonces.remember,
      // The default is an admit that always says yes, so that every test NOT about the gate is
      // testing the same thing it tested before the gate existed. The tests that ARE about the
      // gate override it through `over`.
      admit: async () => ({ ok: true as const }),
      now: () => NOW,
      ...over,
    },
  };
}

test('a signed request verifies', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(res.ok);
  assert.equal(res.deviceId, 'dev_1');
});

test('THE REPLAY DEFENCE: the same request cannot be sent twice', async () => {
  // Without the nonce table, the clock-skew window IS a 5-minute replay window: a captured
  // request replays verbatim, with a perfectly valid signature, until the timestamp ages out.
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const req = { method: 'POST', path: '/api/sync', body: b };

  assert.ok((await verifyRequest(headers, req, d)).ok);

  const second = await verifyRequest(headers, req, d);
  assert.ok(!second.ok);
  assert.equal(second.failure.kind, 'replayed_nonce');
});

test('the nonce is NOT consumed when the signature is invalid', async () => {
  // Order matters: consuming first would let an unauthenticated attacker burn arbitrary nonces
  // and grow the table for free.
  const { deps: d, kp, nonces } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const forged = { ...headers, 'x-tb-signature': Buffer.alloc(64).toString('base64') };

  const res = await verifyRequest(forged, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'bad_signature');
  assert.equal(nonces.seen.size, 0, 'a bogus request must not consume nonce-table space');
});

test('tampering with the body fails', async () => {
  const { deps: d, kp } = await deps();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: body(), timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(
    headers,
    { method: 'POST', path: '/api/sync', body: new TextEncoder().encode('{"ciphertext":"EVIL"}') },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'bad_signature');
});

test('tampering with the method or path fails', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const wrongPath = await verifyRequest(headers, { method: 'POST', path: '/api/devices', body: b }, d);
  assert.ok(!wrongPath.ok);
  assert.equal(wrongPath.failure.kind, 'bad_signature');

  const wrongMethod = await verifyRequest(headers, { method: 'DELETE', path: '/api/sync', body: b }, d);
  assert.ok(!wrongMethod.ok);
});

test('tampering with the timestamp fails', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  // Push the timestamp forward to dodge expiry — the signature covers it, so this fails.
  const res = await verifyRequest(
    { ...headers, 'x-tb-timestamp': String(NOW + 1000) },
    { method: 'POST', path: '/api/sync', body: b },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'bad_signature');
});

test('a stale request is rejected', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW - MAX_CLOCK_SKEW_MS - 1 },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'clock_skew');
});

test('a future-dated request is rejected too', async () => {
  // Indian SMB PCs frequently have wrong clocks; skew is checked in both directions.
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW + MAX_CLOCK_SKEW_MS + 1 },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'clock_skew');
});

test('a request just inside the skew window is accepted', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW - MAX_CLOCK_SKEW_MS + 1000 },
    kp.secretKey,
  );
  assert.ok((await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d)).ok);
});

test('REVOCATION: a stolen device key becomes worthless with one click', async () => {
  // This is what makes keeping the signing key in DPAPI acceptable. DPAPI does not protect
  // against other processes running as the same user, so the key CAN be stolen — but its theft
  // is survivable precisely because of this path.
  const kp = await generateDeviceKeypair('dev_1');
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const revoked: VerifyDeps = {
    lookupDevice: async () => ({ publicKey: kp.publicKey, revoked: true }),
    rememberNonce: async () => true,
    // A revoked device is refused before the gate is reached, so this must never run. Throwing
    // says so where a comment could only claim it: revocation must not spend the rate budget of
    // the device it just disarmed.
    admit: async () => assert.fail('a revoked device must not reach the admission gate'),
    now: () => NOW,
  };
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, revoked);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'revoked_device');
});

test('an unknown device is rejected', async () => {
  const { deps: d, kp } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_unknown', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'unknown_device');
});

test('another device cannot sign for this one', async () => {
  const { deps: d } = await deps();
  const mallory = await generateDeviceKeypair('dev_1'); // claims dev_1, different key
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    mallory.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'bad_signature');
});

test('missing headers are reported, not crashed on', async () => {
  const { deps: d } = await deps();
  const res = await verifyRequest({}, { method: 'POST', path: '/api/sync', body: body() }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'missing_header');
});

test('a malformed signature does not throw', async () => {
  // libsodium throws on a wrong-length signature rather than returning false; an unhandled
  // throw here would be a trivial 500-on-demand.
  const { deps: d } = await deps();
  const res = await verifyRequest(
    {
      'x-tb-device': 'dev_1',
      'x-tb-timestamp': String(NOW),
      'x-tb-nonce': 'abc',
      'x-tb-signature': 'AAAA', // valid base64, wrong length
    },
    { method: 'POST', path: '/api/sync', body: body() },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'bad_signature');
});

test('a non-numeric timestamp is rejected as malformed', async () => {
  const { deps: d } = await deps();
  const res = await verifyRequest(
    {
      'x-tb-device': 'dev_1',
      'x-tb-timestamp': 'not-a-number',
      'x-tb-nonce': 'abc',
      'x-tb-signature': Buffer.alloc(64).toString('base64'),
    },
    { method: 'POST', path: '/api/sync', body: body() },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'malformed');
});

test('signer and verifier build byte-identical signing strings', async () => {
  // The contract. If these ever diverge, every request 401s.
  const b = body();
  const s1 = await buildSigningString({
    deviceId: 'dev_1', method: 'post', path: '/api/sync', timestamp: NOW, nonce: 'n1', body: b,
  });
  const s2 = await buildSigningString({
    deviceId: 'dev_1', method: 'POST', path: '/api/sync', timestamp: NOW, nonce: 'n1', body: b,
  });
  assert.equal(s1, s2, 'method is normalized to uppercase on both sides');
  assert.equal(s1.split('\n').length, 6);
});

test('signing strings differ when any component differs', async () => {
  const b = body();
  const base = { deviceId: 'd', method: 'POST', path: '/p', timestamp: NOW, nonce: 'n', body: b };
  const s = await buildSigningString(base);
  for (const [label, over] of [
    ['device', { deviceId: 'd2' }],
    ['method', { method: 'GET' }],
    ['path', { path: '/p2' }],
    ['timestamp', { timestamp: NOW + 1 }],
    ['nonce', { nonce: 'n2' }],
    ['body', { body: new TextEncoder().encode('other') }],
  ] as const) {
    assert.notEqual(await buildSigningString({ ...base, ...over }), s, `${label} must be covered`);
  }
});

test('each signature gets a fresh random nonce', async () => {
  const kp = await generateDeviceKeypair('dev_1');
  const b = body();
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) {
    const h = await signRequest({ deviceId: 'dev_1', method: 'POST', path: '/p', body: b }, kp.secretKey);
    seen.add(h['x-tb-nonce']);
  }
  assert.equal(seen.size, 50);
});

// ---------------------------------------------------------------- bootstrap

test('the bootstrap secret matches only itself', async () => {
  assert.equal(await bootstrapSecretMatches('s3cret', 's3cret'), true);
  assert.equal(await bootstrapSecretMatches('s3cret', 'wrong'), false);
  assert.equal(await bootstrapSecretMatches('short', 'longer-secret'), false);
});

test('bootstrap comparison does not early-exit on a prefix match', async () => {
  // Constant-time: this is attacker-submittable, so a byte-by-byte early exit leaks it.
  assert.equal(await bootstrapSecretMatches('aaaaaaaa', 'aaaaaaab'), false);
  assert.equal(await bootstrapSecretMatches('baaaaaaa', 'aaaaaaaa'), false);
});

// ---------------------------------------------------------------- adversarial audit additions

test('AUDIT: THE SIGNING STRING MUST BE UNAMBIGUOUS — one signature, two different requests', async () => {
  // The fields are newline-joined with no length prefixes, and the comment above
  // buildSigningString asserts the framing is safe because "none of them may contain a
  // newline". NOTHING ENFORCES THAT. An unenforced invariant is a comment, not a defence.
  //
  // The framing is therefore not injective: shift the field boundaries and two completely
  // different tuples serialise to the same bytes. Here the path swallows a body hash, a
  // timestamp and a nonce; the nonce on the other side swallows the rest. Both are well-formed
  // inputs to this function, and the joined strings are identical -- so ONE Ed25519 signature
  // authenticates a request with a DIFFERENT BODY at a DIFFERENT TIME. The signature is doing
  // its job perfectly; the serialisation is lying to it.
  const realBody = new TextEncoder().encode('{"amount":"1.00"}');
  const evilBody = new TextEncoder().encode('{"amount":"999999.00"}');

  const hashOf = async (b: Uint8Array) =>
    Buffer.from(await crypto.subtle.digest('SHA-256', b as BufferSource)).toString('base64');
  const realHash = await hashOf(realBody);
  const evilHash = await hashOf(evilBody);

  // Tuple 1: an innocent-looking path that happens to carry newlines.
  const tuple1 = {
    deviceId: 'dev_1',
    method: 'POST',
    path: `/api/sync\n${evilHash}\n${NOW}\nnonceY`,
    timestamp: 1,
    nonce: 'N',
    body: realBody,
  };

  // Tuple 2: a DIFFERENT path, a DIFFERENT body, a DIFFERENT timestamp, a DIFFERENT nonce --
  // and, before the fix, BYTE-IDENTICAL signing bytes. A signature over a 1.00 body verified a
  // 999999.00 body.
  const tuple2 = {
    deviceId: 'dev_1',
    method: 'POST',
    path: '/api/sync',
    timestamp: NOW,
    nonce: `nonceY\n${realHash}\n1\nN`,
    body: evilBody,
  };

  // The collision is now unconstructible: it REQUIRES a delimiter inside a field, and the only
  // function that frames these fields refuses to. Both halves are turned away, so no signature
  // over either can ever be presented for the other.
  const s1 = await buildSigningString(tuple1).catch((e: Error) => e);
  const s2 = await buildSigningString(tuple2).catch((e: Error) => e);
  assert.ok(s1 instanceof Error, 'the crafted path must be refused');
  assert.ok(s2 instanceof Error, 'the crafted nonce must be refused');

  // And the framing is injective for everything it DOES accept: vary one field at a time and no
  // two tuples may ever land on the same bytes.
  const legit = {
    deviceId: 'dev_1',
    method: 'POST',
    path: '/api/sync',
    timestamp: NOW,
    nonce: 'nonceY',
    body: realBody,
  };
  const variants = [
    legit,
    { ...legit, deviceId: 'dev_2' },
    { ...legit, method: 'PUT' },
    { ...legit, path: '/api/sync2' },
    { ...legit, timestamp: NOW + 1 },
    { ...legit, nonce: 'nonceZ' },
    { ...legit, body: evilBody },
  ];
  const strings = await Promise.all(variants.map((v) => buildSigningString(v)));
  assert.equal(new Set(strings).size, variants.length, 'distinct tuples must give distinct bytes');
});

test('AUDIT: a newline in any signed field is rejected, not silently framed', async () => {
  // The invariant the framing depends on, enforced at the only place both sides go through.
  // deviceId is the sharpest case -- verifyRequest takes it straight from an attacker-supplied
  // header and feeds it back into this function before anything has authenticated it.
  const body = new TextEncoder().encode('x');
  const base = { deviceId: 'dev_1', method: 'POST', path: '/api/sync', timestamp: NOW, nonce: 'N', body };

  await assert.rejects(
    () => buildSigningString({ ...base, deviceId: 'a\nPOST\n/api/evil' }),
    /newline|invalid/i,
    'deviceId="a\\nPOST\\n/api/evil" must be refused',
  );
  await assert.rejects(() => buildSigningString({ ...base, path: '/api/sync\nGET\n/x' }), /newline|invalid/i);
  await assert.rejects(() => buildSigningString({ ...base, nonce: 'n\nmore' }), /newline|invalid/i);
  await assert.rejects(() => buildSigningString({ ...base, method: 'PO\nST' }), /newline|invalid/i);
  // A carriage return splits lines just as well in most parsers.
  await assert.rejects(() => buildSigningString({ ...base, deviceId: 'a\rb' }), /newline|invalid/i);
});

test('AUDIT: a request whose device header carries a newline is malformed, not a 500', async () => {
  // verifyRequest must convert the refusal into a clean rejection. An uncaught throw here is an
  // unauthenticated attacker crashing a serverless function on demand.
  const { deps: d } = await deps();
  const res = await verifyRequest(
    {
      'x-tb-device': 'dev_1\nPOST\n/api/evil',
      'x-tb-timestamp': String(NOW),
      'x-tb-nonce': 'AAAA',
      'x-tb-signature': 'AAAA',
    },
    { method: 'POST', path: '/api/sync', body: body() },
    d,
  );
  assert.ok(!res.ok);
  assert.ok(
    res.failure.kind === 'malformed' || res.failure.kind === 'unknown_device',
    `expected a clean rejection, got ${res.failure.kind}`,
  );
});

test('AUDIT: the nonce is not consumed by a request that fails on clock skew', async () => {
  // The nonce table must only ever be written by an AUTHENTICATED request. Anything else is a
  // free table-growth primitive for an unauthenticated attacker.
  const { deps: d, kp, nonces } = await deps({ now: () => NOW + MAX_CLOCK_SKEW_MS * 10 });
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok && res.failure.kind === 'clock_skew');
  assert.equal(nonces.seen.size, 0, 'nothing may be written before the signature is checked');
});

// ------------------------------------------------- audit round 2: fail-open and amplification

test('AUDIT: AN UNUSABLE CLOCK MUST FAIL CLOSED, NOT WAVE EVERYTHING THROUGH', async () => {
  // The NaN fail-open, in the one comparison that bounds the replay window.
  //
  // `skew > MAX_CLOCK_SKEW_MS` is a single `>`, and EVERY comparison against NaN is false. So a
  // `now()` that returns NaN does not fail the skew check — it SKIPS it, and verifyRequest
  // returned ok:true for a request of ANY age. The ±300s window is the only thing that bounds
  // how long a captured request stays replayable once its nonce row has been pruned; with the
  // window gone, a request captured a year ago verifies today.
  //
  // The same shape was already caught and fixed in checkQuota (see `measurable`); this is the
  // identical bug one file over, on the clock instead of the counters.
  const { deps: d, kp } = await deps({ now: () => NaN });
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok, 'a NaN clock must never authenticate a request');
  assert.equal(res.failure.kind, 'unusable_clock');

  // Infinity happens to be caught by `>` today, but only by luck of the sign. Pin it.
  const inf = await deps({ now: () => Infinity });
  const res2 = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, inf.deps);
  assert.ok(!res2.ok);
  assert.equal(res2.failure.kind, 'unusable_clock');

  const neg = await deps({ now: () => -Infinity });
  const res3 = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, neg.deps);
  assert.ok(!res3.ok);
  assert.equal(res3.failure.kind, 'unusable_clock');
});

test('AUDIT: THE NONCE IS BOUNDED — a stolen key cannot amplify one request into a megabyte of table', async () => {
  // The nonce is spec'd as "128 bits, base64" — 24 characters. NOTHING enforced that. The only
  // checks were non-empty and newline-free, so a 1MB nonce header rode a perfectly valid
  // signature straight into rememberNonce, which writes it to seen_nonce.
  //
  // This is the write-amplification multiplier on the bill: the row count is what the rate limit
  // bounds, but the row SIZE was unbounded, so 60 permitted uploads/hour could still write 60MB
  // of nonce rows per hour per device — onto the CLIENT'S OWN Neon card, with no refund path.
  // Model the attacker honestly: they hold a stolen key and run their OWN signer, so the fact
  // that our signRequest now refuses to build this is not a defence — the verifier has to be the
  // one that says no. Note the nonce never even reaches lookupDevice, let alone rememberNonce.
  const hugeNonce = 'A'.repeat(1_000_000);
  let lookups = 0;
  const { deps: d, kp, nonces } = await deps({
    lookupDevice: async (id) => {
      lookups++;
      const k = await kpRef;
      return id === 'dev_1' ? { publicKey: k.publicKey, revoked: false } : undefined;
    },
  });
  const kpRef = Promise.resolve(kp);
  const b = body();
  const res = await verifyRequest(
    {
      'x-tb-device': 'dev_1',
      'x-tb-timestamp': String(NOW),
      'x-tb-nonce': hugeNonce,
      'x-tb-signature': Buffer.alloc(64).toString('base64'),
    },
    { method: 'POST', path: '/api/sync', body: b },
    d,
  );
  assert.ok(!res.ok, 'a 1MB nonce must never reach the nonce table');
  assert.equal(res.failure.kind, 'malformed');
  assert.equal(nonces.seen.size, 0, 'no row may be spent on it');
  assert.equal(lookups, 0, 'and it must not even reach the database');

  // Our own signer refuses to emit one too — defence in depth, not the defence itself.
  await assert.rejects(
    () => signRequest(
      { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW, nonce: hugeNonce },
      kp.secretKey,
    ),
    /at most/,
  );

  // The real thing still fits, with room to spare.
  const honest = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  assert.ok(honest['x-tb-nonce'].length <= MAX_NONCE_LENGTH);
  assert.ok((await verifyRequest(honest, { method: 'POST', path: '/api/sync', body: b }, d)).ok);
});

test('AUDIT: an oversized deviceId is refused BEFORE it reaches the device lookup', async () => {
  // deviceId is unauthenticated attacker input that gets used as a DATABASE QUERY PARAMETER
  // before anything has verified a signature. A 500KB device header must not become a 500KB
  // query against Neon on demand, from anyone, with no key and no account.
  let lookups = 0;
  const { deps: d } = await deps({
    lookupDevice: async () => {
      lookups++;
      return undefined;
    },
  });
  const res = await verifyRequest(
    {
      'x-tb-device': 'dev_1'.padEnd(500_000, 'B'),
      'x-tb-timestamp': String(NOW),
      'x-tb-nonce': 'AAAA',
      'x-tb-signature': Buffer.alloc(64).toString('base64'),
    },
    { method: 'POST', path: '/api/sync', body: body() },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'malformed');
  assert.equal(lookups, 0, 'an oversized device header must not reach the database at all');
});

test('AUDIT: a non-string header is refused before it reaches the device lookup', async () => {
  // The type says `string | undefined`; the runtime is a request. A duplicated header can arrive
  // as an array, and `!value` waves an array through — after which an ARRAY was handed to
  // lookupDevice as a device id, before buildSigningString (the only thing that type-checks it)
  // ever ran.
  let lookups = 0;
  const { deps: d } = await deps({
    lookupDevice: async () => {
      lookups++;
      return undefined;
    },
  });
  const res = await verifyRequest(
    {
      'x-tb-device': ['dev_1'] as unknown as string,
      'x-tb-timestamp': String(NOW),
      'x-tb-nonce': 'AAAA',
      'x-tb-signature': Buffer.alloc(64).toString('base64'),
    },
    { method: 'POST', path: '/api/sync', body: body() },
    d,
  );
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'malformed');
  assert.equal(lookups, 0, 'a non-string device header must not reach the database');
});

test('AUDIT: THE BOOTSTRAP SECRET FAILS CLOSED when the env var was never set', async () => {
  // `bootstrapSecretMatches(presented, process.env.BOOTSTRAP_SECRET)` is the natural call, and
  // env vars are `string | undefined`. TextEncoder().encode(undefined) is not "undefined" — the
  // WebIDL default makes it the EMPTY STRING. So an unset secret encoded to zero bytes, a
  // presented "" encoded to zero bytes, and memcmp(empty, empty) is TRUE: presenting an empty
  // secret authenticated against a secret that does not exist.
  //
  // apps/server currently guards this at the call site (`if (!deps.expectedSecret)`), so this
  // was not live — but a comparison primitive that answers "yes" to nothing-vs-nothing is a
  // landmine that survives exactly as long as every future caller remembers the guard.
  assert.equal(await bootstrapSecretMatches('', undefined as unknown as string), false);
  assert.equal(await bootstrapSecretMatches('', ''), false, 'nothing must never match nothing');
  assert.equal(await bootstrapSecretMatches(undefined as unknown as string, ''), false);
  assert.equal(await bootstrapSecretMatches('s3cret', undefined as unknown as string), false);
  assert.equal(await bootstrapSecretMatches(null as unknown as string, null as unknown as string), false);
  // A real secret still matches itself.
  assert.equal(await bootstrapSecretMatches('s3cret', 's3cret'), true);
});

// ------------------------------------------------- audit round 2: nonce write amplification

test('AUDIT: THE RATE LIMIT RUNS BEFORE THE NONCE IS WRITTEN', async () => {
  // The amplification: verifyRequest wrote a seen_nonce row for every request with a valid
  // signature, and handleIngest only reached its rate limiter AFTERWARDS. A stolen device key
  // could therefore grow seen_nonce without bound at full request rate — running up the
  // CLIENT'S OWN Neon bill, which is the exact thing the quota cap exists to prevent, and which
  // is not undoable for the customer.
  //
  // `admit` closes it by giving the caller a seat between "the signature is good" and "we spend
  // a row on it".
  const { deps: d, kp, nonces } = await deps({
    admit: async () => ({ ok: false, detail: 'rate_limited' }),
  });
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'not_admitted');
  assert.equal(nonces.seen.size, 0, 'a rate-limited request must not cost a nonce row');
});

test('AUDIT: admit runs only AFTER the signature is verified', async () => {
  // The other half of the ordering. If admit ran first, an attacker with no key could burn a
  // real device's rate-limit budget — trading a bill DoS for an availability DoS.
  let admitted = 0;
  const { deps: d, kp } = await deps({
    admit: async () => {
      admitted++;
      return { ok: true };
    },
  });
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const forged = { ...headers, 'x-tb-signature': Buffer.alloc(64).toString('base64') };
  const res = await verifyRequest(forged, { method: 'POST', path: '/api/sync', body: b }, d);
  assert.ok(!res.ok && res.failure.kind === 'bad_signature');
  assert.equal(admitted, 0, 'an unsigned request must not spend the device budget');

  assert.ok((await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d)).ok);
  assert.equal(admitted, 1, 'a signed request is admitted exactly once');
});

test('AUDIT: REPLAY PROTECTION SURVIVES THE ADMIT HOOK', async () => {
  // The thing that must not be traded away. admit sits BEFORE rememberNonce, so the proof that
  // replay still holds is: a request that is admitted always reaches rememberNonce, and
  // rememberNonce is still the last gate before ok:true. Nothing that returns ok skips it.
  const { deps: d, kp, nonces } = await deps({ admit: async () => ({ ok: true }) });
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  const req = { method: 'POST', path: '/api/sync', body: b };
  assert.ok((await verifyRequest(headers, req, d)).ok);
  const second = await verifyRequest(headers, req, d);
  assert.ok(!second.ok);
  assert.equal(second.failure.kind, 'replayed_nonce', 'admit must not open a replay window');
  assert.equal(nonces.seen.size, 1);
});

test('AUDIT: the nonce TTL covers the whole window in which the request is still acceptable', async () => {
  // Why pruning is safe, stated as an invariant rather than a hope. A nonce row may only be
  // dropped once the request that used it can no longer verify, or pruning IS a replay window.
  //
  // A request with timestamp T verifies while |now - T| <= 300s, i.e. up to T + 300s. The row is
  // told to expire at exactly T + 300s. So the row outlives the acceptance window by
  // construction, and `DELETE WHERE expires_at < now()` can never resurrect a replayable
  // request: anything whose row is gone is also outside the skew window.
  const { deps: d, kp, nonces } = await deps();
  const b = body();
  const headers = await signRequest(
    { deviceId: 'dev_1', method: 'POST', path: '/api/sync', body: b, timestamp: NOW },
    kp.secretKey,
  );
  assert.ok((await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, d)).ok);
  assert.equal(nonces.expiries.length, 1);
  assert.equal(nonces.expiries[0], NOW + MAX_CLOCK_SKEW_MS, 'TTL must equal the end of the skew window');

  // The boundary, from the other side: one millisecond past the TTL, the skew check alone
  // already refuses the request — so the row is dead weight and safe to drop.
  const late = await deps({ now: () => NOW + MAX_CLOCK_SKEW_MS + 1 });
  const res = await verifyRequest(headers, { method: 'POST', path: '/api/sync', body: b }, late.deps);
  assert.ok(!res.ok && res.failure.kind === 'clock_skew');
  assert.equal(late.nonces.seen.size, 0, 'an expired request never needed its row');
});

test('AUDIT: admit is REQUIRED — a caller cannot silently forget the gate', async () => {
  // This test used to assert the opposite: "verifyRequest without an admit hook still behaves".
  // It did, and that was the whole problem. admit was optional for one reason — making it
  // required would have broken a package that had not wired it yet — and apps/server has now
  // wired it. What optionality leaves behind is a security seat a caller can omit with no word
  // from the compiler, i.e. the ORIGINAL amplification bug, one forgotten property away.
  //
  // The enforcement is the TYPE, so the test for it is a type test. tsconfig.test.json checks
  // this file, and `@ts-expect-error` is not a suppression here — it is an ASSERTION that the
  // error still occurs. If admit ever goes back to optional, the directive becomes unused and
  // `npm run typecheck` FAILS. That is the point: the guarantee is checked, not commented.
  const { kp } = await deps();
  const withoutAdmit = {
    lookupDevice: async () => ({ publicKey: kp.publicKey, revoked: false }),
    rememberNonce: async () => true,
    now: () => NOW,
  };
  // @ts-expect-error a VerifyDeps that omits the admission gate must not typecheck.
  const unmetered: VerifyDeps = withoutAdmit;
  assert.ok(unmetered, 'the runtime half is trivial; the compiler is the assertion above');
});
