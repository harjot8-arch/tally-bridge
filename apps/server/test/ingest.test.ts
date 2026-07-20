import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, makeAad, sealSection } from '@tally-bridge/crypto';
import {
  MAX_CLOCK_SKEW_MS,
  MAX_UPLOADS_PER_HOUR_PER_DEVICE,
  bootstrapSecretMatches,
  generateDeviceKeypair,
  signRequest,
  type SignedHeaders,
} from '@tally-bridge/protocol';
import type { CanonicalValue, SealedEnvelope, Section } from '@tally-bridge/core';
import { BOOTSTRAP_TTL_MS, handleIngest, handleRegister, type IngestDeps } from '../src/ingest.ts';

const NOW = 1_752_600_000_000;
const TENANT = 'tnt_1';
const DEVICE = 'dev_1';

/**
 * @param slowDb model a dep that costs a network round trip, as every real one does. Stubs that
 *   answer inside the same microtask drain hide read-then-write races by accident.
 */
async function fixture({ slowDb = false }: { slowDb?: boolean } = {}) {
  const identity = await generateIdentity();
  const device = await generateDeviceKeypair(DEVICE);
  const roundTrip = async () => {
    if (slowDb) await new Promise((r) => setTimeout(r, 1));
  };

  const stored = new Map<string, { snapshotTs: number; bytes: number; contentHash: string }>();
  const nonces = new Set<string>();
  /** Every dep call, in the order it happened. The ORDER is the whole fix; see the audit tests. */
  const calls: string[] = [];
  let uploadCount = 0;
  let tenantBytes = 0;
  let clock = NOW;

  const deps: IngestDeps = {
    lookupDevice: async (id) => (id === DEVICE ? { publicKey: device.publicKey, revoked: false } : undefined),
    // seen_nonce. This Set IS the table whose growth the rate cap must bound — every entry is a
    // permanent row on the client's own Neon bill.
    rememberNonce: async (d, n) => {
      calls.push('rememberNonce');
      // The round trip is BEFORE the check-and-insert, never between them. The real statement is
      // one `INSERT ... ON CONFLICT DO NOTHING RETURNING`, which is atomic against itself; what
      // must not be modelled as free is the POST that carries it.
      await roundTrip();
      const k = `${d}|${n}`;
      if (nonces.has(k)) return false;
      nonces.add(k);
      return true;
    },
    now: () => clock,
    tenantIdForDevice: async (id) => (id === DEVICE ? TENANT : undefined),
    latestSnapshot: async (t, c, s, a) => {
      const row = stored.get(`${t}|${c}|${s}|${a}`);
      return row ? { snapshotTs: row.snapshotTs, contentHash: row.contentHash } : undefined;
    },
    // The atomic reservation the real dep must be: the count is read and incremented with no
    // await in between, exactly as a single `INSERT ... RETURNING` would.
    reserveUpload: async (_d, bytes) => {
      calls.push('reserveUpload');
      await roundTrip();
      tenantBytes += bytes;
      return ++uploadCount;
    },
    tenantBytesStored: async () => {
      await roundTrip();
      return tenantBytes;
    },
    storeSnapshot: async (row) => {
      stored.set(`${row.tenantId}|${row.companyGuid}|${row.section}|${row.asOf}`, {
        snapshotTs: row.snapshotTs,
        bytes: row.bytes,
        contentHash: row.contentHash,
      });
    },
    touchDevice: async () => {},
  };

  async function makeUpload(over: Partial<{ section: Section; snapshotTs: number; seq: number; tenantId: string; deviceId: string; asOf: string; content: CanonicalValue }> = {}) {
    const aad = makeAad({
      tenantId: over.tenantId ?? TENANT,
      deviceId: over.deviceId ?? DEVICE,
      companyGuid: 'guid-acme',
      section: over.section ?? 'group_balance',
      asOf: over.asOf ?? '2026-07-16',
      snapshotTs: over.snapshotTs ?? NOW,
      seq: over.seq ?? 1,
    });
    const env = await sealSection(
      over.content ?? { rows: [{ g: 'Cash', amt: '100.00' }] },
      aad,
      identity.publicKey,
      device.secretKey,
    );
    const body = new TextEncoder().encode(JSON.stringify(env));
    const headers = await signRequest(
      { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: clock },
      device.secretKey,
    );
    return { env, body, headers };
  }

  /**
   * Re-sign the SAME body with a fresh nonce, which is exactly what a stolen key floods with:
   * every request is genuinely signed and genuinely distinct, so every one of them reaches
   * `rememberNonce` and buys a row. Cheap on purpose — one seal, N signatures — so the flood in
   * the amplification test can be large enough to be a flood.
   */
  async function resign(body: Uint8Array) {
    return signRequest(
      { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: clock },
      device.secretKey,
    );
  }

  return {
    deps,
    identity,
    device,
    makeUpload,
    resign,
    nonces,
    calls,
    setUploadCount: (n: number) => {
      uploadCount = n;
    },
    setTenantBytes: (n: number) => {
      tenantBytes = n;
    },
    advance: (ms: number) => {
      clock += ms;
    },
    stored,
  };
}

test('a well-formed signed upload is accepted', async () => {
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const res = await handleIngest(headers, body, f.deps);
  assert.equal(res.status, 200);
  assert.equal(f.stored.size, 1);
});

test('THE SERVER NEVER SEES PLAINTEXT — even on a fully successful ingest', async () => {
  // The product's central claim, asserted at the boundary the data actually crosses.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const asText = new TextDecoder().decode(body);
  assert.ok(!asText.includes('Cash'));
  assert.ok(!asText.includes('100.00'));
  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);
});

test('an unsigned request is rejected', async () => {
  const f = await fixture();
  const { body } = await f.makeUpload();
  const res = await handleIngest({}, body, f.deps);
  assert.equal(res.status, 401);
});

test('a replayed upload is rejected', async () => {
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);
  const res = await handleIngest(headers, body, f.deps);
  assert.equal(res.status, 409);
  assert.match(res.body.ok ? '' : res.body.error, /replay/);
});

test('a revoked device gets 403', async () => {
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const revoked = { ...f.deps, lookupDevice: async () => ({ publicKey: f.device.publicKey, revoked: true }) };
  assert.equal((await handleIngest(headers, body, revoked)).status, 403);
});

test('THE FRESHNESS CHECK: an older snapshot cannot roll the dashboard back', async () => {
  // AEAD gives integrity, not freshness. Last quarter's envelope is perfectly authentic — every
  // signature and every tag still verifies. Without this check, a malicious operator or anyone
  // who captured an old upload could restore stale numbers and the owner would see them under a
  // green checkmark and believe them.
  const f = await fixture();
  const current = await f.makeUpload({ snapshotTs: NOW, seq: 2 });
  assert.equal((await handleIngest(current.headers, current.body, f.deps)).status, 200);

  const old = await f.makeUpload({ snapshotTs: NOW - 90 * 86_400_000, seq: 1 });
  const res = await handleIngest(old.headers, old.body, f.deps);
  assert.equal(res.status, 409);
  assert.match(res.body.ok ? '' : res.body.error, /stale/);
});

test('CROSS-TENANT WRITE: a device cannot write into another tenant', async () => {
  // The AAD is authenticated — but only against the key the DEVICE holds, so it is the device's
  // claim, not a fact this server can take on trust. Without the cross-check, device A simply
  // asserts tenantId: B and lands data in someone else's books.
  const f = await fixture();
  const { body, headers } = await f.makeUpload({ tenantId: 'tnt_victim' });
  const res = await handleIngest(headers, body, f.deps);
  assert.equal(res.status, 403);
  assert.match(res.body.ok ? '' : res.body.error, /tenant/);
});

test('IMPERSONATION: the envelope device must match the signer', async () => {
  const f = await fixture();
  const { body, headers } = await f.makeUpload({ deviceId: 'dev_other' });
  const res = await handleIngest(headers, body, f.deps);
  assert.equal(res.status, 403);
  assert.match(res.body.ok ? '' : res.body.error, /device/);
});

test('an oversized body is rejected before it is parsed', async () => {
  const f = await fixture();
  const huge = new Uint8Array(2 * 1024 * 1024);
  const res = await handleIngest({}, huge, f.deps);
  assert.equal(res.status, 413, 'and without reaching the JSON parser');
});

test('rate limiting protects the client’s own Neon bill', async () => {
  // A stolen device key otherwise runs up an overage on a small business's card, with no
  // refund path.
  const f = await fixture();
  f.setUploadCount(60);
  const { body, headers } = await f.makeUpload();
  assert.equal((await handleIngest(headers, body, f.deps)).status, 429);
});

test('the tenant storage quota is enforced', async () => {
  const f = await fixture();
  f.setTenantBytes(600 * 1024 * 1024);
  const { body, headers } = await f.makeUpload();
  assert.equal((await handleIngest(headers, body, f.deps)).status, 507);
});

test('malformed JSON is a 400, not a crash', async () => {
  const f = await fixture();
  const body = new TextEncoder().encode('{not json');
  const headers = await signRequest(
    { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: NOW },
    f.device.secretKey,
  );
  assert.equal((await handleIngest(headers, body, f.deps)).status, 400);
});

test('structural garbage is rejected field by field', async () => {
  const f = await fixture();
  const cases: Array<[string, unknown]> = [
    ['not an object', 42],
    ['missing aad', { nonce: 'x', sealedCek: 'x', ciphertext: 'x', contentHash: 'x' }],
    ['unknown section', { aad: { v: 1, tenantId: TENANT, deviceId: DEVICE, companyGuid: 'g', section: 'evil', asOf: '2026-07-16', snapshotTs: NOW, seq: 1, schemaVer: 1 }, nonce: 'x', sealedCek: 'x', ciphertext: 'x', contentHash: 'x' }],
    ['bad asOf', { aad: { v: 1, tenantId: TENANT, deviceId: DEVICE, companyGuid: 'g', section: 'group_balance', asOf: 'yesterday', snapshotTs: NOW, seq: 1, schemaVer: 1 }, nonce: 'x', sealedCek: 'x', ciphertext: 'x', contentHash: 'x' }],
    ['future envelope version', { aad: { v: 99, tenantId: TENANT, deviceId: DEVICE, companyGuid: 'g', section: 'group_balance', asOf: '2026-07-16', snapshotTs: NOW, seq: 1, schemaVer: 1 }, nonce: 'x', sealedCek: 'x', ciphertext: 'x', contentHash: 'x' }],
  ];

  for (const [label, payload] of cases) {
    const body = new TextEncoder().encode(JSON.stringify(payload));
    const headers = await signRequest(
      { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: NOW },
      f.device.secretKey,
    );
    const res = await handleIngest(headers, body, f.deps);
    assert.equal(res.status, 400, `${label} must be a 400`);
  }
});

test('a wrong clock gets an actionable message, not "unauthorized"', async () => {
  // SMB PCs frequently have wrong clocks. This is the difference between a support call that
  // resolves in one sentence and one that doesn't resolve.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  f.advance(600_000);
  const res = await handleIngest(headers, body, f.deps);
  assert.equal(res.status, 401);
  assert.match(res.body.ok ? '' : res.body.error, /clock/);
});

test('unknown device and bad signature are indistinguishable to the caller', async () => {
  // Distinguishing them enumerates valid device IDs.
  const f = await fixture();
  const { body } = await f.makeUpload();
  const other = await generateDeviceKeypair('dev_ghost');
  const ghost = await signRequest(
    { deviceId: 'dev_ghost', method: 'POST', path: '/api/sync', body, timestamp: NOW },
    other.secretKey,
  );
  const forged = await signRequest(
    { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: NOW },
    other.secretKey,
  );
  const a = await handleIngest(ghost, body, f.deps);
  const b = await handleIngest(forged as SignedHeaders, body, f.deps);
  assert.equal(a.status, b.status);
  assert.deepEqual(a.body, b.body);
});

/* ------------------------------------------------------------------ *
 * Adversarial audit
 * ------------------------------------------------------------------ */

test('POISONED SLOT: a far-future snapshotTs must not brick a slot forever', async () => {
  // The freshness check has a floor (reject older than newest) but needs a CEILING too.
  // Without one, a device with a stolen key uploads snapshotTs = year 275760 ONCE, and every
  // honest upload for that (tenant, company, section, as_of) is 409 "stale" from then on.
  //
  // This outlives the attacker: revoking the device stops new writes but does NOT remove the
  // poisoned row, and there is no path — re-sync included — that lands a lower snapshotTs. The
  // slot is dead for the life of the deployment. A cap costs one comparison and is consistent
  // with the request-timestamp window already enforced on every upload.
  const f = await fixture();

  const poison = await f.makeUpload({ snapshotTs: Number.MAX_SAFE_INTEGER, seq: 1 });
  const res = await handleIngest(poison.headers, poison.body, f.deps);
  assert.equal(res.status, 400, 'a snapshot from the year 275760 is not a snapshot');

  // And the honest Bridge must still be able to write.
  f.advance(1000);
  const honest = await f.makeUpload({ snapshotTs: NOW + 500, seq: 2 });
  assert.equal((await handleIngest(honest.headers, honest.body, f.deps)).status, 200);
});

test('a snapshotTs beyond the clock-skew window is rejected, at the boundary', async () => {
  const f = await fixture();
  const justInside = await f.makeUpload({ snapshotTs: NOW + MAX_CLOCK_SKEW_MS });
  assert.equal((await handleIngest(justInside.headers, justInside.body, f.deps)).status, 200);

  f.advance(1);
  const justOutside = await f.makeUpload({ snapshotTs: NOW + MAX_CLOCK_SKEW_MS + 5000 });
  assert.equal((await handleIngest(justOutside.headers, justOutside.body, f.deps)).status, 400);
});

test('snapshotTs and seq must be safe non-negative integers, not merely finite', async () => {
  // Number.isFinite admits 1.5, -1, and 2^53+1. All three reach a BIGINT column: the fractional
  // and negative ones are nonsense the freshness check then reasons about, and any of them can
  // turn a correctly signed upload into a 500 raised from inside the driver.
  //
  // The envelopes here are hand-built rather than produced by sealSection, and that is the
  // point: the canonical serializer refuses to hash a fractional number, so an HONEST Bridge
  // cannot construct these. An attacker holding a stolen device key does not call sealSection —
  // it POSTs JSON. validateEnvelope is the only thing standing here, so it is what gets tested.
  const f = await fixture();
  const aadOf = (over: Record<string, unknown>) => ({
    v: 1,
    tenantId: TENANT,
    deviceId: DEVICE,
    companyGuid: 'guid-acme',
    section: 'group_balance',
    asOf: '2026-07-16',
    snapshotTs: NOW,
    seq: 1,
    schemaVer: 1,
    ...over,
  });

  const cases: Array<[string, Record<string, unknown>]> = [
    ['fractional snapshotTs', { snapshotTs: NOW + 0.5 }],
    ['negative snapshotTs', { snapshotTs: -1 }],
    ['snapshotTs beyond 2^53', { snapshotTs: Number.MAX_SAFE_INTEGER + 2 }],
    ['fractional seq', { seq: 1.5 }],
    ['negative seq', { seq: -5 }],
    ['NaN-ish seq', { seq: null }],
    ['oversized companyGuid', { companyGuid: 'g'.repeat(5000) }],
    ['empty companyGuid', { companyGuid: '' }],
  ];

  for (const [label, over] of cases) {
    const payload = {
      aad: aadOf(over),
      nonce: 'x',
      sealedCek: 'x',
      ciphertext: 'x',
      contentHash: 'x',
    };
    const body = new TextEncoder().encode(JSON.stringify(payload));
    const headers = await signRequest(
      { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: NOW },
      f.device.secretKey,
    );
    assert.equal((await handleIngest(headers, body, f.deps)).status, 400, label);
    assert.equal(f.stored.size, 0, `${label} must not reach the database`);
  }
});

test('IDEMPOTENT MEANS IDENTICAL: an equal snapshotTs may not overwrite different content', async () => {
  // ingest.ts accepts an equal snapshot_ts and calls it "an idempotent retry — the upsert makes
  // it a no-op". That is true only when the content is the same. The upsert keys on
  // (tenant, company, section, as_of) and REPLACES the envelope, so an equal-ts upload carrying
  // different content silently swaps the stored blob while the freshness check reports nothing
  // moved. A genuine retry after a lost ACK re-sends the same bytes and so the same
  // contentHash; anything else is not a retry and must not be waved through on the retry path.
  const f = await fixture();
  const real = await f.makeUpload({ snapshotTs: NOW, content: { rows: [{ g: 'Cash', amt: '100.00' }] } });
  assert.equal((await handleIngest(real.headers, real.body, f.deps)).status, 200);
  const key = `${TENANT}|guid-acme|group_balance|2026-07-16`;
  const original = f.stored.get(key)!.contentHash;

  f.advance(1000);
  const swap = await f.makeUpload({ snapshotTs: NOW, content: { rows: [{ g: 'Cash', amt: '0.00' }] } });
  const res = await handleIngest(swap.headers, swap.body, f.deps);

  assert.equal(res.status, 409, 'different content at the same snapshotTs is a conflict, not a retry');
  assert.equal(f.stored.get(key)!.contentHash, original, 'the stored envelope was overwritten');
});

test('a true idempotent retry — identical bytes, fresh nonce — is still accepted', async () => {
  // The mirror of the test above: tightening the rule must not break the lost-ACK path it
  // exists to serve, or the Bridge goes into pointless backoff.
  const f = await fixture();
  const a = await f.makeUpload({ snapshotTs: NOW });
  assert.equal((await handleIngest(a.headers, a.body, f.deps)).status, 200);

  f.advance(1000);
  const b = await f.makeUpload({ snapshotTs: NOW }); // same content, fresh nonce
  assert.equal((await handleIngest(b.headers, b.body, f.deps)).status, 200);
  assert.equal(f.stored.size, 1, 'upsert, not duplicate');
});

test('QUOTA RACE: concurrent uploads cannot exceed the hourly cap', async () => {
  // The cap protects the client's own Neon bill from a stolen device key, and a cap a caller can
  // step around by opening twenty sockets is not a cap. Read-then-check-then-write is a TOCTOU:
  // every in-flight request observes the same count, every one of them passes.
  //
  // NOTE ON THE FIXTURE: the counter dep here yields to the event loop before answering. That is
  // not a trick to manufacture a failure — it is the only faithful model. In production this dep
  // is one HTTP POST to Neon, and a stub that answers in the same microtask drain closes the
  // window by accident and would let this bug ship green.
  //
  // This test covers the HANDLER's half of the contract: given a reservation that counts
  // correctly, handleIngest admits exactly the cap. It says nothing about whether the real
  // reservation counts correctly under concurrency — that is a property of the SQL, and it is
  // proved separately against a fake that models row locking and snapshot isolation. See
  // test/db.test.ts, and schema.sql for why an append-only upload log cannot carry this cap.
  const f = await fixture({ slowDb: true });
  f.setUploadCount(59); // one slot left

  const uploads = await Promise.all(
    Array.from({ length: 20 }, (_, i) => f.makeUpload({ seq: i + 1, snapshotTs: NOW - i })),
  );
  const results = await Promise.all(uploads.map((u) => handleIngest(u.headers, u.body, f.deps)));

  const accepted = results.filter((r) => r.status === 200).length;
  assert.equal(accepted, 1, `the 60th upload is the last one; ${accepted} got through`);
  assert.equal(results.filter((r) => r.status === 429).length, 19);
});

// ------------------------------------------- audit: the nonce write amplification, at INGEST

test('THE AMPLIFICATION IS CLOSED: N signed requests over the cap buy CAP nonce rows, not N', async () => {
  // THE BUG, stated at the level it actually shipped at. `verifyRequest` writes a seen_nonce row
  // the instant a signature verifies, and handleIngest only reached its rate limiter AFTERWARDS.
  // So a stolen device key could take 429 after 429 and still buy one PERMANENT row per request,
  // at full request rate. The cap bounded uploads and did not bound the table — and the table is
  // billed to the CLIENT'S OWN Neon account, which is the exact loss the cap exists to prevent
  // and which the customer cannot undo.
  //
  // protocol proved `admit` closes it in isolation. That proof is worth nothing until a caller
  // passes admit, and until this test existed, none did. THIS is the test that would have caught
  // the hole shipping: it exercises the real handler with the deps a real deployment builds.
  //
  // The fixture is slowDb, and that is not decoration. Every dep here costs a modelled round
  // trip, because in production each one is an HTTP POST to Neon; a stub that answers in the
  // same microtask drain closes the window BY ACCIDENT and proves nothing about the real thing.
  const f = await fixture({ slowDb: true });
  const N = 200; // well over the 60/hr cap
  const { body } = await f.makeUpload();
  const flood = await Promise.all(Array.from({ length: N }, () => f.resign(body)));

  const results = await Promise.all(flood.map((h) => handleIngest(h, body, f.deps)));

  // Every request was genuinely signed and carried a distinct, never-seen nonce. Before the fix
  // that is N rows, forever. The cap is now the ceiling on the TABLE, not merely on uploads.
  assert.equal(
    f.nonces.size,
    MAX_UPLOADS_PER_HOUR_PER_DEVICE,
    `seen_nonce must be bounded by the cap (${MAX_UPLOADS_PER_HOUR_PER_DEVICE}), not by the flood (${N})`,
  );
  assert.ok(f.nonces.size < N, 'the write amplification is gone, not merely reduced');

  // And the rejections are real: the flood was refused, it did not just go unrecorded.
  assert.equal(results.filter((r) => r.status === 200).length, MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  assert.equal(results.filter((r) => r.status === 429).length, N - MAX_UPLOADS_PER_HOUR_PER_DEVICE);
});

test('THE ORDER IS THE FIX: the reservation runs BEFORE the nonce row, on every request', async () => {
  // The amplification test above is a count, and a count can be satisfied by luck. This is the
  // mechanism: for a REFUSED request the nonce write must never happen at all, and for an
  // ACCEPTED one the reservation must still come first — otherwise the limit is running after
  // the write it exists to prevent, which is not a limit.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();

  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);
  assert.deepEqual(
    f.calls,
    ['reserveUpload', 'rememberNonce'],
    'an accepted request reserves first, then spends its row',
  );

  f.calls.length = 0;
  f.setUploadCount(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const over = await f.resign(body);
  assert.equal((await handleIngest(over, body, f.deps)).status, 429);
  assert.deepEqual(f.calls, ['reserveUpload'], 'a refused request must never reach rememberNonce');
});

test('admit runs only AFTER the signature — a keyless attacker cannot burn a device’s budget', async () => {
  // The other half of the ordering, and the reason admit is not simply hoisted to the top of the
  // handler. A gate that ran before the signature check would let anyone with NO KEY AT ALL spend
  // a real device's hourly budget by posting garbage — trading a bill DoS for an availability
  // DoS, at a lower cost to the attacker. Nothing unauthenticated may reach the reservation.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const forged = { ...headers, 'x-tb-signature': Buffer.alloc(64).toString('base64') };

  assert.equal((await handleIngest(forged as SignedHeaders, body, f.deps)).status, 401);
  assert.deepEqual(f.calls, [], 'an unsigned request must cost the device nothing at all');
  assert.equal(f.nonces.size, 0);

  assert.equal((await handleIngest({}, body, f.deps)).status, 401);
  assert.deepEqual(f.calls, [], 'nor may a request with no headers at all');
});

test('REPLAY PROTECTION STILL HOLDS: a genuine replay is still refused, and costs one row', async () => {
  // The thing that must not be traded away for the fix. admit sits BEFORE rememberNonce, so the
  // question is whether moving the limit earlier let anything skip the nonce. It did not:
  // rememberNonce remains the last gate before a 200, and no path reaches storeSnapshot without
  // passing it.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();

  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);
  assert.equal(f.nonces.size, 1);

  // Byte-identical re-send: same signature, same nonce, still inside the skew window.
  const replay = await handleIngest(headers, body, f.deps);
  assert.equal(replay.status, 409, 'the ±300s skew window must not become a 5-minute replay window');
  assert.match(replay.body.ok ? '' : replay.body.error, /replay/);
  assert.equal(f.nonces.size, 1, 'a replay consumes no NEW row — it collides with the old one');
});

test('a request refused by the gate consumes no nonce, so nothing was consumed to replay', async () => {
  // Why rejecting at admit does not open a replay hole, stated as the property rather than the
  // hope: a refused request never reached rememberNonce, so it never took effect and there is no
  // state for anyone to replay. Its nonce is untouched — and that is correct, not a leak: the
  // request it belongs to did nothing.
  const f = await fixture();
  const { body } = await f.makeUpload();
  f.setUploadCount(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const headers = await f.resign(body);

  assert.equal((await handleIngest(headers, body, f.deps)).status, 429);
  assert.equal(f.nonces.size, 0, 'a rate-limited request must not cost a nonce row');

  // The same nonce is still spendable once the budget frees up, because it was never spent. The
  // request is being accepted on its own merits for the first time, not replayed.
  f.setUploadCount(0);
  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);
  assert.equal(f.nonces.size, 1);
  // ...and only once. Replay protection resumes from there.
  assert.equal((await handleIngest(headers, body, f.deps)).status, 409);
});

test('A REPLAY IS METERED: an authenticated flood cannot get an unmetered channel by re-sending', async () => {
  // A consequence of the fix that is worth pinning rather than discovering. The reservation now
  // runs before the nonce is checked, so a replayed request spends rate budget where it used to
  // 409 for free. That is REQUIRED, not incidental: "is this a replay?" cannot be answered
  // without writing the nonce, which is the very write being gated. An unmetered 409 channel
  // would hand a stolen key back the flood this fix removes.
  //
  // It costs an honest Bridge nothing: a retry after a lost ACK re-signs with a FRESH nonce (see
  // the idempotent-retry test above), so it is never on this path.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  assert.equal((await handleIngest(headers, body, f.deps)).status, 200);

  f.calls.length = 0;
  assert.equal((await handleIngest(headers, body, f.deps)).status, 409);
  assert.ok(f.calls.includes('reserveUpload'), 'a replay is charged to the budget it arrived on');
});

// ------------------------------------------- audit: the failure-kind -> status mapping

test('not_admitted IS 429, NOT 401 — a rate limit is not an auth failure', async () => {
  // THE BUG: the switch on `auth.failure.kind` had a `default:` that mapped everything it did not
  // recognise to 401. When protocol added `not_admitted`, the default silently swallowed it and a
  // RATE LIMIT was reported as an AUTH FAILURE. That is not cosmetic: 401 tells an operator to go
  // re-enrol a device that is working perfectly, and it buries the one signal that says "your key
  // is being flooded and your Neon bill is the target".
  const f = await fixture();
  f.setUploadCount(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const { body, headers } = await f.makeUpload();

  const res = await handleIngest(headers, body, f.deps);
  assert.notEqual(res.status, 401, 'the signature was genuine — that is why the gate ran at all');
  assert.equal(res.status, 429);
  assert.equal(res.body.ok ? '' : res.body.error, 'rate_limited');
});

test('the gate does not flatten three distinct answers into one status', async () => {
  // The risk in moving the quota check inside `admit`: admit can only answer yes/no with a
  // string, so it would be easy to collapse every refusal into 429. These are different facts
  // about the request and the Bridge's outbox reads them differently.
  const rate = await fixture();
  rate.setUploadCount(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const a = await rate.makeUpload();
  assert.equal((await handleIngest(a.headers, a.body, rate.deps)).status, 429);

  const full = await fixture();
  full.setTenantBytes(600 * 1024 * 1024);
  const b = await full.makeUpload();
  assert.equal((await handleIngest(b.headers, b.body, full.deps)).status, 507, 'tenant full is 507');
  assert.equal(full.nonces.size, 0, 'and an over-quota tenant still buys no row');
});

test('NaN FAILS CLOSED: an unreadable count is a 400 and costs no nonce, not a free pass', async () => {
  // Every comparison with NaN is false, so a `>=` chain does not REJECT a NaN, it SKIPS — and the
  // count reaching the cap comes from `reserveUpload`, i.e. from a bigint the driver may hand back
  // as anything. `checkQuota` refuses it as `unmeasurable`; the point of this test is that the
  // refusal survives the trip through `admit` and that the request still buys nothing. A quota
  // that fails open costs the customer real money.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const blind: IngestDeps = { ...f.deps, reserveUpload: async () => Number.NaN };

  const res = await handleIngest(headers, body, blind);
  assert.equal(res.status, 400, 'an unmeasurable request is refused, not admitted');
  assert.equal(res.body.ok ? '' : res.body.error, 'unmeasurable');
  assert.equal(f.nonces.size, 0, 'and it does not get to write a row on the way out');
  assert.equal(f.stored.size, 0);
});

test('an unusable clock is still a 401, and still writes nothing', async () => {
  // `unusable_clock` maps to 401 and that is correct — an unmeasurable skew is an unverifiable
  // request. Pinned because the switch that decides it was just rewritten: NaN must not walk
  // through the skew check, and the request must not reach the gate or the nonce table.
  const f = await fixture();
  const { body, headers } = await f.makeUpload();
  const broken: IngestDeps = { ...f.deps, now: () => Number.NaN };

  assert.equal((await handleIngest(headers, body, broken)).status, 401);
  assert.deepEqual(f.calls, [], 'an unverifiable request costs nothing');
  assert.equal(f.nonces.size, 0);
});

// ---------------------------------------------------------------- registration

function registerDeps(over: Partial<Parameters<typeof handleRegister>[1]> = {}) {
  let consumed = false;
  const registered: string[] = [];
  return {
    registered,
    deps: {
      bootstrapConsumed: async () => consumed,
      bootstrapAgeMs: async () => 0,
      expectedSecret: 'the-secret',
      registerDevice: async (id: string) => {
        registered.push(id);
      },
      consumeBootstrap: async () => {
        if (consumed) return false;
        consumed = true;
        return true;
      },
      ...over,
    },
  };
}

test('the first device registers with the bootstrap secret', async () => {
  const { deps, registered } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const res = await handleRegister(
    { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: Buffer.from(kp.publicKey).toString('base64') },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 200);
  assert.deepEqual(registered, [DEVICE]);
});

test('THE ONE-SHOT RULE: registration closes after the first success', async () => {
  // This is the only door that opens without a device key. Left open, anyone who ever learns
  // BOOTSTRAP_SECRET — from a log, a screenshot, a support ticket — can enrol a device forever.
  const { deps } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const body = { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: Buffer.from(kp.publicKey).toString('base64') };

  assert.equal((await handleRegister(body, deps, bootstrapSecretMatches)).status, 200);
  const second = await handleRegister({ ...body, deviceId: 'dev_2' }, deps, bootstrapSecretMatches);
  assert.equal(second.status, 403);
});

test('registration expires after 24h even if never used', async () => {
  const { deps } = registerDeps({ bootstrapAgeMs: async () => BOOTSTRAP_TTL_MS + 1 });
  const kp = await generateDeviceKeypair(DEVICE);
  const res = await handleRegister(
    { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: Buffer.from(kp.publicKey).toString('base64') },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 403);
});

test('a wrong bootstrap secret does not consume the one shot', async () => {
  // Otherwise a single wrong guess permanently bricks onboarding.
  const { deps } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');

  assert.equal(
    (await handleRegister({ secret: 'wrong', deviceId: DEVICE, tenantId: TENANT, publicKey: pk }, deps, bootstrapSecretMatches)).status,
    403,
  );
  assert.equal(
    (await handleRegister({ secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: pk }, deps, bootstrapSecretMatches)).status,
    200,
    'the real secret must still work afterwards',
  );
});

test('an unconfigured secret fails closed', async () => {
  // "No secret set" must never read as "no secret required".
  const { deps } = registerDeps({ expectedSecret: undefined });
  const kp = await generateDeviceKeypair(DEVICE);
  const res = await handleRegister(
    { secret: 'anything', deviceId: DEVICE, tenantId: TENANT, publicKey: Buffer.from(kp.publicKey).toString('base64') },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 403);
});

test('a bad public key is rejected', async () => {
  const { deps } = registerDeps();
  const res = await handleRegister(
    { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: Buffer.from('short').toString('base64') },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 400);
});

test('TYPE CONFUSION: a JSON array is not a base64 public key', async () => {
  // Buffer.from(value, 'base64') ignores the encoding argument entirely when value is an array,
  // so `publicKey: [1,2,...,32]` yields a 32-byte Buffer, passes the length check, and enrols a
  // key that was never base64 — on the one endpoint with no device key behind it.
  const { deps, registered } = registerDeps();
  const res = await handleRegister(
    {
      secret: 'the-secret',
      deviceId: DEVICE,
      tenantId: TENANT,
      publicKey: Array.from({ length: 32 }, (_, i) => i),
    },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 400);
  assert.deepEqual(registered, [], 'nothing may be enrolled from a non-string key');
});

test('a public key that is not strict base64 is rejected, not silently mangled', async () => {
  // Buffer.from never throws on garbage — it drops the characters it does not recognise. A
  // "key" that decodes to 32 bytes by luck would be enrolled in place of the one the device
  // actually holds, and that device could then never sign a request that verifies. The one-shot
  // bootstrap is already spent by then: the deployment is bricked with no way back.
  const { deps, registered } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const real = Buffer.from(kp.publicKey).toString('base64');
  const mangled = `${real.slice(0, 20)}!!!!${real.slice(20)}`; // still decodes to 32 bytes

  assert.equal(Buffer.from(mangled, 'base64').length, 32, 'precondition: it decodes cleanly');

  const res = await handleRegister(
    { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: mangled },
    deps,
    bootstrapSecretMatches,
  );
  assert.equal(res.status, 400);
  assert.deepEqual(registered, []);
});

test('non-string identity fields are rejected before they become the tenant', async () => {
  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');

  const cases: Array<[string, Record<string, unknown>]> = [
    ['object tenantId', { tenantId: { evil: true } }],
    ['array deviceId', { deviceId: ['a'] }],
    ['numeric tenantId', { tenantId: 7 }],
    ['oversized tenantId', { tenantId: 'x'.repeat(5000) }],
    ['oversized label', { label: 'x'.repeat(5000) }],
  ];

  for (const [name, over] of cases) {
    const { deps, registered } = registerDeps();
    const res = await handleRegister(
      { secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: pk, ...over },
      deps,
      bootstrapSecretMatches,
    );
    assert.equal(res.status, 400, name);
    assert.deepEqual(registered, [], name);
  }
});

test('CONCURRENT REGISTRATION: two racing registrations, exactly one wins', async () => {
  // The one door that opens without a device key. Two requests arriving in the same second on
  // two cold instances both pass the `bootstrapConsumed` pre-check — that read is not the
  // gate, and cannot be. `consumeBootstrap` is the gate: it must be a conditional UPDATE that
  // reports whether it won, and the handler must bail on a loss BEFORE registering.
  let consumed = false;
  const registered: string[] = [];
  const deps = {
    bootstrapConsumed: async () => {
      await new Promise((r) => setTimeout(r, 1)); // a real read is a round trip
      return consumed;
    },
    bootstrapAgeMs: async () => 0,
    expectedSecret: 'the-secret',
    registerDevice: async (id: string) => {
      registered.push(id);
    },
    // The atomic conditional UPDATE, modelled: tested and set with no await between them.
    consumeBootstrap: async () => {
      if (consumed) return false;
      consumed = true;
      return true;
    },
  };

  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      handleRegister(
        { secret: 'the-secret', deviceId: `dev_${i}`, tenantId: TENANT, publicKey: pk },
        deps,
        bootstrapSecretMatches,
      ),
    ),
  );

  assert.equal(results.filter((r) => r.status === 200).length, 1, 'exactly one enrolment');
  assert.equal(registered.length, 1, 'a loser must not reach registerDevice');
});

test('a wrong secret cannot burn the one shot — onboarding DoS', async () => {
  // If the secret check ran after the consume, one wrong guess from anyone who can reach the
  // URL would permanently brick onboarding for a customer mid-setup.
  const { deps, registered } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');

  for (let i = 0; i < 25; i++) {
    const res = await handleRegister(
      { secret: `guess-${i}`, deviceId: DEVICE, tenantId: TENANT, publicKey: pk },
      deps,
      bootstrapSecretMatches,
    );
    assert.equal(res.status, 403);
  }

  assert.equal(
    (await handleRegister({ secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: pk }, deps, bootstrapSecretMatches)).status,
    200,
    '25 wrong guesses must not spend the shot',
  );
  assert.deepEqual(registered, [DEVICE]);
});

test('a malformed body cannot burn the one shot either', async () => {
  // The same DoS one layer out: a garbage publicKey must be rejected without consuming.
  const { deps } = registerDeps();
  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');

  assert.equal(
    (await handleRegister({ secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: 'nope' }, deps, bootstrapSecretMatches)).status,
    400,
  );
  assert.equal(
    (await handleRegister({ secret: 'the-secret', deviceId: DEVICE, tenantId: TENANT, publicKey: pk }, deps, bootstrapSecretMatches)).status,
    200,
  );
});
