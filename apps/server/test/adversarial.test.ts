/**
 * ADVERSARIAL CHECK of the `admit` seat. Written from scratch — deliberately does NOT reuse the
 * fixture in ingest.test.ts, because the question under test includes "is that fixture honest?".
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, makeAad, sealSection } from '@tally-bridge/crypto';
import {
  MAX_UPLOADS_PER_HOUR_PER_DEVICE,
  generateDeviceKeypair,
  signRequest,
  type SignedHeaders,
} from '@tally-bridge/protocol';
import { handleIngest, type IngestDeps } from '../src/ingest.ts';

const NOW = 1_752_600_000_000;
const TENANT = 'tnt_x';
const DEVICE = 'dev_x';

/** A REAL round trip: a macrotask hop, so a concurrent request genuinely interleaves here. */
const hop = () => new Promise((r) => setTimeout(r, 1));

/**
 * @param atomicReserve when false, reserveUpload reads, HOPS, then writes — the TOCTOU shape the
 *   dep contract forbids. Used to prove our own race test can actually fail.
 */
async function rig({ atomicReserve = true }: { atomicReserve?: boolean } = {}) {
  const identity = await generateIdentity();
  const device = await generateDeviceKeypair(DEVICE);

  const nonceRows = new Set<string>();
  const calls: string[] = [];
  const stored = new Map<string, unknown>();
  let uploads = 0;
  let tenantBytes = 0;
  let clock = NOW;

  const deps: IngestDeps = {
    lookupDevice: async (id) => {
      await hop();
      return id === DEVICE ? { publicKey: device.publicKey, revoked: false } : undefined;
    },
    rememberNonce: async (d, n) => {
      calls.push('rememberNonce');
      await hop();
      const k = `${d}|${n}`;
      if (nonceRows.has(k)) return false;
      nonceRows.add(k);
      return true;
    },
    now: () => clock,
    tenantIdForDevice: async (id) => {
      await hop();
      return id === DEVICE ? TENANT : undefined;
    },
    latestSnapshot: async () => {
      await hop();
      return undefined;
    },
    reserveUpload: async (_d, bytes) => {
      calls.push('reserveUpload');
      await hop();
      if (atomicReserve) {
        tenantBytes += bytes;
        return ++uploads;
      }
      // TOCTOU shape: read, round trip, write. The gap is wide (and not a 1ms timer) so the
      // interleaving is DETERMINISTIC rather than a race against the timer queue — this dep is
      // the control for the whole file and a flaky control proves nothing either way.
      const seen = uploads;
      await new Promise((r) => setTimeout(r, 50));
      uploads = seen + 1;
      tenantBytes += bytes;
      return uploads;
    },
    tenantBytesStored: async () => {
      await hop();
      return tenantBytes;
    },
    storeSnapshot: async (row) => {
      await hop();
      stored.set(`${row.tenantId}|${row.companyGuid}|${row.section}|${row.asOf}`, row);
    },
    touchDevice: async () => {
      await hop();
    },
  };

  const sealOne = async (seq = 1, snapshotTs = NOW) => {
    const aad = makeAad({
      tenantId: TENANT,
      deviceId: DEVICE,
      companyGuid: 'guid-x',
      section: 'group_balance',
      asOf: '2026-07-16',
      snapshotTs,
      seq,
    });
    const env = await sealSection({ rows: [{ g: 'Cash', amt: '1.00' }] }, aad, identity.publicKey, device.secretKey);
    return new TextEncoder().encode(JSON.stringify(env));
  };

  const sign = (body: Uint8Array) =>
    signRequest({ deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: clock }, device.secretKey);

  return {
    deps,
    sealOne,
    sign,
    nonceRows,
    calls,
    stored,
    setUploads: (n: number) => {
      uploads = n;
    },
    setTenantBytes: (n: number) => {
      tenantBytes = n;
    },
  };
}

// ============================================================ 1. the amplification, my own flood

test('ADV: 500 distinct signed requests from one stolen key buy at most CAP nonce rows', async () => {
  const r = await rig();
  const N = 500;
  const body = await r.sealOne();
  const flood = await Promise.all(Array.from({ length: N }, () => r.sign(body)));
  const results = await Promise.all(flood.map((h) => handleIngest(h, body, r.deps)));

  assert.ok(
    r.nonceRows.size <= MAX_UPLOADS_PER_HOUR_PER_DEVICE,
    `seen_nonce grew to ${r.nonceRows.size}; the cap is ${MAX_UPLOADS_PER_HOUR_PER_DEVICE} and the flood was ${N}`,
  );
  assert.ok(r.nonceRows.size < N / 4, 'bounded by the cap, not by N');
  assert.equal(results.filter((x) => x.status === 200).length, MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  assert.equal(results.filter((x) => x.status === 429).length, N - MAX_UPLOADS_PER_HOUR_PER_DEVICE);
});

// ============================================================ 2. is the harness real?

test('ADV: the rig detects a NON-atomic reservation (proves the hops are load-bearing)', async () => {
  // If this rig were accidentally atomic, a deliberately racy reserveUpload would still pass the
  // cap. It must not. This is the control that makes every other concurrency claim here mean
  // something.
  const r = await rig({ atomicReserve: false });
  r.setUploads(MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1); // one slot left
  const uploads = await Promise.all(
    Array.from({ length: 20 }, async (_, i) => {
      const body = await r.sealOne(i + 1, NOW - i);
      return { body, headers: await r.sign(body) };
    }),
  );
  const results = await Promise.all(uploads.map((u) => handleIngest(u.headers, u.body, r.deps)));
  const accepted = results.filter((x) => x.status === 200).length;
  assert.ok(accepted > 1, `a read-then-write reservation MUST over-admit; got ${accepted}`);
});

test('ADV: with an atomic reservation, 20 concurrent uploads for 1 slot admit exactly 1', async () => {
  const r = await rig();
  r.setUploads(MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1);
  const uploads = await Promise.all(
    Array.from({ length: 20 }, async (_, i) => {
      const body = await r.sealOne(i + 1, NOW - i);
      return { body, headers: await r.sign(body) };
    }),
  );
  const results = await Promise.all(uploads.map((u) => handleIngest(u.headers, u.body, r.deps)));
  assert.equal(results.filter((x) => x.status === 200).length, 1);
});

// ============================================================ 3. replay protection still holds

test('ADV: no path to 200 skips rememberNonce', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  assert.equal((await handleIngest(headers, body, r.deps)).status, 200);
  assert.ok(r.calls.includes('rememberNonce'), 'a 200 must have spent a nonce');
  assert.equal(r.calls.indexOf('reserveUpload') < r.calls.indexOf('rememberNonce'), true);
});

test('ADV: a rememberNonce that always says "seen" can never produce a 200', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const deps: IngestDeps = { ...r.deps, rememberNonce: async () => false };
  const res = await handleIngest(headers, body, deps);
  assert.equal(res.status, 409, 'if the nonce gate says replay, there must be no way to 200');
  assert.equal(r.stored.size, 0);
});

test('ADV: a genuine byte-identical replay is refused and buys no second row', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  assert.equal((await handleIngest(headers, body, r.deps)).status, 200);
  assert.equal(r.nonceRows.size, 1);
  assert.equal((await handleIngest(headers, body, r.deps)).status, 409);
  assert.equal(r.nonceRows.size, 1);
});

test('ADV: 50 CONCURRENT replays of one captured request — exactly one wins', async () => {
  // The race the nonce table exists for. If rememberNonce were a SELECT-then-INSERT this would
  // let many through; the rig hops inside it, so the ordering is genuinely interleaved.
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const results = await Promise.all(Array.from({ length: 50 }, () => handleIngest(headers, body, r.deps)));
  assert.equal(results.filter((x) => x.status === 200).length, 1, 'exactly one of 50 identical requests may win');
  assert.equal(r.nonceRows.size, 1);
});

// ============================================================ 4. ordering vs. the signature

test('ADV: a bad signature costs the victim device ZERO budget and zero rows', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);

  for (const forged of [
    { ...headers, 'x-tb-signature': Buffer.alloc(64).toString('base64') },
    { ...headers, 'x-tb-signature': Buffer.alloc(8).toString('base64') }, // wrong length: libsodium throws
    { ...headers, 'x-tb-nonce': 'tampered-nonce' },
    { ...headers, 'x-tb-timestamp': String(NOW + 1) },
  ]) {
    r.calls.length = 0;
    const res = await handleIngest(forged as SignedHeaders, body, r.deps);
    assert.equal(res.status, 401, `expected 401 for ${JSON.stringify(forged['x-tb-signature']).slice(0, 20)}`);
    assert.deepEqual(r.calls, [], 'an unauthenticated request must never reach reserveUpload');
  }
  assert.equal(r.nonceRows.size, 0);
});

test('ADV: a body swapped under a valid signature costs zero budget', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const other = await r.sealOne(2, NOW - 1);
  const res = await handleIngest(headers, other, r.deps);
  assert.equal(res.status, 401);
  assert.deepEqual(r.calls, []);
});

// ============================================================ 5. NaN / numeric fail-open battery

const HOSTILE: Array<[string, unknown]> = [
  ['NaN', Number.NaN],
  ['Infinity', Number.POSITIVE_INFINITY],
  ['-Infinity', Number.NEGATIVE_INFINITY],
  ['-1', -1],
  ['2^53', 2 ** 53],
  ['null', null],
  ['undefined', undefined],
  ['"abc"', 'abc'],
  ['{}', {}],
  ['[]', []],
];

for (const [label, value] of HOSTILE) {
  test(`ADV: reserveUpload -> ${label} must FAIL CLOSED (no 200, no nonce row)`, async () => {
    const r = await rig();
    const body = await r.sealOne();
    const headers = await r.sign(body);
    const deps: IngestDeps = { ...r.deps, reserveUpload: async () => value as number };
    const res = await handleIngest(headers, body, deps);
    assert.notEqual(res.status, 200, `reserveUpload returning ${label} was ADMITTED — the cap failed open`);
    assert.equal(r.nonceRows.size, 0, `${label} bought a permanent row on the way out`);
    assert.equal(r.stored.size, 0);
  });

  test(`ADV: tenantBytesStored -> ${label} must FAIL CLOSED`, async () => {
    const r = await rig();
    const body = await r.sealOne();
    const headers = await r.sign(body);
    const deps: IngestDeps = { ...r.deps, tenantBytesStored: async () => value as number };
    const res = await handleIngest(headers, body, deps);
    assert.notEqual(res.status, 200, `tenantBytesStored returning ${label} was ADMITTED — the cap failed open`);
    assert.equal(r.nonceRows.size, 0);
  });
}

test('ADV: a fractional count (1.5) must not be treated as a usable count', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const deps: IngestDeps = { ...r.deps, reserveUpload: async () => 1.5 };
  const res = await handleIngest(headers, body, deps);
  assert.notEqual(res.status, 200, 'a fractional upload count is a broken accounting query, not headroom');
});

test('ADV: a bigint-as-string count from the driver must not fail OPEN', async () => {
  // node-postgres hands BIGINT back as a STRING. "60" - 1 === 59 numerically, so this happens to
  // work; "60" >= 60 would ALSO work. The one that must not happen is admission past the cap.
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const deps: IngestDeps = { ...r.deps, reserveUpload: async () => '9999' as unknown as number };
  const res = await handleIngest(headers, body, deps);
  assert.notEqual(res.status, 200, 'a string count over the cap must still be refused');
  assert.equal(r.nonceRows.size, 0);
});

for (const [label, value] of [
  ['NaN', Number.NaN],
  ['Infinity', Number.POSITIVE_INFINITY],
  ['"abc"', 'abc'],
  ['null', null],
  ['undefined', undefined],
] as Array<[string, unknown]>) {
  test(`ADV: a ${label} clock must not SKIP the skew check`, async () => {
    const r = await rig();
    const body = await r.sealOne();
    const headers = await r.sign(body);
    const deps: IngestDeps = { ...r.deps, now: () => value as number };
    const res = await handleIngest(headers, body, deps);
    assert.equal(res.status, 401, `a ${label} clock returned ${res.status} — the skew check was skipped`);
    assert.deepEqual(r.calls, [], 'an unverifiable request must cost nothing');
    assert.equal(r.nonceRows.size, 0);
  });
}

test('ADV: a NaN clock does not let a 10-year-old request through', async () => {
  const r = await rig();
  const body = await r.sealOne();
  // Sign with a timestamp a decade old, then hand the verifier a broken clock.
  const stale = await signRequest(
    { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: NOW - 10 * 365 * 24 * 3600_000 },
    (await generateDeviceKeypair(DEVICE)).secretKey,
  );
  const deps: IngestDeps = { ...r.deps, now: () => Number.NaN };
  assert.equal((await handleIngest(stale, body, deps)).status, 401);
  assert.equal(r.nonceRows.size, 0);
});

// ============================================================ 6. status mapping

test('ADV: each refusal keeps its own status and spends no row', async () => {
  const rate = await rig();
  rate.setUploads(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const b1 = await rate.sealOne();
  const res1 = await handleIngest(await rate.sign(b1), b1, rate.deps);
  assert.equal(res1.status, 429);
  assert.equal(rate.nonceRows.size, 0);

  const full = await rig();
  full.setTenantBytes(600 * 1024 * 1024);
  const b2 = await full.sealOne();
  const res2 = await handleIngest(await full.sign(b2), b2, full.deps);
  assert.equal(res2.status, 507);
  assert.equal(full.nonceRows.size, 0);

  const blind = await rig();
  const b3 = await blind.sealOne();
  const res3 = await handleIngest(await blind.sign(b3), b3, { ...blind.deps, reserveUpload: async () => Number.NaN });
  assert.equal(res3.status, 400);
  assert.equal(blind.nonceRows.size, 0);
});

test('ADV: a device with no tenant is 401 and never reaches the reservation', async () => {
  const r = await rig();
  const body = await r.sealOne();
  const headers = await r.sign(body);
  const deps: IngestDeps = { ...r.deps, tenantIdForDevice: async () => undefined };
  const res = await handleIngest(headers, body, deps);
  assert.equal(res.status, 401);
  assert.ok(!r.calls.includes('reserveUpload'), 'no tenant means no quota to spend');
  assert.equal(r.nonceRows.size, 0);
});

// ============================================================ 7. the admitted behaviour change

test('ADV: REPLAY-METERING DoS — a captured request replayed N times burns an honest budget', async () => {
  // Documents the regression this change introduces. An observer (the compromised SERVER is in
  // this product's threat model — the client hosts it precisely so they need not trust it, and it
  // sees every request) captures ONE signed request and re-sends it. Each replay 409s, but each
  // replay now spends a reservation FIRST. No key required.
  const r = await rig();
  const body = await r.sealOne();
  const captured = await r.sign(body);
  assert.equal((await handleIngest(captured, body, r.deps)).status, 200);

  // The attacker replays the SAME captured request to the cap.
  for (let i = 0; i < MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1; i++) {
    await handleIngest(captured, body, r.deps);
  }
  assert.equal(r.nonceRows.size, 1, 'the bill is protected: replays buy no rows');

  // Now the HONEST device tries a fresh, legitimate upload with a brand-new nonce.
  const fresh = await r.sealOne(2, NOW - 1);
  const honest = await handleIngest(await r.sign(fresh), fresh, r.deps);
  assert.equal(
    honest.status,
    429,
    'CONFIRMED: replaying one captured request exhausts the honest device budget',
  );
});
