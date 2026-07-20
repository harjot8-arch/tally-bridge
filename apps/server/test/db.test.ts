import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, makeAad, sealSection } from '@tally-bridge/crypto';
import {
  MAX_UPLOADS_PER_HOUR_PER_DEVICE,
  bootstrapSecretMatches,
  generateDeviceKeypair,
  signRequest,
} from '@tally-bridge/protocol';
import type { Section } from '@tally-bridge/core';
import {
  RATE_WINDOW_SECONDS,
  ingestDepsFromSql,
  registerDepsFromSql,
  type Row,
  type Sql,
} from '../src/db.ts';
import { handleIngest, handleRegister } from '../src/ingest.ts';

/**
 * THE DATA LAYER'S CONCURRENCY TESTS.
 *
 * Two properties are load-bearing here and neither can be tested against a stub that answers
 * instantly:
 *
 *   1. `consumeBootstrap` admits exactly ONE registration, ever.
 *   2. `reserveUpload` admits exactly the cap, no matter how many sockets ask at once.
 *
 * WHY THE FAKE BELOW IS SHAPED THE WAY IT IS. A previous attempt at these tests passed against a
 * stub that resolved in the same microtask drain — and it passed for a broken implementation,
 * because a dep that answers with no await between the read and the write has closed the TOCTOU
 * window by accident. The test was theatre: it asserted the property while removing the only
 * conditions under which the property can fail.
 *
 * So this fake models the three facts about Neon-over-HTTP and Postgres that these two
 * properties actually rest on, and it models them as PROPERTIES OF POSTGRES rather than as
 * "whatever db.ts happens to do":
 *
 *   ROUND TRIPS. Every query awaits a real timer twice — once for the POST travelling out, once
 *   for the response coming back. Neon's HTTP driver sends each query as an independent POST, so
 *   anything a handler does across two queries has a window this wide in production. `hop()` is
 *   what makes that window exist in the test.
 *
 *   SNAPSHOTS. Under READ COMMITTED a statement's snapshot is taken when the statement STARTS.
 *   An unlocked read therefore CANNOT see a concurrent statement's uncommitted writes, however
 *   long it takes. This is the fact that kills the append-a-row-and-count-them design, and the
 *   fake reproduces it by copying state on arrival.
 *
 *   ROW LOCKS. `INSERT ... ON CONFLICT DO UPDATE` and a conditional `UPDATE` take an exclusive
 *   lock on the contended row, and the waiter RE-READS the newest committed version before
 *   evaluating its SET or its WHERE. This is the only mechanism in the whole file that is exact
 *   under concurrency, and the fake models it by reading live state inside the lock.
 *
 * The harness is proved to have teeth further down ("THE HARNESS CATCHES..."), by running the
 * two designs that are known to be broken through it and watching them fail. A concurrency test
 * that has never failed for a bad implementation has proved nothing.
 *
 * WHAT THIS CANNOT PROVE. It cannot prove Postgres behaves as modelled — there is no live Neon
 * here. It proves the code's shape given those semantics. The semantics themselves come from the
 * documentation and are argued in the comments in db.ts and schema.sql.
 */

const NOW = 1_752_600_000_000;
const TENANT = 'tnt_1';
const DEVICE = 'dev_1';
const MINUTE = 60_000;

/** One network hop. Small enough to keep the suite fast, real enough to yield the event loop. */
const LATENCY_MS = 1;

interface Bucket {
  deviceId: string;
  windowStart: number;
  uploads: number;
  bytes: number;
}

interface SnapshotRow {
  tenantId: string;
  companyGuid: string;
  section: string;
  asOf: string;
  contentHash: string;
  envelope: unknown;
  snapshotTs: number;
  seq: number;
  deviceId: string;
  bytes: number;
}

function fakeNeon(opts: { publicKey?: Uint8Array } = {}) {
  let clock = NOW;

  const devices = new Map<
    string,
    {
      tenantId: string;
      publicKey: Uint8Array;
      label: string;
      revokedAt: number | null;
      lastSeenAt?: number | null;
      lastSeenIp?: string | null;
    }
  >();
  /** key -> expires_at, in millis. The value is what the sweep in `reserveUpload` filters on. */
  const nonces = new Map<string, number>();
  const buckets = new Map<string, Bucket>();
  const snapshots = new Map<string, SnapshotRow>();
  const bootstrap = { consumedAt: null as number | null, createdAt: NOW };

  if (opts.publicKey) {
    devices.set(DEVICE, { tenantId: TENANT, publicKey: opts.publicKey, label: '', revokedAt: null });
  }

  const queries: Array<{ text: string; params: unknown[] }> = [];

  /* -- the three modelled facts ------------------------------------- */

  /** A network hop. THIS is what makes a TOCTOU window exist in the test. */
  const hop = () => new Promise((r) => setTimeout(r, LATENCY_MS));

  /**
   * A READ COMMITTED statement snapshot, taken when the statement starts.
   *
   * Copying the bucket rows is the whole point: a statement that reads from this cannot observe
   * a write another statement commits while it is running, exactly as in Postgres.
   */
  const snapshotOf = (m: Map<string, Bucket>) => new Map([...m].map(([k, v]) => [k, { ...v }]));

  /**
   * Exclusive row locks, with a FIFO queue. Waiters re-read live state when they wake.
   *
   * NOTE THE `await hop()` INSIDE THE LOCKED SECTIONS BELOW. Without it the fake's
   * read-modify-write would be synchronous, and JavaScript would make it atomic for free —
   * the lock would be decorative and this whole file would pass with `withRowLock` deleted.
   * That is the same accident that made the last attempt at these tests theatre, one level
   * down. The hop models the server-side work between reading a row and writing it back, so
   * mutual exclusion is the ONLY thing that makes the result exact. It is verified: removing
   * the lock makes the race tests below fail.
   */
  const locks = new Map<string, Promise<void>>();
  async function withRowLock<T>(key: string, fn: () => T | Promise<T>): Promise<T> {
    const prev = locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => (release = r));
    locks.set(
      key,
      prev.then(() => mine),
    );
    await prev;
    try {
      // `return await`, not `return`. Without the await, `finally` fires the moment `fn` hands
      // back its promise and the lock is released while the holder is still mid-update — which
      // is a lock that type-checks, reads correctly, and serializes nothing.
      return await fn();
    } finally {
      release();
    }
  }

  const bucketStart = (t: number) => Math.floor(t / MINUTE) * MINUTE;

  /* -- the fake driver ---------------------------------------------- */

  const sql: Sql = async (strings, ...params) => {
    const text = strings.join(' $? ').replace(/\s+/g, ' ').trim();
    queries.push({ text, params });

    // The request travels to Neon.
    await hop();
    // The statement arrives and takes its snapshot.
    const snap = snapshotOf(buckets);
    const startedAt = clock;

    const rows = await execute(text, params, snap, startedAt);

    // The response travels back.
    await hop();
    return rows;
  };

  async function execute(
    text: string,
    params: unknown[],
    snap: Map<string, Bucket>,
    startedAt: number,
  ): Promise<Row[]> {
    /* ---- upload_window: the rate-limit reservation ---- */
    if (/INSERT INTO upload_window/i.test(text)) {
      const [gcDevice, retentionSecs, nonceDevice, nonceRetentionSecs, insDevice, bytes, sumDevice, windowSecs] =
        params;
      assert.equal(gcDevice, insDevice, 'the sweep and the upsert must target one device');
      assert.equal(nonceDevice, insDevice, 'the nonce sweep must target the reserving device');
      assert.equal(sumDevice, insDevice, 'the trailing sum must target the reserving device');
      assert.equal(windowSecs, RATE_WINDOW_SECONDS);

      const deviceId = String(insDevice);
      const start = bucketStart(startedAt);
      const key = `${deviceId}|${start}`;

      // gc_buckets: a data-modifying CTE always runs to completion. It must never touch the row
      // the upsert is about — assert that, since db.ts claims it is disjoint BY CONSTRUCTION.
      const cutoff = startedAt - Number(retentionSecs) * 1000;
      for (const [k, b] of [...buckets]) {
        if (b.deviceId === deviceId && b.windowStart < cutoff) {
          assert.notEqual(k, key, 'the sweep deleted the bucket being written');
          buckets.delete(k);
        }
      }

      // gc_nonces: a different table, so there is no interaction with the upsert to model.
      const nonceCutoff = startedAt - Number(nonceRetentionSecs) * 1000;
      for (const [k, expiresAt] of [...nonces]) {
        if (k.startsWith(`${deviceId}|`) && expiresAt < nonceCutoff) nonces.delete(k);
      }

      // bucket: ON CONFLICT DO UPDATE. Serializes on the row and re-reads the LIVE version, so
      // the returned count is exact and unique per caller.
      const uploads = await withRowLock(key, async () => {
        const live = buckets.get(key);
        const next: Bucket = live
          ? { ...live, uploads: live.uploads + 1, bytes: live.bytes + Number(bytes) }
          : { deviceId, windowStart: start, uploads: 1, bytes: Number(bytes) };
        await hop(); // server-side work between the read and the write
        buckets.set(key, next);
        return next.uploads;
      });

      // The trailing sum reads the SNAPSHOT — earlier buckets only.
      let earlier = 0;
      for (const b of snap.values()) {
        if (b.deviceId !== deviceId) continue;
        if (b.windowStart <= startedAt - Number(windowSecs) * 1000) continue;
        if (b.windowStart >= start) continue;
        earlier += b.uploads;
      }

      // BIGINT arrives as a string from pg's default type parser. Model that, or db.ts's
      // Number() coercion is never actually exercised.
      return [{ uploads_in_window: String(uploads + earlier) }];
    }

    /* ---- bootstrap ---- */
    if (/UPDATE bootstrap/i.test(text)) {
      assert.match(text, /consumed_at IS NULL/, 'the one-shot gate must be conditional');
      assert.match(text, /RETURNING/, 'the gate must report whether it won');
      return withRowLock('bootstrap|1', async () => {
        // Re-read live under the lock. A waiter that woke after the winner committed sees the
        // NEW row version, so its WHERE no longer matches.
        const consumed = bootstrap.consumedAt !== null;
        await hop(); // server-side work between evaluating the WHERE and writing
        if (consumed) return [];
        bootstrap.consumedAt = clock;
        return [{ id: 1 }];
      });
    }
    if (/FROM bootstrap/i.test(text) && /consumed_at/.test(text) && /SELECT/i.test(text)) {
      return [{ consumed_at: bootstrap.consumedAt }];
    }
    if (/FROM bootstrap/i.test(text) && /EXTRACT/i.test(text)) {
      // numeric also arrives as a string.
      return [{ age_ms: String(clock - bootstrap.createdAt) }];
    }

    /* ---- seen_nonce ---- */
    if (/INSERT INTO seen_nonce/i.test(text)) {
      assert.match(text, /ON CONFLICT .* DO NOTHING/i, 'the unique constraint is the mechanism');
      const key = `${String(params[0])}|${String(params[1])}`;
      const expiresAt = Number(params[2]);
      // The speculative insert checks the LIVE index, not a snapshot — two concurrent replays
      // cannot both come back with a row.
      return withRowLock(`nonce|${key}`, async () => {
        const seen = nonces.has(key);
        await hop();
        if (seen) return [];
        nonces.set(key, expiresAt);
        return [{ nonce: params[1] }];
      });
    }

    /* ---- snapshot ---- */
    if (/INSERT INTO snapshot/i.test(text)) {
      const [tenantId, companyGuid, section, asOf, contentHash, envelope, snapshotTs, seq, deviceId, bytes] =
        params;
      assert.equal(typeof envelope, 'string', 'jsonb must be bound as text, not as an object');
      const key = `${String(tenantId)}|${String(companyGuid)}|${String(section)}|${String(asOf)}`;
      const incoming: SnapshotRow = {
        tenantId: String(tenantId),
        companyGuid: String(companyGuid),
        section: String(section),
        asOf: String(asOf),
        contentHash: String(contentHash),
        envelope: JSON.parse(String(envelope)),
        snapshotTs: Number(snapshotTs),
        seq: Number(seq),
        deviceId: String(deviceId),
        bytes: Number(bytes),
      };
      return withRowLock(`snapshot|${key}`, async () => {
        const live = snapshots.get(key);
        await hop();
        // The conditional DO UPDATE, re-read live under the lock.
        if (live && /WHERE snapshot\.snapshot_ts <= EXCLUDED\.snapshot_ts/i.test(text)) {
          if (live.snapshotTs > incoming.snapshotTs) return [];
        }
        snapshots.set(key, incoming);
        return [];
      });
    }
    if (/FROM snapshot/i.test(text) && /sum\(bytes\)/i.test(text)) {
      let total = 0;
      for (const s of snapshots.values()) if (s.tenantId === params[0]) total += s.bytes;
      return [{ total: String(total) }];
    }
    if (/FROM snapshot/i.test(text)) {
      const key = `${String(params[0])}|${String(params[1])}|${String(params[2])}|${String(params[3])}`;
      const r = snapshots.get(key);
      return r ? [{ snapshot_ts: String(r.snapshotTs), content_hash: r.contentHash }] : [];
    }

    /* ---- device ---- */
    if (/INSERT INTO device/i.test(text)) {
      const [deviceId, tenantId, publicKeyB64, label] = params;
      if (devices.has(String(deviceId))) throw new Error('duplicate key value violates unique constraint');
      devices.set(String(deviceId), {
        tenantId: String(tenantId),
        publicKey: new Uint8Array(Buffer.from(String(publicKeyB64), 'base64')),
        label: String(label),
        revokedAt: null,
      });
      return [];
    }
    if (/UPDATE device/i.test(text)) {
      // The SET clause is bound before the WHERE clause, so the IP is $1 and the device is $2.
      const [ip, deviceId] = params;
      const d = devices.get(String(deviceId));
      if (d) {
        d.lastSeenIp = ip == null ? null : String(ip);
        d.lastSeenAt = clock;
      }
      return [];
    }
    if (/FROM device/i.test(text) && /public_key/i.test(text)) {
      const d = devices.get(String(params[0]));
      if (!d) return [];
      return [
        {
          // Postgres does the encoding, so the fake must too.
          public_key_b64: Buffer.from(d.publicKey).toString('base64'),
          revoked_at: d.revokedAt,
        },
      ];
    }
    if (/FROM device/i.test(text) && /tenant_id/i.test(text)) {
      const d = devices.get(String(params[0]));
      return d ? [{ tenant_id: d.tenantId }] : [];
    }

    throw new Error(`fakeNeon: unhandled statement: ${text.slice(0, 90)}`);
  }

  return {
    sql,
    queries,
    devices,
    buckets,
    nonces,
    snapshots,
    bootstrap,
    hop,
    withRowLock,
    snapshotOf,
    bucketStart,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
    /** Seed a device's bucket for the current minute, as if it had already uploaded n times. */
    seedUploads: (deviceId: string, n: number) => {
      const start = Math.floor(clock / MINUTE) * MINUTE;
      buckets.set(`${deviceId}|${start}`, { deviceId, windowStart: start, uploads: n, bytes: 0 });
    },
  };
}

/* ------------------------------------------------------------------ *
 * consumeBootstrap
 * ------------------------------------------------------------------ */

test('consumeBootstrap: the one shot is a conditional UPDATE, not a read', async () => {
  const db = fakeNeon();
  const deps = registerDepsFromSql(db.sql, 'the-secret');

  assert.equal(await deps.consumeBootstrap(), true);
  assert.equal(await deps.consumeBootstrap(), false, 'a second call must lose');

  const update = db.queries.find((q) => /UPDATE bootstrap/i.test(q.text))!;
  assert.match(update.text, /consumed_at IS NULL/);
  assert.match(update.text, /RETURNING id/);
  assert.doesNotMatch(update.text, /pg_advisory_lock/, 'a session lock is a no-op on HTTP');
});

test('CONCURRENT consumeBootstrap: N racing callers, exactly one wins', async () => {
  // The bootstrap secret is ONE-SHOT. Two concurrent registrations both consuming it means two
  // devices enrol on a one-device secret, or the wrong one enrols permanently — and the shot is
  // spent either way, so the customer's deployment is bricked mid-setup with no way back.
  //
  // Every one of these 32 callers has already passed `bootstrapConsumed`, because that read is a
  // snapshot and cannot be the gate. The UPDATE is the gate.
  const db = fakeNeon();
  const deps = registerDepsFromSql(db.sql, 'the-secret');

  const results = await Promise.all(Array.from({ length: 32 }, () => deps.consumeBootstrap()));

  assert.equal(results.filter(Boolean).length, 1, 'exactly one winner');
  assert.equal(db.bootstrap.consumedAt !== null, true);
});

test('CONCURRENT REGISTRATION, end to end: 16 requests, one device enrolled', async () => {
  const db = fakeNeon();
  const deps = registerDepsFromSql(db.sql, 'the-secret');
  const kp = await generateDeviceKeypair(DEVICE);
  const pk = Buffer.from(kp.publicKey).toString('base64');

  const results = await Promise.all(
    Array.from({ length: 16 }, (_, i) =>
      handleRegister(
        { secret: 'the-secret', deviceId: `dev_${i}`, tenantId: TENANT, publicKey: pk },
        deps,
        bootstrapSecretMatches,
      ),
    ),
  );

  assert.equal(results.filter((r) => r.status === 200).length, 1, 'exactly one enrolment');
  assert.equal(db.devices.size, 1, 'a loser must never reach the device table');
});

test('bootstrapConsumed and bootstrapAgeMs fail CLOSED when the row is unreadable', async () => {
  // "I cannot tell whether the shot is spent" must resolve to spent. This is the one endpoint
  // that opens without a device key.
  const sql: Sql = async () => [];
  const deps = registerDepsFromSql(sql, 'the-secret');

  assert.equal(await deps.bootstrapConsumed(), true, 'a missing row must read as consumed');
  assert.equal(await deps.bootstrapAgeMs(), Number.POSITIVE_INFINITY, 'unknown age must expire');
});

test('bootstrapAgeMs is measured by the database clock, not the function instance clock', async () => {
  // created_at was stamped by Postgres. Comparing it against a Vercel instance's Date.now() would
  // make the 24h TTL depend on two clocks agreeing.
  const db = fakeNeon();
  const deps = registerDepsFromSql(db.sql, 'the-secret');
  db.advance(90 * 60 * 1000);

  assert.equal(await deps.bootstrapAgeMs(), 90 * 60 * 1000);
  const q = db.queries.find((x) => /FROM bootstrap/i.test(x.text) && /EXTRACT/i.test(x.text))!;
  assert.match(q.text, /now\(\) - created_at/, 'both halves must come from the database');
});

test('registerDevice binds the public key as checked base64, not as a driver-encoded blob', async () => {
  const db = fakeNeon();
  const deps = registerDepsFromSql(db.sql, 'the-secret');
  const kp = await generateDeviceKeypair(DEVICE);

  await deps.registerDevice(DEVICE, TENANT, kp.publicKey, 'Accounts PC');

  assert.deepEqual(db.devices.get(DEVICE)!.publicKey, kp.publicKey, 'the key must round-trip exactly');
  const q = db.queries.find((x) => /INSERT INTO device/i.test(x.text))!;
  assert.match(q.text, /decode\( \$\? , 'base64'\)/, 'Postgres decodes; the driver does not guess');
});

/* ------------------------------------------------------------------ *
 * reserveUpload
 * ------------------------------------------------------------------ */

test('reserveUpload: the returned count INCLUDES the caller’s own row', async () => {
  // ingest.ts subtracts 1 to get "uploads before this one", so an off-by-one here moves the cap.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  assert.equal(await deps.reserveUpload(DEVICE, 100), 1, 'the first upload is the 1st');
  assert.equal(await deps.reserveUpload(DEVICE, 100), 2);
  assert.equal(await deps.reserveUpload(DEVICE, 100), 3);
});

test('reserveUpload: the window slides across minute buckets and expires at the hour', async () => {
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  await deps.reserveUpload(DEVICE, 1);
  db.advance(30 * MINUTE);
  assert.equal(await deps.reserveUpload(DEVICE, 1), 2, 'a bucket 30 minutes back still counts');

  // Step past an hour from the FIRST upload: it leaves the window, the second one has not.
  db.advance(31 * MINUTE);
  assert.equal(await deps.reserveUpload(DEVICE, 1), 2, 'the 61-minute-old bucket has aged out');
});

test('reserveUpload: buckets past the retention are swept, so the table cannot grow forever', async () => {
  // The cap protects the client's Neon bill; a table that grows without bound bills them anyway.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  for (let i = 0; i < 5; i++) {
    await deps.reserveUpload(DEVICE, 1);
    db.advance(MINUTE);
  }
  assert.equal(db.buckets.size, 5);

  db.advance(RATE_WINDOW_SECONDS * 2 * 1000);
  await deps.reserveUpload(DEVICE, 1);
  assert.equal(db.buckets.size, 1, 'only the live bucket survives');
});

test('reserveUpload: one round trip', async () => {
  // Two round trips is the bug this shape exists to remove. Assert the shape, not just the count.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  await deps.reserveUpload(DEVICE, 100);

  assert.equal(db.queries.length, 1, 'the reservation must be a single statement');
  const q = db.queries[0]!;
  assert.match(q.text, /ON CONFLICT .* DO UPDATE/i, 'the row lock is the gate');
  assert.match(q.text, /RETURNING window_start, uploads/i, 'the exact count comes from RETURNING');
  assert.doesNotMatch(q.text, /pg_advisory_lock/, 'a session lock is a no-op on HTTP');

  // THE FAKE CANNOT CHECK THESE FOR US, so they are asserted as text.
  //
  // The fake dispatches on statement SHAPE and then applies the semantics this file believes the
  // SQL has — so it models the intent, not the bytes. Flip a `-` to a `+` in either sweep and the
  // fake goes on sweeping correctly and every test still passes. (Verified by mutation: it does.)
  // The direction of a retention predicate is exactly the kind of typo that reads as fine and
  // deletes live rows, so it is pinned here, where a mutation has to survive a string match.
  assert.match(
    q.text,
    /DELETE FROM upload_window[\s\S]*?window_start < now\(\) - \(/i,
    'the bucket sweep must delete rows OLDER than the retention',
  );
  assert.match(
    q.text,
    /DELETE FROM seen_nonce[\s\S]*?expires_at < now\(\) - \(/i,
    'the nonce sweep must delete rows PAST their expiry, never before it',
  );
});

test('THE QUOTA RACE: N concurrent reservations at the cap admit exactly the cap', async () => {
  // 20 sockets, one slot left. A cap that 20 concurrent callers can step around is not a cap —
  // it is a comment, and the bill it was protecting is the client's own.
  //
  // The proof is that the counts come back DISTINCT. If the reservation were a snapshot read,
  // every caller would be handed the same number; distinctness is only possible if they
  // serialized on the row.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  db.seedUploads(DEVICE, MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1); // 59 used, one slot left

  const counts = await Promise.all(Array.from({ length: 20 }, () => deps.reserveUpload(DEVICE, 100)));

  assert.equal(new Set(counts).size, 20, 'every racing caller must get a distinct count');
  assert.deepEqual(
    [...counts].sort((a, b) => a - b),
    Array.from({ length: 20 }, (_, i) => 60 + i),
    'the counts must be exactly 60..79',
  );

  // And the count is what the caller compares against: exactly one sees a free slot.
  const admitted = counts.filter((n) => n - 1 < MAX_UPLOADS_PER_HOUR_PER_DEVICE).length;
  assert.equal(admitted, 1, `exactly one upload may be admitted; ${admitted} were`);
});

test('THE QUOTA RACE, end to end: 20 concurrent signed uploads, one 200 and nineteen 429s', async () => {
  // The same property through the real handler and the real deps, which is what actually ships.
  const identity = await generateIdentity();
  const device = await generateDeviceKeypair(DEVICE);
  const db = fakeNeon({ publicKey: device.publicKey });
  const deps = ingestDepsFromSql(db.sql, db.now);
  db.seedUploads(DEVICE, MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1);

  const uploads = await Promise.all(
    Array.from({ length: 20 }, async (_, i) => {
      const aad = makeAad({
        tenantId: TENANT,
        deviceId: DEVICE,
        companyGuid: 'guid-acme',
        section: 'group_balance' as Section,
        asOf: '2026-07-16',
        snapshotTs: NOW - i,
        seq: i + 1,
      });
      const env = await sealSection(
        { rows: [{ g: 'Cash', amt: '100.00' }] },
        aad,
        identity.publicKey,
        device.secretKey,
      );
      const body = new TextEncoder().encode(JSON.stringify(env));
      const headers = await signRequest(
        { deviceId: DEVICE, method: 'POST', path: '/api/sync', body, timestamp: db.now() },
        device.secretKey,
      );
      return { body, headers };
    }),
  );

  const results = await Promise.all(uploads.map((u) => handleIngest(u.headers, u.body, deps)));

  assert.equal(results.filter((r) => r.status === 200).length, 1, 'the 60th upload is the last one');
  assert.equal(results.filter((r) => r.status === 429).length, 19);
});

/* ------------------------------------------------------------------ *
 * THE HARNESS CATCHES THE BUGS IT CLAIMS TO — otherwise it is theatre
 * ------------------------------------------------------------------ */

test('THE HARNESS CATCHES the two-round-trip TOCTOU it was built to detect', async () => {
  // The shape the old code had: read the count, compare, write. Two POSTs to Neon. Every request
  // in flight during the gap sees the same count and every one of them passes.
  //
  // If this test ever stops failing for THIS implementation, the harness has stopped modelling
  // the round trip and every other concurrency assertion in this file is worthless.
  const db = fakeNeon();
  const log: string[] = [];

  const naiveReserve = async (deviceId: string): Promise<number> => {
    await db.hop(); // SELECT count(*) ... — one POST
    const before = log.filter((d) => d === deviceId).length;
    await db.hop();
    await db.hop(); // INSERT INTO upload_log ... — a second POST
    log.push(deviceId);
    await db.hop();
    return before + 1;
  };

  const counts = await Promise.all(Array.from({ length: 20 }, () => naiveReserve(DEVICE)));
  const admitted = counts.filter((n) => n - 1 < 1).length; // cap of 1, for clarity

  assert.equal(admitted, 20, 'the harness must expose the read-then-write race');
  assert.equal(new Set(counts).size, 1, 'every caller saw the same count — that is the bug');
});

test('THE HARNESS CATCHES the single-statement snapshot count — the subtler wrong answer', async () => {
  // This is the shape that LOOKS correct and is not, and it is the one worth a test.
  //
  //   WITH ins AS (INSERT INTO upload_log ... RETURNING id)
  //   SELECT count(*) FROM upload_log WHERE device_id = $1 AND received_at > now() - '1 hour'
  //
  // One statement, one round trip, an INSERT and a windowed count over the device/time index.
  // It still cannot enforce a cap, for two reasons that have nothing to do with the code:
  //
  //   * A data-modifying CTE's effects are invisible to the rest of the statement — "the
  //     sub-statements in WITH can't see one another's effects on the target tables" — so the
  //     count does not include the row just inserted.
  //   * Concurrent INSERTs into a log table do not contend, so nothing serializes them, and each
  //     statement's READ COMMITTED snapshot predates every other in-flight INSERT.
  //
  // So twenty simultaneous callers each count the same 59 predecessors and all twenty pass. This
  // is why the real implementation counts a LOCKED COUNTER ROW instead of counting log rows.
  const db = fakeNeon();
  const committed: string[] = [];

  const cteReserve = async (deviceId: string): Promise<number> => {
    await db.hop(); // the POST travels out; the statement arrives
    // The statement's READ COMMITTED snapshot, taken on arrival. It sees only what has
    // COMMITTED — and the CTE's own insert is invisible to it regardless.
    const snapshotCount = committed.filter((d) => d === deviceId).length;
    const pending = deviceId; // the CTE's insert: written, not yet committed
    await db.hop(); // the statement runs and commits; the other 19 are snapshotting right now
    committed.push(pending);
    return snapshotCount + 1;
  };

  const counts = await Promise.all(Array.from({ length: 20 }, () => cteReserve(DEVICE)));
  const admitted = counts.filter((n) => n - 1 < 1).length;

  assert.equal(admitted, 20, 'a single statement is not automatically an atomic one');
  assert.equal(new Set(counts).size, 1, 'all twenty counted the same pre-insert state');
});

test('THE HARNESS CATCHES a non-atomic consumeBootstrap', async () => {
  // The read-then-write version of the one shot, which is what "check then consume" degrades to
  // without the conditional UPDATE.
  const db = fakeNeon();
  let consumed = false;

  const naiveConsume = async (): Promise<boolean> => {
    await db.hop();
    const seen = consumed; // SELECT consumed_at ...
    await db.hop();
    if (seen) return false;
    await db.hop(); // UPDATE bootstrap SET consumed_at = now() ...
    consumed = true;
    await db.hop();
    return true;
  };

  const wins = (await Promise.all(Array.from({ length: 8 }, () => naiveConsume()))).filter(Boolean);
  assert.equal(wins.length, 8, 'the harness must expose a bootstrap that eight callers can win');
});

/* ------------------------------------------------------------------ *
 * Fail-closed accounting
 * ------------------------------------------------------------------ */

test('an unreadable count fails CLOSED, as an unmeasurable quota, not as zero', async () => {
  // A count read as 0 means "plenty of headroom" and admits the request. checkQuota refuses a
  // value it cannot compare, so NaN is the fail-closed answer and 0 is the fail-open one.
  const empty: Sql = async () => [];
  const deps = ingestDepsFromSql(empty, () => NOW);

  assert.ok(Number.isNaN(await deps.reserveUpload(DEVICE, 100)));
  assert.ok(Number.isNaN(await deps.tenantBytesStored(TENANT)));
});

test('a tenant with no rows is a measurable zero, not an unmeasurable one', async () => {
  // The mirror of the test above: failing closed must not mean refusing the very first upload.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  assert.equal(await deps.tenantBytesStored(TENANT), 0);
});

test('BIGINT columns arrive as strings and are coerced, not trusted', async () => {
  // pg's default int8 parser returns a string. A layer that assumed a number would compare a
  // string against a cap and quietly get the wrong answer.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  await deps.storeSnapshot({
    tenantId: TENANT,
    companyGuid: 'g',
    section: 'group_balance' as Section,
    asOf: '2026-07-16',
    contentHash: 'h',
    envelope: { aad: {}, nonce: 'n', sealedCek: 'c', ciphertext: 'x', contentHash: 'h' } as never,
    snapshotTs: NOW,
    seq: 1,
    deviceId: DEVICE,
    bytes: 4096,
  });

  const bytes = await deps.tenantBytesStored(TENANT);
  assert.equal(typeof bytes, 'number');
  assert.equal(bytes, 4096);

  const latest = await deps.latestSnapshot(TENANT, 'g', 'group_balance' as Section, '2026-07-16');
  assert.equal(typeof latest!.snapshotTs, 'number');
  assert.equal(latest!.snapshotTs, NOW);
});

/* ------------------------------------------------------------------ *
 * storeSnapshot
 * ------------------------------------------------------------------ */

test('STORE IS MONOTONE: a racing older snapshot cannot overwrite a newer one', async () => {
  // handleIngest reads `latestSnapshot` and then writes — two round trips. Two uploads for the
  // same slot can both read the same "latest", both judge themselves fresh, and both write. Last
  // writer wins, and last-to-arrive is not the same as newest, so the OLDER one can land on top:
  // exactly the rollback the freshness check exists to prevent, through a different door.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  const row = (snapshotTs: number, contentHash: string) => ({
    tenantId: TENANT,
    companyGuid: 'g',
    section: 'group_balance' as Section,
    asOf: '2026-07-16',
    contentHash,
    envelope: { aad: {}, nonce: 'n', sealedCek: 'c', ciphertext: 'x', contentHash } as never,
    snapshotTs,
    seq: 1,
    deviceId: DEVICE,
    bytes: 10,
  });

  // The newer one commits first; the older one arrives after and must be refused by the WHERE.
  await deps.storeSnapshot(row(NOW, 'new'));
  await deps.storeSnapshot(row(NOW - 90 * 86_400_000, 'old'));

  const latest = await deps.latestSnapshot(TENANT, 'g', 'group_balance' as Section, '2026-07-16');
  assert.equal(latest!.contentHash, 'new', 'last quarter’s numbers must not land on top');
});

test('storeSnapshot upserts on the natural key — a retry does not duplicate', async () => {
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);
  const row = {
    tenantId: TENANT,
    companyGuid: 'g',
    section: 'group_balance' as Section,
    asOf: '2026-07-16',
    contentHash: 'h',
    envelope: { aad: {}, nonce: 'n', sealedCek: 'c', ciphertext: 'x', contentHash: 'h' } as never,
    snapshotTs: NOW,
    seq: 1,
    deviceId: DEVICE,
    bytes: 10,
  };

  await deps.storeSnapshot(row);
  await deps.storeSnapshot(row);
  assert.equal(db.snapshots.size, 1);
});

test('THE UNMETERED TABLE: a rate-limited flood cannot grow seen_nonce forever', async () => {
  // rememberNonce is a WRITE and verifyRequest calls it BEFORE the reservation, so a signed
  // request buys a permanent seen_nonce row even when it is then refused with a 429. The rate cap
  // does not bound this table — which makes it an unmetered write channel for a stolen device
  // key, billed to the client, for traffic the server already rejected. schema.sql says these
  // rows are "Swept, not kept"; reserveUpload is what sweeps them.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  // An hour of a device hammering the endpoint: every request writes a nonce.
  for (let i = 0; i < 40; i++) {
    await deps.rememberNonce(DEVICE, `n${i}`, db.now() + 300_000);
    await deps.reserveUpload(DEVICE, 100);
    db.advance(MINUTE);
  }
  assert.ok(db.nonces.size > 0, 'precondition: the flood wrote rows');

  // Long enough that every one of those nonces is expired and past its retention slack.
  db.advance(3 * RATE_WINDOW_SECONDS * 1000);
  await deps.rememberNonce(DEVICE, 'fresh', db.now() + 300_000);
  await deps.reserveUpload(DEVICE, 100);

  assert.deepEqual([...db.nonces.keys()], [`${DEVICE}|fresh`], 'only the live nonce survives');
});

test('the nonce sweep never removes a nonce that could still be replayed', async () => {
  // The mirror: sweeping too eagerly would silently re-open the replay window that the ±300s
  // clock-skew tolerance depends on this table to close.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  await deps.rememberNonce(DEVICE, 'n1', db.now() + 300_000);
  db.advance(300_000); // exactly expired, but within the retention slack
  await deps.reserveUpload(DEVICE, 100);

  assert.equal(await deps.rememberNonce(DEVICE, 'n1', db.now() + 300_000), false, 'still a replay');
});

test('touchDevice: a missing client IP is bound as NULL, not as the string "undefined"', async () => {
  // The IP is rendered in the revocation UI, where "undefined — 2h ago" is the row an owner has
  // to make a decision about under stress.
  const device = await generateDeviceKeypair(DEVICE);
  const db = fakeNeon({ publicKey: device.publicKey });
  const deps = ingestDepsFromSql(db.sql, db.now);

  await deps.touchDevice(DEVICE, '49.36.1.1');
  assert.equal(db.devices.get(DEVICE)!.lastSeenIp, '49.36.1.1');
  assert.equal(db.devices.get(DEVICE)!.lastSeenAt, NOW);

  await deps.touchDevice(DEVICE, undefined);
  assert.equal(db.devices.get(DEVICE)!.lastSeenIp, null);
});

/* ------------------------------------------------------------------ *
 * rememberNonce
 * ------------------------------------------------------------------ */

test('rememberNonce: the unique constraint is the mechanism, and it holds under a race', async () => {
  // Without this, the ±300s clock-skew tolerance IS a 5-minute replay window.
  const db = fakeNeon();
  const deps = ingestDepsFromSql(db.sql, db.now);

  const first = await Promise.all(Array.from({ length: 10 }, () => deps.rememberNonce(DEVICE, 'n1', NOW)));
  assert.equal(first.filter(Boolean).length, 1, 'ten concurrent replays, one survivor');

  assert.equal(await deps.rememberNonce(DEVICE, 'n2', NOW), true, 'a fresh nonce still passes');
  assert.equal(await deps.rememberNonce('dev_2', 'n1', NOW), true, 'nonces are scoped per device');
});

/* ------------------------------------------------------------------ *
 * Injection
 * ------------------------------------------------------------------ */

test('every value reaches the database as a bound parameter, never as SQL text', async () => {
  const db = fakeNeon();
  const ingest = ingestDepsFromSql(db.sql, db.now);
  const register = registerDepsFromSql(db.sql, 'the-secret');
  const evil = "'; DROP TABLE snapshot; --";

  await ingest.lookupDevice(evil);
  await ingest.tenantIdForDevice(evil);
  await ingest.reserveUpload(evil, 1);
  await ingest.tenantBytesStored(evil);
  await ingest.touchDevice(evil, evil);
  await register.bootstrapConsumed();

  for (const q of db.queries) {
    assert.ok(!q.text.includes('DROP TABLE'), `value spliced into SQL: ${q.text.slice(0, 80)}`);
  }
  assert.ok(
    db.queries.some((q) => q.params.includes(evil)),
    'the value must arrive as a parameter',
  );
});
