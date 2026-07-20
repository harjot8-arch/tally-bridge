import { neon } from '@neondatabase/serverless';
import type { KdfParams, SealedEnvelope, WrappedKey } from '@tally-bridge/core';
import {
  SESSION_ABSOLUTE_TTL_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  hashSessionToken,
  sessionTokenFromHeaders,
  type AuthDeps,
  type PutWrappedKeyDeps,
} from './auth.ts';
import type { IngestDeps, RegisterDeps } from './ingest.ts';
import type { DeviceSummary, ReadDeps, RequireSession, StoredSnapshot } from './read.ts';

/**
 * The database layer.
 *
 * Two rules shape this whole file.
 *
 * RULE 1 — A CONNECTION MAY NOT OUTLIVE A REQUEST.
 *
 * The reflex from a long-lived Node server is to build a `Pool` at module scope and share it.
 * On a serverless platform that reflex is a bug with a delayed fuse. A Vercel function instance
 * is frozen the instant the response is sent and thawed for the next request, minutes or hours
 * later — the process survives, but the TCP socket underneath a pooled connection does not.
 * Neon's proxy has already closed it, or the platform has. The pool hands out a corpse and the
 * next request fails with a read ECONNRESET that reproduces on no developer's machine, because
 * no developer's machine freezes a process between requests. Worse, every warm instance holds
 * its connections open against Neon's per-project connection cap, so the failure mode under
 * load is "the database refuses everyone" rather than "one request is slow".
 *
 * So: `connect()` is called INSIDE a handler, per request, and the result is never cached in a
 * module-level variable. Do not "optimize" this by hoisting it.
 *
 * RULE 2 — HTTP MODE, NOT WEBSOCKETS.
 *
 * `neon(...)` is the HTTP driver: each query is one stateless POST to Neon's SQL-over-HTTP
 * endpoint. There is no connection to keep alive, no handshake to amortize, and nothing to leak
 * when the instance freezes — which is precisely why it is the right default here and why
 * Rule 1 costs nothing. Every query this app issues is a one-shot: read the envelopes, read the
 * device list, flip a revoked_at. None of them needs a session.
 *
 * The one thing HTTP mode does NOT give you is a session, and one caller needs one: the
 * migration runner, whose advisory lock must be held across several statements. That is what
 * `transaction()` below is for — Neon's HTTP transaction ships a batch of statements to be run
 * on ONE connection inside one BEGIN/COMMIT. It buys session semantics for the length of the
 * batch without ever holding a socket open across requests. See migrate.ts for why this
 * distinction is load-bearing rather than academic.
 *
 * Everything is expressed over the `Sql` interface rather than the concrete driver, so the
 * handlers can be tested against an in-memory stub and no test needs a real Postgres.
 */

export type Row = Record<string, unknown>;

/**
 * A tagged-template query function — the one thing the rest of the server may assume about a
 * database.
 *
 * Tagged-template rather than `query(text, params)` on purpose: with this shape the only way to
 * get a value into a statement is as an interpolation, which the driver binds as a parameter.
 * String concatenation is not merely discouraged, it is inconvenient. That is the correct
 * ergonomic gradient for a query builder.
 */
export interface Sql {
  (strings: TemplateStringsArray, ...params: unknown[]): Promise<Row[]>;
}

/**
 * Runs several statements on ONE connection inside one transaction.
 *
 * Statements are raw SQL strings with no parameters, because its only caller is the migration
 * runner and DDL cannot be parameterized anyway. Do not reach for this to run user input.
 */
export interface SqlTransaction {
  (statements: readonly string[]): Promise<void>;
}

export interface Db {
  sql: Sql;
  transaction: SqlTransaction;
}

/**
 * Open a handle for THIS REQUEST. Call it inside the handler; never at module scope.
 *
 * Cheap by construction: in HTTP mode this builds a closure over a URL. It opens no socket, so
 * calling it per request costs approximately nothing and calling it once per process costs
 * correctness.
 */
export function connect(connectionString?: string): Db {
  const url = connectionString ?? process.env['DATABASE_URL'];
  if (!url) {
    // Fail loudly at the first request rather than emitting a confusing driver error later.
    throw new Error('DATABASE_URL is not set');
  }

  const q = neon(url);

  return {
    // The driver's tagged-template overload matches `Sql` exactly; the cast discards the extra
    // overloads (`.transaction`, options objects) that callers must not reach for.
    sql: q as unknown as Sql,
    transaction: async (statements) => {
      if (statements.length === 0) return;
      // `q(text)` builds a LAZY query promise — nothing is sent until it is awaited or handed
      // to `transaction`, which is what lets a batch be assembled and shipped as one unit.
      await q.transaction(statements.map((s) => q(s)));
    },
  };
}

/* ------------------------------------------------------------------ *
 * Row mapping
 * ------------------------------------------------------------------ */

/**
 * Build the read handlers' dependencies from a live connection.
 *
 * The projections here are DENY-BY-DEFAULT: every function names the exact columns it wants
 * and rebuilds a typed object from them. `SELECT *` is banned — not for performance, but
 * because it makes tomorrow's column an automatic export. A future `plaintext_cache` or
 * `debug_dump` column added by someone in a hurry would be shipped to the browser by a
 * `SELECT *`, silently, with no diff to review in this file. Naming columns means a leak has to
 * be typed out by hand.
 *
 * `requireSession` is injected rather than imported; see read.ts for the whole story.
 */
export function readDepsFromSql(sql: Sql, requireSession: ReadDeps['requireSession']): ReadDeps {
  return {
    requireSession,

    listSnapshots: async (tenantId) => {
      const rows = await sql`
        SELECT company_guid, section, as_of, content_hash, envelope, snapshot_ts, seq, bytes, received_at
        FROM snapshot
        WHERE tenant_id = ${tenantId}
        ORDER BY company_guid, section, as_of DESC
      `;
      return rows.map(toSnapshot);
    },

    getWrappedKeys: async (tenantId) => {
      const rows = await sql`
        SELECT kind, blob, updated_at
        FROM wrapped_key
        WHERE tenant_id = ${tenantId}
      `;
      return rows.map((r) => r['blob'] as WrappedKey);
    },

    listDevices: async (tenantId) => {
      const rows = await sql`
        SELECT device_id, label, last_seen_ip, last_seen_at, revoked_at, created_at
        FROM device
        WHERE tenant_id = ${tenantId}
        ORDER BY created_at
      `;
      return rows.map(toDevice);
    },

    tenantIdForDevice: tenantIdForDevice(sql),

    // Scoped by tenant as well as device id. The handler has already checked ownership, but a
    // WHERE clause that cannot be reasoned about without reading another file is a WHERE clause
    // that will eventually be wrong. Defence in depth costs one AND here.
    revokeDevice: async (deviceId, tenantId) => {
      const rows = await sql`
        UPDATE device
        SET revoked_at = now()
        WHERE device_id = ${deviceId} AND tenant_id = ${tenantId} AND revoked_at IS NULL
        RETURNING device_id
      `;
      return rows.length > 0;
    },
  };
}

/* ------------------------------------------------------------------ *
 * Ingest deps
 * ------------------------------------------------------------------ */

/**
 * The width of the rate-limit window, in seconds.
 *
 * Paired with `MAX_UPLOADS_PER_HOUR_PER_DEVICE` in packages/protocol: that constant is the
 * COUNT, this is the WINDOW the count is taken over, and the cap is only "per hour" if the two
 * agree. It is a bound parameter rather than SQL text so that it cannot be edited here without
 * the tests below noticing.
 */
export const RATE_WINDOW_SECONDS = 3600;

/**
 * How long a spent bucket is kept before the sweep in `reserveUpload` removes it.
 *
 * Anything older than the window can never be counted again, so this is pure retention slack.
 * Two windows rather than one so that a clock adjustment cannot delete a bucket that is still
 * inside somebody's hour.
 */
const BUCKET_RETENTION_SECONDS = RATE_WINDOW_SECONDS * 2;

/**
 * How long a nonce is kept PAST its own expiry before `reserveUpload` sweeps it.
 *
 * Not a security parameter: an expired nonce is already unusable, because a request carrying one
 * fails the clock-skew check before the nonce is ever looked at. This is slack against the
 * database's clock and the function instance's clock disagreeing.
 */
const NONCE_RETENTION_SECONDS = 3600;

/**
 * Build the ingest handler's dependencies from a live connection.
 *
 * `now` is the JavaScript clock, not the database's. It is compared against the timestamp the
 * device signed, so what matters is that it tracks real time — and a Vercel function's clock is
 * NTP-synced. Reading `now()` from Postgres instead would cost a round trip on every request to
 * answer a question the process can already answer. `bootstrapAgeMs` in `registerDepsFromSql`
 * makes the opposite choice, for the opposite reason; see there.
 */
export function ingestDepsFromSql(sql: Sql, now: () => number = Date.now): IngestDeps {
  return {
    now,

    lookupDevice: async (deviceId) => {
      // `encode(...)` rather than selecting the BYTEA raw. The driver's type parser decides
      // whether a bytea arrives as a Buffer or as a `\x...` hex string, and a public key that
      // silently decodes to the wrong bytes is a device that can never sign a request that
      // verifies. Making Postgres do the encoding pins the wire format to one thing.
      const rows = await sql`
        SELECT encode(public_key, 'base64') AS public_key_b64, revoked_at
        FROM device
        WHERE device_id = ${deviceId}
      `;
      const r = rows[0];
      if (!r) return undefined;
      return {
        publicKey: new Uint8Array(Buffer.from(String(r['public_key_b64']), 'base64')),
        revoked: r['revoked_at'] != null,
      };
    },

    /**
     * THE UNIQUE CONSTRAINT IS THE MECHANISM, exactly as the schema demands.
     *
     * `ON CONFLICT DO NOTHING ... RETURNING` returns a row only when THIS statement inserted it.
     * Two concurrent replays of the same nonce cannot both get a row back: the second one's
     * speculative insert conflicts against the live index — not against a snapshot — so it
     * returns nothing and is reported as seen. A SELECT-then-INSERT would race both through.
     */
    rememberNonce: async (deviceId, nonce, expiresAt) => {
      const rows = await sql`
        INSERT INTO seen_nonce (device_id, nonce, expires_at)
        VALUES (${deviceId}, ${nonce}, to_timestamp(${expiresAt}::double precision / 1000))
        ON CONFLICT (device_id, nonce) DO NOTHING
        RETURNING nonce
      `;
      return rows.length > 0;
    },

    tenantIdForDevice: tenantIdForDevice(sql),

    /**
     * ATOMICALLY reserve a slot and report the post-insert count. See schema.sql for why this
     * table is a counter and not a log; the short version is that concurrent INSERTs into a log
     * never contend, so nothing serializes them and a windowed `count(*)` over them cannot
     * enforce anything.
     *
     * The three pieces, and why each is where it is:
     *
     * `bucket` is the gate. `ON CONFLICT DO UPDATE` takes an exclusive lock on the conflicting
     * row and re-reads its latest committed version before evaluating the SET, so racing
     * requests queue on that row and each `uploads + 1` builds on the last. The value in
     * RETURNING is therefore exact and unique per caller — 60, then 61, then 62 — which is what
     * lets the caller compare against a number that already includes its own row. This is the
     * only part of the statement that is exact under concurrency, and it is deliberately the
     * part that decides.
     *
     * The trailing sum covers the EARLIER buckets only (`window_start < b.window_start`). Those
     * are closed: nothing writes to a minute that has passed. It reads them from the statement
     * snapshot, which can miss an upload that was still in flight when the clock crossed a
     * minute boundary — a bounded undercount, at most the number of requests racing across one
     * boundary, and it cannot compound because the current minute is always taken from the lock.
     *
     * `gc_buckets` bounds this table. Buckets older than the retention are unreachable by any
     * future window, so dropping them is free. It is safe to run in the same statement as the
     * upsert because the two can never touch the same row: `now()` is fixed for the whole
     * statement, so the bucket being written is `date_trunc('minute', now())` and the rows being
     * deleted are strictly older than `now() - 2 hours`. Disjoint by construction, not by luck.
     *
     * `gc_nonces` is the sweep schema.sql asks for ("Swept, not kept") and nothing else performs.
     * It looks out of place here and it is not:
     *
     * `rememberNonce` is a WRITE, and `verifyRequest` calls it BEFORE this function runs — so a
     * signed request inserts a seen_nonce row even when the reservation below refuses it. THE
     * RATE CAP THEREFORE DOES NOT BOUND seen_nonce. A stolen device key can take 429 after 429
     * and still buy one permanent row per request, forever, which is the client's Neon bill going
     * up for traffic we already rejected — precisely the loss the cap exists to prevent, through
     * the one table the cap does not cover.
     *
     * This statement is the right host because it runs on EXACTLY the requests that create the
     * garbage: every authenticated request, accepted or refused, one per nonce row. It is a
     * different table from the upsert, so there is no CTE interaction to reason about at all, and
     * it costs no round trip.
     *
     * The hour of slack past `expires_at` is deliberate. An expired nonce is already worthless —
     * a request carrying one is refused by the clock-skew check before `rememberNonce` is ever
     * reached, which is what `expires_at` means — so the margin is pure insurance against this
     * database's clock and the function's disagreeing, and it costs 60 rows per device.
     */
    reserveUpload: async (deviceId, bytes) => {
      const rows = await sql`
        WITH gc_buckets AS (
          DELETE FROM upload_window
          WHERE device_id = ${deviceId}
            AND window_start < now() - (${BUCKET_RETENTION_SECONDS}::double precision * interval '1 second')
        ), gc_nonces AS (
          DELETE FROM seen_nonce
          WHERE device_id = ${deviceId}
            AND expires_at < now() - (${NONCE_RETENTION_SECONDS}::double precision * interval '1 second')
        ), bucket AS (
          INSERT INTO upload_window (device_id, window_start, uploads, bytes)
          VALUES (${deviceId}, date_trunc('minute', now()), 1, ${bytes})
          ON CONFLICT (device_id, window_start) DO UPDATE
            SET uploads = upload_window.uploads + 1,
                bytes   = upload_window.bytes + EXCLUDED.bytes
          RETURNING window_start, uploads
        )
        SELECT (
          b.uploads + COALESCE((
            SELECT sum(w.uploads)
            FROM upload_window w
            WHERE w.device_id = ${deviceId}
              AND w.window_start > now() - (${RATE_WINDOW_SECONDS}::double precision * interval '1 second')
              AND w.window_start < b.window_start
          ), 0)
        )::bigint AS uploads_in_window
        FROM bucket b
      `;
      // A count we cannot read is NOT a free pass. Returning 0 here would report "no uploads yet"
      // and wave the request through; NaN is refused by checkQuota as `unmeasurable` and becomes
      // a 400. The row has already been reserved either way, so the caller's budget is spent —
      // failing closed costs one upload, failing open costs the bill this cap exists to protect.
      return bigintCount(rows[0]?.['uploads_in_window']);
    },

    tenantBytesStored: async (tenantId) => {
      const rows = await sql`
        SELECT COALESCE(sum(bytes), 0)::bigint AS total
        FROM snapshot
        WHERE tenant_id = ${tenantId}
      `;
      // NaN rather than 0 on an unreadable answer, for the reason in `reserveUpload`. Note the
      // COALESCE means a tenant with no rows is a genuine, measurable 0 — the two cases are
      // distinguished here rather than collapsed.
      return bigintCount(rows[0]?.['total']);
    },

    latestSnapshot: async (tenantId, companyGuid, section, asOf) => {
      const rows = await sql`
        SELECT snapshot_ts, content_hash
        FROM snapshot
        WHERE tenant_id = ${tenantId}
          AND company_guid = ${companyGuid}
          AND section = ${section}
          AND as_of = ${asOf}::date
      `;
      const r = rows[0];
      if (!r) return undefined;
      return { snapshotTs: Number(r['snapshot_ts']), contentHash: String(r['content_hash']) };
    },

    /**
     * Upsert on the natural key, so a retry after a lost ACK lands on the same row.
     *
     * THE `WHERE` ON THE DO UPDATE IS A FRESHNESS BACKSTOP, and it closes a race the handler
     * cannot. `handleIngest` reads `latestSnapshot` and then writes — two round trips — so two
     * uploads for the same slot can both read the same "latest", both decide they are fresh, and
     * both write. Last writer wins, and last-to-arrive is not the same as newest: the OLDER
     * snapshot can land on top. That is precisely the rollback the freshness check exists to
     * prevent, arriving by a different door.
     *
     * `ON CONFLICT DO UPDATE` re-reads the live row under its lock, so this comparison is against
     * whatever actually committed rather than against what the handler read a round trip ago. It
     * makes the stored `snapshot_ts` monotone at the storage layer, unconditionally. The handler
     * has already rejected stale uploads by the time it gets here, so this only ever fires in the
     * racing case — where dropping the older write is exactly right. A no-op is invisible to the
     * caller, which is correct: it asked for the newest snapshot to be stored, and it is.
     */
    storeSnapshot: async (row) => {
      await sql`
        INSERT INTO snapshot (
          tenant_id, company_guid, section, as_of,
          content_hash, envelope, snapshot_ts, seq, device_id, bytes
        )
        VALUES (
          ${row.tenantId}, ${row.companyGuid}, ${row.section}, ${row.asOf}::date,
          ${row.contentHash}, ${JSON.stringify(row.envelope)}::jsonb,
          ${row.snapshotTs}, ${row.seq}, ${row.deviceId}, ${row.bytes}
        )
        ON CONFLICT (tenant_id, company_guid, section, as_of) DO UPDATE
          SET content_hash = EXCLUDED.content_hash,
              envelope     = EXCLUDED.envelope,
              snapshot_ts  = EXCLUDED.snapshot_ts,
              seq          = EXCLUDED.seq,
              device_id    = EXCLUDED.device_id,
              bytes        = EXCLUDED.bytes,
              received_at  = now()
          WHERE snapshot.snapshot_ts <= EXCLUDED.snapshot_ts
      `;
    },

    touchDevice: async (deviceId, ip) => {
      await sql`
        UPDATE device
        SET last_seen_at = now(), last_seen_ip = ${ip ?? null}
        WHERE device_id = ${deviceId}
      `;
    },
  };
}

/* ------------------------------------------------------------------ *
 * Register deps
 * ------------------------------------------------------------------ */

/**
 * Build the registration handler's dependencies from a live connection.
 *
 * `expectedSecret` is passed in rather than read from `process.env` here so that the one place
 * this deployment's bootstrap secret enters the server is the route file, where it is visible.
 */
export function registerDepsFromSql(sql: Sql, expectedSecret: string | undefined): RegisterDeps {
  return {
    expectedSecret,

    // A pre-check, NOT the gate — see `consumeBootstrap`. Its only job is to turn the common,
    // uncontended "this endpoint is closed" case into a cheap 403.
    //
    // A missing row means the migration has not run or someone deleted it. Registration is the
    // one door that opens without a device key, so "I cannot tell whether it is spent" resolves
    // to spent.
    bootstrapConsumed: async () => {
      const rows = await sql`SELECT consumed_at FROM bootstrap WHERE id = 1`;
      const r = rows[0];
      if (!r) return true;
      return r['consumed_at'] != null;
    },

    /**
     * The age of the one shot, measured by the DATABASE's clock.
     *
     * `now() - created_at` is computed in Postgres on purpose. Both halves of that subtraction
     * then come from the same clock, so the TTL cannot be defeated — or tripped — by the
     * function instance's clock disagreeing with the one that stamped `created_at`. This is the
     * mirror of `ingestDepsFromSql`'s choice: there the question was "does this match a timestamp
     * the DEVICE signed", so the JS clock was the honest answer; here the question is about a row
     * this database wrote, so the database is.
     */
    bootstrapAgeMs: async () => {
      const rows = await sql`
        SELECT EXTRACT(EPOCH FROM (now() - created_at)) * 1000 AS age_ms
        FROM bootstrap
        WHERE id = 1
      `;
      // Infinity reads as "older than any TTL" and therefore closes registration. Every
      // unreadable answer lands here — no row, a NULL, a numeric the driver hands back as
      // something Number() cannot parse. An unreadable age must never read as "brand new".
      const age = Number(rows[0]?.['age_ms']);
      return Number.isFinite(age) ? age : Number.POSITIVE_INFINITY;
    },

    /**
     * THE GATE. One shot, and exactly one winner.
     *
     * A conditional UPDATE, one round trip, atomic by row lock. Two concurrent registrations both
     * pass the `bootstrapConsumed` pre-check — that read is a snapshot and cannot be the gate —
     * and both arrive here. Postgres serializes them on the row: the first sets `consumed_at` and
     * commits; the second was blocked on the lock and, under READ COMMITTED, re-evaluates its
     * WHERE against the NEW row version, where `consumed_at IS NULL` is now false. It matches
     * nothing, RETURNING is empty, and it reports the loss. The handler bails before registering.
     *
     * What is at stake if this is not atomic: two devices enrol on a one-shot secret, or the
     * wrong one does, permanently. The shot is spent either way, so there is no second attempt —
     * the customer's deployment is bricked mid-setup with no way back.
     *
     * Do NOT "improve" this into a SELECT followed by an UPDATE, and do not reach for
     * `pg_advisory_lock` to protect the pair: that lock is SESSION-scoped, and Neon's HTTP driver
     * has no session — it would be released the instant its own POST returned, leaving a race
     * with a lock around it. One statement needs neither.
     */
    consumeBootstrap: async () => {
      const rows = await sql`
        UPDATE bootstrap
        SET consumed_at = now()
        WHERE id = 1 AND consumed_at IS NULL
        RETURNING id
      `;
      return rows.length > 0;
    },

    /**
     * `decode(..., 'base64')` for the same reason `lookupDevice` uses `encode`: the key crosses
     * the wire as text with an explicit, checked encoding rather than relying on the driver to
     * turn a Uint8Array into a bytea literal.
     *
     * No `ON CONFLICT`. A conflict is unreachable — `consumeBootstrap` has already won, and it
     * can only be won once in the life of a deployment, so the table is empty. If that ever
     * proves false the INSERT throws and the request 500s, which is the honest outcome: both
     * alternatives are worse than a loud failure. DO NOTHING would spend the shot while leaving
     * the OLD key enrolled, so the new device could never sign — bricked. DO UPDATE would let
     * this endpoint overwrite an existing device's public key, which is a hijack.
     */
    registerDevice: async (deviceId, tenantId, publicKey, label) => {
      await sql`
        INSERT INTO device (device_id, tenant_id, public_key, label)
        VALUES (
          ${deviceId}, ${tenantId},
          decode(${Buffer.from(publicKey).toString('base64')}, 'base64'),
          ${label}
        )
      `;
    },
  };
}

/* ------------------------------------------------------------------ *
 * Session + auth deps
 * ------------------------------------------------------------------ */

/**
 * How long a spent auth bucket outlives the window before the sweep in `reserveAuthAttempt`
 * removes it. Same retention argument as BUCKET_RETENTION_SECONDS above.
 */
const AUTH_WINDOW_SECONDS = 3600;
const AUTH_BUCKET_RETENTION_SECONDS = AUTH_WINDOW_SECONDS * 2;

/**
 * The REAL implementation of read.ts's `RequireSession` seam. Every obligation from that
 * contract, honoured here and tested in auth.test.ts:
 *
 *   1. VERIFY, do not trust — the tenant id comes from the `session` ROW, found by the SHA-256
 *      of the cookie token. `sessionTokenFromHeaders` reads only the `cookie` header; nothing
 *      here ever consults `x-tenant-id` or any other client-settable claim.
 *   2. `undefined` on EVERY failure — missing cookie, malformed token, unknown token, expired,
 *      idle-timed-out, and (the easy one to miss) a database error: the whole body is inside
 *      the try. A Neon blip during session lookup must be a 401, not a 500 — a throw here
 *      escapes into four different read handlers, none of which signed up to translate it.
 *   3. It hits the database. That is why the seam was async.
 *
 * ONE statement, and the statement is both the check and the idle slide: an UPDATE whose WHERE
 * enforces absolute expiry and idle timeout on the DATABASE clock, RETURNING the tenant. The
 * split version — SELECT to validate, UPDATE to touch — would let a session answer its last
 * query just past its idle deadline, and costs a second round trip besides. All three
 * timestamps in that WHERE come from the same `now()`, so no JS/DB clock skew can widen a
 * window (mirror of the bootstrapAgeMs reasoning: these are rows this database wrote, so this
 * database's clock is the honest ruler).
 *
 * The lookup is by hash equality on an index, which is not a constant-time scan. That is fine
 * HERE and would not be fine for a low-entropy secret, so the reasoning gets written down: any
 * timing signal is about SHA-256(token), and walking a 256-bit random token back from partial
 * knowledge of its hash's B-tree position is a preimage problem. Compare handleLogin, where the
 * compared value is attacker-supplied and the compare is constant-time.
 */
export function requireSessionFromSql(sql: Sql): RequireSession {
  return async (headers) => {
    try {
      const token = sessionTokenFromHeaders(headers);
      if (!token) return undefined;
      const hashB64 = Buffer.from(hashSessionToken(token)).toString('base64');
      const rows = await sql`
        UPDATE session
        SET last_seen_at = now()
        WHERE token_hash = decode(${hashB64}, 'base64')
          AND expires_at > now()
          AND last_seen_at > now() - (${SESSION_IDLE_TIMEOUT_SECONDS}::double precision * interval '1 second')
        RETURNING tenant_id
      `;
      const tenant = rows[0]?.['tenant_id'];
      return typeof tenant === 'string' && tenant.length > 0 ? tenant : undefined;
    } catch {
      // Obligation 2. Fails CLOSED: an unreadable session table is a dashboard that shows
      // nothing, never one that shows everything, and never a 500 dressed as a server bug.
      return undefined;
    }
  };
}

/** Build the login/prelogin/logout dependencies from a live connection. */
export function authDepsFromSql(sql: Sql): AuthDeps {
  return {
    deploymentSecret: async () => {
      const rows = await sql`SELECT secret FROM deployment_secret WHERE id = 1`;
      const s = rows[0]?.['secret'];
      return typeof s === 'string' && s.length > 0 ? s : undefined;
    },

    getLoginCredential: async (tenantId) => {
      // encode() for the same driver-ambiguity reason as lookupDevice: a bytea that arrives as
      // a hex string instead of a Buffer would make every login fail closed but inexplicably.
      const rows = await sql`
        SELECT encode(token_hash, 'base64') AS token_hash_b64, kdf
        FROM login_credential
        WHERE tenant_id = ${tenantId}
      `;
      const r = rows[0];
      if (!r) return undefined;
      return {
        tokenHash: new Uint8Array(Buffer.from(String(r['token_hash_b64']), 'base64')),
        kdf: r['kdf'] as KdfParams,
      };
    },

    /**
     * The upload_window mechanism, verbatim, on a different table — see `reserveUpload` above
     * and schema.sql's counter-not-log essay for why only this shape counts correctly under
     * concurrency. The GC rides along on exactly the requests that create the garbage.
     * NaN (not 0) for an unreadable count; the handler refuses it — same fail-closed contract.
     */
    reserveAuthAttempt: async (bucketKey) => {
      const rows = await sql`
        WITH gc AS (
          DELETE FROM auth_window
          WHERE bucket_key = ${bucketKey}
            AND window_start < now() - (${AUTH_BUCKET_RETENTION_SECONDS}::double precision * interval '1 second')
        ), bucket AS (
          INSERT INTO auth_window (bucket_key, window_start, attempts)
          VALUES (${bucketKey}, date_trunc('minute', now()), 1)
          ON CONFLICT (bucket_key, window_start) DO UPDATE
            SET attempts = auth_window.attempts + 1
          RETURNING window_start, attempts
        )
        SELECT (
          b.attempts + COALESCE((
            SELECT sum(w.attempts)
            FROM auth_window w
            WHERE w.bucket_key = ${bucketKey}
              AND w.window_start > now() - (${AUTH_WINDOW_SECONDS}::double precision * interval '1 second')
              AND w.window_start < b.window_start
          ), 0)
        )::bigint AS attempts_in_window
        FROM bucket b
      `;
      return bigintCount(rows[0]?.['attempts_in_window']);
    },

    /**
     * Insert the row; sweep the dead in the same statement (the seen_nonce "swept, not kept"
     * pattern — ix_session_expiry is the index it walks). The sweep's two disjuncts match the
     * two WHERE conditions in requireSessionFromSql exactly: a row is deleted only once it can
     * no longer authenticate anything, so the sweep can never open or close a window the check
     * itself did not. Expiry is computed on the DB clock for the same one-ruler reason.
     *
     * A token_hash PK collision would make this INSERT throw (a 500): that is two SHA-256
     * outputs colliding by chance, ~2^-128 per pair, and a loud impossible failure beats an
     * upsert that would silently hand an existing session a new tenant.
     */
    createSession: async (tokenHash, tenantId) => {
      const hashB64 = Buffer.from(tokenHash).toString('base64');
      await sql`
        WITH gc AS (
          DELETE FROM session
          WHERE expires_at < now()
             OR last_seen_at < now() - (${SESSION_IDLE_TIMEOUT_SECONDS}::double precision * interval '1 second')
        )
        INSERT INTO session (token_hash, tenant_id, expires_at)
        VALUES (
          decode(${hashB64}, 'base64'),
          ${tenantId},
          now() + (${SESSION_ABSOLUTE_TTL_SECONDS}::double precision * interval '1 second')
        )
      `;
    },

    deleteSession: async (tokenHash) => {
      const hashB64 = Buffer.from(tokenHash).toString('base64');
      const rows = await sql`
        DELETE FROM session
        WHERE token_hash = decode(${hashB64}, 'base64')
        RETURNING tenant_id
      `;
      return rows.length > 0;
    },
  };
}

/**
 * Build the wrapped-key PUT dependencies. The device-door plumbing (lookupDevice,
 * rememberNonce, the admission gate's counters) is ingestDepsFromSql's, reused wholesale so the
 * two device endpoints cannot drift apart in how they authenticate or meter.
 */
export function wrappedKeyDepsFromSql(sql: Sql, now: () => number = Date.now): PutWrappedKeyDeps {
  const base = ingestDepsFromSql(sql, now);
  return {
    lookupDevice: base.lookupDevice,
    rememberNonce: base.rememberNonce,
    now: base.now,
    tenantIdForDevice: base.tenantIdForDevice,
    reserveUpload: base.reserveUpload,
    tenantBytesStored: base.tenantBytesStored,

    /**
     * Blobs first, credential LAST, one upsert each — the ordering contract is on
     * PutWrappedKeyDeps.storeWrappedKeys and the partial-failure analysis lives there. Neon's
     * HTTP driver runs each await as its own POST, so this is NOT atomic; it does not need to
     * be, because every statement is an idempotent upsert and a retried PUT converges.
     *
     * The credential's kdf column is `pass.kdf` — the SAME object that is inside the stored
     * blob — which is what makes "prelogin's salt" and "the blob's salt" one value by
     * construction rather than by a comparison someone has to remember to run.
     */
    storeWrappedKeys: async (tenantId, keys, authTokenHash) => {
      for (const key of keys) {
        await sql`
          INSERT INTO wrapped_key (tenant_id, kind, blob)
          VALUES (${tenantId}, ${key.kind}, ${JSON.stringify(key)}::jsonb)
          ON CONFLICT (tenant_id, kind) DO UPDATE
            SET blob = EXCLUDED.blob, updated_at = now()
        `;
      }
      if (authTokenHash) {
        // validatePutBody enforced hash⇔pass coupling; the `!` below would be a lie without it,
        // so re-assert it here where the invariant is actually consumed.
        const pass = keys.find((k) => k.kind === 'pass');
        if (!pass || !pass.kdf) {
          throw new Error('storeWrappedKeys: authTokenHash without a pass key');
        }
        const hashB64 = Buffer.from(authTokenHash).toString('base64');
        await sql`
          INSERT INTO login_credential (tenant_id, token_hash, kdf)
          VALUES (${tenantId}, decode(${hashB64}, 'base64'), ${JSON.stringify(pass.kdf)}::jsonb)
          ON CONFLICT (tenant_id) DO UPDATE
            SET token_hash = EXCLUDED.token_hash, kdf = EXCLUDED.kdf, updated_at = now()
        `;
      }
    },
  };
}

/* ------------------------------------------------------------------ *
 * Row mapping helpers
 * ------------------------------------------------------------------ */

function tenantIdForDevice(sql: Sql): (deviceId: string) => Promise<string | undefined> {
  return async (deviceId) => {
    const rows = await sql`SELECT tenant_id FROM device WHERE device_id = ${deviceId}`;
    const first = rows[0];
    return first ? (first['tenant_id'] as string) : undefined;
  };
}

/**
 * Read a count that Postgres returns as BIGINT.
 *
 * pg's default type parser leaves int8 as a STRING, because a bigint does not fit a JS number.
 * `Number()` is exact for every value these columns can hold (a byte total below 2^53 and an
 * upload count in the dozens), and the alternative — trusting the driver to have handed back a
 * number — silently produces NaN the day a parser changes.
 *
 * NaN is returned, not 0, for anything unreadable. Every caller of this feeds a quota check, and
 * `checkQuota` refuses a value it cannot compare while treating 0 as "plenty of headroom". The
 * difference between those two is the difference between a cap and a comment.
 */
function bigintCount(v: unknown): number {
  if (v == null) return Number.NaN;
  return Number(v);
}

function toSnapshot(r: Row): StoredSnapshot {
  return {
    companyGuid: String(r['company_guid']),
    section: String(r['section']),
    asOf: isoDate(r['as_of']),
    contentHash: String(r['content_hash']),
    envelope: r['envelope'] as SealedEnvelope,
    snapshotTs: Number(r['snapshot_ts']),
    seq: Number(r['seq']),
    bytes: Number(r['bytes']),
    receivedAt: isoTimestamp(r['received_at']),
  };
}

function toDevice(r: Row): DeviceSummary {
  return {
    deviceId: String(r['device_id']),
    label: String(r['label'] ?? ''),
    lastSeenIp: r['last_seen_ip'] == null ? undefined : String(r['last_seen_ip']),
    lastSeenAt: nullableTimestamp(r['last_seen_at']),
    revokedAt: nullableTimestamp(r['revoked_at']),
    createdAt: isoTimestamp(r['created_at']),
  };
}

/**
 * `snapshot.as_of` is a DATE. The driver hands back either a `Date` (parsed in the server's
 * zone) or the raw `YYYY-MM-DD` string depending on type-parser configuration, and letting a
 * `Date` through here would mean `toISOString()` shifting an Indian financial-year boundary a
 * day backwards for a UTC-hosted function. Take the string when we are given one.
 */
function isoDate(v: unknown): string {
  if (typeof v === 'string') return v.slice(0, 10);
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v);
}

function isoTimestamp(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

function nullableTimestamp(v: unknown): string | undefined {
  return v == null ? undefined : isoTimestamp(v);
}
