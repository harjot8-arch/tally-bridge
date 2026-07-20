-- Server schema.
--
-- The defining property: THIS DATABASE HOLDS NO SECRET THAT GRANTS READ ACCESS TO PLAINTEXT.
-- A full dump, a leaked DATABASE_URL, or RCE on a Vercel function yields ciphertext and public
-- keys. That is the whole point of the sealed-box design, and every table here is written to
-- keep it true.
--
-- Run idempotently on first request behind an advisory lock -- POST /v13/deployments does NOT
-- run migrations, so without this the deploy succeeds and the first request dies on a missing
-- table, which reads as our bug.

CREATE TABLE IF NOT EXISTS device (
  device_id     TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  -- Ed25519 PUBLIC key. Safe at rest: it verifies uploads, it cannot produce them.
  public_key    BYTEA NOT NULL,
  label         TEXT NOT NULL DEFAULT '',
  -- Shown in the device list so the owner can recognize which PC to revoke.
  last_seen_ip  TEXT,
  last_seen_at  TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_device_tenant ON device (tenant_id);

-- The identity keypair's wrapped forms. Ciphertext only.
--
-- The server stores these so the owner can unlock the dashboard from any browser by typing a
-- passphrase. It cannot open them: the wrapping key is derived from the passphrase (Argon2id)
-- or the recovery key, neither of which ever reaches this machine.
CREATE TABLE IF NOT EXISTS wrapped_key (
  tenant_id  TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('pass', 'recovery', 'device')),
  blob       JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kind)
);

-- Nonce replay defence.
--
-- THE UNIQUE CONSTRAINT IS THE MECHANISM -- never SELECT-then-INSERT, which races two
-- concurrent replays straight through. Insert and treat a unique violation as "seen".
-- Without this table the +/-300s clock-skew tolerance IS a 5-minute replay window.
CREATE TABLE IF NOT EXISTS seen_nonce (
  device_id  TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (device_id, nonce)
);

-- Swept, not kept. Rows are only useful for the length of the skew window.
CREATE INDEX IF NOT EXISTS ix_seen_nonce_expiry ON seen_nonce (expires_at);

-- The data. Append-only, opaque.
CREATE TABLE IF NOT EXISTS snapshot (
  tenant_id    TEXT NOT NULL,
  company_guid TEXT NOT NULL,
  section      TEXT NOT NULL,
  as_of        DATE NOT NULL,
  -- sha256 of the PLAINTEXT, computed on the Bridge. The idempotency key: a retry after a lost
  -- ACK upserts to the same row instead of duplicating.
  content_hash TEXT NOT NULL,
  -- The sealed envelope: aad + nonce + sealedCek + ciphertext. Opaque to this database.
  envelope     JSONB NOT NULL,
  -- Denormalized from envelope.aad for the freshness check and for quota accounting, WITHOUT
  -- having to parse JSONB on every read. These are already public in the AAD -- copying them
  -- here leaks nothing that the AAD does not.
  snapshot_ts  BIGINT NOT NULL,
  seq          BIGINT NOT NULL,
  device_id    TEXT NOT NULL,
  bytes        INTEGER NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, company_guid, section, as_of)
);

CREATE INDEX IF NOT EXISTS ix_snapshot_tenant ON snapshot (tenant_id);

-- Per-device upload accounting for the rate cap.
--
-- The cap protects the CLIENT'S OWN Neon bill from a stolen device key. There is no free way
-- to undo a $400 overage on a small business's card. So the cap must hold under CONCURRENCY,
-- which is what dictates the shape of this table.
--
-- WHY A COUNTER PER BUCKET AND NOT A ROW PER UPLOAD. The obvious design is an append-only log
-- (one row per upload, `count(*)` over a trailing hour). It cannot enforce a cap, and the
-- reason is MVCC rather than anything about the code:
--
--   * Concurrent INSERTs into a log table never contend. Nothing serializes them.
--   * Under READ COMMITTED a statement's snapshot is taken when the statement STARTS, so an
--     in-flight INSERT from another request is invisible to this one's count.
--   * And a data-modifying CTE cannot see its own effects -- "the sub-statements in WITH can't
--     see one another's effects on the target tables" -- so even `WITH ins AS (INSERT ...)
--     SELECT count(*) ...` counts the PRE-insert state.
--
-- So twenty simultaneous uploads at the cap each count the same 59 predecessors and all twenty
-- pass. Collapsing the read and the write into one statement does not fix that; it only makes
-- the race narrower and much harder to see.
--
-- What DOES serialize is contention on a single row. `INSERT ... ON CONFLICT DO UPDATE` takes
-- an exclusive lock on the conflicting row and RE-READS the latest committed version before
-- applying its SET, so `uploads = upload_window.uploads + 1 RETURNING uploads` hands every
-- racing request a distinct, exact, post-increment count. That is the whole mechanism, and it
-- is why the accounting lives in a counter keyed by (device, minute) rather than in a log.
--
-- The bucket is one MINUTE, and the hourly figure is the sum of the trailing 60 buckets. A
-- single per-device counter would be simpler but would make the window TUMBLE -- 60 uploads at
-- 10:59 and 60 more at 11:00 is 120 in two minutes, and the constant is named
-- MAX_UPLOADS_PER_HOUR_PER_DEVICE. Minute buckets keep that name honest.
CREATE TABLE IF NOT EXISTS upload_window (
  device_id    TEXT NOT NULL,
  -- date_trunc('minute', now()) at the time of the upload.
  window_start TIMESTAMPTZ NOT NULL,
  uploads      INTEGER NOT NULL,
  bytes        BIGINT NOT NULL,
  -- The PK is the lock and the index: it is what ON CONFLICT contends on, and its (device_id,
  -- window_start) ordering is what the trailing-hour sum and the retention sweep scan.
  PRIMARY KEY (device_id, window_start)
);

-- One-shot bootstrap.
--
-- The desktop app mints BOOTSTRAP_SECRET and sets it as a Vercel env var BEFORE the first
-- deploy, so provisioning and trust-bootstrap are the same step -- no out-of-band channel.
-- This table records that it has been spent.
CREATE TABLE IF NOT EXISTS bootstrap (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  consumed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO bootstrap (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- The dashboard login verifier. NOT a password hash, and the distinction is the design.
--
-- token_hash is SHA-256 of the AUTH TOKEN, which the browser derives as
-- HKDF(Argon2id(passphrase), 'tally/v1/auth'). The passphrase never reaches this machine; the
-- Argon2id happens in the browser. A plain SHA-256 is sufficient here BECAUSE the token behind
-- it already carries 256 bits sitting behind a ~0.5s memory-hard derive: an attacker with this
-- table dump who wants the passphrase must run the same Argon2id per guess that they would have
-- to run against the wrapped_key blob in the SAME dump -- this row makes the offline grind no
-- cheaper than the one the dump already offered (quantified in auth.ts).
--
-- kdf duplicates the Argon2id params carried inside the 'pass' wrapped_key blob, so that
-- prelogin can hand the browser its salt WITHOUT an authenticated read of wrapped_key -- the
-- chicken-and-egg of passphrase auth. It is written in the same request as the blob, from the
-- same object, so the two cannot disagree by construction (see storeWrappedKeys in db.ts).
CREATE TABLE IF NOT EXISTS login_credential (
  tenant_id  TEXT PRIMARY KEY,
  -- SHA-256(authToken), 32 bytes. The token itself is never stored: this table is the thing we
  -- assume leaks, and a leaked hash of a 256-bit token is a preimage problem, not a login.
  token_hash BYTEA NOT NULL,
  kdf        JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dashboard sessions. One row per successful login.
--
-- token_hash, never the token: a database dump must not mint working cookies. The cookie holds
-- the 256-bit random token; this holds its SHA-256, and lookup is by exact hash. Growth is
-- bounded because a row requires a SUCCESSFUL login (the auth token), logins are rate-limited,
-- and createSession sweeps expired rows on the same statement -- the seen_nonce pattern.
CREATE TABLE IF NOT EXISTS session (
  token_hash   BYTEA PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Absolute ceiling: a stolen cookie dies at most this far from the login that minted it.
  expires_at   TIMESTAMPTZ NOT NULL,
  -- Idle timeout: slid forward by requireSessionFromSql on every authenticated read.
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Swept, not kept -- same shape as ix_seen_nonce_expiry, for the sweep in createSession.
CREATE INDEX IF NOT EXISTS ix_session_expiry ON session (expires_at);

-- Attempt counters for the unauthenticated auth endpoints (prelogin, login).
--
-- The same counter-not-log shape as upload_window, for the same MVCC reason documented there:
-- only contention on a single row serializes concurrent requests, so the atomic
-- ON CONFLICT DO UPDATE increment is the only count that holds under concurrency. bucket_key
-- namespaces the counters ('login:ip:1.2.3.4', 'login:all', ...) so one table meters every
-- unauthenticated door.
CREATE TABLE IF NOT EXISTS auth_window (
  bucket_key   TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  attempts     INTEGER NOT NULL,
  PRIMARY KEY (bucket_key, window_start)
);

-- A per-deployment random value, minted once at migration time.
--
-- Its ONLY job is to make prelogin's decoy salts for nonexistent tenants deterministic without
-- being predictable to a remote caller (see handlePrelogin). It grants no read access to
-- anything: an attacker who can read this table can read login_credential in the same dump and
-- has no need to enumerate tenants through prelogin. gen_random_uuid() draws from the server's
-- CSPRNG (pg_strong_random); two of them give ~244 bits of key material.
CREATE TABLE IF NOT EXISTS deployment_secret (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  secret     TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO deployment_secret (id, secret)
  SELECT 1, gen_random_uuid()::text || gen_random_uuid()::text
  ON CONFLICT (id) DO NOTHING;
