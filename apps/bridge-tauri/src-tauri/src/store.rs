//! Local sync state — Rust port of `packages/sync/src/store.ts` (Milestone 2).
//!
//! Watermarks, section hashes, the Tally probe cache, and the outbox, backed by a single rusqlite
//! `Connection`. Everything here is disposable: Tally is the source of truth and the server is a
//! derivative cache, so the worst case for losing this file is a full re-sync, not data loss. That
//! fact is what lets the whole design be relaxed about local durability.
//!
//! The engine that drives this store lands in a later milestone; for now nothing in `src` calls
//! these methods, hence the module-wide `dead_code` allow.
#![allow(dead_code)]

use rusqlite::{params, Connection, OptionalExtension};

/// Highest AlterID pair seen for a company. `Dr negative, Cr positive` etc. live upstream; this is
/// pure bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watermark {
    pub company_guid: String,
    pub alt_mst_id: i64,
    pub alt_vch_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub id: i64,
    pub company_guid: String,
    pub section: String,
    pub as_of: String,
    /// Already-encrypted envelope bytes. Never plaintext at rest — stored as a BLOB rather than
    /// the TS side's TEXT because the encrypted payload is bytes, not a string, on this side.
    pub payload: Vec<u8>,
    pub content_hash: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quirks {
    pub quirks_schema_version: i64,
    pub tally_version: String,
    pub probed_at: i64,
    pub json: String,
}

// Identical to `packages/sync/src/store.ts` SCHEMA, with one deliberate divergence: `outbox.payload`
// is BLOB here (the payload is already-encrypted bytes on the Rust side) where the TS store used
// TEXT. Column names, keys, and the ux_outbox unique index are byte-for-byte the same.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS watermark (
  company_guid TEXT PRIMARY KEY,
  alt_mst_id   INTEGER NOT NULL,
  alt_vch_id   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

-- Keyed by (company, section, as_of) -- NOT by section alone. Keying on section alone would
-- collide the moment the as-of date rolls over midnight, and the gate would skip the first
-- sync of every new day.
CREATE TABLE IF NOT EXISTS section_hash (
  company_guid TEXT NOT NULL,
  section      TEXT NOT NULL,
  as_of        TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  acked_at     INTEGER NOT NULL,
  PRIMARY KEY (company_guid, section, as_of)
);

CREATE TABLE IF NOT EXISTS quirks (
  id                    INTEGER PRIMARY KEY CHECK (id = 1),
  quirks_schema_version INTEGER NOT NULL,
  tally_version         TEXT NOT NULL,
  probed_at             INTEGER NOT NULL,
  json                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  company_guid    TEXT NOT NULL,
  section         TEXT NOT NULL,
  as_of           TEXT NOT NULL,
  payload         BLOB NOT NULL,
  content_hash    TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);

-- THE UNIQUE INDEX IS THE DESIGN.
--
-- Re-enqueueing a section SUPERSEDES the pending row instead of appending. So a laptop offline
-- for a week holds exactly one current row per section, not 700 stale snapshots -- queue depth
-- is bounded by SCHEMA SIZE, not by outage duration. Without this, a fortnight in a drawer
-- would produce an upload storm of obsolete data on reconnect.
CREATE UNIQUE INDEX IF NOT EXISTS ux_outbox ON outbox (company_guid, section, as_of);
";

pub struct SyncStore {
    conn: Connection,
}

impl SyncStore {
    /// Open (or create) the store at `path`. Pass `":memory:"` for an ephemeral test database.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // WAL: the Bridge is killed abruptly (machine sleep, power cut, force-quit) far more often
        // than it exits cleanly. (A no-op on an in-memory db, which stays MEMORY-journaled.)
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(SyncStore { conn })
    }

    // -------------------------------------------------------------- watermarks

    pub fn get_watermark(&self, company_guid: &str) -> Option<Watermark> {
        self.conn
            .query_row(
                "SELECT company_guid, alt_mst_id, alt_vch_id FROM watermark WHERE company_guid = ?1",
                params![company_guid],
                |r| {
                    Ok(Watermark {
                        company_guid: r.get(0)?,
                        alt_mst_id: r.get(1)?,
                        alt_vch_id: r.get(2)?,
                    })
                },
            )
            .optional()
            .expect("get_watermark")
    }

    pub fn set_watermark(&self, w: &Watermark, now: i64) {
        self.conn
            .execute(
                "INSERT INTO watermark (company_guid, alt_mst_id, alt_vch_id, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (company_guid) DO UPDATE SET
                   alt_mst_id = ?2, alt_vch_id = ?3, updated_at = ?4",
                params![w.company_guid, w.alt_mst_id, w.alt_vch_id, now],
            )
            .expect("set_watermark");
    }

    /// Used when a full resync is forced — the stored hashes are no longer trustworthy either.
    pub fn reset_company(&self, company_guid: &str) {
        let tx = self.conn.unchecked_transaction().expect("reset_company tx");
        tx.execute("DELETE FROM watermark WHERE company_guid = ?1", params![company_guid])
            .expect("reset_company watermark");
        tx.execute("DELETE FROM section_hash WHERE company_guid = ?1", params![company_guid])
            .expect("reset_company section_hash");
        tx.execute("DELETE FROM outbox WHERE company_guid = ?1", params![company_guid])
            .expect("reset_company outbox");
        tx.commit().expect("reset_company commit");
    }

    /// Full local reset for "start over": drop EVERY company's sync state so the next cycle
    /// re-extracts everything from Tally under the new identity. Without clearing watermarks the
    /// AlterID gate would report "nothing changed" and write no new snapshots — leaving only the
    /// old identity's snapshots, which the new identity cannot decrypt. Section hashes (the upload
    /// gate) and the outbox (uploads sealed to the discarded identity) go too. The Tally
    /// capability probe is KEPT: it describes the Tally install, not the identity.
    pub fn reset(&self) {
        let tx = self.conn.unchecked_transaction().expect("reset tx");
        tx.execute("DELETE FROM watermark", []).expect("reset watermark");
        tx.execute("DELETE FROM section_hash", []).expect("reset section_hash");
        tx.execute("DELETE FROM outbox", []).expect("reset outbox");
        tx.commit().expect("reset commit");
    }

    // -------------------------------------------------------------- section hashes

    pub fn get_section_hash(&self, company_guid: &str, section: &str, as_of: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT content_hash FROM section_hash WHERE company_guid = ?1 AND section = ?2 AND as_of = ?3",
                params![company_guid, section, as_of],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .expect("get_section_hash")
    }

    /// Record a hash as uploaded.
    ///
    /// CALL THIS ON ACK, NEVER ON SEND. Advancing on send means a crash between send and ack loses
    /// that section permanently and silently: the gate would believe it was uploaded and skip it
    /// forever, and the dashboard would show a stale figure with a green checkmark.
    pub fn ack_section_hash(&self, company_guid: &str, section: &str, as_of: &str, hash: &str, now: i64) {
        self.conn
            .execute(
                "INSERT INTO section_hash (company_guid, section, as_of, content_hash, acked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (company_guid, section, as_of) DO UPDATE SET
                   content_hash = excluded.content_hash, acked_at = excluded.acked_at",
                params![company_guid, section, as_of, hash, now],
            )
            .expect("ack_section_hash");
    }

    // -------------------------------------------------------------- quirks cache

    pub fn get_quirks(&self) -> Option<Quirks> {
        self.conn
            .query_row(
                "SELECT quirks_schema_version, tally_version, probed_at, json FROM quirks WHERE id = 1",
                [],
                |r| {
                    Ok(Quirks {
                        quirks_schema_version: r.get(0)?,
                        tally_version: r.get(1)?,
                        probed_at: r.get(2)?,
                        json: r.get(3)?,
                    })
                },
            )
            .optional()
            .expect("get_quirks")
    }

    pub fn set_quirks(&self, q: &Quirks) {
        self.conn
            .execute(
                "INSERT INTO quirks (id, quirks_schema_version, tally_version, probed_at, json)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT (id) DO UPDATE SET
                   quirks_schema_version = ?1, tally_version = ?2, probed_at = ?3, json = ?4",
                params![q.quirks_schema_version, q.tally_version, q.probed_at, q.json],
            )
            .expect("set_quirks");
    }

    // -------------------------------------------------------------- outbox

    /// Enqueue a section, superseding any pending row for the same (company, section, as_of).
    ///
    /// Note `attempts` resets to 0 on supersede: this is NEW data, so it deserves a fresh retry
    /// budget rather than inheriting the backoff of the stale payload it replaced.
    pub fn enqueue(
        &self,
        company_guid: &str,
        section: &str,
        as_of: &str,
        payload: &[u8],
        content_hash: &str,
        now: i64,
    ) {
        self.conn
            .execute(
                "INSERT INTO outbox (company_guid, section, as_of, payload, content_hash,
                                     attempts, next_attempt_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)
                 ON CONFLICT (company_guid, section, as_of) DO UPDATE SET
                   payload = excluded.payload,
                   content_hash = excluded.content_hash,
                   attempts = 0,
                   next_attempt_at = excluded.next_attempt_at",
                params![company_guid, section, as_of, payload, content_hash, now],
            )
            .expect("enqueue");
    }

    /// Rows due for an upload attempt, oldest first.
    pub fn due(&self, now: i64, limit: i64) -> Vec<OutboxRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, company_guid, section, as_of, payload, content_hash, attempts,
                        next_attempt_at, created_at
                 FROM outbox WHERE next_attempt_at <= ?1 ORDER BY created_at ASC LIMIT ?2",
            )
            .expect("due prepare");
        let rows = stmt
            .query_map(params![now, limit], |r| {
                Ok(OutboxRow {
                    id: r.get(0)?,
                    company_guid: r.get(1)?,
                    section: r.get(2)?,
                    as_of: r.get(3)?,
                    payload: r.get(4)?,
                    content_hash: r.get(5)?,
                    attempts: r.get(6)?,
                    next_attempt_at: r.get(7)?,
                    created_at: r.get(8)?,
                })
            })
            .expect("due query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("due collect");
        rows
    }

    /// Remove a row that has been ACKed — but ONLY if it still holds the data that was ACKed.
    ///
    /// The `content_hash` predicate is load-bearing, and the reason is the unique index. A
    /// supersede is an UPSERT, so the fresh row INHERITS THE ROWID of the row it replaced.
    /// Deleting by id alone therefore deletes whatever is sitting at that id *now*:
    ///
    /// ```text
    ///   drain reads id=1 (h1)        -> upload(payload1) in flight...
    ///   another cycle enqueues h2    -> supersedes IN PLACE, still id=1
    ///   upload(payload1) returns ok  -> ack(h1); dequeue(1)   <-- h2 deleted, never sent
    /// ```
    ///
    /// Nothing errors. h2 was never uploaded and is no longer queued, and the cycle that produced
    /// it already advanced the watermark — so it is never extracted again either. That is a
    /// section silently DROPPED rather than superseded, which is precisely what the unique index
    /// exists to promise cannot happen. With the predicate, the stale ack is a no-op and h2 simply
    /// drains on the next pass.
    pub fn dequeue(&self, id: i64, content_hash: &str) {
        self.conn
            .execute(
                "DELETE FROM outbox WHERE id = ?1 AND content_hash = ?2",
                params![id, content_hash],
            )
            .expect("dequeue");
    }

    /// Record a failed attempt and schedule the next one.
    ///
    /// Guarded by content_hash for the same reason as `dequeue`, in the failure direction: a
    /// supersede deliberately resets `attempts` to 0 because it is NEW data deserving a fresh
    /// retry budget. A late defer from the upload it replaced would otherwise hand the fresh
    /// payload the dead one's backoff — up to an hour of staleness the new data never earned.
    pub fn defer_attempt(&self, id: i64, next_attempt_at: i64, content_hash: &str) {
        self.conn
            .execute(
                "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ?1
                 WHERE id = ?2 AND content_hash = ?3",
                params![next_attempt_at, id, content_hash],
            )
            .expect("defer_attempt");
    }

    /// Void a company's watermark, and only the watermark.
    ///
    /// The narrow tool that `reset_company` is too blunt for. It exists so an abandoned upload can
    /// RE-ARM EXTRACTION on the next cycle: the section hash is not the only gate, and a dropped
    /// row whose watermark has already advanced is never re-extracted at all — decideGate skips
    /// the company before extract() is ever reached.
    ///
    /// This leaves hashes and queued rows in place, but a missing watermark makes decideGate
    /// return `full`, and runCycle's full path then calls `reset_company()` — so the hashes DO get
    /// cleared and the next cycle re-pulls and re-uploads every section, not just the one that
    /// failed. That is the deliberate trade: correct-but-slow on an install that has already
    /// proven it cannot deliver, rather than quietly frozen.
    pub fn invalidate_watermark(&self, company_guid: &str) {
        self.conn
            .execute("DELETE FROM watermark WHERE company_guid = ?1", params![company_guid])
            .expect("invalidate_watermark");
    }

    pub fn depth(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) AS n FROM outbox", [], |r| r.get(0))
            .expect("depth")
    }
}

/// Exponential backoff with jitter.
///
/// The jitter is not decoration. These installs share failure modes at a granularity that matters:
/// one office NAT, one broadband outage, one power cut, one municipal supply coming back at the
/// same instant. Without jitter every Bridge in the building retries in lockstep.
///
/// `random` returns a value in `[0, 1)` (mirrors JS `Math.random`). Using f64 throughout means an
/// absurd `attempts` yields `f64::INFINITY` from `powi`, which `min` tames to the 1h cap — never
/// NaN, so `next_attempt_at` can never be poisoned into a permanently-un-due row.
pub fn backoff_ms(attempts: i32, random: impl FnOnce() -> f64) -> i64 {
    let base = (2f64.powi(attempts) * 30_000.0).min(3_600_000.0);
    let jitter = 1.0 + (random() * 0.5 - 0.25); // +/-25%
    (base * jitter).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_752_600_000_000;

    fn store() -> SyncStore {
        SyncStore::open(":memory:").expect("open")
    }

    // (a) Re-enqueue supersedes: 700 enqueues of the same key => depth 1, newest payload wins.
    #[test]
    fn re_enqueue_supersedes() {
        let s = store();
        for i in 0..700 {
            let payload = format!("{{\"ct\":\"v{i}\"}}");
            let hash = format!("h{i}");
            s.enqueue("guid-a", "group_balance", "2026-07-16", payload.as_bytes(), &hash, NOW + i);
        }
        assert_eq!(s.depth(), 1, "700 enqueues of the same section => 1 row");
        let due = s.due(i64::MAX, 20);
        assert_eq!(due[0].payload, b"{\"ct\":\"v699\"}", "and it is the LATEST, not the first");
        assert_eq!(due[0].content_hash, "h699");
    }

    #[test]
    fn distinct_keys_keep_own_rows() {
        let s = store();
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);
        s.enqueue("guid-a", "cash_bank", "2026-07-16", b"p", "h", NOW);
        s.enqueue("guid-a", "group_balance", "2026-07-17", b"p", "h", NOW);
        s.enqueue("guid-b", "group_balance", "2026-07-16", b"p", "h", NOW);
        assert_eq!(s.depth(), 4);
    }

    // (b) A stale-hash dequeue must NOT delete the superseding-newer row.
    #[test]
    fn stale_dequeue_does_not_drop_superseding_row() {
        let s = store();
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"old", "h1", NOW);
        let in_flight = s.due(NOW, 20).remove(0);
        assert_eq!(in_flight.content_hash, "h1");

        // A concurrent cycle supersedes with fresher data while the upload is in flight.
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"new", "h2", NOW + 1);

        // The in-flight upload of the OLD payload now ACKs and tries to dequeue by its stale hash.
        s.dequeue(in_flight.id, &in_flight.content_hash);

        let left = s.due(NOW + 10, 20);
        assert_eq!(left.len(), 1, "the superseding row must survive an ack of the row it replaced");
        assert_eq!(left[0].content_hash, "h2");
        assert_eq!(left[0].payload, b"new");
    }

    // Failure-path twin of (b): a stale defer must not push back the fresh row.
    #[test]
    fn stale_defer_does_not_delay_fresh_row() {
        let s = store();
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h1", NOW);
        let in_flight = s.due(NOW, 20).remove(0);
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h2", NOW + 1);
        s.defer_attempt(in_flight.id, NOW + 3_600_000, &in_flight.content_hash);

        let due = s.due(NOW + 10, 20);
        assert_eq!(due.len(), 1, "the fresh row is still due now, not in an hour");
        assert_eq!(due[0].content_hash, "h2");
        assert_eq!(due[0].attempts, 0, "and keeps its fresh retry budget");
    }

    // (c) due() returns only next_attempt_at<=now, oldest first, respecting the limit.
    #[test]
    fn due_respects_schedule_order_and_limit() {
        let s = store();
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);
        let r = s.due(NOW, 20).remove(0);
        s.defer_attempt(r.id, NOW + 60_000, &r.content_hash);
        assert_eq!(s.due(NOW, 20).len(), 0, "deferred out of reach");
        assert_eq!(s.due(NOW + 59_999, 20).len(), 0);
        assert_eq!(s.due(NOW + 60_000, 20).len(), 1, "due exactly at the boundary");

        // Ordering + limit: three sections, ascending created_at; limit clips to the oldest two.
        let s2 = store();
        s2.enqueue("guid-a", "s_c", "d", b"p", "h", NOW + 2);
        s2.enqueue("guid-a", "s_a", "d", b"p", "h", NOW + 0);
        s2.enqueue("guid-a", "s_b", "d", b"p", "h", NOW + 1);
        let two = s2.due(i64::MAX, 2);
        assert_eq!(two.len(), 2, "limit respected");
        assert_eq!(two[0].section, "s_a", "oldest first");
        assert_eq!(two[1].section, "s_b");
    }

    #[test]
    fn defer_increments_attempts() {
        let s = store();
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);
        let r = s.due(NOW, 20).remove(0);
        s.defer_attempt(r.id, 0, &r.content_hash);
        s.defer_attempt(r.id, 0, &r.content_hash);
        assert_eq!(s.due(NOW, 20)[0].attempts, 2);
    }

    // (d) set_watermark upsert + get_watermark round-trip.
    #[test]
    fn watermark_round_trip_and_upsert() {
        let s = store();
        assert_eq!(s.get_watermark("guid-a"), None);
        s.set_watermark(
            &Watermark { company_guid: "guid-a".into(), alt_mst_id: 1, alt_vch_id: 2 },
            NOW,
        );
        assert_eq!(
            s.get_watermark("guid-a"),
            Some(Watermark { company_guid: "guid-a".into(), alt_mst_id: 1, alt_vch_id: 2 })
        );
        s.set_watermark(
            &Watermark { company_guid: "guid-a".into(), alt_mst_id: 9, alt_vch_id: 9 },
            NOW,
        );
        assert_eq!(
            s.get_watermark("guid-a"),
            Some(Watermark { company_guid: "guid-a".into(), alt_mst_id: 9, alt_vch_id: 9 })
        );
    }

    // (f) ack_section_hash / get_section_hash round-trip, keyed by as_of (no midnight collision).
    #[test]
    fn section_hash_round_trip_keyed_by_as_of() {
        let s = store();
        s.ack_section_hash("guid-a", "group_balance", "2026-07-16", "h-yesterday", NOW);
        assert_eq!(
            s.get_section_hash("guid-a", "group_balance", "2026-07-16").as_deref(),
            Some("h-yesterday")
        );
        assert_eq!(
            s.get_section_hash("guid-a", "group_balance", "2026-07-17"),
            None,
            "a new day must not inherit yesterday's hash"
        );
    }

    // (e) reset_company clears only that company.
    #[test]
    fn reset_company_scopes_to_one_company() {
        let s = store();
        s.set_watermark(&Watermark { company_guid: "guid-a".into(), alt_mst_id: 1, alt_vch_id: 1 }, NOW);
        s.set_watermark(&Watermark { company_guid: "guid-b".into(), alt_mst_id: 1, alt_vch_id: 1 }, NOW);
        s.ack_section_hash("guid-a", "group_balance", "2026-07-16", "h", NOW);
        s.ack_section_hash("guid-b", "group_balance", "2026-07-16", "h", NOW);
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);
        s.enqueue("guid-b", "group_balance", "2026-07-16", b"p", "h", NOW);

        s.reset_company("guid-a");

        assert_eq!(s.get_watermark("guid-a"), None);
        assert_eq!(s.get_section_hash("guid-a", "group_balance", "2026-07-16"), None);
        assert!(s.get_watermark("guid-b").is_some(), "the other company is untouched");
        assert_eq!(
            s.get_section_hash("guid-b", "group_balance", "2026-07-16").as_deref(),
            Some("h")
        );
        assert_eq!(s.depth(), 1);
    }

    #[test]
    fn reset_clears_everything() {
        let s = store();
        s.set_watermark(&Watermark { company_guid: "guid-a".into(), alt_mst_id: 1, alt_vch_id: 1 }, NOW);
        s.set_watermark(&Watermark { company_guid: "guid-b".into(), alt_mst_id: 1, alt_vch_id: 1 }, NOW);
        s.ack_section_hash("guid-a", "group_balance", "2026-07-16", "h", NOW);
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);
        s.enqueue("guid-b", "group_balance", "2026-07-16", b"p", "h", NOW);

        s.reset();

        assert_eq!(s.get_watermark("guid-a"), None);
        assert_eq!(s.get_watermark("guid-b"), None);
        assert_eq!(s.get_section_hash("guid-a", "group_balance", "2026-07-16"), None);
        assert_eq!(s.depth(), 0, "the outbox is empty");
    }

    #[test]
    fn invalidate_watermark_leaves_the_rest() {
        let s = store();
        s.set_watermark(&Watermark { company_guid: "guid-a".into(), alt_mst_id: 1, alt_vch_id: 1 }, NOW);
        s.ack_section_hash("guid-a", "group_balance", "2026-07-16", "h", NOW);
        s.enqueue("guid-a", "group_balance", "2026-07-16", b"p", "h", NOW);

        s.invalidate_watermark("guid-a");

        assert_eq!(s.get_watermark("guid-a"), None);
        assert_eq!(s.get_section_hash("guid-a", "group_balance", "2026-07-16").as_deref(), Some("h"));
        assert_eq!(s.depth(), 1, "hashes and queued rows survive");
    }

    #[test]
    fn quirks_round_trip_single_row() {
        let s = store();
        s.set_quirks(&Quirks { quirks_schema_version: 1, tally_version: "3.0".into(), probed_at: NOW, json: "{\"a\":1}".into() });
        s.set_quirks(&Quirks { quirks_schema_version: 1, tally_version: "4.0".into(), probed_at: NOW, json: "{\"a\":2}".into() });
        let q = s.get_quirks().expect("quirks");
        assert_eq!(q.tally_version, "4.0");
        assert_eq!(q.json, "{\"a\":2}");
    }

    // (g) backoff grows exponentially, caps at 1h, and stays finite for absurd attempt counts.
    #[test]
    fn backoff_grows_and_caps() {
        let no_jitter = || 0.5; // 1 + (0.5*0.5 - 0.25) = 1.0
        assert_eq!(backoff_ms(1, no_jitter), 60_000);
        assert_eq!(backoff_ms(2, no_jitter), 120_000);
        assert_eq!(backoff_ms(3, no_jitter), 240_000);
        assert_eq!(backoff_ms(20, no_jitter), 3_600_000, "capped at 1h");

        // Jitter bounds: deterministic 0.0 and 1.0 give the +/-25% edges.
        assert_eq!(backoff_ms(2, || 0.0), 90_000); // 120s * 0.75
        assert_eq!(backoff_ms(2, || 1.0), 150_000); // 120s * 1.25

        // Absurd attempts stay finite and within the capped +/-25% window (never NaN/Infinity).
        for n in [0, 1, 12, 64, 1024, 1_000_000_000] {
            let ms = backoff_ms(n, || 0.5);
            assert!(ms > 0 && ms <= (3_600_000.0 * 1.25) as i64, "attempts={n} produced {ms}");
        }
    }
}
