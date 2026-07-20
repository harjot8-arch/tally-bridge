import Database from 'better-sqlite3';
import type { IsoDate, Section } from '@tally-bridge/core';
import type { Watermark } from './gate.ts';

/**
 * Local state: watermarks, section hashes, probe cache, and the outbox.
 *
 * Everything here is disposable. Tally is the source of truth and the server is a derivative
 * cache, so the worst case for losing this file is a full re-sync — not data loss. That fact is
 * what lets the whole design be relaxed about local durability.
 */

export interface OutboxRow {
  id: number;
  companyGuid: string;
  section: Section;
  asOf: IsoDate;
  /** Already-encrypted envelope JSON. Never plaintext at rest. */
  payload: string;
  contentHash: string;
  attempts: number;
  nextAttemptAt: number;
  createdAt: number;
}

const SCHEMA = `
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
  payload         TEXT NOT NULL,
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
`;

export class SyncStore {
  private readonly db: Database.Database;

  constructor(filename: string) {
    this.db = new Database(filename);
    // WAL: the Bridge is killed abruptly (machine sleep, power cut, force-quit) far more often
    // than it exits cleanly.
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  // ------------------------------------------------------------------ watermarks

  getWatermark(companyGuid: string): Watermark | undefined {
    const r = this.db
      .prepare('SELECT company_guid, alt_mst_id, alt_vch_id FROM watermark WHERE company_guid = ?')
      .get(companyGuid) as { company_guid: string; alt_mst_id: number; alt_vch_id: number } | undefined;
    if (!r) return undefined;
    return { companyGuid: r.company_guid, altMstId: r.alt_mst_id, altVchId: r.alt_vch_id };
  }

  setWatermark(w: Watermark, now: number): void {
    this.db
      .prepare(
        `INSERT INTO watermark (company_guid, alt_mst_id, alt_vch_id, updated_at)
         VALUES (@companyGuid, @altMstId, @altVchId, @now)
         ON CONFLICT (company_guid) DO UPDATE SET
           alt_mst_id = @altMstId, alt_vch_id = @altVchId, updated_at = @now`,
      )
      .run({ ...w, now });
  }

  /** Used when a full resync is forced — the stored hashes are no longer trustworthy either. */
  resetCompany(companyGuid: string): void {
    const tx = this.db.transaction((guid: string) => {
      this.db.prepare('DELETE FROM watermark WHERE company_guid = ?').run(guid);
      this.db.prepare('DELETE FROM section_hash WHERE company_guid = ?').run(guid);
      this.db.prepare('DELETE FROM outbox WHERE company_guid = ?').run(guid);
    });
    tx(companyGuid);
  }

  // ------------------------------------------------------------------ section hashes

  getSectionHash(companyGuid: string, section: Section, asOf: IsoDate): string | undefined {
    const r = this.db
      .prepare(
        'SELECT content_hash FROM section_hash WHERE company_guid = ? AND section = ? AND as_of = ?',
      )
      .get(companyGuid, section, asOf) as { content_hash: string } | undefined;
    return r?.content_hash;
  }

  /**
   * Record a hash as uploaded.
   *
   * CALL THIS ON ACK, NEVER ON SEND. Advancing on send means a crash between send and ack
   * loses that section permanently and silently: the gate would believe it was uploaded and
   * skip it forever, and the dashboard would show a stale figure with a green checkmark.
   */
  ackSectionHash(companyGuid: string, section: Section, asOf: IsoDate, hash: string, now: number): void {
    this.db
      .prepare(
        `INSERT INTO section_hash (company_guid, section, as_of, content_hash, acked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (company_guid, section, as_of) DO UPDATE SET
           content_hash = excluded.content_hash, acked_at = excluded.acked_at`,
      )
      .run(companyGuid, section, asOf, hash, now);
  }

  // ------------------------------------------------------------------ quirks cache

  getQuirks():
    | { quirksSchemaVersion: number; tallyVersion: string; probedAt: number; json: string }
    | undefined {
    const r = this.db
      .prepare('SELECT quirks_schema_version, tally_version, probed_at, json FROM quirks WHERE id = 1')
      .get() as
      | { quirks_schema_version: number; tally_version: string; probed_at: number; json: string }
      | undefined;
    if (!r) return undefined;
    return {
      quirksSchemaVersion: r.quirks_schema_version,
      tallyVersion: r.tally_version,
      probedAt: r.probed_at,
      json: r.json,
    };
  }

  setQuirks(q: { quirksSchemaVersion: number; tallyVersion: string; probedAt: number; json: string }): void {
    this.db
      .prepare(
        `INSERT INTO quirks (id, quirks_schema_version, tally_version, probed_at, json)
         VALUES (1, @quirksSchemaVersion, @tallyVersion, @probedAt, @json)
         ON CONFLICT (id) DO UPDATE SET
           quirks_schema_version = @quirksSchemaVersion, tally_version = @tallyVersion,
           probed_at = @probedAt, json = @json`,
      )
      .run(q);
  }

  // ------------------------------------------------------------------ outbox

  /**
   * Enqueue a section, superseding any pending row for the same (company, section, as_of).
   *
   * Note `attempts` resets to 0 on supersede: this is NEW data, so it deserves a fresh retry
   * budget rather than inheriting the backoff of the stale payload it replaced.
   */
  enqueue(row: Omit<OutboxRow, 'id' | 'attempts' | 'nextAttemptAt' | 'createdAt'>, now: number): void {
    this.db
      .prepare(
        `INSERT INTO outbox (company_guid, section, as_of, payload, content_hash,
                             attempts, next_attempt_at, created_at)
         VALUES (@companyGuid, @section, @asOf, @payload, @contentHash, 0, @now, @now)
         ON CONFLICT (company_guid, section, as_of) DO UPDATE SET
           payload = excluded.payload,
           content_hash = excluded.content_hash,
           attempts = 0,
           next_attempt_at = excluded.next_attempt_at`,
      )
      .run({ ...row, now });
  }

  /** Rows due for an upload attempt, oldest first. */
  due(now: number, limit = 20): OutboxRow[] {
    const rows = this.db
      .prepare(
        `SELECT id, company_guid, section, as_of, payload, content_hash, attempts,
                next_attempt_at, created_at
         FROM outbox WHERE next_attempt_at <= ? ORDER BY created_at ASC LIMIT ?`,
      )
      .all(now, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r.id as number,
      companyGuid: r.company_guid as string,
      section: r.section as Section,
      asOf: r.as_of as IsoDate,
      payload: r.payload as string,
      contentHash: r.content_hash as string,
      attempts: r.attempts as number,
      nextAttemptAt: r.next_attempt_at as number,
      createdAt: r.created_at as number,
    }));
  }

  /**
   * Remove a row that has been ACKed — but ONLY if it still holds the data that was ACKed.
   *
   * The `content_hash` predicate is load-bearing, and the reason is the unique index. A
   * supersede is an UPSERT, so the fresh row INHERITS THE ROWID of the row it replaced.
   * Deleting by id alone therefore deletes whatever is sitting at that id *now*:
   *
   *   drain reads id=1 (h1)        -> upload(payload1) in flight...
   *   another cycle enqueues h2    -> supersedes IN PLACE, still id=1
   *   upload(payload1) returns ok  -> ack(h1); dequeue(1)   <-- h2 deleted, never sent
   *
   * Nothing errors. h2 was never uploaded and is no longer queued, and the cycle that produced
   * it already advanced the watermark — so it is never extracted again either. That is a
   * section silently DROPPED rather than superseded, which is precisely what the unique index
   * exists to promise cannot happen. With the predicate, the stale ack is a no-op and h2 simply
   * drains on the next pass.
   */
  dequeue(id: number, contentHash: string): void {
    this.db.prepare('DELETE FROM outbox WHERE id = ? AND content_hash = ?').run(id, contentHash);
  }

  /**
   * Record a failed attempt and schedule the next one.
   *
   * Guarded by content_hash for the same reason as `dequeue`, in the failure direction: a
   * supersede deliberately resets `attempts` to 0 because it is NEW data deserving a fresh
   * retry budget. A late defer from the upload it replaced would otherwise hand the fresh
   * payload the dead one's backoff — up to an hour of staleness the new data never earned.
   */
  deferAttempt(id: number, nextAttemptAt: number, contentHash: string): void {
    this.db
      .prepare(
        'UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ? WHERE id = ? AND content_hash = ?',
      )
      .run(nextAttemptAt, id, contentHash);
  }

  /**
   * Void a company's watermark, and only the watermark.
   *
   * The narrow tool that `resetCompany` is too blunt for. It exists so an abandoned upload can
   * RE-ARM EXTRACTION on the next cycle: the section hash is not the only gate, and a dropped
   * row whose watermark has already advanced is never re-extracted at all — decideGate skips
   * the company before extract() is ever reached. See the abandon path in `drainOutbox`.
   *
   * This leaves hashes and queued rows in place, but be clear about the cycle-level effect: a
   * missing watermark makes decideGate return `full`, and runCycle's full path then calls
   * `resetCompany()` — so the hashes DO get cleared and the next cycle re-pulls and re-uploads
   * every section, not just the one that failed. That is the deliberate trade: correct-but-slow
   * on an install that has already proven it cannot deliver, rather than quietly frozen.
   */
  invalidateWatermark(companyGuid: string): void {
    this.db.prepare('DELETE FROM watermark WHERE company_guid = ?').run(companyGuid);
  }

  depth(): number {
    const r = this.db.prepare('SELECT COUNT(*) AS n FROM outbox').get() as { n: number };
    return r.n;
  }
}

/**
 * Exponential backoff with jitter.
 *
 * The jitter is not decoration. These installs share failure modes at a granularity that
 * matters: one office NAT, one broadband outage, one power cut, one municipal supply coming
 * back at the same instant. Without jitter every Bridge in the building retries in lockstep.
 */
export function backoffMs(attempts: number, random: () => number = Math.random): number {
  const base = Math.min(2 ** attempts * 30_000, 3_600_000);
  const jitter = 1 + (random() * 0.5 - 0.25); // +/-25%
  return Math.round(base * jitter);
}
