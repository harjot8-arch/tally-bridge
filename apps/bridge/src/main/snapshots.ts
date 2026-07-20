import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SECTIONS, type IsoDate, type Section } from '@tally-bridge/core';
import { ROSTER_FIRST_VERSION, RosterError, type RosterMemory } from '@tally-bridge/crypto';
import { SyncStore, type OutboxRow } from '@tally-bridge/sync';

/**
 * The reader's local storage: sealed section snapshots, and the roster high-water mark.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THE DASHBOARD DOES NOT READ THE OUTBOX, AND NEEDS THIS AT ALL.
 * ------------------------------------------------------------------------------------------
 *
 * The outbox is a QUEUE, not a cache. `drainOutbox` deletes a row the moment the server ACKs
 * it — that is its correctness contract (see `dequeue` in @tally-bridge/sync) — so on a healthy
 * install the outbox is EMPTY almost all of the time. A dashboard that read only the outbox
 * would render cards for exactly the window between "sealed" and "uploaded", then go blank the
 * moment sync succeeded: the better the sync works, the less the owner sees. So the sealed
 * envelope is copied HERE at enqueue time, into a store that supersedes and never drains —
 * always the latest sealed envelope per (company, section).
 *
 * The alternative — fetching ciphertext back from the server like the web dashboard does — was
 * rejected: it makes the local dashboard need the network to show numbers that were produced on
 * this very machine, and it hands the server a lever over what the DESKTOP reader sees. Local
 * data, local storage.
 *
 * WHAT IS AT REST HERE: ciphertext. The snapshot is the same `SignedEnvelope` JSON the outbox
 * holds — sealed to the identity public key, signed by the device key. This process cannot read
 * it back; only an unlocked session (passphrase -> idSK) can. So this store adds nothing to
 * what a same-user process could already steal (which, on the Tally host, is Tally's own
 * plaintext files anyway).
 *
 * WHAT ELSE LIVES HERE: the sidecar metadata (companyGuid, section, asOf) recorded from the
 * ENQUEUE CALL — i.e. from the Bridge's own extraction request — never parsed out of the
 * envelope. That is deliberate and load-bearing: the reader builds `openSection`'s `expect`
 * from this metadata, so "what was asked for" and "what the envelope claims to be" remain two
 * independent facts that can disagree detectably. Deriving the metadata from `envelope.aad`
 * would make `expect` a copy of the thing it checks — a tautology.
 */

/** One stored snapshot: the request that produced it, plus the sealed envelope. */
export interface StoredSnapshot {
  companyGuid: string;
  section: Section;
  asOf: IsoDate;
  contentHash: string;
  storedAt: number;
  /** The `SignedEnvelope` as JSON, exactly as it was enqueued. Opaque ciphertext at rest. */
  envelope: string;
}

const SECTION_SET: ReadonlySet<string> = new Set(SECTIONS);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
/** 64 hex chars + .json — exactly what `slotFileName` produces. */
const SNAPSHOT_FILE = /^[0-9a-f]{64}\.json$/;

function isSection(s: unknown): s is Section {
  return typeof s === 'string' && SECTION_SET.has(s);
}

/**
 * Slot -> file name.
 *
 * HASHED, never interpolated. `companyGuid` comes out of a customer's Tally file and is
 * arbitrary text — `../../` is a legal Tally GUID as far as this code can know, and the
 * keystore's own header warns that the day someone keys a file by a company GUID is the day a
 * silent traversal ships. So the GUID never touches the path: the name is hex of a SHA-256.
 *
 * The digest input is `guid + '\n' + section`, which is injective because `section` is checked
 * against the closed SECTIONS set first and no section contains a newline — the LAST newline
 * therefore always splits the pair unambiguously.
 */
function slotFileName(companyGuid: string, section: Section): string {
  const h = createHash('sha256');
  h.update(companyGuid, 'utf8');
  h.update('\n');
  h.update(section, 'utf8');
  return `${h.digest('hex')}.json`;
}

/** Write-then-rename, so a crash mid-write leaves the previous snapshot, never half a file. */
function writeAtomic(dir: string, name: string, content: string): void {
  const tmp = join(dir, `${name}.tmp`);
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, join(dir, name));
}

export class SnapshotStore {
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  /**
   * Record the latest sealed envelope for a slot, superseding whatever was there.
   *
   * Last write wins with no version check, and that is sound for the same reason the outbox's
   * UPSERT is: the only writer is this process's own sync cycle, which extracts monotonically.
   * There is no server anywhere in this write path, so there is nothing here for a server to
   * roll back.
   */
  put(row: { companyGuid: string; section: Section; asOf: IsoDate; payload: string; contentHash: string }, now: number): void {
    if (typeof row.companyGuid !== 'string' || row.companyGuid.length === 0) {
      throw new Error('snapshot row has no companyGuid');
    }
    if (!isSection(row.section)) {
      throw new Error(`snapshot row has an unknown section: ${String(row.section)}`);
    }
    if (typeof row.asOf !== 'string' || !ISO_DATE.test(row.asOf)) {
      throw new Error(`snapshot row has a malformed asOf: ${String(row.asOf)}`);
    }
    if (typeof row.payload !== 'string' || row.payload.length === 0) {
      throw new Error('snapshot row has no envelope payload');
    }
    const snapshot: StoredSnapshot = {
      companyGuid: row.companyGuid,
      section: row.section,
      asOf: row.asOf,
      contentHash: row.contentHash,
      storedAt: now,
      envelope: row.payload,
    };
    writeAtomic(this.dir, slotFileName(row.companyGuid, row.section), JSON.stringify(snapshot));
  }

  /**
   * Every stored snapshot, plus a count of files that could not be read.
   *
   * `unreadable` is surfaced rather than swallowed: a corrupt file must not silently shrink the
   * dashboard. It is a COUNT rather than a throw because one damaged file must not blank the
   * other six cards — the reader marks the result incomplete instead.
   */
  list(): { slots: StoredSnapshot[]; unreadable: number } {
    const slots: StoredSnapshot[] = [];
    let unreadable = 0;
    for (const name of readdirSync(this.dir)) {
      // Exactly the shape slotFileName emits. This skips .tmp leftovers from a crash mid-write
      // AND any other tenant of the directory (the roster mark file lives here too).
      if (!SNAPSHOT_FILE.test(name)) continue;
      const parsed = this.readOne(join(this.dir, name));
      if (parsed) slots.push(parsed);
      else unreadable++;
    }
    return { slots, unreadable };
  }

  private readOne(path: string): StoredSnapshot | undefined {
    let doc: unknown;
    try {
      doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      return undefined;
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return undefined;
    const d = doc as Partial<StoredSnapshot>;
    // The metadata read back must satisfy exactly what `put` enforced: it is what the reader's
    // `expect` is built from, so a field that fails these checks is a slot with no statable
    // expectation — refused, not defaulted.
    if (typeof d.companyGuid !== 'string' || d.companyGuid.length === 0) return undefined;
    if (!isSection(d.section)) return undefined;
    if (typeof d.asOf !== 'string' || !ISO_DATE.test(d.asOf)) return undefined;
    if (typeof d.envelope !== 'string' || d.envelope.length === 0) return undefined;
    return {
      companyGuid: d.companyGuid,
      section: d.section,
      asOf: d.asOf,
      contentHash: typeof d.contentHash === 'string' ? d.contentHash : '',
      storedAt: typeof d.storedAt === 'number' ? d.storedAt : 0,
      envelope: d.envelope,
    };
  }

  /** Used by "reset dashboard": a new identity cannot read the old snapshots anyway. */
  clear(): void {
    for (const name of readdirSync(this.dir)) {
      if (SNAPSHOT_FILE.test(name) || name.endsWith('.tmp')) rmSync(join(this.dir, name));
    }
  }
}

/**
 * A SyncStore that also mirrors every enqueued envelope into the snapshot store.
 *
 * A SUBCLASS rather than a wrapper object, because `SyncStore` has private members and TypeScript
 * therefore refuses a structural stand-in — which is a feature: the orchestrator keeps its exact
 * store type and this class cannot drift from it.
 *
 * The capture is NOT wrapped in a try/catch. If the snapshot cannot be written (disk full,
 * permissions), the enqueue throws, the cycle fails, and the tray goes red — noisy and
 * self-healing, per the house rule that an install that cannot deliver must never be quietly
 * frozen behind a green checkmark. The alternative (swallow, keep syncing) produces a dashboard
 * whose numbers silently stop moving while the status says "Synced", which is the worst failure
 * this system can have. The watermark has not advanced when enqueue throws, so the next cycle
 * re-extracts and retries the capture.
 *
 * Capture happens BEFORE the outbox insert so the snapshot is never behind the outbox; whichever
 * of the two writes fails, the next cycle's re-extraction supersedes both.
 */
export class CapturingSyncStore extends SyncStore {
  private readonly snapshots: SnapshotStore;

  constructor(filename: string, snapshots: SnapshotStore) {
    super(filename);
    this.snapshots = snapshots;
  }

  override enqueue(row: Omit<OutboxRow, 'id' | 'attempts' | 'nextAttemptAt' | 'createdAt'>, now: number): void {
    this.snapshots.put(row, now);
    super.enqueue(row, now);
  }
}

/* ------------------------------------------------------------------ *
 * Roster rollback memory — the high-water mark, persisted.
 * ------------------------------------------------------------------ */

interface MarkDoc {
  v: 1;
  /** base64 of the identity PUBLIC key this mark belongs to. */
  idPK: string;
  highestVersionSeen: number;
}

const MARK_FILE = 'roster-mark.json';

/**
 * Persists `highestVersionSeen` — the whole of the rollback defence (see `RosterMemory` in
 * @tally-bridge/crypto). This lives on local disk under the app's userData, which the server
 * cannot write: the adversary who rolls a wrapped-key blob back holds the database, not this
 * machine. (An adversary ON this machine reads Tally's plaintext directly and is out of scope —
 * ARCHITECTURE.md.)
 *
 * KEYED BY IDENTITY PUBLIC KEY, because "reset dashboard" mints a new identity whose roster
 * legitimately starts at version 1 again. A bare global mark would refuse the new identity's
 * first bundle forever; a mark scoped to the old idPK simply stops applying. A mark for a
 * DIFFERENT idPK therefore reads as first-use, which is correct and not a rollback hole: the
 * mark's job is per-identity freshness, and a new identity is a genuinely fresh reader.
 *
 * CORRUPTION FAILS CLOSED. A file that exists but does not parse — or parses to a version that
 * is not an integer >= 1 — throws rather than degrading to first-use. "Unreadable memory" and
 * "no memory" must not look the same (the same rule `acceptRosterVersion` applies to the value
 * it is handed): degrading would let anything that can scribble one byte into this file reset
 * the rollback defence to zero. Recovering from a genuinely damaged disk is a deliberate,
 * visible act (reset dashboard), not a default.
 */
export class RosterMarkStore {
  private readonly path: string;
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
    this.path = join(dir, MARK_FILE);
    mkdirSync(dir, { recursive: true });
  }

  load(idPkB64: string): RosterMemory {
    let raw: string;
    try {
      raw = readFileSync(this.path, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'first-use' };
      // Unreadable is not absent. EACCES/EIO here means this reader's memory exists and cannot
      // be consulted, and pretending otherwise re-opens the rollback window.
      throw new RosterError('the roster high-water mark exists but cannot be read');
    }
    let doc: unknown;
    try {
      doc = JSON.parse(raw);
    } catch {
      throw new RosterError('the roster high-water mark is not valid JSON: refusing to treat unreadable memory as no memory');
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
      throw new RosterError('the roster high-water mark is malformed');
    }
    const d = doc as Partial<MarkDoc>;
    if (d.v !== 1 || typeof d.idPK !== 'string') {
      throw new RosterError('the roster high-water mark is malformed');
    }
    if (d.idPK !== idPkB64) {
      // A mark for another identity: this identity has never been opened here. First use,
      // honestly named.
      return { kind: 'first-use' };
    }
    if (!Number.isSafeInteger(d.highestVersionSeen) || (d.highestVersionSeen as number) < ROSTER_FIRST_VERSION) {
      // NaN, floats, negatives: all of these compare uselessly and must not become the mark.
      throw new RosterError(
        `the stored roster high-water mark is not an integer >= ${ROSTER_FIRST_VERSION}: refusing`,
      );
    }
    return { kind: 'seen', highestVersionSeen: d.highestVersionSeen as number };
  }

  save(idPkB64: string, highestVersionSeen: number): void {
    if (typeof idPkB64 !== 'string' || idPkB64.length === 0) {
      throw new RosterError('cannot save a roster mark without an identity public key');
    }
    if (!Number.isSafeInteger(highestVersionSeen) || highestVersionSeen < ROSTER_FIRST_VERSION) {
      throw new RosterError(`refusing to save a roster mark of ${String(highestVersionSeen)}`);
    }
    // MONOTONIC: never lower an existing mark for the same identity. `openIdentity` already
    // refuses a version below the memory it was given, so on the happy path this is redundant —
    // it exists so that no OTHER caller of save() can ever regress the mark, and so a test can
    // prove the property against this class alone.
    let current: RosterMemory | undefined;
    try {
      current = this.load(idPkB64);
    } catch {
      // Corrupt existing mark: overwriting it with a valid one is the one legitimate repair,
      // and it can only make the defence stronger than "throw forever".
      current = undefined;
    }
    if (current?.kind === 'seen' && highestVersionSeen < current.highestVersionSeen) {
      throw new RosterError(
        `refusing to lower the roster high-water mark from ${current.highestVersionSeen} to ${highestVersionSeen}`,
      );
    }
    const doc: MarkDoc = { v: 1, idPK: idPkB64, highestVersionSeen };
    writeAtomic(this.dir, MARK_FILE, JSON.stringify(doc));
  }
}
