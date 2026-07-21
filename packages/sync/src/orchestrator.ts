import {
  SCHEMA_VERSION,
  SECTIONS,
  type CanonicalValue,
  type IsoDate,
  type Section,
} from '@tally-bridge/core';
import { contentHashOf, makeAad, sealSection } from '@tally-bridge/crypto';
import { decideGate, shouldUpload, type GateDecision, type Watermark } from './gate.ts';
import { SyncStore, backoffMs } from './store.ts';

/**
 * The sync cycle.
 *
 * Two gates in series, and they exist for different reasons:
 *   1. AlterID  -- don't even ASK Tally (protects a single-threaded desktop app the owner is
 *                  typing into from being interrogated every 15 minutes for nothing)
 *   2. hashing  -- don't UPLOAD (protects the client's own bandwidth and Neon bill)
 *
 * Steady state for an idle company: one ~2KB round trip and nothing else.
 */

export interface ExtractedSection {
  section: Section;
  asOf: IsoDate;
  payload: CanonicalValue;
}

export interface UploadResult {
  ok: boolean;
  /** True when the failure is worth retrying (network, 5xx). False for 4xx: retrying won't help. */
  retryable: boolean;
  status?: number;
}

export interface OrchestratorDeps {
  store: SyncStore;
  /** Reads the company probe from Tally. Returns [] when Tally is closed or no company is open. */
  probeCompanies: () => Promise<Array<Watermark & { name: string }>>;
  /** Pulls the given sections for a company. */
  extract: (companyGuid: string, sections: Section[]) => Promise<ExtractedSection[]>;
  /** POSTs one sealed envelope. */
  upload: (envelopeJson: string, idempotencyKey: string) => Promise<UploadResult>;
  identityPublicKey: Uint8Array;
  /**
   * The Ed25519 device signing key — the SAME one that signs uploads via RFC 9421.
   *
   * This does not weaken the "Bridge holds no key that reads its own uploads" property, and it
   * is worth being explicit about why, because a signing key in an encryption path looks like a
   * regression at a glance. It signs; it cannot decrypt. What it buys is the property a sealed
   * box never had: a sealed box needs only `identityPublicKey`, which the SERVER also holds,
   * so without this the server could mint envelopes full of invented numbers that passed every
   * check the reader made. Confidentiality was never the gap. Authenticity was.
   */
  deviceSecretKey: Uint8Array;
  tenantId: string;
  deviceId: string;
  now: () => number;
  random?: () => number;
  log?: (event: SyncEvent) => void;
}

export type SyncEvent =
  | { kind: 'tally_unavailable' }
  | { kind: 'company_skipped'; companyGuid: string; reason: string }
  | { kind: 'gate'; companyGuid: string; decision: GateDecision }
  | { kind: 'section_unchanged'; companyGuid: string; section: Section }
  | { kind: 'section_enqueued'; companyGuid: string; section: Section }
  | { kind: 'uploaded'; companyGuid: string; section: Section }
  | { kind: 'upload_deferred'; companyGuid: string; section: Section; attempts: number }
  | { kind: 'upload_abandoned'; companyGuid: string; section: Section; attempts: number }
  | { kind: 'cycle_done'; stats: CycleStats };

export interface CycleStats {
  companiesSeen: number;
  companiesSkipped: number;
  sectionsChecked: number;
  sectionsSkippedByHash: number;
  sectionsEnqueued: number;
  uploaded: number;
  deferred: number;
}

/** Give up after roughly a day of failures and surface it rather than retrying forever. */
const MAX_ATTEMPTS = 12;

/**
 * A monotonic per-device counter bound into the AAD.
 *
 * Gaps are visible to the server and reuse is a replay signal. It is NOT a nonce — the AEAD
 * nonce is 192 bits of randomness precisely so that a counter rolling backward (backup restore,
 * cloned machine) cannot be a cryptographic break. If this counter rolls back, the worst case
 * is a duplicate seq the server can notice, not a key recovery.
 */
export class SeqCounter {
  private value: number;

  constructor(start = 0) {
    this.value = start;
  }

  next(): number {
    return ++this.value;
  }

  /**
   * Read without consuming.
   *
   * Needed so the caller can persist the counter across restarts. Without it the obvious code
   * is `store(seq.next())`, which burns a sequence number on every save — the gaps then look
   * exactly like the dropped uploads this counter exists to make visible.
   */
  get current(): number {
    return this.value;
  }
}

export async function runCycle(deps: OrchestratorDeps, seq: SeqCounter): Promise<CycleStats> {
  const stats: CycleStats = {
    companiesSeen: 0,
    companiesSkipped: 0,
    sectionsChecked: 0,
    sectionsSkippedByHash: 0,
    sectionsEnqueued: 0,
    uploaded: 0,
    deferred: 0,
  };
  const log = deps.log ?? (() => {});

  const companies = await deps.probeCompanies();

  if (companies.length === 0) {
    // Tally closed, or open with no company loaded. NOT an error — this is the normal state
    // every night and every weekend. We still drain the outbox: uploads are independent of
    // Tally being up, and a laptop that reconnects at 2am should flush.
    log({ kind: 'tally_unavailable' });
    await drainOutbox(deps, stats, log);
    log({ kind: 'cycle_done', stats });
    return stats;
  }

  for (const company of companies) {
    stats.companiesSeen++;

    const stored = deps.store.getWatermark(company.companyGuid);
    const decision = decideGate(stored, company);
    log({ kind: 'gate', companyGuid: company.companyGuid, decision });

    if (decision.action === 'skip') {
      stats.companiesSkipped++;
      log({ kind: 'company_skipped', companyGuid: company.companyGuid, reason: decision.reason });
      continue;
    }

    if (decision.action === 'full') {
      // Stored hashes are as void as the watermark: after a backup restore the server may hold
      // data that no longer matches Tally, and a hash saying "already uploaded" would keep it
      // there forever.
      deps.store.resetCompany(company.companyGuid);
    }

    // A 'full' pull is EVERY section, taken from the one canonical list in core rather than a
    // hand-maintained copy — a second copy silently drops a new section from first-sight and
    // backup-restore syncs, which is exactly how `duties_taxes` was missing here for one commit.
    const sections =
      decision.action === 'partial' ? decision.sections : ([...SECTIONS] as Section[]);

    const extracted = await deps.extract(company.companyGuid, sections);

    for (const s of extracted) {
      stats.sectionsChecked++;
      const hash = await contentHashOf(s.payload);
      const storedHash = deps.store.getSectionHash(company.companyGuid, s.section, s.asOf);

      if (!shouldUpload(storedHash, hash)) {
        stats.sectionsSkippedByHash++;
        log({ kind: 'section_unchanged', companyGuid: company.companyGuid, section: s.section });
        continue;
      }

      const aad = makeAad({
        tenantId: deps.tenantId,
        deviceId: deps.deviceId,
        companyGuid: company.companyGuid,
        section: s.section,
        asOf: s.asOf,
        snapshotTs: deps.now(),
        seq: seq.next(),
      });

      // Sealed to the identity PUBLIC key, signed with the DEVICE key. Neither parameter can
      // decrypt the result: after this line the Bridge cannot read what it just produced, and
      // the outbox therefore holds ciphertext at rest — never plaintext.
      //
      // The signature is what makes the ciphertext worth anything to the reader. Without it,
      // the server — which holds identityPublicKey, because it is the env var onboarding hands
      // the Bridge — could fabricate an envelope indistinguishable from this one.
      const envelope = await sealSection(
        s.payload,
        aad,
        deps.identityPublicKey,
        deps.deviceSecretKey,
      );

      deps.store.enqueue(
        {
          companyGuid: company.companyGuid,
          section: s.section,
          asOf: s.asOf,
          payload: JSON.stringify(envelope),
          contentHash: hash,
        },
        deps.now(),
      );
      stats.sectionsEnqueued++;
      log({ kind: 'section_enqueued', companyGuid: company.companyGuid, section: s.section });
    }

    // Advance the watermark only AFTER the sections are safely in the outbox. Advancing before
    // extraction would skip this change set forever if extraction threw.
    deps.store.setWatermark(company, deps.now());
  }

  await drainOutbox(deps, stats, log);
  log({ kind: 'cycle_done', stats });
  return stats;
}

async function drainOutbox(
  deps: OrchestratorDeps,
  stats: CycleStats,
  log: (e: SyncEvent) => void,
): Promise<void> {
  const rows = deps.store.due(deps.now());

  for (const row of rows) {
    // Idempotency key: the server upserts on this, so a retry after a lost ACK is free.
    const key = `${row.companyGuid}|${row.section}|${row.asOf}|${row.contentHash}`;
    const res = await deps.upload(row.payload, key);

    if (res.ok) {
      // ACK, and only now advance the hash. Doing this on SEND would mean a crash in between
      // loses the section permanently and silently — the gate would skip it forever after.
      deps.store.ackSectionHash(row.companyGuid, row.section, row.asOf, row.contentHash, deps.now());
      deps.store.dequeue(row.id, row.contentHash);
      stats.uploaded++;
      log({ kind: 'uploaded', companyGuid: row.companyGuid, section: row.section });
      continue;
    }

    if (!res.retryable || row.attempts + 1 >= MAX_ATTEMPTS) {
      // A 4xx means retrying THIS payload cannot help (bad device key, revoked device, quota),
      // and so does a spent retry budget. Drop it and surface.
      deps.store.dequeue(row.id, row.contentHash);

      // AND RE-ARM EXTRACTION. The comforting version of this comment used to say the data is
      // not lost because the hash was never advanced — which is true and NOT ENOUGH, because
      // the hash is not the only gate. The WATERMARK was already advanced when this section was
      // enqueued, so decideGate skips the company on the next cycle, extract() is never called,
      // and this section re-enqueues on NO cycle, healthy or not. It is gone: the owner reads a
      // number that stopped moving, under a green checkmark. Silent staleness is the worst
      // failure this system has, and dropping a row without voiding the watermark causes it.
      //
      // Voiding the watermark makes that claim true: the next cycle sees no watermark, decides
      // `full`, and pulls this company again. The cost is a full re-pull (and re-upload, since
      // the `full` path resets the hashes too) on every cycle for as long as the failure lasts
      // — real Tally load for a demonstrably broken install. That is the right way round: an
      // install that cannot deliver should be noisy and self-healing the moment the cause
      // clears, never quietly frozen behind a green checkmark.
      deps.store.invalidateWatermark(row.companyGuid);

      log({
        kind: 'upload_abandoned',
        companyGuid: row.companyGuid,
        section: row.section,
        attempts: row.attempts + 1,
      });
      continue;
    }

    deps.store.deferAttempt(
      row.id,
      deps.now() + backoffMs(row.attempts + 1, deps.random ?? Math.random),
      row.contentHash,
    );
    stats.deferred++;
    log({
      kind: 'upload_deferred',
      companyGuid: row.companyGuid,
      section: row.section,
      attempts: row.attempts + 1,
    });
  }
}

export const ORCHESTRATOR_SCHEMA_VERSION = SCHEMA_VERSION;
