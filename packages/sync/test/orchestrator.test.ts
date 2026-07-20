import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { generateIdentity, openSection, sodiumReady } from '@tally-bridge/crypto';
import type { SealedEnvelope } from '@tally-bridge/core';
import { SyncStore, backoffMs } from '../src/store.ts';
import {
  SeqCounter,
  runCycle,
  type ExtractedSection,
  type OrchestratorDeps,
  type SyncEvent,
  type UploadResult,
} from '../src/orchestrator.ts';

function tmpStore(): { store: SyncStore; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'tally-sync-'));
  const store = new SyncStore(join(dir, 'sync.db'));
  return {
    store,
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

interface Harness {
  deps: OrchestratorDeps;
  seq: SeqCounter;
  events: SyncEvent[];
  uploads: Array<{ envelopeJson: string; key: string }>;
  setCompanies: (c: Array<{ companyGuid: string; name: string; altMstId: number; altVchId: number }>) => void;
  setSections: (s: ExtractedSection[]) => void;
  setUploadResult: (r: UploadResult) => void;
  /** Advance the fake clock. Backoff is real, so retries need time to pass. */
  advance: (ms: number) => void;
  extractCalls: number;
  identity: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** The Bridge's Ed25519 device key. Signs envelopes; cannot read them. */
  device: { deviceId: string; publicKey: Uint8Array; secretKey: Uint8Array };
  cleanup: () => void;
}

async function harness(): Promise<Harness> {
  const { store, cleanup } = tmpStore();
  const identity = await generateIdentity();
  const sodium = await sodiumReady();
  const kp = sodium.crypto_sign_keypair();
  const device = { deviceId: 'dev_1', publicKey: kp.publicKey, secretKey: kp.privateKey };
  const events: SyncEvent[] = [];
  const uploads: Array<{ envelopeJson: string; key: string }> = [];

  let companies = [{ companyGuid: 'guid-acme', name: 'Acme', altMstId: 100, altVchId: 200 }];
  let sections: ExtractedSection[] = [
    { section: 'group_balance', asOf: '2026-07-16', payload: { rows: [{ g: 'Cash', amt: '100.00' }] } },
  ];
  let uploadResult: UploadResult = { ok: true, retryable: false };
  let clock = 1_752_600_000_000;

  const h: Harness = {
    events,
    uploads,
    identity,
    device,
    extractCalls: 0,
    seq: new SeqCounter(),
    setCompanies: (c) => {
      companies = c;
    },
    setSections: (s) => {
      sections = s;
    },
    setUploadResult: (r) => {
      uploadResult = r;
    },
    advance: (ms) => {
      clock += ms;
    },
    cleanup,
    deps: {
      store,
      probeCompanies: async () => companies,
      extract: async () => {
        h.extractCalls++;
        return sections;
      },
      upload: async (envelopeJson, key) => {
        uploads.push({ envelopeJson, key });
        return uploadResult;
      },
      identityPublicKey: identity.publicKey,
      deviceSecretKey: device.secretKey,
      tenantId: 'tnt_1',
      deviceId: device.deviceId,
      now: () => clock,
      random: () => 0.5,
      log: (e) => events.push(e),
    },
  };
  return h;
}

test('a first cycle extracts, seals, enqueues, and uploads', async () => {
  const h = await harness();
  try {
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.sectionsEnqueued, 1);
    assert.equal(stats.uploaded, 1);
    assert.equal(h.uploads.length, 1);
    assert.equal(h.deps.store.depth(), 0, 'a successful upload clears the outbox');
  } finally {
    h.cleanup();
  }
});

test('THE STEADY STATE: an unchanged company costs zero extracts and zero uploads', async () => {
  // This is the reason the gate exists. Tally is a single-threaded desktop app the owner is
  // typing into; interrogating it every 15 minutes for nothing is the thing to avoid.
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    const before = h.extractCalls;

    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.companiesSkipped, 1);
    assert.equal(h.extractCalls, before, 'must not ask Tally anything');
    assert.equal(stats.uploaded, 0);
    assert.equal(h.uploads.length, 1, 'still just the first cycle upload');
  } finally {
    h.cleanup();
  }
});

test('the hash gate blocks re-upload when AlterID moved but the section did not change', async () => {
  // The second gate. AlterID moves whenever ANY voucher changes, but a sales entry leaves the
  // stock summary byte-identical.
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    assert.equal(h.uploads.length, 1);

    // Vouchers moved, but extraction returns identical data.
    h.setCompanies([{ companyGuid: 'guid-acme', name: 'Acme', altMstId: 100, altVchId: 999 }]);
    const stats = await runCycle(h.deps, h.seq);

    assert.ok(h.extractCalls > 1, 'we DID ask Tally, because AlterID moved');
    assert.equal(stats.sectionsSkippedByHash, 1, 'but we did NOT upload');
    assert.equal(h.uploads.length, 1);
  } finally {
    h.cleanup();
  }
});

test('changed data does upload', async () => {
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    h.setCompanies([{ companyGuid: 'guid-acme', name: 'Acme', altMstId: 100, altVchId: 999 }]);
    h.setSections([
      { section: 'group_balance', asOf: '2026-07-16', payload: { rows: [{ g: 'Cash', amt: '999.00' }] } },
    ]);
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.sectionsEnqueued, 1);
    assert.equal(h.uploads.length, 2);
  } finally {
    h.cleanup();
  }
});

test('THE CORE SECURITY PROPERTY holds through the whole pipeline', async () => {
  // What lands in the outbox and goes over the wire must be openable ONLY with the identity
  // secret key — which the Bridge does not have.
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    const env = JSON.parse(h.uploads[0]!.envelopeJson) as SealedEnvelope;

    // The envelope carries no plaintext.
    assert.ok(!h.uploads[0]!.envelopeJson.includes('Cash'));
    assert.ok(!h.uploads[0]!.envelopeJson.includes('100.00'));

    // Only the secret key opens it — and only when the envelope is SIGNED by the device whose
    // key the reader has pinned, and only when it is the slot the reader asked for.
    const out = await openSection(env, {
      identityPublicKey: h.identity.publicKey,
      identitySecretKey: h.identity.secretKey,
      expect: {
        tenantId: 'tnt_1',
        companyGuid: 'guid-acme',
        section: 'group_balance',
        asOf: '2026-07-16',
      },
      trustedDevices: [{ deviceId: h.device.deviceId, publicKey: h.device.publicKey }],
    });
    assert.deepEqual(out, { rows: [{ g: 'Cash', amt: '100.00' }] });

    // AAD is bound and meaningful.
    assert.equal(env.aad.section, 'group_balance');
    assert.equal(env.aad.companyGuid, 'guid-acme');
    assert.equal(env.aad.tenantId, 'tnt_1');
  } finally {
    h.cleanup();
  }
});

test('the outbox holds ciphertext at rest, never plaintext', async () => {
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: true });
    await runCycle(h.deps, h.seq);
    const rows = h.deps.store.due(Number.MAX_SAFE_INTEGER);
    assert.equal(rows.length, 1);
    assert.ok(!rows[0]!.payload.includes('Cash'), 'a stolen SQLite file must yield nothing');
  } finally {
    h.cleanup();
  }
});

test('a backup restore (AlterID backward) forces a full resync and clears stale hashes', async () => {
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    assert.equal(h.uploads.length, 1);

    // Restore from backup: same GUID, LOWER AlterID, and the data is genuinely identical.
    h.setCompanies([{ companyGuid: 'guid-acme', name: 'Acme', altMstId: 50, altVchId: 100 }]);
    const stats = await runCycle(h.deps, h.seq);

    // The stored hash matches, so a hash gate alone would skip. But resetCompany() cleared it,
    // because after a restore the server may hold data that no longer matches Tally.
    assert.equal(stats.sectionsEnqueued, 1);
    assert.equal(h.uploads.length, 2, 'must re-upload after a restore');
  } finally {
    h.cleanup();
  }
});

test('a company switch never merges across GUIDs', async () => {
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    h.setCompanies([{ companyGuid: 'guid-other', name: 'Other Co', altMstId: 1, altVchId: 1 }]);
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.sectionsEnqueued, 1);
    assert.equal(JSON.parse(h.uploads[1]!.envelopeJson).aad.companyGuid, 'guid-other');
  } finally {
    h.cleanup();
  }
});

test('multiple open companies are all synced, keyed by GUID', async () => {
  const h = await harness();
  try {
    h.setCompanies([
      { companyGuid: 'guid-a', name: 'A', altMstId: 1, altVchId: 1 },
      { companyGuid: 'guid-b', name: 'B', altMstId: 1, altVchId: 1 },
    ]);
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.companiesSeen, 2);
    assert.equal(h.uploads.length, 2);
    const guids = h.uploads.map((u) => JSON.parse(u.envelopeJson).aad.companyGuid).sort();
    assert.deepEqual(guids, ['guid-a', 'guid-b']);
  } finally {
    h.cleanup();
  }
});

test('Tally being closed is a silent no-op, but the outbox still drains', async () => {
  // The normal state every night. A laptop that reconnects at 2am should flush even though
  // Tally is shut.
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: true });
    await runCycle(h.deps, h.seq);
    assert.equal(h.deps.store.depth(), 1);

    h.setCompanies([]); // Tally closed
    h.setUploadResult({ ok: true, retryable: false });
    h.advance(120_000); // past the ~60s backoff from the failed attempt

    const stats = await runCycle(h.deps, h.seq);

    assert.equal(stats.companiesSeen, 0);
    assert.ok(h.events.some((e) => e.kind === 'tally_unavailable'));
    assert.equal(stats.uploaded, 1, 'the queued section must still upload');
    assert.equal(h.deps.store.depth(), 0);
  } finally {
    h.cleanup();
  }
});

test('THE ACK RULE: a lost ACK does not lose the section', async () => {
  // Advancing the hash on SEND would mean a crash between send and ack loses the section
  // permanently and silently — the gate would skip it forever after, and the dashboard would
  // show a stale figure under a green checkmark.
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: true }); // upload sent, ACK never arrives
    await runCycle(h.deps, h.seq);
    assert.equal(h.deps.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'), undefined,
      'the hash must NOT be advanced without an ACK');

    // Next cycle succeeds; the section is still there to send.
    h.setUploadResult({ ok: true, retryable: false });
    const pending = h.deps.store.due(Number.MAX_SAFE_INTEGER)[0]!;
    h.deps.store.deferAttempt(pending.id, 0, pending.contentHash);
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.uploaded, 1);
    assert.ok(h.deps.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'));
  } finally {
    h.cleanup();
  }
});

test('a non-retryable failure is abandoned, not retried forever', async () => {
  // A 4xx (revoked device, quota exceeded) cannot be fixed by trying again.
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: false, status: 403 });
    await runCycle(h.deps, h.seq);
    assert.equal(h.deps.store.depth(), 0, 'dropped from the queue');
    assert.ok(h.events.some((e) => e.kind === 'upload_abandoned'));
    // But the data is not lost: the hash was never advanced, so a later cycle re-enqueues it.
    assert.equal(h.deps.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'), undefined);
  } finally {
    h.cleanup();
  }
});

test('the idempotency key is stable for the same data and changes with it', async () => {
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    const k1 = h.uploads[0]!.key;
    assert.match(k1, /^guid-acme\|group_balance\|2026-07-16\|/);

    h.setCompanies([{ companyGuid: 'guid-acme', name: 'Acme', altMstId: 100, altVchId: 999 }]);
    h.setSections([
      { section: 'group_balance', asOf: '2026-07-16', payload: { rows: [{ g: 'Cash', amt: '2.00' }] } },
    ]);
    await runCycle(h.deps, h.seq);
    assert.notEqual(h.uploads[1]!.key, k1);
  } finally {
    h.cleanup();
  }
});

test('SeqCounter.current reads without consuming', async () => {
  // Persisting across restarts is the reason this exists. The obvious `store(seq.next())`
  // burns a number on every save, and the resulting gaps look exactly like the dropped uploads
  // this counter exists to make visible.
  const seq = new SeqCounter(5);
  assert.equal(seq.current, 5);
  assert.equal(seq.current, 5, 'reading twice must not advance');
  assert.equal(seq.next(), 6);
  assert.equal(seq.current, 6);
});

test('a SeqCounter resumed from a stored value does not repeat', async () => {
  // A repeated seq for a given device reads as a replay to the server.
  const first = new SeqCounter(0);
  first.next();
  first.next();
  const resumed = new SeqCounter(first.current);
  assert.equal(resumed.next(), 3, 'continues, never restarts');
});

test('the seq counter is monotonic across sections and cycles', async () => {
  const h = await harness();
  try {
    h.setSections([
      { section: 'group_balance', asOf: '2026-07-16', payload: { a: 1 } },
      { section: 'cash_bank', asOf: '2026-07-16', payload: { b: 2 } },
    ]);
    await runCycle(h.deps, h.seq);
    const seqs = h.uploads.map((u) => JSON.parse(u.envelopeJson).aad.seq);
    assert.deepEqual(seqs, [1, 2]);
  } finally {
    h.cleanup();
  }
});

// ---------------------------------------------------------------- adversarial audit additions

test('AUDIT: THE FROZEN DASHBOARD — an abandoned upload must not strand the company forever', async () => {
  // The bug this pins down is the exact failure the whole design exists to prevent, and both
  // quota.ts and ARCHITECTURE.md assert it cannot happen: "Nothing is lost -- Tally is the
  // source of truth and the section hash is only advanced on ACK, so the data re-enqueues on
  // the next healthy cycle."
  //
  // The hash argument is sound but incomplete, because the hash is not the only gate. The
  // WATERMARK was already advanced when the section was enqueued. So when the upload is then
  // abandoned (a 429 from the rate cap, a 507, a transient 403, or simply MAX_ATTEMPTS of a
  // day-long outage), the row is dropped -- and the next cycle never reaches the hash gate at
  // all, because decideGate skips the company on an unchanged watermark. extract() is never
  // called, the section is never re-enqueued, and it re-enqueues on NO cycle, healthy or not.
  //
  // The owner sees a number that stopped moving, under a green checkmark. Silent staleness.
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: false, status: 429 });
    await runCycle(h.deps, h.seq);
    assert.ok(h.events.some((e) => e.kind === 'upload_abandoned'));
    assert.equal(h.deps.store.depth(), 0, 'dropped, as intended for a 4xx');

    // The server is healthy again. Tally has not changed -- an idle company, which is the
    // common case and precisely when nothing will ever nudge AlterID again.
    h.setUploadResult({ ok: true, retryable: false });
    const stats = await runCycle(h.deps, h.seq);

    assert.equal(stats.uploaded, 1, 'the abandoned section MUST reach the server eventually');
    assert.ok(
      h.deps.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'),
      'and only then is its hash advanced',
    );
  } finally {
    h.cleanup();
  }
});

test('AUDIT: exhausting the retry budget strands the company the same way', async () => {
  // The likelier route in the field: a laptop offline overnight. Backoff caps at an hour and
  // MAX_ATTEMPTS is 12, so ~a day of no network abandons the row -- with the watermark long
  // since advanced past the change set it described.
  const h = await harness();
  try {
    h.setUploadResult({ ok: false, retryable: true });
    for (let i = 0; i < 13; i++) {
      await runCycle(h.deps, h.seq);
      h.advance(3_600_000 * 2);
    }
    assert.ok(h.events.some((e) => e.kind === 'upload_abandoned'), 'the budget is spent');

    h.setUploadResult({ ok: true, retryable: false });
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.uploaded, 1, 'the network came back; the section must still go');
    assert.ok(
      h.deps.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'),
      'and the dashboard is current again, not frozen at the overnight figure',
    );
  } finally {
    h.cleanup();
  }
});

test('AUDIT: a successful cycle still costs zero extracts afterwards', async () => {
  // The guard on the fix above: re-arming after an ABANDONED upload must not re-arm after a
  // HEALTHY one. If it did, the AlterID gate would be defeated outright -- every cycle would
  // interrogate the single-threaded desktop app the owner is typing into, forever, and the
  // hash gate would hide it by never uploading. Nothing would error; we would simply have
  // thrown away the entire point of the gate.
  const h = await harness();
  try {
    await runCycle(h.deps, h.seq);
    const before = h.extractCalls;
    await runCycle(h.deps, h.seq);
    await runCycle(h.deps, h.seq);
    assert.equal(h.extractCalls, before, 'an idle company must never be asked again');
  } finally {
    h.cleanup();
  }
});

test('AUDIT: extract() throwing mid-cycle never advances the watermark past the change set', async () => {
  // If it did, the change set that was never pulled would be skipped forever.
  const h = await harness();
  try {
    const boom = new Error('Tally shut mid-pull');
    h.deps.extract = async () => {
      throw boom;
    };
    await assert.rejects(runCycle(h.deps, h.seq), /Tally shut mid-pull/);
    assert.equal(
      h.deps.store.getWatermark('guid-acme'),
      undefined,
      'no watermark: the next cycle must pull this change set again',
    );

    // And it does.
    h.deps.extract = async () => {
      h.extractCalls++;
      return [
        { section: 'group_balance', asOf: '2026-07-16', payload: { rows: [{ g: 'Cash', amt: '100.00' }] } },
      ] as ExtractedSection[];
    };
    const stats = await runCycle(h.deps, h.seq);
    assert.equal(stats.uploaded, 1);
  } finally {
    h.cleanup();
  }
});
