import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { SyncStore, backoffMs, type OutboxRow } from '../src/store.ts';

function tmp(): { store: SyncStore; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'tally-store-'));
  const store = new SyncStore(join(dir, 'sync.db'));
  return { store, cleanup: () => { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const NOW = 1_752_600_000_000;

type OutboxInput = Omit<OutboxRow, 'id' | 'attempts' | 'nextAttemptAt' | 'createdAt'>;

// `section` is typed as Section, not string: widening it here let `as never` casts creep into
// the call sites, which is precisely the kind of thing an unchecked test file hides.
const row = (over: Partial<OutboxInput> = {}): OutboxInput => ({
  companyGuid: 'guid-a',
  section: 'group_balance',
  asOf: '2026-07-16',
  payload: '{"ct":"v1"}',
  contentHash: 'h1',
  ...over,
});

test('THE UNIQUE INDEX: re-enqueueing supersedes instead of appending', async () => {
  // The single most important property of the outbox. A laptop offline for a week must hold
  // ONE current row per section, not 700 stale snapshots — queue depth is bounded by SCHEMA
  // SIZE, not by outage duration. Without this, a fortnight in a drawer becomes an upload
  // storm of obsolete data on reconnect.
  const { store, cleanup } = tmp();
  try {
    for (let i = 0; i < 700; i++) {
      store.enqueue(row({ payload: `{"ct":"v${i}"}`, contentHash: `h${i}` }), NOW + i);
    }
    assert.equal(store.depth(), 1, '700 enqueues of the same section => 1 row');

    const due = store.due(Number.MAX_SAFE_INTEGER);
    assert.equal(due[0]!.payload, '{"ct":"v699"}', 'and it is the LATEST, not the first');
    assert.equal(due[0]!.contentHash, 'h699');
  } finally {
    cleanup();
  }
});

test('different sections, companies, and dates each keep their own row', async () => {
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row(), NOW);
    store.enqueue(row({ section: 'cash_bank' }), NOW);
    store.enqueue(row({ asOf: '2026-07-17' }), NOW);
    store.enqueue({ ...row(), companyGuid: 'guid-b' }, NOW);
    assert.equal(store.depth(), 4);
  } finally {
    cleanup();
  }
});

test('superseding resets the retry budget', async () => {
  // New data deserves a fresh start rather than inheriting the backoff of the stale payload
  // it replaced — otherwise a section that failed overnight would stay throttled for an hour
  // after the owner fixed their wifi.
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row(), NOW);
    const first = store.due(Number.MAX_SAFE_INTEGER)[0]!;
    store.deferAttempt(first.id, NOW + 3_600_000, first.contentHash);
    assert.equal(store.due(NOW).length, 0, 'deferred out of reach');

    store.enqueue(row({ contentHash: 'h2', payload: '{"ct":"v2"}' }), NOW);
    const after = store.due(NOW);
    assert.equal(after.length, 1, 'fresh data is immediately due again');
    assert.equal(after[0]!.attempts, 0);
  } finally {
    cleanup();
  }
});

test('due() respects the backoff schedule', async () => {
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row(), NOW);
    const r = store.due(NOW)[0]!;
    store.deferAttempt(r.id, NOW + 60_000, r.contentHash);
    assert.equal(store.due(NOW).length, 0);
    assert.equal(store.due(NOW + 59_999).length, 0);
    assert.equal(store.due(NOW + 60_000).length, 1, 'due exactly at the boundary');
  } finally {
    cleanup();
  }
});

test('deferAttempt increments the attempt count', async () => {
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row(), NOW);
    const r = store.due(NOW)[0]!;
    store.deferAttempt(r.id, 0, r.contentHash);
    store.deferAttempt(r.id, 0, r.contentHash);
    assert.equal(store.due(NOW)[0]!.attempts, 2);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------- watermarks & hashes

test('watermarks round-trip and upsert', async () => {
  const { store, cleanup } = tmp();
  try {
    assert.equal(store.getWatermark('guid-a'), undefined);
    store.setWatermark({ companyGuid: 'guid-a', altMstId: 1, altVchId: 2 }, NOW);
    assert.deepEqual(store.getWatermark('guid-a'), { companyGuid: 'guid-a', altMstId: 1, altVchId: 2 });
    store.setWatermark({ companyGuid: 'guid-a', altMstId: 9, altVchId: 9 }, NOW);
    assert.deepEqual(store.getWatermark('guid-a'), { companyGuid: 'guid-a', altMstId: 9, altVchId: 9 });
  } finally {
    cleanup();
  }
});

test('section hashes are keyed by as_of, so midnight rollover does not collide', async () => {
  // Keying on section alone would make the first sync of every new day look already-done.
  const { store, cleanup } = tmp();
  try {
    store.ackSectionHash('guid-a', 'group_balance', '2026-07-16', 'h-yesterday', NOW);
    assert.equal(store.getSectionHash('guid-a', 'group_balance', '2026-07-16'), 'h-yesterday');
    assert.equal(
      store.getSectionHash('guid-a', 'group_balance', '2026-07-17'),
      undefined,
      'a new day must not inherit yesterday’s hash',
    );
  } finally {
    cleanup();
  }
});

test('resetCompany clears watermark, hashes, and queue for that company only', async () => {
  const { store, cleanup } = tmp();
  try {
    store.setWatermark({ companyGuid: 'guid-a', altMstId: 1, altVchId: 1 }, NOW);
    store.setWatermark({ companyGuid: 'guid-b', altMstId: 1, altVchId: 1 }, NOW);
    store.ackSectionHash('guid-a', 'group_balance', '2026-07-16', 'h', NOW);
    store.ackSectionHash('guid-b', 'group_balance', '2026-07-16', 'h', NOW);
    store.enqueue(row(), NOW);
    store.enqueue({ ...row(), companyGuid: 'guid-b' }, NOW);

    store.resetCompany('guid-a');

    assert.equal(store.getWatermark('guid-a'), undefined);
    assert.equal(store.getSectionHash('guid-a', 'group_balance', '2026-07-16'), undefined);
    assert.ok(store.getWatermark('guid-b'), 'the other company is untouched');
    assert.equal(store.getSectionHash('guid-b', 'group_balance', '2026-07-16'), 'h');
    assert.equal(store.depth(), 1);
  } finally {
    cleanup();
  }
});

test('reset() clears EVERY company — the "start over" full wipe', async () => {
  const { store, cleanup } = tmp();
  try {
    store.setWatermark({ companyGuid: 'guid-a', altMstId: 1, altVchId: 1 }, NOW);
    store.setWatermark({ companyGuid: 'guid-b', altMstId: 1, altVchId: 1 }, NOW);
    store.ackSectionHash('guid-a', 'group_balance', '2026-07-16', 'h', NOW);
    store.enqueue(row(), NOW);
    store.enqueue({ ...row(), companyGuid: 'guid-b' }, NOW);

    store.reset();

    // Every company gone — the point is that the next cycle re-extracts EVERYTHING, so a stale
    // watermark can never leave the new identity staring at snapshots it cannot decrypt.
    assert.equal(store.getWatermark('guid-a'), undefined);
    assert.equal(store.getWatermark('guid-b'), undefined);
    assert.equal(store.getSectionHash('guid-a', 'group_balance', '2026-07-16'), undefined);
    assert.equal(store.depth(), 0, 'the outbox is empty');
  } finally {
    cleanup();
  }
});

test('the quirks cache round-trips and stays a single row', async () => {
  const { store, cleanup } = tmp();
  try {
    store.setQuirks({ quirksSchemaVersion: 1, tallyVersion: '3.0', probedAt: NOW, json: '{"a":1}' });
    store.setQuirks({ quirksSchemaVersion: 1, tallyVersion: '4.0', probedAt: NOW, json: '{"a":2}' });
    const q = store.getQuirks();
    assert.equal(q?.tallyVersion, '4.0');
    assert.equal(q?.json, '{"a":2}');
  } finally {
    cleanup();
  }
});

test('state survives reopening the database', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tally-store-'));
  const path = join(dir, 'sync.db');
  try {
    const a = new SyncStore(path);
    a.setWatermark({ companyGuid: 'guid-a', altMstId: 5, altVchId: 6 }, NOW);
    a.enqueue(row(), NOW);
    a.close();

    // A force-kill mid-cycle is the norm, not the exception.
    const b = new SyncStore(path);
    assert.deepEqual(b.getWatermark('guid-a'), { companyGuid: 'guid-a', altMstId: 5, altVchId: 6 });
    assert.equal(b.depth(), 1);
    b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- backoff

test('backoff grows exponentially and caps at an hour', () => {
  const noJitter = () => 0.5; // 1 + (0.5*0.5 - 0.25) = 1.0
  assert.equal(backoffMs(1, noJitter), 60_000);
  assert.equal(backoffMs(2, noJitter), 120_000);
  assert.equal(backoffMs(3, noJitter), 240_000);
  assert.equal(backoffMs(20, noJitter), 3_600_000, 'capped at 1h');
});

test('backoff jitter stays within +/-25%', () => {
  // The jitter is not decoration: these installs share one office NAT, one broadband line, and
  // one power cut. Without it every Bridge in the building retries in lockstep.
  const lo = backoffMs(2, () => 0);
  const hi = backoffMs(2, () => 1);
  assert.equal(lo, 90_000); // 120s * 0.75
  assert.equal(hi, 150_000); // 120s * 1.25
  for (let i = 0; i < 200; i++) {
    const v = backoffMs(2);
    assert.ok(v >= lo && v <= hi, `${v} outside [${lo}, ${hi}]`);
  }
});

test('jitter actually spreads retries apart', () => {
  const seen = new Set(Array.from({ length: 50 }, () => backoffMs(3)));
  assert.ok(seen.size > 10, 'lockstep retries would collapse to a single value');
});

// ---------------------------------------------------------------- adversarial audit additions

test('AUDIT: an in-flight row that gets superseded must not be DELETED by the ack of the old one', async () => {
  // The unique index supersedes in place, which means the superseding row INHERITS THE ROWID of
  // the row it replaced. So an ack that dequeues by id alone deletes whatever is sitting at
  // that id now -- including fresh data that was never sent.
  //
  //   drain reads row id=1 (hash h1)     ->  upload(payload1) in flight...
  //   a second cycle enqueues h2         ->  supersedes IN PLACE, still id=1
  //   upload(payload1) returns ok        ->  ack(h1); dequeue(1)  <-- h2 is gone
  //
  // Nothing errors. h2 was never uploaded and is no longer queued, and the cycle that produced
  // it already advanced the watermark -- so it is never extracted again either. The section is
  // silently DROPPED, not superseded, which is the exact thing the unique index promises cannot
  // happen. (The app's Scheduler collapses overlapping cycles today, so this is latent -- but
  // SyncStore is exported and the guarantee must live here, not in a caller's timer.)
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row({ contentHash: 'h1', payload: 'old' }), NOW);
    const inFlight = store.due(NOW)[0]!;
    assert.equal(inFlight.contentHash, 'h1');

    // A concurrent cycle supersedes it with fresher data while the upload is in flight.
    store.enqueue(row({ contentHash: 'h2', payload: 'new' }), NOW + 1);

    // The in-flight upload of the OLD payload now ACKs.
    store.ackSectionHash('guid-a', 'group_balance', '2026-07-16', inFlight.contentHash, NOW + 2);
    store.dequeue(inFlight.id, inFlight.contentHash);

    const left = store.due(NOW + 10);
    assert.equal(left.length, 1, 'the superseding row must survive an ack of the row it replaced');
    assert.equal(left[0]!.contentHash, 'h2');
    assert.equal(left[0]!.payload, 'new');
  } finally {
    cleanup();
  }
});

test('AUDIT: deferring a stale in-flight row must not push back the fresh row that replaced it', async () => {
  // Same shape, failure path: a supersede deliberately resets the retry budget to zero because
  // it is NEW data. A late deferAttempt from the superseded upload would hand the fresh payload
  // the dead one's backoff -- up to an hour of staleness the new data never earned.
  const { store, cleanup } = tmp();
  try {
    store.enqueue(row({ contentHash: 'h1' }), NOW);
    const inFlight = store.due(NOW)[0]!;

    store.enqueue(row({ contentHash: 'h2' }), NOW + 1);
    store.deferAttempt(inFlight.id, NOW + 3_600_000, inFlight.contentHash);

    const due = store.due(NOW + 10);
    assert.equal(due.length, 1, 'the fresh row is still due now, not in an hour');
    assert.equal(due[0]!.contentHash, 'h2');
    assert.equal(due[0]!.attempts, 0, 'and keeps its fresh retry budget');
  } finally {
    cleanup();
  }
});

test('AUDIT: backoff survives absurd attempt counts', async () => {
  // 2 ** 1024 is Infinity. Math.min tames it, but NaN would not be tamed: it would poison
  // next_attempt_at and the row would never be due again -- a silently stranded section.
  for (const n of [0, 1, 12, 64, 1024, 1e9]) {
    const ms = backoffMs(n, () => 0.5);
    assert.ok(Number.isFinite(ms), `attempts=${n} produced ${ms}`);
    assert.ok(ms > 0 && ms <= 3_600_000 * 1.25, `attempts=${n} produced ${ms}`);
  }
});
