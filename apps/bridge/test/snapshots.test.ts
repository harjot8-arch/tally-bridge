import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IsoDate, Section } from '@tally-bridge/core';
import { CapturingSyncStore, RosterMarkStore, SnapshotStore } from '../src/main/snapshots.ts';

/**
 * The reader's storage. The tests that matter most here are the OUTBOX TRAP (a drained outbox
 * must not blank the dashboard) and the rollback mark's refusal to treat unreadable memory as
 * no memory.
 */

const dir = () => mkdtempSync(join(tmpdir(), 'bridge-snap-'));

const row = (over: Partial<{ companyGuid: string; section: Section; asOf: IsoDate; payload: string; contentHash: string }> = {}) => ({
  companyGuid: 'guid-1',
  section: 'cash_bank' as Section,
  asOf: '2026-07-16' as IsoDate,
  payload: '{"fake":"envelope"}',
  contentHash: 'h1',
  ...over,
});

// ---------------------------------------------------------------- the trap

test('THE OUTBOX TRAP: draining the outbox does not blank the dashboard', () => {
  const snaps = new SnapshotStore(dir());
  const store = new CapturingSyncStore(':memory:', snaps);

  store.enqueue(row(), 1000);
  assert.equal(store.depth(), 1, 'the outbox got the row');
  assert.equal(snaps.list().slots.length, 1, 'the snapshot got the row too');

  // Simulate a successful upload cycle: the orchestrator ACKs and dequeues.
  const due = store.due(2000);
  assert.equal(due.length, 1);
  store.dequeue(due[0]!.id, due[0]!.contentHash);
  assert.equal(store.depth(), 0, 'the outbox drained — as it must');

  // The moment this assertion is the design: sync succeeding must not erase the local reader's
  // data. If cards read the outbox, this is where the dashboard would go blank.
  const after = snaps.list().slots;
  assert.equal(after.length, 1);
  assert.equal(after[0]!.envelope, '{"fake":"envelope"}');
});

test('a new enqueue supersedes the snapshot for the same slot', () => {
  const snaps = new SnapshotStore(dir());
  const store = new CapturingSyncStore(':memory:', snaps);
  store.enqueue(row({ payload: 'old', contentHash: 'h1' }), 1000);
  store.enqueue(row({ payload: 'new', contentHash: 'h2', asOf: '2026-07-17' }), 2000);
  const slots = snaps.list().slots;
  assert.equal(slots.length, 1, 'one slot, superseded in place');
  assert.equal(slots[0]!.envelope, 'new');
  assert.equal(slots[0]!.asOf, '2026-07-17');
});

test('a failing snapshot write fails the enqueue loudly rather than silently freezing the dashboard', () => {
  const snaps = new SnapshotStore(dir());
  const store = new CapturingSyncStore(':memory:', snaps);
  // An unknown section cannot be stored (and could never be read back into an expectation).
  assert.throws(() => store.enqueue(row({ section: 'not_a_section' as Section }), 1000));
  // And the outbox row was NOT written either: the cycle fails before the watermark advances,
  // so the next cycle re-extracts. No half-state.
  assert.equal(store.depth(), 0);
});

// ---------------------------------------------------------------- file safety

test('a traversal-shaped company GUID cannot choose the file path', () => {
  const d = dir();
  const snaps = new SnapshotStore(d);
  snaps.put(row({ companyGuid: '../../../evil', section: 'company' }), 1);
  snaps.put(row({ companyGuid: 'C:\\Windows\\system32', section: 'stock_value' }), 1);
  const names = readdirSync(d);
  assert.equal(names.length, 2);
  for (const n of names) {
    assert.match(n, /^[0-9a-f]{64}\.json$/, `file name must be a digest, got ${n}`);
  }
  // And the slots read back with their hostile GUIDs intact as DATA.
  const guids = snaps.list().slots.map((s) => s.companyGuid).sort();
  assert.deepEqual(guids, ['../../../evil', 'C:\\Windows\\system32']);
});

test('put refuses rows that could not later state an expectation', () => {
  const snaps = new SnapshotStore(dir());
  assert.throws(() => snaps.put(row({ companyGuid: '' }), 1));
  assert.throws(() => snaps.put(row({ asOf: 'yesterday' as IsoDate }), 1));
  assert.throws(() => snaps.put(row({ payload: '' }), 1));
});

test('a corrupt snapshot file is counted, not silently dropped, and does not take the rest down', () => {
  const d = dir();
  const snaps = new SnapshotStore(d);
  snaps.put(row(), 1);
  writeFileSync(join(d, `${'ab'.repeat(32)}.json`), 'not json at all');
  const { slots, unreadable } = snaps.list();
  assert.equal(slots.length, 1);
  assert.equal(unreadable, 1);
});

test('the roster mark file and tmp leftovers in the same directory are not read as snapshots', () => {
  const d = dir();
  const snaps = new SnapshotStore(d);
  const marks = new RosterMarkStore(d);
  snaps.put(row(), 1);
  marks.save('idpk', 3);
  writeFileSync(join(d, 'whatever.tmp'), 'crashed mid-write');
  const { slots, unreadable } = snaps.list();
  assert.equal(slots.length, 1);
  assert.equal(unreadable, 0, 'the mark file must not count as a corrupt snapshot');
});

// ---------------------------------------------------------------- the rollback mark

test('the high-water mark persists across store instances — this is the whole rollback defence', () => {
  const d = dir();
  new RosterMarkStore(d).save('idpk-A', 4);
  // A NEW instance over the same directory: proves disk, not object state.
  const memory = new RosterMarkStore(d).load('idpk-A');
  assert.deepEqual(memory, { kind: 'seen', highestVersionSeen: 4 });
});

test('no mark on disk is a genuine first use', () => {
  assert.deepEqual(new RosterMarkStore(dir()).load('idpk-A'), { kind: 'first-use' });
});

test('a mark for a different identity is first-use for this one (reset dashboard mints a new idPK)', () => {
  const d = dir();
  const marks = new RosterMarkStore(d);
  marks.save('idpk-OLD', 9);
  assert.deepEqual(marks.load('idpk-NEW'), { kind: 'first-use' });
  // And the old identity's mark is still intact.
  assert.deepEqual(marks.load('idpk-OLD'), { kind: 'seen', highestVersionSeen: 9 });
});

test('the mark is monotonic: no caller can lower it', () => {
  const d = dir();
  const marks = new RosterMarkStore(d);
  marks.save('idpk-A', 5);
  assert.throws(() => marks.save('idpk-A', 4), /refusing to lower/);
  assert.deepEqual(marks.load('idpk-A'), { kind: 'seen', highestVersionSeen: 5 });
  marks.save('idpk-A', 5); // same version is fine — re-unlocks happen
  marks.save('idpk-A', 6);
});

test('UNREADABLE MEMORY IS NOT NO MEMORY: a corrupt mark file throws instead of degrading to first-use', () => {
  const d = dir();
  const marks = new RosterMarkStore(d);
  writeFileSync(join(d, 'roster-mark.json'), '{ definitely not json');
  assert.throws(() => marks.load('idpk-A'), /refusing to treat unreadable memory as no memory/);
});

test('a NaN, float, zero or negative stored version is refused, never compared', () => {
  const d = dir();
  const marks = new RosterMarkStore(d);
  for (const bad of ['1.5', '0', '-3', 'null', '"7"', '9007199254740993']) {
    writeFileSync(join(d, 'roster-mark.json'), `{"v":1,"idPK":"idpk-A","highestVersionSeen":${bad}}`);
    assert.throws(() => marks.load('idpk-A'), `stored version ${bad} must throw`);
  }
});

test('save refuses to write a mark that load would refuse', () => {
  const marks = new RosterMarkStore(dir());
  assert.throws(() => marks.save('idpk-A', Number.NaN));
  assert.throws(() => marks.save('idpk-A', 0));
  assert.throws(() => marks.save('idpk-A', 2.5));
  assert.throws(() => marks.save('', 1));
});

test('a corrupt mark can be repaired by a deliberate save, and only upward from nothing', () => {
  const d = dir();
  const marks = new RosterMarkStore(d);
  writeFileSync(join(d, 'roster-mark.json'), 'garbage');
  marks.save('idpk-A', 2); // the one legitimate repair
  assert.deepEqual(marks.load('idpk-A'), { kind: 'seen', highestVersionSeen: 2 });
});
