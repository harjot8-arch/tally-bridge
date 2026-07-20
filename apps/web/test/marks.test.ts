import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RosterError } from '@tally-bridge/crypto';
import {
  localStorageKV,
  loadRosterMemory,
  loadSlotMark,
  memoryKV,
  saveRosterMark,
  saveSlotMark,
} from '../src/data/marks.ts';
import { spyKV } from './helpers.ts';

/**
 * The browser twin of the desktop's RosterMarkStore, tested to the same standard as
 * apps/bridge/test/backend.adversary.test.ts tests the file version: monotonic, corrupt fails
 * CLOSED, deleted mark is silently first-use (the honest residual, pinned so nobody later
 * claims localStorage is tamper-evident — it is not; "clear site data" resets it).
 */

const IDPK = 'A'.repeat(43) + '=';

// ---------------------------------------------------------------- roster mark

test('missing mark is first-use; a saved mark reads back as seen', () => {
  const kv = spyKV();
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'first-use' });
  saveRosterMark(kv, IDPK, 5);
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'seen', highestVersionSeen: 5 });
});

test('MONOTONIC: the roster mark can never be lowered, only raised or repeated', () => {
  const kv = spyKV();
  saveRosterMark(kv, IDPK, 5);
  assert.throws(() => saveRosterMark(kv, IDPK, 3), RosterError);
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'seen', highestVersionSeen: 5 });
  saveRosterMark(kv, IDPK, 5); // idempotent re-save is fine
  saveRosterMark(kv, IDPK, 9);
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'seen', highestVersionSeen: 9 });
});

test('CORRUPT FAILS CLOSED: every hostile stored shape throws, none reads as "no mark"', () => {
  for (const bad of ['', 'abc', '-1', '0', '1.5', '1e3', ' 5', '5 ', 'NaN', 'null', '"5"',
    '9007199254740993', '0x10', 'Infinity']) {
    const kv = spyKV();
    kv.map.set(`tb/v1/roster-mark/${IDPK}`, bad);
    assert.throws(() => loadRosterMemory(kv, IDPK), RosterError, `stored ${JSON.stringify(bad)} must throw`);
  }
});

test('a corrupt existing mark may be REPAIRED by a valid save (the one legitimate overwrite)', () => {
  const kv = spyKV();
  kv.map.set(`tb/v1/roster-mark/${IDPK}`, 'scribble');
  saveRosterMark(kv, IDPK, 4);
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'seen', highestVersionSeen: 4 });
});

test('save refuses garbage versions outright', () => {
  const kv = spyKV();
  for (const v of [0, -1, 1.5, NaN, Infinity, 2 ** 53]) {
    assert.throws(() => saveRosterMark(kv, IDPK, v), RosterError, `save(${String(v)})`);
  }
});

test('THE RESIDUAL, PINNED: deleting the mark silently resets to first-use — localStorage is NOT tamper-evident', () => {
  const kv = spyKV();
  saveRosterMark(kv, IDPK, 9);
  kv.map.delete(`tb/v1/roster-mark/${IDPK}`);
  // Documented, not endorsed: same finding as the desktop's dangling-symlink test. Anything
  // that deletes the key — the browser's own "clear site data", Safari's 7-day eviction, a
  // different browser profile — reopens the fresh-reader window. Rollback protection on the
  // web survives only as long as this key does.
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'first-use' });
});

test('marks are scoped per identity: one idPK cannot spend or lower another idPK mark', () => {
  const kv = spyKV();
  const other = 'B'.repeat(43) + '=';
  saveRosterMark(kv, IDPK, 9);
  assert.deepEqual(loadRosterMemory(kv, other), { kind: 'first-use' });
  saveRosterMark(kv, other, 1); // a genuinely fresh identity starting at 1 is legitimate
  // ...and unlike the desktop's single-identity file, it does NOT erase the first mark.
  assert.deepEqual(loadRosterMemory(kv, IDPK), { kind: 'seen', highestVersionSeen: 9 });
});

// ---------------------------------------------------------------- slot (freshness) marks

test('slot marks are monotonic and scoped by (idPK, company, section)', () => {
  const kv = spyKV();
  saveSlotMark(kv, IDPK, 'guid-1', 'cash_bank', 2000);
  assert.equal(loadSlotMark(kv, IDPK, 'guid-1', 'cash_bank'), 2000);
  assert.throws(() => saveSlotMark(kv, IDPK, 'guid-1', 'cash_bank', 1000), RosterError);
  // Different section and different company are independent slots.
  saveSlotMark(kv, IDPK, 'guid-1', 'stock_value', 1);
  saveSlotMark(kv, IDPK, 'guid-2', 'cash_bank', 1);
  assert.equal(loadSlotMark(kv, IDPK, 'guid-1', 'cash_bank'), 2000);
});

test('slot mark corruption fails closed; a weird GUID cannot smash the key space', () => {
  const kv = spyKV();
  kv.map.set(`tb/v1/snap-mark/${JSON.stringify([IDPK, 'guid-1', 'cash_bank'])}`, '12x');
  assert.throws(() => loadSlotMark(kv, IDPK, 'guid-1', 'cash_bank'), RosterError);
  // A GUID containing the delimiter characters of a naive scheme must stay its own slot.
  const evil = 'guid/"],[';
  saveSlotMark(kv, IDPK, evil, 'cash_bank', 7);
  assert.equal(loadSlotMark(kv, IDPK, evil, 'cash_bank'), 7);
  assert.equal(loadSlotMark(kv, IDPK, 'guid-x', 'cash_bank'), undefined);
});

// ---------------------------------------------------------------- storage adapters

test('localStorageKV verifies the write stuck and throws when it did not', () => {
  const backing = new Map<string, string>();
  const fake = {
    getItem: (k: string) => backing.get(k) ?? null,
    setItem: (k: string, v: string) => {
      backing.set(k, v);
    },
  } as unknown as Storage;
  const kv = localStorageKV(fake);
  kv.set('k', 'v');
  assert.equal(kv.get('k'), 'v');
  assert.equal(kv.persistent, true);

  // A Storage whose writes silently vanish (some private modes) must surface as a throw —
  // the caller fails the unlock rather than believing a mark that was never kept.
  const black = {
    getItem: () => null,
    setItem: () => {},
  } as unknown as Storage;
  assert.throws(() => localStorageKV(black).set('k', 'v'), /did not stick/);

  // Quota errors propagate rather than being swallowed.
  const full = {
    getItem: () => null,
    setItem: () => {
      throw new DOMException('quota', 'QuotaExceededError');
    },
  } as unknown as Storage;
  assert.throws(() => localStorageKV(full).set('k', 'v'));
});

test('memoryKV works but is labelled non-persistent, so the UI must disclose it', () => {
  const kv = memoryKV();
  kv.set('a', '1');
  assert.equal(kv.get('a'), '1');
  assert.equal(kv.persistent, false);
});
