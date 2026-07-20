import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decideGate, hashHitRate, shouldUpload, type Watermark } from '../src/gate.ts';

const w = (over: Partial<Watermark> = {}): Watermark => ({
  companyGuid: 'guid-acme',
  altMstId: 100,
  altVchId: 200,
  ...over,
});

test('unchanged watermarks skip the cycle entirely', () => {
  // The common case, and the whole point: an idle company costs one 2KB round trip.
  const d = decideGate(w(), w());
  assert.equal(d.action, 'skip');
});

test('a first sighting pulls everything', () => {
  assert.equal(decideGate(undefined, w()).action, 'full');
});

test('vouchers moving pulls the voucher-dependent sections', () => {
  const d = decideGate(w(), w({ altVchId: 201 }));
  assert.equal(d.action, 'partial');
  assert.ok(d.action === 'partial' && d.sections.includes('ageing_receivable'));
  assert.ok(d.action === 'partial' && d.sections.includes('group_balance'));
});

test('masters moving pulls the master-dependent sections', () => {
  // A master edit can rename or re-parent a group without touching a voucher — the numbers
  // don't move but what the cards SAY does.
  const d = decideGate(w(), w({ altMstId: 101 }));
  assert.equal(d.action, 'partial');
  assert.ok(d.action === 'partial' && d.sections.includes('company'));
  assert.ok(d.action === 'partial' && d.sections.includes('group_balance'));
});

test('both moving pulls everything', () => {
  assert.equal(decideGate(w(), w({ altMstId: 101, altVchId: 201 })).action, 'full');
});

test('THE SILENT KILLER: AlterID moving BACKWARD forces a full resync', () => {
  // Restoring from a backup, or a Tally data rewrite, can leave AlterID lower than what we
  // stored. A naive `>` comparison would conclude "nothing new" on every subsequent cycle and
  // skip syncing FOREVER — silently — while the owner watches a frozen dashboard and believes
  // it. Same GUID + lower AlterID is the signature.
  const back = decideGate(w(), w({ altVchId: 150 }));
  assert.equal(back.action, 'full');
  assert.match(back.reason, /backward|restore/i);

  const backMst = decideGate(w(), w({ altMstId: 50 }));
  assert.equal(backMst.action, 'full');
});

test('a naive greater-than would have skipped the backward case — proving the check earns its place', () => {
  const stored = w();
  const current = w({ altVchId: 150 });
  const naiveWouldSync = current.altVchId > stored.altVchId || current.altMstId > stored.altMstId;
  assert.equal(naiveWouldSync, false, 'naive check sees no change...');
  assert.equal(decideGate(stored, current).action, 'full', '...but we resync anyway');
});

test('a changed company GUID never merges history', () => {
  // Company names get edited and are duplicated across financial years. Keying on name would
  // silently merge or split two businesses' books.
  const d = decideGate(w(), w({ companyGuid: 'guid-other' }));
  assert.equal(d.action, 'full');
  assert.match(d.reason, /GUID/);
});

test('a GUID change wins even when the watermarks look like a normal advance', () => {
  const d = decideGate(w(), w({ companyGuid: 'guid-other', altMstId: 101, altVchId: 201 }));
  assert.equal(d.action, 'full');
  assert.match(d.reason, /GUID/, 'must be attributed to the GUID, not to the watermarks');
});

// ---------------------------------------------------------------- hash gate

test('the hash gate blocks an unchanged section and passes a changed one', () => {
  assert.equal(shouldUpload('abc', 'abc'), false);
  assert.equal(shouldUpload('abc', 'def'), true);
  assert.equal(shouldUpload(undefined, 'abc'), true);
});

test('hash-hit rate reports the health of the gate', () => {
  // Near 1.0 on an idle company. Near 0 means canonicalization is non-deterministic and the
  // gate is silently defeated — we would upload forever and nothing would error.
  assert.equal(hashHitRate({ checked: 10, skipped: 10 }), 1);
  assert.equal(hashHitRate({ checked: 10, skipped: 0 }), 0);
  assert.equal(hashHitRate({ checked: 0, skipped: 0 }), 1, 'no data is not a failure');
});

// ---------------------------------------------------------------- adversarial audit additions

test('AUDIT: a non-finite AlterID must never read as "nothing changed"', () => {
  // A garbled probe row (Tally returned an empty column, a `<ALTMSTID></ALTMSTID>`, or XML the
  // parser gave up on) can produce NaN. Every comparison against NaN is false, so both
  // `current < stored` and `current > stored` are false and the gate concludes "watermarks
  // unchanged" -- and SKIPS. Forever, silently, while the owner reads a frozen dashboard.
  //
  // The gate's default on garbage must be fail-SAFE (pull everything, correct-but-slow), never
  // fail-QUIET. The current caller happens to sanitise NaN to 0 upstream, but decideGate is
  // exported and that guarantee lives in someone else's package.
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.equal(decideGate(w(), w({ altVchId: bad })).action, 'full', `altVchId=${bad}`);
    assert.equal(decideGate(w(), w({ altMstId: bad })).action, 'full', `altMstId=${bad}`);
  }
});

test('AUDIT: a non-finite STORED AlterID is void too', () => {
  // The same reasoning from the other side: a corrupt row read back out of SQLite.
  assert.equal(decideGate(w({ altMstId: NaN }), w()).action, 'full');
  assert.equal(decideGate(w({ altVchId: NaN }), w()).action, 'full');
});

test('AUDIT: masters up and vouchers down at the same instant is a restore, not a partial', () => {
  // A partial pull here would trust a watermark that has already been proven void.
  const d = decideGate(w(), w({ altMstId: 101, altVchId: 199 }));
  assert.equal(d.action, 'full');
});
