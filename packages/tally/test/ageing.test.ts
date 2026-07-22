import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  OTHERS_PARTY,
  TOP_PARTY_COUNT,
  parseAmountToPaise,
  sumPaise,
  toPaise,
} from '@tally-bridge/core';
import {
  aggregateAgeing,
  assertBillsLookSane,
  bucketFor,
  classify,
  parseBillRow,
  billsForSide,
  type RawBill,
} from '../src/ageing.ts';

const ctx = { companyGuid: 'g', asOf: '2026-07-16', side: 'receivable' as const };

/**
 * Total a set of emitted wire amounts, exactly.
 *
 * These assertions used to run through `sumAmounts`, i.e. rupee floats. Now that the aggregator
 * emits the canonical string it computed from integer paise, the test totals in paise too — so a
 * drift of one paisa fails instead of being absorbed by the float that used to carry the total.
 */
const totalPaise = (amounts: readonly string[]): number =>
  sumPaise(amounts.map((a) => parseAmountToPaise(a)));

const bill = (over: Partial<RawBill> = {}): RawBill => ({
  partyName: 'Party',
  daysSinceBill: 10,
  creditPeriodDays: 0,
  amountPaise: toPaise(1000),
  isAdvance: false,
  // A plain debtor invoice by default: classifies to 'receivable'.
  group: 'debtor',
  ...over,
});

test('buckets by days OVERDUE, not days since the bill', () => {
  // A 90-day-old invoice with 90 days of agreed credit is not late. Ageing it as "61-90"
  // would tell the owner their customer is delinquent when they are not.
  assert.equal(bucketFor({ daysSinceBill: 90, creditPeriodDays: 90 }), 'not_due');
  assert.equal(bucketFor({ daysSinceBill: 91, creditPeriodDays: 90 }), '0_30');
  assert.equal(bucketFor({ daysSinceBill: 10, creditPeriodDays: 0 }), '0_30');
});

test('a bill due today is current, not overdue', () => {
  // Standard AR practice separates "current" from "1-30 days past due". Treating overdue === 0
  // as late would flag every cash-on-delivery invoice as overdue the day it is raised.
  assert.equal(bucketFor({ daysSinceBill: 0, creditPeriodDays: 0 }), 'not_due');
  assert.equal(bucketFor({ daysSinceBill: 1, creditPeriodDays: 0 }), '0_30');
});

test('bucket boundaries are inclusive at the top', () => {
  assert.equal(bucketFor({ daysSinceBill: 30, creditPeriodDays: 0 }), '0_30');
  assert.equal(bucketFor({ daysSinceBill: 31, creditPeriodDays: 0 }), '31_60');
  assert.equal(bucketFor({ daysSinceBill: 60, creditPeriodDays: 0 }), '31_60');
  assert.equal(bucketFor({ daysSinceBill: 61, creditPeriodDays: 0 }), '61_90');
  assert.equal(bucketFor({ daysSinceBill: 90, creditPeriodDays: 0 }), '61_90');
  assert.equal(bucketFor({ daysSinceBill: 91, creditPeriodDays: 0 }), '91_180');
  assert.equal(bucketFor({ daysSinceBill: 180, creditPeriodDays: 0 }), '91_180');
  assert.equal(bucketFor({ daysSinceBill: 181, creditPeriodDays: 0 }), '180_plus');
});

test('an advance is never overdue', () => {
  // An advance is money received against no invoice yet. It cannot be late, however old it is.
  const { totals } = aggregateAgeing(
    [bill({ daysSinceBill: 900, isAdvance: true, amountPaise: toPaise(500) })],
    ctx,
  );
  assert.deepEqual(
    totals.map((t) => t.bucket),
    ['not_due'],
  );
});

test('THE invariant: totals are computed from every bill, not from the truncated matrix', () => {
  // 60 parties, all distinct, only TOP_PARTY_COUNT survive into the matrix by name.
  const bills = Array.from({ length: 60 }, (_, i) =>
    bill({ partyName: `Party ${String(i).padStart(2, '0')}`, amountPaise: toPaise(100 * (i + 1)) }),
  );
  const { rows, totals } = aggregateAgeing(bills, ctx);

  const expected = sumPaise(bills.map((b) => b.amountPaise));
  assert.equal(totalPaise(totals.map((t) => t.amount)), expected);
  assert.equal(
    totals.reduce((n, t) => n + t.billCount, 0),
    60,
  );

  // And the matrix, including the OTHERS rollup, must reconcile to the same figure — the
  // long tail is folded, never dropped.
  assert.equal(totalPaise(rows.map((r) => r.amount)), expected);
});

test('only the top N parties are named; the rest roll into OTHERS', () => {
  const bills = Array.from({ length: 60 }, (_, i) =>
    bill({ partyName: `Party ${String(i).padStart(2, '0')}`, amountPaise: toPaise(100 * (i + 1)) }),
  );
  const { rows } = aggregateAgeing(bills, ctx);
  const named = new Set(rows.map((r) => r.partyName));
  assert.ok(named.has(OTHERS_PARTY), 'the tail must be represented');
  assert.equal(named.size, TOP_PARTY_COUNT + 1, 'top N plus the OTHERS rollup');

  // The biggest party survives; the smallest does not.
  assert.ok(named.has('Party 59'));
  assert.ok(!named.has('Party 00'));
});

test('no OTHERS row appears when every party fits', () => {
  const bills = [bill({ partyName: 'Solo' })];
  const { rows } = aggregateAgeing(bills, ctx);
  assert.deepEqual(rows.map((r) => r.partyName), ['Solo']);
});

test('parties are ranked by ABSOLUTE exposure so advances cannot hide a debt', () => {
  // A party with +500000 owing and -500000 on advance nets to zero. Signed ranking would
  // drop them entirely despite them being one of the most significant relationships.
  const bills = [
    bill({ partyName: 'Big Both Ways', amountPaise: toPaise(500000) }),
    bill({ partyName: 'Big Both Ways', amountPaise: toPaise(-500000), isAdvance: true }),
    ...Array.from({ length: 40 }, (_, i) =>
      bill({ partyName: `Small ${i}`, amountPaise: toPaise(10) }),
    ),
  ];
  const { rows } = aggregateAgeing(bills, ctx);
  assert.ok(rows.some((r) => r.partyName === 'Big Both Ways'));
});

test('a party spread across buckets gets one row per bucket', () => {
  const bills = [
    bill({ partyName: 'Spread', daysSinceBill: 10 }),
    bill({ partyName: 'Spread', daysSinceBill: 200 }),
  ];
  const { rows } = aggregateAgeing(bills, ctx);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => r.bucket).sort(), ['0_30', '180_plus']);
});

test('output ordering is deterministic regardless of input order', () => {
  // Tally's row order is not guaranteed stable across runs. If it leaked into the output the
  // section hash would flap and we would upload forever while nothing errored.
  const bills = [
    bill({ partyName: 'Zed', amountPaise: toPaise(100) }),
    bill({ partyName: 'Abe', amountPaise: toPaise(100) }),
    bill({ partyName: 'Mid', amountPaise: toPaise(100) }),
  ];
  const a = aggregateAgeing(bills, ctx);
  const b = aggregateAgeing([...bills].reverse(), ctx);
  assert.deepEqual(a.rows, b.rows);
  assert.deepEqual(a.totals, b.totals);
});

test('ties in exposure are broken by name, not by arrival order', () => {
  const mk = (names: string[]) =>
    aggregateAgeing(
      names.map((n) => bill({ partyName: n, amountPaise: toPaise(100) })),
      ctx,
    ).rows.map((r) => r.partyName);
  assert.deepEqual(mk(['B', 'A', 'C']), mk(['C', 'B', 'A']));
});

test('totals are ordered by bucket age, not alphabetically', () => {
  const bills = [
    bill({ daysSinceBill: 200 }),
    bill({ daysSinceBill: 10 }),
    bill({ daysSinceBill: 45 }),
  ];
  const { totals } = aggregateAgeing(bills, ctx);
  // Alphabetically '0_30' < '180_plus' < '31_60', which would read as nonsense on a chart.
  assert.deepEqual(totals.map((t) => t.bucket), ['0_30', '31_60', '180_plus']);
});

test('an empty bill list produces nothing, not a crash', () => {
  const { rows, totals } = aggregateAgeing([], ctx);
  assert.deepEqual(rows, []);
  assert.deepEqual(totals, []);
});

test('money does not drift across thousands of bills', () => {
  // 2000 bills of 0.01 is exactly 20.00.
  const bills = Array.from({ length: 2000 }, () => bill({ amountPaise: 1 }));
  const { totals } = aggregateAgeing(bills, ctx);
  assert.equal(totals[0]!.amount, '20.00');
});

// ---------------------------------------------------------------- row parsing

test('parses a bill row off the wire', () => {
  const row = parseBillRow(['A & B Traders', '2026-01-01', '30', '125000.00', '0', '90', '1']);
  assert.deepEqual(row, {
    partyName: 'A & B Traders',
    daysSinceBill: 90,
    creditPeriodDays: 30,
    amountPaise: 12500000,
    isAdvance: false,
    group: 'debtor',
  });
});

test('an unparseable amount rejects the row rather than coercing it to zero', () => {
  // Coercing would silently understate what a customer owes.
  assert.equal(parseBillRow(['Party', '2026-01-01', '0', 'garbage', '0', '10']), undefined);
  assert.equal(parseBillRow([]), undefined);
});

// ---------------------------------------------------------------- the sanity gate

test('empty party names across the board are refused, loudly', () => {
  // The characteristic Tally failure: a wrong method name returns an EMPTY COLUMN, not an
  // error. Without this gate we would publish a dashboard of blank debtors and correct-looking
  // totals, and nobody would notice until a customer did.
  const bills = [bill({ partyName: '' }), bill({ partyName: '  ' })];
  assert.throws(() => assertBillsLookSane(bills), /every party name is empty/);
});

test('a half-broken extraction is refused too', () => {
  const bills = [bill({ partyName: 'Real' }), bill({ partyName: '' }), bill({ partyName: '' })];
  assert.throws(() => assertBillsLookSane(bills), /only 1 have party names/);
});

test('genuinely having no outstanding bills is fine', () => {
  // Distinguishing "nobody owes anything" from "the query is broken" matters: the first is a
  // legitimate state for a business that collects on delivery.
  assert.doesNotThrow(() => assertBillsLookSane([]));
});

test('a healthy extraction passes', () => {
  assert.doesNotThrow(() => assertBillsLookSane([bill({ partyName: 'Real Party' })]));
});

// ---------------------------------------------------------------- adversarial row parsing

test('parseBillRow never emits a non-finite day count', () => {
  // `Number(x) || 0` rejects NaN but NOT Infinity, which is truthy and sails straight through.
  // Everything downstream then does arithmetic on it: `Infinity - Infinity` is NaN, and NaN
  // fails every `<=` in bucketFor, so the bill silently lands in `180_plus` — the single most
  // alarming answer the card can give. This function's whole job is to not trust the wire.
  const nonFinite = parseBillRow(['P', 'd', 'Infinity', '1.00', '0', 'Infinity']);
  assert.ok(nonFinite);
  assert.equal(nonFinite.daysSinceBill, 0);
  assert.equal(nonFinite.creditPeriodDays, 0);

  for (const junk of ['NaN', 'garbage', '', '   ', '-Infinity', '1e400']) {
    const row = parseBillRow(['P', 'd', junk, '1.00', '0', junk])!;
    assert.ok(Number.isFinite(row.daysSinceBill), `daysSinceBill from ${JSON.stringify(junk)}`);
    assert.ok(Number.isFinite(row.creditPeriodDays), `creditPeriodDays from ${JSON.stringify(junk)}`);
  }
});

test('an undated bill is UNKNOWN age, not ancient — no false "180+ overdue"', () => {
  // THE all-receivables-180+-overdue bug. An empty BillDate makes Tally return the as-of
  // day-serial (~45,000) for F06, so every undated bill piles into the oldest bucket at once —
  // which is what an owner saw as "all my money is 180+ days overdue". The TDL now emits -1 for
  // an empty date; either way an IMPOSSIBLE age (negative, or older than 100 years) is treated as
  // UNKNOWN and buckets as not_due, while the amount is preserved so the total stays exact.
  const sentinel = parseBillRow(['Party', '', '0', '50000.00', '0', '-1'])!;
  assert.equal(sentinel.daysSinceBill, 0);
  assert.equal(sentinel.amountPaise, 5000000); // amount kept — only the ageing bucket is withheld
  assert.equal(bucketFor(sentinel), 'not_due');

  const epoch = parseBillRow(['Party', '', '0', '50000.00', '0', '45231'])!;
  assert.equal(epoch.daysSinceBill, 0);
  assert.equal(bucketFor(epoch), 'not_due');

  // A genuinely old bill (400 days past due) is NOT clamped — real ageing must still survive.
  const old = parseBillRow(['Party', '2025-01-01', '0', '50000.00', '0', '400'])!;
  assert.equal(old.daysSinceBill, 400);
  assert.equal(bucketFor(old), '180_plus');
});

test('a bill dated in the future is not due, not overdue', () => {
  // Tally lets a user post a bill with a future date. `daysSinceBill` is then negative.
  assert.equal(bucketFor({ daysSinceBill: -500, creditPeriodDays: 0 }), 'not_due');
  assert.equal(bucketFor({ daysSinceBill: -1, creditPeriodDays: 30 }), 'not_due');
});

test('an absurd credit period is not due, not overdue', () => {
  assert.equal(bucketFor({ daysSinceBill: 10, creditPeriodDays: 1_000_000 }), 'not_due');
  assert.equal(bucketFor({ daysSinceBill: 100_000, creditPeriodDays: 0 }), '180_plus');
});

// ---------------------------------------------------------------- the invariant, adversarially

test('THE invariant holds when a party is literally named __OTHERS__', () => {
  // OTHERS_PARTY is a sentinel in the same namespace as real party names. A supplier can be
  // named anything, so the sentinel is forgeable; the totals must survive it regardless.
  const bills = [
    bill({ partyName: OTHERS_PARTY, amountPaise: toPaise(999999) }),
    ...Array.from({ length: 40 }, (_, i) =>
      bill({ partyName: `Small ${i}`, amountPaise: toPaise(i + 1) }),
    ),
  ];
  const { rows, totals } = aggregateAgeing(bills, ctx);
  const expected = sumPaise(bills.map((b) => b.amountPaise));
  assert.equal(totalPaise(totals.map((t) => t.amount)), expected);
  assert.equal(totalPaise(rows.map((r) => r.amount)), expected);
  assert.equal(rows.reduce((n, r) => n + r.billCount, 0), bills.length);
  assert.equal(totals.reduce((n, t) => n + t.billCount, 0), bills.length);
});

test('THE invariant holds for party names differing only by case or whitespace', () => {
  const bills = ['Acme', 'ACME', 'acme', 'Acme ', ' Acme'].map((partyName) =>
    bill({ partyName, amountPaise: toPaise(1000) }),
  );
  const { rows, totals } = aggregateAgeing(bills, ctx);
  assert.equal(totalPaise(totals.map((t) => t.amount)), toPaise(5000));
  assert.equal(totalPaise(rows.map((r) => r.amount)), toPaise(5000));
});

test('THE invariant holds across 10,000 parties', () => {
  const bills = Array.from({ length: 10_000 }, (_, i) =>
    bill({ partyName: `P${i}`, amountPaise: (i % 97) + 1, daysSinceBill: i % 400 }),
  );
  const { rows, totals } = aggregateAgeing(bills, ctx);
  const expectedPaise = bills.reduce((n, b) => n + b.amountPaise, 0);
  assert.equal(totalPaise(totals.map((t) => t.amount)), expectedPaise);
  assert.equal(totalPaise(rows.map((r) => r.amount)), expectedPaise);
  assert.equal(totals.reduce((n, t) => n + t.billCount, 0), 10_000);
});

test('a party whose bills net to exactly zero produces "0.00", never "-0.00"', () => {
  // A computed -0 and a literal 0 render differently, so they hash differently, so the section
  // would re-upload forever while nothing errored.
  //
  // This assertion used to be `!Object.is(amount, -0)`, which was right while `amount` was a
  // number. Now that it is the wire string, `Object.is('0.00', -0)` is false for the trivial
  // reason that a string is not a number — the check would have passed without testing anything.
  // Asserting the emitted TEXT is what keeps it honest: "-0.00" is the only way this can fail
  // now, and it is exactly what a missing normalization emits.
  const bills = [
    bill({ partyName: 'Z', amountPaise: toPaise(100) }),
    bill({ partyName: 'Z', amountPaise: toPaise(-100) }),
  ];
  const { rows, totals } = aggregateAgeing(bills, ctx);
  assert.equal(rows[0]!.amount, '0.00');
  assert.equal(totals[0]!.amount, '0.00');
});

test('a cell key cannot collide across party/bucket boundaries', () => {
  // The cell key is `${party} ${bucket}`. A party named "Acme 0_30" must not merge into the
  // "Acme"/"0_30" cell.
  const bills = [
    bill({ partyName: 'Acme', daysSinceBill: 10, amountPaise: toPaise(100) }),
    bill({ partyName: 'Acme 0_30', daysSinceBill: 400, amountPaise: toPaise(7) }),
  ];
  const { rows } = aggregateAgeing(bills, ctx);
  assert.equal(rows.length, 2);
  assert.equal(rows.find((r) => r.partyName === 'Acme')!.amount, '100.00');
  assert.equal(rows.find((r) => r.partyName === 'Acme 0_30')!.amount, '7.00');
});

// ---------------------------------------------------------------- the side test (F07)
//
// A real TallyPrime 7.0 refused to narrow the Bills collection at all: CHILDOF emptied it and
// $ClosingBalance was unavailable in filter context, while both worked fine as FIELDS. So the
// side test and the open-bill test moved into Node, and these are the tests that keep them
// honest — the failure they guard against is an EMPTY CARD, which looks exactly like a
// business that is owed nothing.

test('CLASSIFY routes a bill to a side by group + advance — advances flip sides', () => {
  assert.equal(classify({ group: 'debtor', isAdvance: false }), 'receivable');
  assert.equal(classify({ group: 'creditor', isAdvance: false }), 'payable');
  // The rule the owner asked for: a customer (debtor) advance is a LIABILITY (payable); a supplier
  // (creditor) advance is an ASSET (receivable). Advances land on the OPPOSITE side from the group.
  assert.equal(classify({ group: 'debtor', isAdvance: true }), 'payable');
  assert.equal(classify({ group: 'creditor', isAdvance: true }), 'receivable');
  // A party in neither Sundry group belongs on no side at all.
  assert.equal(classify({ group: 'other', isAdvance: false }), null);
});

test('billsForSide keeps only the bills that classify to that side (advances separated, not netted)', () => {
  const debtorInvoice = bill({ partyName: 'Debtor', amountPaise: 100000, group: 'debtor' });
  const creditorInvoice = bill({ partyName: 'Creditor', amountPaise: 250000, group: 'creditor' });
  const customerAdvance = bill({ partyName: 'Prepaid Cust', amountPaise: 40000, group: 'debtor', isAdvance: true });
  const supplierAdvance = bill({ partyName: 'Prepaid Supp', amountPaise: -30000, group: 'creditor', isAdvance: true });
  const all = [debtorInvoice, creditorInvoice, customerAdvance, supplierAdvance];

  // Receivables: the debtor invoice + the supplier advance (we prepaid, they owe us) — NOT the
  // customer advance, which no longer nets the receivable total down.
  assert.deepEqual(billsForSide(all, 'receivable').map((b) => b.partyName).sort(), ['Debtor', 'Prepaid Supp']);
  // Payables: the creditor invoice + the customer advance (they prepaid, we owe them).
  assert.deepEqual(billsForSide(all, 'payable').map((b) => b.partyName).sort(), ['Creditor', 'Prepaid Cust']);
});

test('settled bills are dropped in Node, because Tally will not filter them', () => {
  // This WAS `<FILTER>NOT $$IsZero:$ClosingBalance</FILTER>`. On a real Tally that filter
  // returned zero rows out of 141 while every one of those 141 carried a non-zero balance.
  const kept = billsForSide(
    [bill({ amountPaise: 0 }), bill({ amountPaise: -1 }), bill({ amountPaise: 500 })],
    'receivable',
  );
  assert.equal(kept.length, 2);
});

test('a bill in NEITHER group belongs to no side and is dropped', () => {
  // F07 = 0 (or absent) means $$IsLedOfGrp did not place the party. It cannot be sided, so it is
  // dropped from both sides — and if EVERY row is like this, assertBillsLookSane refuses the sync.
  const parsed = parseBillRow(['Party', '2026-01-01', '30', '1000.00', '0', '40', '0']);
  assert.equal(parsed?.group, 'other');
  assert.equal(billsForSide([parsed!], 'receivable').length, 0);
  assert.equal(billsForSide([parsed!], 'payable').length, 0);
});

test('F07 group code is read from the wire: 1 debtor, 2 creditor, else other', () => {
  assert.equal(parseBillRow(['P', 'd', '0', '1.00', '0', '5', '1'])?.group, 'debtor');
  assert.equal(parseBillRow(['P', 'd', '0', '1.00', '0', '5', '2'])?.group, 'creditor');
  assert.equal(parseBillRow(['P', 'd', '0', '1.00', '0', '5', '0'])?.group, 'other');
  assert.equal(parseBillRow(['P', 'd', '0', '1.00', '0', '5'])?.group, 'other'); // absent column
});

test('A BROKEN GROUP TEST IS LOUD: no bill in either group cannot mean "owed nothing"', () => {
  // If $$IsLedOfGrp does not resolve on a bill, F07 is 0 (other) for EVERY row and both cards
  // silently empty. A book where not one bill is a debtor or creditor does not exist — so this
  // shape is always a broken extraction, and must never reach a dashboard.
  const bills = [bill({ partyName: 'Real', group: 'other' }), bill({ partyName: 'Also Real', group: 'other' })];
  assert.throws(() => assertBillsLookSane(bills), /NOT ONE is in Sundry/);
});

test('the group gate does not fire when even one bill is a debtor or creditor', () => {
  assert.doesNotThrow(() => assertBillsLookSane([bill({ group: 'other' }), bill({ group: 'debtor' })]));
});
