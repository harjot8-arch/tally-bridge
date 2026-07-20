import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalAmount,
  canonicalStringify,
  type Amount,
  type CanonicalValue,
  type SectionPayload,
} from '@tally-bridge/core';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  profitCard,
  salesTrendCard,
  stockCard,
} from '../src/cards.ts';

/**
 * THE SEAM TEST — the wire against the cards, with nothing pretending in between.
 *
 * This file exists because of BUG-6, and BUG-6 exists because this file did not.
 *
 * The Bridge rendered money to canonical 2dp decimal STRINGS (correctly — money must never cross
 * the wire as a float). `packages/core`'s model declared `Amount = number`. Nothing converted
 * between them. 457 unit tests passed, because every one of them built its own fixtures out of
 * its own idea of the data: the card tests handed cards `closing: -342110`, a shape no producer
 * in the system had ever emitted. The two halves were each self-consistent and disagreed with
 * each other, and the type that should have caught it — `ExtractedSection.payload` — was
 * `CanonicalValue`, which accepts anything JSON-shaped.
 *
 * What shipped as a result:
 *   - `profitCard` / `salesTrendCard`  THREW — `Number.isFinite("500000.00")` is false.
 *   - `balanceSheetTree`               rendered `₹—` for the ENTIRE balance sheet, silently.
 *   - `cashBankCard` / `ageingCard` / `stockCard`
 *                                      "worked", by ACCIDENTAL STRING COERCION (`-"-342110.75"`
 *                                      is 342110.75). The worst outcome of the three: they would
 *                                      have shipped looking perfect.
 *
 * So the rule this file enforces: amounts here are produced by the REAL producer-side renderer
 * (`canonicalAmount`), serialized by the REAL canonical serializer, put through a REAL JSON round
 * trip — which is literally what the crypto layer seals and a surface later parses — and only
 * then handed to the REAL cards. No hand-written amount literals, no mock on either side. If the
 * producer and the consumer ever disagree about the shape of money again, these tests fail.
 */

const base = { companyGuid: 'g', asOf: '2026-07-16' };

/**
 * The actual wire round trip: canonical JSON out, JSON back in.
 *
 * This is not a formality. `canonicalStringify` is what the section hash and the sealed payload
 * are computed over, and `JSON.parse` is what every reading surface does. Anything that survives
 * this is what a card genuinely receives; anything that does not could never have shipped.
 */
function overTheWire<T extends SectionPayload>(payload: T): T {
  return JSON.parse(canonicalStringify(payload)) as T;
}

// ---------------------------------------------------------------- the fixture

/**
 * The same books as scripts/e2e-simulation.ts, in the house convention: Dr negative, Cr positive.
 * Rupee numbers here are only an authoring convenience — every one of them is rendered through
 * `canonicalAmount` before a card ever sees it, exactly as the Bridge does.
 */
const CASH_BANK: SectionPayload = {
  section: 'cash_bank',
  rows: [
    { ...base, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing: canonicalAmount(-342110.75) },
    { ...base, ledgerName: 'Cash-in-Hand', parent: 'Cash-in-Hand', closing: canonicalAmount(-48250) },
    // An overdraft is a LIABILITY: Cr, positive. It must pull the headline total DOWN.
    { ...base, ledgerName: 'ICICI OD 8890', parent: 'Bank OD A/c', closing: canonicalAmount(125000) },
  ],
};

const REVENUE: SectionPayload = {
  section: 'period_revenue',
  rows: [
    { companyGuid: 'g', period: '2026-07', groupName: 'Sales Accounts', parent: '', amount: canonicalAmount(500000) },
    { companyGuid: 'g', period: '2026-07', groupName: 'Purchase Accounts', parent: '', amount: canonicalAmount(-300000) },
    { companyGuid: 'g', period: '2026-07', groupName: 'Direct Expenses', parent: '', amount: canonicalAmount(-45000) },
    { companyGuid: 'g', period: '2026-07', groupName: 'Indirect Expenses', parent: '', amount: canonicalAmount(-30000) },
  ],
};

// ---------------------------------------------------------------- BUG-6 itself

test('BUG-6: a payload whose amounts are NUMBERS is not even a legal wire payload', () => {
  // The proof that `Amount = number` was never merely a style disagreement: the canonical
  // serializer REJECTS non-integer numbers outright, precisely so that float formatting can
  // never differ between Node and a browser. A rupee amount as a number could not be hashed,
  // sealed or shipped. The model spent the whole life of the codebase describing data that was
  // impossible to send — and the card layer was written to trust that description.
  const illegal = {
    section: 'cash_bank',
    rows: [
      {
        ...base,
        ledgerName: 'HDFC CA 4471',
        parent: 'Bank Accounts',
        closing: -342110.75 as unknown as Amount,
      },
    ],
  };
  assert.throws(
    () => canonicalStringify(illegal as unknown as CanonicalValue),
    /non-integer number/,
    'a float amount must never be serializable — that is what forces the string wire format',
  );
});

test('BUG-6: every card reads the REAL wire and agrees with the books', () => {
  // The single test that would have caught all of it. Real producer, real serializer, real JSON
  // round trip, real cards — the numbers out must equal the numbers in.
  const cash = overTheWire(CASH_BANK);
  assert.equal(cash.section, 'cash_bank');
  if (cash.section !== 'cash_bank') return;

  const card = cashBankCard(cash.rows);

  // 342110.75 + 48250.00 - 125000.00
  assert.equal(card.total.raw, 265360.75);
  assert.equal(card.total.paise, 26536075, 'the exact integer must be exposed, not just a float');
  assert.equal(card.total.display, '₹2,65,361');
  assert.equal(card.tone, 'good');

  const hdfc = card.accounts.find((a) => a.name === 'HDFC CA 4471')!;
  assert.equal(hdfc.balance.raw, 342110.75, 'a funded account flips positive');
  assert.ok(!hdfc.balance.display.startsWith('-'), 'and never displays a minus sign');

  const od = card.accounts.find((a) => a.name === 'ICICI OD 8890')!;
  assert.equal(od.balance.raw, -125000, 'an overdraft is money owed: negative');
});

test('BUG-6: the cards that THREW on the real wire now compute', () => {
  // `Number.isFinite("500000.00")` is false, so `toPaise` threw and these two cards were dead on
  // arrival against real data while passing every unit test they had.
  const rev = overTheWire(REVENUE);
  if (rev.section !== 'period_revenue') throw new Error('unreachable');

  // 500000 - 300000 - 45000 - 30000
  assert.equal(profitCard(rev.rows, []).current.raw, 125000);
  assert.equal(salesTrendCard(rev.rows).points[0]!.value.raw, 500000);
});

test('BUG-6: the balance sheet renders numbers, not ₹— for every row', () => {
  // The quietest failure of the set. `formatMoney` degrades a non-finite value to "₹—", so every
  // node of the balance sheet rendered an em dash and nothing threw, logged, or turned red.
  const sheet = overTheWire({
    section: 'group_balance',
    rows: [
      { ...base, groupName: 'Current Assets', parent: '', primaryGroup: 'Current Assets', isRevenue: false, opening: canonicalAmount(-870000), closing: canonicalAmount(-1010361.5) },
      { ...base, groupName: 'Bank Accounts', parent: 'Current Assets', primaryGroup: 'Current Assets', isRevenue: false, opening: canonicalAmount(-300000), closing: canonicalAmount(-342110.75) },
    ],
  } satisfies SectionPayload);
  if (sheet.section !== 'group_balance') throw new Error('unreachable');

  const tree = balanceSheetTree(sheet.rows);
  const assets = tree.find((n) => n.name === 'Current Assets')!;
  assert.equal(assets.amount.raw, -1010361.5);
  assert.notEqual(assets.amount.display, '₹—');
  assert.equal(assets.children[0]!.amount.raw, -342110.75, 'children hydrate too');
});

test('BUG-6: the cards that "worked" by string coercion were never actually parsing', () => {
  // The subtlest half of the bug, and the reason a throw was the LUCKY outcome. `-"-342110.75"`
  // is 342110.75 and `"500000.00" * -1` is -500000: the coercing cards produced correct-looking
  // numbers from a value they had not understood. Pin the parse: garbage must throw, never coerce
  // and never default to zero.
  for (const garbage of ['', '₹1,00,000', '1.005', 'NaN', 'abc', '1e5', '  ']) {
    assert.throws(
      () =>
        cashBankCard([
          { ...base, ledgerName: 'X', parent: 'Bank Accounts', closing: garbage as Amount },
        ]),
      `an unparseable amount ${JSON.stringify(garbage)} was coerced instead of throwing`,
    );
  }
});

test('THE PAISA survives the wire, and summing it does not drift', () => {
  // 0.1 + 0.2 = 0.30000000000000004 is the classic. Every total on every card goes through
  // integer paise for this reason; the wire round trip must not undo it.
  const wire = overTheWire({
    section: 'stock_value',
    rows: [
      { ...base, stockGroup: 'A', closingValue: canonicalAmount(-0.1) },
      { ...base, stockGroup: 'B', closingValue: canonicalAmount(-0.2) },
    ],
  } satisfies SectionPayload);
  if (wire.section !== 'stock_value') throw new Error('unreachable');

  const card = stockCard(wire.rows);
  assert.equal(card.total.raw, 0.3, 'not 0.30000000000000004');
  assert.equal(card.total.paise, 30);
});

test('an ageing payload round-trips totals[] exactly, paise included', () => {
  const wire = overTheWire({
    section: 'ageing_receivable',
    rows: [
      { ...base, side: 'receivable', partyName: 'A & B Traders <Mumbai>', bucket: '91_180', amount: canonicalAmount(-125000), billCount: 1 },
      { ...base, side: 'receivable', partyName: 'श्री गणेश ट्रेडर्स', bucket: 'not_due', amount: canonicalAmount(-87500.5), billCount: 1 },
      { ...base, side: 'receivable', partyName: 'Café Traders', bucket: '0_30', amount: canonicalAmount(-2500.25), billCount: 1 },
    ],
    totals: [
      { ...base, side: 'receivable', bucket: '91_180', amount: canonicalAmount(-125000), billCount: 1 },
      { ...base, side: 'receivable', bucket: 'not_due', amount: canonicalAmount(-87500.5), billCount: 1 },
      { ...base, side: 'receivable', bucket: '0_30', amount: canonicalAmount(-2500.25), billCount: 1 },
    ],
  } satisfies SectionPayload);
  if (wire.section !== 'ageing_receivable') throw new Error('unreachable');

  const card = ageingCard(wire.totals, wire.rows, 'receivable');
  assert.equal(card.total.raw, 215000.75, 'the half-paise fixtures must survive the whole path');
  assert.equal(card.total.paise, 21500075);
  assert.equal(card.overdue.raw, 127500.25, 'not_due is excluded');
  // Non-ASCII party names ride the same wire as the money.
  assert.ok(card.topParties.some((p) => p.name === 'श्री गणेश ट्रेडर्स'));
});

// ---------------------------------------------------------------- task #16

test('THE DOUBLE COUNT: profit does not count a nested revenue group twice', () => {
  // Tally's revenue collection filters on `$IsRevenue` and returns every revenue group at every
  // depth, and a parent's closing balance ALREADY CONTAINS its children's. Summing every row
  // counted "Sales - Domestic" once inside "Sales" and once on its own.
  const wire = overTheWire({
    section: 'period_revenue',
    rows: [
      { companyGuid: 'g', period: '2026-07', groupName: 'Sales Accounts', parent: '', amount: canonicalAmount(500000) },
      { companyGuid: 'g', period: '2026-07', groupName: 'Sales - Domestic', parent: 'Sales Accounts', amount: canonicalAmount(300000) },
      { companyGuid: 'g', period: '2026-07', groupName: 'Sales - Export', parent: 'Sales Accounts', amount: canonicalAmount(200000) },
      { companyGuid: 'g', period: '2026-07', groupName: 'Purchase Accounts', parent: '', amount: canonicalAmount(-300000) },
    ],
  } satisfies SectionPayload);
  if (wire.section !== 'period_revenue') throw new Error('unreachable');

  const card = profitCard(wire.rows, []);
  // 500000 - 300000. NOT 500000 + 300000 + 200000 - 300000 = 700000.
  assert.equal(card.current.raw, 200000, 'the nested sales groups are already inside their parent');
});

test('a revenue child whose parent was not fetched still counts', () => {
  // A partial or filtered pull can hand us children with no parent row. Excluding them on
  // "parent !== ''" alone would swap an overstatement for an UNDERSTATEMENT — equally wrong, and
  // the direction that makes a profitable month look like a loss.
  const card = profitCard(
    [
      { companyGuid: 'g', period: '2026-07', groupName: 'Sales - Export', parent: 'Sales Accounts', amount: canonicalAmount(200000) },
      { companyGuid: 'g', period: '2026-07', groupName: 'Direct Expenses', parent: '', amount: canonicalAmount(-50000) },
    ],
    [],
  );
  assert.equal(card.current.raw, 150000, 'an orphaned child is top-level, not invisible');
});

test('a parent cycle in the revenue groups cannot zero out the profit', () => {
  // Group parents are user-editable, so A->B->A is reachable data. "Every row is somebody's
  // child" would exclude EVERY row and report a profit of exactly ₹0 — silently. Same failure,
  // and the same guard, as balanceSheetTree's cycle handling.
  const card = profitCard(
    [
      { companyGuid: 'g', period: '2026-07', groupName: 'A', parent: 'B', amount: canonicalAmount(100000) },
      { companyGuid: 'g', period: '2026-07', groupName: 'B', parent: 'A', amount: canonicalAmount(-40000) },
    ],
    [],
  );
  assert.equal(card.current.raw, 60000, 'both cycle members must count');
});

test('a self-parenting revenue group still counts', () => {
  const card = profitCard(
    [{ companyGuid: 'g', period: '2026-07', groupName: 'Sales', parent: 'Sales', amount: canonicalAmount(100000) }],
    [],
  );
  assert.equal(card.current.raw, 100000);
});

test('containment is judged PER PERIOD, not across the whole pull', () => {
  // Rows for different months never contain each other. Building one name set across periods
  // would let a parent present in June suppress its child in July — silently dropping a month's
  // revenue out of a multi-period sum.
  const card = profitCard(
    [
      { companyGuid: 'g', period: '2026-06', groupName: 'Sales Accounts', parent: '', amount: canonicalAmount(100000) },
      // July has the CHILD only; its parent exists in June's rows but not in July's.
      { companyGuid: 'g', period: '2026-07', groupName: 'Sales - Export', parent: 'Sales Accounts', amount: canonicalAmount(50000) },
    ],
    [],
  );
  assert.equal(card.current.raw, 150000, "June's parent must not suppress July's child");
});
