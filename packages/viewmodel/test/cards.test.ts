import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OTHERS_PARTY, canonicalAmount as amt, type AgeingBucketRow, type AgeingTotalRow, type CashBankBalance, type GroupBalance, type PeriodRevenueRow, type StockValueRow } from '@tally-bridge/core';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  profitCard,
  salesTrendCard,
  stockCard,
} from '../src/cards.ts';

const base = { companyGuid: 'g', asOf: '2026-07-16' };

// ---------------------------------------------------------------- cash & bank

test('THE SIGN FLIP: a healthy bank balance never shows a minus sign', () => {
  // Dr is negative in our convention and cash/bank assets are Dr, so a full account arrives
  // here NEGATIVE. An owner asking "how much do I have?" must not be shown -₹3,42,110.
  const rows: CashBankBalance[] = [
    { ...base, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing: amt(-342110) },
    { ...base, ledgerName: 'Cash', parent: 'Cash-in-Hand', closing: amt(-25000) },
  ];
  const card = cashBankCard(rows);
  assert.equal(card.total.raw, 367110);
  assert.equal(card.total.display, '₹3,67,110');
  assert.equal(card.tone, 'good');
});

test('an overdrawn position reads as bad', () => {
  const rows: CashBankBalance[] = [
    { ...base, ledgerName: 'HDFC OD', parent: 'Bank OD A/c', closing: amt(50000) }, // Cr = overdrawn
  ];
  assert.equal(cashBankCard(rows).tone, 'bad');
});

test('accounts sort largest first and cash is flagged', () => {
  const rows: CashBankBalance[] = [
    { ...base, ledgerName: 'Small', parent: 'Bank Accounts', closing: amt(-1000) },
    { ...base, ledgerName: 'Cash', parent: 'Cash-in-Hand', closing: amt(-5000) },
  ];
  const card = cashBankCard(rows);
  assert.deepEqual(card.accounts.map((a) => a.name), ['Cash', 'Small']);
  assert.equal(card.accounts[0]!.isCash, true);
  assert.equal(card.accounts[1]!.isCash, false);
});

test('no accounts is neutral, not an error', () => {
  assert.equal(cashBankCard([]).tone, 'neutral');
  assert.equal(cashBankCard([]).total.display, '₹0');
});

// ---------------------------------------------------------------- ageing

// The helpers take RUPEE numbers for readability and render them to the wire form the cards
// actually receive. Tests that hand-build numeric amounts are how BUG-6 stayed invisible: every
// card passed against a model that no producer ever emitted.
const total = (bucket: AgeingTotalRow['bucket'], amount: number, count = 1): AgeingTotalRow => ({
  ...base, side: 'receivable', bucket, amount: amt(amount), billCount: count,
});
const cell = (partyName: string, bucket: AgeingBucketRow['bucket'], amount: number): AgeingBucketRow => ({
  ...base, side: 'receivable', partyName, bucket, amount: amt(amount), billCount: 1,
});

test('receivables flip so "who owes me" reads positive', () => {
  const card = ageingCard([total('0_30', -100000)], [cell('Acme', '0_30', -100000)], 'receivable');
  assert.equal(card.total.raw, 100000);
  assert.equal(card.total.display, '₹1,00,000');
});

test('THE TOTALS INVARIANT: headline totals come from totals[], never from the truncated matrix', () => {
  // rows[] is capped at the top parties + an OTHERS rollup. Deriving the headline from it would
  // couple the number the owner reads to a display decision.
  const totals = [total('0_30', -500000, 40)];
  const rows = [cell('Big', '0_30', -100000)]; // deliberately inconsistent, and much smaller
  const card = ageingCard(totals, rows, 'receivable');
  assert.equal(card.total.raw, 500000, 'the total must follow totals[], not rows[]');
  assert.equal(card.buckets[0]!.billCount, 40);
});

test('overdue excludes not_due', () => {
  const card = ageingCard(
    [total('not_due', -100000), total('0_30', -50000), total('180_plus', -25000)],
    [],
    'receivable',
  );
  assert.equal(card.total.raw, 175000);
  assert.equal(card.overdue.raw, 75000, 'not_due is not overdue');
});

test('tone escalates with the overdue share, not the absolute amount', () => {
  // A crore of receivables that are all current is healthy. ₹10k that is all 180+ is not.
  const healthy = ageingCard([total('not_due', -10_000_000)], [], 'receivable');
  assert.equal(healthy.tone, 'good');

  const sick = ageingCard([total('180_plus', -10_000)], [], 'receivable');
  assert.equal(sick.tone, 'bad');
});

test('buckets are ordered by age and labelled for humans', () => {
  const card = ageingCard(
    [total('180_plus', -1), total('0_30', -1), total('not_due', -1)],
    [],
    'receivable',
  );
  assert.deepEqual(card.buckets.map((b) => b.bucket), ['not_due', '0_30', '180_plus']);
  assert.equal(card.buckets[1]!.label, '1–30 days', 'label states 1-30, matching the bucketing');
});

test('empty buckets are omitted rather than rendered as zero rows', () => {
  const card = ageingCard([total('0_30', -100)], [], 'receivable');
  assert.equal(card.buckets.length, 1);
});

test('top parties answer "who owes me most"', () => {
  const card = ageingCard(
    [total('0_30', -600)],
    [cell('Small', '0_30', -100), cell('Big', '0_30', -500)],
    'receivable',
  );
  assert.deepEqual(card.topParties.map((p) => p.name), ['Big', 'Small']);
});

test('OTHERS always sinks to the bottom regardless of size', () => {
  // "__OTHERS__ owes you the most" is not an actionable sentence.
  const card = ageingCard(
    [total('0_30', -1_000_000)],
    [cell(OTHERS_PARTY, '0_30', -900000), cell('Real Party', '0_30', -100000)],
    'receivable',
  );
  assert.equal(card.topParties[0]!.name, 'Real Party');
  assert.equal(card.topParties.at(-1)!.name, OTHERS_PARTY);
  assert.equal(card.topParties.at(-1)!.isOthers, true);
});

test('a party spread across buckets is summed and tagged with its WORST bucket', () => {
  // The worst bucket is the actionable fact: this customer has something 180+ days late.
  const card = ageingCard(
    [total('0_30', -100), total('180_plus', -50)],
    [cell('Acme', '0_30', -100), cell('Acme', '180_plus', -50)],
    'receivable',
  );
  assert.equal(card.topParties.length, 1);
  assert.equal(card.topParties[0]!.amount.raw, 150);
  assert.equal(card.topParties[0]!.worstBucket, '180_plus');
});

test('payables do not flip', () => {
  // Creditors are Cr (positive); what we owe already reads positive.
  const t: AgeingTotalRow = { ...base, side: 'payable', bucket: '0_30', amount: amt(75000), billCount: 1 };
  const card = ageingCard([t], [], 'payable');
  assert.equal(card.total.raw, 75000);
  assert.equal(card.side, 'payable');
});

test('nothing outstanding is a clean, good card', () => {
  const card = ageingCard([], [], 'receivable');
  assert.equal(card.total.raw, 0);
  assert.equal(card.tone, 'good');
  assert.deepEqual(card.buckets, []);
});

// ---------------------------------------------------------------- profit

const rev = (period: string, groupName: string, amount: number, parent = ''): PeriodRevenueRow => ({
  companyGuid: 'g', period, groupName, parent, amount: amt(amount),
});

test('profit falls out of the sign convention: income Cr positive, expenses Dr negative', () => {
  const current = [rev('2026-07', 'Sales Accounts', 500000), rev('2026-07', 'Direct Expenses', -300000)];
  const previous = [rev('2026-06', 'Sales Accounts', 400000), rev('2026-06', 'Direct Expenses', -300000)];
  const card = profitCard(current, previous);
  assert.equal(card.current.raw, 200000);
  assert.equal(card.previous.raw, 100000);
  assert.equal(card.delta.text, '+100%');
  assert.equal(card.tone, 'good');
});

test('a loss reads as bad even if it improved', () => {
  const card = profitCard([rev('2026-07', 'Sales Accounts', -50000)], [rev('2026-06', 'Sales Accounts', -100000)]);
  assert.equal(card.tone, 'bad', 'still losing money');
  assert.equal(card.delta.direction, 'up', 'but losing less than last month');
});

// ---------------------------------------------------------------- trend

test('the sales trend is ordered chronologically and labelled by month', () => {
  const card = salesTrendCard([
    rev('2026-07', 'Sales Accounts', 300),
    rev('2026-05', 'Sales Accounts', 100),
    rev('2026-06', 'Sales Accounts', 200),
  ]);
  assert.deepEqual(card.points.map((p) => p.period), ['2026-05', '2026-06', '2026-07']);
  assert.deepEqual(card.points.map((p) => p.label), ['May', 'Jun', 'Jul']);
  assert.equal(card.peak.raw, 300);
  assert.equal(card.tone, 'good');
});

test('the trend ignores non-sales groups', () => {
  const card = salesTrendCard([
    rev('2026-07', 'Sales Accounts', 300),
    rev('2026-07', 'Direct Expenses', -100),
  ]);
  assert.equal(card.points.length, 1);
  assert.equal(card.points[0]!.value.raw, 300);
});

test('a falling month warns', () => {
  const card = salesTrendCard([rev('2026-06', 'Sales Accounts', 500), rev('2026-07', 'Sales Accounts', 100)]);
  assert.equal(card.tone, 'warn');
});

test('a single data point is neutral, not a trend', () => {
  assert.equal(salesTrendCard([rev('2026-07', 'Sales Accounts', 100)]).tone, 'neutral');
  assert.equal(salesTrendCard([]).points.length, 0);
});

// ---------------------------------------------------------------- stock

test('stock flips sign and reports each group’s share', () => {
  const rows: StockValueRow[] = [
    { ...base, stockGroup: 'Cement', closingValue: amt(-75000) },
    { ...base, stockGroup: 'Steel', closingValue: amt(-25000) },
  ];
  const card = stockCard(rows);
  assert.equal(card.total.raw, 100000);
  assert.equal(card.groups[0]!.name, 'Cement');
  assert.equal(card.groups[0]!.share, 0.75);
});

test('empty stock does not divide by zero', () => {
  assert.equal(stockCard([]).total.raw, 0);
  assert.deepEqual(stockCard([]).groups, []);
});

// ---------------------------------------------------------------- balance sheet

const grp = (groupName: string, parent: string, closing: number, isRevenue = false): GroupBalance => ({
  ...base, groupName, parent, primaryGroup: '', isRevenue, opening: amt(0), closing: amt(closing),
});

test('the flat group rows roll into a tree', () => {
  const tree = balanceSheetTree([
    grp('Current Assets', '', -100000),
    grp('Bank Accounts', 'Current Assets', -80000),
    grp('Cash-in-Hand', 'Current Assets', -20000),
  ]);
  assert.equal(tree.length, 1);
  assert.equal(tree[0]!.name, 'Current Assets');
  assert.deepEqual(tree[0]!.children.map((c) => c.name), ['Bank Accounts', 'Cash-in-Hand']);
});

test('P&L groups are excluded from the balance sheet', () => {
  const tree = balanceSheetTree([grp('Current Assets', '', -1), grp('Sales Accounts', '', 1, true)]);
  assert.deepEqual(tree.map((n) => n.name), ['Current Assets']);
});

test('a dangling parent surfaces at the root instead of vanishing', () => {
  // A partial pull can reference a parent we did not fetch. Dropping the node would silently
  // understate a total — surfacing it is visibly odd, which is what we want.
  const tree = balanceSheetTree([grp('Orphan', 'Missing Parent', -500)]);
  assert.equal(tree.length, 1);
  assert.equal(tree[0]!.name, 'Orphan');
});

test('A CYCLE IN THE GROUP PARENTS DOES NOT SWALLOW THE BALANCE SHEET', () => {
  // Tally group parents are user-editable and a corrupt/edited company can produce A->B->A.
  // The old code attached each to the other, so NEITHER became a root: the whole subtree
  // vanished from the return value, silently understating the balance sheet — the exact failure
  // the dangling-parent branch exists to prevent. Any consumer that walks children (the web
  // dashboard) would also recurse forever on the structure it built.
  const tree = balanceSheetTree([grp('A', 'B', -100), grp('B', 'A', -200)]);
  assert.equal(tree.length, 2, 'both cycle members must surface');
  assert.deepEqual(tree.map((n) => n.name).sort(), ['A', 'B']);
  assert.ok(tree.every((n) => n.children.length === 0), 'the cycle edge must be broken');
  assert.doesNotThrow(() => JSON.stringify(tree), 'the returned graph must be acyclic');
});

test('a self-parenting group does not vanish', () => {
  const tree = balanceSheetTree([grp('Loop', 'Loop', -100)]);
  assert.deepEqual(tree.map((n) => n.name), ['Loop']);
  assert.equal(tree[0]!.children.length, 0);
});

test('a walk of the tree terminates even with a cycle present', () => {
  // The real hang is in the RENDERER, not here. Prove the structure we hand it is finite.
  const tree = balanceSheetTree([
    grp('Root', '', -1),
    grp('Child', 'Root', -2),
    grp('A', 'B', -3),
    grp('B', 'A', -4),
  ]);
  let seen = 0;
  const walk = (ns: typeof tree, depth: number): void => {
    assert.ok(depth < 50, 'infinite recursion — the tree contains a cycle');
    for (const n of ns) {
      seen++;
      walk(n.children, depth + 1);
    }
  };
  walk(tree, 0);
  assert.equal(seen, 4, 'every group appears exactly once');
});

test('a node deeper than a cycle still attaches, and appears once', () => {
  const tree = balanceSheetTree([grp('A', 'B', -1), grp('B', 'A', -2), grp('C', 'A', -3)]);
  assert.equal(JSON.stringify(tree).includes('"C"'), true);
  const names: string[] = [];
  const walk = (ns: typeof tree): void => { for (const n of ns) { names.push(n.name); walk(n.children); } };
  walk(tree);
  assert.deepEqual(names.sort(), ['A', 'B', 'C']);
});

test('a duplicated group row cannot double-count a node into the tree', () => {
  // Two rows for the same group (two asOf dates in one payload, a bad merge) put the SAME node
  // object into the tree twice: any consumer summing the tree reports the group twice.
  const tree = balanceSheetTree([grp('Current Assets', '', -100000), grp('Current Assets', '', -100000)]);
  assert.equal(tree.length, 1, 'one group, one node');
});

// -------------------------------------------------- the whole company, end to end

test('THE ACCOUNTANT’S READING: a trader with an OD, a customer advance, stock and a loss', () => {
  // One realistic company, every card, checked against what an accountant would say out loud.
  // Getting any single flip backwards means the owner reads their debt as cash.

  // Cash ₹40,000 in hand (Dr, negative). HDFC overdrawn by ₹5,00,000 (Cr, positive).
  const cash = cashBankCard([
    { ...base, ledgerName: 'Cash', parent: 'Cash-in-Hand', closing: amt(-40000) },
    { ...base, ledgerName: 'HDFC OD 4471', parent: 'Bank OD A/c', closing: amt(500000) },
  ]);
  assert.equal(cash.accounts.find((a) => a.name === 'Cash')!.balance.raw, 40000, 'cash is an asset: positive');
  assert.equal(cash.accounts.find((a) => a.name === 'HDFC OD 4471')!.balance.raw, -500000, 'an OD is money OWED: negative');
  assert.equal(cash.total.raw, -460000);
  assert.equal(cash.total.display, '-₹4,60,000');
  assert.equal(cash.tone, 'bad', 'net overdrawn is the most urgent thing on the dashboard');

  // Receivables: Acme owes ₹2,00,000, 91-180 days (Dr, negative). Zenith paid a ₹50,000 advance
  // before delivery, so Zenith's ledger sits Cr (positive) — the trader OWES Zenith goods.
  const ar = ageingCard(
    [total('91_180', -200000), total('not_due', 50000)],
    [cell('Acme', '91_180', -200000), cell('Zenith', 'not_due', 50000)],
    'receivable',
  );
  assert.equal(ar.total.raw, 150000, 'net receivable is 2L owed less the 50k advance held');
  assert.equal(ar.overdue.raw, 200000, 'the advance is not_due and must not net off the overdue bucket');
  assert.equal(ar.topParties.find((p) => p.name === 'Zenith')!.amount.raw, -50000, 'an advance reads negative: not a debtor');
  assert.equal(ar.tone, 'bad', '2L stuck at 91-180 days on a 1.5L book');

  // Payables: the trader owes Supplier ₹3,00,000 (Cr, positive) — no flip.
  const ap = ageingCard([{ ...base, side: 'payable', bucket: '0_30', amount: amt(300000), billCount: 2 }], [], 'payable');
  assert.equal(ap.total.raw, 300000, 'what I owe reads positive without a flip');

  // Stock: ₹8,00,000 of cement (Dr, negative).
  const stock = stockCard([{ ...base, stockGroup: 'Cement', closingValue: amt(-800000) }]);
  assert.equal(stock.total.raw, 800000, 'stock on hand is an asset: positive');
  assert.equal(stock.total.display, '₹8,00,000');

  // P&L: sales ₹5,00,000 (Cr), purchases+expenses ₹6,00,000 (Dr) => a ₹1,00,000 loss.
  const pl = profitCard(
    [rev('2026-07', 'Sales Accounts', 500000), rev('2026-07', 'Purchase Accounts', -450000), rev('2026-07', 'Indirect Expenses', -150000)],
    [rev('2026-06', 'Sales Accounts', 600000), rev('2026-06', 'Purchase Accounts', -450000)],
  );
  assert.equal(pl.current.raw, -100000, 'a loss is negative');
  assert.equal(pl.current.display, '-₹1,00,000');
  assert.equal(pl.tone, 'bad');
  assert.equal(pl.delta.direction, 'down', 'from +1.5L to -1L is down');

  // The balance sheet keeps the raw convention: assets Dr-negative, liabilities Cr-positive.
  // Documented, because a renderer that assumes otherwise prints the owner's assets as debts.
  const tree = balanceSheetTree([grp('Current Assets', '', -840000), grp('Bank OD A/c', '', 500000)]);
  assert.equal(tree.find((n) => n.name === 'Current Assets')!.amount.raw, -840000);
  assert.equal(tree.find((n) => n.name === 'Bank OD A/c')!.amount.raw, 500000);
});

// -------------------------------------------------- adversarial: ageing

test('duplicate bucket rows in totals[] accumulate rather than overwrite', () => {
  // Last-write-wins silently DROPS money from the headline. Two rows for one bucket is exactly
  // what a merged/backfilled payload looks like, and it fails without a single error.
  const card = ageingCard([total('0_30', -100), total('0_30', -200)], [], 'receivable');
  assert.equal(card.total.raw, 300, 'both rows count');
  assert.equal(card.buckets[0]!.billCount, 2, 'bill counts add too');
});

test('customer advances cannot mask genuinely overdue money in the tone', () => {
  // Big advance held (Cr => negative after flip) can push the NET total negative while real
  // money is stuck 180+ days. overdue/total then goes NEGATIVE and the ratio reads "good".
  const card = ageingCard([total('not_due', 100000), total('180_plus', -50000)], [], 'receivable');
  assert.equal(card.total.raw, -50000);
  assert.equal(card.overdue.raw, 50000, '₹50,000 is 180+ days late');
  assert.equal(card.tone, 'bad', 'a negative net book must not launder overdue money into "good"');
});

test('a net-credit book with nothing overdue is not alarming', () => {
  const card = ageingCard([total('not_due', 100000)], [], 'receivable');
  assert.equal(card.total.raw, -100000);
  assert.equal(card.tone, 'good');
});

test('a party spread across buckets sums exactly, without float drift', () => {
  // raw is documented as the number for charts and for a renderer doing its own formatting.
  // 0.1 + 0.2 = 0.30000000000000004 is the classic; every other card sums via integer paise.
  const card = ageingCard(
    [total('0_30', -30)],
    [cell('Acme', '0_30', -0.1), cell('Acme', '31_60', -0.2)],
    'receivable',
  );
  assert.equal(card.topParties[0]!.amount.raw, 0.3);
});

test('a party present in rows[] but absent from totals[] still ranks', () => {
  const card = ageingCard([total('0_30', -100)], [cell('Ghost', '61_90', -900)], 'receivable');
  assert.equal(card.total.raw, 100, 'the headline still follows totals[]');
  assert.deepEqual(card.topParties.map((p) => p.name), ['Ghost']);
});

test('a real party literally named __OTHERS__ collides with the rollup sentinel', () => {
  // Documented, not fixed: this layer cannot distinguish them. Pinned so the behaviour is a
  // decision rather than a surprise.
  const card = ageingCard([total('0_30', -100)], [cell(OTHERS_PARTY, '0_30', -100)], 'receivable');
  assert.equal(card.topParties[0]!.isOthers, true);
});

// -------------------------------------------------- adversarial: stock

test('a negative stock value never renders a bar backwards or past 100%', () => {
  // Negative stock (Cr closing) is real in Tally: issue before receipt. A share of 2.0 draws a
  // bar at 200% and -1.0 draws one backwards.
  const card = stockCard([
    { ...base, stockGroup: 'Cement', closingValue: amt(-100) },
    { ...base, stockGroup: 'Steel', closingValue: amt(50) }, // negative stock
  ]);
  assert.equal(card.total.raw, 50);
  for (const g of card.groups) {
    assert.ok(g.share >= 0 && g.share <= 1, `share out of range for ${g.name}: ${g.share}`);
  }
  assert.equal(card.groups.find((g) => g.name === 'Steel')!.value.raw, -50, 'the raw value keeps its sign');
});

test('a wholly negative stock total does not produce a share at all', () => {
  const card = stockCard([{ ...base, stockGroup: 'Steel', closingValue: amt(50) }]);
  assert.equal(card.total.raw, -50);
  assert.equal(card.groups[0]!.share, 0);
});

// -------------------------------------------------- adversarial: trend

test('the trend must not net an EXPENSE group into sales', () => {
  // /sales/i matches "Sales Promotion Expenses" — an ordinary user group under Indirect
  // Expenses, which the revenue query returns because it filters on $IsRevenue. It arrives Dr
  // (negative) and is SUBTRACTED from the sales line. The owner reads sales as lower than it is.
  const card = salesTrendCard([
    rev('2026-07', 'Sales Accounts', 300000),
    rev('2026-07', 'Sales Promotion Expenses', -20000),
  ]);
  assert.equal(card.points.length, 1);
  assert.equal(card.points[0]!.value.raw, 300000, 'sales are 3L, not 2.8L');
});

test('the trend does not double-count a sub-group of Sales Accounts', () => {
  // The revenue collection returns every $IsRevenue group at every depth, and a parent closing
  // already contains its children.
  const card = salesTrendCard([
    rev('2026-07', 'Sales Accounts', 300000),
    rev('2026-07', 'Sales - Export', 100000),
  ]);
  assert.equal(card.points[0]!.value.raw, 300000);
});

test('trend periods sum exactly, without float drift', () => {
  const card = salesTrendCard([rev('2026-07', 'Sales Accounts', 0.1), rev('2026-07', 'Sales Accounts', 0.2)]);
  assert.equal(card.points[0]!.value.raw, 0.3);
});

test('a malformed period does not produce an undefined label', () => {
  for (const p of ['2026', 'garbage', '2026-13', '2026-00', '']) {
    const card = salesTrendCard([rev(p, 'Sales Accounts', 100)]);
    assert.equal(typeof card.points[0]!.label, 'string');
    assert.ok(card.points[0]!.label.length > 0 || p === '', `empty label for ${JSON.stringify(p)}`);
  }
});

test('all-equal periods are flat, not a fall', () => {
  const card = salesTrendCard([rev('2026-06', 'Sales Accounts', 100), rev('2026-07', 'Sales Accounts', 100)]);
  assert.equal(card.tone, 'good', 'holding steady is not a warning');
  assert.equal(card.peak.raw, 100);
});
