import { test } from 'node:test';
import assert from 'node:assert/strict';
import type {
  AgeingBucketRow,
  AgeingTotalRow,
  CashBankBalance,
  GroupBalance,
  PeriodRevenueRow,
  StockValueRow,
} from '@tally-bridge/core';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  profitCard,
  salesTrendCard,
  stockCard,
} from '@tally-bridge/viewmodel';
import { formatRelativeTime } from '@tally-bridge/viewmodel';
import { allText, byClass, byTag, firstByClass, installDom, texts, type FakeNode } from './dashboard.dom.ts';
import {
  LOCALES,
  LOCALE_NAMES,
  dateLabel,
  monthLabel,
  relativeTime,
  t as lookup,
  translator,
  type Locale,
} from '../src/renderer/i18n.ts';
import { donut, ringIsHonest, type Slice } from '../src/renderer/charts.ts';
import {
  renderAgeing,
  renderCashBank,
  renderProfit,
  renderSheet,
  renderStock,
  renderTrend,
} from '../src/renderer/cards.ts';

/**
 * Rendering tests.
 *
 * These drive the REAL card layer — `cashBankCard`, `ageingCard` and friends — and then the
 * real renderers, against a fake document. Nothing is stubbed between the wire format and the
 * nodes, which is the point: the bugs worth catching here (a coerced amount, an unescaped party
 * name, a bar wider than its track) all live at that seam, and a test that hand-built a view
 * model would step over every one of them.
 *
 * The data is deliberately hostile. Every fixture below is either something a real Tally file
 * contains or something a supplier can put in one.
 */

const dom = installDom();
process.on('exit', () => dom.uninstall());

const t = translator('en');
const hi = translator('hi');

const GUID = 'guid-1';

// Cash and stock are ASSETS: Dr, and Dr is negative in the house convention. So a healthy bank
// balance arrives here with a minus sign and the card layer flips it. Fixtures that "look
// right" on the wire are fixtures that are testing the wrong thing.
const cash = (ledgerName: string, closing: string, parent = 'Bank Accounts'): CashBankBalance => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  ledgerName,
  parent,
  closing,
});

const total = (bucket: AgeingTotalRow['bucket'], amount: string, billCount = 1): AgeingTotalRow => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  side: 'receivable',
  bucket,
  amount,
  billCount,
});

const bill = (partyName: string, bucket: AgeingBucketRow['bucket'], amount: string): AgeingBucketRow => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  side: 'receivable',
  partyName,
  bucket,
  amount,
  billCount: 1,
});

const rev = (period: string, groupName: string, amount: string, parent = ''): PeriodRevenueRow => ({
  companyGuid: GUID,
  period,
  groupName,
  parent,
  amount,
});

const stockRow = (stockGroup: string, closingValue: string): StockValueRow => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  stockGroup,
  closingValue,
});

const group = (groupName: string, parent: string, closing: string): GroupBalance => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  groupName,
  parent,
  primaryGroup: '',
  isRevenue: false,
  opening: '0.00',
  closing,
});

// ---------------------------------------------------------------- the XSS rule

/**
 * The canary. `A & B Traders <Mumbai>` is not a payload — it is an ordinary Indian trade name,
 * and that is exactly why it is the right test: an escaping bug that mangles it is a bug a real
 * customer reports on day one, and the same bug is an XSS the moment a supplier is called
 * `<img src=x onerror=...>`. Both are the same line of code.
 */
const HOSTILE = 'A & B Traders <Mumbai>';
const SCRIPTY = '<img src=x onerror="alert(1)">';
const DEVANAGARI = 'श्री राम ट्रेडर्स प्राइवेट लिमिटेड';
const ACCENTED = 'Café Coffee Supplies';
const LONG_NAME = 'Shree Krishna Enterprises and Allied Trading Company Limited';

test('THE XSS RULE: a hostile party name renders as TEXT, not as nodes', () => {
  const vm = ageingCard(
    [total('0_30', '-500000.00', 3)],
    [bill(HOSTILE, '0_30', '-300000.00'), bill(SCRIPTY, '0_30', '-200000.00')],
    'receivable',
  );
  const card = renderAgeing(vm, t) as unknown as FakeNode;

  // The name survives byte for byte — an escaping bug would show `A &amp; B Traders`.
  assert.ok(allText(card).includes(HOSTILE), 'the ampersand and the angle brackets must survive verbatim');
  assert.ok(allText(card).includes(SCRIPTY));

  // And it is text, not structure. Nothing parsed it.
  assert.equal(byTag(card, 'img').length, 0, 'a party name must never become an element');
  assert.equal(byTag(card, 'script').length, 0);

  const names = byClass(card, 'row-name').map((n) => n.textContent);
  assert.ok(names.includes(HOSTILE));
});

test('a 60-character name, Devanagari and an accented name all render intact', () => {
  assert.equal(LONG_NAME.length, 60);
  const vm = cashBankCard([
    cash(LONG_NAME, '-100000.00'),
    cash(DEVANAGARI, '-200000.00'),
    cash(ACCENTED, '-300000.00'),
  ]);
  const card = renderCashBank(vm, t) as unknown as FakeNode;
  const names = byClass(card, 'row-name').map((n) => n.textContent);
  // Truncation is CSS's job (`text-overflow: ellipsis`); the DOM must hold the whole name so
  // that the tooltip and a screen reader still get it.
  assert.ok(names.includes(LONG_NAME));
  assert.ok(names.includes(DEVANAGARI));
  assert.ok(names.includes(ACCENTED));
});

// ---------------------------------------------------------------- Indian numbering

test('THE NUMBERING is lakh/crore, and it comes from the card layer untouched', () => {
  const vm = cashBankCard([cash('HDFC CA 4471', '-342110.00'), cash('Cash in Hand', '-123456.00', 'Cash-in-Hand')]);
  const card = renderCashBank(vm, t) as unknown as FakeNode;
  const shown = texts(card);

  // ₹1,23,456 — never ₹123,456. The grouping IS the number's meaning to this reader.
  assert.ok(shown.includes('₹1,23,456'), `expected Indian grouping, got ${JSON.stringify(shown)}`);
  assert.ok(shown.includes('₹3,42,110'));
  assert.ok(shown.includes('₹4,65,566'), 'the total is the card layer\'s, not the renderer\'s');

  // Nothing on the card re-derives a rupee figure: every string above is a MoneyValue.display.
  assert.equal(vm.total.display, '₹4,65,566');
});

// ---------------------------------------------------------------- empty

test('EMPTY DATA: a brand-new company gets sentences, not a broken screen', () => {
  const cards: FakeNode[] = [
    renderCashBank(cashBankCard([]), t) as unknown as FakeNode,
    renderAgeing(ageingCard([], [], 'receivable'), t) as unknown as FakeNode,
    renderAgeing(ageingCard([], [], 'payable'), t) as unknown as FakeNode,
    renderProfit(profitCard([], []), t) as unknown as FakeNode,
    renderTrend(salesTrendCard([]), t, 'en') as unknown as FakeNode,
    renderStock(stockCard([]), t) as unknown as FakeNode,
    renderSheet(balanceSheetTree([]), t) as unknown as FakeNode,
  ];

  for (const card of cards) {
    // Every card says something. A blank card reads as a broken app; "Nobody owes you anything"
    // reads as good news, which for a new company it is.
    const note = firstByClass(card, 'card-empty');
    assert.ok(note, `a card rendered nothing at all: ${allText(card)}`);
    assert.ok(note.textContent.length > 10);
    // No stack traces, no codes, no "undefined".
    assert.ok(!/undefined|NaN|Error|\bat \w+\./.test(allText(card)), allText(card));
  }
});

test('₹0 renders as ₹0 and never as -₹0', () => {
  const vm = cashBankCard([cash('Petty Cash', '0.00', 'Cash-in-Hand')]);
  const card = renderCashBank(vm, t) as unknown as FakeNode;
  const shown = texts(card);
  assert.ok(shown.includes('₹0'));
  assert.ok(!shown.some((s) => s.includes('-₹0')), 'a rounded zero must not keep a sign');
  assert.equal(firstByClass(card, 'big')?.className, 'big neutral');
});

// ---------------------------------------------------------------- negatives

test('an overdrawn account is tone-bad and draws NO composition bar', () => {
  // Real: a current account in overdraft. Cr, so it arrives positive and flips negative.
  const vm = cashBankCard([cash('HDFC OD', '250000.00'), cash('Cash in Hand', '-50000.00', 'Cash-in-Hand')]);
  assert.equal(vm.tone, 'bad');

  const card = renderCashBank(vm, t) as unknown as FakeNode;
  assert.equal(firstByClass(card, 'big')?.className, 'big bad');
  assert.ok(texts(card).includes('-₹2,00,000'));
  // A stacked bar of shares of a NEGATIVE whole would overflow its own track and draw a
  // proportion that does not exist.
  assert.equal(firstByClass(card, 'stack'), undefined, 'no composition bar on a non-positive book');
  assert.ok(allText(card).includes(t('cash.overdrawn')));
});

/**
 * THE RING INVARIANT.
 *
 * The bug these pin was real and it shipped in this file: `donut()` dropped its non-positive
 * slices, so a book that nets NEGATIVE — advances exceeding what is owed — was drawn as a
 * confident 100% ring of the one positive bucket, centred under a headline that disagreed with
 * it. Every number in that picture was true. The picture was a lie.
 */
test('THE RING INVARIANT: a book that nets negative from advances gets a sentence, not a ring', () => {
  // A customer advance is Cr and flips negative here, so the book nets below zero while a real
  // ₹1L still sits 180 days late. This is ordinary for anyone taking deposits.
  const vm = ageingCard(
    [total('180_plus', '-100000.00', 1), total('not_due', '400000.00', 1)],
    [bill('Advance Customer', 'not_due', '400000.00'), bill(HOSTILE, '180_plus', '-100000.00')],
    'receivable',
  );
  assert.ok(vm.total.paise < 0, 'fixture must actually net negative');

  const card = renderAgeing(vm, t) as unknown as FakeNode;
  assert.equal(byClass(card, 'donut-slice').length, 0, 'no ring may be drawn over a negative whole');
  // And the state is NAMED, because it is a fact about the business and not a charting problem.
  assert.ok(allText(card).includes('paid more in advance than they owe'), allText(card));
  // The sentence carries the signed total straight from the card layer.
  assert.ok(allText(card).includes(vm.total.display));
  // The bars still show every bucket, signed and exact.
  assert.equal(byClass(card, 'bar-row').length, 2);
});

test('THE RING INVARIANT: a positive book with an advance inside one bucket draws no ring', () => {
  // Nets positive (+₹3L), but one bucket is negative. Segments still cannot be arcs.
  const vm = ageingCard(
    [total('not_due', '-500000.00', 2), total('0_30', '200000.00', 1)],
    [],
    'receivable',
  );
  assert.ok(vm.total.paise > 0, 'fixture must net positive');
  assert.ok(vm.buckets.some((b) => b.amount.paise < 0), 'fixture must hold a negative bucket');

  const card = renderAgeing(vm, t) as unknown as FakeNode;
  assert.equal(byClass(card, 'donut-slice').length, 0);
  assert.ok(allText(card).includes('would misread'), allText(card));
});

test('THE RING INVARIANT, directly: segments must sum to the drawn whole, exactly', () => {
  const s = (paise: number): Slice => ({ paise, tone: 'good', title: 'x' });

  // The honest case.
  assert.equal(ringIsHonest([s(300), s(700)], 1000), true);
  assert.ok(donut([s(300), s(700)], 1000, 'label') !== null);

  // One paisa out. Not "close enough" — there is no epsilon, because paise are integers and an
  // epsilon is where a real discrepancy hides.
  assert.equal(ringIsHonest([s(300), s(700)], 1001), false);
  assert.equal(donut([s(300), s(700)], 1001, 'label'), null);
  assert.equal(ringIsHonest([s(300), s(699)], 1000), false);

  // A negative segment can never be an arc, whatever the whole says.
  assert.equal(ringIsHonest([s(1200), s(-200)], 1000), false);
  assert.equal(donut([s(1200), s(-200)], 1000, 'label'), null);

  // A non-positive whole is not a whole.
  assert.equal(ringIsHonest([s(0)], 0), false);
  assert.equal(ringIsHonest([s(500)], -500), false);
  assert.equal(ringIsHonest([], 0), false);

  // The exact bug that shipped: drop the negative and the survivors "sum" to a ring of their
  // own. The invariant is what refuses it.
  assert.equal(ringIsHonest([s(1000)], -3000), false);
});

// ---------------------------------------------------------------- the donut

test('the donut slices are exact: they sum to one full turn', () => {
  const vm = ageingCard(
    [total('not_due', '-300000.00', 2), total('31_60', '-100000.00', 1), total('180_plus', '-100000.00', 1)],
    [bill(HOSTILE, '180_plus', '-100000.00')],
    'receivable',
  );
  const card = renderAgeing(vm, t) as unknown as FakeNode;
  const slices = byClass(card, 'donut-slice');
  assert.equal(slices.length, 3);

  const C = 2 * Math.PI * 42;
  const lengths = slices.map((s) => Number((s.getAttribute('stroke-dasharray') ?? '').split(' ')[0]));
  assert.ok(Math.abs(lengths.reduce((a, b) => a + b, 0) - C) < 0.01, 'the arcs must close the ring');

  // 3:1:1 of the total, computed from paise. Slice one is 60% of the circumference.
  assert.ok(Math.abs(lengths[0]! - C * 0.6) < 0.01);

  // Each slice starts where the last ended.
  /*
   * Assert the ATTRIBUTE STRING, not a re-parse of it.
   *
   * The first offset is `-0`: the code computes `(-offset).toFixed(3)` and `offset` starts at 0,
   * so the value handed to the DOM is negative zero. Reading it back through `Number()` and
   * comparing to `0` was the original assertion here and it is a trap in both directions —
   * `assert.equal` is Object.is under node:assert/strict, so `Number('-0.000')` would FAIL
   * against `0` while `Number('0.000')` passes, and neither outcome tells you what the attribute
   * actually says. This repo has already had an `Object.is(x, -0)` check go silently VACUOUS
   * when the value became a string, and pass forever while testing nothing.
   *
   * The string is what the browser parses, so the string is the thing to pin. `toFixed` on `-0`
   * yields "0.000" — no sign — which is what we assert, and it can genuinely fail: change the
   * accumulator or the sign and this line goes red.
   */
  assert.equal(slices[0]!.getAttribute('stroke-dashoffset'), '0.000');
  assert.equal(slices[1]!.getAttribute('stroke-dashoffset'), (-lengths[0]!).toFixed(3));
  assert.notEqual(slices[1]!.getAttribute('stroke-dashoffset'), '0.000', 'the second arc must be offset at all');
});

test('a single bucket fills the ring and does not divide by zero', () => {
  const vm = ageingCard([total('0_30', '-50000.00', 1)], [bill(ACCENTED, '0_30', '-50000.00')], 'receivable');
  const card = renderAgeing(vm, t) as unknown as FakeNode;
  const slices = byClass(card, 'donut-slice');
  assert.equal(slices.length, 1);
  const [len] = (slices[0]!.getAttribute('stroke-dasharray') ?? '').split(' ').map(Number);
  assert.ok(Math.abs(len! - 2 * Math.PI * 42) < 0.01);

  // One bucket, and it is not due, so nothing is overdue and the ring's centre says so.
  assert.equal(byClass(card, 'bar-row').length, 1);
});

test('every bar is inside its track, whatever the data', () => {
  const vm = ageingCard(
    [
      total('not_due', '-1000000.00', 5),
      total('0_30', '-1.00', 1),
      total('180_plus', '-999999.00', 9),
    ],
    [],
    'receivable',
  );
  const card = renderAgeing(vm, t) as unknown as FakeNode;
  for (const fill of byClass(card, 'bar-fill')) {
    const w = Number((fill.styles.get('--w') ?? '').replace('%', ''));
    assert.ok(w >= 2 && w <= 100, `bar width ${w}% is outside its track`);
  }
});

// ---------------------------------------------------------------- scale

test('10,000 parties render in a fixed number of rows', () => {
  const bills: AgeingBucketRow[] = [];
  for (let i = 0; i < 10_000; i++) bills.push(bill(`Party ${i} ${HOSTILE}`, '0_30', `-${(i + 1) * 100}.00`));
  const started = Date.now();
  const vm = ageingCard([total('0_30', '-5005000000.00', 10_000)], bills, 'receivable');
  const card = renderAgeing(vm, t) as unknown as FakeNode;
  const elapsed = Date.now() - started;

  // The card layer caps the list; the renderer must not undo that by iterating the raw rows.
  assert.equal(byClass(card, 'row-name').length, 6);
  assert.ok(elapsed < 2000, `10k parties took ${elapsed}ms`);
});

test('a huge chart of accounts builds only its roots; children wait for a click', () => {
  const rows: GroupBalance[] = [group('Sundry Debtors', '', '-5000000.00')];
  for (let i = 0; i < 5000; i++) rows.push(group(`Ledger Group ${i}`, 'Sundry Debtors', '-1000.00'));

  const tree = balanceSheetTree(rows);
  const started = Date.now();
  const card = renderSheet(tree, t) as unknown as FakeNode;
  const elapsed = Date.now() - started;

  // One root drawn. Five thousand children exist in the model and are not in the document.
  assert.equal(byClass(card, 'tree-node').length, 1);
  assert.ok(elapsed < 500, `${elapsed}ms to paint one root`);

  // Opening it builds them, once.
  const toggle = byClass(card, 'tree-toggle')[0]!;
  toggle.click();
  assert.equal(byClass(card, 'tree-node').length, 5001);
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  toggle.click();
  toggle.click();
  assert.equal(byClass(card, 'tree-node').length, 5001, 'reopening must not duplicate the children');
});

test('a long ledger list collapses behind a button', () => {
  const rows: CashBankBalance[] = [];
  for (let i = 0; i < 40; i++) rows.push(cash(`Bank ${i}`, `-${(i + 1) * 1000}.00`));
  const card = renderCashBank(cashBankCard(rows), t) as unknown as FakeNode;

  assert.equal(byClass(card, 'row-name').length, 6, 'the tail must not push the receivables card off screen');
  const more = firstByClass(card, 'link-button')!;
  assert.equal(more.textContent, 'Show all 40');
  more.click();
  assert.equal(byClass(card, 'row-name').length, 40);
  assert.equal(more.textContent, 'Show less');
});

// ---------------------------------------------------------------- columns

test('the sales trend plots against zero and puts a negative month below the line', () => {
  const rows = [
    rev('2026-05', 'Sales', '400000.00'),
    rev('2026-06', 'Sales', '-100000.00'), // a month of net returns: real, and it happens
    rev('2026-07', 'Sales', '800000.00'),
  ];
  const vm = salesTrendCard(rows);
  const card = renderTrend(vm, t, 'en') as unknown as FakeNode;

  const bars = byClass(card, 'column');
  assert.equal(bars.length, 3);
  assert.equal(bars[1]!.className.includes('negative'), true);
  assert.equal(bars[2]!.className.includes('accent'), true, 'the latest month is the one they came for');

  // The zero line exists only because a value went below it.
  assert.equal(byClass(card, 'zero-line').length, 1);

  // Heights are proportional to the amounts, not to their spread: 8L is twice 4L.
  const h = (n: FakeNode) => Number(n.getAttribute('height'));
  assert.ok(Math.abs(h(bars[2]!) / h(bars[0]!) - 2) < 0.01, 'a chart with a floating baseline lies');
});

test('a flat trend does not divide by zero', () => {
  const vm = salesTrendCard([rev('2026-06', 'Sales', '0.00'), rev('2026-07', 'Sales', '0.00')]);
  const card = renderTrend(vm, t, 'en') as unknown as FakeNode;
  for (const bar of byClass(card, 'column')) {
    const h = Number(bar.getAttribute('height'));
    assert.ok(Number.isFinite(h) && h >= 2, `height ${h}`);
  }
});

test('a single month of history says so instead of drawing a chart of one bar', () => {
  const vm = salesTrendCard([rev('2026-07', 'Sales', '500000.00')]);
  const card = renderTrend(vm, t, 'en') as unknown as FakeNode;
  assert.equal(byClass(card, 'column').length, 0);
  assert.ok(allText(card).includes(t('trend.empty')));
  // The number itself is still there — one month of sales is information.
  assert.ok(texts(card).includes('₹5,00,000'));
});

// ---------------------------------------------------------------- stock

test('the stock card uses the card layer\'s clamped share and never recomputes it', () => {
  // Negative stock is real: issued before receipt. The honest ratio then exceeds 1 or inverts.
  const vm = stockCard([stockRow('Cement', '-800000.00'), stockRow('Steel', '150000.00')]);
  const card = renderStock(vm, t) as unknown as FakeNode;
  const widths = byClass(card, 'bar-fill').map((n) => Number((n.styles.get('--w') ?? '').replace('%', '')));
  for (const w of widths) assert.ok(w >= 2 && w <= 100, `${w}%`);
  // The card layer already decided the negative group gets no bar.
  assert.equal(vm.groups.find((g) => g.name === 'Steel')?.share, 0);
});

// ---------------------------------------------------------------- profit

test('profit shows the delta the card layer computed, and "new" rather than a fake percentage', () => {
  const vm = profitCard([rev('2026-07', 'Sales', '500000.00')], []);
  const card = renderProfit(vm, t) as unknown as FakeNode;
  assert.equal(firstByClass(card, 'delta')?.textContent, 'new');
  assert.equal(firstByClass(card, 'delta')?.className, 'delta up');
  assert.ok(texts(card).includes('₹5,00,000'));
});

test('a loss is toned bad', () => {
  const vm = profitCard([rev('2026-07', 'Purchase Accounts', '-200000.00')], [rev('2026-06', 'Sales', '100000.00')]);
  assert.equal(vm.tone, 'bad');
  const card = renderProfit(vm, t) as unknown as FakeNode;
  assert.equal(firstByClass(card, 'big')?.className, 'big bad');
});

// ---------------------------------------------------------------- balance sheet

/*
 * THE BALANCE SHEET SHOWS BOTH SIDES POSITIVE, LIKE TALLY DOES.
 *
 * The test that used to live here asserted the opposite — `-₹5,00,000` for Current Assets —
 * and its own comment gave the game away: "The sign is explained, because 'your assets are
 * negative' is otherwise a support call." It saw the support call coming and chose to explain
 * it in a note rather than fix it. But Dr/Cr signing is Tally's INTERNAL convention: Tally's own
 * Balance Sheet screen shows assets positive, so the dashboard was contradicting the very
 * software the owner cross-checks it against.
 *
 * Siding by SIGN needs `primaryGroup` for nothing, which is what made this fixable — see
 * renderSheet.
 */
test('THE BALANCE SHEET SHOWS BOTH SIDES POSITIVE, the way Tally shows them', () => {
  const tree = balanceSheetTree([
    group('Current Assets', '', '-500000.00'),
    group('Bank Accounts', 'Current Assets', '-300000.00'),
    group('Capital Account', '', '500000.00'),
  ]);
  const card = renderSheet(tree, t) as unknown as FakeNode;

  const values = byClass(card, 'tree-value');
  assert.deepEqual(
    values.map((v) => [v.textContent, v.className]),
    [
      // Dr root, normalised against its own side: the owner OWNS five lakh.
      ['₹5,00,000', 'tree-value cr'],
      // Cr root, already positive on its side.
      ['₹5,00,000', 'tree-value cr'],
    ],
  );

  const text = allText(card);
  assert.ok(text.includes('What you own'), text);
  assert.ok(text.includes('What you owe'), text);
  // The jargon is gone. It explained an internal convention to a shop owner who has never seen
  // it in Tally, to excuse a presentation that should not have existed.
  assert.ok(!text.includes('Dr/Cr'), 'the Dr/Cr apology must not survive the fix');
  assert.ok(!text.includes('-₹'), `no minus on either side: ${text}`);
});

test('AN OVERDRAWN BANK STILL READS NEGATIVE — this is why it is not Math.abs', () => {
  // The case that makes blind `Math.abs` a WORSE lie than the one being fixed. An overdraft is a
  // CREDIT balance sitting under Current Assets: abs would print it as a positive asset and
  // delete the single most important fact on the card. Normalising against the ROOT's sign — not
  // against zero — keeps it negative, exactly as Tally shows an overdraft under Assets.
  const tree = balanceSheetTree([
    group('Current Assets', '', '-500000.00'),
    group('HDFC OD Account', 'Current Assets', '200000.00'),
  ]);
  const card = renderSheet(tree, t) as unknown as FakeNode;

  // The root reads positive on its side...
  assert.equal(byClass(card, 'tree-value')[0]?.textContent, '₹5,00,000');

  // ...and the overdrawn child, which opposes it, still reads negative once opened.
  const toggle = byClass(card, 'tree-toggle')[0];
  assert.ok(toggle, 'the root must be expandable');
  // `.click()` — the fake DOM's own test hook (dashboard.dom.ts fires the registered listeners).
  // There is no `dispatchEvent`, and reaching for one is how you end up testing a DOM you wish
  // you had.
  toggle.click();
  const od = byClass(card, 'tree-value').find((v) => v.textContent?.includes('2,00,000'));
  assert.equal(od?.textContent, '-₹2,00,000', 'an overdraft under Assets must keep its minus');
  assert.equal(od?.className, 'tree-value dr');
});

test('a NIL-balance root is named, never sided — the sign carries no information', () => {
  // Zero cannot be sided by sign, and `primaryGroup` is not trusted here (the flavour probe
  // reports it empty on some installs). Putting it under "What you own" would be inventing
  // information about a group holding no money. So it gets a name and nothing else.
  const tree = balanceSheetTree([
    group('Current Assets', '', '-500000.00'),
    group('Suspense Account', '', '0.00'),
  ]);
  const card = renderSheet(tree, t) as unknown as FakeNode;
  const text = allText(card);
  assert.ok(text.includes('Suspense Account'), 'a nil group must not vanish silently');
  assert.ok(text.includes('Nil balance'), text);
});

// ---------------------------------------------------------------- i18n

test('Hindi translates the buckets from the TOKEN, not from the view model\'s English label', () => {
  const vm = ageingCard(
    [total('91_180', '-100000.00', 1), total('not_due', '-100000.00', 1)],
    [bill(DEVANAGARI, '91_180', '-100000.00')],
    'receivable',
  );
  // The card layer is surface-agnostic but not locale-aware, and must not become so.
  assert.equal(vm.buckets[1]!.label, '91–180 days');

  const card = renderAgeing(vm, hi) as unknown as FakeNode;
  const labels = byClass(card, 'bar-label').map((n) => n.textContent);
  assert.deepEqual(labels, ['बाकी नहीं', '91–180 दिन']);
  assert.ok(allText(card).includes('सबसे ज़्यादा किससे लेना है'));

  // The party's own name is never translated, and the money is still Indian-grouped.
  assert.ok(allText(card).includes(DEVANAGARI));
  assert.ok(allText(card).includes('₹2,00,000'));
});

test('Hindi month labels come from the period, not from a Date', () => {
  const vm = salesTrendCard([rev('2026-01', 'Sales', '100.00'), rev('2026-07', 'Sales', '200.00')]);
  const card = renderTrend(vm, hi, 'hi') as unknown as FakeNode;
  const labels = byClass(card, 'column-label').map((n) => n.textContent);
  // `new Date('2026-01')` is UTC midnight and renders as December for anyone west of Greenwich.
  assert.deepEqual(labels, ['जन', 'जुल']);
});

test('A NEW LOCALE FALLS BACK TO ENGLISH, NEVER TO A NEIGHBOUR\'S LANGUAGE', () => {
  // The next language (Gujarati) looks exactly like this on the day it is added to LOCALES and
  // before a translator has touched it. The old `if (en) … else <Hindi>` shape answered
  // correctly for the two locales that existed and would have served every Gujarati user HINDI
  // timestamps — deliberate-looking, and insulting. English is untranslated; Hindi is wrong.
  const NEXT = 'gu' as Locale;

  const rel = relativeTime(NEXT, 0, 120_000);
  assert.equal(rel, formatRelativeTime(0, 120_000), 'an untranslated locale gets the shared English formatter');
  assert.equal(rel, '2 min ago');
  assert.ok(!/[ऀ-ॿ]/.test(rel), `Devanagari leaked into a non-Hindi locale: ${rel}`);

  // The same rule for the strings themselves — per KEY, so a half-done locale is half English
  // rather than half broken.
  assert.equal(lookup(NEXT, 'card.cash'), 'Cash & Bank');
  assert.equal(lookup(NEXT, 'ageing.total'), 'total');
  // ...and Hindi still works, so the fallback is not just swallowing everything.
  assert.equal(lookup('hi', 'card.cash'), 'नकद और बैंक');
  assert.equal(relativeTime('hi', 0, 120_000), '2 मिनट पहले');
  assert.equal(relativeTime('en', 0, 120_000), '2 min ago');
});

test('every locale is complete where completeness is compile-enforced', () => {
  // LOCALE_NAMES, DICTS and MONTHS are `Record<Locale, …>`, so tsc already fails on a missing
  // locale. This asserts the part tsc cannot: that the values are usable.
  for (const l of LOCALES) {
    assert.ok(LOCALE_NAMES[l].length > 0, `${l} has no name`);
    // A language's name is always written in that language — someone scanning for their own
    // language is looking for the word they know.
    assert.equal(monthLabel(l, '2026-07').length > 0, true);
    assert.equal(dateLabel(l, '2026-07-16').includes('2026'), true);
  }
});

// ---------------------------------------------------------------- accessibility

test('every chart is labelled, and every colour has a word beside it', () => {
  const vm = ageingCard(
    [total('0_30', '-100000.00', 1), total('180_plus', '-50000.00', 1)],
    [bill(HOSTILE, '180_plus', '-50000.00')],
    'receivable',
  );
  const card = renderAgeing(vm, t) as unknown as FakeNode;

  const chart = byTag(card, 'svg')[0]!;
  assert.equal(chart.getAttribute('role'), 'img');
  assert.ok((chart.getAttribute('aria-label') ?? '').includes('₹1,50,000'));

  // A tone dot never travels alone: the label beside it says the same thing in words.
  assert.equal(byClass(card, 'tone-dot').length, byClass(card, 'bar-label').length);
  for (const label of byClass(card, 'bar-label')) assert.ok(label.textContent.length > 0);

  // And the chip on a debtor row is a word, not just a colour.
  assert.equal(firstByClass(card, 'chip')?.textContent, '180d+');
});
