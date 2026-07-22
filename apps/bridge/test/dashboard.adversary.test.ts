import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AgeingBucketRow, AgeingTotalRow, CashBankBalance, PeriodRevenueRow } from '@tally-bridge/core';
import { ageingCard, cashBankCard, formatMoney, formatMoneyCompact, salesTrendCard } from '@tally-bridge/viewmodel';
import type { BridgeApi, CompanyCards, GetCardsResult } from '../src/main/ipc.ts';
import type { SyncStatus } from '../src/main/scheduler.ts';
import { mountDashboard } from '../src/renderer/dashboard.ts';
import { renderAgeing, renderTrend } from '../src/renderer/cards.ts';
import { donut, ringIsHonest, type Slice } from '../src/renderer/charts.ts';
import { translator } from '../src/renderer/i18n.ts';
import { allText, byClass, firstByClass, installDom, type FakeNode } from './dashboard.dom.ts';

/**
 * ADVERSARIAL tests. Written to BREAK the dashboard, not to describe it.
 */

const dom = installDom();
process.on('exit', () => dom.uninstall());

const GUID = 'guid-acme';

const cashRow = (closing: string): CashBankBalance => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  ledgerName: 'HDFC CA 4471',
  parent: 'Bank Accounts',
  closing,
});

function company(closing: string): CompanyCards {
  return {
    companyGuid: GUID,
    name: 'Acme Traders',
    asOf: '2026-07-16',
    cashBank: cashBankCard([cashRow(closing)]),
  };
}

const ready = (closing: string): GetCardsResult => ({
  state: 'ready',
  companies: [company(closing)],
  incomplete: false,
});

function fakeBridge(overrides: Partial<BridgeApi> = {}): BridgeApi {
  const notOurs = (verb: string) => (): never => {
    throw new Error(`the dashboard must not call ${verb}`);
  };
  return {
    getStatus: async () => ({ state: 'ok', message: 'Synced', lastRun: 1_000_000 }) as SyncStatus,
    syncNow: async () => {},
    isProvisioned: async () => true,
    detectTally: async () => ({ reachable: true, message: '', companies: [] }),
    unlock: async () => true,
    lock: async () => {},
    resetDashboard: async () => {},
    rebuildFromTally: async () => {},
    getCards: async () => ready('-100000.00'),
    openExternal: async () => {},
    onStatusChanged: () => () => {},
    getWizardState: notOurs('getWizardState'),
    sendWizardEvent: notOurs('sendWizardEvent'),
    onWizardStateChanged: notOurs('onWizardStateChanged'),
    recoveryQr: notOurs('recoveryQr'),
    printRecoverySheet: notOurs('printRecoverySheet'),
    ...overrides,
  };
}

const container = (): FakeNode => document.createElement('div') as unknown as FakeNode;
const tick = async (n = 8): Promise<void> => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

const t = translator('en');

const arTotal = (bucket: AgeingTotalRow['bucket'], amount: string, billCount = 1): AgeingTotalRow => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  side: 'receivable',
  bucket,
  amount,
  billCount,
});

const arBill = (partyName: string, bucket: AgeingBucketRow['bucket'], amount: string): AgeingBucketRow => ({
  companyGuid: GUID,
  asOf: '2026-07-16',
  side: 'receivable',
  partyName,
  bucket,
  amount,
  billCount: 1,
});

const rev = (period: string, amount: string): PeriodRevenueRow => ({
  companyGuid: GUID,
  period,
  groupName: 'Sales',
  parent: '',
  amount,
});

// ---------------------------------------------------------------- ATTACK: the centre label

/**
 * THE THIRD INSTANCE.
 *
 * `renderAgeing` claims: "The centre prints the ring's WHOLE, never a different quantity...
 * Putting `overdue` here (as this once did) made the arcs sum to a number that was nowhere in
 * the middle of them." That bug has now been introduced TWICE in this codebase and NOTHING
 * asserted the fix: swapping `vm.total.compact` for `vm.overdue.compact` left all 73 tests
 * green. The ring-invariant tests only check the ARCS; the centre is a second, unchecked claim
 * printed in 28px in the middle of them.
 *
 * The failure is silent and total: the arcs are the parts of ₹4 L and the number they surround
 * says ₹1 L. Every arc is true, the number is true, and the picture is a lie — which is the
 * exact family of bug `ringIsHonest` was written to end.
 */
test('ADVERSARY: the ring centre prints the RING\'S WHOLE, not some other quantity', () => {
  const vm = ageingCard(
    [arTotal('not_due', '-300000.00', 2), arTotal('180_plus', '-100000.00', 1)],
    [arBill('Shah & Co <Surat>', '180_plus', '-100000.00')],
    'receivable',
  );
  // The fixture must make the two candidates DIFFERENT, or this asserts nothing.
  assert.equal(vm.total.compact, '₹4 L');
  assert.equal(vm.overdue.compact, '₹1 L');
  assert.notEqual(vm.total.compact, vm.overdue.compact, 'fixture must distinguish total from overdue');

  const card = renderAgeing(vm, t) as unknown as FakeNode;
  const arcs = byClass(card, 'donut-slice');
  assert.equal(arcs.length, 2, 'this fixture must actually draw a ring');

  const centre = firstByClass(card, 'donut-center-top');
  assert.ok(centre, 'a ring must carry its whole in its centre');
  assert.equal(
    centre.textContent,
    vm.total.compact,
    'THE CENTRE DISAGREES WITH THE ARCS AROUND IT. The arcs are the parts of vm.total; the ' +
      'centre must be vm.total and nothing else.',
  );
  assert.notEqual(centre.textContent, vm.overdue.compact, 'the centre must never be `overdue` — that bug shipped');

  // And the arcs really are the parts of the number in the middle: 3:1.
  const len = (n: FakeNode) => Number((n.getAttribute('stroke-dasharray') ?? '').split(' ')[0]);
  assert.ok(Math.abs(len(arcs[0]!) / len(arcs[1]!) - 3) < 0.001, 'the arcs must be 3:1, the parts of ₹4 L');
});

// ---------------------------------------------------------------- ATTACK: BUG-6 regrowth

/**
 * `cards.ts` claims: "Bar widths and arc lengths are computed from `.paise` — exact integers —
 * and never from `.raw`. Adding `raw` values is BUG-6, and BUG-6 shipped believable numbers."
 *
 * Nothing asserted it. Swapping `b.amount.paise` for `b.amount.raw` in the bar peak left every
 * test green — because `raw` is 100x smaller, every share clamps to 1 and every bar renders at
 * a confident, identical 100%. A picture in which a ₹1 L bucket and a ₹3 L bucket are the same
 * length is exactly the "believable number" failure mode.
 */
test('ADVERSARY: bar widths come from exact paise, and stay proportional', () => {
  const vm = ageingCard(
    [arTotal('not_due', '-300000.00', 2), arTotal('180_plus', '-100000.00', 1)],
    [],
    'receivable',
  );
  const card = renderAgeing(vm, t) as unknown as FakeNode;
  const widths = byClass(card, 'bar-fill').map((n) => Number((n.styles.get('--w') ?? '').replace('%', '')));
  assert.equal(widths.length, 2);

  // The biggest bucket fills its track; the ₹1 L bucket is a THIRD of it — not another 100%.
  assert.ok(Math.abs(widths[0]! - 100) < 0.01, `the peak bucket must fill its track, got ${widths[0]}%`);
  assert.ok(
    Math.abs(widths[1]! - 100 / 3) < 0.01,
    `a bucket a third the size must draw a third the bar, got ${widths[1]}% — a peak taken from ` +
      `\`raw\` (rupees) instead of \`paise\` clamps every share to 1 and draws them all identical`,
  );
});

// ---------------------------------------------------------------- ATTACK: the floating baseline

/**
 * `columnChart` claims: "The scale always includes zero... a chart whose baseline is not zero
 * exaggerates every difference on it, which on a sales trend is a chart that lies."
 *
 * Their test for this ("a chart with a floating baseline lies") uses a fixture that ALREADY
 * contains a negative month, so `Math.max(0, …)` and `Math.max(…)` return the same numbers and
 * the assertion holds either way — it is vacuous for the property it is named after. An
 * ALL-POSITIVE trend is where the baseline can float, and it is also the ordinary case: most
 * months are not net returns.
 */
test('ADVERSARY: an ALL-POSITIVE trend is still measured from zero', () => {
  const vm = salesTrendCard([rev('2026-05', '400000.00'), rev('2026-06', '500000.00'), rev('2026-07', '800000.00')]);
  const card = renderTrend(vm, t, 'en') as unknown as FakeNode;
  const bars = byClass(card, 'column');
  assert.equal(bars.length, 3);

  const h = (n: FakeNode) => Number(n.getAttribute('height'));
  const y = (n: FakeNode) => Number(n.getAttribute('y'));
  const PLOT_H = 96;

  // ₹8 L is the peak, so it fills the plot; ₹4 L is HALF of it, not a zero-height stub.
  assert.ok(Math.abs(h(bars[2]!) - PLOT_H) < 0.01, `the peak must fill the plot, got ${h(bars[2]!)}`);
  assert.ok(
    Math.abs(h(bars[0]!) - PLOT_H / 2) < 0.01,
    `₹4 L against a ₹8 L peak must be half the plot; got ${h(bars[0]!)} — a baseline that floats ` +
      `up to the smallest month draws ₹4 L as nothing and ₹5 L as a third of ₹8 L`,
  );

  // Nothing may escape the plot, and there is no zero line to draw on an all-positive trend.
  for (const b of bars) {
    assert.ok(y(b) >= -0.01 && y(b) + h(b) <= PLOT_H + 0.01, `bar escapes the plot: y=${y(b)} h=${h(b)}`);
  }
  assert.equal(byClass(card, 'zero-line').length, 0, 'the zero line is the floor here and would just thicken the axis');
});

// ---------------------------------------------------------------- ATTACK: out-of-order responses

/**
 * THE ATTACK: two refreshes in flight, the OLDER one resolving last.
 *
 * `refresh()` has no request-sequence guard: it assigns `model = buildModel(payload)` with
 * whatever its own await resolved to, whenever it resolves. Two refreshes overlap trivially in
 * the real app — the company picker calls `void refresh()` on every click, the error card's
 * "Try again" calls `void refresh()` on every press, `sync()` calls it, and the shell holds an
 * exported `refresh()` too. IPC over a busy single-threaded main process does not answer in
 * order.
 *
 * The result is a stale figure under whatever status the newest call painted.
 */
test('ADVERSARY: a slow OLD getCards must not overwrite a fast NEW one', async (t) => {
  const root = container();
  /** Every in-flight getCards, in call order, each parked until its gate is opened. */
  const gates: Array<(r: GetCardsResult) => void> = [];

  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: () => new Promise<GetCardsResult>((resolve) => gates.push(resolve)),
    }),
    now: () => 1_000_000,
    locale: 'en',
    chrome: false,
  });
  t.after(() => dash.destroy());

  // Let mountDashboard's own refresh park on gate 0 and answer it, so the board is at a known
  // state before the race.
  await tick(2);
  gates[0]?.(ready('-100000.00'));
  await tick(4);
  assert.ok(allText(root).includes('₹1,00,000'), `setup: ${allText(root)}`);

  // Refresh #1 (the STALE payload — a busy main process, a big decrypt) starts and parks.
  const first = dash.refresh();
  await tick(2);
  // Refresh #2 (the FRESH payload) starts and answers first.
  const second = dash.refresh();
  await tick(2);
  assert.equal(gates.length, 3, 'both refreshes must actually be in flight');

  gates[2]?.(ready('-900000.00'));
  await second;
  await tick(2);
  assert.ok(allText(root).includes('₹9,00,000'), 'the fresh payload should be on screen');

  // Now the OLD call finally answers.
  gates[1]?.(ready('-100000.00'));
  await first;
  await tick(2);

  assert.ok(
    !allText(root).includes('₹1,00,000'),
    `A STALE PAYLOAD OVERWROTE A NEWER ONE. The owner is reading ₹1,00,000 while the bridge's ` +
      `latest answer is ₹9,00,000. Screen: ${allText(root)}`,
  );
  assert.ok(allText(root).includes('₹9,00,000'), 'the newest answer must win');
});

// ---------------------------------------------------------------- ATTACK: the ring

test('ADVERSARY: NaN, Infinity and floats can never become an arc', () => {
  const s = (paise: number): Slice => ({ paise, tone: 'good', title: 'x' });

  assert.equal(ringIsHonest([s(NaN), s(1000)], 1000), false, 'NaN slice');
  assert.equal(ringIsHonest([s(Infinity)], Infinity), false, 'Infinity slice and whole');
  assert.equal(ringIsHonest([s(500), s(500)], NaN), false, 'NaN whole');
  assert.equal(ringIsHonest([s(300.5), s(699.5)], 1000), false, 'float slices that sum exactly');
  assert.equal(ringIsHonest([s(1000)], 1000.0000001), false, 'float whole');
  assert.equal(ringIsHonest([s(0), s(0)], 0), false, 'all-zero slices on a zero whole');
  assert.equal(ringIsHonest([s(-0)], 0), false, 'negative zero whole');
  assert.equal(donut([s(NaN), s(1000)], 1000, 'l'), null);
  assert.equal(donut([s(300.5), s(699.5)], 1000, 'l'), null);

  // 2^53: integer addition stops being exact above here. Number.isInteger still says yes, so
  // this is the one place the "exact integer" claim leans on the source rather than the check.
  // ₹90,071,992,547,409.91 is not a receivable anyone has; recorded, not asserted as a bug.
  assert.equal(ringIsHonest([s(2 ** 53), s(1)], 2 ** 53 + 1), true);
});

// ---------------------------------------------------------------- ATTACK: compact numbering

test('ADVERSARY: formatMoneyCompact is monotonic across every unit boundary', () => {
  const cases: number[] = [
    0, -0, 1, 999, 1000, 1001, 99_499, 99_500, 99_999, 100_000, 100_001, 999_999, 1_000_000,
    9_999_999, 10_000_000, 10_000_001, 99_999_999, 100_000_000, 1_000_000_000,
  ];
  for (const n of cases) {
    const s = formatMoneyCompact(n);
    assert.ok(!s.includes('e+'), `${n} leaked an exponent: ${s}`);
    assert.ok(!/^-₹0$|^₹-/.test(s), `${n} produced ${s}`);
  }

  // The bug that was real: "₹100 K" reading smaller than the very next rupee's "₹1 L".
  assert.equal(formatMoneyCompact(99_999), '₹1 L');
  assert.equal(formatMoneyCompact(100_000), '₹1 L');
  assert.equal(formatMoneyCompact(999_999), '₹10 L');
  assert.equal(formatMoneyCompact(1_000_000), '₹10 L');
  assert.equal(formatMoneyCompact(9_999_999), '₹1 Cr');
  assert.equal(formatMoneyCompact(10_000_000), '₹1 Cr');
  assert.equal(formatMoneyCompact(-12_345_678), '-₹1.2 Cr');

  // Never a bare ASCII grouping.
  assert.equal(formatMoney(123456), '₹1,23,456');
  assert.equal(formatMoney(12345678), '₹1,23,45,678');
});

/**
 * THE ROUNDED ZERO, exercised where it can actually fail.
 *
 * The existing "₹0 renders as ₹0 and never as -₹0" test feeds the card a `0.00` closing. That
 * makes `rupees` exactly `-0`, and `-0 < 0` is FALSE — so the `hasNonZeroDigit` guard the test
 * is named after is never reached and the assertion holds with the guard deleted. Confirmed by
 * mutation: removing `&& hasNonZeroDigit(fixed)` leaves that test green.
 *
 * The value that reaches the guard is a SUB-RUPEE negative, which is not exotic: a 40-paise
 * remnant on a settled ledger is what a rounded-off Tally book looks like. It must read "₹0",
 * because "-₹0" asserts a debt whose digits are no longer there.
 */
test('ADVERSARY: a sub-rupee negative rounds to ₹0 and DROPS ITS SIGN', () => {
  // -0.4 rupees: rounds to zero, and `-0.4 < 0` is genuinely true, so the guard is live here.
  assert.equal(formatMoney(-0.4), '₹0');
  assert.equal(formatMoney(-0.004), '₹0');
  assert.equal(formatMoneyCompact(-0.4), '₹0');
  assert.equal(formatMoney(-0.5), '-₹1', 'and a value that still rounds to a rupee keeps its sign');
  assert.equal(formatMoney(-0.4, { paise: true }), '-₹0.40', 'with paise shown, the digits are there again');

  // Both zeroes, through the real card layer: a ledger holding 40 paise Cr.
  const vm = cashBankCard([{ ...cashRow('0.40'), ledgerName: 'Petty Cash', parent: 'Cash-in-Hand' }]);
  assert.equal(vm.total.paise, -40, 'fixture must be a live sub-rupee negative, not -0');
  assert.ok(vm.total.raw < 0);
  assert.equal(vm.total.display, '₹0', 'a rounded zero must not keep a sign the digits no longer carry');
  assert.equal(vm.accounts[0]!.balance.display, '₹0');
});

// ---------------------------------------------------------------- ATTACK: staleness

test('ADVERSARY: a status push cannot desynchronise from the data it tones', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge(),
    now: () => 1_000_000,
    locale: 'en',
  });
  await dash.refresh();

  // A status push saying "ok" while the model is `unavailable` must not paint a green dot over
  // an error card that has no numbers... but it also must not tone a grid that is not there.
  dash.setStatus({ state: 'error', message: 'Tally stopped responding.', action: 'Try again' });
  assert.equal(firstByClass(root, 'grid')?.classList.contains('stale'), true);
  dash.setStatus({ state: 'ok', message: 'Synced', lastRun: 1_000_000 });
  assert.equal(firstByClass(root, 'grid')?.classList.contains('stale'), false);
  dash.destroy();
});
