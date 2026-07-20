import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatDelta,
  formatMoney,
  formatMoneyCompact,
  formatRelativeTime,
  groupIndian,
} from '../src/format.ts';

test('THE MARKET DETAIL: Indian digit grouping, not Western', () => {
  // ₹1,23,456 reads instantly to an owner in Surat. ₹123,456 makes them stop and count.
  assert.equal(groupIndian('123456'), '1,23,456');
  assert.equal(groupIndian('1234'), '1,234');
  assert.equal(groupIndian('12345678'), '1,23,45,678');
  assert.equal(groupIndian('100000'), '1,00,000');
  assert.equal(groupIndian('10000000'), '1,00,00,000');
});

test('short numbers are not grouped', () => {
  assert.equal(groupIndian('1'), '1');
  assert.equal(groupIndian('12'), '12');
  assert.equal(groupIndian('123'), '123');
});

test('grouping matches the platform Intl (proving the hand-rolled version is right)', () => {
  // Cross-check against ICU where it IS available — but we do not depend on it at runtime,
  // because React Native ships without full ICU and would silently fall back to en-US grouping.
  const fmt = new Intl.NumberFormat('en-IN', { maximumFractionDigits: 0 });
  for (const n of [1, 12, 123, 1234, 12345, 123456, 1234567, 12345678, 123456789]) {
    assert.equal(groupIndian(String(n)), fmt.format(n), `mismatch at ${n}`);
  }
});

test('formatMoney renders rupees the way the market reads them', () => {
  assert.equal(formatMoney(123456), '₹1,23,456');
  assert.equal(formatMoney(342110.75), '₹3,42,111', 'rounds by default — cards do not want paise');
  assert.equal(formatMoney(342110.75, { paise: true }), '₹3,42,110.75');
  assert.equal(formatMoney(0), '₹0');
});

test('negatives render as a minus by default and in brackets on request', () => {
  assert.equal(formatMoney(-1234), '-₹1,234');
  assert.equal(formatMoney(-1234, { accountingNegative: true }), '(₹1,234)');
});

test('a non-finite amount degrades to a dash instead of NaN', () => {
  // "₹NaN" on a business dashboard destroys trust faster than an error message.
  assert.equal(formatMoney(NaN), '₹—');
  assert.equal(formatMoney(Infinity), '₹—');
});

test('compact form uses lakh and crore, not million and billion', () => {
  // An Indian trader thinks in crores. "1.2M" forces a conversion on every glance.
  assert.equal(formatMoneyCompact(12_000_000), '₹1.2 Cr');
  assert.equal(formatMoneyCompact(4_560_000), '₹45.6 L');
  assert.equal(formatMoneyCompact(12_300), '₹12.3 K');
  assert.equal(formatMoneyCompact(500), '₹500');
});

test('compact form drops a pointless trailing .0', () => {
  assert.equal(formatMoneyCompact(50_000_000), '₹5 Cr');
  assert.equal(formatMoneyCompact(100_000), '₹1 L');
});

test('compact negatives keep their sign', () => {
  assert.equal(formatMoneyCompact(-12_000_000), '-₹1.2 Cr');
});

test('delta reports direction and magnitude', () => {
  assert.deepEqual(formatDelta(150, 100), { text: '+50%', direction: 'up' });
  assert.deepEqual(formatDelta(50, 100), { text: '-50%', direction: 'down' });
  assert.deepEqual(formatDelta(100, 100), { text: 'no change', direction: 'flat' });
});

test('growth from zero is not reported as a percentage', () => {
  // "+∞%" and "+100%" are both lies. Say "new".
  assert.deepEqual(formatDelta(500, 0), { text: 'new', direction: 'up' });
  assert.deepEqual(formatDelta(0, 0), { text: 'no change', direction: 'flat' });
});

test('delta handles a negative baseline without flipping direction', () => {
  // Last month lost ₹100, this month lost ₹50: that is an improvement, not a -50% decline.
  const d = formatDelta(-50, -100);
  assert.equal(d.direction, 'up');
});

test('tiny changes read as flat rather than noise', () => {
  assert.equal(formatDelta(100.2, 100).direction, 'flat');
});

// ---------------------------------------------------------------- fuzz / boundaries

test('a value that rounds to zero never carries a minus sign', () => {
  // "-₹0" on a card reads as a debt that does not exist. If the digits we print are all zero,
  // the sign is printing information the number no longer contains.
  assert.equal(formatMoney(-0.4), '₹0');
  assert.equal(formatMoney(-0.004), '₹0');
  assert.equal(formatMoney(-0), '₹0');
  assert.equal(formatMoney(-0.004, { paise: true }), '₹0.00');
  assert.equal(formatMoney(-0.4, { accountingNegative: true }), '₹0', 'nor brackets');
  assert.equal(formatMoneyCompact(-0.4), '₹0');
  // ...but a value that still has a digit keeps it.
  assert.equal(formatMoney(-0.6), '-₹1');
  assert.equal(formatMoney(-0.005, { paise: true }), '-₹0.01');
});

test('an absurd magnitude never leaks exponential notation into the digits', () => {
  // toFixed switches to "1e+21" at 1e21, and groupIndian would cheerfully render that as
  // "₹1e,+21". Nothing upstream clamps a raw closing balance before it reaches a card.
  // 1e21 is a 1 followed by 21 zeros: 22 digits, grouped 1 / nine pairs / final three.
  assert.equal(formatMoney(1e21), '₹1,00,00,00,00,00,00,00,00,00,000');
  assert.equal(formatMoney(-1e21), '-₹1,00,00,00,00,00,00,00,00,00,000');
  assert.equal(formatMoney(1e21, { paise: true }), '₹1,00,00,00,00,00,00,00,00,00,000.00');
  assert.equal(formatMoney(1e21).replace(/[₹,]/g, ''), '1' + '0'.repeat(21), 'digits survive intact');
  for (const v of [1e21, 1e22, 5e23, 1e28, 1e30]) {
    assert.ok(!/[e+]/.test(formatMoney(v)), `exponent leaked at ${v}: ${formatMoney(v)}`);
    // The compact path divides by a crore first, so it only trips 1e28 and up.
    assert.ok(!/[e+]/.test(formatMoneyCompact(v)), `exponent leaked at ${v}: ${formatMoneyCompact(v)}`);
  }
  assert.equal(formatMoney(Number.MAX_SAFE_INTEGER), '₹9,00,71,99,25,47,40,991');
});

test('compact units never round across their own boundary', () => {
  // 99,999 is 99.999 K, which rounds to "100.0" -> "₹100 K". That reads LARGER than the very
  // next rupee, ₹1,00,000 -> "₹1 L". The unit must agree with the digits after rounding.
  assert.equal(formatMoneyCompact(99_999), '₹1 L');
  assert.equal(formatMoneyCompact(9_999_999), '₹1 Cr');
  assert.equal(formatMoneyCompact(999_999_999), '₹100 Cr', 'Cr is the top unit — 100 Cr is correct');
});

test('compact boundaries are exact, with no gap and no overlap', () => {
  assert.equal(formatMoneyCompact(999), '₹999');
  assert.equal(formatMoneyCompact(1_000), '₹1 K');
  assert.equal(formatMoneyCompact(99_500), '₹99.5 K');
  assert.equal(formatMoneyCompact(100_000), '₹1 L');
  assert.equal(formatMoneyCompact(9_950_000), '₹99.5 L');
  assert.equal(formatMoneyCompact(10_000_000), '₹1 Cr');
  // MONOTONICITY is the invariant that survives rounding: two nearby values may compact to the
  // same string (that is the point of compacting), but a bigger number must never READ smaller
  // than a smaller one. That is what "₹100 K" for 99,999 broke, right next to "₹1 L".
  const parse = (s: string): number => {
    const m = /^(-?)₹([\d,.]+)(?: (K|L|Cr))?$/.exec(s);
    assert.ok(m, `unparseable compact output: ${s}`);
    const mult = { K: 1_000, L: 100_000, Cr: 10_000_000 }[m![3] ?? ''] ?? 1;
    return Number(m![2]!.replace(/,/g, '')) * mult * (m![1] ? -1 : 1);
  };
  let prev = -Infinity;
  for (let v = 0; v < 20_000_000; v += 997) {
    const read = parse(formatMoneyCompact(v));
    assert.ok(read >= prev, `${v} reads as ${formatMoneyCompact(v)}, smaller than the value before it`);
    // One decimal place at the bottom of a unit ("₹1 L" covers 0.95–1.05 L) is inherently
    // ±5%. Anything worse than that is a rounding bug, not the cost of compacting.
    assert.ok(Math.abs(read - v) <= v * 0.051 + 0.5, `${v} reads as ${formatMoneyCompact(v)} — too far off`);
    prev = read;
  }
});

test('a non-finite delta degrades instead of printing "NaN%"', () => {
  // formatMoney guards this; formatDelta did not, and "+Infinity%" beside a "₹—" is worse than
  // either alone.
  assert.deepEqual(formatDelta(NaN, 100), { text: '—', direction: 'flat' });
  assert.deepEqual(formatDelta(100, NaN), { text: '—', direction: 'flat' });
  assert.deepEqual(formatDelta(Infinity, 100), { text: '—', direction: 'flat' });
  assert.deepEqual(formatDelta(100, Infinity), { text: '—', direction: 'flat' });
});

test('a sub-rupee baseline is not a baseline', () => {
  // The card renders previous as "₹0". A percentage measured against a base the SAME card shows
  // as zero is fabricated precision: "+99999900%" is arithmetically true and a lie in context.
  assert.deepEqual(formatDelta(1000, 0.001), { text: 'new', direction: 'up' });
  assert.deepEqual(formatDelta(0.2, 0.001), { text: 'no change', direction: 'flat' });
  assert.deepEqual(formatDelta(-1000, 0.4), { text: 'new', direction: 'down' });
});

test('delta across a sign change reports the real direction', () => {
  // Lost ₹1L last month, made ₹50k this month: unambiguously up.
  assert.deepEqual(formatDelta(50_000, -100_000), { text: '+150%', direction: 'up' });
  // Made ₹50k last month, lost ₹1L this month: unambiguously down.
  assert.deepEqual(formatDelta(-100_000, 50_000), { text: '-300%', direction: 'down' });
});

test('relative time is human', () => {
  const now = 1_752_600_000_000;
  assert.equal(formatRelativeTime(now, now), 'just now');
  assert.equal(formatRelativeTime(now - 30_000, now), 'just now');
  assert.equal(formatRelativeTime(now - 120_000, now), '2 min ago');
  assert.equal(formatRelativeTime(now - 3_600_000, now), '1 hour ago');
  assert.equal(formatRelativeTime(now - 7_200_000, now), '2 hours ago');
  assert.equal(formatRelativeTime(now - 86_400_000, now), '1 day ago');
  assert.equal(formatRelativeTime(now - 172_800_000, now), '2 days ago');
});

test('a clock skewed into the future does not render "in -5 minutes"', () => {
  // SMB PCs have wrong clocks constantly.
  const now = 1_752_600_000_000;
  assert.equal(formatRelativeTime(now + 60_000, now), 'just now');
});
