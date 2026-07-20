/**
 * Number formatting for an Indian audience.
 *
 * This is not a cosmetic detail. A business owner in Surat reads `₹1,23,456` instantly and
 * stumbles over `₹123,456` — the digit grouping IS the number's meaning to them. Getting this
 * wrong makes the product feel foreign on the first screen, before anyone has evaluated a
 * single feature.
 *
 * Pure functions returning strings — no DOM, no React, no framework. That is what lets the
 * desktop renderer, a web dashboard, and a React Native app share this verbatim.
 */

/**
 * Indian digit grouping: last three digits, then pairs.
 *
 *   1234       ->      1,234
 *   123456     ->    1,23,456
 *   12345678   -> 1,23,45,678   (1.23 crore)
 *
 * Implemented directly rather than via Intl.NumberFormat('en-IN'). Intl is available on every
 * target we care about, but its output depends on the ICU data the runtime was BUILT with —
 * React Native ships without full ICU by default, and a stripped Node/Electron build can fall
 * back to en-US grouping silently. A number that renders differently on mobile than on desktop
 * is a bug report we would struggle to reproduce. 20 lines removes the dependency.
 */
export function groupIndian(digits: string): string {
  if (digits.length <= 3) return digits;
  const last3 = digits.slice(-3);
  const rest = digits.slice(0, -3);
  // Everything above the last three digits is grouped in pairs, right to left.
  const pairs = rest.replace(/\B(?=(\d{2})+(?!\d))/g, ',');
  return `${pairs},${last3}`;
}

export interface MoneyOptions {
  /** Show paise. Default false: an owner scanning cards does not want two decimals of noise. */
  paise?: boolean;
  /** Prefix with ₹. Default true. */
  symbol?: boolean;
  /** Render negatives as (1,234) rather than -1,234, per accounting convention. */
  accountingNegative?: boolean;
}

/**
 * `toFixed` without the exponential cliff.
 *
 * `(1e21).toFixed(0)` is `"1e+21"`, not `"1000000000000000000000"` — and `groupIndian` would
 * cheerfully render that as `"1e,+21"`. Nothing upstream clamps a value before it reaches a card
 * (`money()` formats a raw `closing` straight off the wire), so a corrupt row must degrade to
 * *wrong but readable digits*, never to punctuation soup.
 *
 * Every float at or above 1e21 is already an integer — 2^53 is ~9e15 — so BigInt renders it
 * exactly, and the fractional part is definitionally zero.
 */
function toFixedPlain(abs: number, dp: number): string {
  if (abs < 1e21) return abs.toFixed(dp);
  const whole = BigInt(abs).toString();
  return dp > 0 ? `${whole}.${'0'.repeat(dp)}` : whole;
}

/** True when a rendered magnitude still has a significant digit — i.e. it is not a rounded zero. */
function hasNonZeroDigit(s: string): boolean {
  return /[1-9]/.test(s);
}

/** Format rupees for display. Input is a signed decimal number of rupees. */
export function formatMoney(rupees: number, opts: MoneyOptions = {}): string {
  const { paise = false, symbol = true, accountingNegative = false } = opts;

  if (!Number.isFinite(rupees)) return symbol ? '₹—' : '—';

  const abs = Math.abs(rupees);
  const fixed = toFixedPlain(abs, paise ? 2 : 0);
  const [whole = '0', frac] = fixed.split('.');

  // A value that ROUNDS to zero must not keep its sign. `-0.4` formatted to rupees is "0", and
  // "-₹0" reads as a debt that does not exist — the sign would be asserting information the
  // digits no longer carry. This also covers negative zero, which `-0 < 0` misses but which
  // arithmetic here produces readily.
  const negative = rupees < 0 && hasNonZeroDigit(fixed);

  let out = groupIndian(whole);
  if (paise && frac) out += `.${frac}`;
  if (symbol) out = `₹${out}`;
  if (negative) out = accountingNegative ? `(${out})` : `-${out}`;
  return out;
}

/** Descending, because the unit is chosen by the first threshold the value clears. */
const COMPACT_UNITS = [
  { div: 10_000_000, suffix: ' Cr' },
  { div: 100_000, suffix: ' L' },
  { div: 1_000, suffix: ' K' },
] as const;

/**
 * Compact form for big headline numbers: 1.2 Cr, 45.6 L, 12.3 K.
 *
 * Lakh and crore, not million and billion. An Indian trader thinks in crores; "12.3M" requires
 * a conversion step every single time they look at the card.
 */
export function formatMoneyCompact(rupees: number, opts: { symbol?: boolean } = {}): string {
  const { symbol = true } = opts;
  if (!Number.isFinite(rupees)) return symbol ? '₹—' : '—';

  const abs = Math.abs(rupees);

  let out: string;
  const i = COMPACT_UNITS.findIndex((u) => abs >= u.div);
  if (i === -1) {
    out = groupIndian(Math.round(abs).toString());
  } else {
    let unit = COMPACT_UNITS[i]!;
    let s = trim(abs / unit.div);
    // Rounding to one decimal can push a value across its own unit: 99,999 is 99.999 K, which
    // trims to "100 K" — and "₹100 K" reads LARGER than the very next rupee, ₹1,00,000, which
    // renders "₹1 L". Every unit here steps by 100, so promoting once always resolves it. Cr is
    // the top unit and legitimately runs past 100.
    if (Number(s) >= 100 && i > 0) {
      unit = COMPACT_UNITS[i - 1]!;
      s = trim(abs / unit.div);
    }
    out = `${s}${unit.suffix}`;
  }

  // Same rule as formatMoney: a rounded zero keeps no sign.
  const negative = rupees < 0 && hasNonZeroDigit(out);
  if (symbol) out = `₹${out}`;
  return negative ? `-${out}` : out;
}

function trim(n: number): string {
  // One decimal, but drop a trailing ".0" — "5 Cr" reads better than "5.0 Cr".
  // toFixedPlain, not toFixed: a value past 1e28 is still past 1e21 after dividing by a crore,
  // and "₹1e+23 Cr" is the same exponential leak by a longer route.
  const s = toFixedPlain(n, 1);
  return s.endsWith('.0') ? s.slice(0, -2) : s;
}

/** Percentage change, for the "vs last month" line. */
export function formatDelta(current: number, previous: number): { text: string; direction: 'up' | 'down' | 'flat' } {
  // formatMoney degrades a non-finite amount to "—"; without the same guard here the card
  // pairs "₹—" with "+Infinity%" or "NaN%", and NaN comparisons silently resolved to 'down'.
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return { text: '—', direction: 'flat' };

  // Anything under 50 paise renders as "₹0" on the very same card. A percentage measured
  // against a baseline the card itself shows as zero is fabricated: 1000 vs 0.001 is a true
  // "+99999900%" and a useless one. Treat a rounded-zero baseline as no baseline.
  if (Math.abs(previous) < 0.5) {
    if (Math.abs(current) < 0.5) return { text: 'no change', direction: 'flat' };
    // Growth from nothing is not a percentage. Saying "+∞%" or "+100%" would both be lies.
    return { text: 'new', direction: current > 0 ? 'up' : 'down' };
  }
  const pct = ((current - previous) / Math.abs(previous)) * 100;
  if (Math.abs(pct) < 0.5) return { text: 'no change', direction: 'flat' };
  const dir = pct > 0 ? 'up' : 'down';
  return { text: `${pct > 0 ? '+' : ''}${pct.toFixed(0)}%`, direction: dir };
}

/**
 * Relative time for the sync status line.
 *
 * Deliberately not Intl.RelativeTimeFormat — same ICU-availability reasoning as groupIndian,
 * and these strings need translating into Hindi and regional languages anyway, which means
 * owning them.
 */
export function formatRelativeTime(then: number, now: number): string {
  const s = Math.max(0, Math.floor((now - then) / 1000));
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hour${h === 1 ? '' : 's'} ago`;
  const d = Math.floor(h / 24);
  return `${d} day${d === 1 ? '' : 's'} ago`;
}
