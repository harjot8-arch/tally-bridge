import type { Tone } from '@tally-bridge/viewmodel';
import { describe, el, mount, svg, svgText } from './dom.ts';

/**
 * Charts, drawn by hand with `createElementNS`.
 *
 * WHY NOT A CHART LIBRARY. Two reasons, and only the second is about weight:
 *
 *   1. The CSP has no 'unsafe-inline' and no remote origin. Every mainstream charting library
 *      either injects a <style> block, sets style attributes from strings, or wants a CDN.
 *      Making one work would mean widening the policy that protects the owner's receivables.
 *   2. A donut is an arc length and a column chart is a rectangle. That is ~120 lines. A
 *      dependency here would be several thousand lines of supply chain, inside a signed desktop
 *      binary, to avoid writing them.
 *
 * THE ARITHMETIC RULE IN THIS FILE — read before touching it.
 *
 * These functions take PAISE (exact integers), never `MoneyValue.raw`, and never a formatted
 * string they might parse back. They divide paise to get a PROPORTION and turn that into
 * geometry. That is allowed and is the case `MoneyValue.paise` exists for: integers add
 * associatively, so a ring's slices sum to exactly one turn.
 *
 * What is NOT allowed, ever, is deriving a number the owner READS. Every rupee figure on screen
 * comes from a `MoneyValue` the card layer produced (`.display` / `.compact`). If you find
 * yourself formatting money in this file, or adding two `raw` values anywhere, stop: that is
 * BUG-6 growing back, and the version of it that shipped produced *plausible* numbers, which is
 * why nobody caught it.
 */

// ---------------------------------------------------------------- donut

export interface Slice {
  /** Exact integer paise. */
  paise: number;
  tone: Tone;
  /** Already-translated, already-formatted text for the <title> and the aria-label. */
  title: string;
  /** Extra classes (e.g. the `sev b-<bucket>` severity-ramp hue). Tone stays as the fallback. */
  cls?: string;
}

const R = 42;
// Thin, architectural. The ring is a proportion instrument, not a pie — 7 units of stroke reads
// as a hairline gauge and leaves the centre number the loudest thing in the card.
const STROKE = 7;
const CIRCUMFERENCE = 2 * Math.PI * R;

/**
 * THE RING INVARIANT: the segments sum to the drawn whole, or there is no ring.
 *
 * This is a FUNCTION and not a comment, and that is the entire point. This file previously
 * "enforced" the rule by dropping non-positive slices and documenting the rest, and the result
 * was a ring that was internally consistent and externally false: given a book that nets
 * NEGATIVE — advances exceeding what is owed, which is ordinary for anyone taking deposits —
 * it silently drew a perfect 100% circle of the one positive bucket, centred on a headline that
 * disagreed with it. Every number in that picture was true and the picture was a lie. That
 * family of bug has bitten this codebase before: a customer advance once laundered overdue
 * money into a GREEN card (see `overdueRatio` in `packages/viewmodel/src/cards.ts`).
 *
 * A ring is a claim: "these arcs are the parts of THIS number". So the number is an argument,
 * not an inference, and the claim is checked before a single node is created:
 *
 *   1. `whole > 0`          — you cannot take a slice of nothing or of a negative.
 *   2. every slice >= 0     — an arc cannot have negative length, and clamping one to zero
 *                             would make the rest silently sum to more than the ring.
 *   3. sum(slices) == whole — EXACTLY. Not within a tolerance.
 *
 * Check 3 is exact because these are integer PAISE, which is the whole reason `MoneyValue`
 * carries `paise` alongside `raw`. In rupee floats this comparison would need an epsilon, and
 * an epsilon is a place for a real discrepancy to hide. In paise it is `===`, and it either
 * holds or the ring does not exist.
 *
 * The caller cannot opt out: there is no parameter to skip this and no code path to a ring that
 * has not passed it. When it returns `null` the caller must say what is true in words — see
 * `ringRefusal` in cards.ts — because a missing chart with a sentence is a dashboard, and a
 * wrong chart is a liability.
 */
export function ringIsHonest(slices: readonly Slice[], whole: number): boolean {
  if (!Number.isInteger(whole) || whole <= 0) return false;
  if (!slices.every((s) => Number.isInteger(s.paise) && s.paise >= 0)) return false;
  // Exact integer addition. Associative, no rounding, no epsilon.
  return slices.reduce((a, s) => a + s.paise, 0) === whole;
}

/**
 * A donut of the parts of `whole`.
 *
 * `whole` is the number the ring CLAIMS to be — the same quantity the caller prints in its
 * centre. Returns `null` whenever that claim cannot be honoured; see `ringIsHonest`.
 */
export function donut(slices: readonly Slice[], whole: number, ariaLabel: string): SVGElement | null {
  if (!ringIsHonest(slices, whole)) return null;

  const root = svg('svg', { class: 'donut', viewBox: '0 0 100 100' });
  describe(root, 'img', ariaLabel);

  const ring = svg('g', { transform: `rotate(-90 50 50)` });

  // The track. Without it, a ring made of one 100% slice and a ring with a missing sector look
  // identical on a dark background.
  mount(
    ring,
    svg('circle', {
      class: 'donut-track',
      cx: '50',
      cy: '50',
      r: String(R),
      'stroke-width': String(STROKE),
    }),
  );

  let offset = 0;
  for (const s of slices) {
    // A zero bucket contributes no arc. It is still in the bar list beside the ring, where it
    // reads as "nothing in this bucket" rather than as a bucket that does not exist.
    if (s.paise === 0) continue;
    const len = (s.paise / whole) * CIRCUMFERENCE;
    const arc = svg('circle', {
      class: `donut-slice ${s.tone}${s.cls ? ` ${s.cls}` : ''}`,
      cx: '50',
      cy: '50',
      r: String(R),
      'stroke-width': String(STROKE),
      'stroke-dasharray': `${len.toFixed(3)} ${(CIRCUMFERENCE - len).toFixed(3)}`,
      // Negative offset winds clockwise from 12 o'clock, which is the direction a reader
      // expects and the direction the buckets are ordered in.
      'stroke-dashoffset': (-offset).toFixed(3),
    });
    const title = svg('title');
    title.textContent = s.title;
    mount(arc, title);
    mount(ring, arc);
    offset += len;
  }

  mount(root, ring);
  return root;
}

/**
 * The two lines of text inside the ring. Kept out of the SVG and positioned over it by CSS.
 *
 * `foreignObject` would put HTML inside the SVG and keep them in one node, and it is the wrong
 * trade: text inside an SVG scales with the viewBox, so the headline number would change size
 * with the card width and lose its tabular alignment with every other number on the screen.
 */
export function donutCenter(top: string, bottom: string): HTMLElement {
  const wrap = el('div', 'donut-center');
  mount(wrap, el('div', 'donut-center-top', top), el('div', 'donut-center-bottom', bottom));
  return wrap;
}

// ---------------------------------------------------------------- columns

export interface Column {
  /** Exact integer paise. May be negative — a month of net returns is real. */
  paise: number;
  /** Already-translated axis label, e.g. "Jul". */
  label: string;
  /** Already-formatted amount for the <title>. Never parsed, only shown. */
  title: string;
  accent?: boolean;
}

const W = 340;
const PLOT_H = 96;
const AXIS_H = 18;

/**
 * A column chart for the sales trend.
 *
 * Columns rather than a line, deliberately. A line chart answers "which way is it going"; an
 * owner looking at twelve months of sales is comparing June against last June, which is a
 * magnitude comparison, and bars win magnitude comparisons. It is also the only form that shows
 * a negative month honestly — a line through the axis reads as a dip, a bar below it reads as
 * what it is.
 *
 * The axis labels live inside the SVG so they cannot drift out of alignment with the bars they
 * name. `preserveAspectRatio` is left at its default (uniform), so nothing is stretched.
 */
export function columnChart(columns: readonly Column[], ariaLabel: string): SVGElement {
  const root = svg('svg', {
    class: 'columns',
    viewBox: `0 0 ${W} ${PLOT_H + AXIS_H}`,
  });
  describe(root, 'img', ariaLabel);
  if (columns.length === 0) return root;

  // The scale always includes zero, so bar heights are proportional to the amounts rather than
  // to their distance from the smallest one — a chart whose baseline is not zero exaggerates
  // every difference on it, which on a sales trend is a chart that lies.
  const max = Math.max(0, ...columns.map((c) => c.paise));
  const min = Math.min(0, ...columns.map((c) => c.paise));
  // A flat run of identical months (or all zeroes) would divide by zero and paint nothing.
  const span = max - min || 1;
  const y = (paise: number) => PLOT_H - ((paise - min) / span) * PLOT_H;
  const zeroY = y(0);

  // The zero line, drawn only when it is not the floor: on an all-positive trend it would sit
  // exactly on the axis and just thicken it.
  if (min < 0) {
    mount(root, svg('line', { class: 'zero-line', x1: '0', x2: String(W), y1: String(zeroY), y2: String(zeroY) }));
  }

  const band = W / columns.length;
  const barW = Math.max(3, Math.min(26, band * 0.56));

  columns.forEach((c, i) => {
    const cx = band * (i + 0.5);
    const top = Math.min(y(c.paise), zeroY);
    const h = Math.abs(y(c.paise) - zeroY);

    const bar = svg('rect', {
      class: `column${c.accent ? ' accent' : ''}${c.paise < 0 ? ' negative' : ''}`,
      x: (cx - barW / 2).toFixed(2),
      // A zero month still gets a 2-unit stub. It is a deliberate, visible mark meaning "this
      // month exists and was nothing", which is different from a gap meaning "no data".
      y: (h < 2 ? Math.min(top, zeroY - 2) : top).toFixed(2),
      width: barW.toFixed(2),
      height: Math.max(2, h).toFixed(2),
      // Square corners — the architectural grid has no radii anywhere.
      rx: '0',
    });
    const title = svg('title');
    title.textContent = `${c.label}: ${c.title}`;
    mount(bar, title);
    mount(root, bar);

    mount(
      root,
      svgText(c.label, {
        class: `column-label${c.accent ? ' accent' : ''}`,
        x: cx.toFixed(2),
        y: String(PLOT_H + AXIS_H - 5),
        'text-anchor': 'middle',
      }),
    );
  });

  return root;
}
