import {
  AGEING_BUCKETS,
  OTHERS_PARTY,
  fromPaise,
  parseAmountToPaise,
  sumPaise,
  type AgeingBucket,
  type AgeingBucketRow,
  type AgeingTotalRow,
  type Amount,
  type CashBankBalance,
  type GroupBalance,
  type PeriodRevenueRow,
  type Side,
  type StockValueRow,
} from '@tally-bridge/core';
import { formatDelta, formatMoney, formatMoneyCompact } from './format.ts';

/**
 * The card layer — the mobile seam.
 *
 * Every function here is pure: decrypted rows in, a plain data structure out. No React, no DOM,
 * no framework, and the tsconfig has no "DOM" lib so the build FAILS if anyone reaches for one.
 *
 * Why this exists as its own package: the mobile surface is undecided (web view vs React
 * Native vs fully native). This layer is the part that must not have to be decided twice. A web
 * dashboard and a React Native app both consume these view models verbatim and only supply
 * rendering; a fully native Swift/Kotlin client reimplements the rendering and can port these
 * ~200 lines mechanically, because there is nothing JavaScript-specific in them.
 *
 * The rule that keeps this honest: NOTHING in this package may return markup, a component, a
 * colour hex, or a pixel value. It returns numbers, strings, and semantic tokens
 * ('good' | 'warn' | 'bad'). What red means is the renderer's problem.
 */

/** Semantic health, not a colour. Each surface maps this to its own palette. */
export type Tone = 'good' | 'warn' | 'bad' | 'neutral';

/**
 * THE HYDRATION BOUNDARY.
 *
 * Amounts arrive here as canonical 2dp decimal STRINGS — that is the wire format, it is
 * authoritative, and it is a string precisely so that money never rides a float across the
 * network (ARCHITECTURE.md). This layer is where the wire becomes arithmetic, so this is where
 * the parse belongs.
 *
 * It parses to integer PAISE, not to rupees, and every card below computes in paise and converts
 * exactly once, at `moneyFromPaise`. Rupee floats are fine to LOOK at and treacherous to ADD:
 * carrying rupees would put a rounding step between every pair of numbers on a card, which is
 * the exact defect the wire format was designed to avoid.
 *
 * `parseAmountToPaise` THROWS on anything that is not a 2dp decimal. That is deliberate and it
 * is the whole lesson of BUG-6: `cashBankCard`, `ageingCard` and `stockCard` "worked" against
 * the real wire only because `-"−342110.75"` coerces and `"500000.00" * -1` coerces. They
 * shipped plausible numbers from data the layer did not understand. A card that throws gets
 * fixed; a card that quietly renders a coerced number gets believed. Never soften this to
 * `Number(...)` or a `?? 0`.
 */
function paiseOf(amount: Amount): number {
  return parseAmountToPaise(amount);
}

export interface MoneyValue {
  /**
   * The signed amount in RUPEES, for charts and for a renderer that wants its own formatting.
   *
   * Rupees rather than paise because this is the presentation boundary: every consumer of `raw`
   * plots it, formats it, or compares it, and `formatMoney` takes rupees. It is derived from
   * `paise` by a single exact division — but if you are going to do ARITHMETIC, use `paise`.
   */
  raw: number;
  /**
   * The same amount as exact integer paise.
   *
   * The number this card actually computed. `raw` is a float and floats do not add associatively;
   * a surface that needs to re-total or re-bucket anything should do it here and divide once at
   * the end, exactly as this layer does internally.
   */
  paise: number;
  /** Pre-formatted, e.g. "₹1,23,456". */
  display: string;
  /** Pre-formatted compact, e.g. "₹1.2 L". Use on small screens. */
  compact: string;
}

/** The ONE place paise become rupees. Everything above it is integer arithmetic. */
function moneyFromPaise(paise: number): MoneyValue {
  const raw = fromPaise(paise);
  return { raw, paise, display: formatMoney(raw), compact: formatMoneyCompact(raw) };
}

// ---------------------------------------------------------------- cash & bank

export interface CashBankCard {
  kind: 'cash_bank';
  total: MoneyValue;
  accounts: Array<{ name: string; balance: MoneyValue; isCash: boolean }>;
  tone: Tone;
}

export function cashBankCard(rows: readonly CashBankBalance[]): CashBankCard {
  // Dr is negative in our convention, and cash/bank assets are Dr — so a healthy balance
  // arrives here NEGATIVE. Flip it for display: an owner asking "how much do I have?" must not
  // be shown a minus sign on a full bank account.
  //
  // Negating integer paise is exact and cannot round. The old code negated `r.closing`
  // straight off the wire — where it was a STRING — and `-"-342110.75"` silently coerces to
  // 342110.75. It produced the right number by accident, from a value it had not parsed.
  const parsed = rows
    .map((r) => ({
      name: r.ledgerName,
      paise: -paiseOf(r.closing),
      isCash: /cash/i.test(r.parent),
    }))
    .sort((a, b) => b.paise - a.paise);

  const totalPaise = sumPaise(parsed.map((a) => a.paise));

  return {
    kind: 'cash_bank',
    total: moneyFromPaise(totalPaise),
    accounts: parsed.map((a) => ({
      name: a.name,
      balance: moneyFromPaise(a.paise),
      isCash: a.isCash,
    })),
    // An overdrawn position is the single most urgent thing on the dashboard.
    tone: totalPaise < 0 ? 'bad' : totalPaise === 0 ? 'neutral' : 'good',
  };
}

// ---------------------------------------------------------------- duties & taxes

export interface DutiesTaxesCard {
  kind: 'duties_taxes';
  /** Net tax position: positive = payable (you owe), negative = input credit (refund/offset). */
  total: MoneyValue;
  ledgers: Array<{ name: string; balance: MoneyValue }>;
  tone: Tone;
}

/**
 * Tax ledgers under Duties & Taxes, at ledger grain.
 *
 * NO sign flip, unlike cash/bank. Duties & Taxes is a LIABILITY group: a GST payable is a Cr
 * balance and arrives POSITIVE in this codebase's Dr-negative/Cr-positive convention, which is
 * already the honest reading — "IGST Payable ₹1,80,000" is a positive number an owner owes.
 * Input credit ledgers (ITC) are Dr and arrive negative, and that is also correct: a negative
 * line is money the tax office owes back. The total is the net of the two.
 */
export function dutiesTaxesCard(rows: readonly CashBankBalance[]): DutiesTaxesCard {
  const parsed = rows
    .map((r) => ({ name: r.ledgerName, paise: paiseOf(r.closing) }))
    // Rank by absolute size: a large input credit is as worth surfacing as a large payable,
    // and a signed sort would bury it at the bottom.
    .sort((a, b) => Math.abs(b.paise) - Math.abs(a.paise));

  const totalPaise = sumPaise(parsed.map((l) => l.paise));

  return {
    kind: 'duties_taxes',
    total: moneyFromPaise(totalPaise),
    ledgers: parsed.map((l) => ({ name: l.name, balance: moneyFromPaise(l.paise) })),
    // Net credit (they owe you) is good news; owing tax is just a fact, not an alarm.
    tone: totalPaise < 0 ? 'good' : 'neutral',
  };
}

// ---------------------------------------------------------------- ageing

export interface AgeingCard {
  kind: 'ageing';
  side: Side;
  total: MoneyValue;
  overdue: MoneyValue;
  buckets: Array<{ bucket: AgeingBucket; label: string; amount: MoneyValue; billCount: number; tone: Tone }>;
  topParties: Array<{ name: string; amount: MoneyValue; isOthers: boolean; worstBucket: AgeingBucket }>;
  tone: Tone;
}

const BUCKET_LABELS: Record<AgeingBucket, string> = {
  not_due: 'Not due',
  '0_30': '1–30 days',
  '31_60': '31–60 days',
  '61_90': '61–90 days',
  '91_180': '91–180 days',
  '180_plus': '180+ days',
};

const BUCKET_TONE: Record<AgeingBucket, Tone> = {
  not_due: 'good',
  '0_30': 'good',
  '31_60': 'warn',
  '61_90': 'warn',
  '91_180': 'bad',
  '180_plus': 'bad',
};

export function ageingCard(
  totals: readonly AgeingTotalRow[],
  rows: readonly AgeingBucketRow[],
  side: Side,
): AgeingCard {
  // Receivables are Dr (negative here); flip so "who owes me" reads positive.
  const flip = side === 'receivable' ? -1 : 1;

  // TOTALS COME FROM `totals`, NEVER FROM `rows`.
  //
  // `rows` is truncated to the top parties plus an OTHERS rollup — correct for display, wrong
  // for arithmetic. Summing it would still be right today because the rollup preserves the
  // sum, but it couples the headline number to a display decision. If anyone ever caps the
  // matrix differently, the total must not silently follow.
  // ACCUMULATE, never overwrite. `totals[]` is not guaranteed one row per bucket — a backfill,
  // a merged payload or a re-pull can legitimately hand us two rows for the same bucket, and
  // last-write-wins would silently DROP money out of the headline with nothing to log.
  const byBucket = new Map<AgeingBucket, { paise: number[]; count: number }>();
  for (const t of totals) {
    const cur = byBucket.get(t.bucket) ?? { paise: [], count: 0 };
    cur.paise.push(paiseOf(t.amount) * flip);
    cur.count += t.billCount;
    byBucket.set(t.bucket, cur);
  }
  // Sum via integer paise, like every other total here — never `+=` on a float.
  const bucketTotal = new Map<AgeingBucket, number>();
  for (const [b, v] of byBucket) bucketTotal.set(b, sumPaise(v.paise));

  const buckets = AGEING_BUCKETS.filter((b) => byBucket.has(b)).map((b) => ({
    bucket: b,
    label: BUCKET_LABELS[b],
    amount: moneyFromPaise(bucketTotal.get(b)!),
    billCount: byBucket.get(b)!.count,
    tone: BUCKET_TONE[b],
  }));

  const total = sumPaise([...bucketTotal.values()]);
  const overdue = sumPaise(
    [...bucketTotal.entries()].filter(([b]) => b !== 'not_due').map(([, v]) => v),
  );

  // "Who owes me most" — the question the owner actually opens the app to answer.
  const byParty = new Map<string, { paise: number[]; worst: AgeingBucket }>();
  for (const r of rows) {
    const cur = byParty.get(r.partyName) ?? { paise: [], worst: 'not_due' as AgeingBucket };
    cur.paise.push(paiseOf(r.amount) * flip);
    if (AGEING_BUCKETS.indexOf(r.bucket) > AGEING_BUCKETS.indexOf(cur.worst)) cur.worst = r.bucket;
    byParty.set(r.partyName, cur);
  }
  const partyTotal = new Map<string, number>();
  for (const [name, v] of byParty) partyTotal.set(name, sumPaise(v.paise));

  const topParties = [...byParty.entries()]
    .sort((a, b) => {
      // OTHERS always sinks to the bottom regardless of size: it is a rollup, not a party, and
      // "__OTHERS__ owes you the most" is not an actionable sentence.
      if (a[0] === OTHERS_PARTY) return 1;
      if (b[0] === OTHERS_PARTY) return -1;
      return partyTotal.get(b[0])! - partyTotal.get(a[0])!;
    })
    .slice(0, 6)
    .map(([name, v]) => ({
      name,
      amount: moneyFromPaise(partyTotal.get(name)!),
      isOthers: name === OTHERS_PARTY,
      worstBucket: v.worst,
    }));

  // The ratio is only meaningful against a POSITIVE book. Advances from customers arrive Cr and
  // flip negative, so the net total can go negative while real money sits 180+ days late —
  // `overdue / total` then comes out negative and the tone reads 'good'. That is an advance
  // laundering an overdue debt into a green card, so: no positive book, judge on the overdue
  // amount alone.
  const overdueRatio = total > 0 ? overdue / total : overdue > 0 ? 1 : 0;

  return {
    kind: 'ageing',
    side,
    total: moneyFromPaise(total),
    overdue: moneyFromPaise(overdue),
    buckets,
    topParties,
    tone: overdueRatio > 0.5 ? 'bad' : overdueRatio > 0.2 ? 'warn' : 'good',
  };
}

// ---------------------------------------------------------------- profit

export interface ProfitCard {
  kind: 'profit';
  current: MoneyValue;
  previous: MoneyValue;
  delta: { text: string; direction: 'up' | 'down' | 'flat' };
  tone: Tone;
}

/**
 * Sum the revenue rows that are NOT already counted inside another row.
 *
 * Tally's revenue collection filters on `$IsRevenue`, which returns every revenue group at EVERY
 * DEPTH, and a Tally parent's closing balance ALREADY CONTAINS its children's. So a company with
 * "Sales - Domestic" under "Sales" gets both rows, and a naive sum counts the domestic sales
 * twice — reporting a profit that is too high, with no error and nothing in the payload to hint
 * at it. `salesTrendCard` was hardened against exactly this (see `isSalesGroup`); `profitCard`
 * sums EVERY group, so it was wide open.
 *
 * A row is a child — and therefore already included in its parent — only when its parent is
 * PRESENT IN THE SAME PULL. This matters more than "parent !== ''": a filtered or partial pull
 * can hand us children whose parents were never fetched, and dropping those would understate
 * profit, swapping an overstatement for an understatement. Presence, not depth, is the question.
 *
 * Scoped PER PERIOD, because containment is a fact about one month's balances. Rows for
 * different months never contain each other, and merging them into one name set would make a
 * parent present in June suppress its child in July.
 */
function topLevelRevenuePaise(rows: readonly PeriodRevenueRow[]): number {
  const byPeriod = new Map<string, PeriodRevenueRow[]>();
  for (const r of rows) {
    const cur = byPeriod.get(r.period) ?? [];
    cur.push(r);
    byPeriod.set(r.period, cur);
  }

  const paise: number[] = [];
  for (const periodRows of byPeriod.values()) {
    const parentOf = new Map<string, string>();
    for (const r of periodRows) parentOf.set(r.groupName, r.parent);

    for (const r of periodRows) {
      // A group on a parent CYCLE (A->B->A, or a self-parent) counts as top-level. Group parents
      // are user-editable, so a cycle is reachable data, and "everything is somebody's child"
      // would otherwise exclude every row and report a profit of exactly ₹0 — a silent, total,
      // catastrophic wrong answer. Same reasoning, and the same helper, as `balanceSheetTree`.
      const containedByAnotherRow =
        r.parent !== '' && parentOf.has(r.parent) && !isOnParentCycle(r.groupName, parentOf);
      if (!containedByAnotherRow) paise.push(paiseOf(r.amount));
    }
  }
  return sumPaise(paise);
}

/**
 * Profit for a period from the revenue rows.
 *
 * Cr is positive in our convention, and income is Cr — so income arrives positive and expenses
 * negative, which means profit is simply their sum. That falls out of the sign convention
 * rather than needing a special case, which is exactly why the convention was fixed at the
 * extraction boundary.
 *
 * "Their sum" over the TOP-LEVEL rows only — see `topLevelRevenuePaise`. Summing every row
 * double-counts every nested group.
 */
export function profitCard(current: readonly PeriodRevenueRow[], previous: readonly PeriodRevenueRow[]): ProfitCard {
  const p1 = topLevelRevenuePaise(current);
  const p0 = topLevelRevenuePaise(previous);
  return {
    kind: 'profit',
    current: moneyFromPaise(p1),
    previous: moneyFromPaise(p0),
    delta: formatDelta(fromPaise(p1), fromPaise(p0)),
    tone: p1 < 0 ? 'bad' : p1 > p0 ? 'good' : 'neutral',
  };
}

// ---------------------------------------------------------------- sales trend

export interface TrendPoint {
  period: string;
  /** For the axis label: "Jul". */
  label: string;
  value: MoneyValue;
}

export interface TrendCard {
  kind: 'trend';
  title: string;
  points: TrendPoint[];
  peak: MoneyValue;
  tone: Tone;
}

const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * The sales group, matched EXACTLY (case- and space-insensitively), never by substring.
 *
 * `/sales/i` was wrong twice over, and both failures understate the number the owner reads:
 *
 *  1. The revenue query filters on `$IsRevenue`, which returns every revenue group at every
 *     depth — including ordinary user groups like "Sales Promotion Expenses", an INDIRECT
 *     EXPENSE that arrives Dr (negative) and got subtracted from the sales line.
 *  2. A parent's closing balance already contains its children, so a company with "Sales -
 *     Export" under "Sales Accounts" had its exports counted twice.
 *
 * Exact match on the primary group fixes both. A company that has RENAMED the primary group
 * (rare, and possible in Tally) drops off the trend — visibly empty, rather than quietly wrong.
 */
function isSalesGroup(groupName: string): boolean {
  return /^sales(\s+accounts?)?$/i.test(groupName.trim());
}

export function salesTrendCard(rows: readonly PeriodRevenueRow[]): TrendCard {
  const byPeriod = new Map<string, number[]>();
  for (const r of rows) {
    if (!isSalesGroup(r.groupName)) continue;
    // Sales are Cr (positive). Keep as-is.
    const cur = byPeriod.get(r.period) ?? [];
    cur.push(paiseOf(r.amount));
    byPeriod.set(r.period, cur);
  }

  const points = [...byPeriod.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1))
    // Exact via integer paise — `+=` on floats would drift a value that renderers plot raw.
    .map(([period, values]) => ({
      period,
      label: MONTH_NAMES[Number(period.slice(5, 7)) - 1] ?? period,
      value: moneyFromPaise(sumPaise(values)),
    }));

  // Compare in paise: `Math.max` over rupee floats picks the same winner, but taking it from the
  // exact integers means `peak` is the very number one of the points holds, not a re-derivation.
  const peak = points.length === 0 ? 0 : Math.max(...points.map((p) => p.value.paise));
  const last = points.at(-1)?.value.paise ?? 0;
  const prev = points.at(-2)?.value.paise ?? 0;

  return {
    kind: 'trend',
    title: 'Sales',
    points,
    peak: moneyFromPaise(peak),
    tone: points.length < 2 ? 'neutral' : last >= prev ? 'good' : 'warn',
  };
}

// ---------------------------------------------------------------- stock

export interface StockCard {
  kind: 'stock';
  total: MoneyValue;
  groups: Array<{
    name: string;
    value: MoneyValue;
    /**
     * Fraction of the total, CLAMPED to 0..1 — safe to use as a bar width directly.
     *
     * Negative stock is real (issued before receipt) and makes the honest ratio nonsense: it
     * can exceed 1, or go negative and draw a bar backwards. `value.raw` keeps the true signed
     * number for anyone who needs it.
     */
    share: number;
  }>;
  tone: Tone;
}

export function stockCard(rows: readonly StockValueRow[]): StockCard {
  // Stock is an asset: Dr-negative on the wire, flipped here for display. That premise is NOT
  // assumed from the TDL idiom alone — `$$IsDebit` on a StockGroup's computed `$ClosingValue`
  // is exactly the place it could silently fail, and this flip would then negate every stock
  // figure in the product. The Bridge measures the idiom's actual sign at probe time against
  // the Stock-in-Hand group and negates at extraction when needed (packages/tally,
  // stocksign.ts; `stockValueSign` quirk), so rows arriving here are Dr-negative either by
  // verification or, when the book was too empty to verify, by the documented default.
  const groups = rows
    .map((r) => ({ name: r.stockGroup, paise: -paiseOf(r.closingValue) }))
    .sort((a, b) => b.paise - a.paise);
  const total = sumPaise(groups.map((g) => g.paise));

  return {
    kind: 'stock',
    total: moneyFromPaise(total),
    groups: groups.slice(0, 5).map((g) => ({
      name: g.name,
      value: moneyFromPaise(g.paise),
      // A share is only meaningful as a slice of a positive whole. With any negative group in
      // the mix the raw ratio can exceed 1 (a bar past 100%) or go negative (a bar drawn
      // backwards); with a negative TOTAL the sign inverts for every group at once.
      //
      // The ratio is taken in paise: same value, but both operands are exact, so the division is
      // the only rounding step rather than the third one.
      share: total > 0 && g.paise > 0 ? Math.min(1, g.paise / total) : 0,
    })),
    tone: 'neutral',
  };
}

// ---------------------------------------------------------------- balance sheet tree

export interface TreeNode {
  name: string;
  amount: MoneyValue;
  children: TreeNode[];
}

/**
 * Roll the flat group rows into the Balance Sheet tree.
 *
 * The rows arrive flat with a `parent` pointer, exactly as Tally models them. The tree is
 * rebuilt here rather than on the Bridge because it is a PRESENTATION concern — the wire format
 * stays flat, which keeps it small and lets a native client build whatever structure suits it.
 *
 * Amounts here are RAW, in the house convention: Dr negative, Cr positive. Unlike every other
 * card, nothing is flipped — a balance sheet shows both sides at once, so there is no single
 * correct flip, and choosing per node would mean trusting `primaryGroup`, which the flavour
 * probe reports as EMPTY on installs where `$_PrimaryGroup` is unavailable. So: assets read
 * negative and liabilities positive. A renderer that wants an accountant's two-column sheet
 * must flip the asset side itself, deliberately.
 */
export function balanceSheetTree(rows: readonly GroupBalance[]): TreeNode[] {
  const sheet = rows.filter((r) => !r.isRevenue);
  const byName = new Map<string, TreeNode>();
  const parentOf = new Map<string, string>();
  for (const r of sheet) {
    byName.set(r.groupName, {
      name: r.groupName,
      amount: moneyFromPaise(paiseOf(r.closing)),
      children: [],
    });
    parentOf.set(r.groupName, r.parent);
  }

  const roots: TreeNode[] = [];
  // Iterate the UNIQUE groups, not the rows: two rows for one group (two asOf dates in one
  // payload, a bad merge) would otherwise place the same node object into the tree twice, and
  // anything summing the tree would count that group twice.
  for (const [name, node] of byName) {
    const parentName = parentOf.get(name)!;
    if (!parentName) {
      roots.push(node);
      continue;
    }
    const parent = byName.get(parentName);
    // A dangling parent means the tree is partial (a filtered pull). Surface the node at the
    // root rather than dropping it — losing a group silently would understate a total.
    // A node on a PARENT CYCLE gets the same treatment, for the same reason: group parents are
    // user-editable, and A->B->A left neither node a root, so the entire subtree vanished from
    // the returned array — silently, which is exactly what this branch exists to prevent. It
    // also handed any consumer that walks `children` an infinitely recursive structure.
    if (parent && !isOnParentCycle(name, parentOf)) parent.children.push(node);
    else roots.push(node);
  }
  return roots;
}

/**
 * Does following `name`'s parent chain lead back to `name`?
 *
 * Only nodes ON the cycle are broken out. A node that merely descends FROM one (C under A,
 * where A<->B) still attaches to its parent — the cycle members become roots, so C stays
 * reachable and appears exactly once.
 */
function isOnParentCycle(name: string, parentOf: ReadonlyMap<string, string>): boolean {
  const seen = new Set<string>([name]);
  let cur = parentOf.get(name);
  while (cur) {
    if (cur === name) return true;
    // Walked into a cycle that does not contain `name`; it terminates, so `name` is not on it.
    if (seen.has(cur)) return false;
    seen.add(cur);
    cur = parentOf.get(cur);
  }
  return false;
}
