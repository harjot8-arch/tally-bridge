/**
 * Pure mapping from `CompanyCards` (the data layer's finished view models) to the flat
 * key → value dictionaries the dashboard page paints. No DOM, no fetch, no formatting of
 * its own beyond the injected `formatMoney`/`formatDelta` from @tally-bridge/viewmodel.
 *
 * THE RULE THIS FILE ENFORCES: nothing here invents a figure. Every rupee string is either
 * a card's own pre-formatted `.display`/`.compact`, or `formatMoney` over an exact
 * integer-paise sum (the bank-vs-cash split, which the card layer does not provide). A key
 * whose data has not synced maps to '—' (rendered dimmed) or '' (its row is hidden) —
 * never to a number, never to zero.
 *
 * What deliberately does NOT appear here, because the pipeline never syncs it (the original
 * hand-written UI simulated all of these): domestic/international purchase split, CGST/SGST/
 * IGST/ITC ledger figures, SKU counts, stock turnover, stock ageing, cash burn/limits, loan
 * principal/interest/amortisation, expense budgets. See apps/web/test/ui.test.ts for the
 * guard that keeps those keys out of the shipped page.
 *
 * Formatters are injected so tests run this file against the real viewmodel package without
 * needing the built browser bundle beside it.
 */
import type { CompanyCards } from '../src/data/assemble.ts';
import type { TreeNode } from '@tally-bridge/viewmodel';

export interface Formatters {
  formatMoney(rupees: number): string;
  formatDelta(current: number, previous: number): { text: string; direction: string };
}

export interface CompanyView {
  /** data-key → textContent. '—' = no data (dim it); '' = hide the enclosing [data-slot]. */
  text: Record<string, string>;
  /** data-key → segmented-bar width, 0..100. */
  widths: Record<string, number>;
  /** data-key → viz-fill scaleX, 0..100. */
  scales: Record<string, number>;
  /** Raw monthly sales for the chart; null when fewer than two months have synced. */
  chart: number[] | null;
}

const EM = '—';

export function mapCompany(cards: Partial<CompanyCards>, fmt: Formatters): CompanyView {
  const text: Record<string, string> = {};
  const widths: Record<string, number> = {};
  const scales: Record<string, number> = {};

  // ---- sales trend + profit (period_revenue) ------------------------------------------
  const pts = cards.salesTrend?.points ?? [];
  const last = pts.at(-1);
  const prev = pts.at(-2);
  text['sales'] = last?.value.display ?? EM;
  if (last && prev) {
    const d = fmt.formatDelta(last.value.raw, prev.value.raw);
    text['salesTrend'] = d.text.endsWith('%') ? `${d.text} MoM` : d.text;
  } else {
    text['salesTrend'] = EM;
  }
  text['profit'] = cards.profit?.current.display ?? EM;
  const last4 = pts.slice(-4);
  for (let i = 0; i < 4; i++) {
    const p = last4[i];
    text[`mL${i + 1}`] = p?.label ?? '';
    text[`m${i + 1}`] = p?.value.display ?? '';
  }
  const chart = pts.length >= 2 ? pts.map((p) => p.value.raw) : null;

  // ---- payables (ageing_payable) ------------------------------------------------------
  const pay = cards.payables;
  text['payables'] = pay?.total.display ?? EM;
  text['payOverdue'] = pay?.overdue.display ?? EM;
  const notDue = pay?.buckets.find((b) => b.bucket === 'not_due');
  text['payNotDue'] = notDue?.amount.display ?? EM;
  const v = shares3(
    (pay?.topParties ?? []).filter((p) => !p.isOthers).map((p) => p.amount.paise),
    pay?.total.paise,
  );
  for (let i = 0; i < 4; i++) widths[`v${i + 1}`] = v[i]!;

  // ---- receivables (ageing_receivable) ------------------------------------------------
  const rcv = cards.receivables;
  text['receivables'] = rcv?.total.display ?? EM;
  const parties = (rcv?.topParties ?? []).slice(0, 3);
  for (let i = 0; i < 3; i++) {
    const p = parties[i];
    text[`rcvP${i + 1}Name`] = p ? (p.isOthers ? 'Others' : p.name) : '';
    text[`rcvP${i + 1}`] = p?.amount.display ?? '';
  }
  const rp = pct(rcv?.overdue.paise, rcv?.total.paise);
  text['rcvOverduePct'] = rp === null ? EM : `${rp}%`;
  scales['rcvOverduePct'] = rp ?? 0;

  // AGEING — "how late", the half of the question the party list does not answer.
  //
  // Buckets come from the card's own `buckets[]`, which the card layer built from the
  // AUTHORITATIVE `totals[]` rows, never from the truncated party matrix (ARCHITECTURE.md: a
  // total must not follow a display decision). Receivables are Dr, so the card has already
  // flipped them to read positive — `pct` refuses anything negative, so a sign regression
  // upstream renders a blank bar rather than a confident wrong one.
  //
  // Four bands, not six: at 390px six segments are ~4px each and communicate nothing. 90+ is the
  // merge because it is the band that changes what the owner does today.
  const bucketPaise = (...names: string[]): number | undefined => {
    const bs = rcv?.buckets;
    if (!bs) return undefined;
    let sum = 0;
    let seen = false;
    for (const b of bs) {
      if (names.includes(b.bucket)) { sum += b.amount.paise; seen = true; }
    }
    return seen ? sum : undefined;
  };
  const bands: Array<[string, number | undefined]> = [
    ['Not due', bucketPaise('not_due')],
    ['0–30 days', bucketPaise('0_30')],
    ['31–90 days', bucketPaise('31_60', '61_90')],
    ['Over 90 days', bucketPaise('91_180', '180_plus')],
  ];
  const bandTotal = rcv?.total.paise;
  let bandUsed = 0;
  bands.forEach(([, p], i) => {
    const s = p !== undefined && p > 0 && bandTotal !== undefined && bandTotal > 0
      ? Math.min(100 - bandUsed, Math.round((p / bandTotal) * 100))
      : 0;
    widths[`age${i + 1}`] = s;
    bandUsed += s;
  });
  // Name the worst band that actually holds money — the single line worth reading.
  const worst = [...bands].reverse().find(([, p]) => p !== undefined && p > 0);
  const worstAmt = worst?.[1];
  text['ageWorstName'] = worst && worstAmt !== undefined ? `Oldest — ${worst[0]}` : '';
  text['ageWorst'] = worst && worstAmt !== undefined ? fmt.formatMoney(worstAmt / 100) : '';

  // ---- cash & bank (cash_bank, LEDGER grain with real names) --------------------------
  // The card gives a combined total and per-ledger balances; the bank/cash split is not a
  // card field, so it is derived here in exact integer paise and formatted exactly once —
  // the same arithmetic discipline as the card layer. /100 is `fromPaise`.
  const accounts = cards.cashBank?.accounts ?? [];
  const bankAccts = accounts.filter((a) => !a.isCash);
  const cashAccts = accounts.filter((a) => a.isCash);
  const bankPaise = bankAccts.reduce((s, a) => s + a.balance.paise, 0);
  const cashPaise = cashAccts.reduce((s, a) => s + a.balance.paise, 0);
  text['bank'] = cards.cashBank ? fmt.formatMoney(bankPaise / 100) : EM;
  text['cash'] = cards.cashBank ? fmt.formatMoney(cashPaise / 100) : EM;
  for (let i = 0; i < 3; i++) {
    const a = bankAccts[i];
    text[`acct${i + 1}Name`] = a?.name ?? '';
    text[`acct${i + 1}`] = a?.balance.display ?? '';
    scales[`acct${i + 1}Pct`] = a ? (pct(a.balance.paise, bankPaise) ?? 0) : 0;
  }
  for (let i = 0; i < 2; i++) {
    const a = cashAccts[i];
    text[`cashL${i + 1}Name`] = a?.name ?? '';
    text[`cashL${i + 1}`] = a?.balance.display ?? '';
  }
  const cs = pct(cashPaise, cards.cashBank?.total.paise);
  text['cashShare'] = cs === null ? EM : `${cs}%`;
  scales['cashShare'] = cs ?? 0;

  // ---- balance sheet lookups (group_balance; raw sign: Dr negative, Cr positive) ------
  const tree = cards.balanceSheet ?? [];
  // Prefer the LEDGER-grain tax card: "IGST Payable ₹1,80,000" is what the owner acts on, where
  // the Duties & Taxes GROUP total answers nothing. The group tree is the fallback for a book
  // that has not synced the duties_taxes section yet. Both read Cr-positive — a payable is a
  // positive number here, the honest orientation.
  const dt = cards.dutiesTaxes;
  if (dt) {
    text['tax'] = dt.total.display;
    for (let i = 0; i < 3; i++) {
      text[`taxC${i + 1}Name`] = dt.ledgers[i]?.name ?? '';
      text[`taxC${i + 1}`] = dt.ledgers[i]?.balance.display ?? '';
    }
  } else {
    const tax = findNode(tree, /^duties\s*(&|and)\s*taxes$/i);
    text['tax'] = tax?.amount.display ?? EM;
    const taxKids = kidsByMagnitude(tax, 3);
    for (let i = 0; i < 3; i++) {
      text[`taxC${i + 1}Name`] = taxKids[i]?.name ?? '';
      text[`taxC${i + 1}`] = taxKids[i]?.amount.display ?? '';
    }
  }
  const loan = findNode(tree, /^loans\s*\(liability\)$/i);
  text['loan'] = loan?.amount.display ?? EM;
  const loanKids = kidsByMagnitude(loan, 2);
  for (let i = 0; i < 2; i++) {
    text[`loanC${i + 1}Name`] = loanKids[i]?.name ?? '';
    text[`loanC${i + 1}`] = loanKids[i]?.amount.display ?? '';
  }
  // Current ratio. Current Assets arrive Dr (negative); a ratio is only meaningful when the
  // assets really are a Dr balance and the liabilities really are Cr — anything else is '—'.
  const ca = findNode(tree, /^current\s+assets$/i);
  const cl = findNode(tree, /^current\s+liabilities$/i);
  const liq =
    ca && cl && cl.amount.paise > 0 && ca.amount.paise < 0
      ? -ca.amount.paise / cl.amount.paise
      : null;
  text['liquidity'] = liq === null ? EM : liq.toFixed(2);

  // ---- stock (stock_value, StockGroup grain) ------------------------------------------
  const gs = cards.stock?.groups ?? [];
  text['stock'] = cards.stock?.total.display ?? EM;
  let used = 0;
  for (let i = 0; i < 3; i++) {
    const g = gs[i];
    const s = g ? Math.min(100 - used, Math.round(g.share * 100)) : 0;
    widths[`stk${i + 1}`] = s;
    used += s;
  }
  widths['stk4'] = used > 0 ? Math.max(0, 100 - used) : 0;
  for (let i = 0; i < 2; i++) {
    text[`stkG${i + 1}Name`] = gs[i]?.name ?? '';
    text[`stkG${i + 1}`] = gs[i]?.value.compact ?? '';
  }

  return { text, widths, scales, chart };
}

/** Top-3-vs-rest shares of a positive total, clamped so they always sum to ≤100. */
function shares3(
  paise: readonly number[],
  totalPaise: number | undefined,
): [number, number, number, number] {
  const out: [number, number, number, number] = [0, 0, 0, 0];
  if (totalPaise === undefined || !(totalPaise > 0)) return out;
  let used = 0;
  for (let i = 0; i < 3; i++) {
    const p = paise[i];
    const s = p !== undefined && p > 0 ? Math.min(100 - used, Math.round((p / totalPaise) * 100)) : 0;
    out[i] = s;
    used += s;
  }
  out[3] = Math.max(0, 100 - used);
  return out;
}

/** Integer percentage of a POSITIVE total, or null when the ratio would be nonsense. */
function pct(part: number | undefined, total: number | undefined): number | null {
  if (part === undefined || total === undefined || !(total > 0) || part < 0) return null;
  return Math.min(100, Math.round((part / total) * 100));
}

function findNode(nodes: readonly TreeNode[], re: RegExp): TreeNode | undefined {
  for (const n of nodes) {
    if (re.test(n.name.trim())) return n;
    const hit = findNode(n.children, re);
    if (hit) return hit;
  }
  return undefined;
}

function kidsByMagnitude(node: TreeNode | undefined, n: number): TreeNode[] {
  return [...(node?.children ?? [])]
    .sort((a, b) => Math.abs(b.amount.paise) - Math.abs(a.amount.paise))
    .slice(0, n);
}
