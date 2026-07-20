import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Section } from '@tally-bridge/core';
import { formatDelta, formatMoney } from '@tally-bridge/viewmodel';
import { assembleCompanyCards, type CompanySections } from '../src/data/assemble.ts';
import { mapCompany } from '../ui/viewmap.ts';

/**
 * The UI's tests, in two halves:
 *
 *  1. STATIC GUARDS over the shipped page. The original hand-written design rendered
 *     Math.random() simulation data, formatted money with Intl.NumberFormat('en-IN')
 *     (which silently prints en-US grouping on ICU-stripped runtimes — the one thing this
 *     market must never see), and loaded GSAP from cdnjs (forbidden: the CSP allows no
 *     remote origin). These tests are the anti-regression tripwire for all three, plus the
 *     innerHTML ban (party names are attacker-controlled).
 *
 *  2. MAPPING tests: a known CompanyCards fixture — built by the REAL card layer via
 *     assembleCompanyCards, not hand-written card objects — must produce exactly the right
 *     strings, and data we do not sync must never surface as a number.
 */

const UI = join(import.meta.dirname, '../ui');
const DIST = join(import.meta.dirname, '../dist');

const read = (p: string): string => readFileSync(p, 'utf8');

/** Every file that ships to (or feeds) the browser. dist copies included: stale dist deploys. */
const SHIPPED: Array<[string, string]> = [
  ['ui/index.html', join(UI, 'index.html')],
  ['ui/app.js', join(UI, 'app.js')],
  ['ui/viewmap.ts', join(UI, 'viewmap.ts')],
  ['ui/entry.ts', join(UI, 'entry.ts')],
  ['dist/index.html', join(DIST, 'index.html')],
  ['dist/app.js', join(DIST, 'app.js')],
  ['dist/viewmap.js', join(DIST, 'viewmap.js')],
  ['dist/tally-data.js', join(DIST, 'tally-data.js')],
];

test('the shipped UI contains no simulation, no remote origins, no Intl.NumberFormat, no innerHTML', () => {
  for (const [name, path] of SHIPPED) {
    assert.ok(existsSync(path), `${name} is missing — run \`node build.mjs\` in apps/web`);
    const src = read(path);
    assert.ok(!src.includes('Math.random('), `${name} contains Math.random( — simulated data must never ship`);
    assert.ok(!src.includes('cdnjs'), `${name} references cdnjs — no third-party origin may be fetched`);
    assert.ok(!src.includes('Intl.NumberFormat'), `${name} uses Intl.NumberFormat — banned; use formatMoney (ARCHITECTURE.md)`);
    assert.ok(!/innerHTML|insertAdjacentHTML|document\.write/.test(src), `${name} writes markup — decrypted strings are textContent-only`);
  }

  const html = read(join(UI, 'index.html'));
  assert.ok(!/(src|href)\s*=\s*["']https?:/i.test(html), 'index.html loads a remote resource');
  assert.ok(/http-equiv="Content-Security-Policy"/.test(html) && html.includes("default-src 'self'"), 'index.html lost its CSP meta tag');
  // One external module script, zero inline script bodies (the CSP forbids inline scripts).
  const scripts = html.match(/<script\b[^>]*>/g) ?? [];
  assert.equal(scripts.length, 1, 'exactly one <script> tag expected');
  assert.ok(scripts[0]!.includes('src="./app.js"') && scripts[0]!.includes('type="module"'), 'the one script must be the local module');
  assert.ok(!/<script\b[^>]*>[^<]*[^\s<][^<]*<\/script>/.test(html), 'inline script body found');
});

test('dist copies are byte-identical to ui sources (a stale dist is what actually deploys)', () => {
  for (const f of ['index.html', 'app.js']) {
    assert.equal(read(join(DIST, f)), read(join(UI, f)), `dist/${f} is stale — run \`node build.mjs\` in apps/web`);
  }
});

/**
 * Bucket C — figures the pipeline NEVER syncs. The original design invented all of these
 * with Math.random(); the wired page must not carry even the slot. Grain reasons:
 * tax ledgers (CGST/SGST/IGST/ITC) are ledger grain under a group-grain sync; SKUs are item
 * grain under a StockGroup-grain sync; stock is never aged (only receivables/payables are);
 * burn/limits/budgets/amortisation schedules simply do not exist in any synced section.
 */
const NEVER_SYNCED_KEYS = [
  'purDom', 'purInt',
  'expPayroll', 'expMkt', 'expOps', 'expVar', 'expVarPct',
  'bankOp', 'bankPay', 'bankRes', 'bOpPct', 'bPayPct', 'bResPct',
  'cashBurn', 'cashLimit', 'cashCapPct',
  'taxCgst', 'taxSgst', 'taxIgst', 'taxItc',
  'skuCount', 'turnover', 'stkFast', 'stkMed', 'stkSlow',
  'loanPrin', 'loanInt', 'loanProg',
  'q1', 'q2', 'q3', 'q4', 'salesVar', 'chartData',
];

test('no data-key exists for a figure the pipeline does not sync', () => {
  for (const path of [join(UI, 'index.html'), join(DIST, 'index.html')]) {
    const html = read(path);
    for (const k of NEVER_SYNCED_KEYS) {
      assert.ok(!html.includes(`data-key="${k}"`), `${path} still has a slot for unsynced figure "${k}"`);
    }
  }
});

/* ------------------------------------------------------------------ mapping fixture */

const GUID = 'guid-acme';
const AS_OF = '2026-07-16';
const FMT = { formatMoney, formatDelta };

/** Run the REAL assembly over section payloads — never hand-write a card object. */
function cardsFrom(sections: Record<string, unknown>) {
  const acc: CompanySections = {
    companyGuid: GUID,
    asOf: AS_OF,
    sections: new Map(Object.entries(sections)) as ReadonlyMap<Section, unknown>,
  };
  const { cards, failed } = assembleCompanyCards(acc, () => {});
  assert.equal(failed, false, 'fixture payloads must assemble cleanly');
  return cards;
}

const XSS_CANARY = 'A & B Traders <Mumbai>';

function fullFixture() {
  return cardsFrom({
    company: {
      section: 'company',
      rows: [{
        companyGuid: GUID, name: XSS_CANARY, state: 'Gujarat', booksFrom: '2024-04-01',
        lastVoucherDate: AS_OF, tallyFlavour: 'prime', tallyVersion: '4.1',
      }],
    },
    cash_bank: {
      section: 'cash_bank',
      rows: [
        // Dr negative on the wire; the card flips for display.
        { companyGuid: GUID, asOf: AS_OF, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing: '-4500000.00' },
        { companyGuid: GUID, asOf: AS_OF, ledgerName: 'SBI CA 1102', parent: 'Bank Accounts', closing: '-1500000.00' },
        { companyGuid: GUID, asOf: AS_OF, ledgerName: 'Petty Cash', parent: 'Cash-in-Hand', closing: '-45000.00' },
      ],
    },
    period_revenue: {
      section: 'period_revenue',
      rows: [
        { companyGuid: GUID, period: '2026-04', groupName: 'Sales Accounts', parent: '', amount: '1000000.00' },
        { companyGuid: GUID, period: '2026-05', groupName: 'Sales Accounts', parent: '', amount: '1100000.00' },
        { companyGuid: GUID, period: '2026-06', groupName: 'Sales Accounts', parent: '', amount: '1200000.00' },
        { companyGuid: GUID, period: '2026-07', groupName: 'Sales Accounts', parent: '', amount: '1500000.00' },
        { companyGuid: GUID, period: '2026-06', groupName: 'Indirect Expenses', parent: '', amount: '-350000.00' },
        { companyGuid: GUID, period: '2026-07', groupName: 'Indirect Expenses', parent: '', amount: '-400000.00' },
      ],
    },
    ageing_payable: {
      section: 'ageing_payable',
      totals: [
        { companyGuid: GUID, asOf: AS_OF, side: 'payable', bucket: 'not_due', amount: '500000.00', billCount: 4 },
        { companyGuid: GUID, asOf: AS_OF, side: 'payable', bucket: '31_60', amount: '300000.00', billCount: 2 },
      ],
      rows: [
        { companyGuid: GUID, asOf: AS_OF, side: 'payable', partyName: 'Steel Traders', bucket: 'not_due', amount: '400000.00', billCount: 3 },
        { companyGuid: GUID, asOf: AS_OF, side: 'payable', partyName: XSS_CANARY, bucket: '31_60', amount: '300000.00', billCount: 2 },
        { companyGuid: GUID, asOf: AS_OF, side: 'payable', partyName: '__OTHERS__', bucket: 'not_due', amount: '100000.00', billCount: 1 },
      ],
    },
    ageing_receivable: {
      section: 'ageing_receivable',
      totals: [
        // Receivables are Dr: negative on the wire, flipped positive by the card.
        { companyGuid: GUID, asOf: AS_OF, side: 'receivable', bucket: 'not_due', amount: '-350000.00', billCount: 5 },
        { companyGuid: GUID, asOf: AS_OF, side: 'receivable', bucket: '91_180', amount: '-250000.00', billCount: 1 },
      ],
      rows: [
        { companyGuid: GUID, asOf: AS_OF, side: 'receivable', partyName: XSS_CANARY, bucket: 'not_due', amount: '-350000.00', billCount: 5 },
        { companyGuid: GUID, asOf: AS_OF, side: 'receivable', partyName: 'Kanha Retail', bucket: '91_180', amount: '-250000.00', billCount: 1 },
      ],
    },
    stock_value: {
      section: 'stock_value',
      rows: [
        { companyGuid: GUID, asOf: AS_OF, stockGroup: 'Pipes & Fittings', closingValue: '-500000.00' },
        { companyGuid: GUID, asOf: AS_OF, stockGroup: 'Cement', closingValue: '-300000.00' },
        { companyGuid: GUID, asOf: AS_OF, stockGroup: 'Paint', closingValue: '-200000.00' },
      ],
    },
    group_balance: {
      section: 'group_balance',
      rows: [
        { companyGuid: GUID, asOf: AS_OF, groupName: 'Current Assets', parent: '', primaryGroup: '', isRevenue: false, opening: '0.00', closing: '-2000000.00' },
        { companyGuid: GUID, asOf: AS_OF, groupName: 'Current Liabilities', parent: '', primaryGroup: '', isRevenue: false, opening: '0.00', closing: '1000000.00' },
        { companyGuid: GUID, asOf: AS_OF, groupName: 'Duties & Taxes', parent: 'Current Liabilities', primaryGroup: '', isRevenue: false, opening: '0.00', closing: '185000.00' },
        { companyGuid: GUID, asOf: AS_OF, groupName: 'Loans (Liability)', parent: '', primaryGroup: '', isRevenue: false, opening: '0.00', closing: '650000.00' },
        { companyGuid: GUID, asOf: AS_OF, groupName: 'Secured Loans', parent: 'Loans (Liability)', primaryGroup: '', isRevenue: false, opening: '0.00', closing: '650000.00' },
      ],
    },
  });
}

test('mapping: real figures land on the right keys with Indian grouping', () => {
  const cards = fullFixture();
  const v = mapCompany(cards, FMT);

  // Sales trend (period_revenue): latest month, MoM delta, last four months, chart.
  assert.equal(v.text['sales'], '₹15,00,000'); // lakh grouping, not ₹1,500,000
  assert.equal(v.text['salesTrend'], '+25% MoM');
  assert.equal(v.text['mL1'], 'Apr');
  assert.equal(v.text['m1'], '₹10,00,000');
  assert.equal(v.text['mL4'], 'Jul');
  assert.equal(v.text['m4'], '₹15,00,000');
  assert.deepEqual(v.chart, [1000000, 1100000, 1200000, 1500000]);

  // Profit (period_revenue): 15,00,000 sales − 4,00,000 expenses this month.
  assert.equal(v.text['profit'], '₹11,00,000');

  // Payables (ageing_payable) + vendor concentration from topParties — the real one.
  assert.equal(v.text['payables'], '₹8,00,000');
  assert.equal(v.text['payOverdue'], '₹3,00,000');
  assert.equal(v.text['payNotDue'], '₹5,00,000');
  assert.equal(v.widths['v1'], 50);
  assert.equal(v.widths['v2'], 38);
  assert.equal(v.widths['v3'], 0);
  assert.equal(v.widths['v4'], 12);

  // Receivables (ageing_receivable): real party names, overdue share.
  assert.equal(v.text['receivables'], '₹6,00,000');
  assert.equal(v.text['rcvP1Name'], XSS_CANARY); // reaches the page verbatim; textContent renders it inert
  assert.equal(v.text['rcvP1'], '₹3,50,000');
  assert.equal(v.text['rcvP2Name'], 'Kanha Retail');
  assert.equal(v.text['rcvOverduePct'], '42%');
  assert.equal(v.scales['rcvOverduePct'], 42);

  /*
   * AGEING — "how late", the half of the question the party list cannot answer, and the reason
   * this product exists rather than a list of debtors.
   *
   * The fixture holds ₹3,50,000 not due and ₹2,50,000 at 91–180 days, ₹6,00,000 total. Bands are
   * merged 4-wide for a 390px screen, so 31_60+61_90 (empty here) collapse to one segment and
   * 91_180+180_plus to another.
   *
   * The shares are asserted EXACTLY, not just "non-zero": a bar that renders is not a bar that is
   * right, and a sign regression upstream (receivables are Dr on the wire) would show as an empty
   * bar rather than a confident wrong one — `pct` refuses negatives.
   */
  assert.equal(v.widths['age1'], 58); // not due — 3,50,000 / 6,00,000
  assert.equal(v.widths['age2'], 0); // 0–30: nothing in this bucket
  assert.equal(v.widths['age3'], 0); // 31–90: nothing
  assert.equal(v.widths['age4'], 42); // over 90 — the band that changes behaviour
  assert.equal(v.text['ageWorstName'], 'Oldest — Over 90 days');
  assert.equal(v.text['ageWorst'], '₹2,50,000');

  // Cash & bank (cash_bank, LEDGER grain): REAL ledger names, never "Operating/Payroll/Reserve".
  assert.equal(v.text['bank'], '₹60,00,000');
  assert.equal(v.text['cash'], '₹45,000');
  assert.equal(v.text['acct1Name'], 'HDFC CA 4471');
  assert.equal(v.text['acct1'], '₹45,00,000');
  assert.equal(v.scales['acct1Pct'], 75);
  assert.equal(v.text['acct2Name'], 'SBI CA 1102');
  assert.equal(v.text['acct3Name'], ''); // only two bank ledgers → third slot hides
  assert.equal(v.text['cashL1Name'], 'Petty Cash');
  assert.equal(v.text['cashShare'], '1%');

  // Balance sheet (group_balance): Duties & Taxes group, Loans group + real sub-groups, liquidity.
  assert.equal(v.text['tax'], '₹1,85,000');
  assert.equal(v.text['taxC1Name'], ''); // no sub-groups under Duties & Taxes → rows hide
  assert.equal(v.text['loan'], '₹6,50,000');
  assert.equal(v.text['loanC1Name'], 'Secured Loans');
  assert.equal(v.text['loanC1'], '₹6,50,000');
  assert.equal(v.text['liquidity'], '2.00'); // 20L current assets / 10L current liabilities

  // Stock (stock_value, StockGroup grain): composition + top groups by name.
  assert.equal(v.text['stock'], '₹10,00,000');
  assert.equal(v.widths['stk1'], 50);
  assert.equal(v.widths['stk2'], 30);
  assert.equal(v.widths['stk3'], 20);
  assert.equal(v.widths['stk4'], 0);
  assert.equal(v.text['stkG1Name'], 'Pipes & Fittings');
  assert.equal(v.text['stkG1'], '₹5 L');

  // Company name is the attacker-controlled canary and must survive unescaped (textContent-only page).
  assert.equal(cards.name, XSS_CANARY);

  // Nothing in the view invents a key for unsynced data.
  for (const k of NEVER_SYNCED_KEYS) {
    assert.ok(!(k in v.text) && !(k in v.widths) && !(k in v.scales), `view invented "${k}"`);
  }
});

test('mapping: missing sections must never surface a number — em dash or hidden, never 0', () => {
  const v = mapCompany({}, FMT);
  for (const [k, s] of Object.entries(v.text)) {
    assert.ok(!/\d/.test(s), `"${k}" shows "${s}" with no data behind it`);
    assert.ok(s === '—' || s === '', `"${k}" is "${s}", expected '—' or ''`);
  }
  for (const [k, n] of Object.entries({ ...v.widths, ...v.scales })) {
    assert.equal(n, 0, `bar "${k}" is ${n} with no data behind it`);
  }
  assert.equal(v.chart, null);
});

test('mapping: a single synced month yields no fabricated trend', () => {
  const cards = cardsFrom({
    period_revenue: {
      section: 'period_revenue',
      rows: [{ companyGuid: GUID, period: '2026-07', groupName: 'Sales Accounts', parent: '', amount: '1500000.00' }],
    },
  });
  const v = mapCompany(cards, FMT);
  assert.equal(v.text['sales'], '₹15,00,000');
  assert.equal(v.text['salesTrend'], '—'); // no previous month → no delta, not "+∞%"
  assert.equal(v.chart, null); // one point is not a line
  assert.equal(v.text['mL4'], ''); // unfilled month cells hide
});
