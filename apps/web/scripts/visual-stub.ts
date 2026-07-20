/**
 * The STUB data layer for the visual harness. Built by scripts/visual-harness.mjs into a temp
 * directory as `tally-data.js`, beside verbatim copies of the real dist/{index.html, app.js,
 * viewmap.js}. Nothing here ever enters dist/ or ui/.
 *
 * WHAT IS REAL HERE, AND WHY IT HAS TO BE
 *
 * `formatMoney` and `formatDelta` are re-exported from @tally-bridge/viewmodel unchanged — a
 * harness that formatted its own rupees would prove nothing about the one thing this page is
 * most likely to break on (₹1,42,34,110 is 12 glyphs wide and the layout was never seen).
 *
 * The cards are built by `assembleCompanyCards` — the SAME function loadDashboard calls in
 * production — over section payloads shaped like the wire. A hand-written `CompanyCards` object
 * is how a previous harness rendered a blank page: the author invented `rows` for `accounts`
 * and a `90_plus` ageing bucket that does not exist, and every test stayed green. If a card
 * field is renamed, this file breaks at the typecheck or the page comes up empty — either way
 * the harness tells the truth about the shape the UI actually receives.
 *
 * ONLY `unlock` and `loadDashboard` are faked, because they are the crypto/network boundary.
 */
import { assembleCompanyCards, type CompanyCards } from '../src/data/assemble.ts';
import type { Section } from '@tally-bridge/core';

export { formatMoney, formatDelta } from '@tally-bridge/viewmodel';

const GUID = '00000000-0000-0000-0000-00000000abcd';
const AS_OF = '2026-07-19';

const co = (name: string) => [{ companyGuid: GUID, name, state: 'Maharashtra' }];

/** Dr negative, Cr positive — fixed at extraction (ARCHITECTURE.md). Assets arrive negative. */
const CASH_BANK = {
  rows: [
    { ledgerName: 'HDFC Bank CA 50200041234471', parent: 'Bank Accounts', closing: '-8450000.00' },
    { ledgerName: 'ICICI Bank CA 002105001234', parent: 'Bank Accounts', closing: '-1234500.00' },
    { ledgerName: 'Axis Bank CC 918020012345678', parent: 'Bank OCC A/c', closing: '-562340.50' },
    { ledgerName: 'Cash', parent: 'Cash-in-Hand', closing: '-142500.00' },
    { ledgerName: 'Petty Cash — Godown', parent: 'Cash-in-Hand', closing: '-18750.25' },
  ],
};

const RECEIVABLE = {
  totals: [
    { bucket: 'not_due', amount: '-4200000.00', billCount: 31 },
    { bucket: '0_30', amount: '-2850000.00', billCount: 24 },
    { bucket: '31_60', amount: '-1420000.00', billCount: 11 },
    { bucket: '61_90', amount: '-680000.00', billCount: 6 },
    { bucket: '91_180', amount: '-310000.00', billCount: 3 },
    { bucket: '180_plus', amount: '-145000.00', billCount: 2 },
  ],
  rows: [
    // THE CANARY: a real Tally party name may contain < & >. It must reach the DOM as text.
    { partyName: 'A & B Traders <Mumbai>', bucket: '0_30', amount: '-1842000.00', billCount: 7 },
    { partyName: 'A & B Traders <Mumbai>', bucket: '91_180', amount: '-310000.00', billCount: 2 },
    { partyName: 'Kirloskar Brothers Ltd', bucket: 'not_due', amount: '-1650000.00', billCount: 5 },
    { partyName: 'Ramesh Enterprises, Pune', bucket: '31_60', amount: '-975000.00', billCount: 4 },
    { partyName: '__OTHERS__', bucket: '0_30', amount: '-1008000.00', billCount: 59 },
  ],
};

const PAYABLE = {
  totals: [
    { bucket: 'not_due', amount: '3150000.00', billCount: 18 },
    { bucket: '0_30', amount: '1875000.00', billCount: 14 },
    { bucket: '31_60', amount: '640000.00', billCount: 5 },
    { bucket: '61_90', amount: '285000.00', billCount: 2 },
  ],
  rows: [
    { partyName: 'Jindal Steel & Power Ltd', bucket: 'not_due', amount: '1980000.00', billCount: 6 },
    { partyName: 'Sanghvi Metal Corporation', bucket: '0_30', amount: '1120000.00', billCount: 5 },
    { partyName: 'Maharashtra State Electricity Board', bucket: '31_60', amount: '410000.00', billCount: 3 },
    { partyName: '__OTHERS__', bucket: '0_30', amount: '2440000.00', billCount: 25 },
  ],
};

const STOCK = {
  rows: [
    { stockGroup: 'Raw Material — TMT Bars', closingValue: '-4820000.00' },
    { stockGroup: 'Finished Goods', closingValue: '-3150000.00' },
    { stockGroup: 'Consumables & Spares', closingValue: '-890000.00' },
    { stockGroup: 'Packing Material', closingValue: '-240000.00' },
  ],
};

/** Income is Cr (positive), expenses Dr (negative), so profit is simply their sum. */
const revenueMonth = (period: string, sales: string, purchases: string, direct: string, indirect: string) => [
  { period, groupName: 'Sales Accounts', parent: '', amount: sales },
  { period, groupName: 'Purchase Accounts', parent: '', amount: purchases },
  { period, groupName: 'Direct Expenses', parent: '', amount: direct },
  { period, groupName: 'Indirect Expenses', parent: '', amount: indirect },
];

const REVENUE = {
  rows: [
    ...revenueMonth('2026-03', '9875300.00', '-6980000.00', '-910000.00', '-845000.00'),
    ...revenueMonth('2026-04', '11890450.00', '-8120000.00', '-1050000.00', '-902000.00'),
    ...revenueMonth('2026-05', '13205600.00', '-9040000.00', '-1180000.00', '-931000.00'),
    ...revenueMonth('2026-06', '12450900.00', '-8610000.00', '-1105000.00', '-918000.00'),
    // ₹1,42,34,110 — the string this layout has to survive.
    ...revenueMonth('2026-07', '14234110.00', '-9850000.00', '-1250000.00', '-980000.00'),
  ],
};

const g = (groupName: string, parent: string, closing: string) => ({
  groupName,
  parent,
  primaryGroup: '',
  isRevenue: false,
  opening: '0.00',
  closing,
});

const GROUPS = {
  rows: [
    g('Current Assets', '', '-21450000.00'),
    g('Current Liabilities', '', '9875000.00'),
    g('Duties & Taxes', 'Current Liabilities', '1842300.00'),
    g('CGST Payable', 'Duties & Taxes', '512400.00'),
    g('SGST Payable', 'Duties & Taxes', '512400.00'),
    g('IGST Payable', 'Duties & Taxes', '817500.00'),
    g('Loans (Liability)', '', '6540000.00'),
    g('HDFC Term Loan — Plant & Machinery', 'Loans (Liability)', '4890000.00'),
    g('Bajaj Finance Vehicle Loan', 'Loans (Liability)', '1650000.00'),
  ],
};

function build(name: string, sections: Record<string, unknown>): CompanyCards {
  const { cards } = assembleCompanyCards(
    {
      companyGuid: GUID,
      asOf: AS_OF,
      sections: new Map(Object.entries({ company: { rows: co(name) }, ...sections }) as [Section, unknown][]),
    },
    (m) => console.warn(m),
  );
  return cards;
}

const COMPANIES: CompanyCards[] = [
  build('Shree Ganesh Steel Traders Pvt Ltd', {
    cash_bank: CASH_BANK,
    ageing_receivable: RECEIVABLE,
    ageing_payable: PAYABLE,
    stock_value: STOCK,
    period_revenue: REVENUE,
    group_balance: GROUPS,
  }),
  // PARTIAL — sections sync independently, so this is a normal state, not an error.
  // Only cash & bank has landed; every other slot must read as a deliberate blank.
  build('Vaishnavi Agro Exports', { cash_bank: CASH_BANK }),
];

/** Which company the harness wants on screen. */
const only = new URL(location.href).searchParams.get('only');
const companies = only === null ? COMPANIES : [COMPANIES[Number(only)]!];

export class UnlockError extends Error {
  failure = 'credentials';
}
export const localStorageKV = () => ({});
export const memoryKV = () => ({});
export const workerUnlockSeams = () => ({});
export const lockSession = async () => {};

export async function unlock(deps: { onStage?: (s: string) => void }) {
  deps.onStage?.('deriving');
  return { firstUse: false, persistentMemory: true };
}

export async function loadDashboard() {
  return { state: 'ready', companies, incomplete: false, staleRefused: 0 };
}
