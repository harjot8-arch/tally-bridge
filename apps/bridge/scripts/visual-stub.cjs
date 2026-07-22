// The fake `window.bridge` for the visual harness. See visual-harness.mjs.
//
// ---------------------------------------------------------------------------------------------
// THE CARDS ARE BUILT BY THE REAL CARD LAYER, FROM REAL WIRE ROWS.
//
// The first version of this file hand-wrote the card objects, and it was wrong within minutes:
// `CashBankCard` has `accounts`, `tone` and `kind`, and the fixture invented `rows`. The page
// died on `vm.accounts.length` — a TypeError, not a screenshot. That is the exact failure this
// file's own header warned about ("nothing typechecks these fixtures"), which is a good argument
// for not having such fixtures at all.
//
// So: this builds cards the way the main process does — `cashBankCard(rows)`, `ageingCard(...)`,
// `balanceSheetTree(...)` — over the 2dp wire strings Tally actually produces. Nothing between
// the wire format and the pixels is invented. If the card layer changes shape, this file follows
// automatically, because it never states the shape.
//
// What remains faked is exactly one thing: the IPC transport. That is the point.
//
// ---------------------------------------------------------------------------------------------
// THE VALUES ARE HOSTILE ON PURPOSE
//
// A screenshot of ideal data proves only that ideal data looks fine. Every question worth
// answering with real pixels is about the ugly case:
//
//   - `A & B Traders <Mumbai>` — the parser canary AND an HTML-escaping canary. If this renders
//     as markup, or as `&amp;`, the screenshot says so and no unit test would.
//   - CRORE-scale figures — `₹1,42,34,110` is WIDER than the en-US grouping of the same number.
//     Does it fit the card, or does it overflow?
//   - a 46-character bank ledger name and a 47-character party name — where does text break?
//   - a LOSS, not a profit. Dr is negative in the house convention, so cash arrives NEGATIVE and
//     the card layer flips it; the P&L rows here are built so the profit card lands red.
const { join } = require('node:path');

const VM = join(__dirname, '../../../packages/viewmodel/dist/index.js');
const {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  dutiesTaxesCard,
  profitCard,
  salesTrendCard,
  stockCard,
} = require(VM);

const GUID = 'guid-acme';
const AS_OF = '2026-07-16';

// Cash and bank are ASSETS: Dr, and Dr is NEGATIVE here. A healthy balance therefore arrives
// with a minus sign, and `cashBankCard` flips it — an owner asking "how much have I got" must
// never be shown a minus on a full account.
const cashRows = [
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'HDFC Current Account 50200047718841', parent: 'Bank Accounts', closing: '-13892000.00' },
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'Cash-in-Hand', parent: 'Cash-in-Hand', closing: '-342110.00' },
];

// THE REAL BUCKETS, from packages/core AGEING_BUCKETS. The first draft of this list invented
// `90_plus`, which does not exist — the real tail buckets are `91_180` and `180_plus` — and the
// screenshot showed the consequence immediately: the bar vanished from the chart and the party
// in it was tagged `current`, the most reassuring label on the card, because the card layer
// orders buckets by their index in AGEING_BUCKETS and an unknown one sorts as least-bad.
//
// That is NOT a product bug and must not be reported as one: `AgeingBucket` is a closed union
// and every row on the wire comes from our own aggregator, so an unknown bucket cannot occur.
// It is a bug in THIS FILE, which is CJS and therefore typechecked by nothing — the exact cost
// this harness's header names. It is recorded here because the next person to edit these
// fixtures will make the same mistake.
const BUCKETS = [
  ['not_due', '-300000.00', 2],
  ['0_30', '-2200000.00', 14],
  ['31_60', '-1420500.00', 9],
  ['61_90', '-800000.00', 4],
  ['91_180', '-400000.00', 3],
  ['180_plus', '-1200000.00', 5],
];

const PARTIES = [
  'A & B Traders <Mumbai>',
  'Shree Ganesh Hardware & Sanitary Stores Pvt Ltd',
  'Kumar Enterprises',
  'Patel & Sons',
  'Verma Traders',
];

const totalsFor = (side) =>
  BUCKETS.map(([bucket, amount, billCount]) => ({
    companyGuid: GUID,
    asOf: AS_OF,
    side,
    bucket,
    amount: side === 'payable' ? amount.replace('-', '') : amount,
    billCount,
  }));

const rowsFor = (side) =>
  PARTIES.map((partyName, i) => {
    const raw = BUCKETS[i % BUCKETS.length][1];
    return {
      companyGuid: GUID,
      asOf: AS_OF,
      side,
      partyName,
      bucket: BUCKETS[i % BUCKETS.length][0],
      amount: side === 'payable' ? raw.replace('-', '') : raw,
      billCount: 1,
    };
  });

// Revenue is Cr: POSITIVE. Last month earned more than this month, so the profit card goes red —
// the path nobody looks at.
const revRows = [
  { companyGuid: GUID, period: '2026-02', groupName: 'Sales', parent: '', amount: '3200000.00' },
  { companyGuid: GUID, period: '2026-03', groupName: 'Sales', parent: '', amount: '4100000.00' },
  { companyGuid: GUID, period: '2026-04', groupName: 'Sales', parent: '', amount: '2800000.00' },
  { companyGuid: GUID, period: '2026-05', groupName: 'Sales', parent: '', amount: '5200000.00' },
  { companyGuid: GUID, period: '2026-06', groupName: 'Sales', parent: '', amount: '4700000.00' },
  { companyGuid: GUID, period: '2026-07', groupName: 'Sales', parent: '', amount: '3800000.00' },
  { companyGuid: GUID, period: '2026-06', groupName: 'Indirect Expenses', parent: '', amount: '-3890000.00' },
  { companyGuid: GUID, period: '2026-07', groupName: 'Indirect Expenses', parent: '', amount: '-4040000.00' },
];
const current = revRows.filter((r) => r.period === '2026-07');
const previous = revRows.filter((r) => r.period === '2026-06');

// NEGATIVE, matching cash, because `stockCard` states "Stock is an asset (Dr, negative here)"
// and flips. Feeding it POSITIVE rows renders `-₹62,00,000` — a minus sign on inventory — which
// is how this fixture found task #34: whether Tally's `$$IsDebit` is even TRUE for a StockGroup's
// `$ClosingValue` is unverified, and a stock group is not a ledger with a Dr/Cr balance. If it is
// false in the field, the extraction hands this card a positive and every stock figure in the
// product inverts.
//
// These rows follow the convention the pipeline INTENDS, so the screenshot shows the intended
// product rather than a picture of an open question. The question itself is tracked, not hidden.
const stockRows = [
  { companyGuid: GUID, asOf: AS_OF, stockGroup: 'Sanitaryware', closingValue: '-4100000.00' },
  { companyGuid: GUID, asOf: AS_OF, stockGroup: 'Pipes & Fittings', closingValue: '-2100000.00' },
];

// Shaped like a REAL Tally balance sheet: several roots per side, some with children. A thin
// two-root fixture never exercised the wide-viewport overflow an owner hit at 1920px, where the
// deeper asset roots' values ran off the right edge. Assets are Dr (negative), liabilities Cr.
const groupRows = [
  // Liabilities (WHAT YOU OWE) — positive closing.
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Capital Account', parent: '', primaryGroup: 'Capital Account', isRevenue: false, opening: '20000000.00', closing: '24501062.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Current Liabilities', parent: '', primaryGroup: 'Current Liabilities', isRevenue: false, opening: '10000000.00', closing: '12312936.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Sundry Creditors', parent: 'Current Liabilities', primaryGroup: 'Current Liabilities', isRevenue: false, opening: '8000000.00', closing: '11672736.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Duties & Taxes', parent: 'Current Liabilities', primaryGroup: 'Current Liabilities', isRevenue: false, opening: '2000000.00', closing: '640200.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Loans (Liability)', parent: '', primaryGroup: 'Loans (Liability)', isRevenue: false, opening: '5000000.00', closing: '4273482.00' },
  // Assets (WHAT YOU OWN) — negative closing.
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Current Assets', parent: '', primaryGroup: 'Current Assets', isRevenue: false, opening: '-30000000.00', closing: '-41846538.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Bank Accounts', parent: 'Current Assets', primaryGroup: 'Current Assets', isRevenue: false, opening: '-10000000.00', closing: '-13892000.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Sundry Debtors', parent: 'Current Assets', primaryGroup: 'Current Assets', isRevenue: false, opening: '-3000000.00', closing: '-6320500.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Cash-in-Hand', parent: 'Current Assets', primaryGroup: 'Current Assets', isRevenue: false, opening: '-500000.00', closing: '-342110.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Fixed Assets', parent: '', primaryGroup: 'Fixed Assets', isRevenue: false, opening: '-2000000.00', closing: '-2438868.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Investments', parent: '', primaryGroup: 'Investments', isRevenue: false, opening: '-3000000.00', closing: '-3000000.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Loans & Advances (Asset)', parent: '', primaryGroup: 'Loans & Advances (Asset)', isRevenue: false, opening: '-2400000.00', closing: '-2400000.00' },
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Deposits (Asset)', parent: '', primaryGroup: 'Deposits (Asset)', isRevenue: false, opening: '-2300000.00', closing: '-2300000.00' },
  // A revenue group, deliberately: `balanceSheetTree` must filter it out. If it shows up in the
  // screenshot, the P&L has leaked into the balance sheet.
  { companyGuid: GUID, asOf: AS_OF, groupName: 'Sales', parent: '', primaryGroup: 'Sales Accounts', isRevenue: true, opening: '0.00', closing: '3800000.00' },
];

// Duties & Taxes at ledger grain. NO flip, unlike cash/stock: GST payable is a LIABILITY (Cr,
// POSITIVE here) and reads as money owed; Input Tax Credit is an asset (Dr, NEGATIVE) and reads
// as money the tax office owes back. `dutiesTaxesCard` prints these signs verbatim, so feeding
// them the other way round would invert the whole card — same open question as stock, tracked.
const dutiesRows = [
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'CGST Payable', parent: 'Duties & Taxes', closing: '410200.00' },
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'SGST Payable', parent: 'Duties & Taxes', closing: '410200.00' },
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'IGST Payable', parent: 'Duties & Taxes', closing: '180000.00' },
  { companyGuid: GUID, asOf: AS_OF, ledgerName: 'Input Tax Credit (ITC)', parent: 'Duties & Taxes', closing: '-360800.00' },
];

const CARDS = {
  state: 'ready',
  incomplete: false,
  companies: [
    {
      companyGuid: GUID,
      name: 'Acme Traders',
      asOf: AS_OF,
      cashBank: cashBankCard(cashRows),
      dutiesTaxes: dutiesTaxesCard(dutiesRows),
      receivables: ageingCard(totalsFor('receivable'), rowsFor('receivable'), 'receivable'),
      payables: ageingCard(totalsFor('payable'), rowsFor('payable'), 'payable'),
      profit: profitCard(current, previous),
      stock: stockCard(stockRows),
      salesTrend: salesTrendCard(revRows.filter((r) => r.groupName === 'Sales')),
      balanceSheet: balanceSheetTree(groupRows),
    },
  ],
};

// A placeholder QR for the harness only (the real app builds a scannable one with `qrcode`, which
// is async and cannot run in this synchronous stub). Three finder eyes read unmistakably as a QR.
const QR_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' width='128' height='128' viewBox='0 0 7 7' " +
  "shape-rendering='crispEdges'><rect width='7' height='7' fill='white'/><g fill='black'>" +
  "<rect x='0' y='0' width='3' height='1'/><rect x='0' y='2' width='3' height='1'/>" +
  "<rect x='0' y='0' width='1' height='3'/><rect x='2' y='0' width='1' height='3'/>" +
  "<rect x='4' y='0' width='3' height='1'/><rect x='4' y='2' width='3' height='1'/>" +
  "<rect x='4' y='0' width='1' height='3'/><rect x='6' y='0' width='1' height='3'/>" +
  "<rect x='0' y='4' width='3' height='1'/><rect x='0' y='6' width='3' height='1'/>" +
  "<rect x='0' y='4' width='1' height='3'/><rect x='2' y='4' width='1' height='3'/>" +
  "<rect x='4' y='4' width='1' height='1'/><rect x='6' y='4' width='1' height='1'/>" +
  "<rect x='5' y='5' width='1' height='1'/><rect x='4' y='6' width='1' height='1'/>" +
  "<rect x='6' y='6' width='1' height='1'/></g></svg>";
const MOBILE = {
  url: 'https://acme-traders.vercel.app',
  tenantId: 'tn_9f3a2c1b',
  qr: 'data:image/svg+xml;utf8,' + encodeURIComponent(QR_SVG),
};

/**
 * The stub, as a source string.
 *
 * The cards are serialised here, in Node, having been built by the real card layer above; the
 * page only ever sees the finished JSON — which is precisely what `getCards()` sends over IPC.
 */
const STUB = `
window.bridge = {
  isProvisioned: async () => true,
  getStatus: async () => ({ state: 'ok', lastRun: Date.now() - 120000 }),
  onStatusChanged: () => {},
  syncNow: async () => {},
  getCards: async () => (${JSON.stringify(CARDS)}),
  openExternal: async () => {},
  getMobileAccess: async () => (${JSON.stringify(MOBILE)}),
};
`;

module.exports = { STUB, CARDS };
