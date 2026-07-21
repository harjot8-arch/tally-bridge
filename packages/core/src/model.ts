/**
 * The normalized data model.
 *
 * Grain principle: the coarsest grain that still answers the question a card asks.
 * Anything finer is data we are choosing not to hold — see EXCLUDED below.
 */

/**
 * Money on the wire: a canonical 2dp decimal STRING, signed, Dr negative and Cr positive.
 *
 * This is a string and not a number, and that is the whole point — see ARCHITECTURE.md, "Money
 * never touches a float on the extraction path". `canonicalStringify` REJECTS non-integer
 * numbers outright, so an `Amount = number` could not even be serialized without first being
 * rendered to this form. The wire format is authoritative; the model describes the wire.
 *
 * This type was `number` while every producer emitted strings (`amountFrom` in the Bridge's
 * cycle, `canonicalAmount` in the ageing path). Nothing converted between them and nothing
 * caught it, because the one seam where the two met — `ExtractedSection.payload` — was typed
 * `CanonicalValue`, which accepts anything JSON-shaped. The declaration lied for the entire
 * life of the codebase and TypeScript had no way to know. That was BUG-6.
 *
 * Contract, enforced at runtime by `parseAmountToPaise`, not by the type:
 *   - optional sign, digits, optionally `.` and one or two decimal places
 *   - no thousands separators, no currency symbol, no exponent
 *   - `-0.00` is normalized to `0.00` by every producer here
 *
 * To READ one, call `parseAmount` (rupee number) or `parseAmountToPaise` (exact integer paise —
 * prefer this when you are about to do arithmetic). Both throw on anything else. Do NOT reach
 * for `Number(...)`: it turns `""` into `0` and `"1,00,000"` into `NaN`, which is how a money
 * product ships a confident wrong number.
 *
 * To WRITE one, call `canonicalAmount` (from a rupee number) — never `String(x)` or `toFixed`.
 */
export type Amount = string;

/** `YYYY-MM-DD`. */
export type IsoDate = string;

/** `YYYY-MM`. */
export type IsoMonth = string;

export type TallyFlavour = 'prime' | 'erp9';

export type Side = 'receivable' | 'payable';

export const AGEING_BUCKETS = [
  'not_due',
  '0_30',
  '31_60',
  '61_90',
  '91_180',
  '180_plus',
] as const;

export type AgeingBucket = (typeof AGEING_BUCKETS)[number];

/**
 * Every section is independently extracted, hashed, encrypted and uploaded.
 * The section name is part of the AEAD's AAD, so a ciphertext cannot be replayed as
 * a different section.
 */
export const SECTIONS = [
  'company',
  'group_balance',
  'cash_bank',
  'duties_taxes',
  'ageing_receivable',
  'ageing_payable',
  'stock_value',
  'period_revenue',
] as const;

export type Section = (typeof SECTIONS)[number];

/**
 * The row types below are `type` aliases rather than `interface`s, deliberately.
 *
 * An interface has no implicit index signature, so `SectionPayload` built from interfaces is NOT
 * assignable to `CanonicalValue` — which is precisely why the Bridge's cycle had to widen its
 * payload to `CanonicalValue` by hand and lost every ounce of type checking at the one seam that
 * mattered. As type aliases, `SectionPayload` structurally satisfies `CanonicalValue`, so the
 * producer can be typed honestly and the compiler verifies the whole payload with no cast.
 *
 * Changing any of these back to `interface` will break that assignment loudly. That is the point.
 */
export type Company = {
  /** Tally `$Guid`. The stable join key — NEVER key on name (see note below). */
  companyGuid: string;
  /**
   * Names get edited ("ABC Traders" -> "ABC Traders Pvt Ltd") and are duplicated across
   * financial years. Keying on name silently merges or splits financial history.
   */
  name: string;
  state: string;
  booksFrom: IsoDate;
  lastVoucherDate: IsoDate;
  tallyFlavour: TallyFlavour;
  tallyVersion: string;
}

export type GroupBalance = {
  companyGuid: string;
  asOf: IsoDate;
  groupName: string;
  /** '' at root. */
  parent: string;
  primaryGroup: string;
  /** 0 -> Balance Sheet, 1 -> P&L. Both statements are views over this one table. */
  isRevenue: boolean;
  opening: Amount;
  closing: Amount;
}

export type CashBankBalance = {
  companyGuid: string;
  asOf: IsoDate;
  /** Ledger grain here is deliberate: the owner wants "HDFC CA 4471", not "Bank Accounts". */
  ledgerName: string;
  parent: string;
  closing: Amount;
}

/**
 * A tax ledger balance under the Duties & Taxes group — CGST, SGST, IGST, ITC, TDS payable.
 *
 * Structurally identical to CashBankBalance (ledger name, parent, closing balance) and kept as
 * its own alias so the two sections read distinctly at every call site. Ledger grain is the
 * whole point: "Duties & Taxes: ₹2,40,000" answers nothing an owner acts on, but "IGST Payable
 * ₹1,80,000 / CGST ₹30,000 / SGST ₹30,000" is the number they take to their accountant.
 */
export type DutiesTaxesBalance = CashBankBalance;

/** Long-tail rollup party name. Chosen so it cannot collide with a real Tally ledger name. */
export const OTHERS_PARTY = '__OTHERS__';

/** How many parties survive by exposure before being rolled into OTHERS_PARTY. */
export const TOP_PARTY_COUNT = 25;

export type AgeingBucketRow = {
  companyGuid: string;
  asOf: IsoDate;
  side: Side;
  /** OTHERS_PARTY for the long tail beyond TOP_PARTY_COUNT. */
  partyName: string;
  bucket: AgeingBucket;
  amount: Amount;
  billCount: number;
}

/**
 * Authoritative totals, kept separate from AgeingBucketRow ON PURPOSE.
 *
 * The "Total Receivables" card must never be wrong just because party #26 fell out of
 * the top-N. Truncation must not corrupt a total.
 */
export type AgeingTotalRow = {
  companyGuid: string;
  asOf: IsoDate;
  side: Side;
  bucket: AgeingBucket;
  amount: Amount;
  billCount: number;
}

export type StockValueRow = {
  companyGuid: string;
  asOf: IsoDate;
  /** StockGroup grain, never StockItem: a hardware store has 8,000 items and 12 groups. */
  stockGroup: string;
  closingValue: Amount;
}

export type PeriodRevenueRow = {
  companyGuid: string;
  period: IsoMonth;
  /** 'Sales Accounts', 'Purchase Accounts', 'Direct Expenses', ... */
  groupName: string;
  /**
   * '' at root. Load-bearing for arithmetic, not just for display.
   *
   * The revenue collection filters on `$IsRevenue`, which returns every revenue group at EVERY
   * DEPTH, and a Tally parent's closing balance ALREADY CONTAINS its children's. So "Sales" and
   * "Sales - Domestic" both come back, and summing every row counts the domestic sales twice —
   * inflating profit with no error and no clue. `profitCard` uses this field to sum top-level
   * rows only; without it the card cannot tell a parent from a child and has to guess.
   *
   * A row whose parent is absent from the same pull is itself top-level: a filtered or partial
   * pull must understate nothing.
   */
  parent: string;
  amount: Amount;
}

/** Discriminated payload — one variant per section. */
export type SectionPayload =
  | { section: 'company'; rows: Company[] }
  | { section: 'group_balance'; rows: GroupBalance[] }
  | { section: 'cash_bank'; rows: CashBankBalance[] }
  | { section: 'duties_taxes'; rows: DutiesTaxesBalance[] }
  | { section: 'ageing_receivable'; rows: AgeingBucketRow[]; totals: AgeingTotalRow[] }
  | { section: 'ageing_payable'; rows: AgeingBucketRow[]; totals: AgeingTotalRow[] }
  | { section: 'stock_value'; rows: StockValueRow[] }
  | { section: 'period_revenue'; rows: PeriodRevenueRow[] };

/**
 * Data we deliberately never fetch. This list is most of the privacy posture:
 * you cannot leak a narration you never read.
 *
 *  - Voucher lines            10^5-10^6 rows, every transaction ever. Tally pre-aggregates
 *                             them for us in the Bills collection, so we never need them.
 *  - Narrations               Highest PII density in the dataset ("cash paid to Ramesh for...").
 *                             Also the #1 source of malformed XML.
 *  - Bill reference numbers   Business identifiers. Fetched (Tally needs them to build the
 *                             collection) but never emitted.
 *  - Individual stock items   10^3-10^4 rows; stock groups answer the question.
 *  - Ledger balances          Except cash/bank. Ledger names leak the customer list.
 *  - Party address/GSTIN/     Pure PII, zero card value.
 *    phone/email
 *  - Cost centres, godowns,   Whole subsystems most SMBs don't use. Add on demand.
 *    batches, payroll
 */
export const EXCLUDED_BY_DESIGN = Object.freeze([
  'voucher_lines',
  'narrations',
  'bill_reference_numbers',
  'stock_items',
  'non_cash_ledger_balances',
  'party_contact_details',
  'cost_centres',
  'godowns',
  'batches',
  'payroll',
] as const);
