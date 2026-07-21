import { buildRequest, expr, type RequestSpec } from './tdl.ts';

/**
 * The request catalog.
 *
 * Every request here is deliberately narrow. The payload-minimization story is not "fetch a lot
 * and filter it down" — it is that Tally never builds the big response in the first place.
 */

/**
 * The probe. Runs every cycle and usually TERMINATES the cycle.
 *
 * ~2KB, one round trip, and it answers the whole state machine at once: is Tally up, is a
 * company open, which companies, and have the AlterID watermarks moved since last time.
 * Deliberately does NOT set SVCURRENTCOMPANY — it enumerates whatever is open.
 */
export function probeRequest(): string {
  return buildRequest({
    id: 'TSProbe',
    fields: [
      { tag: 'F01', set: expr.text('$Name') },
      { tag: 'F02', set: expr.text('$Guid') },
      // The AlterID high-water marks: masters and vouchers respectively.
      { tag: 'F03', set: expr.text('$AltMstId') },
      { tag: 'F04', set: expr.text('$AltVchId') },
      {
        tag: 'F05',
        set: '(($$YearOfDate:$BooksFrom)*10000)+(($$MonthOfDate:$BooksFrom)*100)+($$DayOfDate:$BooksFrom)',
      },
      {
        tag: 'F06',
        set: '(($$YearOfDate:$LastVoucherDate)*10000)+(($$MonthOfDate:$LastVoucherDate)*100)+($$DayOfDate:$LastVoucherDate)',
      },
      // Flags which of the open companies is the active one.
      { tag: 'F07', set: '$$IsEqual:##SVCurrentCompany:$Name' },
      { tag: 'F08', set: expr.text('$StateName') },
    ],
    collection: {
      type: 'Company',
      fetch: ['Name', 'Guid', 'AltMstId', 'AltVchId', 'BooksFrom', 'LastVoucherDate', 'StateName'],
    },
  });
}

/**
 * Balance Sheet AND Profit & Loss, in ONE request.
 *
 * They are not two reports; they are two projections of the same object — the Group tree with
 * closing balances. `$IsRevenue` splits P&L from BS and `$_PrimaryGroup` names the root bucket.
 * This is literally how Tally computes them. ~40-90 rows, under 6KB, for both statements.
 */
export function groupsRequest(opts: {
  company?: string | undefined;
  booksFrom: string;
  asOf: string;
  /** Set false when the flavour probe finds `$_PrimaryGroup` unavailable. */
  usePrimaryGroup?: boolean;
}): string {
  const fields: RequestSpec['fields'] = [
    { tag: 'F01', set: expr.text('$Name') },
    { tag: 'F02', set: 'if $$IsEqual:$Parent:$$SysName:Primary then "" else $Parent' },
    { tag: 'F03', set: opts.usePrimaryGroup === false ? '""' : expr.text('$_PrimaryGroup') },
    { tag: 'F04', set: expr.logical('$IsRevenue') },
    { tag: 'F05', set: expr.amount('$OpeningBalance') },
    { tag: 'F06', set: expr.amount('$ClosingBalance') },
    { tag: 'F07', set: expr.logical('$IsDeemedPositive') },
  ];

  const fetch = ['Name', 'Parent', 'IsRevenue', 'IsDeemedPositive', 'OpeningBalance', 'ClosingBalance'];
  if (opts.usePrimaryGroup !== false) fetch.push('_PrimaryGroup');

  return buildRequest({
    id: 'TSGroups',
    company: opts.company,
    fromDate: opts.booksFrom,
    toDate: opts.asOf,
    fields,
    collection: { type: 'Group', fetch },
  });
}

/**
 * Cash and bank balances at LEDGER grain.
 *
 * Ledger grain is correct here and nowhere else: the owner wants to see
 * "HDFC CA 4471: Rs 3,42,110", not "Bank Accounts: Rs 5,00,000". It is also cheap — 2-15 rows.
 */
export function cashBankRequest(opts: {
  company?: string | undefined;
  asOf: string;
  /** Set false when the flavour probe finds the reserved bank group functions unavailable. */
  useGroupBankFunctions?: boolean;
}): string {
  // $$GroupCash is verified. $$GroupBank / $$GroupBankOD are assumed by symmetry and probed at
  // runtime; the fallback matches on _PrimaryGroup, which is brittle against renamed groups and
  // is therefore the fallback rather than the default.
  const filter =
    opts.useGroupBankFunctions === false
      ? `$$IsLedOfGrp:$Name:$$GroupCash OR $$IsEqual:$_PrimaryGroup:"Bank Accounts" OR $$IsEqual:$_PrimaryGroup:"Bank OD A/c"`
      : `$$IsLedOfGrp:$Name:$$GroupCash OR $$IsLedOfGrp:$Name:$$GroupBank OR $$IsLedOfGrp:$Name:$$GroupBankOD`;

  return buildRequest({
    id: 'TSCashBank',
    company: opts.company,
    toDate: opts.asOf,
    fields: [
      { tag: 'F01', set: expr.text('$Name') },
      { tag: 'F02', set: expr.text('$Parent') },
      { tag: 'F03', set: expr.amount('$ClosingBalance') },
    ],
    collection: {
      type: 'Ledger',
      fetch: ['Name', 'Parent', 'ClosingBalance'],
      filter: 'FltrCashBank',
    },
    systemFormulae: { FltrCashBank: filter },
  });
}

/** The two unverified axes of the ageing request. See `SPIKE_A_VARIANTS`. */
export type BillsCollectionType = 'Bills' | 'Bill';
export type BillPartyMethod = '$PartyName' | '$LedgerName' | '$..Name';

/**
 * Outstanding receivables / payables — THE CENTERPIECE.
 *
 * The key insight: the Bills collection is ALREADY AN AGGREGATE. Tally has done the
 * bill-matching itself — netted every invoice against every receipt and adjustment, and kept
 * only the open residue. We are not summarizing raw data; we are reading a summary Tally
 * maintains natively. THIS is why voucher lines are never needed, and it is the single reason
 * this product can be honest about "we only pull what's necessary".
 *
 * Payables are the same request with a different group. One code path, one parameter.
 *
 * ## Three things a real TallyPrime 7.0 refuted, all of which used to be in this request
 *
 * The first run against real books returned ZERO rows for all six probed variants, against a
 * company with 141 bills. An isolation ladder — strip the request bare, add one clause back at
 * a time — separated three independent faults that no amount of varying the collection type
 * and party method could have told apart:
 *
 * 1. **CHILDOF empties the collection.** Bare: 141 rows. Add `CHILDOF $$GroupSundryDebtors`:
 *    zero. Add the group's own literal name instead: still zero. So it is CHILDOF on a Bills
 *    collection that does not work here, not the group reference — `$$GroupSundryDebtors`
 *    itself resolves correctly (it matches exactly one group).
 * 2. **`$ClosingBalance` is unavailable in FILTER context.** All 141 bills carry a non-zero
 *    `$ClosingBalance` as a FIELD, and every filter over that same expression returns zero
 *    rows — including via `$$NumValue`. A control filter (`NOT $$IsEmpty:$Name`) passes on the
 *    same collection, so filters work; this value is simply not there when the filter runs.
 *    The open-bill test therefore happens in Node, where the balance demonstrably exists.
 * 3. **`$PartyName` is empty on every bill.** `$LedgerName` names all 141. This is the exact
 *    silent failure this file's `assertBillsLookSane` was written for: a wrong party method
 *    returns an empty column, not an error.
 *
 * ## Why the side test is a FIELD and not a FILTER
 *
 * Fields work on this collection and filters over fetched values do not, so F07 asks
 * `$$IsLedOfGrp` per bill and Node keeps the rows that answer 1. The whole collection is 141
 * rows — filtering client-side costs nothing, and it fails LOUDLY (`assertBillsLookSane`)
 * rather than emptying a card, which is the failure mode that cost this feature two rounds.
 */
export function billsRequest(opts: {
  company?: string | undefined;
  booksFrom: string;
  asOf: string;
  side: 'receivable' | 'payable';
  collectionType?: BillsCollectionType;
  partyMethod?: BillPartyMethod;
}): string {
  const collectionType = opts.collectionType ?? 'Bills';
  const partyMethod = opts.partyMethod ?? '$LedgerName';
  const group = opts.side === 'receivable' ? '$$GroupSundryDebtors' : '$$GroupSundryCreditors';

  return buildRequest({
    id: 'TSBills',
    company: opts.company,
    fromDate: opts.booksFrom,
    toDate: opts.asOf,
    fields: [
      { tag: 'F01', set: expr.text(partyMethod) },
      { tag: 'F02', set: expr.date('$BillDate') },
      { tag: 'F03', set: 'if $$IsEmpty:$BillCreditPeriod then 0 else $$Number:$BillCreditPeriod' },
      { tag: 'F04', set: expr.amount('$ClosingBalance') },
      { tag: 'F05', set: expr.logical('$IsAdvance') },
      // Raw days since the bill date. Bucketing happens in Node, not TDL, so buckets stay
      // tunable without redeploying TDL. Due-date ageing is F06 - F03.
      { tag: 'F06', set: '$$Number:($$Date:##SVToDate - $BillDate)' },
      // WHICH SIDE this bill is on, as a FIELD rather than as a collection filter. See below.
      { tag: 'F07', set: `if $$IsLedOfGrp:${partyMethod}:${group} then 1 else 0` },
    ],
    collection: {
      type: collectionType,
      // `Name` (the bill reference) is FETCHED because Tally needs it to build the collection,
      // but it is never emitted as a field — see EXCLUDED_BY_DESIGN in core.
      fetch: ['PartyName', 'LedgerName', 'BillDate', 'BillCreditPeriod', 'ClosingBalance', 'IsAdvance', 'Name'],
    },
  });
}

/**
 * Stock value at STOCK GROUP grain, never StockItem.
 *
 * A hardware store has 8,000 stock items and 12 stock groups. The card shows a value and a
 * top-5 breakdown; groups answer that question completely.
 */
export function stockRequest(opts: { company?: string | undefined; asOf: string }): string {
  return buildRequest({
    id: 'TSStock',
    company: opts.company,
    toDate: opts.asOf,
    fields: [
      { tag: 'F01', set: expr.text('$Name') },
      { tag: 'F02', set: expr.amount('$ClosingValue') },
    ],
    collection: { type: 'StockGroup', fetch: ['Name', 'ClosingValue'] },
  });
}

/**
 * Revenue for ONE period.
 *
 * Deliberately one period per request. Getting a monthly series out of a single request needs a
 * derived-collection walk that is verified for `Ledger` but NOT for `Group`. Rather than put
 * unverified TDL on the hot path, we backfill 12 months once (closed months are immutable) and
 * thereafter refresh only the current month. Slow first run, zero risk afterwards.
 *
 * ## Why the parent column exists
 *
 * `$IsRevenue` matches revenue groups at EVERY DEPTH, and a Tally parent's closing balance
 * already contains its children's. "Sales Accounts" and "Sales - Domestic" both come back, so
 * summing every row counts the domestic sales twice and overstates profit with no error and no
 * clue. `profitCard` needs the parent to sum top-level rows only.
 *
 * F03 rather than F02 because `cycle.ts` reads the amount at index 1 and the parent at index 2.
 * (The codec indexes by tag, so the ORDER of the field list does not by itself move a column —
 * the constraint is the consumer's, not the parser's.)
 *
 * ## Why this is NOT `expr.text('$Parent')`
 *
 * A top-level group's `$Parent` is not empty — it is Tally's reserved `Primary` sysname. Raw
 * `$Parent` would therefore put "Primary" in the parent column of every root revenue group,
 * while `PeriodRevenueRow.parent` is specified as '' at root. The consumer treats a row as a
 * child only when its parent is PRESENT AS A ROW in the same pull, and no group is named
 * "Primary", so raw `$Parent` would happen to survive that particular test — but only by
 * accident, and not if a book actually contains a group named "Primary".
 *
 * So: the same guard `groupsRequest` already uses, character for character. `$$SysName:Primary`
 * resolves the reserved name rather than matching the English literal, which is what keeps it
 * working on a localized Tally.
 */
export function revenueRequest(opts: {
  company?: string | undefined;
  from: string;
  to: string;
}): string {
  return buildRequest({
    id: 'TSRevenue',
    company: opts.company,
    fromDate: opts.from,
    toDate: opts.to,
    fields: [
      { tag: 'F01', set: expr.text('$Name') },
      { tag: 'F02', set: expr.amount('$ClosingBalance') },
      { tag: 'F03', set: 'if $$IsEqual:$Parent:$$SysName:Primary then "" else $Parent' },
    ],
    collection: {
      type: 'Group',
      fetch: ['Name', 'Parent', 'ClosingBalance'],
      filter: 'FltrRev',
    },
    systemFormulae: { FltrRev: '$IsRevenue' },
  });
}

/**
 * Every combination Spike A must try against a real Tally.
 *
 * Sources genuinely conflict on both axes and no amount of desk research settles it. The
 * failure mode is what makes this dangerous: a wrong method name yields a SILENT EMPTY COLUMN,
 * not an error. That is the characteristic Tally failure and the most likely way this product
 * ships a confidently broken dashboard.
 */
export const SPIKE_A_VARIANTS: ReadonlyArray<{
  collectionType: BillsCollectionType;
  partyMethod: BillPartyMethod;
}> = [
  { collectionType: 'Bills', partyMethod: '$PartyName' }, // documented + most likely
  { collectionType: 'Bills', partyMethod: '$LedgerName' },
  { collectionType: 'Bills', partyMethod: '$..Name' }, // parent traversal
  { collectionType: 'Bill', partyMethod: '$PartyName' },
  { collectionType: 'Bill', partyMethod: '$LedgerName' },
  { collectionType: 'Bill', partyMethod: '$..Name' },
];
