import type { TallyFlavour } from '@tally-bridge/core';
import { parseTagRows, type TallyEncoding } from './codec.ts';
import { fieldCountOfRequest } from './tdl.ts';
import { checkGroupSignConvention, describeSignCheck, type SignCheck } from './signs.ts';
import {
  checkStockSignConvention,
  describeStockSignCheck,
  type StockSignVerdict,
} from './stocksign.ts';
import { TallyTransport, TIMEOUTS, describeFailure } from './transport.ts';
import {
  SPIKE_A_VARIANTS,
  billsRequest,
  cashBankRequest,
  groupsRequest,
  probeRequest,
  stockRequest,
  type BillPartyMethod,
  type BillsCollectionType,
} from './requests.ts';
import { parseBillRow } from './ageing.ts';

/**
 * Runtime capability probing.
 *
 * This exists because the alternative — hardcoding which TDL dialect Tally speaks — cannot be
 * made correct from a desk. Sources genuinely conflict on whether the outstanding-bills
 * collection is `Bills` or `Bill`, and on whether the party is reachable as `$PartyName`,
 * `$LedgerName`, or `$..Name`. Rather than block on answering that once, for one build, on one
 * machine, the Bridge answers it on EVERY install, against the Tally actually in front of it.
 *
 * That is strictly better than version branching (`if (version >= 3.0)`) because it also
 * survives Tally 6.x in 2029, regional builds, and the combinations nobody has tested. The
 * flavour string below is for telemetry and support; the QUIRKS are what drive behaviour.
 *
 * The method: every probe cross-checks a narrow query against a broad one we already trust.
 * THE GROUP COLLECTION IS THE ORACLE — it is the thing most likely to work everywhere, so it
 * is used to decide whether a narrower query's silence is real or a bug.
 */

export interface TallyQuirks {
  flavour: TallyFlavour;
  tallyVersion: string;
  requestEncoding: TallyEncoding;
  /** `$_PrimaryGroup` is an internal method (leading underscore); may not resolve. */
  supportsPrimaryGroupMethod: boolean;
  /** `$$GroupBank` / `$$GroupBankOD` are assumed by symmetry with the verified `$$GroupCash`. */
  useGroupBankFunctions: boolean;
  billsCollectionType: BillsCollectionType;
  billPartyMethod: BillPartyMethod;
  /**
   * Whether a real book agreed that amounts arrive Dr-negative / Cr-positive.
   *
   * Never `'inverted'` — that throws. `'unknown'` means the book was too empty to judge, which
   * is normal on day one and worth knowing when a support ticket says every number looks
   * backwards.
   */
  amountSigns: 'ok' | 'unknown';
  /**
   * How `expr.amount('$ClosingValue')` behaves on a StockGroup — measured against the
   * Stock-in-Hand group, never assumed. See stocksign.ts for the full argument.
   *
   * `dr_negative`: verified to match the group idiom; the card layer's flip is correct.
   * `positive_magnitude`: `$$IsDebit` does not fire for StockGroup here; the extraction must
   * negate stock values or every stock figure in the product renders with the wrong sign.
   * `unknown`: the book could not adjudicate (no inventory, or no trusted reference). The
   * extraction then assumes the documented idiom UNCORRECTED, and `shouldReprobe` re-asks
   * daily rather than monthly so the verdict lands as soon as the book can supply one.
   */
  stockValueSign: StockSignVerdict;
  /** When the probe could not decide, and why. Surfaced to support, never to the owner. */
  notes: string[];
}

/** Cache key: quirks are per Tally installation, not per company. Bump 2: stockValueSign. */
export const QUIRKS_SCHEMA_VERSION = 2;

export interface ProbeContext {
  company: string;
  booksFrom: string;
  asOf: string;
}

export class TallyProbeError extends Error {
  readonly notes: string[];

  constructor(message: string, notes: string[] = []) {
    super(message);
    this.name = 'TallyProbeError';
    this.notes = notes;
  }
}

/**
 * Discover what this Tally supports. Run once on first connect, and again when the Tally
 * version string changes. Cache the result; it costs ~9 round trips.
 */
export async function probeCapabilities(
  transport: TallyTransport,
  ctx: ProbeContext,
): Promise<TallyQuirks> {
  const notes: string[] = [];

  // --- Encoding first: nothing else can be trusted until the bytes decode.
  const requestEncoding = await transport.detectEncoding(probeRequest());
  if (!requestEncoding) {
    throw new TallyProbeError('Could not reach Tally to determine its request encoding.');
  }

  // --- The oracle. If this fails, we have no basis to judge anything else, so stop.
  const oracle = await fetchGroupOracle(transport, ctx, notes);

  // --- The sign canary, against the real book, before anything is published from it.
  //
  // This is the one moment in the product's life where a KNOWN-SIGN invariant can be tested
  // against real data, and it is cheap: the oracle already fetched the rows. If `$$NumValue`
  // turns out to be signed rather than a magnitude, `expr.amount` double-negates every debit and
  // the entire dashboard renders inside-out — confidently, with no error anywhere. Refusing to
  // configure is the only honest answer to that; there is no partial version of it to ship.
  notes.push(describeSignCheck(oracle.signs));
  if (oracle.signs.verdict === 'inverted') {
    throw new TallyProbeError(
      `${describeSignCheck(oracle.signs)} Every amount in the product would be the wrong way ` +
        'round, so refusing to sync rather than publish an inside-out dashboard.',
      notes,
    );
  }

  const supportsPrimaryGroupMethod = oracle.primaryGroupPopulated;
  if (!supportsPrimaryGroupMethod) {
    notes.push('$_PrimaryGroup returned empty for every group; falling back to $Parent walking.');
  }

  const useGroupBankFunctions = await probeBankFunctions(transport, ctx, oracle, notes);
  const bills = await probeBillsVariant(transport, ctx, oracle, notes);
  const stockValueSign = await probeStockSign(transport, ctx, oracle, notes);

  return {
    flavour: oracle.flavour,
    tallyVersion: oracle.tallyVersion,
    requestEncoding,
    supportsPrimaryGroupMethod,
    useGroupBankFunctions,
    billsCollectionType: bills.collectionType,
    billPartyMethod: bills.partyMethod,
    amountSigns: oracle.signs.verdict === 'ok' ? 'ok' : 'unknown',
    stockValueSign,
    notes,
  };
}

interface GroupOracle {
  groupCount: number;
  primaryGroupPopulated: boolean;
  /**
   * Does the book have outstanding receivables?
   *
   * `undefined` means WE COULD NOT TELL, and it is a third state rather than a `false` because
   * the two are opposite instructions. `false` licenses the prober to shrug and adopt the
   * documented default — a business that is owed nothing must still be able to onboard.
   * `undefined` licenses nothing: if the Sundry Debtors group is missing from a chart of
   * accounts, the extraction is broken, and treating that as "owed nothing" would publish
   * "Receivables: 0" to a business owed crores. Collapsing the two is how a wrong number ships.
   */
  debtorsHaveBalance: boolean | undefined;
  bankGroupHasBalance: boolean;
  /**
   * Stock-in-Hand's own closing balance, read through the idiom the sign canary just verified.
   * `undefined` means the reserved group was absent from the chart — a renamed group or a
   * broken extraction, and (same discipline as `debtorsHaveBalance`) NOT the same thing as
   * zero. The stock-sign probe treats both as "no trusted reference", but the note it leaves
   * for support distinguishes them.
   */
  stockInHandClosing: number | undefined;
  signs: SignCheck;
  flavour: TallyFlavour;
  tallyVersion: string;
}

/** A group's own closing balance, or 0. Tolerant: NaN and Infinity are both "no reading". */
function closingOf(row: readonly string[]): number {
  const n = Number((row[5] ?? '').trim());
  return Number.isFinite(n) ? n : 0;
}

const nameOf = (row: readonly string[]) => (row[0] ?? '').trim();
const primaryGroupOf = (row: readonly string[]) => (row[2] ?? '').trim();

async function fetchGroupOracle(
  transport: TallyTransport,
  ctx: ProbeContext,
  notes: string[],
): Promise<GroupOracle> {
  // Ask WITH $_PrimaryGroup first. If the method is unsupported the column comes back empty
  // rather than erroring — which is itself the signal we want.
  const request = groupsRequest({ company: ctx.company, booksFrom: ctx.booksFrom, asOf: ctx.asOf });
  const res = await transport.request(request, TIMEOUTS.probeMs);
  if (!res.ok) {
    throw new TallyProbeError(
      `The group collection failed, so nothing else can be verified: ${describeFailure(res.failure)}`,
      notes,
    );
  }

  // Parsed against the schema the request actually declared, so a tag beyond it is caught rather
  // than tolerated. Every read below is positional, and this is what earns that right: the codec
  // indexes by TAG, so `row[5]` is `$ClosingBalance` because it came back as `<F06>` — not
  // because it happened to be the sixth thing in the stream. If `$_PrimaryGroup` is unsupported
  // and Tally OMITS `<F03>` rather than emitting it empty, F04..F07 stay exactly where they are.
  // That was the whole of RESIDUAL 2: this oracle is what every other probe is cross-checked
  // against, so a one-column shift here would make the prober confidently choose a WRONG dialect
  // and there would be nothing left to notice it.
  const parsed = parseTagRows(res.xml, { fieldCount: fieldCountOfRequest(request) });
  if (parsed.rejected.length > 0) {
    throw new TallyProbeError(
      `The group collection came back structurally malformed (${parsed.rejected.length} of ` +
        `${parsed.rejected.length + parsed.rows.length} rows: ${parsed.rejected[0]!.reason}). ` +
        'This is the oracle every other capability is judged against, so a partial read of it ' +
        'is worse than none — it would silently pick a wrong TDL dialect. Refusing to guess.',
      notes,
    );
  }
  const rows = parsed.rows;
  if (rows.length === 0) {
    throw new TallyProbeError(
      'The group collection returned no rows. Every Tally company has a chart of accounts, ' +
        'so this means the request itself is wrong rather than the company being empty.',
      notes,
    );
  }

  const primaryGroupPopulated = rows.some((r) => primaryGroupOf(r).length > 0);

  // `find` took the FIRST name CONTAINING "sundry debtors", which is a coin toss in row order
  // between the real group and a user group called "Sundry Debtors - Export". Picking the
  // sub-group reads its balance and can miss a crore sitting on the parent. Match the reserved
  // group exactly, and fall back to _PrimaryGroup — where ANY non-zero member proves debtors
  // exist, which is all this flag claims.
  const debtorRows = rows.filter((r) => /^sundry debtors$/i.test(nameOf(r)));
  const debtorsByPrimary = rows.filter((r) => /^sundry debtors$/i.test(primaryGroupOf(r)));
  let debtorsHaveBalance: boolean | undefined;
  if (debtorRows.length > 0) debtorsHaveBalance = debtorRows.some((r) => closingOf(r) !== 0);
  else if (debtorsByPrimary.length > 0) {
    debtorsHaveBalance = debtorsByPrimary.some((r) => closingOf(r) !== 0);
  } else {
    notes.push(
      'No Sundry Debtors group in the chart of accounts — it is reserved, so either it was ' +
        'renamed or the group extraction is wrong. Treating "are there debtors?" as unknown.',
    );
  }

  const anyNonZero = (re: RegExp) => rows.some((r) => re.test(nameOf(r)) && closingOf(r) !== 0);

  // Exact reserved-name match, like Sundry Debtors above and for the same reason: a user group
  // named "Stock-in-Hand - Depot" must not shadow the parent whose balance we actually want.
  const stockInHandRow = rows.find((r) => /^stock-in-hand$/i.test(nameOf(r)));

  return {
    groupCount: rows.length,
    primaryGroupPopulated,
    debtorsHaveBalance,
    stockInHandClosing: stockInHandRow ? closingOf(stockInHandRow) : undefined,
    bankGroupHasBalance: anyNonZero(/^bank accounts$/i) || anyNonZero(/^bank od/i),
    signs: checkGroupSignConvention(rows),
    // The object model is materially identical across flavours (we inject zero UI), so the
    // flavour is recorded for support, not branched on.
    flavour: 'prime',
    tallyVersion: 'unknown',
  };
}

async function probeBankFunctions(
  transport: TallyTransport,
  ctx: ProbeContext,
  oracle: GroupOracle,
  notes: string[],
): Promise<boolean> {
  const request = cashBankRequest({
    company: ctx.company,
    asOf: ctx.asOf,
    useGroupBankFunctions: true,
  });
  const res = await transport.request(request, TIMEOUTS.probeMs);

  if (!res.ok) {
    notes.push(
      `$$GroupBank/$$GroupBankOD request failed (${describeFailure(res.failure)}); using the _PrimaryGroup fallback.`,
    );
    return false;
  }

  // Tolerant on purpose: this decides ONE boolean about which filter to use, and a malformed
  // ledger row is not a reason to abandon the probe. It is a reason not to count that row as
  // evidence the reserved functions work — so rejections are simply not rows.
  const parsed = parseTagRows(res.xml, { fieldCount: fieldCountOfRequest(request) });
  if (parsed.rejected.length > 0) {
    notes.push(
      `The $$GroupBank probe returned ${parsed.rejected.length} structurally invalid rows ` +
        `(${parsed.rejected[0]!.reason}); they were not counted.`,
    );
  }
  if (parsed.rows.length > 0) return true;

  // Zero rows is only damning if the oracle says a bank balance exists. A business that
  // genuinely runs on cash alone legitimately has no bank ledgers.
  if (oracle.bankGroupHasBalance) {
    notes.push(
      'Reserved bank group functions returned no ledgers despite a non-zero Bank Accounts ' +
        'balance; falling back to _PrimaryGroup matching.',
    );
    return false;
  }

  notes.push('No cash/bank ledgers found, and no bank balance exists to contradict it.');
  return true;
}

interface BillsVariant {
  collectionType: BillsCollectionType;
  partyMethod: BillPartyMethod;
}

/**
 * Resolve the ageing query — the highest-risk unknown in the product.
 *
 * The failure mode is what makes this worth six round trips: a wrong method name does NOT
 * error. Tally returns rows with an EMPTY party column. Left undetected, the product ships a
 * confident dashboard full of blank debtors, and nobody notices until a customer does.
 *
 * So "returned rows" is not the acceptance test. "Returned rows WITH party names" is.
 */
async function probeBillsVariant(
  transport: TallyTransport,
  ctx: ProbeContext,
  oracle: GroupOracle,
  notes: string[],
): Promise<BillsVariant> {
  let sawRowsWithoutNames = false;

  for (const variant of SPIKE_A_VARIANTS) {
    const request = billsRequest({
      company: ctx.company,
      booksFrom: ctx.booksFrom,
      asOf: ctx.asOf,
      side: 'receivable',
      collectionType: variant.collectionType,
      partyMethod: variant.partyMethod,
    });
    const res = await transport.request(request, TIMEOUTS.probeMs);

    if (!res.ok) continue;

    // The one caller that must NOT throw on a malformed row. Rejecting variants is this
    // function's entire job, and a variant whose rows do not fit the schema has failed the
    // interview — including the "rows arrived with no F01 at all" shape, which under the
    // blank-tag-omission hypothesis is precisely what a wrong party method looks like.
    const parsed = parseTagRows(res.xml, { fieldCount: fieldCountOfRequest(request) });
    if (parsed.rejected.length > 0) {
      notes.push(
        `${variant.collectionType}+${variant.partyMethod} returned ${parsed.rejected.length} ` +
          `structurally invalid rows (${parsed.rejected[0]!.reason}); rejected.`,
      );
      // Rows we cannot trust must not vote on whether this variant works.
      if (parsed.rows.length === 0) continue;
    }

    const bills = parsed.rows.map(parseBillRow).filter((b) => b !== undefined);

    if (bills.length === 0) continue;

    const named = bills.filter((b) => b.partyName.trim().length > 0).length;
    if (named === 0) {
      // Rows but no names: right collection, wrong party method. Keep going.
      sawRowsWithoutNames = true;
      continue;
    }
    if (named < bills.length / 2) {
      notes.push(
        `${variant.collectionType}+${variant.partyMethod} named only ${named}/${bills.length} parties; rejected.`,
      );
      continue;
    }

    notes.push(
      `Ageing resolved to ${variant.collectionType} + ${variant.partyMethod} (${named}/${bills.length} rows named).`,
    );
    return variant;
  }

  // --- Nothing worked. Whether that is a bug depends entirely on the oracle.
  //
  // `=== false` and not `!oracle.debtorsHaveBalance`: `undefined` means the oracle could not
  // find the Sundry Debtors group at all, and "I could not tell" must never be read as
  // "there is nothing owed". That coercion is exactly how the permissive branch would end up
  // publishing a confident zero to a business that is owed money.
  if (oracle.debtorsHaveBalance === false) {
    // Not a failure: this business is owed nothing. Adopt the documented default and let the
    // next sync re-probe once invoices exist. Refusing to configure here would block a
    // cash-trade business from ever onboarding.
    notes.push(
      'No variant returned bills, but Sundry Debtors is zero — there is genuinely nothing ' +
        'outstanding. Using the documented default; will re-probe when debtors appear.',
    );
    return { collectionType: 'Bills', partyMethod: '$PartyName' };
  }

  throw new TallyProbeError(
    sawRowsWithoutNames
      ? 'Found outstanding bills but could not read party names by any known method. Refusing ' +
        'to sync rather than publish a dashboard of blank debtors.'
      : oracle.debtorsHaveBalance === undefined
        ? 'No known bills collection returned rows, and the chart of accounts has no Sundry ' +
          'Debtors group to say whether that silence is honest. Refusing to sync rather than ' +
          'silently report zero receivables.'
        : 'This company has outstanding debtors, but no known bills collection returned them. ' +
          'Refusing to sync rather than silently report zero receivables.',
    notes,
  );
}

/**
 * Resolve the stock sign — the second place the Dr/Cr idiom is unverifiable from a desk.
 *
 * Sends the EXACT request the extraction ships (`stockRequest`), so what gets judged is the
 * idiom in production, not a lookalike. The verdict logic and its full rationale live in
 * stocksign.ts; this function only fetches the two readings and records what was decided.
 *
 * Tolerant like `probeBankFunctions`: this decides one enum, and a malformed row is not a
 * reason to abandon the probe — it is a reason not to count that row as evidence.
 */
async function probeStockSign(
  transport: TallyTransport,
  ctx: ProbeContext,
  oracle: GroupOracle,
  notes: string[],
): Promise<StockSignVerdict> {
  const request = stockRequest({ company: ctx.company, asOf: ctx.asOf });
  const res = await transport.request(request, TIMEOUTS.probeMs);
  if (!res.ok) {
    notes.push(
      `The stock sign probe could not run (${describeFailure(res.failure)}); ` +
        'the stock idiom sign is unknown and the documented default is assumed.',
    );
    return 'unknown';
  }

  const parsed = parseTagRows(res.xml, { fieldCount: fieldCountOfRequest(request) });
  if (parsed.rejected.length > 0) {
    notes.push(
      `The stock sign probe returned ${parsed.rejected.length} structurally invalid rows ` +
        `(${parsed.rejected[0]!.reason}); they were not counted as sign evidence.`,
    );
  }

  const check = checkStockSignConvention(parsed.rows, oracle.stockInHandClosing);
  if (check.stockInHand === undefined) {
    notes.push(
      'No Stock-in-Hand group in the chart of accounts — it is reserved, so either it was ' +
        'renamed or the group extraction is wrong; it cannot serve as the stock-sign reference.',
    );
  }
  notes.push(describeStockSignCheck(check));
  return check.verdict;
}

/**
 * Should we re-probe?
 *
 * Quirks are cached because probing costs ~9 round trips against a single-threaded desktop app
 * the owner is typing into. But a cache that never expires is how a product ships a wrong
 * answer forever, so re-probe when the ground could have moved.
 *
 * `stockSignUnresolved` shortens the age-out to a day: an 'unknown' stock verdict usually means
 * the book had no inventory to judge, and the first stocked month must not spend 30 days being
 * rendered under an unverified sign. ~9 round trips a day against a local port is cheap;
 * a wrong sign on a card for a month is not.
 */
export function shouldReprobe(
  cached:
    | {
        quirksSchemaVersion: number;
        tallyVersion: string;
        probedAt: number;
        stockSignUnresolved?: boolean | undefined;
      }
    | undefined,
  current: { tallyVersion: string; now: number },
): boolean {
  if (!cached) return true;
  if (cached.quirksSchemaVersion !== QUIRKS_SCHEMA_VERSION) return true;
  if (cached.tallyVersion !== current.tallyVersion) return true;
  // Tally is upgraded in place and the version string is not always reliable, so age out
  // regardless.
  const ONE_DAY = 24 * 60 * 60 * 1000;
  const maxAgeMs = cached.stockSignUnresolved === true ? ONE_DAY : 30 * ONE_DAY;
  return current.now - cached.probedAt > maxAgeMs;
}
