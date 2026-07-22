import {
  QUIRKS_SCHEMA_VERSION,
  TIMEOUTS,
  TallyTransportError,
  aggregateAgeing,
  assertBillsLookSane,
  billsRequest,
  cashBankRequest,
  dutiesTaxesRequest,
  groupsRequest,
  fieldCountOfRequest,
  parseBillRow,
  billsForSide,
  probeCapabilities,
  probeRequest,
  revenueRequest,
  shouldReprobe,
  stockRequest,
  xmlTagResponseToRows,
  type RawBill,
  type TallyFailure,
  type TallyQuirks,
  type TallyTransport,
} from '@tally-bridge/tally';
import {
  canonicalAmount,
  parseAmount,
  parseAmountToPaise,
  sortRows,
  type Amount,
  type IsoDate,
  type Section,
  type SectionPayload,
  type Side,
} from '@tally-bridge/core';
import { ROUTES, signRequest } from '@tally-bridge/protocol';
import {
  SeqCounter,
  runCycle,
  type ExtractedSection,
  type SyncEvent,
  type SyncStore,
  type UploadResult,
  type Watermark,
} from '@tally-bridge/sync';

/**
 * The real sync cycle: Tally extraction wired to the sync orchestrator.
 *
 * This module is the only place where the three halves of the product meet — the Tally
 * transport, the AlterID/hash gates, and the upload. Everything it does is already tested in
 * isolation elsewhere; what is tested HERE is the wiring, because the wiring is where the
 * conventions get quietly violated: a float in the money path, a name used as an identity, an
 * empty party column shipped as a dashboard.
 *
 * Shape: `buildCycle(deps)` returns a `() => Promise<void>` suitable for handing straight to
 * `Scheduler.runCycle`. Nothing here imports Electron, so it is testable in milliseconds.
 */

/**
 * The one path the server verifies signatures against.
 *
 * Re-exported from the shared route table rather than declared, so "must match `apps/server`
 * exactly" is now enforced by the type checker instead of asked of the reader. The path is
 * signed (see packages/protocol/src/routes.ts); a divergence here would be a 401 on the owner's
 * own deployment, not a crash.
 */
export const SYNC_PATH = ROUTES.sync.path;

/**
 * What `probeCapabilities` reports as the Tally version today.
 *
 * The version string is not actually readable from the object model we query, so the cache
 * validity check below compares "unknown" against "unknown" and effectively reduces to the
 * 30-day age-out. Named rather than inlined so that the day a version probe lands, the two
 * call sites that must agree are obvious.
 */
const TALLY_VERSION_UNKNOWN = 'unknown';

/** Company facts that come off the probe and are needed to build every later request. */
interface CompanyInfo {
  /** The identity. Everything is keyed on this — never on the name. */
  companyGuid: string;
  /**
   * Used ONLY to target the request (`SVCURRENTCOMPANY`), never to identify data. Tally has no
   * way to select a company by GUID, so the name is unavoidable here — which is exactly why it
   * must not leak into the keys.
   */
  name: string;
  state: string;
  booksFrom: IsoDate;
  lastVoucherDate: IsoDate;
  isActive: boolean;
  altMstId: number;
  altVchId: number;
}

export interface CycleDeps {
  transport: TallyTransport;
  store: SyncStore;
  /** Sealing key. A public key and nothing else — the Bridge cannot read what it uploads. */
  identityPublicKey: Uint8Array;
  /** Ed25519 device key: proves who is uploading, decrypts nothing. */
  deviceSecretKey: Uint8Array;
  deviceId: string;
  tenantId: string;
  /** Origin of the client's own deployment, e.g. `https://acme.vercel.app`. */
  serverUrl: string;
  seq?: SeqCounter | undefined;
  now?: (() => number) | undefined;
  /** The as-of date. Defaults to today in LOCAL time — Tally's books are local, not UTC. */
  today?: (() => IsoDate) | undefined;
  fetch?: typeof fetch | undefined;
  /** Override the HTTP uploader. Tests inject a fake; production leaves it alone. */
  upload?: ((envelopeJson: string, idempotencyKey: string) => Promise<UploadResult>) | undefined;
  log?: ((e: SyncEvent) => void) | undefined;
}

/**
 * Tally not being reachable is NOT an error.
 *
 * Closed overnight and every weekend is the normal state of a desktop app, and "no company
 * open" is the normal state between launching Tally and opening the books. Surfacing either as
 * an error would train the owner to ignore a red dot that is right 95% of the time.
 */
function isSilentFailure(f: TallyFailure): boolean {
  return f.kind === 'not_running' || f.kind === 'no_company_open';
}

function isSilentError(e: unknown): boolean {
  return e instanceof TallyTransportError && isSilentFailure(e.failure);
}

export function buildCycle(deps: CycleDeps): () => Promise<void> {
  const now = deps.now ?? (() => Date.now());
  const seq = deps.seq ?? new SeqCounter();
  const log = deps.log ?? (() => {});
  const upload =
    deps.upload ??
    createUploader({
      serverUrl: deps.serverUrl,
      deviceId: deps.deviceId,
      deviceSecretKey: deps.deviceSecretKey,
      fetch: deps.fetch,
    });

  /** Populated by the probe each cycle; read by `extract`, which only gets a GUID. */
  const companies = new Map<string, CompanyInfo>();

  return async function cycle(): Promise<void> {
    const asOf = (deps.today ?? (() => isoDateOf(now())))();
    companies.clear();

    /**
     * A hard Tally failure found during the probe, held rather than thrown.
     *
     * Throwing here would skip the outbox drain, and the outbox has nothing to do with Tally:
     * a laptop that reconnects at 2am must flush even if Tally is broken or shut. So the probe
     * reports "no companies", the orchestrator drains, and only then does this surface.
     */
    let probeFailure: TallyFailure | undefined;

    const probeCompanies = async (): Promise<Array<Watermark & { name: string }>> => {
      // Encoding first: nothing decodes until this is settled, and it is cached on the
      // transport for the life of the process, so this costs one extra round trip ONCE.
      if (!deps.transport.currentEncoding) {
        await deps.transport.detectEncoding(probeRequest());
      }

      const res = await deps.transport.request(probeRequest(), TIMEOUTS.probeMs);
      if (!res.ok) {
        if (!isSilentFailure(res.failure)) probeFailure = res.failure;
        return [];
      }

      const out: Array<Watermark & { name: string }> = [];
      // Schema-checked like `ask()` — a company NAME containing an `<F0n>` tag would otherwise
      // widen its row and shift the GUID, and the GUID is this product's identity for a company.
      for (const cols of xmlTagResponseToRows(res.xml, { fieldCount: fieldCountOfRequest(probeRequest()) })) {
        const info = parseProbeRow(cols, asOf);
        if (!info) {
          // No GUID means no identity. Syncing it under its name would merge or split the
          // company's history the first time the name is edited — silently, and months later.
          log({ kind: 'company_skipped', companyGuid: '', reason: 'probe row has no GUID' });
          continue;
        }
        companies.set(info.companyGuid, info);
        out.push({
          companyGuid: info.companyGuid,
          altMstId: info.altMstId,
          altVchId: info.altVchId,
          name: info.name,
        });
      }
      return out;
    };

    const extract = async (companyGuid: string, sections: Section[]): Promise<ExtractedSection[]> => {
      const info = companies.get(companyGuid);
      if (!info) throw new Error(`extract called for a company the probe never saw: ${companyGuid}`);

      const quirks = await ensureQuirks(deps, info, asOf, now);

      // Strictly serial. The transport mutex already enforces one request at a time; a
      // Promise.all here would only queue them anyway while making the code look concurrent.
      const out: ExtractedSection[] = [];
      for (const section of sections) {
        out.push(await extractSection(deps.transport, section, info, quirks, asOf));
      }
      return out;
    };

    try {
      await runCycle(
        {
          store: deps.store,
          probeCompanies,
          extract,
          upload,
          identityPublicKey: deps.identityPublicKey,
          // Signs the sealed envelope. It cannot decrypt one — see OrchestratorDeps: the server
          // also holds identityPublicKey, so without a signature it could mint envelopes full of
          // invented numbers. Confidentiality was never the gap; authenticity was.
          deviceSecretKey: deps.deviceSecretKey,
          tenantId: deps.tenantId,
          deviceId: deps.deviceId,
          now,
          log,
        },
        seq,
      );
    } catch (e) {
      // Tally shut mid-cycle (the owner closed it while we were pulling sections). Same
      // non-event as finding it shut at the top of the cycle.
      if (isSilentError(e)) {
        log({ kind: 'tally_unavailable' });
        return;
      }
      throw e;
    }

    if (probeFailure) throw new TallyTransportError(probeFailure);
  };
}

// ---------------------------------------------------------------- quirks

/**
 * Resolve this Tally's dialect, from cache when we can.
 *
 * Probing costs ~9 round trips against a single-threaded desktop app the owner is typing into,
 * so it must not happen every cycle. But a cache that never expires is how a product ships a
 * wrong answer forever — `shouldReprobe` owns that judgment, not this function.
 */
async function ensureQuirks(
  deps: CycleDeps,
  info: CompanyInfo,
  asOf: IsoDate,
  now: () => number,
): Promise<TallyQuirks> {
  const cached = deps.store.getQuirks();
  if (cached) {
    const cachedQuirks = JSON.parse(cached.json) as TallyQuirks;
    if (
      !shouldReprobe(
        {
          quirksSchemaVersion: cached.quirksSchemaVersion,
          tallyVersion: cached.tallyVersion,
          probedAt: cached.probedAt,
          // An unresolved stock sign ages out daily rather than monthly — the first stocked
          // month must not render under an unverified sign for 30 days. See shouldReprobe.
          stockSignUnresolved: cachedQuirks.stockValueSign === 'unknown',
        },
        { tallyVersion: TALLY_VERSION_UNKNOWN, now: now() },
      )
    ) {
      return cachedQuirks;
    }
  }

  const quirks = await probeCapabilities(deps.transport, {
    company: info.name,
    booksFrom: info.booksFrom,
    asOf,
  });

  deps.store.setQuirks({
    quirksSchemaVersion: QUIRKS_SCHEMA_VERSION,
    tallyVersion: quirks.tallyVersion,
    probedAt: now(),
    json: JSON.stringify(quirks),
  });
  return quirks;
}

// ---------------------------------------------------------------- extraction

/**
 * Ask Tally, and turn a failure into a throw. Silent kinds are unwound by `buildCycle`.
 *
 * The `fieldCount` is not optional decoration. Without it the decoder infers each row's width from
 * the widest tag PRESENT IN THAT ROW, so a field whose text contains one of our own `<F0n>` tags
 * silently widens its row and the extra columns are dropped off the end — a party or group name
 * eating its neighbour's value with nothing thrown. Passing the count the REQUEST declared makes
 * the row schema an assertion instead of a guess: an out-of-schema tag is rejected loudly, and a
 * loud failure beats a wrong number on a card someone makes decisions from.
 *
 * `flavour.ts` already did this; the extraction path did not, which is the half that touches money.
 */
async function ask(transport: TallyTransport, xml: string, timeoutMs: number): Promise<string[][]> {
  const res = await transport.request(xml, timeoutMs);
  if (!res.ok) throw new TallyTransportError(res.failure);
  return xmlTagResponseToRows(res.xml, { fieldCount: fieldCountOfRequest(xml) });
}

/**
 * `ExtractedSection`, but with the payload typed as what it ACTUALLY is.
 *
 * The orchestrator declares `payload: CanonicalValue` — "anything JSON-shaped" — which is the
 * hole BUG-6 lived in for the life of the codebase: this file emitted amount STRINGS, the model
 * declared `Amount = number`, the card layer did arithmetic on the result, and no compiler
 * anywhere had a reason to object. Every module passed its own tests while disagreeing with the
 * one on the other side of this line.
 *
 * Naming `SectionPayload` here closes it. `amountFrom` returns `string`, `Amount` is now
 * `string`, and if either side ever drifts again the build fails HERE — at the producer, where
 * the mistake is, rather than three packages away inside a card at runtime.
 *
 * No cast is needed to widen this back to `ExtractedSection`: `SectionPayload` structurally
 * satisfies `CanonicalValue` (see the note on the row types in core's model.ts), so the compiler
 * verifies the entire payload rather than taking our word for it.
 */
type TypedExtractedSection = {
  section: Section;
  asOf: IsoDate;
  payload: SectionPayload;
};

async function extractSection(
  transport: TallyTransport,
  section: Section,
  info: CompanyInfo,
  quirks: TallyQuirks,
  asOf: IsoDate,
): Promise<TypedExtractedSection> {
  const companyGuid = info.companyGuid;

  switch (section) {
    // The probe already told us everything this section holds; asking Tally again would be a
    // round trip for data sitting in a local variable.
    case 'company':
      return {
        section,
        asOf,
        payload: {
          section: 'company',
          rows: [
            {
              companyGuid,
              name: info.name,
              state: info.state,
              booksFrom: info.booksFrom,
              lastVoucherDate: info.lastVoucherDate,
              tallyFlavour: quirks.flavour,
              tallyVersion: quirks.tallyVersion,
            },
          ],
        },
      };

    case 'group_balance': {
      const rows = await ask(
        transport,
        groupsRequest({
          company: info.name,
          booksFrom: info.booksFrom,
          asOf,
          usePrimaryGroup: quirks.supportsPrimaryGroupMethod,
        }),
        TIMEOUTS.sectionMs,
      );
      const mapped = rows.map((c) => ({
        companyGuid,
        asOf,
        groupName: c[0] ?? '',
        parent: c[1] ?? '',
        primaryGroup: c[2] ?? '',
        isRevenue: c[3] === '1',
        opening: amountFrom(c[4]),
        closing: amountFrom(c[5]),
      }));
      return {
        section,
        asOf,
        // Tally's collection order is not guaranteed stable across runs, and an unstable order
        // flaps the section hash — which defeats the upload gate silently.
        payload: { section: 'group_balance', rows: sortRows(mapped, (r) => r.groupName) },
      };
    }

    case 'cash_bank': {
      const rows = await ask(
        transport,
        cashBankRequest({
          company: info.name,
          asOf,
          useGroupBankFunctions: quirks.useGroupBankFunctions,
        }),
        TIMEOUTS.sectionMs,
      );
      const mapped = rows.map((c) => ({
        companyGuid,
        asOf,
        ledgerName: c[0] ?? '',
        parent: c[1] ?? '',
        closing: amountFrom(c[2]),
      }));
      return {
        section,
        asOf,
        payload: { section: 'cash_bank', rows: sortRows(mapped, (r) => r.ledgerName) },
      };
    }

    case 'duties_taxes': {
      // Same ledger-grain mechanism as cash_bank, filtered to the Duties & Taxes group. The
      // real TallyPrime confirmed `$$IsLedOfGrp` on a Ledger collection resolves (Spike A 7c),
      // so this reuses a mechanism a real book has already validated rather than a new guess.
      const rows = await ask(
        transport,
        dutiesTaxesRequest({ company: info.name, asOf }),
        TIMEOUTS.sectionMs,
      );
      const mapped = rows.map((c) => ({
        companyGuid,
        asOf,
        ledgerName: c[0] ?? '',
        parent: c[1] ?? '',
        closing: amountFrom(c[2]),
      }));
      return {
        section,
        asOf,
        payload: { section: 'duties_taxes', rows: sortRows(mapped, (r) => r.ledgerName) },
      };
    }

    case 'ageing_receivable':
      return ageingSection(transport, section, 'receivable', info, quirks, asOf);

    case 'ageing_payable':
      return ageingSection(transport, section, 'payable', info, quirks, asOf);

    case 'stock_value': {
      const rows = await ask(transport, stockRequest({ company: info.name, asOf }), TIMEOUTS.sectionMs);
      // The probe MEASURED how `expr.amount('$ClosingValue')` behaves on this Tally by
      // cross-checking it against the Stock-in-Hand group (packages/tally, stocksign.ts).
      // 'positive_magnitude' means $$IsDebit did not fire for StockGroup, so the idiom handed
      // us positive valuations; negating here restores the Dr-negative convention the whole
      // product — including stockCard's display flip — is built on. 'unknown' means the book
      // could not adjudicate; the documented idiom is assumed uncorrected and the quirks cache
      // re-probes daily until the book can answer.
      const negate = quirks.stockValueSign === 'positive_magnitude';
      const mapped = rows.map((c) => ({
        companyGuid,
        asOf,
        stockGroup: c[0] ?? '',
        closingValue: negate ? negatedAmount(amountFrom(c[1])) : amountFrom(c[1]),
      }));
      return {
        section,
        asOf,
        payload: { section: 'stock_value', rows: sortRows(mapped, (r) => r.stockGroup) },
      };
    }

    case 'period_revenue': {
      // The CURRENT month only. Closed months are immutable, so they are backfilled once at
      // onboarding rather than re-pulled every fifteen minutes forever.
      const monthStart = `${asOf.slice(0, 8)}01`;
      const from = monthStart < info.booksFrom ? info.booksFrom : monthStart;
      const rows = await ask(
        transport,
        revenueRequest({ company: info.name, from, to: asOf }),
        TIMEOUTS.sectionMs,
      );
      // Columns are positional and fixed by `revenueRequest`: F01 name, F02 amount, F03 parent.
      //
      // Parent is read from F03 — APPENDED after the amount rather than inserted next to the
      // name, so that adding it to the TDL is a purely additive change that cannot silently
      // shift the amount column and misread every number on the card.
      //
      // `revenueRequest` now fetches the parent, so F03 carries it and the top-level-only sum in
      // viewmodel is live. (It did not, for a while: this whole column read `''` and every row
      // looked top-level, so the double-count fix was correct and INERT at the same time.)
      //
      // `c[2] ?? ''` is load-bearing, not defensive padding. A ROOT group's parent is emitted as
      // the empty string, and production calls `xmlTagResponseToRows` WITHOUT a fieldCount — so
      // row width falls back to the widest tag present in that row, and a root whose blank F03 is
      // omitted by Tally decodes to a length-2 row. `c[2]` is then `undefined`, not `''`. Root and
      // "Tally omitted the blank" are indistinguishable here, and both mean the same thing.
      const mapped = rows.map((c) => ({
        companyGuid,
        period: asOf.slice(0, 7),
        groupName: c[0] ?? '',
        amount: amountFrom(c[1]),
        parent: c[2] ?? '',
      }));
      return {
        section,
        asOf,
        payload: { section: 'period_revenue', rows: sortRows(mapped, (r) => r.groupName) },
      };
    }
  }
}

/**
 * The centerpiece.
 *
 * The Bills collection is already an aggregate — Tally has netted every invoice against every
 * receipt and kept the open residue — so this reads a summary rather than summarizing raw data.
 * Payables are the same request with a different CHILDOF.
 */
async function ageingSection(
  transport: TallyTransport,
  section: Section,
  side: Side,
  info: CompanyInfo,
  quirks: TallyQuirks,
  asOf: IsoDate,
): Promise<TypedExtractedSection> {
  const rows = await ask(
    transport,
    billsRequest({
      company: info.name,
      booksFrom: info.booksFrom,
      asOf,
      side,
      collectionType: quirks.billsCollectionType,
      partyMethod: quirks.billPartyMethod,
    }),
    TIMEOUTS.sectionMs,
  );

  const bills: RawBill[] = rows.map(parseBillRow).filter((b) => b !== undefined);

  // THE check that must never be removed. A wrong party method does not error in Tally — it
  // returns a silently empty column, and without this the product publishes a confident
  // dashboard of blank debtors with correct-looking totals. Throwing here aborts the cycle
  // BEFORE the watermark advances, so the next cycle retries rather than skipping forever.
  assertBillsLookSane(bills);

  // The Bills collection cannot be narrowed to one side or to open bills in the TDL on a real
  // TallyPrime 7.0 (see the note on `billsRequest`), so both cuts happen here. `bills`, not
  // the filtered set, is what gets asserted above — a side test that discarded everything must
  // read as a broken extraction, never as a company that owes nothing.
  // `billsForSide(bills, side)` keeps the bills that CLASSIFY to this side — debtor invoices +
  // creditor advances for receivables, creditor invoices + debtor advances for payables. Both
  // sections fetch the same rows (F07 tags the group) and each keeps its own; advances land on the
  // opposite side from their group, shown separately rather than netted. See `classify`.
  const agg = aggregateAgeing(billsForSide(bills, side), {
    companyGuid: info.companyGuid,
    asOf,
    side,
  });

  return {
    section,
    asOf,
    payload: {
      section: section === 'ageing_payable' ? 'ageing_payable' : 'ageing_receivable',
      rows: agg.rows.map((r) => ({
        companyGuid: r.companyGuid,
        asOf: r.asOf,
        side: r.side,
        partyName: r.partyName,
        bucket: r.bucket,
        amount: ageingAmount(r.amount),
        billCount: r.billCount,
      })),
      // Totals travel SEPARATELY from the matrix, computed over every bill before top-N
      // truncation. The "Total Receivables" card must not be wrong because party #26 fell out.
      totals: agg.totals.map((t) => ({
        companyGuid: t.companyGuid,
        asOf: t.asOf,
        side: t.side,
        bucket: t.bucket,
        amount: ageingAmount(t.amount),
        billCount: t.billCount,
      })),
    },
  };
}

// ---------------------------------------------------------------- money

/**
 * A Tally decimal string to its canonical wire form, with no float in between.
 *
 * `Number("1.005") * 100` is `100.49999999999999`, so any route through a float loses a paisa
 * to a rounding step that never had to exist. String -> integer paise -> string has no such
 * step. Amounts ride the wire as strings for the same reason: `canonicalStringify` rejects
 * non-integer numbers outright, precisely so nobody can reintroduce this.
 */
function amountFrom(col: string | undefined): Amount {
  if (col === undefined || col.length === 0) return '0.00';
  return paiseToDecimalString(parseAmountToPaise(col));
}

/**
 * An amount from `aggregateAgeing` to its canonical wire form.
 *
 * `aggregateAgeing` (packages/tally) declares its result as `AgeingBucketRow`/`AgeingTotalRow` —
 * the WIRE model, whose `amount` is a canonical decimal string — but actually populates it with
 * rupee NUMBERS from `fromPaise`. That is BUG-6 all over again, in a second location: one type
 * doing two jobs (the pre-wire aggregate AND the wire row), with nothing to catch the difference
 * while `Amount` was `number` and the two happened to coincide.
 *
 * Fixing it properly means `ageing.ts` emitting `canonicalAmount(...)` itself and this function
 * disappearing — but that file is outside this change's territory, so this accepts BOTH shapes
 * and normalizes. It is an adapter, not a coercion: every branch goes through a parser that
 * THROWS on anything that is not money. It keeps working unchanged the day `ageing.ts` is fixed.
 */
function ageingAmount(v: Amount | number): Amount {
  return typeof v === 'number' ? canonicalAmount(v) : canonicalAmount(parseAmount(v));
}

/**
 * Exact negation of a canonical amount, through integer paise — no float, no rounding step.
 * `-0` cannot escape: `paiseToDecimalString` only writes the minus sign for `paise < 0`, and
 * `-0 < 0` is false.
 */
function negatedAmount(a: Amount): Amount {
  return paiseToDecimalString(-parseAmountToPaise(a));
}

function paiseToDecimalString(paise: number): string {
  // Integer arithmetic only: `abs` is a safe integer, so `abs / 100` truncates exactly and
  // `abs % 100` is exact. There is no rounding decision anywhere in here.
  const abs = Math.abs(paise);
  const whole = Math.trunc(abs / 100);
  const frac = abs % 100;
  const body = `${whole}.${String(frac).padStart(2, '0')}`;
  // `-0` must never escape: it is !== 0 under Object.is and would hash differently from 0.
  return paise < 0 ? `-${body}` : body;
}

// ---------------------------------------------------------------- probe parsing

/**
 * One probe row -> a company.
 *
 * Columns are fixed by `probeRequest()`: F01 name, F02 guid, F03 AltMstId, F04 AltVchId,
 * F05 booksFrom (YYYYMMDD int), F06 lastVoucherDate (same), F07 isActive, F08 state.
 */
function parseProbeRow(cols: readonly string[], asOf: IsoDate): CompanyInfo | undefined {
  const [name, guid, altMst, altVch, booksFrom, lastVoucher, isActive, state] = cols;
  if (!guid || guid.length === 0) return undefined;

  return {
    companyGuid: guid,
    name: name ?? '',
    state: state ?? '',
    // A company whose books-from date is unreadable still syncs: the financial-year start is a
    // safe lower bound for the collections we ask for, and refusing would strand the install.
    booksFrom: isoFromTallyInt(booksFrom) ?? financialYearStart(asOf),
    // Empty is honest here — a company with no vouchers yet genuinely has no last voucher date.
    lastVoucherDate: isoFromTallyInt(lastVoucher) ?? '',
    isActive: isActive === '1',
    // A missing watermark degrades to "always full sync", which is correct-but-slow. Defaulting
    // to something non-zero would instead skip real changes.
    altMstId: Number(altMst ?? 0) || 0,
    altVchId: Number(altVch ?? 0) || 0,
  };
}

/** The probe returns dates as YYYYMMDD integers. */
function isoFromTallyInt(v: string | undefined): IsoDate | undefined {
  if (!v || !/^\d{8}$/.test(v)) return undefined;
  return `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}`;
}

/** Indian financial year: 1 April to 31 March. */
function financialYearStart(asOf: IsoDate): IsoDate {
  const year = Number(asOf.slice(0, 4));
  const month = Number(asOf.slice(5, 7));
  return `${month >= 4 ? year : year - 1}-04-01`;
}

/** Local, not UTC. A business in Mumbai closes its books on its own calendar, not Greenwich's. */
function isoDateOf(ms: number): IsoDate {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// ---------------------------------------------------------------- upload

export interface UploaderOptions {
  serverUrl: string;
  deviceId: string;
  deviceSecretKey: Uint8Array;
  fetch?: typeof fetch | undefined;
}

/**
 * POST one sealed envelope to the client's own server.
 *
 * The body signed and the body sent are the same bytes, and the signed path is the constant the
 * server verifies against — build either from anything else and every request 401s.
 */
export function createUploader(
  opts: UploaderOptions,
): (envelopeJson: string, idempotencyKey: string) => Promise<UploadResult> {
  const doFetch = opts.fetch ?? globalThis.fetch;

  return async (envelopeJson: string, idempotencyKey: string): Promise<UploadResult> => {
    const body = new TextEncoder().encode(envelopeJson);
    const url = new URL(SYNC_PATH, opts.serverUrl);

    const headers = await signRequest(
      { deviceId: opts.deviceId, method: 'POST', path: SYNC_PATH, body },
      opts.deviceSecretKey,
    );

    let res: Response;
    try {
      res = await doFetch(url, {
        method: 'POST',
        body,
        headers: {
          ...headers,
          'content-type': 'application/json',
          // The server upserts on this, so a retry after a lost ACK is free.
          'idempotency-key': idempotencyKey,
        },
      });
    } catch {
      // DNS, TLS, refused, reset, offline. All of it is a laptop in a drawer, not a bug.
      return { ok: false, retryable: true };
    }

    // Read and discard the body: an unconsumed response leaks the socket under undici, and this
    // runs every fifteen minutes forever.
    try {
      await res.arrayBuffer();
    } catch {
      // A truncated response to an otherwise-successful POST changes nothing about the status.
    }

    if (res.status >= 200 && res.status < 300) {
      return { ok: true, retryable: false, status: res.status };
    }

    // 5xx and network are worth a backoff; 4xx is not. A revoked device, a bad signature or a
    // full quota does not fix itself by being asked again in a minute — the orchestrator drops
    // it and surfaces it. Nothing is lost: the section hash is only advanced on ACK, so Tally
    // (the source of truth) re-supplies it on the next cycle.
    return { ok: false, retryable: res.status >= 500, status: res.status };
  };
}
