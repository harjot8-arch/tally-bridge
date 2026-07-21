import type {
  AgeingBucketRow,
  AgeingTotalRow,
  CashBankBalance,
  Company,
  GroupBalance,
  IsoDate,
  PeriodRevenueRow,
  Section,
  StockValueRow,
} from '@tally-bridge/core';
import { openSection, type DeviceRoster, type MaybeSignedEnvelope } from '@tally-bridge/crypto';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  dutiesTaxesCard,
  profitCard,
  salesTrendCard,
  stockCard,
} from '@tally-bridge/viewmodel';
import type { CompanyCards, GetCardsResult } from './ipc.ts';
import type { StoredSnapshot } from './snapshots.ts';

/**
 * The reader: sealed local snapshots -> decrypted sections -> card view models.
 *
 * This is the production caller of `openSection`, and the two arguments that make or break its
 * security are populated here, so their provenance is spelled out at the call site they feed:
 *
 *   `expect` COMES FROM THE SLOT METADATA — the (company, section, asOf) that the Bridge's own
 *   sync cycle recorded when IT decided to seal this section — plus the tenantId from the local
 *   keystore. It is never derived from `envelope.aad`. Feeding the envelope's own AAD back as
 *   the expectation would compare a value with itself: every mis-slotted or swapped envelope
 *   would "match". The slot metadata and the AAD are two independent records of the same fact,
 *   which is precisely what lets them disagree when something is wrong.
 *
 *   `trustedDevices` COMES FROM THE UNLOCKED SESSION — the roster that `openIdentity` unwrapped
 *   from inside the passphrase-sealed bundle. It is typed as an argument here and there is
 *   nothing else in scope to populate it with: this module has no server client, no keystore
 *   read, no env access. An envelope signed by any key the bundle does not pin is refused by
 *   `openSection`, however valid its seal and hash are — that includes an envelope minted by
 *   the server, which knows the identity public key and the device public key but can never
 *   know a roster it cannot decrypt.
 *
 * FAILURE SHAPE: one bad slot must not blank six good cards, and no failure may reach the
 * renderer as a stack. Every slot and every card is built inside its own catch; failures mark
 * the result `incomplete` and go to the injected log (the main-process console, where an
 * engineer looks — never the UI).
 */

export interface ReaderInputs {
  slots: readonly StoredSnapshot[];
  /** Slots that existed but could not be read — folded into `incomplete`. */
  unreadable: number;
  tenantId: string;
  identityPublicKey: Uint8Array;
  identitySecretKey: Uint8Array;
  /** From `openIdentity` via the unlocked session. Nowhere else — read the header. */
  roster: DeviceRoster;
  log?: ((message: string) => void) | undefined;
}

interface CompanyAccumulator {
  companyGuid: string;
  name: string | undefined;
  asOf: IsoDate;
  sections: Map<Section, unknown>;
}

export async function buildCards(inputs: ReaderInputs): Promise<GetCardsResult> {
  const log = inputs.log ?? (() => {});
  let incomplete = inputs.unreadable > 0;

  const companies = new Map<string, CompanyAccumulator>();

  for (const slot of inputs.slots) {
    let payload: unknown;
    try {
      payload = await openSlot(slot, inputs);
    } catch (e) {
      // A slot that fails to open is EXCLUDED, never defaulted. The cases that land here:
      // an envelope that does not answer the slot's question (aad/expect mismatch), a signature
      // by an unpinned key, a tampered ciphertext, a corrupt file. All of them are "do not show
      // this number", and none of them may take the rest of the dashboard down.
      incomplete = true;
      log(`[reader] snapshot for ${slot.section} could not be opened: ${(e as Error).message}`);
      continue;
    }

    const acc = companies.get(slot.companyGuid) ?? {
      companyGuid: slot.companyGuid,
      name: undefined,
      asOf: slot.asOf,
      sections: new Map<Section, unknown>(),
    };
    if (slot.asOf > acc.asOf) acc.asOf = slot.asOf;
    acc.sections.set(slot.section, payload);
    companies.set(slot.companyGuid, acc);
  }

  if (companies.size === 0) {
    return incomplete
      ? { state: 'error', message: 'Your saved dashboard data could not be read on this computer.' }
      : { state: 'empty' };
  }

  const out: CompanyCards[] = [];
  for (const acc of companies.values()) {
    const { cards, failed } = buildCompanyCards(acc, log);
    if (failed) incomplete = true;
    out.push(cards);
  }
  // Deterministic order: by display name, then GUID. IPC results should not shuffle per call.
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.companyGuid < b.companyGuid ? -1 : 1));

  return { state: 'ready', companies: out, incomplete };
}

/**
 * Open one slot's envelope against what THIS reader asked for.
 */
async function openSlot(slot: StoredSnapshot, inputs: ReaderInputs): Promise<unknown> {
  let env: unknown;
  try {
    env = JSON.parse(slot.envelope);
  } catch {
    throw new Error('stored envelope is not JSON');
  }
  if (typeof env !== 'object' || env === null || Array.isArray(env)) {
    throw new Error('stored envelope is not an object');
  }

  const payload = await openSection(env as MaybeSignedEnvelope, {
    identityPublicKey: inputs.identityPublicKey,
    identitySecretKey: inputs.identitySecretKey,
    // What WE asked for: the slot's request record + this install's tenant. Never env.aad.
    expect: {
      tenantId: inputs.tenantId,
      companyGuid: slot.companyGuid,
      section: slot.section,
      asOf: slot.asOf,
    },
    trustedDevices: inputs.roster,
  });

  // The payload is now authenticated plaintext written by a pinned device — but "written by us"
  // is a claim about a past version of this codebase, so the discriminant is still checked
  // against the slot rather than trusted.
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('section payload is not an object');
  }
  const section = (payload as { section?: unknown }).section;
  if (section !== slot.section) {
    throw new Error(`payload names section ${String(section)}, slot is ${slot.section}`);
  }
  return payload;
}

function rowsOf<T>(payload: unknown): readonly T[] {
  const rows = (payload as { rows?: unknown }).rows;
  if (!Array.isArray(rows)) throw new Error('section payload has no rows array');
  return rows as T[];
}

function totalsOf<T>(payload: unknown): readonly T[] {
  const totals = (payload as { totals?: unknown }).totals;
  if (!Array.isArray(totals)) throw new Error('ageing payload has no totals array');
  return totals as T[];
}

function buildCompanyCards(
  acc: CompanyAccumulator,
  log: (message: string) => void,
): { cards: CompanyCards; failed: boolean } {
  let failed = false;

  /** One card per catch: a bad amount string in one section throws in the viewmodel (by design
   *  — see `paiseOf`), and that card is omitted rather than rendered coerced or taking the
   *  company down. */
  const tryCard = <T>(name: string, fn: () => T): T | undefined => {
    try {
      return fn();
    } catch (e) {
      failed = true;
      log(`[reader] ${name} card failed for ${acc.companyGuid}: ${(e as Error).message}`);
      return undefined;
    }
  };

  const companyRows = acc.sections.has('company')
    ? tryCard('company', () => rowsOf<Company>(acc.sections.get('company')))
    : undefined;
  const name = companyRows?.[0]?.name;

  const cards: CompanyCards = {
    companyGuid: acc.companyGuid,
    // The GUID is a poor label but an honest one; a company section that failed to open must
    // not erase the company's cards.
    name: typeof name === 'string' && name.length > 0 ? name : acc.companyGuid,
    asOf: acc.asOf,
  };

  if (acc.sections.has('cash_bank')) {
    cards.cashBank = tryCard('cash_bank', () =>
      cashBankCard(rowsOf<CashBankBalance>(acc.sections.get('cash_bank'))),
    );
  }
  if (acc.sections.has('duties_taxes')) {
    cards.dutiesTaxes = tryCard('duties_taxes', () =>
      dutiesTaxesCard(rowsOf<CashBankBalance>(acc.sections.get('duties_taxes'))),
    );
  }
  if (acc.sections.has('ageing_receivable')) {
    const p = acc.sections.get('ageing_receivable');
    cards.receivables = tryCard('receivables', () =>
      ageingCard(totalsOf<AgeingTotalRow>(p), rowsOf<AgeingBucketRow>(p), 'receivable'),
    );
  }
  if (acc.sections.has('ageing_payable')) {
    const p = acc.sections.get('ageing_payable');
    cards.payables = tryCard('payables', () =>
      ageingCard(totalsOf<AgeingTotalRow>(p), rowsOf<AgeingBucketRow>(p), 'payable'),
    );
  }
  if (acc.sections.has('stock_value')) {
    cards.stock = tryCard('stock', () =>
      stockCard(rowsOf<StockValueRow>(acc.sections.get('stock_value'))),
    );
  }
  if (acc.sections.has('period_revenue')) {
    const p = acc.sections.get('period_revenue');
    cards.profit = tryCard('profit', () => {
      const rows = rowsOf<PeriodRevenueRow>(p);
      const { current, previous } = splitPeriods(rows);
      return profitCard(current, previous);
    });
    cards.salesTrend = tryCard('salesTrend', () =>
      salesTrendCard(rowsOf<PeriodRevenueRow>(p)),
    );
  }
  if (acc.sections.has('group_balance')) {
    // `balanceSheetTree` filters `isRevenue` itself and returns the non-revenue side. The P&L
    // half of these same rows is NOT read here: `profit`/`salesTrend` come from
    // `period_revenue`, which is a different section with a different grain. Two projections of
    // one idea, deliberately not merged — see ARCHITECTURE.md.
    cards.balanceSheet = tryCard('balanceSheet', () =>
      balanceSheetTree(rowsOf<GroupBalance>(acc.sections.get('group_balance'))),
    );
  }

  return { cards, failed };
}

/**
 * Split revenue rows into the latest period ("this month") and the one before it.
 *
 * The steady-state payload holds only the current month (closed months are backfilled once at
 * onboarding), so `previous` is frequently empty — `profitCard` renders that as a ₹0 baseline,
 * which is honest for an install with no history yet.
 */
function splitPeriods(rows: readonly PeriodRevenueRow[]): {
  current: PeriodRevenueRow[];
  previous: PeriodRevenueRow[];
} {
  const periods = [...new Set(rows.map((r) => r.period))].sort();
  const cur = periods.at(-1);
  const prev = periods.at(-2);
  return {
    current: cur === undefined ? [] : rows.filter((r) => r.period === cur),
    previous: prev === undefined ? [] : rows.filter((r) => r.period === prev),
  };
}
