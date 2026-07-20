import type { CompanyCards, GetCardsResult } from '../main/ipc.ts';

/**
 * `getCards()` -> what the dashboard draws.
 *
 * This file is deliberately thin, and it is worth saying why, because it was briefly the
 * opposite. `getCards()` was typed `Promise<unknown>` while the main process was being written,
 * so this started life SNIFFING the payload — rows or cards, keyed or arrayed — to avoid a
 * blank dashboard if the other side chose a shape this one had not guessed. That hedge is now
 * deleted. The contract is `GetCardsResult`, the cards arrive already built by
 * `@tally-bridge/viewmodel` inside the main process, and a typed contract the compiler checks
 * is worth more than any amount of runtime tolerance: if `ipc.ts` changes, `tsc` fails here,
 * whereas the sniffer would have silently kept working and silently drawn something else.
 *
 * So the whole job is: pick the company, and turn the wire's four states into one value the
 * renderer can switch on. There is NO arithmetic in this file and there must never be. Every
 * number that reaches the screen was computed once, in integer paise, in the card layer.
 */

/** The wire's four states, plus the one the wire cannot report: that we never reached it. */
export type DashboardState = 'locked' | 'empty' | 'error' | 'ready' | 'unavailable';

export interface DashboardModel {
  state: DashboardState;
  /** Every company in the payload, for the switcher. One or zero means no switcher. */
  companies: Array<{ guid: string; name: string }>;
  selected: string | undefined;
  /** The selected company's cards. Present only in the `ready` state. */
  cards: CompanyCards | undefined;
  /**
   * At least one section or card was skipped upstream. The dashboard must SAY that some figures
   * are missing rather than let the cards it did get imply they are the whole picture.
   */
  incomplete: boolean;
  /**
   * One plain sentence, or undefined. It comes from the main process, which guarantees it
   * carries no code and no stack. It is never built here and never contains a value we echo.
   */
  message: string | undefined;
}

function base(state: DashboardState): DashboardModel {
  return { state, companies: [], selected: undefined, cards: undefined, incomplete: false, message: undefined };
}

/**
 * Build the model. Never throws.
 *
 * `null` means the IPC call itself rejected and the caller's `ask()` handed us its fallback.
 * That is a FIFTH state the wire has no word for, and it must not be laundered into `empty`:
 * "nothing has synced yet" and "the Bridge is not answering" are different sentences with
 * different actions, and showing the first when the second is true is precisely the quiet lie
 * this dashboard exists not to tell.
 */
export function buildModel(result: GetCardsResult | null | undefined, selectedGuid?: string): DashboardModel {
  if (!result) return base('unavailable');

  switch (result.state) {
    case 'locked': {
      const m = base('locked');
      // Set ONLY when the last unlock failed for a reason that is provably not the passphrase.
      // A wrong passphrase never sets it, so this is safe to show verbatim.
      m.message = result.problem;
      return m;
    }
    case 'empty':
      return base('empty');
    case 'error': {
      const m = base('error');
      m.message = result.message;
      return m;
    }
    case 'ready': {
      const companies = result.companies ?? [];
      // Unlocked and readable, but with nothing in it. `empty` already has the honest sentence
      // for that; a company switcher over zero companies does not.
      if (companies.length === 0) return base('empty');

      const m = base('ready');
      m.companies = companies.map((c) => ({ guid: c.companyGuid, name: c.name || c.companyGuid }));
      // A remembered selection that is no longer in the payload — a company closed in Tally —
      // falls back to the first rather than showing an empty dashboard for a company that is
      // gone.
      const chosen = companies.find((c) => c.companyGuid === selectedGuid) ?? companies[0];
      m.selected = chosen?.companyGuid;
      m.cards = chosen;
      m.incomplete = result.incomplete;
      return m;
    }
    default:
      // A default rather than a never-assertion: this value crossed a process boundary, so "the
      // type says it cannot happen" is a claim about our source, not about the bytes that
      // arrived.
      return base('unavailable');
  }
}

/** True when the selected company has no card at all — unlocked, synced, and genuinely blank. */
export function hasNoCards(cards: CompanyCards | undefined): boolean {
  if (!cards) return true;
  return (
    !cards.cashBank &&
    !cards.receivables &&
    !cards.payables &&
    !cards.profit &&
    !cards.stock &&
    !cards.salesTrend &&
    // An EMPTY ARRAY is not a card. `balanceSheetTree` returns `[]` for a company whose
    // group_balance section synced but held no non-revenue rows, and `[]` renders as a heading
    // above nothing — so the length check, not just presence. Getting this wrong in the other
    // direction is the bug worth naming: omit `balanceSheet` from this list entirely and a
    // company whose ONLY synced section is group_balance is told "nothing has synced yet" while
    // holding a complete balance sheet.
    !cards.balanceSheet?.length
  );
}
