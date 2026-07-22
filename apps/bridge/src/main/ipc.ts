import type { IsoDate } from '@tally-bridge/core';
import type {
  AgeingCard,
  CashBankCard,
  DutiesTaxesCard,
  ProfitCard,
  StockCard,
  TreeNode,
  TrendCard,
} from '@tally-bridge/viewmodel';
import type { SyncStatus } from './scheduler.ts';
import type { WizardEvent, WizardState } from '../onboarding/wizard.ts';

/**
 * The IPC contract.
 *
 * This is the ONLY surface the renderer can reach. It is deliberately small and deliberately
 * shaped: every channel is a specific verb, never a generic escape hatch.
 *
 * The rule that matters: THERE IS NO `invoke(channel, ...args)` PASSTHROUGH, and there never
 * may be. A generic bridge turns any renderer XSS into main-process code execution, which is
 * the exact vulnerability class contextIsolation exists to prevent. Enumerating the verbs is
 * what makes the bridge auditable.
 *
 * Note what is absent: nothing here can read the identity secret key, because the main process
 * does not have one. The renderer asks for CARDS, and cards are computed from data the user
 * unlocked in this session.
 */

export const CHANNELS = {
  getStatus: 'bridge:getStatus',
  syncNow: 'bridge:syncNow',
  getCards: 'bridge:getCards',
  unlock: 'bridge:unlock',
  lock: 'bridge:lock',
  resetDashboard: 'bridge:resetDashboard',
  isProvisioned: 'bridge:isProvisioned',
  detectTally: 'bridge:detectTally',
  listCompanies: 'bridge:listCompanies',
  openExternal: 'bridge:openExternal',
  getMobileAccess: 'bridge:getMobileAccess',
  statusChanged: 'bridge:statusChanged',
  getWizardState: 'bridge:getWizardState',
  sendWizardEvent: 'bridge:sendWizardEvent',
  wizardStateChanged: 'bridge:wizardStateChanged',
  recoveryQr: 'bridge:recoveryQr',
  printRecoverySheet: 'bridge:printRecoverySheet',
} as const;

export type Channel = (typeof CHANNELS)[keyof typeof CHANNELS];

export interface TallyDetectResult {
  reachable: boolean;
  /** A sentence for a human. Never an error code, never a stack trace. */
  message: string;
  companies: Array<{ guid: string; name: string; isActive: boolean }>;
}

/**
 * One company's cards — plain data from `@tally-bridge/viewmodel`, already computed in the main
 * process. The renderer maps these to pixels and re-derives NOTHING (ARCHITECTURE.md rule 2).
 * A card is absent when its section has not synced yet or failed to open; absence is a state
 * the renderer must render, not an error.
 */
export interface CompanyCards {
  companyGuid: string;
  /** Display name from the company section, or the GUID if that section is unavailable. */
  name: string;
  /** The newest as-of date across this company's sections. */
  asOf: IsoDate;
  cashBank?: CashBankCard | undefined;
  dutiesTaxes?: DutiesTaxesCard | undefined;
  receivables?: AgeingCard | undefined;
  payables?: AgeingCard | undefined;
  profit?: ProfitCard | undefined;
  stock?: StockCard | undefined;
  salesTrend?: TrendCard | undefined;
  /**
   * The Balance Sheet, as a tree of groups.
   *
   * AMOUNTS HERE ARE RAW HOUSE CONVENTION — Dr negative, Cr positive — and unlike every other
   * card on this interface, nothing is flipped. That is `balanceSheetTree`'s deliberate choice,
   * not an oversight: a balance sheet shows both sides at once, so there is no single correct
   * flip, and picking one per node would mean trusting `primaryGroup`, which the flavour probe
   * reports EMPTY on installs where `$_PrimaryGroup` is unavailable. The renderer says what the
   * sign means rather than guessing and being silently wrong for some installs.
   *
   * Flat on the wire, a tree here: the rollup is presentation, so the sync payload stays flat
   * (small, and a future native client can build whatever structure suits it).
   */
  balanceSheet?: TreeNode[] | undefined;
}

/**
 * What getCards resolves to. Every variant is a UI state, and none carries internals:
 *
 *   locked  The owner has not unlocked this session (or it auto-locked). `problem` is present
 *           ONLY when the last unlock failed for a reason that is provably NOT the passphrase
 *           (e.g. the stored key bundle failed its freshness check) — one plain sentence, safe
 *           to show verbatim. A wrong passphrase never sets it.
 *   empty   Unlocked, but nothing has synced yet.
 *   error   Unlocked, but the stored data could not be read at all. One sentence.
 *   ready   Cards. `incomplete: true` means at least one section or card was skipped — the
 *           renderer should say "some figures are missing" rather than pretend this is all.
 */
export type GetCardsResult =
  | { state: 'locked'; problem?: string | undefined }
  | { state: 'empty' }
  | { state: 'error'; message: string }
  | { state: 'ready'; companies: CompanyCards[]; incomplete: boolean };

/** What the "View on your phone" card needs. The QR is a raster PNG data URL of `url`. */
export interface MobileAccess {
  url: string;
  tenantId: string;
  qr: string;
}

export interface BridgeApi {
  getStatus(): Promise<SyncStatus>;
  syncNow(): Promise<void>;
  isProvisioned(): Promise<boolean>;
  detectTally(): Promise<TallyDetectResult>;
  /** Returns false on a wrong passphrase — never throws, never says which part was wrong. */
  unlock(passphrase: string): Promise<boolean>;
  lock(): Promise<void>;
  /**
   * The forgotten-passphrase escape hatch: locks the session and WIPES this computer's local
   * dashboard keys, so the app returns to first-run setup. The owner then sets a new passphrase
   * and the figures come back from Tally (the source of truth). Nothing on the server is touched;
   * its old ciphertext is sealed to the discarded identity and simply goes unread. Irreversible —
   * the renderer confirms first.
   */
  resetDashboard(): Promise<void>;
  getCards(): Promise<GetCardsResult>;
  /** Main-process side validates the URL against an allowlist; this is not a general opener. */
  openExternal(url: string): Promise<void>;
  /**
   * The details an owner needs to open THIS dashboard on their phone: the deployed URL, their
   * Tally ID (the login), and a PNG-data-URL QR of the URL. Returns null before the deployment
   * exists. Nothing secret crosses — the URL is public and the passphrase is never involved.
   *
   * Optional so a test's fake bridge need not implement it; the preload always provides it.
   */
  getMobileAccess?(): Promise<MobileAccess | null>;
  onStatusChanged(cb: (s: SyncStatus) => void): () => void;

  // ---- Setup wizard. The STATE MACHINE runs in the main process; the renderer is a view. ----

  /** The current wizard state, redacted (the recovery key never crosses in raw form). */
  getWizardState(): Promise<WizardState>;
  /**
   * Send ONE user-intent event and receive the state after it. The main process validates the
   * event against the machine's own union and accepts ONLY intent events — driver facts
   * (`probe_succeeded`, `provision_succeeded`, `sheet_ready`, ...) are dropped, because a
   * renderer that could assert facts could walk through the recovery-verification gate with a
   * sheet it invented. There is no verb that skips the gate, and this one cannot be made into it.
   */
  sendWizardEvent(event: WizardEvent): Promise<WizardState>;
  onWizardStateChanged(cb: (s: WizardState) => void): () => void;
  /** PNG data URL of the current sheet's recovery QR. Raster only — the renderer refuses SVG. */
  recoveryQr(): Promise<string>;
  /** Renders the sheet in the main process and opens the print dialog. */
  printRecoverySheet(): Promise<void>;
}

declare global {
  interface Window {
    bridge: BridgeApi;
  }
}
