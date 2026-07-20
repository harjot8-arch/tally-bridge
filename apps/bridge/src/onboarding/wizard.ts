import type { TallyFailure } from '@tally-bridge/tally';
import { VERIFY_WORD_POSITIONS, makeVerificationChallenge, type RecoverySheet } from './recovery.ts';
import { VercelError, type ProvisionEvent, type ProvisionStep } from './vercel.ts';

/**
 * The setup wizard.
 *
 * A PURE state machine: `next(state, event) -> state`. Nothing here imports Electron, opens a
 * socket, or touches a key. That is not fastidiousness — it is the only way the two properties
 * this screen must have are actually checkable:
 *
 *   1. RECOVERY VERIFICATION CANNOT BE SKIPPED. If the gate lives in a click handler, "skip"
 *      is one `if` away, forever, for every future contributor. Here, `done` is unreachable
 *      except through a correct answer, and a test proves it by throwing every event in the
 *      union at the verify state.
 *   2. NO STACK TRACE EVER REACHES THE OWNER. Every failure is a `problem` state carrying a
 *      sentence and EXACTLY ONE action. One action, not a menu: a non-technical owner staring
 *      at three buttons at the moment something broke picks none of them and phones you.
 *
 * THE ORDER THAT IS LOAD-BEARING, AND WHY IT LOOKS WRONG.
 *
 * The screens read findTally -> connectCloud -> setPassphrase, so the identity keypair appears
 * to be born on the LAST screen. It cannot be. `provision()` sets IDENTITY_PUBKEY as a Vercel
 * env var during the middle screen, so the keypair must already exist when the token is pasted.
 *
 * The resolution is that key GENERATION and key WRAPPING are different events:
 *
 *   generate idSK/idPK ......... entering connectCloud   (phase `awaitIdentity`)
 *   IDENTITY_PUBKEY -> Vercel .. during provisioning
 *   wrap idSK under passphrase . setPassphrase
 *   wrap idSK under recovery key setPassphrase
 *
 * The machine ENFORCES this rather than documenting it: `awaitToken` is only reachable via
 * `identity_ready`, and `provisioning` is only reachable from `awaitToken`. There is no path
 * to provisioning that does not carry an `identityPublicKey`, so the ordering bug cannot be
 * written. A comment would have been forgotten in six months.
 *
 * WHAT THIS MACHINE HOLDS AND WHAT IT REFUSES TO HOLD.
 *
 * State carries the identity PUBLIC key only — never the secret, never the passphrase, never
 * the Vercel token. The driver holds those for the microseconds it needs them. The recovery
 * WORDS are in state, which is a deliberate exception: they are printed on the screen the user
 * is looking at, so state is not a new exposure, and the verification gate has to be able to
 * check an answer without asking the driver to do it for us (see property 1).
 */

// ---------------------------------------------------------------- actions

export type ActionKind =
  | 'retry_probe'
  | 'open_neon'
  | 'paste_new_token'
  | 'open_vercel_billing'
  | 'choose_another_name'
  | 'retry_provision'
  | 'choose_another_passphrase'
  | 'print_again'
  | 'start_again';

/**
 * The one thing the owner can do next.
 *
 * Singular by type, not by convention. An `actions: WizardAction[]` field would let a future
 * screen quietly grow a second button, and the "exactly one action" test would still pass.
 */
export interface WizardAction {
  kind: ActionKind;
  label: string;
  /** Present only when the action opens a page. */
  url?: string | undefined;
}

// ---------------------------------------------------------------- state

export interface TallyCompany {
  /** The identity. Names are edited and duplicated across financial years; the GUID is not. */
  guid: string;
  name: string;
}

/** What survives from the cloud screen into the passphrase screen. */
export interface CloudContext {
  company: TallyCompany;
  /** base64 X25519 public key. PUBLIC — this is why it is safe to sit in wizard state. */
  identityPublicKey: string;
  projectId: string;
  deploymentUrl: string;
}

export type WizardState =
  // ---- Screen 1: find Tally.
  | { screen: 'findTally'; phase: 'probing' }
  | {
      screen: 'findTally';
      phase: 'ready';
      companies: TallyCompany[];
      selectedGuid: string | undefined;
    }
  /**
   * NOT A FAILURE. Tally being closed is the normal state overnight, every weekend, and every
   * time the owner steps out for lunch. Rendering it as an error trains people to ignore
   * errors, which is expensive later when one is real.
   */
  | {
      screen: 'findTally';
      phase: 'waiting';
      reason: 'not_running' | 'no_company_open';
      message: string;
      action: WizardAction;
    }
  | { screen: 'findTally'; phase: 'problem'; message: string; action: WizardAction }

  // ---- Screen 2: connect the cloud.
  | { screen: 'connectCloud'; phase: 'awaitIdentity'; company: TallyCompany }
  | { screen: 'connectCloud'; phase: 'awaitToken'; company: TallyCompany; identityPublicKey: string }
  | {
      screen: 'connectCloud';
      phase: 'provisioning';
      company: TallyCompany;
      identityPublicKey: string;
      step: ProvisionStep;
      message: string;
    }
  /** Also not a failure: the one manual click, expected and guided. */
  | {
      screen: 'connectCloud';
      phase: 'needsHuman';
      company: TallyCompany;
      identityPublicKey: string;
      message: string;
      action: WizardAction;
    }
  | {
      screen: 'connectCloud';
      phase: 'problem';
      company: TallyCompany;
      identityPublicKey: string | undefined;
      message: string;
      action: WizardAction;
    }

  // ---- Screen 3: set the passphrase. The gate.
  | { screen: 'setPassphrase'; phase: 'entry'; ctx: CloudContext }
  | { screen: 'setPassphrase'; phase: 'wrapping'; ctx: CloudContext }
  | {
      screen: 'setPassphrase';
      phase: 'sheet';
      ctx: CloudContext;
      sheet: RecoverySheet;
      /**
       * Set when the last print attempt failed. A NOTE ON THIS SCREEN — never a screen of its own.
       *
       * This used to move to `phase: 'problem'`, which has no `sheet` field, so the sheet was
       * dropped and could not be restored: the only action was "Print again", whose success event
       * (`printed`) is a deliberate no-op and whose failure event is ignored off this phase. The
       * state could never move again. Setup dead-ended with the passphrase already set and the
       * identity already wrapped — `done` unreachable, forever. It was reachable by the DEFAULT
       * path: the dialog opens by itself, and pressing Esc on a dialog you did not ask for is the
       * normal human response.
       *
       * Staying put is also the honest model. The printer failed; the sheet did not. The words and
       * the QR are still on screen and still correct, so there is nothing to recover FROM.
       */
      printProblem?: string;
    }
  | {
      screen: 'setPassphrase';
      phase: 'verify';
      ctx: CloudContext;
      sheet: RecoverySheet;
      /** 1-indexed, as printed on the sheet. */
      positions: number[];
      /** Wrong answers so far. Never locks — this is a typo gate, not an auth boundary. */
      attempts: number;
      message: string | undefined;
    }
  | { screen: 'setPassphrase'; phase: 'problem'; ctx: CloudContext; message: string; action: WizardAction }

  | { screen: 'done'; company: TallyCompany; deploymentUrl: string };

// ---------------------------------------------------------------- events

export type WizardEvent =
  | { type: 'probe_started' }
  | { type: 'probe_succeeded'; companies: TallyCompany[] }
  | { type: 'probe_failed'; failure: TallyFailure }
  | { type: 'select_company'; guid: string }
  | { type: 'continue' }
  | { type: 'retry' }
  /** The driver has generated the keypair. MUST precede provisioning — see the header. */
  | { type: 'identity_ready'; identityPublicKey: string }
  | { type: 'token_pasted'; token: string }
  /** Pipe `provision()`'s own log straight in; no translation layer to drift. */
  | { type: 'provision_event'; event: ProvisionEvent }
  | { type: 'provision_failed'; error: unknown }
  | { type: 'provision_succeeded'; projectId: string; deploymentUrl: string }
  | { type: 'passphrase_submitted'; passphrase: string; confirm: string }
  | { type: 'sheet_ready'; sheet: RecoverySheet }
  | { type: 'wrap_failed'; error: unknown }
  | { type: 'printed' }
  | { type: 'print_failed'; error: unknown }
  | { type: 'verify_submitted'; answers: string[] };

// ---------------------------------------------------------------- constants

export const NEON_URL = 'https://vercel.com/marketplace/neon';
export const VERCEL_BILLING_URL = 'https://vercel.com/account/billing';

/**
 * Ten characters, not "one uppercase, one digit, one symbol".
 *
 * Composition rules produce `Tally@123` — which is in every cracking wordlist — and then get
 * written on a sticky note because nobody can remember them. Length is the only lever that
 * actually costs an attacker anything, and Argon2id at 64 MiB is doing the real work here.
 */
export const MIN_PASSPHRASE_LENGTH = 10;

export function initialState(): WizardState {
  return { screen: 'findTally', phase: 'probing' };
}

// ---------------------------------------------------------------- sentences

/**
 * Tally's failures, as sentences an owner can act on.
 *
 * Deliberately NOT `describeFailure()` from the transport, which is written for a slightly
 * different reader and says things like "(HTTP 502)". A status code on the first screen of a
 * setup wizard tells a business owner exactly one thing: that this software is not for them.
 */
function describeTally(f: TallyFailure): WizardState {
  const tryAgain: WizardAction = { kind: 'retry_probe', label: 'Try again' };

  switch (f.kind) {
    case 'not_running':
      return {
        screen: 'findTally',
        phase: 'waiting',
        reason: 'not_running',
        // ONE sentence, and no second clause telling them what to do — the button already
        // says "Try again", and a sentence that repeats the button is noise on the one screen
        // where the owner is deciding whether this software is for them.
        message: 'Tally is not open on this computer.',
        action: tryAgain,
      };
    case 'no_company_open':
      return {
        screen: 'findTally',
        phase: 'waiting',
        reason: 'no_company_open',
        message: 'Tally is open, but no company is loaded.',
        action: tryAgain,
      };
    case 'not_tally':
      return {
        screen: 'findTally',
        phase: 'problem',
        message: 'Another program on this computer is using the port Tally needs. Close it, then try again.',
        action: tryAgain,
      };
    case 'tally_error':
      // Tally's own fault text is the only thing that can explain a licence or security
      // rejection, so it is passed through — but it is passed through SANITISED. It arrives
      // from a parsed XML body, which means it is arbitrary text we do not control: it may be
      // an unterminated fragment ("Licence not active"), may carry markup, and may be a whole
      // paragraph. Interpolating it raw is how the one screen that promised no jargon starts
      // showing `<LINEERROR>` to a business owner.
      return {
        screen: 'findTally',
        phase: 'problem',
        message: `Tally reported a problem: ${cleanFault(f.message)}`,
        action: tryAgain,
      };
    case 'timeout':
      return {
        screen: 'findTally',
        phase: 'problem',
        message: 'Tally did not answer in time. It may be busy, or waiting on a dialog box that is open on screen.',
        action: tryAgain,
      };
    case 'http_status':
    case 'network':
      return {
        screen: 'findTally',
        phase: 'problem',
        message: 'We could not reach Tally on this computer. Check that Tally is open, then try again.',
        action: tryAgain,
      };
  }
}

/**
 * Make Tally's fault text safe to show: one line, no markup, terminated, and short enough to
 * fit on a button-height banner.
 */
function cleanFault(raw: string): string {
  const flat = raw
    .replace(/<[^>]*>/g, ' ')
    // Anything still bracketed is a serialized structure, not prose.
    .replace(/[{}[\]<>]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (flat.length === 0) return 'no details were given.';
  const clipped = flat.length > 120 ? `${flat.slice(0, 117).trimEnd()}…` : flat;
  return /[.!?…]$/.test(clipped) ? clipped : `${clipped}.`;
}

/**
 * Any thrown thing -> one sentence and one action.
 *
 * `VercelError` messages are already written for this reader, so they pass through. EVERYTHING
 * ELSE — a TypeError, a socket reset, a JSON parse failure — collapses to one generic
 * sentence. Echoing `String(error)` here is how "TypeError: Cannot read properties of
 * undefined (reading 'store')" ends up in a screenshot attached to a support ticket.
 */
export function describeProvisionFailure(error: unknown): { message: string; action: WizardAction } {
  if (error instanceof VercelError) {
    return { message: error.message, action: actionForVercelError(error) };
  }
  return {
    message: 'Something went wrong while setting up your dashboard. Nothing was lost — you can try again.',
    action: { kind: 'retry_provision', label: 'Try again' },
  };
}

function actionForVercelError(e: VercelError): WizardAction {
  if (e.step === 'await_neon_install') {
    return { kind: 'open_neon', label: 'Open the Neon page', url: NEON_URL };
  }
  switch (e.status) {
    case 401:
    case 403:
      return { kind: 'paste_new_token', label: 'Paste a new token' };
    case 402:
      return { kind: 'open_vercel_billing', label: 'Open Vercel billing', url: VERCEL_BILLING_URL };
    case 409:
      return { kind: 'choose_another_name', label: 'Choose another name' };
    default:
      return { kind: 'retry_provision', label: 'Try again' };
  }
}

// ---------------------------------------------------------------- the machine

/**
 * The transition function.
 *
 * TOTAL AND PURE. An event that makes no sense in the current state returns the state
 * unchanged rather than throwing — a wizard that crashes because a stale click arrived during
 * an async provision is a worse outcome than a click that does nothing.
 */
export function next(state: WizardState, event: WizardEvent): WizardState {
  switch (state.screen) {
    case 'findTally':
      return nextFindTally(state, event);
    case 'connectCloud':
      return nextConnectCloud(state, event);
    case 'setPassphrase':
      return nextSetPassphrase(state, event);
    case 'done':
      // Terminal. Setup does not un-happen.
      return state;
  }
}

function nextFindTally(
  state: Extract<WizardState, { screen: 'findTally' }>,
  event: WizardEvent,
): WizardState {
  switch (event.type) {
    case 'probe_started':
      return { screen: 'findTally', phase: 'probing' };

    case 'probe_succeeded': {
      if (event.companies.length === 0) {
        // Tally answered but has nothing to offer. Same shape as no_company_open, because to
        // the owner it is the same situation.
        return describeTally({ kind: 'no_company_open' });
      }
      return {
        screen: 'findTally',
        phase: 'ready',
        companies: event.companies,
        // One company is the overwhelmingly common case: pre-select it so the owner clicks
        // Continue rather than being asked a question with one possible answer.
        selectedGuid: event.companies.length === 1 ? event.companies[0]!.guid : undefined,
      };
    }

    case 'probe_failed':
      return describeTally(event.failure);

    case 'select_company': {
      if (state.phase !== 'ready') return state;
      if (!state.companies.some((c) => c.guid === event.guid)) return state;
      return { ...state, selectedGuid: event.guid };
    }

    case 'retry':
      if (state.phase === 'ready') return state;
      return { screen: 'findTally', phase: 'probing' };

    case 'continue': {
      if (state.phase !== 'ready') return state;
      const company = state.companies.find((c) => c.guid === state.selectedGuid);
      if (!company) return state;
      // Entering the cloud screen at `awaitIdentity`, NOT `awaitToken`. This is the ordering
      // constraint from the header, expressed as a state rather than a comment.
      return { screen: 'connectCloud', phase: 'awaitIdentity', company };
    }

    default:
      return state;
  }
}

function nextConnectCloud(
  state: Extract<WizardState, { screen: 'connectCloud' }>,
  event: WizardEvent,
): WizardState {
  switch (event.type) {
    case 'identity_ready': {
      if (state.phase !== 'awaitIdentity') return state;
      return {
        screen: 'connectCloud',
        phase: 'awaitToken',
        company: state.company,
        identityPublicKey: event.identityPublicKey,
      };
    }

    case 'token_pasted': {
      // The gate. A token pasted before the keypair exists goes nowhere, so IDENTITY_PUBKEY
      // can never be absent when `provision()` sets it.
      if (state.phase !== 'awaitToken') return state;
      if (event.token.trim().length === 0) return state;
      return {
        screen: 'connectCloud',
        phase: 'provisioning',
        company: state.company,
        identityPublicKey: state.identityPublicKey,
        step: 'verify_token',
        message: 'Checking your Vercel account…',
      };
    }

    case 'provision_event': {
      if (state.phase !== 'provisioning' && state.phase !== 'needsHuman') return state;
      const e = event.event;
      switch (e.kind) {
        case 'step':
          return {
            screen: 'connectCloud',
            phase: 'provisioning',
            company: state.company,
            identityPublicKey: state.identityPublicKey,
            step: e.step,
            message: e.message,
          };
        case 'needs_human':
          // The one thing no API can do for them: accept Neon's terms. Guided, not blamed.
          return {
            screen: 'connectCloud',
            phase: 'needsHuman',
            company: state.company,
            identityPublicKey: state.identityPublicKey,
            message: e.message,
            action: { kind: 'open_neon', label: 'Open the Neon page', url: e.url },
          };
        case 'waiting':
          if (state.phase === 'needsHuman') return state;
          return { ...state, message: e.message };
      }
      return state;
    }

    case 'provision_failed': {
      if (state.phase !== 'provisioning' && state.phase !== 'needsHuman') return state;
      const { message, action } = describeProvisionFailure(event.error);
      return {
        screen: 'connectCloud',
        phase: 'problem',
        company: state.company,
        identityPublicKey: state.identityPublicKey,
        message,
        action,
      };
    }

    case 'provision_succeeded': {
      if (state.phase !== 'provisioning' && state.phase !== 'needsHuman') return state;
      return {
        screen: 'setPassphrase',
        phase: 'entry',
        ctx: {
          company: state.company,
          identityPublicKey: state.identityPublicKey,
          projectId: event.projectId,
          deploymentUrl: event.deploymentUrl,
        },
      };
    }

    case 'retry': {
      if (state.phase !== 'problem') return state;
      // Back to the paste box, keeping the identity. Regenerating the keypair on every retry
      // would be a quiet disaster: the half-provisioned project would hold a dead
      // IDENTITY_PUBKEY and every upload to it would be unreadable forever.
      if (state.identityPublicKey === undefined) {
        return { screen: 'connectCloud', phase: 'awaitIdentity', company: state.company };
      }
      return {
        screen: 'connectCloud',
        phase: 'awaitToken',
        company: state.company,
        identityPublicKey: state.identityPublicKey,
      };
    }

    default:
      return state;
  }
}

function nextSetPassphrase(
  state: Extract<WizardState, { screen: 'setPassphrase' }>,
  event: WizardEvent,
): WizardState {
  switch (event.type) {
    case 'passphrase_submitted': {
      if (state.phase !== 'entry' && state.phase !== 'problem') return state;
      const problem = checkPassphrase(event.passphrase, event.confirm);
      if (problem) {
        return {
          screen: 'setPassphrase',
          phase: 'problem',
          ctx: state.ctx,
          message: problem,
          action: { kind: 'choose_another_passphrase', label: 'Try another passphrase' },
        };
      }
      // The driver now wraps idSK under BOTH the passphrase and a fresh recovery key. Both, or
      // neither — a passphrase-only wrap is a key with no second door.
      return { screen: 'setPassphrase', phase: 'wrapping', ctx: state.ctx };
    }

    case 'sheet_ready': {
      if (state.phase !== 'wrapping') return state;
      return { screen: 'setPassphrase', phase: 'sheet', ctx: state.ctx, sheet: event.sheet };
    }

    case 'wrap_failed': {
      if (state.phase !== 'wrapping') return state;
      return {
        screen: 'setPassphrase',
        phase: 'problem',
        ctx: state.ctx,
        message: 'We could not finish protecting your data. Nothing was saved — please try again.',
        action: { kind: 'choose_another_passphrase', label: 'Try again' },
      };
    }

    case 'print_failed': {
      if (state.phase !== 'sheet') return state;
      // Annotate the sheet; do NOT leave it. See `printProblem` on the state for why leaving was
      // a permanent dead end. The owner keeps the words, the QR, "Print again" AND "Continue".
      return {
        ...state,
        printProblem:
          'We could not print your recovery sheet. Check the printer and print it again — ' +
          'or write the words down from this screen.',
      };
    }

    case 'printed':
      // Note what this does NOT do: it does not advance. Printing is not proof of anything —
      // the printer may have been out of toner. Only the words the owner reads BACK off the
      // paper prove the paper exists and is legible.
      //
      // It DOES clear a previous failure's note: a stale "we could not print" sitting under a
      // sheet that has just printed is its own small lie.
      //
      // The key is DELETED rather than set to `undefined`: `exactOptionalPropertyTypes` is on, so
      // `printProblem: undefined` is not the same type as an absent `printProblem`.
      if (state.phase !== 'sheet' || state.printProblem === undefined) return state;
      {
        const { printProblem: _cleared, ...withoutNote } = state;
        return withoutNote;
      }

    case 'continue': {
      if (state.phase !== 'sheet') return state;
      return {
        screen: 'setPassphrase',
        phase: 'verify',
        ctx: state.ctx,
        sheet: state.sheet,
        positions: [...VERIFY_WORD_POSITIONS],
        attempts: 0,
        message: undefined,
      };
    }

    case 'verify_submitted': {
      // THE GATE. This is the only edge in the entire machine that reaches `done`, and it is
      // guarded by the sheet's own words. There is no 'skip' event, and adding one would mean
      // adding it to the exported union in front of a reviewer.
      //
      // Why forced: an unverified recovery key is WORSE than no recovery key. It manufactures
      // false confidence. The owner files the paper away believing they are covered, and finds
      // out eight months later that the printer ate it — at the exact moment they have no
      // other way in. Two words is a tax people will actually pay.
      if (state.phase !== 'verify') return state;
      const ok = makeVerificationChallenge(state.sheet).check(event.answers);
      if (ok) {
        return {
          screen: 'done',
          company: state.ctx.company,
          deploymentUrl: state.ctx.deploymentUrl,
        };
      }
      return {
        ...state,
        attempts: state.attempts + 1,
        // No lockout, no scolding, and no hint. This is a typo gate, not an auth boundary —
        // the person holding the sheet is the owner, and the sheet is right there.
        message:
          state.attempts === 0
            ? 'Those words do not match the sheet. Check the numbers on the left and try again.'
            : 'Still not matching. Read the two numbered words straight off the printed sheet.',
      };
    }

    case 'retry': {
      if (state.phase !== 'problem') return state;
      return { screen: 'setPassphrase', phase: 'entry', ctx: state.ctx };
    }

    default:
      return state;
  }
}

/** Returns a sentence when the passphrase is unusable, or undefined when it is fine. */
export function checkPassphrase(passphrase: string, confirm: string): string | undefined {
  if (passphrase !== confirm) {
    return 'The two passphrases are not the same. Type the same one in both boxes.';
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    return `Your passphrase is too short. Use at least ${MIN_PASSPHRASE_LENGTH} characters — a short sentence you will remember works well.`;
  }
  return undefined;
}

// ---------------------------------------------------------------- inspection

/** The single action offered, if any. Never a list — see `WizardAction`. */
export function actionOf(state: WizardState): WizardAction | undefined {
  if (state.screen === 'done') return undefined;
  return 'action' in state ? state.action : undefined;
}

/** The phase within the current screen, or undefined once setup is done. */
export function phaseOf(state: WizardState): string | undefined {
  return state.screen === 'done' ? undefined : state.phase;
}

/** A genuine failure. `waiting` and `needsHuman` are NOT failures, and must not render as such. */
export function isProblem(state: WizardState): boolean {
  return state.screen !== 'done' && state.phase === 'problem';
}

/** Anything the owner is shown as prose. Used by tests to police the wording. */
export function messageOf(state: WizardState): string | undefined {
  if (state.screen === 'done') return undefined;
  return 'message' in state ? state.message : undefined;
}

export function isComplete(state: WizardState): boolean {
  return state.screen === 'done';
}
