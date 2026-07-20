import type { TallyFailure } from '@tally-bridge/tally';
import {
  initialState,
  next,
  type TallyCompany,
  type WizardEvent,
  type WizardState,
} from '../onboarding/wizard.ts';
import type { ProvisionEvent } from '../onboarding/vercel.ts';
import type { RecoverySheet } from '../onboarding/recovery.ts';

/**
 * The main-process wizard host: the ONE authoritative copy of the setup state machine.
 *
 * The machine itself (`onboarding/wizard.ts`) is pure and already tested; this class owns an
 * instance of it and adds the two things a pure machine cannot have — SIDE EFFECTS and a TRUST
 * BOUNDARY — and the boundary is the part to read carefully:
 *
 * ------------------------------------------------------------------------------------------
 * THE RENDERER MAY ONLY SEND INTENT, NEVER FACT.
 * ------------------------------------------------------------------------------------------
 *
 * `WizardEvent` is one union, but its members have two very different authors. Events like
 * `continue`, `token_pasted`, `verify_submitted` are USER INTENT — things a person did on a
 * screen. Events like `probe_succeeded`, `identity_ready`, `provision_succeeded`, `sheet_ready`
 * are DRIVER FACTS — observations of the world that this class makes by running effects.
 *
 * If the renderer could send facts, the machine's own gates would be decoration: a compromised
 * renderer sends `provision_succeeded` to skip provisioning, then `sheet_ready` with a sheet IT
 * invented, then `verify_submitted` with answers read from its own sheet — and walks through the
 * "unskippable" verification gate without a recovery key ever being wrapped. The machine cannot
 * defend against this (to it, an event is an event), so the boundary is enforced HERE:
 * `sendFromRenderer` accepts exactly the intent events, rebuilt field-by-field from validated
 * input, and silently drops everything else. Driver facts enter only through `applyInternal`,
 * which nothing exposes over IPC.
 *
 * SECRETS THAT PASS THROUGH, AND THEIR LIFETIMES:
 *   - The Vercel token: lives in the closure of one provisioning run. Never in state, never
 *     stored, never logged.
 *   - The passphrase: lives in the closure of one wrap run; `wrapIdentity` derives from it and
 *     it is gone. Never in state.
 *   - The identity SECRET key: generated when the cloud screen is entered (the public half must
 *     exist before provisioning — see the machine's header), held here until wrapping, ZEROED
 *     when setup completes or the host is disposed. This is the one window in the product where
 *     idSK exists outside an unlocked session, and it is exactly as long as onboarding itself.
 *   - The recovery sheet: held for the sheet/verify screens (QR + print + the verify gate).
 *     What crosses to the renderer is REDACTED — `keyBase64` is blanked, because the renderer
 *     needs the words and the business name, and the raw key belongs only to the QR and the
 *     printed page, both rendered in the main process. (The words are key material too, but
 *     they ARE the screen — a sheet screen that does not show the words shows nothing.)
 *     Dropped when setup completes.
 */

export interface CloudOutcome {
  projectId: string;
  deploymentUrl: string;
  tenantId: string;
  /** One-shot server enrolment secret, minted during provisioning. Dropped after setup. */
  bootstrapSecret: string;
}

export interface GeneratedIdentity {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  publicKeyB64: string;
}

/** Everything the host asks the outside world to do. Injected: the host itself is Electron-free. */
export interface WizardHostEffects {
  probeCompanies(): Promise<
    { ok: true; companies: TallyCompany[] } | { ok: false; failure: TallyFailure }
  >;
  generateIdentity(): Promise<GeneratedIdentity>;
  provision(
    input: { token: string; company: TallyCompany; identityPublicKeyB64: string },
    onEvent: (e: ProvisionEvent) => void,
  ): Promise<CloudOutcome>;
  /**
   * Wrap the identity, enrol the device, persist the keystore — the whole commit of setup.
   * Must be safe to call again after a failure (a retry re-runs it with the same inputs).
   */
  completeSetup(input: {
    passphrase: string;
    company: TallyCompany;
    identity: GeneratedIdentity;
    cloud: CloudOutcome;
  }): Promise<RecoverySheet>;
  /** Raster (PNG) data URL of the recovery key QR. Never SVG — the renderer refuses it. */
  recoveryQr(keyBase64: string): Promise<string>;
  /** Render + print the sheet. Resolves when the dialog closes; rejects if printing failed. */
  printSheet(sheet: RecoverySheet): Promise<void>;
  /** Fires when setup lands on `done` — index.ts uses it to start the first sync immediately. */
  onDone?: (() => void) | undefined;
}

const MAX_GUID = 256;
const MAX_TOKEN = 4096;
const MAX_PASSPHRASE = 1024;
const MAX_ANSWERS = 8;
const MAX_ANSWER = 128;

/**
 * Validate ONE renderer event, rebuilding it field-by-field.
 *
 * Rebuilt rather than passed through: the input is `JSON`-shaped data from the renderer, and
 * forwarding the object it sent would forward every extra property it chose to attach. The
 * returned object contains exactly the fields the machine's union names, with checked types and
 * bounded lengths, or nothing.
 *
 * The `default` arm is the security boundary described in the header: every driver-fact type —
 * and every unknown type — falls through it and is dropped.
 */
export function validateRendererEvent(e: unknown): WizardEvent | undefined {
  if (typeof e !== 'object' || e === null || Array.isArray(e)) return undefined;
  const type = (e as { type?: unknown }).type;
  switch (type) {
    case 'retry':
    case 'continue':
    case 'printed':
      return { type };
    case 'print_failed':
      // The renderer's `error` is discarded, deliberately: the machine ignores it today, and a
      // renderer-authored object must not ride into main-process state waiting for a future
      // reader to trust it.
      return { type: 'print_failed', error: undefined };
    case 'select_company': {
      const guid = (e as { guid?: unknown }).guid;
      if (typeof guid !== 'string' || guid.length === 0 || guid.length > MAX_GUID) return undefined;
      return { type: 'select_company', guid };
    }
    case 'token_pasted': {
      const token = (e as { token?: unknown }).token;
      if (typeof token !== 'string' || token.length > MAX_TOKEN) return undefined;
      return { type: 'token_pasted', token };
    }
    case 'passphrase_submitted': {
      const p = (e as { passphrase?: unknown }).passphrase;
      const c = (e as { confirm?: unknown }).confirm;
      if (typeof p !== 'string' || p.length > MAX_PASSPHRASE) return undefined;
      if (typeof c !== 'string' || c.length > MAX_PASSPHRASE) return undefined;
      return { type: 'passphrase_submitted', passphrase: p, confirm: c };
    }
    case 'verify_submitted': {
      const answers = (e as { answers?: unknown }).answers;
      if (!Array.isArray(answers) || answers.length > MAX_ANSWERS) return undefined;
      const clean: string[] = [];
      for (const a of answers) {
        if (typeof a !== 'string' || a.length > MAX_ANSWER) return undefined;
        clean.push(a);
      }
      return { type: 'verify_submitted', answers: clean };
    }
    default:
      return undefined;
  }
}

/** What crosses IPC: the state with the raw recovery key blanked out. */
export function redactForRenderer(state: WizardState): WizardState {
  if (state.screen === 'setPassphrase' && (state.phase === 'sheet' || state.phase === 'verify')) {
    return { ...state, sheet: { ...state.sheet, keyBase64: '' } };
  }
  return state;
}

export class WizardHostMain {
  private readonly effects: WizardHostEffects;
  private state: WizardState = initialState();
  private readonly listeners = new Set<(s: WizardState) => void>();

  private identity: GeneratedIdentity | undefined;
  private cloud: CloudOutcome | undefined;
  private sheet: RecoverySheet | undefined;

  private probeInFlight = false;
  private identityInFlight = false;
  private provisionInFlight = false;
  private wrapInFlight = false;

  constructor(effects: WizardHostEffects) {
    this.effects = effects;
  }

  /** The current state, redacted for the renderer. Also nudges any due side effect. */
  getState(): WizardState {
    this.kick();
    return redactForRenderer(this.state);
  }

  subscribe(cb: (s: WizardState) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /**
   * The IPC entry point. Invalid or driver-only events change NOTHING and return the current
   * state — the renderer is a view, and a view that sends garbage gets the truth back.
   */
  async sendFromRenderer(raw: unknown): Promise<WizardState> {
    const event = validateRendererEvent(raw);
    if (!event) return redactForRenderer(this.state);

    this.applyInternal(event);

    // Two intents carry a secret the machine deliberately does not store; if the machine
    // accepted them (i.e. actually transitioned into the working phase), the driver run starts
    // here, with the secret scoped to this call.
    if (event.type === 'token_pasted' && this.is('connectCloud', 'provisioning')) {
      void this.runProvision(event.token);
    }
    if (event.type === 'passphrase_submitted' && this.is('setPassphrase', 'wrapping')) {
      void this.runWrap(event.passphrase);
    }

    return redactForRenderer(this.state);
  }

  /** QR for the CURRENT sheet. Only meaningful while the sheet/verify screen is up. */
  async recoveryQr(): Promise<string> {
    if (!this.sheet) throw new Error('no recovery sheet on screen');
    return this.effects.recoveryQr(this.sheet.keyBase64);
  }

  async printRecoverySheet(): Promise<void> {
    if (!this.sheet) throw new Error('no recovery sheet on screen');
    await this.effects.printSheet(this.sheet);
  }

  /** Zero and drop everything sensitive. Called on quit and when setup completes. */
  dispose(): void {
    if (this.identity) this.identity.secretKey.fill(0);
    this.identity = undefined;
    this.sheet = undefined;
    this.cloud = undefined;
  }

  // ---------------------------------------------------------------- internals

  private is(screen: WizardState['screen'], phase: string): boolean {
    return this.state.screen === screen && 'phase' in this.state && this.state.phase === phase;
  }

  /** Driver facts enter here. NOT reachable from IPC. */
  private applyInternal(event: WizardEvent): void {
    const before = this.state;
    this.state = next(this.state, event);
    if (this.state === before) return;

    if (this.state.screen === 'done') {
      // Setup is committed: the identity secret's onboarding window closes NOW, not at quit.
      this.dispose();
      this.effects.onDone?.();
    }

    const out = redactForRenderer(this.state);
    for (const cb of this.listeners) {
      try {
        cb(out);
      } catch (e) {
        console.error('[bridge] wizard listener threw:', e);
      }
    }
    this.kick();
  }

  /** Start whatever effect the current state is waiting on. Idempotent per in-flight run. */
  private kick(): void {
    if (this.is('findTally', 'probing')) void this.runProbe();
    if (this.is('connectCloud', 'awaitIdentity')) void this.runIdentity();
  }

  private async runProbe(): Promise<void> {
    if (this.probeInFlight) return;
    this.probeInFlight = true;
    try {
      const res = await this.effects.probeCompanies();
      this.applyInternal(
        res.ok
          ? { type: 'probe_succeeded', companies: res.companies }
          : { type: 'probe_failed', failure: res.failure },
      );
    } catch (e) {
      // The effect should not throw, but a throw must surface as a screen, not a rejection.
      console.error('[bridge] wizard probe failed unexpectedly:', e);
      this.applyInternal({ type: 'probe_failed', failure: { kind: 'network', message: '' } });
    } finally {
      this.probeInFlight = false;
    }
  }

  private async runIdentity(): Promise<void> {
    if (this.identityInFlight) return;
    // NEVER REGENERATE. A problem-screen retry comes back through awaitIdentity only when the
    // first generation never happened; once a keypair exists it is THE keypair — a regenerated
    // one would orphan a half-provisioned project whose IDENTITY_PUBKEY nothing can ever read.
    if (this.identity) {
      this.applyInternal({ type: 'identity_ready', identityPublicKey: this.identity.publicKeyB64 });
      return;
    }
    this.identityInFlight = true;
    try {
      this.identity = await this.effects.generateIdentity();
      this.applyInternal({ type: 'identity_ready', identityPublicKey: this.identity.publicKeyB64 });
    } catch (e) {
      console.error('[bridge] identity generation failed:', e);
      // Leave the machine in awaitIdentity; the next getState/kick retries.
    } finally {
      this.identityInFlight = false;
    }
  }

  private async runProvision(token: string): Promise<void> {
    if (this.provisionInFlight) return;
    if (this.state.screen !== 'connectCloud' || this.state.phase !== 'provisioning') return;
    const { company, identityPublicKey } = this.state;
    if (!this.identity || this.identity.publicKeyB64 !== identityPublicKey) {
      // State claims an identity this host never made. Refuse to provision against it.
      this.applyInternal({ type: 'provision_failed', error: new Error('identity mismatch') });
      return;
    }
    this.provisionInFlight = true;
    try {
      const outcome = await this.effects.provision(
        { token, company, identityPublicKeyB64: identityPublicKey },
        (e) => this.applyInternal({ type: 'provision_event', event: e }),
      );
      this.cloud = outcome;
      this.applyInternal({
        type: 'provision_succeeded',
        projectId: outcome.projectId,
        deploymentUrl: outcome.deploymentUrl,
      });
    } catch (e) {
      this.applyInternal({ type: 'provision_failed', error: e });
    } finally {
      this.provisionInFlight = false;
    }
  }

  private async runWrap(passphrase: string): Promise<void> {
    if (this.wrapInFlight) return;
    if (this.state.screen !== 'setPassphrase' || this.state.phase !== 'wrapping') return;
    const ctx = this.state.ctx;
    if (!this.identity || !this.cloud) {
      // Cannot happen through the machine's own transitions; refuse rather than invent.
      this.applyInternal({ type: 'wrap_failed', error: new Error('setup context missing') });
      return;
    }
    this.wrapInFlight = true;
    try {
      const sheet = await this.effects.completeSetup({
        passphrase,
        company: ctx.company,
        identity: this.identity,
        cloud: this.cloud,
      });
      this.sheet = sheet;
      this.applyInternal({ type: 'sheet_ready', sheet });
    } catch (e) {
      this.applyInternal({ type: 'wrap_failed', error: e });
    } finally {
      this.wrapInFlight = false;
    }
  }
}
