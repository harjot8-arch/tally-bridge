import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { generateIdentity, generateRecoveryKey, sodiumReady, wrapIdentity } from '@tally-bridge/crypto';
import { SCHEMA_VERSION } from '@tally-bridge/core';
import { ROUTES, signRequest } from '@tally-bridge/protocol';
import {
  VercelClient,
  provision,
  safeProjectName,
  type DeployFile,
} from '../onboarding/vercel.ts';
import { initialRoster } from '../onboarding/pairing.ts';
import { makeRecoverySheet, type RecoverySheet } from '../onboarding/recovery.ts';
import type { Keystore } from './keystore.ts';
import { HumanError } from './errors.ts';
import { probeCompanyList, type ProbeTransport } from './detect.ts';
import type { CloudOutcome, GeneratedIdentity, WizardHostEffects } from './wizard-host.ts';

/**
 * The real effects behind the wizard host. Everything here either exists elsewhere in this repo
 * and is composed (probe, provision, wrap) or is small and owned here (minting ids, the deploy
 * bundle loader, device enrolment). Electron-specific work — the QR raster and the print window
 * — is injected by index.ts, so this module stays testable under plain Node.
 */

export interface WizardEffectDeps {
  transport: ProbeTransport;
  keystore: Keystore;
  /** PNG data URL for the recovery QR. Electron-free callers inject `qrcode` here. */
  qrPngDataUrl: (text: string) => Promise<string>;
  /** Render + print the sheet HTML. index.ts implements with a hidden window + print dialog. */
  printHtml: (html: string, qrDataUrl: string) => Promise<void>;
  /**
   * Diagnostic sink for cloud setup, written to a local file (never the network, never the UI).
   * The owner-facing failure message is deliberately generic; this is where the real step +
   * Vercel status + message go so a broken deployment can actually be debugged.
   */
  debugLog?: ((line: string) => void) | undefined;
  fetchImpl?: typeof fetch | undefined;
  now?: (() => number) | undefined;
  /**
   * The dashboard/server files to deploy to the client's Vercel, or throw a HumanError when this
   * build does not carry them. See `loadDeployBundle`.
   */
  loadDeployFiles?: (() => DeployFile[]) | undefined;
}

/**
 * Where the server bundle lives: produced by `npm run build:deploy-bundle`
 * (scripts/build-deploy-bundle.ts) and carried into packaged builds by electron-builder.
 */
export const DEPLOY_BUNDLE_DIR = join(import.meta.dirname, '../../deploy-bundle');

/**
 * Read the deployable server files from disk into Vercel's content-addressed shape.
 *
 * The paths are relative to the bundle root, so they arrive at Vercel WITH their
 * `.vercel/output/` prefix — which is what a `?prebuilt=1` deployment requires on the wire.
 *
 * HONESTY OVER HOPE: a missing directory throws a HumanError and the wizard shows one sentence
 * with a retry. So does a directory that exists but is not a deployable bundle — no
 * `.vercel/output/config.json`, or no function code. Without that check, a half-written or
 * clobbered bundle would deploy "successfully" into a dashboard that serves nothing, with a
 * green tick over it; the owner cannot diagnose that, and neither can support.
 */
export function loadDeployBundle(dir: string = DEPLOY_BUNDLE_DIR): DeployFile[] {
  let names: string[];
  try {
    names = walk(dir);
  } catch {
    throw new HumanError(
      'This copy of Tally Bridge is missing its dashboard files, so it cannot set up the cloud dashboard. Please reinstall the app.',
    );
  }
  const files = names.map((abs) => {
    const data = new Uint8Array(readFileSync(abs));
    return {
      // Vercel wants POSIX paths regardless of host OS.
      file: relative(dir, abs).split(sep).join('/'),
      sha: createHash('sha1').update(data).digest('hex'),
      size: data.byteLength,
      data,
    };
  });
  const hasConfig = files.some((f) => f.file === '.vercel/output/config.json');
  const hasFunction = files.some(
    (f) => f.file.startsWith('.vercel/output/functions/') && f.file.endsWith('.func/index.js'),
  );
  if (!hasConfig || !hasFunction) {
    throw new HumanError(
      'This copy of Tally Bridge is missing its dashboard files, so it cannot set up the cloud dashboard. Please reinstall the app.',
    );
  }
  return files;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const hex = (bytes: number): string => randomBytes(bytes).toString('hex');

export function createWizardEffects(deps: WizardEffectDeps): WizardHostEffects {
  const fetchImpl = deps.fetchImpl ?? globalThis.fetch;
  const now = deps.now ?? (() => Date.now());
  const loadFiles = deps.loadDeployFiles ?? (() => loadDeployBundle());

  /**
   * Device identity for THIS setup run, minted once and reused across retries.
   *
   * The reuse is load-bearing, not a cache: enrolment consumes the one-shot BOOTSTRAP_SECRET,
   * so a wrap that fails AFTER enrolment must retry with the SAME device — a fresh keypair
   * would find the bootstrap door already closed and brick the setup. `registered` records that
   * the door was used by us, so the retry skips the knock.
   */
  let device: { deviceId: string; publicKey: Uint8Array; secretKey: Uint8Array } | undefined;
  let registered = false;

  return {
    async probeCompanies() {
      const res = await probeCompanyList(deps.transport);
      if (!res.ok) return res;
      return { ok: true, companies: res.companies.map((c) => ({ guid: c.guid, name: c.name })) };
    },

    async generateIdentity(): Promise<GeneratedIdentity> {
      const id = await generateIdentity();
      return {
        publicKey: id.publicKey,
        secretKey: id.secretKey,
        publicKeyB64: Buffer.from(id.publicKey).toString('base64'),
      };
    },

    async provision(input, onEvent): Promise<CloudOutcome> {
      // Minted HERE, on the machine that owns the deployment — provisioning and trust-bootstrap
      // are the same step, so no out-of-band channel ever exists to intercept.
      const tenantId = `tn_${hex(8)}`;
      const bootstrapSecret = randomBytes(32).toString('base64');

      const dbg = deps.debugLog ?? (() => {});
      // Mirror every provisioning event to the diagnostic file, and tee it to onEvent so the UI
      // still updates. This is the ONLY place the failing step is recorded — the wizard collapses
      // it to a generic sentence for the owner.
      const tee = (e: Parameters<typeof onEvent>[0]) => {
        dbg(`provision ${JSON.stringify(e)}`);
        onEvent(e);
      };

      const client = new VercelClient({
        token: input.token,
        fetch: fetchImpl,
        sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
        now,
        log: tee,
      });

      let result;
      try {
        result = await provision(
          client,
          {
            projectName: safeProjectName(input.company.name, hex(2)),
            tenantId,
            identityPublicKey: input.identityPublicKeyB64,
            bootstrapSecret,
            schemaVersion: String(SCHEMA_VERSION),
            files: loadFiles(),
          },
          { pollMs: 3_000, installTimeoutMs: 10 * 60_000, dbTimeoutMs: 5 * 60_000, deployTimeoutMs: 10 * 60_000 },
          tee,
        );
      } catch (e) {
        // Record the ACTUAL failure — step, HTTP status, Vercel's own message — then rethrow so
        // the owner still sees the calm generic screen. A `VercelError` carries all three.
        const err = e as { step?: string; status?: number; message?: string };
        dbg(`provision FAILED step=${err.step ?? '?'} status=${err.status ?? '?'} message=${err.message ?? String(e)}`);
        throw e;
      }

      const deploymentUrl = result.deploymentUrl.startsWith('http')
        ? result.deploymentUrl
        : `https://${result.deploymentUrl}`;
      return { projectId: result.projectId, deploymentUrl, tenantId, bootstrapSecret };
    },

    /**
     * The commit. ORDER IS LOAD-BEARING:
     *
     *   1. wrap (pure crypto, no side effects worth keeping on failure)
     *   2. enrol the device with the server (consumes the one-shot bootstrap)
     *   3. upload the wrapped keys + login credential (behind the Ed25519 device door, so it
     *      needs the enrolment above to have happened)
     *   4. persist the keystore LAST
     *
     * The keystore write is what flips `isProvisioned()` and wakes the sync cycle, so it must
     * happen only when everything the cycle needs is true. Enrolment before persistence means a
     * crash in between leaves a registered device and an empty keystore — recoverable on retry
     * via the cached device above — while the reverse order would leave a syncing Bridge whose
     * every upload 401s.
     *
     * The upload sits BEFORE the keystore write for that same reasoning turned around: persist
     * first and a failed upload leaves a Bridge that syncs under a green tick while the server
     * has no wrapped key and no login credential — a web dashboard nobody can ever log in to,
     * with nothing on the Bridge's side ever looking wrong. Failing the whole step instead
     * lands on the wizard's problem screen, whose retry re-runs this function: the wrap mints
     * fresh blobs, the server upserts them per kind, and the uploaded pass wrap, the login
     * credential and the keystore's local copy all come from whichever single run finally
     * succeeds — a retry converges, it cannot interleave two runs.
     */
    async completeSetup(input): Promise<RecoverySheet> {
      const sodium = await sodiumReady();
      if (!device) {
        const kp = sodium.crypto_sign_keypair();
        device = { deviceId: `dev_${hex(8)}`, publicKey: kp.publicKey, secretKey: kp.privateKey };
      }

      const roster = initialRoster({ deviceId: device.deviceId, publicKey: device.publicKey });
      const recoveryKey = await generateRecoveryKey();
      let sheet: RecoverySheet;
      let passWrapJson: string;
      let uploadBodyJson: string;
      try {
        const wraps = await wrapIdentity(input.identity.secretKey, roster, {
          passphrase: input.passphrase,
          recoveryKey,
        });
        // The auth token's whole life: hashed, serialized, zeroed. The server stores only this
        // hash (login_credential) and compares it against SHA-256 of the token a browser
        // re-derives at login — from the SAME salt/params, because the server takes the
        // credential's kdf column from the pass blob's own kdf object in this same request
        // (the storeWrappedKeys contract in apps/server/src/auth.ts).
        const authTokenHash = createHash('sha256').update(wraps.authToken).digest('base64');
        wraps.authToken.fill(0);
        // pass + recovery, no device wrap (none is minted above). The server enforces that a
        // pass blob and an authTokenHash arrive together or not at all.
        uploadBodyJson = JSON.stringify({ keys: [wraps.pass, wraps.recovery], authTokenHash });
        passWrapJson = JSON.stringify(wraps.pass);
        sheet = makeRecoverySheet(recoveryKey, input.company.name, isoDate(now()));
      } finally {
        // The raw recovery key has done its job; the sheet carries it onward (that is the
        // sheet's purpose). Best-effort scrub of this copy.
        recoveryKey.fill(0);
      }

      if (!registered) {
        await registerDevice(fetchImpl, input.cloud, device);
        registered = true;
      }

      await putWrappedKeys(fetchImpl, input.cloud, device, uploadBodyJson);

      const ks = deps.keystore;
      ks.setDevice(device.deviceId, device.publicKey, device.secretKey);
      ks.setIdentityPublicKey(input.identity.publicKey);
      ks.setTenantId(input.cloud.tenantId);
      ks.setServerUrl(input.cloud.deploymentUrl);
      ks.setWrappedIdentityForPassphrase(passWrapJson);

      return sheet;
    },

    recoveryQr: (keyBase64) => deps.qrPngDataUrl(keyBase64),

    printSheet: async (sheet) => {
      const qr = await deps.qrPngDataUrl(sheet.keyBase64);
      // recoverySheetHtml validates the QR data URL shape and escapes every interpolation;
      // imported lazily to keep this module's import graph light for tests that never print.
      const { recoverySheetHtml } = await import('../onboarding/recovery.ts');
      await deps.printHtml(recoverySheetHtml(sheet, qr), qr);
    },
  };
}

/**
 * Enrol the device with the freshly deployed server.
 *
 * The path comes from the shared route table, and that is a fix rather than a tidy-up: it used
 * to be a bare `'/api/register'` literal here, mirroring the server's other routes by eye. This
 * is the FIRST request a new deployment ever receives, so a mismatch would strand the owner at
 * the last screen of setup — after they had already paid Vercel — with nothing to go on.
 *
 * Failures become HumanError sentences: this call runs inside the wrap step, whose machine-side
 * failure state already offers "try again", and the enrolment above is retry-safe.
 */
async function registerDevice(
  fetchImpl: typeof fetch,
  cloud: CloudOutcome,
  device: { deviceId: string; publicKey: Uint8Array },
): Promise<void> {
  let res: Response;
  try {
    res = await fetchImpl(new URL(ROUTES.register.path, cloud.deploymentUrl), {
      method: ROUTES.register.method,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        secret: cloud.bootstrapSecret,
        deviceId: device.deviceId,
        tenantId: cloud.tenantId,
        publicKey: Buffer.from(device.publicKey).toString('base64'),
        label: 'Tally PC',
      }),
    });
  } catch {
    throw new HumanError('We could not reach your new dashboard to finish setup. Check the internet connection and try again.');
  }
  try {
    await res.arrayBuffer();
  } catch {
    // Body unused; a truncated read changes nothing about the status.
  }
  if (!res.ok) {
    throw new HumanError('Your new dashboard did not accept this computer yet. Try again in a moment.');
  }
}

/**
 * Store the wrapped identity (pass + recovery) and the login credential on the server —
 * the write that makes the web dashboard's unlock possible at all.
 *
 * Signed with the device key in the same shape as /api/sync uploads (createUploader in
 * cycle.ts): the same bytes are signed and sent, and the path comes from the shared route table
 * because the path is INSIDE the signature — a literal drifting from the server's constant
 * would 401 with a correct signature over a correct body. This must run after `registerDevice`:
 * the endpoint sits behind the Ed25519 device door, and an unenrolled device is unknown to it.
 *
 * Failures become one HumanError sentence; completeSetup's ordering comment covers why a
 * failure here must abort setup before the keystore is written.
 */
async function putWrappedKeys(
  fetchImpl: typeof fetch,
  cloud: CloudOutcome,
  device: { deviceId: string; secretKey: Uint8Array },
  bodyJson: string,
): Promise<void> {
  const body = new TextEncoder().encode(bodyJson);
  const headers = await signRequest(
    {
      deviceId: device.deviceId,
      method: ROUTES.putWrappedKey.method,
      path: ROUTES.putWrappedKey.path,
      body,
    },
    device.secretKey,
  );

  let res: Response;
  try {
    res = await fetchImpl(new URL(ROUTES.putWrappedKey.path, cloud.deploymentUrl), {
      method: ROUTES.putWrappedKey.method,
      headers: { ...headers, 'content-type': 'application/json' },
      body,
    });
  } catch {
    throw new HumanError(
      'We could not reach your new dashboard to save its sign-in setup. Check the internet connection and try again.',
    );
  }
  try {
    await res.arrayBuffer();
  } catch {
    // Body unused; a truncated read changes nothing about the status.
  }
  if (!res.ok) {
    throw new HumanError(
      'Your new dashboard could not save its sign-in setup yet. Try again in a moment.',
    );
  }
}

function isoDate(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
