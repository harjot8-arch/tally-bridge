/**
 * Vercel provisioning.
 *
 * WHAT IS AND IS NOT AUTOMATABLE — stated up front, because the product brief assumed more.
 *
 * NOT automatable, and no amount of engineering changes it:
 *   - Vercel signup. Captcha, email verification, ToS acceptance. Automating account creation
 *     on a user's behalf violates Vercel's ToS and would get the CLIENT'S account banned.
 *   - Marketplace terms acceptance. There is NO REST endpoint. Vercel's own CLI docs say it
 *     "requires an interactive terminal and human confirmation" — it is a contract between the
 *     client and Neon, and Vercel deliberately will not let a third-party app click through it.
 *   - Minting a PAT. No API creates one.
 *
 * Everything else IS automatable, so the flow reduces to ONE PASTE and ONE CLICK:
 *   paste a token, click "Install" on the Neon page. We poll for the result and do the rest.
 *
 * The deploy uses INLINE FILES (`POST /v13/deployments` with `files`), which means the client
 * needs NO GITHUB ACCOUNT. For a non-technical business owner that is not friction removed, it
 * is a wall removed — the Deploy Button path would have forced a GitHub signup and left the
 * dashboard source in a repo they can accidentally delete.
 *
 * OPEN QUESTION (Spike B): whether a Vercel OAuth token can call POST /v11/projects at all.
 * The published scope list has no explicit "create project" scope, and OAuth tokens have
 * historically been scoped to GRANTED projects rather than the account. If OAuth cannot create
 * projects, the PAT paste below is not a fallback — it is the design. This module works either
 * way because it only ever needs a bearer token.
 */

export interface VercelClientOptions {
  token: string;
  teamId?: string | undefined;
  fetch: typeof globalThis.fetch;
  /** Injected so tests do not sleep. */
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  log?: (e: ProvisionEvent) => void;
}

export type ProvisionEvent =
  | { kind: 'step'; step: ProvisionStep; message: string }
  | { kind: 'needs_human'; action: 'install_neon'; url: string; message: string }
  | { kind: 'waiting'; message: string };

export type ProvisionStep =
  | 'verify_token'
  | 'resolve_team'
  | 'check_neon'
  | 'await_neon_install'
  | 'create_project'
  | 'provision_database'
  | 'connect_database'
  | 'set_env'
  | 'upload_files'
  | 'deploy'
  | 'await_ready'
  | 'done';

export class VercelError extends Error {
  readonly status: number;
  readonly step: ProvisionStep;
  /** True when the owner can fix this themselves — surfaced as an action, not an error code. */
  readonly userActionable: boolean;
  /**
   * Vercel's RAW response body, for diagnostics only. Never shown to the owner (the `message` is
   * the calm sentence), but written to the local setup log so an API-drift failure names itself
   * instead of hiding behind "would not accept that request".
   */
  readonly detail: string | undefined;

  constructor(
    step: ProvisionStep,
    status: number,
    message: string,
    userActionable = false,
    detail?: string,
  ) {
    super(message);
    this.name = 'VercelError';
    this.status = status;
    this.step = step;
    this.userActionable = userActionable;
    this.detail = detail;
  }
}

const API = 'https://api.vercel.com';

/**
 * The Neon region the dashboard database is created in.
 *
 * Vercel's Neon integration requires this on `provision_database`. Singapore (`aws-ap-southeast-1`)
 * is the closest first-class Neon region to India and is available on Neon's free tier. The data
 * is small and encrypted, so region is a latency choice, not a correctness one — if a future
 * Vercel/Neon build rejects it, the setup log names the region error and this is the one line to
 * change.
 */
export const NEON_REGION = 'aws-ap-southeast-1';

export interface DeployFile {
  /** Path inside the deployment, e.g. `.next/routes-manifest.json`. */
  file: string;
  /** sha1 of the contents, hex. Vercel is content-addressed and dedupes across deploys. */
  sha: string;
  size: number;
  data: Uint8Array;
}

export class VercelClient {
  private readonly o: VercelClientOptions;

  constructor(o: VercelClientOptions) {
    this.o = o;
  }

  private qs(extra: Record<string, string> = {}): string {
    const p = new URLSearchParams(extra);
    if (this.o.teamId) p.set('teamId', this.o.teamId);
    const s = p.toString();
    return s ? `?${s}` : '';
  }

  private async call<T>(
    step: ProvisionStep,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const res = await this.o.fetch(`${API}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.o.token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      // Keep the raw body as `detail` (clipped) so the setup log can name the real reason —
      // `method path` included so an endpoint that Vercel has since moved is obvious. The bearer
      // token must NEVER appear in any error surface, so scrub it before the body is stored.
      const raw = `${method} ${path} -> ${text.slice(0, 800)}`;
      const detail = this.o.token ? raw.split(this.o.token).join('[redacted-token]') : raw;
      throw new VercelError(
        step,
        res.status,
        describeVercelError(res.status, text),
        isActionable(res.status),
        detail,
      );
    }
    // Some endpoints 204 with no body.
    const text = await res.text();
    return (text ? JSON.parse(text) : {}) as T;
  }

  // ------------------------------------------------------------------ token / team

  async verifyToken(): Promise<{ username: string }> {
    const r = await this.call<{ user?: { username?: string } }>('verify_token', 'GET', '/v2/user');
    return { username: r.user?.username ?? 'unknown' };
  }

  async resolveTeam(): Promise<string | undefined> {
    // A personal account has no team, and that is fine — teamId is simply omitted everywhere.
    const r = await this.call<{ teams?: Array<{ id: string; name: string }> }>(
      'resolve_team',
      'GET',
      '/v2/teams',
    );
    return r.teams?.[0]?.id;
  }

  // ------------------------------------------------------------------ neon integration

  /**
   * Find the Neon integration configuration.
   *
   * The `icfg_*` id only exists AFTER a human has installed Neon and accepted its terms, which
   * is the one step we cannot do for them.
   */
  async findNeonConfiguration(): Promise<string | undefined> {
    const r = await this.call<Array<{ id: string; slug?: string }>>(
      'check_neon',
      'GET',
      `/v1/integrations/configurations${this.qs({ view: 'account' })}`,
    );
    const list = Array.isArray(r) ? r : [];
    return list.find((c) => c.slug === 'neon' && c.id.startsWith('icfg_'))?.id;
  }

  /**
   * Wait for the human to click Install.
   *
   * This is what turns the one unavoidable manual step into a guided ~20 seconds: the app opens
   * the page, says "click Install, then come back", and watches. The owner never has to
   * navigate back or tell us they are done.
   */
  async awaitNeonInstall(opts: { timeoutMs: number; pollMs: number }): Promise<string> {
    this.o.log?.({
      kind: 'needs_human',
      action: 'install_neon',
      url: 'https://vercel.com/marketplace/neon',
      message: 'Click "Install" on the Neon page, then come back here.',
    });

    const deadline = this.o.now() + opts.timeoutMs;
    for (;;) {
      const icfg = await this.findNeonConfiguration();
      if (icfg) return icfg;

      if (this.o.now() >= deadline) {
        throw new VercelError(
          'await_neon_install',
          0,
          'We did not see Neon installed on your Vercel account. Open the Neon page and click Install, then try again.',
          true,
        );
      }
      this.o.log?.({ kind: 'waiting', message: 'Waiting for Neon to be installed…' });
      await this.o.sleep(opts.pollMs);
    }
  }

  // ------------------------------------------------------------------ project

  async createProject(name: string): Promise<{ id: string; name: string }> {
    return this.call<{ id: string; name: string }>('create_project', 'POST', `/v11/projects${this.qs()}`, {
      name,
      // null = "Other". This used to say 'nextjs', from an era when the plan was a Next app.
      // What we deploy now is a prebuilt Build Output API bundle with no framework, and a
      // framework setting exists to configure BUILDS — which a prebuilt deploy never runs.
      // Claiming Next invites Vercel to expect Next's output shape.
      framework: null,
    });
  }

  /**
   * Turn OFF Vercel Deployment Protection (Vercel Authentication) for this project.
   *
   * New Vercel projects now enable "Vercel Authentication" by default, which puts EVERY route —
   * `/api/register`, the login page, the dashboard — behind a Vercel SSO login. That makes the
   * deployment unreachable by the Bridge AND by the owner's phone (confirmed by a live 401
   * "Protected deployment"). It must be off for the product to work at all.
   *
   * This does NOT weaken the security model: the server only ever serves ciphertext, every data
   * route requires the app's own session (209 server tests), and the numbers are opened in the
   * browser with the passphrase-derived key. Vercel's SSO would only block legitimate access, not
   * protect the data — the crypto already does that.
   */
  async disableDeploymentProtection(projectId: string): Promise<void> {
    await this.call('create_project', 'PATCH', `/v9/projects/${projectId}${this.qs()}`, {
      ssoProtection: null,
    });
  }

  /** Look a project up by name. `undefined` when it does not exist — a 404 is an answer here. */
  async findProject(name: string): Promise<{ id: string; name: string } | undefined> {
    try {
      return await this.call<{ id: string; name: string }>(
        'create_project',
        'GET',
        `/v9/projects/${encodeURIComponent(name)}${this.qs()}`,
      );
    } catch (e) {
      if (e instanceof VercelError && e.status === 404) return undefined;
      throw e;
    }
  }

  /**
   * Create the project, or adopt the one a previous attempt already created.
   *
   * THIS IS THE RETRY STORY, AND IT IS THE MOST LIKELY REAL FAILURE IN THIS FILE. Setup is a
   * multi-minute sequence of network calls run by a business owner on office wifi. It WILL die
   * halfway. When it dies after `createProject` — which is early, so most failures are after it —
   * the project exists, and the name is derived deterministically from the business name, so
   * every retry re-POSTs the same name and gets 409. Forever. The owner clicks "Try again" and
   * watches it fail identically each time, with an error blaming a name they never chose.
   *
   * A 409 on a name WE generated is therefore not a conflict — it is evidence of our own earlier
   * attempt, and the correct response is to adopt it and carry on. Every later step (provisionNeon,
   * connectDatabase, setEnv with upsert, uploadFile, deploy) is already idempotent or additive,
   * so adopting the project makes the whole flow resumable.
   *
   * If the lookup does NOT find it, the name genuinely belongs to something we cannot see, and
   * the honest 409 stands.
   */
  async ensureProject(name: string): Promise<{ id: string; name: string; adopted: boolean }> {
    try {
      const p = await this.createProject(name);
      return { ...p, adopted: false };
    } catch (e) {
      if (!(e instanceof VercelError) || e.status !== 409) throw e;
      const existing = await this.findProject(name);
      if (!existing) throw e;
      return { ...existing, adopted: true };
    }
  }

  // ------------------------------------------------------------------ database

  /**
   * Provision a Neon database.
   *
   * `billingPlanId` is deliberately OMITTED: Vercel then auto-discovers the free plan. Passing
   * a paid plan without a card on file returns 402, which must render as "add a card in
   * Vercel", never as a stack trace.
   */
  async provisionNeon(icfg: string, name: string): Promise<{ resourceId: string }> {
    const r = await this.call<{ store?: { id?: string; status?: string } }>(
      'provision_database',
      'POST',
      `/v1/storage/stores/integration/direct${this.qs()}`,
      {
        name,
        integrationConfigurationId: icfg,
        integrationProductIdOrSlug: 'neon',
        // Vercel added a required `metadata.region` to this endpoint after this was first
        // written (confirmed by a live 400: "metadata should have required property 'region'").
        // Singapore is the closest first-class Neon region to India and is on the free tier.
        metadata: { region: NEON_REGION },
      },
    );
    const id = r.store?.id;
    if (!id) {
      throw new VercelError('provision_database', 0, 'Vercel did not return a database id.');
    }
    return { resourceId: id };
  }

  /**
   * Wait for the database to be genuinely ready.
   *
   * `available` IS THE ONLY STATUS THAT MEANS READY. Connecting against `initializing` yields a
   * deployment that boots into a crash loop — which looks exactly like our bug, and is the kind
   * of thing that burns a day of support before anyone suspects the database.
   */
  async awaitDatabaseReady(resourceId: string, opts: { timeoutMs: number; pollMs: number }): Promise<void> {
    const deadline = this.o.now() + opts.timeoutMs;
    for (;;) {
      const r = await this.call<{ store?: { status?: string } }>(
        'provision_database',
        'GET',
        `/v1/storage/stores/${resourceId}${this.qs()}`,
      );
      const status = r.store?.status;
      if (status === 'available') return;
      if (status === 'error' || status === 'suspended') {
        throw new VercelError('provision_database', 0, `The database could not be created (status: ${status}).`);
      }
      if (this.o.now() >= deadline) {
        throw new VercelError('provision_database', 0, 'The database is taking too long to start.');
      }
      this.o.log?.({ kind: 'waiting', message: 'Waiting for the database to start…' });
      await this.o.sleep(opts.pollMs);
    }
  }

  /**
   * Connect the database to the project.
   *
   * Vercel injects DATABASE_URL itself, so THE APP NEVER HANDLES THE CREDENTIAL. That is worth
   * protecting: a connection string we never see is one we cannot log, leak, or store.
   */
  async connectDatabase(icfg: string, resourceId: string, projectId: string): Promise<void> {
    await this.call(
      'connect_database',
      'POST',
      `/v1/integrations/installations/${icfg}/resources/${resourceId}/connections${this.qs()}`,
      {
        projectId,
        envVarEnvironments: ['production'],
        makeEnvVarsSensitive: true,
      },
    );
  }

  // ------------------------------------------------------------------ env

  async setEnv(projectId: string, vars: Array<{ key: string; value: string; sensitive?: boolean }>): Promise<void> {
    await this.call(
      'set_env',
      'POST',
      `/v10/projects/${projectId}/env${this.qs({ upsert: 'true' })}`,
      vars.map((v) => ({
        key: v.key,
        value: v.value,
        type: v.sensitive ? 'sensitive' : 'encrypted',
        target: ['production'],
      })),
    );
  }

  // ------------------------------------------------------------------ deploy

  /** Upload a file. Content-addressed, so re-deploys only send what changed. */
  async uploadFile(f: DeployFile): Promise<void> {
    const res = await this.o.fetch(`${API}/v2/files`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.o.token}`,
        'Content-Type': 'application/octet-stream',
        'x-vercel-digest': f.sha,
        'Content-Length': String(f.size),
      },
      body: f.data as BodyInit,
    });
    if (!res.ok) {
      throw new VercelError('upload_files', res.status, 'We could not upload the dashboard files to Vercel.');
    }
  }

  /**
   * Deploy from pre-uploaded files — no git provider, therefore no GitHub account.
   *
   * `?prebuilt=1` tells Vercel the files ARE the build output (Build Output API v3, paths
   * keeping their `.vercel/output/` prefix) and no build should run. That signal is an
   * undocumented QUERY PARAMETER: it is what the official CLI sends
   * (vercel/vercel packages/client — query-string.ts appends it, deploy.ts sets it), and it is
   * definitively not in the body (`DeploymentOptions` has no such field), not a header, and not
   * `builds.json`.
   *
   * UNVERIFIED, deliberately: Vercel's API is closed-source, so whether `prebuilt=1` is
   * REQUIRED — versus the server also inferring prebuilt from `.vercel/output/config.json`
   * being present in the file list — cannot be proven from any source we can read. We send
   * exactly what the CLI sends and claim nothing more. The experiment that settles it: deploy
   * this same file list with and without the parameter under a real token and diff the results.
   */
  async deploy(projectName: string, files: DeployFile[]): Promise<{ id: string; url: string }> {
    return this.call<{ id: string; url: string }>(
      'deploy',
      'POST',
      `/v13/deployments${this.qs({ prebuilt: '1' })}`,
      {
        name: projectName,
        target: 'production',
        files: files.map((f) => ({ file: f.file, sha: f.sha, size: f.size })),
        // See createProject: this is a prebuilt bundle, not a framework build.
        projectSettings: { framework: null },
      },
    );
  }

  async awaitDeployReady(id: string, opts: { timeoutMs: number; pollMs: number }): Promise<string> {
    const deadline = this.o.now() + opts.timeoutMs;
    for (;;) {
      const r = await this.call<{ readyState?: string; url?: string }>(
        'await_ready',
        'GET',
        `/v13/deployments/${id}${this.qs()}`,
      );
      if (r.readyState === 'READY') return r.url ?? '';
      if (r.readyState === 'ERROR' || r.readyState === 'CANCELED') {
        throw new VercelError('await_ready', 0, 'The dashboard failed to build on Vercel.');
      }
      if (this.o.now() >= deadline) {
        throw new VercelError('await_ready', 0, 'The dashboard is taking too long to deploy.');
      }
      this.o.log?.({ kind: 'waiting', message: 'Building your dashboard…' });
      await this.o.sleep(opts.pollMs);
    }
  }
}

/**
 * Turn an HTTP status into a sentence.
 *
 * 402 is the one that matters most: a growing SMB WILL outgrow Neon's free tier, and the
 * failure must read as "add a card in Vercel", not as a raw status. This is the difference
 * between a support call that resolves in one sentence and one that does not.
 */
function describeVercelError(status: number, body: string): string {
  switch (status) {
    case 401:
      return 'That Vercel token was not accepted. Paste a fresh one from your Vercel account settings.';
    case 402:
      return 'Vercel needs a payment method on your account before it can create the database.';
    case 403:
      return 'That Vercel token does not have permission for this. Create a new token with full account access.';
    case 409:
      return 'A project with that name already exists on your Vercel account.';
    case 429:
      return 'Vercel is rate-limiting us. Wait a minute and try again.';
    default:
      if (status >= 500) return 'Vercel is having trouble right now. Try again in a few minutes.';
      // The default branch used to read `Vercel rejected the request (400).` — a raw status
      // code reaching a business owner, on the one screen that promised no jargon. The status
      // and body belong in the log (VercelError carries `status`), never in the sentence.
      void body;
      return 'Vercel would not accept that request. Please try setup again.';
  }
}

function isActionable(status: number): boolean {
  return status === 401 || status === 402 || status === 403 || status === 409;
}

// ---------------------------------------------------------------- the flow

export interface ProvisionInput {
  projectName: string;
  tenantId: string;
  /** base64 X25519 public key. PUBLIC — safe to hand to Vercel. */
  identityPublicKey: string;
  bootstrapSecret: string;
  schemaVersion: string;
  files: DeployFile[];
}

export interface ProvisionResult {
  projectId: string;
  deploymentUrl: string;
}

/**
 * The whole flow, in the order that matters.
 *
 * ORDER IS LOAD-BEARING in two places:
 *   1. Provision the database, wait for `available`, THEN connect. Connecting early produces a
 *      crash-looping deploy that looks like our bug.
 *   2. Set BOOTSTRAP_SECRET BEFORE the first deploy. Because this app provisions the server, it
 *      can mint the secret the server will expect — so provisioning and trust-bootstrap become
 *      the same step and no out-of-band channel is needed.
 */
export async function provision(
  client: VercelClient,
  input: ProvisionInput,
  timings: { pollMs: number; installTimeoutMs: number; dbTimeoutMs: number; deployTimeoutMs: number },
  log: (e: ProvisionEvent) => void,
): Promise<ProvisionResult> {
  const step = (s: ProvisionStep, message: string) => log({ kind: 'step', step: s, message });

  step('verify_token', 'Checking your Vercel account…');
  await client.verifyToken();

  step('check_neon', 'Looking for the Neon database add-on…');
  let icfg = await client.findNeonConfiguration();
  if (!icfg) {
    step('await_neon_install', 'Neon needs to be installed once.');
    icfg = await client.awaitNeonInstall({
      timeoutMs: timings.installTimeoutMs,
      pollMs: timings.pollMs,
    });
  }

  step('create_project', 'Creating your project…');
  // Adopts the project if a previous attempt already created it — see `ensureProject`. This is
  // what makes "Try again" work for the owner whose wifi dropped mid-setup.
  const project = await client.ensureProject(input.projectName);
  // New projects default to Vercel Authentication, which 401s every route — including the owner's
  // phone. Turn it off now, before anything tries to reach the deployment. The data is protected
  // by the crypto + session auth, not by locking the whole site behind a Vercel login.
  await client.disableDeploymentProtection(project.id);

  step('provision_database', 'Creating your database…');
  const db = await client.provisionNeon(icfg, `${input.projectName}-db`);
  await client.awaitDatabaseReady(db.resourceId, {
    timeoutMs: timings.dbTimeoutMs,
    pollMs: timings.pollMs,
  });

  step('connect_database', 'Connecting the database…');
  await client.connectDatabase(icfg, db.resourceId, project.id);

  step('set_env', 'Configuring your server…');
  await client.setEnv(project.id, [
    { key: 'BOOTSTRAP_SECRET', value: input.bootstrapSecret, sensitive: true },
    { key: 'TENANT_ID', value: input.tenantId },
    { key: 'IDENTITY_PUBKEY', value: input.identityPublicKey },
    { key: 'SCHEMA_VER', value: input.schemaVersion },
  ]);

  step('upload_files', 'Uploading the dashboard…');
  // By sha, not by file: the bundle mounts the SAME server bundle into every route's .func
  // directory, so the file list holds ~10 copies of identical bytes. Vercel's store is
  // content-addressed — the deployment manifest references them all by sha — so each distinct
  // blob needs uploading exactly once. Office-wifi upload time is the owner's longest wait in
  // this whole flow; multiplying it by the route count would be pure waste.
  const uniqueBlobs = new Map<string, DeployFile>();
  for (const f of input.files) uniqueBlobs.set(f.sha, f);
  for (const f of uniqueBlobs.values()) await client.uploadFile(f);

  step('deploy', 'Deploying…');
  const dep = await client.deploy(input.projectName, input.files);

  step('await_ready', 'Building your dashboard…');
  const url = await client.awaitDeployReady(dep.id, {
    timeoutMs: timings.deployTimeoutMs,
    pollMs: timings.pollMs,
  });

  step('done', 'Your dashboard is live.');
  return { projectId: project.id, deploymentUrl: url || dep.url };
}

/**
 * Build a project name Vercel will actually accept.
 *
 * Vercel's rule: 1-100 characters, lowercase, alphanumeric plus `.` `_` `-`, and it rejects a
 * name that begins or ends with a hyphen. Every one of those was reachable here:
 *
 *   - THE SUFFIX WAS NEVER SANITISED. It is interpolated straight in, so an uppercase or empty
 *     suffix produced `acme-dash-A1B2` (illegal characters) or `acme-dash-` (trailing hyphen).
 *     The slug is scrubbed with obvious care, which is exactly why nobody looked at the suffix.
 *   - THE SLICE LANDED MID-SEPARATOR. `slice(0, 40)` runs AFTER the trim, so a name whose 40th
 *     character is a generated hyphen yields `aaa…a--dash-x`.
 *   - NO OVERALL LENGTH BOUND. 40 + suffix could exceed 100 with a long suffix.
 *
 * None of these throw. They surface as a 400 from Vercel on the one screen that promised the
 * owner no jargon, which is why this is scrubbed here and asserted in a fuzz test.
 */
export function safeProjectName(businessName: string, suffix: string): string {
  const scrub = (s: string, max: number): string =>
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .slice(0, max)
      // AFTER the slice, not before: the slice is what creates the trailing hyphen.
      .replace(/^-+|-+$/g, '');

  // A business named entirely in Devanagari slugs to empty — extremely likely in this market,
  // and it would otherwise produce an invalid name and a baffling 400.
  const slug = scrub(businessName, 40) || 'tally';
  const tail = scrub(suffix, 40);
  const name = tail ? `${slug}-dash-${tail}` : `${slug}-dash`;
  // Belt and braces. The parts are already bounded well under 100, but the invariant is stated
  // once, here, rather than inferred from arithmetic at every call site.
  return name.slice(0, 100).replace(/-+$/, '');
}
