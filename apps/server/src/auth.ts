import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { KdfParams, WrappedKey } from '@tally-bridge/core';
import {
  ARGON2ID_MAX_MEMLIMIT_BYTES,
  ARGON2ID_MAX_OPSLIMIT,
  ARGON2ID_MEMLIMIT_BYTES,
  ARGON2ID_MIN_MEMLIMIT_BYTES,
  ARGON2ID_MIN_OPSLIMIT,
  ARGON2ID_OPSLIMIT,
  KDF_INFO,
} from '@tally-bridge/crypto';
import { MAX_PAYLOAD_BYTES, ROUTES, verifyRequest, type VerifyDeps } from '@tally-bridge/protocol';
import {
  admitDevice,
  deviceAuthFailureResponse,
  isId,
  type AdmitDeps,
  type Gate,
  type HttpResponse,
} from './ingest.ts';

/**
 * Dashboard authentication — the session door, and the write path that makes it usable.
 *
 * The derivation, all of it client-side:
 *
 *   passphrase --Argon2id--> root --+-- HKDF('tally/v1/kek')  --> KEK       (browser only,
 *                                   |                                        NEVER sent)
 *                                   +-- HKDF('tally/v1/auth') --> authToken (sent at login)
 *
 * The server stores SHA-256(authToken) and compares in constant time. It never sees the
 * passphrase, the root, or the KEK. HKDF-Expand outputs under distinct `info` labels are
 * computationally independent (this is HMAC-SHA256's PRF property doing the work), so holding
 * the auth token — or its hash — yields nothing about the KEK. Both labels now live in
 * packages/crypto's `KDF_INFO` and are IMPORTED here rather than restated: this file originally
 * declared its own 'tally/v1/auth' literal because the shared one did not exist, and two copies
 * of an HKDF label is a silent, total authentication failure the day one of them is edited.
 *
 * WHY PLAIN SHA-256 SERVER-SIDE IS ENOUGH — verified, not repeated on faith. The stored hash is
 * over a value that already carries 256 bits of entropy *conditioned on the passphrase*, behind
 * a ~475ms, 64MiB Argon2id (measured figures from packages/crypto/src/kdf.ts). An attacker
 * holding this database dump who wants the passphrase must, per guess:
 *
 *   against login_credential:  Argon2id (~475ms) + 2×HKDF + SHA-256   (tail ≈ single-digit µs)
 *   against wrapped_key:       Argon2id (~475ms) + HKDF + AEAD open    (tail ≈ single-digit µs
 *                                                                       for a <1KB blob)
 *
 * Both tails are ~5 orders of magnitude below the Argon2id term, so the hash is not a
 * meaningfully cheaper oracle than the wrapped_key blob that sits in the SAME dump — it is in
 * fact cheaper by a few microseconds per guess, which changes the attack's cost by well under
 * 0.01%. Argon2id's memory-hardness, not the tail operation, is the entire security margin, and
 * it is identical on both paths. What per-guess salting buys elsewhere (rainbow tables) is
 * already bought here by the Argon2id salt inside the derivation.
 *
 * THE SESSION IS NOT THE SECURITY BOUNDARY; THE CRYPTO IS. What the session (and the rate
 * limits below) actually buy: without them, the deployment URL is a public ORACLE — prelogin
 * hands out the salt and wrappedKeys hands out the grindable blob, and this audience's
 * passphrases will include 'tally123'. The session denies the remote attacker the offline
 * grind; the Argon2id makes the online grind cost the attacker half a second of THEIR compute
 * per guess on top of the caps. Neither claim is confidentiality of the ciphertext — that never
 * depended on the session at all.
 *
 * Style follows ingest.ts/read.ts: pure handlers over injected deps, security order stated and
 * tested. The route adapters stay thin.
 */

/**
 * The HKDF info label the client MUST use to derive the auth token from the Argon2id root.
 *
 * Re-exported from packages/crypto rather than declared. The Bridge, the browser and this server
 * must all expand the SAME label or login fails for everyone, and a label is exactly the kind of
 * string that gets typed twice and edited once.
 */
export const AUTH_KDF_INFO: string = KDF_INFO.auth;

/* ------------------------------------------------------------------ *
 * Session parameters
 * ------------------------------------------------------------------ */

export const SESSION_COOKIE_NAME = 'tb_session';

/** 256 bits from the CSPRNG. Not guessable, not enumerable, no structure to leak. */
export const SESSION_TOKEN_BYTES = 32;

/**
 * Absolute ceiling: 7 days. A stolen cookie — XSS'd, synced to a compromised browser profile,
 * lifted from a disk image — dies at most a week after the login that minted it, whatever the
 * attacker does. Chosen against the audience: an owner checks a financial dashboard around
 * daily, so a week keeps "log in once on Monday" working without granting a stolen token a
 * quarter's lifetime.
 */
export const SESSION_ABSOLUTE_TTL_SECONDS = 7 * 24 * 3600;

/**
 * Idle timeout: 24 hours, slid forward by `requireSessionFromSql` on every authenticated read.
 * A daily user never notices it; a cookie on an abandoned machine dies within a day. The slide
 * happens in the SAME statement as the validity check (an UPDATE ... RETURNING), so there is no
 * read-then-write gap in which a just-expired session answers one more query.
 */
export const SESSION_IDLE_TIMEOUT_SECONDS = 24 * 3600;

/**
 * The cookie, exactly. Every attribute is load-bearing:
 *   HttpOnly        — document.cookie cannot read it; an XSS must proxy requests live rather
 *                     than exfiltrate a credential.
 *   Secure          — never sent over cleartext HTTP.
 *   SameSite=Strict — not attached to any cross-site request, which is the CSRF defence for
 *                     /api/logout and /api/devices/revoke (the session door's only writes).
 *                     Strict rather than Lax because this dashboard has no legitimate
 *                     cross-site entry that needs the cookie on first navigation.
 *   Path=/          — the API and the pages share an origin; scoping narrower than the API
 *                     routes would silently drop the cookie from them.
 *   Max-Age         — matches the absolute TTL. The server row is authoritative regardless:
 *                     expiry is enforced by the database clock, not by the browser agreeing to
 *                     forget.
 */
export function sessionCookie(token: string): string {
  return (
    `${SESSION_COOKIE_NAME}=${token}; Max-Age=${SESSION_ABSOLUTE_TTL_SECONDS}; ` +
    `Path=/; HttpOnly; Secure; SameSite=Strict`
  );
}

/** Max-Age=0 deletes the cookie. Attributes must match the set cookie or browsers keep it. */
export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

/* ------------------------------------------------------------------ *
 * Rate caps for the unauthenticated doors
 * ------------------------------------------------------------------ */

/**
 * Login is a password door on the public internet; these caps are what stop it being an online
 * guessing service. Sizing: the owner needs single-digit attempts per day, so 10/hour/IP
 * absorbs any human's fat-fingering; 30/hour across ALL IPs bounds a distributed grind to
 * ~263k guesses/year — each of which also costs the ATTACKER a ~0.5s Argon2id to produce a
 * candidate token. The deliberate trade: an attacker flooding the global cap can deny the owner
 * login for the duration (noisy, visible), which is accepted over the alternative — a
 * per-IP-only cap that a botnet walks straight through against a passphrase like 'tally123'.
 * Counted per ATTEMPT, before any verification, so garbage spends the budget too.
 */
export const MAX_LOGIN_ATTEMPTS_PER_IP_PER_HOUR = 10;
export const MAX_LOGIN_ATTEMPTS_PER_HOUR = 30;

/**
 * Prelogin leaks nothing secret (see handlePrelogin) but is an unauthenticated endpoint that
 * hits the database, i.e. a DoS surface on the client's own Neon bill. One fetch per unlock is
 * the honest rate; these are two orders of magnitude of slack above it.
 */
export const MAX_PRELOGIN_PER_IP_PER_HOUR = 30;
export const MAX_PRELOGIN_PER_HOUR = 120;

/** { tenantId, authToken } in JSON is under 400 bytes; 4KB is an order of magnitude of slack. */
export const MAX_LOGIN_BODY_BYTES = 4096;

/* ------------------------------------------------------------------ *
 * Small crypto helpers (node:crypto — no new dependency)
 * ------------------------------------------------------------------ */

function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** Base64 alphabet, correctly padded. Checked BEFORE Buffer.from, which silently skips junk. */
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

function decodeB64Exact(v: unknown, bytes: number): Uint8Array | undefined {
  if (typeof v !== 'string' || v.length % 4 !== 0 || !B64.test(v)) return undefined;
  const out = new Uint8Array(Buffer.from(v, 'base64'));
  return out.length === bytes ? out : undefined;
}

/** The session cookie value: 32 CSPRNG bytes as base64url — exactly 43 chars, no padding. */
const SESSION_TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/** What goes in the session table: the hash, never the token. The DB is what we assume leaks. */
export function hashSessionToken(token: string): Uint8Array {
  return sha256(token);
}

/**
 * Pull the session token out of the Cookie header, or return undefined.
 *
 * Reads ONLY the `cookie` header. Obligation 1 from read.ts's RequireSession contract is
 * enforced here by construction: there is no code path that consults `x-tenant-id` or any other
 * client-settable claim — the tenant comes from the session ROW, looked up by token hash.
 *
 * The first `tb_session` cookie wins. A duplicate name (cookie-jar tricks, a stale cookie on a
 * parent domain) can only make auth FAIL — the value is hashed and looked up, so a wrong value
 * is a miss, never a different tenant.
 */
export function sessionTokenFromHeaders(
  headers: Record<string, string | undefined>,
): string | undefined {
  const raw = headers['cookie'];
  // The length bound is a parse cost cap, not security: this runs before any authentication.
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 8192) return undefined;
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== SESSION_COOKIE_NAME) continue;
    const value = part.slice(eq + 1).trim();
    // Fail closed on a malformed value rather than scanning on for a well-formed duplicate.
    return SESSION_TOKEN_SHAPE.test(value) ? value : undefined;
  }
  return undefined;
}

/* ------------------------------------------------------------------ *
 * Deps and response shape
 * ------------------------------------------------------------------ */

export interface AuthDeps {
  /**
   * The per-deployment random value from the `deployment_secret` table, or undefined if the
   * migration has not run. Used only to key prelogin's decoy salts.
   */
  deploymentSecret: () => Promise<string | undefined>;
  getLoginCredential: (
    tenantId: string,
  ) => Promise<{ tokenHash: Uint8Array; kdf: KdfParams } | undefined>;
  /**
   * ATOMICALLY record one attempt against `bucketKey` and return how many attempts are now in
   * the trailing hour, INCLUDING this one. Same contract, same reasoning, same required shape
   * as IngestDeps.reserveUpload: one statement, never SELECT-then-INSERT — the TOCTOU argument
   * there applies verbatim to a password door.
   */
  reserveAuthAttempt: (bucketKey: string) => Promise<number>;
  /** Insert the session row (and sweep expired ones). Expiry is computed on the DB clock. */
  createSession: (tokenHash: Uint8Array, tenantId: string) => Promise<void>;
  /** Delete the row. Returns whether one existed; logout does not care, tests do. */
  deleteSession: (tokenHash: Uint8Array) => Promise<boolean>;
}

/** JsonResponse (read.ts) plus the one thing auth endpoints add: a Set-Cookie instruction. */
export interface AuthResponse<T> {
  status: number;
  body: { ok: true; data: T } | { ok: false; error: string };
  /** When present, the adapter MUST emit this verbatim as a Set-Cookie header. */
  setCookie?: string;
}

const ok = <T>(data: T): AuthResponse<T> => ({ status: 200, body: { ok: true, data } });
const err = <T>(status: number, error: string): AuthResponse<T> => ({
  status,
  body: { ok: false, error },
});

/**
 * Meter one attempt and translate the count. `undefined` means "admitted".
 *
 * NaN fails CLOSED as 400, exactly as checkQuota treats an unmeasurable count: every comparison
 * with NaN is false, so `attempts > cap` on a NaN would silently wave the request through — an
 * unreadable counter must never read as an empty one.
 */
async function overLimit<T>(
  deps: AuthDeps,
  bucketKey: string,
  cap: number,
): Promise<AuthResponse<T> | undefined> {
  const attempts = await deps.reserveAuthAttempt(bucketKey);
  if (!Number.isSafeInteger(attempts) || attempts < 0) {
    return err(400, 'attempt counter is unreadable');
  }
  if (attempts > cap) return err(429, 'too many attempts; try again later');
  return undefined;
}

/** One bucket per source IP, one across all sources. See the cap constants for the sizing. */
const ipKey = (door: string, clientIp: string | undefined): string =>
  // An adapter that cannot attribute an IP shares one bucket: degraded to the global cap
  // rather than unmetered. The IP must be the PLATFORM'S attribution (Vercel's
  // x-real-ip/x-vercel-forwarded-for), never a client-settable header like x-forwarded-for
  // taken at face value — a spoofable key is a cap the attacker rotates out of for free.
  `${door}:ip:${clientIp ?? 'unknown'}`;

/* ------------------------------------------------------------------ *
 * GET /api/prelogin — the chicken-and-egg endpoint
 * ------------------------------------------------------------------ */

/**
 * Return the Argon2id parameters (salt included) for a tenant, so a browser can derive.
 *
 * No auth is POSSIBLE here: the browser cannot authenticate until it has derived the auth
 * token, and it cannot derive without these parameters. A salt is public input by construction
 * — its job is to defeat precomputation, not to be secret (Bitwarden's /accounts/prelogin is
 * this same endpoint for this same reason). What this hands an attacker: the KDF cost and 16
 * salt bytes, neither of which shortens a grind they could not already mount after their first
 * failed login told them the same thing.
 *
 * THE TENANT-ENUMERATION QUESTION, reasoned through rather than waved at. A response that
 * differs between "tenant exists" and "tenant does not" makes this endpoint a free existence
 * oracle for anyone holding the deployment URL. The options:
 *
 *   - 404 on unknown: a clean oracle. Rejected.
 *   - Random params per call: detected in two requests (the salt wobbles; a real salt never
 *     does). Costs the attacker nothing to distinguish. Rejected.
 *   - Deterministic decoy: salt = HMAC(deploymentSecret, tenantId), params = the shipped
 *     defaults. Stable across calls, keyed by a value a REMOTE attacker cannot compute, and
 *     shaped identically to a real answer because today every real credential carries exactly
 *     the shipped defaults. This is what is implemented.
 *
 * Honest residuals, so nobody repeats this as stronger than it is: (1) an attacker with the
 * DATABASE can distinguish — and does not need to, having login_credential in hand; the decoy
 * defends the remote-URL-holder boundary only. (2) if defaults are ever raised, old real
 * tenants keep their old params while decoys advance — re-derive the decoy params from the
 * modal REAL credential if that day comes. (3) the code path for a decoy differs from a real
 * hit by one HMAC (~µs) against network jitter (~ms); both paths issue the same two queries in
 * the same order, unconditionally, which is what keeps the timing residual at µs scale.
 *
 * Rate-limited because an unauthenticated endpoint that reaches the database is a spend of the
 * client's Neon budget even when it leaks nothing.
 */
export async function handlePrelogin(
  rawTenantId: unknown,
  deps: AuthDeps,
  clientIp?: string,
): Promise<AuthResponse<{ kdf: KdfParams }>> {
  // Shape first (free, leaks nothing), then the meter, then anything that costs a query.
  if (!isId(rawTenantId)) return err(400, 'missing tenant');
  const tenantId = rawTenantId;

  const ip = await overLimit<{ kdf: KdfParams }>(
    deps,
    ipKey('prelogin', clientIp),
    MAX_PRELOGIN_PER_IP_PER_HOUR,
  );
  if (ip) return ip;
  const all = await overLimit<{ kdf: KdfParams }>(deps, 'prelogin:all', MAX_PRELOGIN_PER_HOUR);
  if (all) return all;

  // Both queries run on BOTH paths — see residual (3) above.
  const secret = await deps.deploymentSecret();
  const cred = await deps.getLoginCredential(tenantId);

  if (!secret) {
    // Migration never ran (or the row was deleted). Without the secret the decoy is either
    // non-deterministic or attacker-computable, so there is no honest unknown-tenant answer —
    // and answering ONLY for known tenants would be the oracle again. Uniform failure, both
    // paths, and it is a real deployment fault worth surfacing as one.
    return err(503, 'server is not initialized');
  }

  if (cred) return ok({ kdf: cred.kdf });

  // The decoy. 16 bytes = libsodium's crypto_pwhash_SALTBYTES — asserted against a real
  // randomSalt() in auth.test.ts rather than trusted from memory here.
  const decoySalt = new Uint8Array(
    createHmac('sha256', secret).update(`tally/v1/prelogin-decoy:${tenantId}`).digest(),
  ).subarray(0, 16);
  return ok({
    kdf: {
      v: 1,
      kdf: 'argon2id',
      m: ARGON2ID_MEMLIMIT_BYTES,
      t: ARGON2ID_OPSLIMIT,
      p: 1,
      salt: Buffer.from(decoySalt).toString('base64'),
    },
  });
}

/* ------------------------------------------------------------------ *
 * POST /api/login
 * ------------------------------------------------------------------ */

/** Fixed decoy for the constant-time compare when no credential row exists. See below. */
const NO_CREDENTIAL_DECOY = sha256('tally/v1/login-no-credential-decoy');

/**
 * Exchange an auth token for a session cookie.
 *
 * Order, and why: size cap (parsing is the cheapest DoS), then the METER — attempts are spent
 * before any verification, mirroring ingest's "counts ATTEMPTS, not successes", so a flood of
 * malformed bodies drains the flood's own budget — then parse, then verify, then mint.
 *
 * The compare is constant-time (node:crypto timingSafeEqual over two 32-byte SHA-256 outputs;
 * lengths are fixed so the length branch never fires). Honesty about what that buys: both
 * inputs are hashes, so a timing early-exit would leak prefix bytes OF A HASH, which does not
 * walk back to a token without a preimage. It is kept constant-time anyway because "safe for
 * subtle reasons" decays into "unsafe after a refactor" — the cheap strong form is the
 * maintainable one.
 *
 * Unknown tenant and wrong token are the SAME answer — status, body, and (to the µs-scale
 * limit of the shared code path) time: the credential fetch always runs, and the compare always
 * runs, against a fixed decoy hash when no row exists. This mirrors read.ts collapsing
 * "unknown device" and "not yours" into one 404.
 */
export async function handleLogin(
  rawBody: Uint8Array,
  deps: AuthDeps,
  clientIp?: string,
): Promise<AuthResponse<{ tenantId: string }>> {
  if (rawBody.byteLength > MAX_LOGIN_BODY_BYTES) return err(413, 'payload too large');

  const ip = await overLimit<{ tenantId: string }>(
    deps,
    ipKey('login', clientIp),
    MAX_LOGIN_ATTEMPTS_PER_IP_PER_HOUR,
  );
  if (ip) return ip;
  const all = await overLimit<{ tenantId: string }>(deps, 'login:all', MAX_LOGIN_ATTEMPTS_PER_HOUR);
  if (all) return all;

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return err(400, 'body is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null) return err(400, 'body is not an object');
  // `unknown` fields for the handleRegister reason: this is JSON.parse output, and a string
  // annotation here would be a claim the runtime never checks.
  const { tenantId, authToken } = parsed as { tenantId?: unknown; authToken?: unknown };
  if (!isId(tenantId)) return err(400, 'missing tenantId');
  const tokenBytes = decodeB64Exact(authToken, 32);
  if (!tokenBytes) return err(400, 'authToken must be 32 bytes, base64');

  const cred = await deps.getLoginCredential(tenantId);
  const presented = sha256(tokenBytes);
  // The compare runs unconditionally; the row-existence check ANDs in afterwards. The length
  // guard exists because node's timingSafeEqual THROWS on mismatched lengths (a throw here is
  // a 500, and a 500 is not a 401) — a stored hash that is not 32 bytes is a corrupt row and
  // must read as "no credential", through the same constant-time path.
  const usable = cred !== undefined && cred.tokenHash.length === presented.length;
  const match = timingSafeEqual(presented, usable ? cred.tokenHash : NO_CREDENTIAL_DECOY);
  if (!usable || !match) return err(401, 'invalid credentials');

  // 256 bits from the CSPRNG, base64url (cookie-safe, no padding). The row stores the HASH:
  // a session-table dump must not mint working cookies — same reasoning as login_credential.
  const token = randomBytes(SESSION_TOKEN_BYTES).toString('base64url');
  await deps.createSession(hashSessionToken(token), tenantId);

  return { ...ok({ tenantId }), setCookie: sessionCookie(token) };
}

/* ------------------------------------------------------------------ *
 * POST /api/logout
 * ------------------------------------------------------------------ */

/**
 * Destroy the session SERVER-SIDE. Clearing the cookie alone would leave the row alive: anyone
 * who had copied the token (the scenario logout exists for — a shared machine) could keep using
 * it until the idle timeout. The DELETE is the logout; the cleared cookie is courtesy.
 *
 * Idempotent on purpose, like revoke: a token whose row is already gone (expired, or a second
 * click) still gets 200 and a cleared cookie. The user asked to be logged out and they are —
 * an error here teaches a user on a cybercafé machine that the button did not work. The 401
 * fires only when no token is presented at all, which honours the route's `auth: 'session'`
 * in the only sense that matters here: the request can destroy exactly the session whose token
 * it holds, and nothing else.
 */
export async function handleLogout(
  headers: Record<string, string | undefined>,
  deps: AuthDeps,
): Promise<AuthResponse<null>> {
  const token = sessionTokenFromHeaders(headers);
  if (!token) return err(401, 'unauthorized');

  await deps.deleteSession(hashSessionToken(token));
  return { ...ok(null), setCookie: clearedSessionCookie() };
}

/* ------------------------------------------------------------------ *
 * PUT /api/wrapped-keys — the Bridge stores what the browser will unwrap
 * ------------------------------------------------------------------ */

export interface PutWrappedKeyDeps extends Omit<VerifyDeps, 'admit'>, AdmitDeps {
  /**
   * Upsert the wrapped-key rows and, when `authTokenHash` is present, the login credential —
   * whose kdf column MUST be taken from the 'pass' blob's own `kdf` object, so the salt
   * prelogin serves and the salt the blob unwraps under are one value by construction.
   *
   * Write order inside: blobs first, credential LAST. A partial failure then leaves the OLD
   * credential serving the OLD salt — which still logs the owner in, after which the browser
   * unwraps with the NEW blob's own embedded kdf (unwrapWithPassphrase always derives from
   * blob.kdf, never from prelogin's answer). Degraded to one extra client-side Argon2id, not
   * to a lockout; a retried PUT heals it because every statement is an upsert.
   */
  storeWrappedKeys: (
    tenantId: string,
    keys: WrappedKey[],
    authTokenHash: Uint8Array | undefined,
  ) => Promise<void>;
}

/**
 * A WRITE, so it goes through the Ed25519 DEVICE door — verifyRequest, with the same admission
 * gate, nonce replay defence and failure mapping as /api/sync. Not the session door: the Bridge
 * holds no session, and per read.ts the two doors must not overlap. Same skeleton as
 * handleIngest, deliberately: size cap before anything, authenticate before parsing, gate
 * inside the verify.
 *
 * The blobs are ciphertext the server cannot open (the wrapping keys derive from the passphrase
 * and recovery key, neither of which is here), so storing them threatens nothing — the checks
 * below are about who may WRITE them, because overwriting the pass wrap + credential with
 * attacker-chosen values is a dashboard lockout, and the tenant binding is what stops device A
 * planting blobs (or a login credential) in tenant B.
 */
export async function handlePutWrappedKey(
  headers: Record<string, string | undefined>,
  rawBody: Uint8Array,
  deps: PutWrappedKeyDeps,
): Promise<HttpResponse> {
  if (rawBody.byteLength > MAX_PAYLOAD_BYTES) {
    return { status: 413, body: { ok: false, error: 'payload too large' } };
  }

  // The verdict box, for the reason documented at handleIngest's twin of this code.
  const verdict: { gate?: Gate } = {};
  const auth = await verifyRequest(
    headers,
    // The route table, never a literal: the path is inside the signature.
    { method: ROUTES.putWrappedKey.method, path: ROUTES.putWrappedKey.path, body: rawBody },
    {
      ...deps,
      admit: async (deviceId) => {
        const decision = await admitDevice(deviceId, rawBody.byteLength, deps);
        verdict.gate = decision;
        return decision.ok ? { ok: true } : { ok: false, detail: decision.detail };
      },
    },
  );
  if (!auth.ok) return deviceAuthFailureResponse(auth.failure, verdict.gate);

  const decided = verdict.gate;
  if (decided === undefined || !decided.ok) {
    return { status: 500, body: { ok: false, error: 'the admission gate did not run' } };
  }
  // THE TENANT COMES FROM THE AUTHENTICATED DEVICE, full stop. The body carries no tenant
  // field, and one smuggled in is ignored by construction — nothing below reads it.
  const tenantId = decided.tenantId;

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return { status: 400, body: { ok: false, error: 'body is not valid JSON' } };
  }

  const shape = validatePutBody(parsed);
  if (typeof shape === 'string') return { status: 400, body: { ok: false, error: shape } };

  await deps.storeWrappedKeys(tenantId, shape.keys, shape.authTokenHash);
  return { status: 200, body: { ok: true } };
}

/** Bounds a roster of hundreds of devices comfortably; rejects a megabyte wearing a key shape. */
const MAX_WRAPPED_CIPHERTEXT_CHARS = 16384;
const WRAPPED_KINDS = ['pass', 'recovery', 'device'] as const;

/**
 * Structural validation, ingest-style: shaped well enough to store and serve back, nothing
 * more — the ciphertext is deliberately not interpretable here. What IS enforced:
 *
 *   - one blob per kind, kinds from the schema's CHECK list;
 *   - kdf present on 'pass' EXACTLY (its salt feeds prelogin), absent elsewhere — matching
 *     WrappedKey's contract in packages/core;
 *   - kdf params inside the same honour band deriveRoot enforces client-side
 *     (packages/crypto/src/kdf.ts): a hostile m/t stored here would be served by prelogin and
 *     OOM phones or be ground at 10ms/guess, the exact attacks that band exists to stop;
 *   - a 'pass' blob and an authTokenHash arrive TOGETHER or not at all. A pass blob without a
 *     credential is a dashboard that can never log in; a credential without a pass blob is a
 *     salt prelogin cannot serve consistently. The coupling makes the drift unrepresentable.
 */
function validatePutBody(
  parsed: unknown,
): { keys: WrappedKey[]; authTokenHash: Uint8Array | undefined } | string {
  if (typeof parsed !== 'object' || parsed === null) return 'body is not an object';
  const { keys, authTokenHash } = parsed as { keys?: unknown; authTokenHash?: unknown };

  if (!Array.isArray(keys) || keys.length === 0) return 'missing keys';
  if (keys.length > WRAPPED_KINDS.length) return 'too many keys';

  const seen = new Set<string>();
  const out: WrappedKey[] = [];
  for (const k of keys) {
    const bad = validateWrappedKey(k);
    if (bad) return bad;
    const key = k as WrappedKey;
    if (seen.has(key.kind)) return `duplicate kind ${key.kind}`;
    seen.add(key.kind);
    // Rebuilt field by field — the read.ts projection argument, applied to a write: what is
    // stored is what was audited, not whatever extra fields rode along in the JSON.
    const rebuilt: WrappedKey = key.kdf
      ? { v: 2, kind: key.kind, kdf: key.kdf, nonce: key.nonce, ciphertext: key.ciphertext }
      : { v: 2, kind: key.kind, nonce: key.nonce, ciphertext: key.ciphertext };
    out.push(rebuilt);
  }

  const hasPass = seen.has('pass');
  if (hasPass && authTokenHash === undefined) {
    return 'a pass key requires authTokenHash';
  }
  if (!hasPass && authTokenHash !== undefined) {
    return 'authTokenHash requires a pass key';
  }

  if (authTokenHash === undefined) return { keys: out, authTokenHash: undefined };
  const hash = decodeB64Exact(authTokenHash, 32);
  if (!hash) return 'authTokenHash must be 32 bytes, base64';
  return { keys: out, authTokenHash: hash };
}

function validateWrappedKey(k: unknown): string | undefined {
  if (typeof k !== 'object' || k === null) return 'key is not an object';
  const key = k as Partial<WrappedKey>;
  if (key.v !== 2) return `unsupported wrapped key version ${String(key.v).slice(0, 20)}`;
  if (!WRAPPED_KINDS.includes(key.kind as (typeof WRAPPED_KINDS)[number])) {
    return 'unknown wrapped key kind';
  }
  // XChaCha20-Poly1305 nonce: 24 bytes, base64 = exactly 32 chars.
  if (!decodeB64Exact(key.nonce, 24)) return 'nonce must be 24 bytes, base64';
  if (
    typeof key.ciphertext !== 'string' ||
    key.ciphertext.length === 0 ||
    key.ciphertext.length > MAX_WRAPPED_CIPHERTEXT_CHARS ||
    key.ciphertext.length % 4 !== 0 ||
    !B64.test(key.ciphertext)
  ) {
    return 'ciphertext must be base64';
  }

  if (key.kind === 'pass') {
    const bad = validateKdfParams(key.kdf);
    if (bad) return bad;
  } else if (key.kdf !== undefined) {
    // Core's WrappedKey: "Present for `pass` only". A kdf on a recovery/device wrap is a blob
    // no code we ship ever writes; store nothing we cannot account for.
    return `kdf is only valid on a pass key`;
  }
  return undefined;
}

function validateKdfParams(p: unknown): string | undefined {
  if (typeof p !== 'object' || p === null) return 'pass key is missing kdf params';
  const kdf = p as Partial<KdfParams>;
  if (kdf.v !== 1) return 'unsupported kdf version';
  if (kdf.kdf !== 'argon2id') return 'unsupported kdf';
  if (kdf.p !== 1) return 'unsupported kdf parallelism';
  const { m, t } = kdf;
  if (typeof m !== 'number' || !Number.isSafeInteger(m) || typeof t !== 'number' || !Number.isSafeInteger(t)) {
    return 'kdf params must be integers';
  }
  if (m < ARGON2ID_MIN_MEMLIMIT_BYTES || t < ARGON2ID_MIN_OPSLIMIT) {
    return 'kdf params below the accepted floor';
  }
  if (m > ARGON2ID_MAX_MEMLIMIT_BYTES || t > ARGON2ID_MAX_OPSLIMIT) {
    return 'kdf params above the accepted ceiling';
  }
  // Argon2id salt: 16 bytes (crypto_pwhash_SALTBYTES), base64.
  if (!decodeB64Exact(kdf.salt, 16)) return 'kdf salt must be 16 bytes, base64';
  return undefined;
}
