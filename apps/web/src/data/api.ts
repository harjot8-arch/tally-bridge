import type { KdfParams, SealedEnvelope, WrappedKey } from '@tally-bridge/core';
import { SECTIONS, type Section } from '@tally-bridge/core';
import { ROUTES } from '@tally-bridge/protocol';

/**
 * The HTTP client for the read API. Thin on purpose: every path comes from
 * `packages/protocol/src/routes.ts` (never a literal — the route table is the one place both
 * sides agree on paths), every response is validated as HOSTILE input before it is typed, and
 * every failure becomes an `ApiError` carrying one plain sentence.
 *
 * `fetch` is injected rather than taken from the global, so the whole data layer can be driven
 * against an in-process fake server in tests — the same seam the server's own handlers use for
 * their dependencies.
 *
 * WHY THE WIRE SHAPES ARE VALIDATED HERE AND NOT TRUSTED FROM THE TYPES: the server is exactly
 * the party this product's security model refuses to trust. A TypeScript annotation on
 * JSON.parse output is a claim the runtime never checks. Everything security-relevant is
 * re-checked downstream by `openSection` (signature, AAD) regardless; the checks here exist so
 * that a malformed row fails with a named reason instead of a TypeError deep in the crypto.
 */

export type FetchLike = (path: string, init?: RequestInit) => Promise<Response>;

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** One snapshot row as `GET /api/snapshots` returns it (SnapshotView in apps/server/src/read.ts). */
export interface SnapshotRow {
  companyGuid: string;
  section: Section;
  asOf: string;
  snapshotTs: number;
  seq: number;
  /** Opaque here. `openSection` is the only reader. */
  envelope: SealedEnvelope;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const SECTION_SET: ReadonlySet<string> = new Set(SECTIONS);

async function requestJson(
  fetchImpl: FetchLike,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  let res: Response;
  try {
    res = await fetchImpl(path, {
      method,
      // The session cookie is HttpOnly; the browser attaches it. Nothing here reads it.
      credentials: 'same-origin',
      ...(body === undefined
        ? {}
        : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    });
  } catch {
    throw new ApiError(0, 'network unreachable');
  }

  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new ApiError(res.status, 'the server answered with something that is not JSON');
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new ApiError(res.status, 'the server answered with a malformed body');
  }
  const { ok, data, error } = parsed as { ok?: unknown; data?: unknown; error?: unknown };
  if (!res.ok || ok !== true) {
    throw new ApiError(res.status, typeof error === 'string' ? error : `request failed (${res.status})`);
  }
  return data;
}

/** GET /api/prelogin?tenant=… → the Argon2id params. The salt is INSIDE the params, base64. */
export async function prelogin(fetchImpl: FetchLike, tenantId: string): Promise<KdfParams> {
  const data = await requestJson(
    fetchImpl,
    ROUTES.prelogin.method,
    `${ROUTES.prelogin.path}?tenant=${encodeURIComponent(tenantId)}`,
  );
  const kdf = (data as { kdf?: unknown }).kdf;
  const bad = (why: string) => new ApiError(200, `prelogin returned unusable KDF params: ${why}`);
  if (typeof kdf !== 'object' || kdf === null) throw bad('not an object');
  const k = kdf as Partial<KdfParams>;
  if (k.v !== 1 || k.kdf !== 'argon2id' || k.p !== 1) throw bad('unknown scheme');
  // `typeof === 'number'` first: `k` is Partial, so `m`/`t` are `number | undefined`, and
  // `Number.isSafeInteger` is typed `(n: unknown) => boolean` — it rejects undefined at runtime
  // but does not narrow. The typeof check is what lets the compiler see what the runtime check
  // already enforced; behaviour is identical.
  const { m, t } = k;
  if (typeof m !== 'number' || !Number.isSafeInteger(m)) throw bad('non-integer cost');
  if (typeof t !== 'number' || !Number.isSafeInteger(t)) throw bad('non-integer cost');
  if (typeof k.salt !== 'string' || k.salt.length === 0) throw bad('missing salt');
  // The m/t honour band is enforced by `deriveRoot` itself (packages/crypto/src/kdf.ts) — the
  // check that stops a hostile blob OOMing this phone lives with the derivation, not here.
  return { v: 1, kdf: 'argon2id', m, t, p: 1, salt: k.salt };
}

/** POST /api/login. On success the server sets the HttpOnly session cookie. */
export async function login(fetchImpl: FetchLike, tenantId: string, authTokenB64: string): Promise<void> {
  await requestJson(fetchImpl, ROUTES.login.method, ROUTES.login.path, {
    tenantId,
    authToken: authTokenB64,
  });
}

/** POST /api/logout. Destroys the session server-side; errors are not interesting to the owner. */
export async function logout(fetchImpl: FetchLike): Promise<void> {
  try {
    await requestJson(fetchImpl, ROUTES.logout.method, ROUTES.logout.path, {});
  } catch {
    // The user asked to be locked and locally they are: the caller drops the keys regardless.
    // A failed server-side delete leaves a cookie that expires on its own.
  }
}

/** GET /api/wrapped-keys → the wrapped identity blobs. Ciphertext; the passphrase opens them. */
export async function wrappedKeys(fetchImpl: FetchLike): Promise<WrappedKey[]> {
  const data = await requestJson(fetchImpl, ROUTES.wrappedKeys.method, ROUTES.wrappedKeys.path);
  if (!Array.isArray(data)) throw new ApiError(200, 'wrapped-keys did not return a list');
  const out: WrappedKey[] = [];
  for (const k of data) {
    if (typeof k !== 'object' || k === null) continue;
    const key = k as Partial<WrappedKey>;
    if (key.v !== 2) continue;
    if (key.kind !== 'pass' && key.kind !== 'recovery' && key.kind !== 'device') continue;
    if (typeof key.nonce !== 'string' || typeof key.ciphertext !== 'string') continue;
    // Rebuilt field by field (the projection habit from apps/server/src/read.ts, applied to a
    // response): what flows on is what was checked, not whatever rode along.
    const rebuilt: WrappedKey = { v: 2, kind: key.kind, nonce: key.nonce, ciphertext: key.ciphertext };
    if (key.kdf !== undefined) rebuilt.kdf = key.kdf as KdfParams;
    out.push(rebuilt);
  }
  return out;
}

/**
 * GET /api/snapshots → sealed envelopes plus the server's OWN index of what each one is.
 *
 * Note the trust status of every field: the row metadata (companyGuid, section, asOf,
 * snapshotTs, seq) is the SERVER'S claim and stays untrusted; `envelope` is opaque until
 * `openSection` verifies its signature against the pinned roster. Rows that fail shape checks
 * are dropped and COUNTED — a malformed row must not blank the readable ones, and must not
 * vanish without trace either.
 */
export async function snapshots(
  fetchImpl: FetchLike,
): Promise<{ rows: SnapshotRow[]; malformed: number }> {
  const data = await requestJson(fetchImpl, ROUTES.snapshots.method, ROUTES.snapshots.path);
  if (!Array.isArray(data)) throw new ApiError(200, 'snapshots did not return a list');
  const rows: SnapshotRow[] = [];
  let malformed = 0;
  for (const r of data) {
    if (typeof r !== 'object' || r === null) {
      malformed++;
      continue;
    }
    const row = r as Partial<SnapshotRow>;
    if (
      typeof row.companyGuid !== 'string' ||
      row.companyGuid.length === 0 ||
      typeof row.section !== 'string' ||
      !SECTION_SET.has(row.section) ||
      typeof row.asOf !== 'string' ||
      !ISO_DATE.test(row.asOf) ||
      !Number.isSafeInteger(row.snapshotTs) ||
      !Number.isSafeInteger(row.seq) ||
      typeof row.envelope !== 'object' ||
      row.envelope === null
    ) {
      malformed++;
      continue;
    }
    rows.push({
      companyGuid: row.companyGuid,
      section: row.section as Section,
      asOf: row.asOf,
      snapshotTs: row.snapshotTs as number,
      seq: row.seq as number,
      envelope: row.envelope as SealedEnvelope,
    });
  }
  return { rows, malformed };
}
