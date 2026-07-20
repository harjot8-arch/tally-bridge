import type { SealedEnvelope, WrappedKey } from '@tally-bridge/core';

/**
 * The read API — what the web dashboard fetches.
 *
 * THE SHAPE OF THE SURFACE IS DECIDED: it is a web app. The browser fetches CIPHERTEXT and
 * decrypts it locally with a key derived from a passphrase the server has never seen. That is
 * not a detail of the client; it is the contract this file implements, and it inverts the usual
 * job of a read API. The normal instinct — return what the screen needs — is here a security
 * bug. These handlers hand over sealed blobs and metadata and nothing else. Rendering is the
 * browser's problem, after it holds a key we do not have.
 *
 * So there is one rule, and it is absolute:
 *
 *   NO ENDPOINT MAY RETURN PLAINTEXT, OR ANYTHING THAT DECRYPTS IT.
 *
 * The server cannot violate the first half even if it tried — it has no key, by construction
 * (see ARCHITECTURE.md). It could violate the second half, easily, by shipping a wrapping key
 * or an identity secret alongside the blob it opens. That would be a total compromise dressed
 * as a convenience, and it is the failure this file and its tests are built to prevent.
 *
 * What is safe to return, and why:
 *   - `envelope.ciphertext`, `envelope.nonce`  — the sealed data and its nonce. Useless alone.
 *   - `envelope.sealedCek`                     — the content key sealed to the identity PUBLIC
 *                                                key. Opening it requires the identity secret,
 *                                                which exists only inside the owner's browser
 *                                                after they type their passphrase. Shipping it
 *                                                is not a leak; it is the mechanism.
 *   - `wrapped_key.blob`                       — the identity secret wrapped under an
 *                                                Argon2id- or recovery-derived key. Same
 *                                                argument: the wrapping key is never here.
 *   - AAD fields, device labels, timestamps    — metadata. Already authenticated in the clear.
 *
 * The AAD is worth being honest about: it names the tenant, the company GUID, the section and
 * the date. Anyone holding this database learns that a company synced a `receivables` section
 * on a date, and how big it was. They do not learn a rupee of it. That trade was made
 * deliberately — the server needs those fields to index, dedupe and enforce freshness — and it
 * is the outer edge of what leaves this machine.
 *
 * Style follows ingest.ts: pure functions over injected dependencies, returning
 * `{status, body}`. Same reason. Every interesting behaviour here is an ACCESS CONTROL
 * behaviour, and an access-control check that can only be exercised by booting Next.js and
 * Postgres is a check that will not be exercised. The route files are thin adapters.
 */

/* ------------------------------------------------------------------ *
 * Session — the pluggable seam
 * ------------------------------------------------------------------ */

/**
 * Dashboard authentication.
 *
 * THE SESSION COOKIE DOES NOT EXIST YET. There is no login page, no cookie, no session store.
 * This is the interface it will implement, defined now and injected, so that the read handlers
 * can be written and — more importantly — TESTED against the access-control rules today,
 * without waiting on it, and so that landing it later touches one adapter instead of four
 * handlers.
 *
 * The contract is deliberately narrow, and every part of it is load-bearing:
 *
 *   - IN:  the raw request headers. Not a parsed cookie, not a user object. Whatever proves
 *          identity — a signed cookie, a bearer token, a WebAuthn assertion — lives in the
 *          headers, so an implementation can change completely without changing this type.
 *   - OUT: a tenant id, or `undefined`. Not a boolean, not a user, not a role. A TENANT ID,
 *          because every row in this system is tenant-scoped and the only question these
 *          handlers ever need answered is "whose data may this request see?".
 *
 * The `undefined` return is the whole safety property: a handler that gets no tenant id has
 * nothing to query. There is no ambient "current user", no fallback, no default tenant. Wiring
 * this up wrong therefore fails CLOSED — an implementation that returns `undefined` for
 * everything is a dashboard that shows nothing, never a dashboard that shows everything.
 *
 * IMPLEMENTOR'S OBLIGATIONS, when the cookie is finally built:
 *   1. VERIFY, do not trust. The tenant id must come from a signature or a session lookup,
 *      never from a header the client can set. `x-tenant-id` is not authentication.
 *   2. Return `undefined` on any failure — expired, malformed, unknown, revoked. Never throw
 *      to mean "denied"; a throw becomes a 500, and a 500 is not a 401.
 *   3. It may hit the database (a session table). That is why it is async.
 *
 * Note what this does NOT do: it does not authenticate DEVICES. Devices sign requests with
 * Ed25519 (`packages/protocol`) and only ever WRITE. Humans hold sessions and only ever READ.
 * Two doors, two mechanisms, no overlap — a stolen device key cannot read the dashboard, and a
 * stolen session cannot forge an upload.
 */
export type RequireSession = (
  headers: Record<string, string | undefined>,
) => Promise<string | undefined>;

/* ------------------------------------------------------------------ *
 * Wire types
 * ------------------------------------------------------------------ */

/** A stored snapshot as it leaves the database. `envelope` is opaque here and stays opaque. */
export interface StoredSnapshot {
  companyGuid: string;
  section: string;
  asOf: string;
  contentHash: string;
  envelope: SealedEnvelope;
  snapshotTs: number;
  seq: number;
  bytes: number;
  receivedAt: string;
}

/**
 * A device as the revocation UI sees it.
 *
 * No `publicKey`. It would be harmless — a public key verifies uploads, it cannot produce them
 * — but the revocation screen displays a label and a last-seen line, and shipping a field no
 * screen renders is how a field nobody audits ends up in a response. Send what is drawn.
 */
export interface DeviceSummary {
  deviceId: string;
  label: string;
  lastSeenIp: string | undefined;
  lastSeenAt: string | undefined;
  revokedAt: string | undefined;
  createdAt: string;
}

/** What `GET /api/snapshots` returns per row. */
export interface SnapshotView {
  companyGuid: string;
  section: string;
  asOf: string;
  contentHash: string;
  snapshotTs: number;
  seq: number;
  bytes: number;
  receivedAt: string;
  /** The sealed envelope, verbatim. The browser's job from here. */
  envelope: SealedEnvelope;
}

export interface JsonResponse<T> {
  status: number;
  body: { ok: true; data: T } | { ok: false; error: string };
}

const ok = <T>(data: T): JsonResponse<T> => ({ status: 200, body: { ok: true, data } });
const err = <T>(status: number, error: string): JsonResponse<T> => ({
  status,
  body: { ok: false, error },
});

export interface ReadDeps {
  requireSession: RequireSession;
  listSnapshots: (tenantId: string) => Promise<StoredSnapshot[]>;
  getWrappedKeys: (tenantId: string) => Promise<WrappedKey[]>;
  listDevices: (tenantId: string) => Promise<DeviceSummary[]>;
  tenantIdForDevice: (deviceId: string) => Promise<string | undefined>;
  /** Conditional UPDATE scoped to the tenant. Returns whether a row changed. */
  revokeDevice: (deviceId: string, tenantId: string) => Promise<boolean>;
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

/**
 * The sealed envelopes. Ciphertext only.
 *
 * The dashboard fetches these, unlocks the identity key with the passphrase, opens each
 * `sealedCek`, decrypts, and feeds `packages/viewmodel`. Every one of those steps happens in
 * the browser. This handler's entire contribution is: prove the caller owns a tenant, and hand
 * over that tenant's blobs.
 *
 * There is no server-side filtering, aggregation, search or sort-by-value here, and there can
 * never be — the server cannot read the values it would be sorting by. Anything richer than
 * "give me the envelopes" is a request to break the security model, and the answer is that the
 * browser already holds the plaintext and can do it locally.
 */
export async function handleListSnapshots(
  headers: Record<string, string | undefined>,
  deps: ReadDeps,
): Promise<JsonResponse<SnapshotView[]>> {
  const tenantId = await deps.requireSession(headers);
  if (!tenantId) return err(401, 'unauthorized');

  const rows = await deps.listSnapshots(tenantId);
  return ok(rows.map(toSnapshotView));
}

/**
 * Rebuild the response row field by field.
 *
 * A pass-through (`...row`) would be shorter and is the thing to resist: it makes every column
 * anyone ever adds to `snapshot` an automatic part of the public API, exported to the browser
 * with no diff in this file to review. The projection is the audit. If a field is in a
 * response, someone typed it here on purpose.
 *
 * `envelope` passes through whole, and that is correct: `packages/crypto` must receive the
 * exact object it sealed. Every field is bound into the AEAD tag, so picking it apart and
 * rebuilding it would risk producing something that no longer authenticates — and the AAD is
 * what stops a malicious server from shuffling a ciphertext into a different section or date.
 */
function toSnapshotView(r: StoredSnapshot): SnapshotView {
  return {
    companyGuid: r.companyGuid,
    section: r.section,
    asOf: r.asOf,
    contentHash: r.contentHash,
    snapshotTs: r.snapshotTs,
    seq: r.seq,
    bytes: r.bytes,
    receivedAt: r.receivedAt,
    envelope: r.envelope,
  };
}

/**
 * The wrapped identity blobs, so a browser can unlock with a passphrase.
 *
 * Each blob is the identity SECRET key encrypted under a key derived from something the server
 * does not have: the passphrase (Argon2id) or the recovery key (HKDF). Returning them to an
 * authenticated session is the design — it is what lets the owner open the dashboard from any
 * browser, with nothing to carry but what is in their head. The blobs are ciphertext; the
 * server holds no key that opens them and could not decrypt one on demand for anybody,
 * including a court.
 *
 * That said, they are the single most attackable thing here, because they are the only object
 * whose difficulty rests on a human-chosen secret rather than on 256 bits of entropy. Whoever
 * gets one can grind it offline, forever, with no rate limit we can impose. The mitigations are
 * Argon2id's parameters (`packages/crypto/src/kdf.ts`) and this session check. So:
 *
 *   - NEVER make this endpoint public "because it's encrypted anyway". The session check is not
 *     protecting confidentiality, it is denying an attacker the offline grind. Those are
 *     different defences and only one of them is cryptographic.
 *   - Rate-limit and log this endpoint when the session layer lands.
 *
 * The `kdf` params travel inside the blob, so parameters can be raised later without a
 * migration. Do not strip them: a blob without its salt is unopenable by its rightful owner.
 */
export async function handleGetWrappedKeys(
  headers: Record<string, string | undefined>,
  deps: ReadDeps,
): Promise<JsonResponse<WrappedKey[]>> {
  const tenantId = await deps.requireSession(headers);
  if (!tenantId) return err(401, 'unauthorized');

  return ok(await deps.getWrappedKeys(tenantId));
}

/**
 * The device list, for the revocation UI.
 *
 * `label` and `lastSeenIp` exist for exactly one reason: an owner staring at this screen has to
 * decide which row is the laptop that went missing. "dev_7f3a" is not a decision they can make;
 * "Accounts PC — last seen 2h ago from 49.36.x.x" is. A revocation UI that cannot be used with
 * confidence under stress does not get used, and an unused revocation UI is not a control.
 */
export async function handleListDevices(
  headers: Record<string, string | undefined>,
  deps: ReadDeps,
): Promise<JsonResponse<DeviceSummary[]>> {
  const tenantId = await deps.requireSession(headers);
  if (!tenantId) return err(401, 'unauthorized');

  return ok(await deps.listDevices(tenantId));
}

/**
 * Revoke a device.
 *
 * REVOCATION IS WHAT MAKES A STOLEN DEVICE KEY SURVIVABLE. Without it, a device key that leaks
 * — a stolen Tally PC, a copied config file — is permanent write access to the tenant, and the
 * only remedy is tearing down the deployment. With it, the remedy is one click, and the blast
 * radius is bounded by how fast the owner notices. This is a small handler carrying a large
 * share of the system's real-world security.
 *
 * What revocation does and does not do, precisely, because overclaiming here would be worse
 * than not shipping it:
 *   - It stops FUTURE uploads. `verifyRequest` rejects a revoked device (ingest.ts returns 403).
 *   - It does NOT retract what that device already wrote. Those envelopes are sealed to the
 *     tenant's identity key and are as authentic as any other. Rolling back bad data is a
 *     re-sync from Tally, which is affordable precisely because the server is a derivative
 *     cache and Tally is the source of truth.
 *   - It does NOT help against malware on the Tally PC itself, which reads Tally's plaintext
 *     files directly and never needed our key. See ARCHITECTURE.md.
 *
 * Two ordering decisions worth defending:
 *
 * OWNERSHIP IS CHECKED BEFORE ANYTHING ELSE. A device id is a guessable-ish opaque string; a
 * handler that revoked by id alone would let any authenticated tenant disable any other
 * tenant's uploads — a cross-tenant denial of service, in a multi-tenant deployment, from an
 * endpoint that looks like it only touches your own stuff.
 *
 * A DEVICE IN ANOTHER TENANT RETURNS 404, NOT 403. 403 means "it exists but is not yours" and
 * turns this endpoint into an oracle for probing which device ids exist across the whole
 * install. Unknown and not-yours are the same answer on purpose. This mirrors ingest.ts
 * collapsing "unknown device" and "bad signature" into one opaque 401.
 *
 * Revoking an already-revoked device returns 200. It is idempotent by intent, not by accident:
 * the owner clicked revoke and the device is revoked. Making the second click an error would
 * teach a panicking user that the button did not work.
 */
export async function handleRevokeDevice(
  headers: Record<string, string | undefined>,
  deviceId: string,
  deps: ReadDeps,
): Promise<JsonResponse<{ deviceId: string; revoked: true }>> {
  const tenantId = await deps.requireSession(headers);
  if (!tenantId) return err(401, 'unauthorized');

  if (!deviceId) return err(400, 'missing deviceId');

  const owner = await deps.tenantIdForDevice(deviceId);
  if (owner !== tenantId) return err(404, 'device not found');

  // The UPDATE is scoped to the tenant too, so the check above and the write cannot disagree
  // even if a device were reassigned between them.
  await deps.revokeDevice(deviceId, tenantId);

  return ok({ deviceId, revoked: true as const });
}
