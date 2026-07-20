import type { SealedEnvelope, Section } from '@tally-bridge/core';
import { ENVELOPE_VERSION, SECTIONS } from '@tally-bridge/core';
import {
  MAX_CLOCK_SKEW_MS,
  MAX_PAYLOAD_BYTES,
  ROUTES,
  checkQuota,
  quotaStatus,
  verifyRequest,
  type VerifyDeps,
  type VerifyFailure,
} from '@tally-bridge/protocol';

/**
 * The ingest handler.
 *
 * Written as pure logic over injected dependencies rather than inside a Next.js route, for one
 * reason: every interesting behaviour here is a SECURITY behaviour, and a security check that
 * can only be exercised by booting a framework and a database is a security check that will not
 * be exercised. The route file is a five-line adapter over this.
 *
 * What this endpoint can and cannot do is the product's central claim: it authenticates the
 * uploader, enforces freshness and quotas, and stores an opaque blob. It holds no key that
 * opens that blob. Full RCE here yields ciphertext.
 */

/**
 * `Omit<VerifyDeps, 'admit'>` is deliberate, and it is the enforcement — not a convenience.
 *
 * `admit` is VerifyDeps' admission gate (the rate limit, sat between "the signature is genuine"
 * and "spend a seen_nonce row"), and it is REQUIRED there. It is omitted HERE because it is not
 * a dependency of this handler: it is a POLICY this handler composes out of `reserveUpload` and
 * `checkQuota`, and it needs the request's byte count, which no dependency factory has.
 *
 * The consequence is the property worth having. A deps-builder — `ingestDepsFromSql`, a test
 * fixture, a future one nobody has written — CANNOT supply admit, so it cannot forget to. There
 * is exactly one place the gate can come from, `handleIngest` below, and it supplies it
 * unconditionally. "Every caller must remember to wire the rate limit" is the failure mode that
 * left the amplification open in the first place; the type now makes it unsayable rather than
 * merely discouraged.
 */
export interface IngestDeps extends Omit<VerifyDeps, 'admit'> {
  tenantIdForDevice: (deviceId: string) => Promise<string | undefined>;
  /**
   * What is already stored in this slot, for the freshness check.
   *
   * The content hash comes back with the timestamp because freshness alone cannot tell an
   * idempotent retry from a same-timestamp content swap — see the equal-`snapshotTs` branch in
   * `handleIngest`.
   */
  latestSnapshot: (
    tenantId: string,
    companyGuid: string,
    section: Section,
    asOf: string,
  ) => Promise<{ snapshotTs: number; contentHash: string } | undefined>;
  /**
   * ATOMICALLY record this upload attempt and return how many attempts are now in the trailing
   * hour, INCLUDING this one.
   *
   * This shape is the whole rate limit. The obvious alternative — a `uploadsInLastHour()` read,
   * a comparison, and a `recordUpload()` write afterwards — is a TOCTOU: the read and the write
   * are two round trips to Neon, and every request in flight during that gap sees the same
   * count and is waved through. Twenty concurrent sockets then buy twenty uploads for the price
   * of one slot, which is exactly the bill this cap exists to protect.
   *
   * Implement as ONE statement — an `INSERT ... RETURNING` alongside a windowed count, or an
   * upsert on a counter row. Never a SELECT followed by an INSERT.
   *
   * It counts ATTEMPTS, not successes: it is called before the body is parsed, so a device
   * flooding malformed payloads spends its own budget rather than getting an unmetered channel.
   */
  reserveUpload: (deviceId: string, bytes: number) => Promise<number>;
  tenantBytesStored: (tenantId: string) => Promise<number>;
  /** Upsert on (tenant, company, section, as_of). Idempotent by construction. */
  storeSnapshot: (row: {
    tenantId: string;
    companyGuid: string;
    section: Section;
    asOf: string;
    contentHash: string;
    envelope: SealedEnvelope;
    snapshotTs: number;
    seq: number;
    deviceId: string;
    bytes: number;
  }) => Promise<void>;
  touchDevice: (deviceId: string, ip: string | undefined) => Promise<void>;
}

export interface HttpResponse {
  status: number;
  body: { ok: true } | { ok: false; error: string };
}

const ok = (): HttpResponse => ({ status: 200, body: { ok: true } });
const err = (status: number, error: string): HttpResponse => ({ status, body: { ok: false, error } });

/**
 * What the admission gate decided, plus everything it learned getting there.
 *
 * `VerifyDeps.admit` may only answer yes/no with a string, because protocol has no opinion about
 * HTTP. But the RIGHT STATUS is not derivable from a yes/no: "rate limited" is 429, "tenant is
 * full" is 507, "the counters were unreadable" is 400. Collapsing all three into one status is
 * the same class of mistake as the `default:` that mapped them all to 401. So the gate records
 * its own verdict here and the handler reads it back, and the mapping stays exactly where it was
 * before the gate moved: `quotaStatus`.
 */
export type Gate = { ok: true; tenantId: string } | { ok: false; status: number; detail: string };

/**
 * What the admission gate needs. A structural subset of IngestDeps, split out (and exported)
 * because the device door now has TWO write endpoints — /api/sync and /api/wrapped-keys — and
 * both must run the SAME gate. A second, slightly different admission policy on the second
 * endpoint would be a second place for the amplification bug to come back.
 */
export interface AdmitDeps {
  tenantIdForDevice: (deviceId: string) => Promise<string | undefined>;
  reserveUpload: (deviceId: string, bytes: number) => Promise<number>;
  tenantBytesStored: (tenantId: string) => Promise<number>;
}

/**
 * THE ADMISSION GATE: reserve, then decide. This is the rate limit.
 *
 * It runs from inside `verifyRequest`, in the seat between "the signature is genuine" and
 * "spend a seen_nonce row" — see `VerifyDeps.admit` for why that is the only correct seat.
 *
 * The reservation is FIRST and is atomic, for the reasons on `IngestDeps.reserveUpload`: it
 * closes the read-then-write TOCTOU that lets twenty concurrent sockets each observe the same
 * count and all pass, and it meters ATTEMPTS rather than successes, so a stolen key flooding
 * garbage spends its own budget instead of getting an unmetered channel.
 *
 * FAIL CLOSED, and note how. `reserveUpload` returns NaN — not 0 — for a count it could not
 * read, and `NaN - 1` is NaN, which `checkQuota` refuses as `unmeasurable` rather than comparing
 * (every comparison with NaN is false, so a `>=` chain would let it WALK THROUGH all three
 * caps). The row is reserved either way, so failing closed costs the device one upload; failing
 * open costs the client the Neon bill this cap exists to protect.
 */
export async function admitDevice(
  deviceId: string,
  payloadBytes: number,
  deps: AdmitDeps,
): Promise<Gate> {
  // Before the reservation, because a device with no tenant has no quota to check against and no
  // row to store into. Opaque 401, as before: it is indistinguishable from an unknown device.
  const tenantId = await deps.tenantIdForDevice(deviceId);
  if (!tenantId) return { ok: false, status: 401, detail: 'unauthorized' };

  const uploadsInWindow = await deps.reserveUpload(deviceId, payloadBytes);
  const quota = checkQuota({
    payloadBytes,
    // Uploads that were already in the window before this one, so the limit keeps meaning
    // "the 61st request in an hour is refused".
    uploadsInLastHour: uploadsInWindow - 1,
    tenantBytesStored: await deps.tenantBytesStored(tenantId),
  });
  if (!quota.ok) {
    return { ok: false, status: quotaStatus(quota.failure), detail: quota.failure.kind };
  }
  return { ok: true, tenantId };
}

/**
 * Map a device-door verification failure to an HTTP response. Shared by every endpoint behind
 * the Ed25519 door (`handleIngest`, `handlePutWrappedKey`), so the two cannot drift into
 * answering the same failure with different statuses.
 *
 * EXHAUSTIVE ON PURPOSE — no `default` that maps the unrecognised to a guess.
 *
 * This switch had a `default: return err(401, 'unauthorized')`, and when protocol added
 * `not_admitted` the default silently swallowed it: a RATE LIMIT was reported to the Bridge
 * as an AUTH FAILURE. That is not cosmetic. 401 tells an operator to go re-enrol a device
 * that is working fine, and it hides the one signal that says "your key is being flooded".
 * The `never` binding below is what makes the NEXT new failure kind a compile error in this
 * file instead of a wrong status in production.
 */
export function deviceAuthFailureResponse(failure: VerifyFailure, gate: Gate | undefined): HttpResponse {
  switch (failure.kind) {
    case 'replayed_nonce':
      return err(409, 'replayed request');
    case 'clock_skew':
      // Actionable: this is almost always a wrong PC clock, not an attack.
      return err(401, 'request timestamp is outside the accepted window; check the system clock');
    case 'revoked_device':
      return err(403, 'device revoked');
    case 'not_admitted':
      // NOT 401. The signature was genuine — that is precisely why the gate got to run. The
      // status comes from `quotaStatus` via the gate's own verdict (429 rate_limited, 507
      // tenant full, 400 unmeasurable), so moving the check into `admit` did not flatten three
      // distinct answers into one. 429 is the floor if the verdict is somehow missing: this is
      // a refusal either way, and a refusal must never be reported as an acceptance.
      return err(gate && !gate.ok ? gate.status : 429, failure.detail);
    case 'missing_header':
    case 'malformed':
    case 'unknown_device':
    case 'unusable_clock':
    case 'bad_signature':
      // These collapse to one opaque message on purpose: distinguishing "unknown device" from
      // "bad signature" tells an attacker which device IDs exist. Listed one by one rather
      // than defaulted, so that adding a kind to this list is a decision someone made.
      return err(401, 'unauthorized');
    default: {
      // Unreachable, and CHECKED to be — a new VerifyFailure kind fails the build here.
      const unhandled: never = failure;
      void unhandled;
      return err(401, 'unauthorized');
    }
  }
}

export async function handleIngest(
  headers: Record<string, string | undefined>,
  rawBody: Uint8Array,
  deps: IngestDeps,
  clientIp?: string,
): Promise<HttpResponse> {
  // Size check BEFORE parsing. Parsing a 500MB body to discover it is too large is the DoS.
  if (rawBody.byteLength > MAX_PAYLOAD_BYTES) {
    return err(413, 'payload too large');
  }

  // Authenticate BEFORE parsing. An unauthenticated caller should not be able to reach the
  // JSON parser at all.
  //
  // THE QUOTA CHECK IS NOW INSIDE THIS CALL, and that is the fix, not a refactor.
  //
  // `verifyRequest` writes a seen_nonce row (`rememberNonce`) the moment a signature verifies,
  // and this handler's rate limiter used to run AFTERWARDS. So a stolen device key could take
  // 429 after 429 and still buy one PERMANENT row per request, at full request rate: the cap
  // bounded uploads and did not bound the table. The bill is the client's own Neon account —
  // the exact loss the cap exists to prevent — and there is no refund path for it.
  //
  // `admit` is the seat protocol opened between "the signature is genuine" and "spend a row".
  // Passing it here is what closes the hole; an unwired admit leaves it exactly as open as it
  // was, which is why VerifyDeps now REQUIRES it and IngestDeps refuses to carry it. The
  // ordering is not ours to choose and must not be re-litigated: earlier than the signature and
  // a keyless attacker burns a real device's budget (a bill DoS traded for an availability DoS);
  // later than rememberNonce and the limit runs after the write it exists to prevent.

  // A one-slot box rather than a plain `let`, and not for style. TypeScript narrows a captured
  // `let` from its initializer and does not model the closure's assignment — it would conclude
  // the verdict is always `undefined` and refuse to read it. A property keeps the declared type.
  const verdict: { gate?: Gate } = {};
  const auth = await verifyRequest(
    headers,
    // The route table, not a literal. This string must be byte-identical to the one the Bridge
    // signed (see packages/protocol/src/routes.ts); typing it out again here is how it stops
    // being.
    { method: ROUTES.sync.method, path: ROUTES.sync.path, body: rawBody },
    {
      ...deps,
      admit: async (deviceId) => {
        const decision = await admitDevice(deviceId, rawBody.byteLength, deps);
        verdict.gate = decision;
        return decision.ok ? { ok: true } : { ok: false, detail: decision.detail };
      },
    },
  );

  if (!auth.ok) {
    return deviceAuthFailureResponse(auth.failure, verdict.gate);
  }

  // The gate's verdict, read back for the tenant it already resolved.
  //
  // `verifyRequest` cannot return ok without calling admit first, so a missing verdict here is
  // impossible. This does not TRUST that: it is a claim about a function in another package, and
  // the whole bug being fixed was a claim like that written in a comment. If the gate did not
  // run, no reservation was made and no quota was checked — proceeding would store an unmetered
  // row, so it fails closed and loudly rather than silently doing the thing the gate exists to
  // prevent.
  const decided = verdict.gate;
  if (decided === undefined || !decided.ok) return err(500, 'the admission gate did not run');
  const tenantId = decided.tenantId;

  let envelope: SealedEnvelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(rawBody)) as SealedEnvelope;
  } catch {
    return err(400, 'body is not valid JSON');
  }

  const shape = validateEnvelope(envelope);
  if (shape) return err(400, shape);

  const aad = envelope.aad;

  // The AAD is authenticated, but only against the key the DEVICE holds. It is not a claim this
  // server can verify, so cross-check the parts that must match the authenticated identity.
  // Otherwise device A could write into device B's tenant.
  if (aad.deviceId !== auth.deviceId) return err(403, 'envelope device does not match signer');
  if (aad.tenantId !== tenantId) return err(403, 'envelope tenant does not match device');

  // FRESHNESS HAS A CEILING AS WELL AS A FLOOR.
  //
  // `snapshotTs` is the device's own claim about when it read Tally, and the floor below trusts
  // it to order snapshots. Unbounded, that trust is a permanent denial of service: one upload
  // stamped with the year 275760 makes every later honest upload for this slot "stale" forever.
  // Revoking the device does not undo it — the poisoned row stays, and nothing, re-sync
  // included, can land a lower timestamp. The slot dies for the life of the deployment.
  //
  // The ceiling is the clock-skew window, which costs an honest Bridge nothing: its request
  // timestamp is already held to that same window, so a device whose clock is inside the window
  // cannot produce a snapshotTs outside it. A device far enough ahead to trip this was going to
  // be rejected for skew anyway — and gets the actionable answer, not a mystery.
  if (aad.snapshotTs > deps.now() + MAX_CLOCK_SKEW_MS) {
    return err(400, 'aad.snapshotTs is in the future; check the system clock');
  }

  // FRESHNESS. AEAD gives integrity, not freshness: an older envelope is perfectly authentic.
  // Without this check a malicious server operator — or anyone who captured an old upload —
  // could roll the dashboard back to last quarter's numbers, and every cryptographic check
  // would still pass. The owner would see stale figures under a green checkmark and believe
  // them.
  const latest = await deps.latestSnapshot(tenantId, aad.companyGuid, aad.section, aad.asOf);
  if (latest !== undefined) {
    if (aad.snapshotTs < latest.snapshotTs) return err(409, 'stale snapshot');

    // An equal snapshot_ts is an idempotent retry — a lost ACK — and must be accepted, or the
    // Bridge backs off for no reason. But "idempotent" is a claim about the CONTENT, and only
    // the content hash can check it. The upsert keys on (tenant, company, section, as_of) and
    // REPLACES the row, so an equal-ts upload carrying different content is not a no-op: it
    // swaps the stored envelope while the freshness check reports that nothing moved. A real
    // retry re-sends the same bytes and therefore the same hash. Anything else is a different
    // snapshot wearing an old timestamp, and it does not get in on the retry path.
    if (aad.snapshotTs === latest.snapshotTs && envelope.contentHash !== latest.contentHash) {
      return err(409, 'conflicting content for an already-stored snapshotTs');
    }
  }

  await deps.storeSnapshot({
    tenantId,
    companyGuid: aad.companyGuid,
    section: aad.section,
    asOf: aad.asOf,
    contentHash: envelope.contentHash,
    envelope,
    snapshotTs: aad.snapshotTs,
    seq: aad.seq,
    deviceId: auth.deviceId,
    bytes: rawBody.byteLength,
  });
  await deps.touchDevice(auth.deviceId, clientIp);

  return ok();
}

/**
 * Structural validation.
 *
 * Note what is NOT validated: the ciphertext. We cannot read it and must not try. This checks
 * only that the envelope is shaped well enough to store and index — anything more would be
 * pretending to understand data we deliberately cannot see.
 */
function validateEnvelope(e: unknown): string | undefined {
  if (typeof e !== 'object' || e === null) return 'envelope is not an object';
  const env = e as Partial<SealedEnvelope>;

  if (!env.aad || typeof env.aad !== 'object') return 'missing aad';
  if (typeof env.nonce !== 'string') return 'missing nonce';
  if (typeof env.sealedCek !== 'string') return 'missing sealedCek';
  if (typeof env.ciphertext !== 'string') return 'missing ciphertext';
  if (typeof env.contentHash !== 'string') return 'missing contentHash';

  const a = env.aad;
  if (a.v !== ENVELOPE_VERSION) return `unsupported envelope version ${brief(a.v)}`;
  if (!isId(a.tenantId)) return 'missing aad.tenantId';
  if (!isId(a.deviceId)) return 'missing aad.deviceId';
  // Unlike tenantId and deviceId, this one is never cross-checked against a registered value —
  // it is whatever the device says, and it becomes part of a primary key. It gets a bound.
  if (!isId(a.companyGuid)) return 'missing aad.companyGuid';
  if (!SECTIONS.includes(a.section as Section)) return `unknown section ${brief(a.section)}`;
  if (typeof a.asOf !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(a.asOf)) return 'bad aad.asOf';
  // Number.isFinite is not the check these need. It admits 1.5, -1 and 2^53+1, all of which
  // reach a BIGINT column: the fractional and negative ones are nonsense the freshness check
  // then reasons about, and any of them can turn a correctly signed upload into a 500 raised
  // from inside the driver.
  if (!isCount(a.snapshotTs)) return 'bad aad.snapshotTs';
  if (!isCount(a.seq)) return 'bad aad.seq';

  return undefined;
}

/**
 * Echo an offending value back, but only a little of it.
 *
 * These two messages are worth keeping specific — "unsupported envelope version 2" is the
 * difference between a one-line support answer and an afternoon — but the value is attacker-
 * controlled and arrives from JSON.parse, so it can be a megabyte of anything. An error string
 * built from it lands in the response body and, if the route ever logs errors, in a Vercel log
 * that is retained and searchable. Echo a bounded slice or echo nothing.
 */
function brief(v: unknown): string {
  return String(v).slice(0, 40);
}

/** Ids are opaque to this server, so the only checks it can honestly make are shape and size. */
export const MAX_ID_LENGTH = 200;
export const isId = (v: unknown): v is string =>
  typeof v === 'string' && v.length > 0 && v.length <= MAX_ID_LENGTH;

/** A non-negative integer a Postgres BIGINT can hold and JavaScript can compare exactly. */
const isCount = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/**
 * Device registration, one shot.
 *
 * The endpoint self-disables after the first success (or after 24h) because it is the only
 * door that opens without a device key. Leaving it open would mean anyone who ever learns
 * BOOTSTRAP_SECRET — from a log, a screenshot, a support ticket — can enrol a device forever.
 */
export interface RegisterDeps {
  bootstrapConsumed: () => Promise<boolean>;
  bootstrapAgeMs: () => Promise<number>;
  expectedSecret: string | undefined;
  registerDevice: (deviceId: string, tenantId: string, publicKey: Uint8Array, label: string) => Promise<void>;
  consumeBootstrap: () => Promise<boolean>;
}

export const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

export async function handleRegister(
  // `unknown` fields, not optional strings. This body is `JSON.parse` output: a `string`
  // annotation here would be a claim the runtime never checks, and it would make the type
  // checker vouch for the exact confusion the handler has to defend against.
  body: {
    secret?: unknown;
    deviceId?: unknown;
    tenantId?: unknown;
    publicKey?: unknown;
    label?: unknown;
  },
  deps: RegisterDeps,
  compare: (a: string, b: string) => Promise<boolean>,
): Promise<HttpResponse> {
  if (!deps.expectedSecret) {
    // The env var was never set, so nothing can legitimately register. Fail closed rather than
    // treating "no secret configured" as "no secret required".
    return err(403, 'registration is not configured');
  }
  if (await deps.bootstrapConsumed()) return err(403, 'registration is closed');
  if ((await deps.bootstrapAgeMs()) > BOOTSTRAP_TTL_MS) return err(403, 'registration has expired');

  const { secret, deviceId, tenantId, publicKey, label } = body;

  // TYPE-CHECK, do not truth-check. `!secret` waves through anything truthy — and
  // `Buffer.from(x, 'base64')` IGNORES the encoding when handed an array, so a JSON body with
  // `publicKey: [1,2,...,32]` produces a perfectly valid 32-byte key from something that was
  // never base64. `tenantId` is worse: unchecked, an object or a 10MB string becomes the tenant
  // every row in this deployment is scoped to, forever, on the one endpoint that has no device
  // key to fall back on.
  if (typeof secret !== 'string' || !secret) return err(400, 'missing fields');
  if (!isId(deviceId) || !isId(tenantId)) return err(400, 'missing fields');
  if (typeof publicKey !== 'string' || !publicKey) return err(400, 'missing fields');
  if (label !== undefined && (typeof label !== 'string' || label.length > MAX_ID_LENGTH)) {
    return err(400, 'label is too long');
  }

  if (!(await compare(secret, deps.expectedSecret))) return err(403, 'invalid bootstrap secret');

  // Buffer.from(str, 'base64') never throws — it silently skips characters outside the alphabet
  // — so the length check below is what actually rejects, and a strictness check is what stops
  // a mangled key being enrolled as if it were the one the device holds. A device whose key was
  // silently corrupted here can never sign a request that verifies, and the one-shot bootstrap
  // is already spent: the deployment is bricked with no way back.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(publicKey)) {
    return err(400, 'publicKey must be a 32-byte Ed25519 key');
  }
  const key = new Uint8Array(Buffer.from(publicKey, 'base64'));
  if (key.length !== 32) return err(400, 'publicKey must be a 32-byte Ed25519 key');

  // Consume BEFORE registering, and bail if it was already taken. This is the race: two
  // concurrent requests must not both enrol. consumeBootstrap must be a conditional UPDATE
  // that reports whether it won.
  if (!(await deps.consumeBootstrap())) return err(403, 'registration is closed');

  await deps.registerDevice(deviceId, tenantId, key, label ?? '');
  return ok();
}
