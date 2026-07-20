import { sodiumReady, timingSafeEqual, wipe } from '@tally-bridge/crypto';

/**
 * Device request signing — Ed25519, in the shape of RFC 9421 HTTP Message Signatures.
 *
 * The Bridge must prove "I am the registered device for tenant T" WITHOUT holding anything that
 * can decrypt data and WITHOUT the user's passphrase. A signing key does exactly that, and the
 * distinction is why this key — and only this key — is the one that lives in Electron's
 * safeStorage (i.e. Windows DPAPI).
 *
 * Be clear-eyed about what DPAPI is worth: it protects against OTHER USERS on the machine, not
 * against other processes running as the SAME user — any of them can call CryptUnprotectData.
 * That is the VS Code / Slack token-theft class of attack. So the key kept there must be one
 * whose theft is SURVIVABLE and REVOCABLE. Steal this key and you can upload garbage until the
 * owner clicks "revoke device"; you cannot read a single number. Steal a data key and there is
 * no undo. That asymmetry is the entire argument.
 */

/** Signature is stale beyond this. Also the width of the replay window the nonce table closes. */
export const MAX_CLOCK_SKEW_MS = 300_000;

/**
 * Bounds on the signed fields. These are not tidiness — they are the write-amplification cap.
 *
 * Every one of these values arrives in a header from an unauthenticated request, and two of them
 * are spent on the CLIENT'S OWN Neon bill before anyone has paid for the privilege: `deviceId`
 * becomes a query parameter against the devices table, and `nonce` becomes a ROW in seen_nonce.
 * Unbounded, a single request writes a megabyte, and the rate limit — which counts requests, not
 * bytes — does not notice. The bill is the asset here and there is no refund path for it.
 *
 * MAX_DEVICE_ID_LENGTH matches the 200 that apps/server's registration endpoint will actually
 * enrol (MAX_ID_LENGTH in ingest.ts). A device that can be registered must be able to sign, so
 * these two numbers are a pair; if that one moves, this one moves with it.
 *
 * MAX_NONCE_LENGTH is 64 against a real nonce of 24 (base64 of 128 bits). The slack is for a
 * future nonce shape, not for an attacker: it costs nothing and it is still four orders of
 * magnitude below "a megabyte per request".
 */
export const MAX_DEVICE_ID_LENGTH = 200;
export const MAX_NONCE_LENGTH = 64;
export const MAX_METHOD_LENGTH = 16;
export const MAX_PATH_LENGTH = 2048;

export interface SignatureInput {
  deviceId: string;
  method: string;
  path: string;
  /** Unix millis. */
  timestamp: number;
  /** 128 bits, base64. Must be unique per request — the server enforces it. */
  nonce: string;
  /** Raw request body bytes. */
  body: Uint8Array;
}

/**
 * Build the string that gets signed.
 *
 * THIS FUNCTION IS THE CONTRACT. Signer and verifier must produce byte-identical output or
 * every request 401s, so both sides call this one implementation rather than each building the
 * string from the spec. A shared helper is not a convenience here; it is the only way to make
 * the two sides provably agree.
 *
 * The body is covered by its SHA-256 rather than inlined, so signing does not require buffering
 * the payload twice and the string stays a fixed shape.
 */
/**
 * Thrown when a field would corrupt the framing. Callers turn this into a 400, never a 500.
 */
export class SigningFieldError extends Error {
  constructor(field: string, detail: string) {
    super(`invalid ${field}: ${detail}`);
    this.name = 'SigningFieldError';
  }
}

/**
 * The delimiter must not appear in the data. THIS IS ENFORCED, NOT ASSUMED.
 *
 * The fields are newline-joined with no length prefixes, so the framing is only injective if
 * no field can contain the delimiter. That used to be asserted in a comment ("none of them may
 * contain a newline") and checked nowhere — and an unenforced invariant is a comment, not a
 * defence.
 *
 * What the gap actually bought an attacker: two DIFFERENT tuples serialising to identical
 * bytes, so one Ed25519 signature authenticates both. Shift the boundaries and a path swallows
 * a body hash, a timestamp and a nonce, while the nonce on the other side swallows the rest:
 *
 *   deviceId=d, POST, path="/api/sync\n<hashB>\n<tsB>\nnonceB", hash=<hashA>, ts=<tsA>, nonce=n
 *   deviceId=d, POST, path="/api/sync", hash=<hashB>, ts=<tsB>, nonce="nonceB\n<hashA>\n<tsA>\nn"
 *
 * — same string, so a signature over a ₹1 body verifies a ₹999999 body. Ed25519 was doing its
 * job perfectly; the serialisation was lying to it. deviceId is the sharpest field of the six,
 * because verifyRequest takes it from an attacker-supplied header and feeds it back in here
 * before anything has been authenticated.
 *
 * \r is refused alongside \n: it terminates a line in enough parsers that treating it as
 * ordinary data is the same bet with worse odds.
 */
const DELIMITER = '\n';

function checkField(name: string, value: string, maxLength: number): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new SigningFieldError(name, 'must be a non-empty string');
  }
  if (value.length > maxLength) {
    throw new SigningFieldError(name, `must be at most ${maxLength} characters`);
  }
  if (value.includes(DELIMITER) || value.includes('\r')) {
    throw new SigningFieldError(name, 'must not contain a newline or carriage return');
  }
}

export async function buildSigningString(input: SignatureInput): Promise<string> {
  // Before `.toUpperCase()`, which is a method call on unvalidated input and throws a TypeError
  // — not a SigningFieldError — on anything that is not a string.
  checkField('method', typeof input.method === 'string' ? input.method : '', MAX_METHOD_LENGTH);
  const method = input.method.toUpperCase();
  // Every attacker-reachable component, before it is framed. The body is not checked because it
  // is not framed — it enters as a fixed-width hash, which is the whole reason it is hashed.
  checkField('deviceId', input.deviceId, MAX_DEVICE_ID_LENGTH);
  checkField('method', method, MAX_METHOD_LENGTH);
  checkField('path', input.path, MAX_PATH_LENGTH);
  checkField('nonce', input.nonce, MAX_NONCE_LENGTH);
  if (!Number.isFinite(input.timestamp)) {
    throw new SigningFieldError('timestamp', 'must be a finite number');
  }

  const digest = await crypto.subtle.digest('SHA-256', input.body as BufferSource);
  const bodyHash = base64(new Uint8Array(digest));

  // Newline-delimited with a fixed field order. The framing is injective because no component
  // contains the delimiter, so the six fields parse back out exactly one way.
  const fields = [
    input.deviceId,
    method,
    input.path,
    bodyHash,
    String(input.timestamp),
    input.nonce,
  ];

  // THE POST-CONDITION, not a comment.
  //
  // The per-field checks above are an ENUMERATION: they are correct only for exactly the fields
  // someone remembered to list, in exactly the types someone anticipated. Two of the six are not
  // in that enumeration at all — `bodyHash` is trusted to be base64, `String(timestamp)` is
  // trusted to be digits — and a seventh field added later would be trusted by default, because
  // forgetting to add a line here is silent. That is precisely how this bug existed the first
  // time: the invariant was asserted where it could not be checked.
  //
  // So the invariant is re-established on the OUTPUT, where it is universally quantified over
  // whatever the fields actually turned out to be. It cannot be bypassed by a field type nobody
  // anticipated, because it does not know or care which field it is looking at. An unambiguous
  // length-prefixed encoding would get this property structurally, and would be the better
  // design on a greenfield wire — but it is a BREAKING wire change that 401s every deployed
  // Bridge until it updates, and this check buys the same guarantee for the same bytes: after
  // it, `fields.join('\n')` is injective, and that is the only property the signature needs.
  for (let i = 0; i < fields.length; i++) {
    if (fields[i]!.includes(DELIMITER)) {
      throw new SigningFieldError(`field ${i}`, 'contains the framing delimiter');
    }
  }
  return fields.join(DELIMITER);
}

export interface DeviceKeypair {
  deviceId: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export async function generateDeviceKeypair(deviceId: string): Promise<DeviceKeypair> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_sign_keypair();
  return { deviceId, publicKey: kp.publicKey, secretKey: kp.privateKey };
}

/**
 * A `type`, not an `interface`, deliberately.
 *
 * TypeScript gives object-literal type aliases an implicit index signature; interfaces get
 * none. So as an interface, the very headers `signRequest` produces could not be passed to
 * `verifyRequest` (which takes `Record<string, string | undefined>`) without a cast — every
 * real caller would hit that friction and paper over it with `as any`, which is exactly how
 * a header check gets silently bypassed later.
 */
export type SignedHeaders = {
  'x-tb-device': string;
  'x-tb-timestamp': string;
  'x-tb-nonce': string;
  'x-tb-signature': string;
};

/** Sign a request. Called by the Bridge on every upload. */
export async function signRequest(
  input: Omit<SignatureInput, 'nonce' | 'timestamp'> & { timestamp?: number; nonce?: string },
  secretKey: Uint8Array,
): Promise<SignedHeaders> {
  const sodium = await sodiumReady();
  const nonce = input.nonce ?? base64(sodium.randombytes_buf(16));
  const timestamp = input.timestamp ?? Date.now();
  const signingString = await buildSigningString({ ...input, nonce, timestamp });
  const sig = sodium.crypto_sign_detached(new TextEncoder().encode(signingString), secretKey);
  return {
    'x-tb-device': input.deviceId,
    'x-tb-timestamp': String(timestamp),
    'x-tb-nonce': nonce,
    'x-tb-signature': base64(sig),
  };
}

export type VerifyFailure =
  | { kind: 'missing_header'; header: string }
  | { kind: 'malformed'; detail: string }
  | { kind: 'unknown_device' }
  | { kind: 'revoked_device' }
  | { kind: 'clock_skew'; skewMs: number }
  /** `now()` did not return a usable instant. Fail closed: an unmeasurable skew is not a pass. */
  | { kind: 'unusable_clock' }
  | { kind: 'replayed_nonce' }
  /** The caller's admission gate said no — typically the rate limit. Carries its reason. */
  | { kind: 'not_admitted'; detail: string }
  | { kind: 'bad_signature' };

export type VerifyResult = { ok: true; deviceId: string } | { ok: false; failure: VerifyFailure };

export interface VerifyDeps {
  /** Returns the device's Ed25519 public key, or undefined if unknown. */
  lookupDevice: (deviceId: string) => Promise<{ publicKey: Uint8Array; revoked: boolean } | undefined>;
  /**
   * Atomically record the nonce. MUST return false if it has been seen before.
   *
   * Implement with a UNIQUE constraint and treat the violation as "seen" — never a
   * SELECT-then-INSERT, which races two concurrent replays straight through.
   */
  rememberNonce: (deviceId: string, nonce: string, expiresAt: number) => Promise<boolean>;
  /**
   * REQUIRED. The seat between "this signature is genuine" and "we are willing to spend a
   * database row on it". Wire the rate limit here.
   *
   * THE BUG THIS EXISTS FOR: rememberNonce is a WRITE, and it used to be the FIRST thing that
   * happened to an authenticated request — before handleIngest had reached its rate limiter. So
   * a stolen device key could grow seen_nonce without bound at full request rate. The victim is
   * not us: it is the CLIENT'S OWN Neon bill, the exact thing the quota cap exists to protect,
   * and a $400 overage on a small business's card has no refund path. A rate limit that runs
   * after the write it is supposed to prevent is not a rate limit.
   *
   * WHY HERE AND NOT EARLIER: an admission gate that ran before the signature check would let an
   * attacker with NO KEY AT ALL burn a real device's hourly budget — trading a bill DoS for an
   * availability DoS, at a lower cost to the attacker. The gate must sit after the signature and
   * before the write, and this is the only point that is both.
   *
   * WHY IT DOES NOT OPEN A REPLAY HOLE: this runs BEFORE rememberNonce, so a rejection here
   * means the nonce was never consumed and the request never took effect — no state changed, so
   * there is nothing to replay. rememberNonce remains the last gate before ok:true; no path
   * returns ok without passing it.
   *
   * WHY IT IS REQUIRED. It was optional for exactly one reason: making it required would have
   * broken the build of a package this one does not own, before that package had wired it.
   * apps/server's handleIngest now wires it, and it is the only caller — so the reason is spent,
   * and what optionality leaves behind is a security seat a caller can omit without a word from
   * the compiler. An unwired admit is not a degraded mode; it is the ORIGINAL BUG silently
   * restored, with the amplification exactly as open as it was. "Optional, but every caller must
   * remember to pass it" is an invariant asserted in a doc comment — the shape this file already
   * learned not to trust (see DELIMITER, and bootstrapSecretMatches). The type is the enforcement.
   *
   * Note for a future dependency-builder: this is deliberately NOT something a `depsFromSql`-style
   * factory can supply, and apps/server models that by omitting it from IngestDeps. It is not a
   * database primitive — it is a POLICY composed of a reservation and a quota decision, and it
   * needs the request's byte count, which no factory has. The handler builds it per request.
   */
  admit: (deviceId: string) => Promise<{ ok: true } | { ok: false; detail: string }>;
  now: () => number;
}

/**
 * Verify a signed request.
 *
 * Order matters and is chosen deliberately: cheap rejections first, and the SIGNATURE IS
 * CHECKED BEFORE THE NONCE IS CONSUMED. Consuming the nonce first would let an unauthenticated
 * attacker burn arbitrary nonces and grow the table for free.
 */
export async function verifyRequest(
  headers: Record<string, string | undefined>,
  request: { method: string; path: string; body: Uint8Array },
  deps: VerifyDeps,
): Promise<VerifyResult> {
  const get = (h: keyof SignedHeaders) => headers[h] ?? headers[h.toLowerCase()];

  for (const h of ['x-tb-device', 'x-tb-timestamp', 'x-tb-nonce', 'x-tb-signature'] as const) {
    if (!get(h)) return { ok: false, failure: { kind: 'missing_header', header: h } };
  }

  // TYPE-CHECK THE HEADERS BEFORE ANYTHING TOUCHES THEM.
  //
  // The parameter says `string | undefined`; the runtime is an HTTP request, and a TypeScript
  // annotation is a claim about what a caller promised, not a fact about what arrived. A
  // duplicated header can surface as an array, and an array is truthy — so the presence loop
  // above passes it, and `deviceId` reached lookupDevice AS AN ARRAY, i.e. as a database query
  // parameter, before any signature had been checked. The only function that type-checks these
  // (buildSigningString) does not run until later.
  for (const h of ['x-tb-device', 'x-tb-timestamp', 'x-tb-nonce', 'x-tb-signature'] as const) {
    if (typeof get(h) !== 'string') {
      return { ok: false, failure: { kind: 'malformed', detail: `${h} is not a single header value` } };
    }
  }

  const deviceId = get('x-tb-device')!;
  const nonce = get('x-tb-nonce')!;

  // BOUND THE UNAUTHENTICATED INPUT BEFORE SPENDING THE CLIENT'S MONEY ON IT.
  //
  // deviceId becomes a query against Neon and nonce becomes a ROW in Neon, and both of those
  // bills land on the client. Neither may be unbounded in size, and the check has to be HERE —
  // buildSigningString enforces the same bounds, but it does not run until after lookupDevice
  // has already gone to the database.
  try {
    checkField('deviceId', deviceId, MAX_DEVICE_ID_LENGTH);
    checkField('nonce', nonce, MAX_NONCE_LENGTH);
  } catch (e) {
    return {
      ok: false,
      failure: { kind: 'malformed', detail: e instanceof SigningFieldError ? e.message : 'bad header' },
    };
  }

  const timestamp = Number(get('x-tb-timestamp'));
  if (!Number.isFinite(timestamp)) {
    return { ok: false, failure: { kind: 'malformed', detail: 'timestamp is not a number' } };
  }

  let signature: Uint8Array;
  try {
    signature = unbase64(get('x-tb-signature')!);
  } catch {
    return { ok: false, failure: { kind: 'malformed', detail: 'signature is not base64' } };
  }

  // The clock, BEFORE it is used in a comparison.
  //
  // THE FAIL-OPEN THIS CLOSES: the skew test below is a single `>`, and every comparison against
  // NaN is false. A `now()` returning NaN therefore did not FAIL the skew check, it SKIPPED it —
  // and verifyRequest returned ok:true for a request of any age whatsoever. The ±300s window is
  // what bounds how long a captured request stays replayable once its nonce row has aged out, so
  // losing the window silently is losing the outer half of the replay defence. This is the same
  // bug shape `measurable()` already closes in quota.ts, on the clock instead of the counters:
  // an unmeasurable skew must answer "no", never "yes".
  const now = deps.now();
  if (!Number.isFinite(now)) {
    return { ok: false, failure: { kind: 'unusable_clock' } };
  }

  const device = await deps.lookupDevice(deviceId);
  if (!device) return { ok: false, failure: { kind: 'unknown_device' } };
  // Revocation is why stealing this key is survivable: one click and the attacker has nothing.
  if (device.revoked) return { ok: false, failure: { kind: 'revoked_device' } };

  // Both directions: `Math.abs` makes a future-dated timestamp as stale as an ancient one, which
  // matters because a clock ahead by an hour is a common Indian SMB PC, not an attack.
  const skew = Math.abs(now - timestamp);
  if (skew > MAX_CLOCK_SKEW_MS) {
    return { ok: false, failure: { kind: 'clock_skew', skewMs: skew } };
  }

  // buildSigningString now REFUSES a field that would corrupt the framing, and every one of
  // those fields arrives here from an unauthenticated request. So the refusal has to become a
  // clean 400 — an uncaught throw would hand an attacker a way to crash a serverless function
  // with a single header, without a key, without an account.
  let signingString: string;
  try {
    signingString = await buildSigningString({
      deviceId,
      method: request.method,
      path: request.path,
      timestamp,
      nonce,
      body: request.body,
    });
  } catch (e) {
    return {
      ok: false,
      failure: { kind: 'malformed', detail: e instanceof Error ? e.message : 'unsignable request' },
    };
  }

  const sodium = await sodiumReady();
  let valid: boolean;
  try {
    valid = sodium.crypto_sign_verify_detached(
      signature,
      new TextEncoder().encode(signingString),
      device.publicKey,
    );
  } catch {
    // libsodium throws on a wrong-length signature rather than returning false.
    return { ok: false, failure: { kind: 'bad_signature' } };
  }
  if (!valid) return { ok: false, failure: { kind: 'bad_signature' } };

  // The signature is genuine. NOTHING HAS BEEN WRITTEN YET — and this is the last moment that is
  // still true, so it is where the caller gets to decline to spend a row. See VerifyDeps.admit:
  // rejecting here costs the attacker a request and costs the client nothing.
  const admitted = await deps.admit(deviceId);
  if (!admitted.ok) {
    return { ok: false, failure: { kind: 'not_admitted', detail: admitted.detail } };
  }

  // Only now consume the nonce. WITHOUT THIS STEP, the clock-skew window IS a 5-minute replay
  // window: a captured request could be re-sent verbatim, with a valid signature, until the
  // timestamp aged out.
  //
  // The TTL is the END OF THE SKEW WINDOW, and that equality is what makes pruning safe. A
  // request stamped T verifies exactly while |now - T| <= MAX_CLOCK_SKEW_MS, so the last instant
  // it can be replayed is T + MAX_CLOCK_SKEW_MS — which is precisely when the row is allowed to
  // die. `DELETE WHERE expires_at < now()` therefore cannot open a replay window: every row it
  // removes belongs to a request the skew check already refuses on its own. Prune anything
  // older; keep nothing longer. (Note for the implementer: prune on the SAME clock this `now()`
  // comes from, or the two windows drift apart at the seam.)
  const fresh = await deps.rememberNonce(deviceId, nonce, timestamp + MAX_CLOCK_SKEW_MS);
  if (!fresh) return { ok: false, failure: { kind: 'replayed_nonce' } };

  return { ok: true, deviceId };
}

/**
 * One-shot bootstrap secret comparison.
 *
 * The chicken-and-egg: how does the FIRST device authenticate, before any device is trusted?
 * Because the desktop app provisions the Vercel deployment itself, it mints this secret and
 * sets it as an env var BEFORE the first deploy — so provisioning and trust-bootstrap are the
 * same step and no out-of-band channel is needed.
 */
export async function bootstrapSecretMatches(
  presented: string,
  expected: string,
): Promise<boolean> {
  // NOTHING MATCHES NOTHING.
  //
  // The natural call is `bootstrapSecretMatches(body.secret, process.env.BOOTSTRAP_SECRET)`, and
  // `process.env.X` is `string | undefined`. The trap: `new TextEncoder().encode(undefined)` does
  // NOT encode the text "undefined" — the WebIDL default makes the argument the EMPTY STRING. So
  // an unset secret encoded to zero bytes, a presented `""` encoded to zero bytes, the lengths
  // agreed, and `memcmp(empty, empty)` is TRUE. Presenting an empty secret authenticated against
  // a secret that does not exist, on the one endpoint that has no device key behind it.
  //
  // apps/server does guard this at the call site today (`if (!deps.expectedSecret)`), so this was
  // not live — but "safe as long as every caller remembers the guard" is the property that fails
  // the first time someone adds a second caller. The primitive fails closed on its own.
  if (typeof presented !== 'string' || typeof expected !== 'string') return false;
  if (presented.length === 0 || expected.length === 0) return false;

  const sodium = await sodiumReady();
  const a = new TextEncoder().encode(presented);
  const b = new TextEncoder().encode(expected);
  // Constant-time: this is an attacker-submittable secret, so a byte-by-byte early exit would
  // leak it one character at a time. The length comparison leaks only the length, which is not
  // the secret and cannot be avoided while comparing buffers at all.
  if (a.length !== b.length) return false;
  return timingSafeEqual(sodium, a, b);
}

export function base64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}

export function unbase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

export { wipe };
