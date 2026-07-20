import type { IsoDate, Section } from './model.ts';

/** Bumped when the wire format changes in a way old clients cannot read. */
export const ENVELOPE_VERSION = 1 as const;

/** Bumped when the normalized model changes shape. Part of the AAD. */
export const SCHEMA_VERSION = 1 as const;

/**
 * Associated data — authenticated but not encrypted.
 *
 * Every field here is bound into the AEAD tag, so the server cannot shuffle a ciphertext
 * into a different slot: not a different section, not a different company, not a different
 * date. Without this, a malicious server could replay last quarter's still-authentic
 * ciphertext as this quarter's and the dashboard would render stale numbers under a green
 * checkmark.
 *
 * Note what this does NOT give you: AEAD provides integrity, not freshness. The dashboard
 * must additionally reject any `snapshotTs` older than the newest it has already seen.
 */
export interface EnvelopeAad {
  v: typeof ENVELOPE_VERSION;
  tenantId: string;
  deviceId: string;
  companyGuid: string;
  section: Section;
  asOf: IsoDate;
  /** Unix millis at extraction. Monotonic per device; the freshness check keys off this. */
  snapshotTs: number;
  schemaVer: typeof SCHEMA_VERSION;
  /** Per-device monotonic counter. Gaps are visible; reuse is a replay signal. */
  seq: number;
}

/** The KDF descriptor travels with the wrapped key so parameters can be raised later. */
export interface KdfParams {
  v: 1;
  kdf: 'argon2id';
  /** Bytes. Raw integer — never libsodium's MEMLIMIT_* constants, whose values have changed. */
  m: number;
  /** Iterations. Raw integer — never libsodium's OPSLIMIT_* constants. */
  t: number;
  /** Parallelism. libsodium's crypto_pwhash pins this to 1. */
  p: 1;
  /** Base64. */
  salt: string;
}

/**
 * A secret key wrapped under some derived key. All fields base64.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THERE IS NO `roster` FIELD ON THIS TYPE, AND WHY THAT IS THE POINT.
 * ------------------------------------------------------------------------------------------
 *
 * The reader must learn the legitimate device public key(s) over a path the SERVER CANNOT
 * REWRITE (read `packages/crypto/src/trust.ts` before touching any of this). This blob is that
 * path: the server stores it and hands it back, but it is AEAD-sealed under a key derived from
 * the user's passphrase or recovery key, so the server can withhold it or corrupt it — and a
 * corrupted blob fails the Poly1305 tag — but it cannot rewrite what is inside.
 *
 * "Inside" is doing all the work in that sentence. A `roster` field HERE would be OUTSIDE the
 * ciphertext: a plaintext field on a JSON document the server serves, and therefore a field the
 * server picks the value of. Binding it into the AEAD's associated data would stop it being
 * *altered* undetectably, but it would still sit on this type as a plausible-looking
 * `DeviceRoster` that any reader could pluck off and pass to `openSection` WITHOUT unwrapping
 * anything — and `blob.roster` written by a dashboard developer in a hurry is a total,
 * silent defeat of envelope signing. There would be nothing to fail; the check would simply
 * never have run.
 *
 * So the roster is not a field here. It is carried in `IdentityBundle` — the PLAINTEXT that
 * this blob's `ciphertext` encrypts — and the only way to obtain it is `openIdentity()` in
 * @tally-bridge/crypto, which requires the passphrase, the recovery key, or the device key.
 * There is no field to misuse because there is no field.
 */
export interface WrappedKey {
  /**
   * 2, not 1: the sealed plaintext is now an `IdentityBundle` (JSON) rather than the raw 32
   * secret-key bytes. Nothing in the field opened a v1 blob — `wrapUnder*` had no production
   * call site when this changed — so there is no v1 compatibility path here, and there must not
   * be one: a reader that accepts a bare-idSK plaintext is a reader with no roster, i.e. one
   * with nothing to verify envelope signatures against.
   */
  v: 2;
  /** Which path can open this: passphrase-derived, recovery-key-derived, or device-bound. */
  kind: 'pass' | 'recovery' | 'device';
  /** Present for `pass` only — recovery keys are full-entropy and use HKDF, not Argon2id. */
  kdf?: KdfParams;
  nonce: string;
  ciphertext: string;
}

/**
 * One trusted device, as it travels inside a sealed `IdentityBundle`.
 *
 * `publicKey` is BASE64 here rather than the `Uint8Array` of crypto's `TrustedDevice`, because
 * this is a wire shape and a typed array canonicalizes to `{}` (see `canonicalStringify`). The
 * conversion — and the validation that goes with it — is `decodeRoster()`'s job.
 */
export type WireTrustedDevice = {
  /** Matched against `aad.deviceId`. */
  deviceId: string;
  /** Ed25519 public key, 32 bytes, base64. */
  publicKey: string;
};

/**
 * The pinned roster, as sealed inside an `IdentityBundle`.
 *
 * `version` is a MONOTONIC counter, bumped on every roster change (a pairing, a revocation).
 * It exists because AEAD gives integrity, not FRESHNESS: the server cannot forge a bundle, but
 * it chooses which of the bundles it stores to hand back, and an old one is perfectly
 * authentic. Rolling back to a roster that still lists a revoked device re-admits that device's
 * forgeries.
 *
 * A version number only helps a reader that REMEMBERS the highest it has seen, in storage the
 * server cannot reach. See `RosterMemory` in @tally-bridge/crypto — and see the residual
 * documented there, which is real and is not closed by this field.
 */
export type RosterDoc = {
  v: 1;
  /** Monotonic, starts at 1. Never reused, never decremented. */
  version: number;
  /** At least one. An empty roster verifies nothing and is refused on both sides. */
  devices: readonly WireTrustedDevice[];
};

/**
 * The plaintext sealed inside a `WrappedKey`.
 *
 * Type aliases rather than interfaces, deliberately, and for the reason `model.ts` spells out:
 * an interface has no implicit index signature and so is not assignable to `CanonicalValue`,
 * which would force the serializer call site to cast — at the one seam where a cast means the
 * compiler stops checking the bytes that carry the trust chain.
 */
export type IdentityBundle = {
  v: 1;
  /** X25519 identity secret key, 32 bytes, base64. */
  idSK: string;
  /**
   * Optional ON THE WIRE, never optional in meaning. A bundle without it is one written by the
   * low-level `wrapUnder*` primitives rather than by `wrapIdentity()`, and `openIdentity()`
   * REFUSES it loudly rather than defaulting to an empty roster (verify nothing) or a wildcard
   * (verify everything). See `ROSTER_MISSING` in @tally-bridge/crypto.
   */
  roster?: RosterDoc;
};

/** The uploaded unit. Everything except `aad` is opaque to the server. */
export interface SealedEnvelope {
  aad: EnvelopeAad;
  /** XChaCha20-Poly1305 nonce, 24 bytes, base64. */
  nonce: string;
  /** crypto_box_seal of the content key to the identity public key, base64. */
  sealedCek: string;
  /** brotli -> Padme -> XChaCha20-Poly1305. Base64. */
  ciphertext: string;
  /**
   * sha256 of the canonical plaintext, base64. Used as the upload idempotency key and to
   * gate re-uploads.
   *
   * This is a hash of PLAINTEXT the server never sees, so it does leak equality: the server
   * learns "this section is unchanged since last time". That is already obvious from the
   * upload simply not happening, so it reveals nothing new.
   */
  contentHash: string;
}
