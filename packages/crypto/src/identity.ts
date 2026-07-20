import {
  canonicalStringify,
  type CanonicalValue,
  type IdentityBundle,
  type KdfParams,
  type RosterDoc,
  type WrappedKey,
} from '@tally-bridge/core';
import { sodiumReady, timingSafeEqual, wipe } from './sodium.ts';
import {
  KDF_INFO,
  defaultKdfParams,
  deriveRoot,
  fromBase64,
  hkdf,
  randomSalt,
  toBase64,
} from './kdf.ts';
import {
  RosterError,
  acceptRosterVersion,
  decodeRoster,
  encodeRoster,
  type DeviceRoster,
  type RosterMemory,
  type SealedRoster,
} from './trust.ts';

/**
 * The identity keypair — the root of the read capability.
 *
 *   passphrase --Argon2id--> root --HKDF--> KEK
 *                                            | wraps
 *                                            v
 *                                    idSK (X25519 secret)
 *
 *   idPK (X25519 public) --> the Bridge holds ONLY this
 *
 * The asymmetry is the design. The Bridge needs to ENCRYPT; it never needs to read anything
 * back. Symmetric crypto conflates those capabilities, so the obvious approach (keep a data
 * key in Windows DPAPI so the unattended syncer can encrypt) means that stealing the DPAPI
 * blob decrypts the entire server history. Public-key crypto separates them: give the Bridge
 * a public key and it is structurally incapable of reading its own uploads.
 *
 * Compromise of the client PC therefore becomes forward-only — and forward compromise is
 * already free to an attacker via Tally's own plaintext data files on that same disk. So the
 * marginal value of stealing anything we store is ~zero, which is the correct place to be.
 */
export interface Identity {
  /** X25519 public key, 32 bytes. Safe to ship to the Bridge, log, and store in plaintext. */
  publicKey: Uint8Array;
  /** X25519 secret key, 32 bytes. Never leaves the dashboard/unlocked-app process memory. */
  secretKey: Uint8Array;
}

export async function generateIdentity(): Promise<Identity> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

/** 256 bits of real entropy. Rendered to the user as BIP39 words + a QR of these raw bytes. */
export async function generateRecoveryKey(): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  return sodium.randombytes_buf(32);
}

/**
 * ------------------------------------------------------------------------------------------
 * THE SEALED BUNDLE — what actually goes inside a WrappedKey's ciphertext.
 * ------------------------------------------------------------------------------------------
 *
 * It used to be the 32 raw bytes of idSK. It is now a JSON `IdentityBundle` carrying idSK AND
 * the pinned device roster, because the roster has to reach the reader over a path the server
 * cannot rewrite and this ciphertext is the only such path the user already unlocks (read
 * trust.ts, and the comment on `WrappedKey` in @tally-bridge/core, before changing any of it).
 *
 * Canonical JSON rather than JSON.stringify, for one reason that matters: `wrapIdentity` seals
 * the SAME bundle three times under three different keys, and verifying afterwards that the
 * three agree is a byte comparison. Key order wobbling between calls would turn that check into
 * a coin flip. It also rejects `undefined` rather than dropping it, so a roster that went
 * missing between build and seal throws instead of vanishing.
 */
const BUNDLE_VERSION = 1;

/** Exactly the 44 characters a base64'd 32-byte key occupies: 43 payload + one '='. */
const KEY_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

function encodeBundle(idSK: Uint8Array, roster: RosterDoc | undefined): Uint8Array {
  if (!(idSK instanceof Uint8Array) || idSK.length !== 32) {
    throw new Error(
      `identity secret key must be 32 bytes, got ` +
        `${idSK instanceof Uint8Array ? String(idSK.length) : typeof idSK}`,
    );
  }
  // Built by branching rather than by assigning `roster: undefined`, because
  // `canonicalStringify` throws on an undefined value — correctly, since a silently dropped key
  // is an undetectable data change. Here that would be the difference between "no roster was
  // ever set" and "the roster vanished", and those must not look the same.
  const bundle: IdentityBundle = roster
    ? { v: BUNDLE_VERSION, idSK: toBase64(idSK), roster }
    : { v: BUNDLE_VERSION, idSK: toBase64(idSK) };
  return new TextEncoder().encode(canonicalStringify(bundle as unknown as CanonicalValue));
}

/**
 * Parse a bundle out of decrypted plaintext.
 *
 * Everything here has already passed the Poly1305 tag, so this is not defending against an
 * attacker — it is defending against a future version of us, and against the one hostile input
 * that DOES reach it: plaintext from a blob written by an older or different implementation.
 */
function decodeBundle(plaintext: Uint8Array): IdentityBundle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
  } catch {
    // A v1 blob (raw idSK bytes) lands exactly here, and this is the message it deserves: the
    // key is fine, the format is old, and an old format means NO ROSTER — which means nothing
    // to verify envelope signatures against. Refused, loudly, not defaulted.
    throw new RosterError(
      'this wrapped key does not contain an identity bundle (it may predate roster ' +
        'distribution). Re-wrap the identity with wrapIdentity(); a bundle with no roster ' +
        'gives the reader no device keys to verify envelope signatures against.',
    );
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new RosterError('identity bundle is not an object');
  }
  const b = parsed as Partial<IdentityBundle>;
  if (b.v !== BUNDLE_VERSION) {
    throw new RosterError(`unsupported identity bundle version ${String(b.v)}`);
  }
  if (typeof b.idSK !== 'string' || !KEY_BASE64.test(b.idSK)) {
    throw new RosterError('identity bundle does not carry a 32-byte base64 secret key');
  }
  return b as IdentityBundle;
}

function bundleSecretKey(bundle: IdentityBundle): Uint8Array {
  const idSK = fromBase64(bundle.idSK);
  // `fromBase64` is atob-based and throws on a bad alphabet, unlike `Buffer.from(x,'base64')`
  // which silently discards. The regex above ran first regardless; this is the length proof.
  if (idSK.length !== 32) {
    throw new RosterError(`identity secret key must be 32 bytes, got ${idSK.length}`);
  }
  return idSK;
}

async function wrap(
  idSK: Uint8Array,
  wrappingKey: Uint8Array,
  kind: WrappedKey['kind'],
  roster: RosterDoc | undefined,
  kdf?: KdfParams,
): Promise<WrappedKey> {
  const sodium = await sodiumReady();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plaintext = encodeBundle(idSK, roster);
  try {
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      // Bind the wrap kind so a recovery-wrapped key cannot be presented as a device-wrapped
      // one and vice versa.
      //
      // NOTE what is deliberately NOT bound here: the roster, and the blob's `v`. Both are
      // INSIDE the ciphertext, which is strictly stronger than binding a cleartext copy as
      // associated data — there is no cleartext copy to bind, so there is nothing for the
      // server to twiddle and no way for a reader to read the roster without the wrapping key.
      // Binding a cleartext `rosterVersion` as AAD was considered and rejected: it would let the
      // server turn a roster question into a Poly1305 failure, which surfaces to the owner as
      // "your passphrase is wrong". Misdiagnosing an attack as a typo is the failure this
      // codebase's recovery path exists to prevent.
      kind,
      null,
      nonce,
      wrappingKey,
    );
    const out: WrappedKey = { v: 2, kind, nonce: toBase64(nonce), ciphertext: toBase64(ct) };
    if (kdf) out.kdf = kdf;
    return out;
  } finally {
    // The bundle plaintext holds idSK in base64. Best-effort scrub: narrows the window for a
    // heap dump, does not close it (the intermediate string from toBase64 is immutable and
    // beyond our reach).
    plaintext.fill(0);
  }
}

async function unwrapBundle(blob: WrappedKey, wrappingKey: Uint8Array): Promise<IdentityBundle> {
  const sodium = await sodiumReady();
  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    fromBase64(blob.ciphertext),
    blob.kind,
    fromBase64(blob.nonce),
    wrappingKey,
  );
  try {
    return decodeBundle(plaintext);
  } finally {
    wipe(sodium, plaintext);
  }
}

async function unwrap(blob: WrappedKey, wrappingKey: Uint8Array): Promise<Uint8Array> {
  return bundleSecretKey(await unwrapBundle(blob, wrappingKey));
}

/**
 * Wrap the identity secret under a passphrase. Stored server-side; opaque to the server.
 *
 * `roster` is optional HERE and nowhere else. This is a primitive: it wraps one key under one
 * derived key, and it is the wrong place to enforce a cross-wrap invariant it cannot see. The
 * product writer is `wrapIdentity()`, which requires a roster and mints all three wraps from
 * it. A blob written without one is not a security hole — `openIdentity()` REFUSES it rather
 * than inventing an empty or wildcard roster — it is simply a blob no reader can use to verify
 * anything, and it says so.
 */
export async function wrapUnderPassphrase(
  idSK: Uint8Array,
  passphrase: string,
  roster?: RosterDoc,
): Promise<WrappedKey> {
  const params = defaultKdfParams(await randomSalt());
  const root = await deriveRoot(passphrase, params);
  const kek = await hkdf(root, KDF_INFO.kek);
  try {
    return await wrap(idSK, kek, 'pass', roster, params);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, root, kek);
  }
}

export async function unwrapWithPassphrase(
  blob: WrappedKey,
  passphrase: string,
): Promise<Uint8Array> {
  if (blob.kind !== 'pass' || !blob.kdf) {
    throw new Error(`not a passphrase-wrapped key (kind=${blob.kind})`);
  }
  // Derive with the blob's own params, never this module's defaults — that is what allows
  // parameters to be raised later without orphaning existing keys.
  const root = await deriveRoot(passphrase, blob.kdf);
  const kek = await hkdf(root, KDF_INFO.kek);
  try {
    return await unwrap(blob, kek);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, root, kek);
  }
}

/**
 * Wrap the identity secret under the recovery key.
 *
 * HKDF, not Argon2id: the recovery key is 256 bits of real entropy, so there is no low-entropy
 * guess space to slow an attacker down in. Argon2id here would cost a second of user time and
 * buy nothing.
 */
export async function wrapUnderRecoveryKey(
  idSK: Uint8Array,
  recoveryKey: Uint8Array,
  roster?: RosterDoc,
): Promise<WrappedKey> {
  if (recoveryKey.length !== 32) {
    throw new Error(`recovery key must be 32 bytes, got ${recoveryKey.length}`);
  }
  const k = await hkdf(recoveryKey, KDF_INFO.recovery);
  try {
    return await wrap(idSK, k, 'recovery', roster);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, k);
  }
}

export async function unwrapWithRecoveryKey(
  blob: WrappedKey,
  recoveryKey: Uint8Array,
): Promise<Uint8Array> {
  if (blob.kind !== 'recovery') {
    throw new Error(`not a recovery-wrapped key (kind=${blob.kind})`);
  }
  const k = await hkdf(recoveryKey, KDF_INFO.recovery);
  try {
    return await unwrap(blob, k);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, k);
  }
}

/**
 * Wrap the identity secret under a device-bound key (the opt-in "remember on this PC").
 *
 * The caller supplies `deviceKey` from Electron's safeStorage, i.e. ultimately Windows DPAPI.
 * Be clear-eyed about what that is worth: safeStorage protects against OTHER USERS on the
 * machine, not against other processes running as the SAME user — any of them can call
 * CryptUnprotectData. It is an obfuscation layer with a per-user boundary, not a vault.
 *
 * We accept that here for one specific reason: on the Tally host machine this leaks nothing
 * Tally does not already leak in plaintext on the same disk. That is why the plan defaults
 * this toggle ON on the Tally host and OFF anywhere else, and why it must be a visible,
 * explained choice rather than a hidden default.
 */
export async function wrapUnderDeviceKey(
  idSK: Uint8Array,
  deviceKey: Uint8Array,
  roster?: RosterDoc,
): Promise<WrappedKey> {
  const k = await hkdf(deviceKey, KDF_INFO.device);
  try {
    return await wrap(idSK, k, 'device', roster);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, k);
  }
}

export async function unwrapWithDeviceKey(
  blob: WrappedKey,
  deviceKey: Uint8Array,
): Promise<Uint8Array> {
  if (blob.kind !== 'device') {
    throw new Error(`not a device-wrapped key (kind=${blob.kind})`);
  }
  const k = await hkdf(deviceKey, KDF_INFO.device);
  try {
    return await unwrap(blob, k);
  } finally {
    const sodium = await sodiumReady();
    wipe(sodium, k);
  }
}

/** Recover the public key from a secret key, for verification after an unwrap. */
export async function publicKeyFromSecret(idSK: Uint8Array): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  return sodium.crypto_scalarmult_base(idSK);
}

/* ------------------------------------------------------------------ *
 * The identity, roster and all — the product-level read and write.
 * ------------------------------------------------------------------ */

/** How a caller proves it may open a wrap. The variant must match the blob's `kind`. */
export type UnlockKey =
  | { kind: 'pass'; passphrase: string }
  | { kind: 'recovery'; recoveryKey: Uint8Array }
  | { kind: 'device'; deviceKey: Uint8Array };

export interface UnwrappedIdentity {
  /** X25519 secret key, 32 bytes. */
  identitySecretKey: Uint8Array;
  /** The pinned roster. Pass this to `openSection`'s `trustedDevices` and nothing else. */
  roster: DeviceRoster;
  /** The version sealed in this bundle. */
  rosterVersion: number;
  /**
   * The high-water mark the caller MUST PERSIST, somewhere the server cannot write.
   *
   * This is not advice. Without it the reader is `{ kind: 'first-use' }` at every unlock and has
   * no rollback protection at all — see `RosterMemory` in trust.ts. This function cannot persist
   * it and cannot verify that anyone did; that limit is real and is stated rather than hidden.
   */
  highestVersionSeen: number;
}

/**
 * Open a wrapped identity: the secret key AND the pinned device roster, in one authenticated
 * step. THIS IS THE ONLY WAY TO OBTAIN A ROSTER, and that is the entire point.
 *
 * A reader that gets its roster anywhere else — most temptingly, by asking the server "what is
 * the key for dev_001?" — is verifying that the server signed what the server sent, which is a
 * tautology dressed as a signature check. There is no roster field on `WrappedKey` to pluck and
 * no `fetchDeviceKey` to call, so the tempting version of this code cannot be written.
 *
 * `memory` is REQUIRED, for the same reason `trustedDevices` is required on `openSection`: the
 * rollback decision has exactly one right place to be made, and a defaulted argument is a
 * decision nobody made. `{ kind: 'first-use' }` is a legitimate answer — it is also a typed
 * admission that this unlock has no rollback protection.
 */
export async function openIdentity(
  blob: WrappedKey,
  key: UnlockKey,
  memory: RosterMemory,
): Promise<UnwrappedIdentity> {
  if (blob.kind !== key.kind) {
    throw new Error(
      `this key cannot open a ${blob.kind}-wrapped blob (it is for the ${key.kind} path)`,
    );
  }

  let bundle: IdentityBundle;
  if (key.kind === 'pass') {
    if (!blob.kdf) throw new Error('passphrase-wrapped key carries no KDF params');
    // The blob's own params, never this module's defaults — see `deriveRoot`.
    const root = await deriveRoot(key.passphrase, blob.kdf);
    const kek = await hkdf(root, KDF_INFO.kek);
    try {
      bundle = await unwrapBundle(blob, kek);
    } finally {
      const sodium = await sodiumReady();
      wipe(sodium, root, kek);
    }
  } else {
    const material = key.kind === 'recovery' ? key.recoveryKey : key.deviceKey;
    if (!(material instanceof Uint8Array) || material.length !== 32) {
      throw new Error(
        `${key.kind} key must be 32 bytes, got ` +
          `${material instanceof Uint8Array ? String(material.length) : typeof material}`,
      );
    }
    const k = await hkdf(material, key.kind === 'recovery' ? KDF_INFO.recovery : KDF_INFO.device);
    try {
      bundle = await unwrapBundle(blob, k);
    } finally {
      const sodium = await sodiumReady();
      wipe(sodium, k);
    }
  }

  // The AEAD tag has verified by here, so the bundle is material the server could not have
  // written. Everything below is about OUR correctness, and about freshness — which the tag
  // says nothing about.
  if (!bundle.roster) {
    // FAIL CLOSED, LOUDLY. A missing roster must mean neither "trust everything" (catastrophic)
    // nor "trust nothing" silently (an unexplained blank dashboard that someone will "fix" by
    // fetching a roster from the server). It means: this blob predates roster distribution or
    // was written by a primitive, and it must be re-wrapped.
    throw new RosterError(
      'this wrapped identity carries no device roster: refusing. Without a roster there is no ' +
        'pinned key to verify envelope signatures against, and the server — which also knows ' +
        'every device public key — could fabricate every number the dashboard shows. Re-wrap ' +
        'the identity with wrapIdentity().',
    );
  }

  const roster = decodeRoster(bundle.roster);
  const highestVersionSeen = acceptRosterVersion(memory, roster.version);

  return {
    identitySecretKey: bundleSecretKey(bundle),
    roster: roster.devices,
    rosterVersion: roster.version,
    highestVersionSeen,
  };
}

/** The wrapping material for a full identity write. `deviceKey` is the opt-in "remember this PC". */
export interface IdentityWrapInputs {
  passphrase: string;
  recoveryKey: Uint8Array;
  deviceKey?: Uint8Array | undefined;
}

/**
 * All the wraps of one identity, all carrying the same roster at the same version — plus the
 * server-login auth token derived from the same passphrase.
 */
export interface IdentityWraps {
  pass: WrappedKey;
  recovery: WrappedKey;
  device?: WrappedKey;
  /**
   * The login credential: HKDF(root, 'tally/v1/auth'), where `root` is the SAME Argon2id output
   * that produced the pass wrap's KEK — and therefore derived under the same salt/params sealed
   * in `pass.kdf`, which is what makes it reproducible by a browser after prelogin serves those
   * params back. Derived here rather than by the caller because the root is in scope here and
   * must not leave this module (it is the KEK's parent), and re-deriving it outside would cost a
   * second ~475ms Argon2id for the same bytes.
   *
   * It OPENS NOTHING. HKDF expansions under distinct info labels are computationally
   * independent (see KDF_INFO.auth in kdf.ts), so holding this value yields nothing about the
   * KEK; its only legitimate use is SHA-256(authToken) sent to the server as the login
   * credential. The caller owns zeroing it once hashed; wrapIdentity zeroes it itself when it
   * throws instead of returning.
   */
  authToken: Uint8Array;
}

/**
 * Write every wrap of an identity from ONE roster. The only supported way to create or update
 * a wrapped identity.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THIS IS ONE FUNCTION AND NOT THREE CALLS.
 * ------------------------------------------------------------------------------------------
 *
 * There are three wraps — passphrase, recovery key, device key — and they wrap the same
 * identity. Once the roster lives inside them, all three must carry the SAME roster, because
 * the reader opens exactly one of them and gets whatever that one says. If the recovery wrap
 * still lists a device the passphrase wrap revoked, then "recover with the printed sheet" is a
 * documented, supported way to downgrade yourself to a stale roster — an attacker who can
 * provoke a recovery (break the PC, wait for the passphrase to be forgotten) gets the rollback
 * without touching the database.
 *
 * The rule is: THEY CANNOT DISAGREE, and it is enforced by CONSTRUCTION rather than by check —
 * a set is never assembled from parts. This function encodes the roster ONCE and seals those
 * identical bytes into every wrap. There is no code path that gives one wrap a different roster
 * from another, because there is no second roster in scope to give it.
 *
 * It then re-opens each wrap with the key it just used and compares what comes back. Be honest
 * about what that step is: it is a REGRESSION NET for a future refactor that reintroduces
 * per-wrap rosters, not the thing that makes the rule true today. It is kept because the failure
 * it would catch is otherwise silent for eight months, surfacing as an owner who recovers from
 * the printed sheet and lands on a stale roster.
 *
 * The net is live, and that is a measured claim rather than a hopeful one: sabotaging this
 * function to seal a different roster into the recovery wrap makes it throw, and every test in
 * trust.test.ts that builds an identity fails. No COMMITTED test drives it — there is no seam to
 * inject a disagreement through without exporting internals purely to weaken them — so it was
 * verified by mutation instead. If you refactor this function, re-run that mutation; a
 * self-check that has quietly stopped checking is worse than none, because it reads as coverage.
 *
 * It re-opens with the WRAPPING KEY, not by calling `openIdentity` with the passphrase. That is
 * not a stylistic choice: `openIdentity` re-derives the KEK, which means a second Argon2id run
 * over a passphrase whose KEK is already sitting in a local variable. An earlier version of this
 * function did exactly that and cost TWO derives; it now costs one, measured against
 * `wrapUnderPassphrase` as the unit (~1x, was ~2x). Quoting a wall-clock figure here would be
 * quoting the load on whatever machine last ran it — the derive count is the honest number, and
 * the comment claiming the derive was already avoided was written before anyone measured it.
 *
 * WHAT THIS DOES NOT DO, AND MUST NOT: it does not give the Bridge a way to read anything. It
 * takes `idSK` because wrapping a key requires the key; that has always been true of this
 * module, and onboarding discards idSK immediately afterwards. The Bridge's keystore stores the
 * identity PUBLIC key and nothing else, and `apps/bridge/test/hardening.test.ts` fails the
 * build if a getter or setter for a secret one ever appears.
 */
export async function wrapIdentity(
  idSK: Uint8Array,
  roster: SealedRoster,
  inputs: IdentityWrapInputs,
): Promise<IdentityWraps> {
  const sodium = await sodiumReady();

  if (!(idSK instanceof Uint8Array) || idSK.length !== 32) {
    throw new Error(
      `identity secret key must be 32 bytes, got ` +
        `${idSK instanceof Uint8Array ? String(idSK.length) : typeof idSK}`,
    );
  }
  if (typeof inputs.passphrase !== 'string' || inputs.passphrase.length === 0) {
    throw new Error('wrapIdentity: a passphrase is required');
  }
  if (!(inputs.recoveryKey instanceof Uint8Array) || inputs.recoveryKey.length !== 32) {
    throw new Error(
      'wrapIdentity: a 32-byte recovery key is required. Both the passphrase and the recovery ' +
        'paths must be written together — a recovery wrap that is not re-written alongside the ' +
        'passphrase wrap is a stale roster the owner can be pushed onto.',
    );
  }
  if (inputs.deviceKey !== undefined) {
    if (!(inputs.deviceKey instanceof Uint8Array) || inputs.deviceKey.length !== 32) {
      throw new Error(`wrapIdentity: device key must be 32 bytes when present`);
    }
  }

  // ONCE. Every wrap below seals these exact bytes.
  const doc = encodeRoster(roster);
  const expected = canonicalStringify(doc as unknown as CanonicalValue);

  /**
   * Seal one wrap and immediately re-open it with THE SAME wrapping key.
   *
   * Taking the wrapping key rather than the passphrase is what keeps the self-check nearly
   * free: the Argon2id derive has already happened by the time we get here, and re-opening via
   * the public `openIdentity` would spend another ~475ms of it — measured at 985ms for this
   * function versus ~500ms this way. On the passphrase path that is half a second of an owner's
   * onboarding bought for nothing.
   */
  const sealAndVerify = async (
    name: string,
    kind: WrappedKey['kind'],
    wrappingKey: Uint8Array,
    kdf?: KdfParams,
  ): Promise<WrappedKey> => {
    const blob = await wrap(idSK, wrappingKey, kind, doc, kdf);
    const back = await unwrapBundle(blob, wrappingKey);
    const secret = bundleSecretKey(back);
    try {
      if (!back.roster) {
        throw new RosterError(`wrapIdentity: the ${name} wrap came back with no roster`);
      }
      const got = canonicalStringify(back.roster as unknown as CanonicalValue);
      if (got !== expected) {
        throw new RosterError(
          `wrapIdentity: the ${name} wrap did not round-trip the roster it was given. ` +
            `Refusing to emit a set of wraps that disagree — a reader opens exactly one of ` +
            `them and would silently get whichever roster that one carries.`,
        );
      }
      if (!timingSafeEqual(sodium, secret, idSK)) {
        throw new Error(`wrapIdentity: the ${name} wrap did not round-trip the identity key`);
      }
      return blob;
    } finally {
      wipe(sodium, secret);
    }
  };

  // --- Passphrase. The one expensive derive, done once; BOTH siblings taken from it. --------
  // The auth token comes off the root here, while the root is in scope, for the same reason
  // sealAndVerify takes the wrapping key instead of the passphrase: the alternative is a second
  // Argon2id over the same passphrase somewhere else, or the root itself crossing this module's
  // boundary — and the root is one public hkdf() call away from the KEK.
  const params = defaultKdfParams(await randomSalt());
  const root = await deriveRoot(inputs.passphrase, params);
  const kek = await hkdf(root, KDF_INFO.kek);
  const authToken = await hkdf(root, KDF_INFO.auth);
  try {
    let pass: WrappedKey;
    try {
      pass = await sealAndVerify('passphrase', 'pass', kek, params);
    } finally {
      wipe(sodium, root, kek);
    }

    // --- Recovery key. HKDF, not Argon2id: 256 bits of real entropy has no guess space. -------
    const rk = await hkdf(inputs.recoveryKey, KDF_INFO.recovery);
    let recovery: WrappedKey;
    try {
      recovery = await sealAndVerify('recovery', 'recovery', rk);
    } finally {
      wipe(sodium, rk);
    }

    // --- Device key, if "remember on this PC" is on. -------------------------------------------
    let device: WrappedKey | undefined;
    if (inputs.deviceKey) {
      const dk = await hkdf(inputs.deviceKey, KDF_INFO.device);
      try {
        device = await sealAndVerify('device', 'device', dk);
      } finally {
        wipe(sodium, dk);
      }
    }

    return device ? { pass, recovery, device, authToken } : { pass, recovery, authToken };
  } catch (e) {
    // A throw returns nothing, so this copy of the token would otherwise be orphaned on the
    // heap. On success the caller owns the wipe (see IdentityWraps.authToken).
    wipe(sodium, authToken);
    throw e;
  }
}
