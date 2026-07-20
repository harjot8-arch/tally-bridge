import {
  ENVELOPE_VERSION,
  SCHEMA_VERSION,
  canonicalStringify,
  type CanonicalValue,
  type EnvelopeAad,
  type IsoDate,
  type SealedEnvelope,
  type Section,
} from '@tally-bridge/core';
import { sodiumReady, wipe } from './sodium.ts';
import { compress, decompress } from './compress.ts';
import { pad, unpad } from './padme.ts';
import { fromBase64, toBase64 } from './kdf.ts';
import type { DeviceRoster } from './trust.ts';

/**
 * The wire pipeline:
 *
 *   canonical JSON -> gzip -> Padme pad -> XChaCha20-Poly1305 -> base64
 *                                              ^
 *                                     fresh CEK, sealed to idPK
 *
 *   ...then the whole envelope is SIGNED with the Bridge's Ed25519 device key.
 *
 * XChaCha20-Poly1305 over AES-256-GCM, deliberately. Payloads here are 1-50KB, so AES-NI's
 * throughput advantage is unmeasurable next to the network round trip — the single argument
 * for GCM does not apply. What does apply is that GCM's 96-bit nonce is a footgun with random
 * generation, and any counter-based scheme would have to survive a consumer Windows PC that
 * WILL be force-killed mid-write, restored from a backup, or cloned onto a new machine by the
 * local IT guy. Every one of those rolls back a persisted counter, which under GCM is a
 * key-recovery-grade break. XChaCha20's 192-bit nonce makes random generation unconditionally
 * safe, turning a correctness obligation we would have to engineer into a property we get for
 * free from randombytes_buf(24).
 *
 * It is moot twice over anyway: a FRESH CEK per message means a nonce collision would need
 * both a 192-bit nonce collision and a key collision. But designs should be safe for the
 * reason they claim, not by accident.
 *
 * ---------------------------------------------------------------------------------------
 * WHY THE SIGNATURE EXISTS — the property the sealed box does NOT give you.
 * ---------------------------------------------------------------------------------------
 *
 * A sealed box is confidentiality only. `crypto_box_seal` needs the identity PUBLIC key and
 * nothing else, and the server HAS the identity public key — onboarding sets it as an env var
 * there, because the Bridge has to be handed it somehow. So a malicious or compromised server
 * could mint a complete, self-consistent envelope: a fresh CEK sealed to idPK, whatever AAD it
 * liked, a ciphertext over a plaintext it invented, and a matching contentHash — matching
 * because the hash is computed over the attacker's own plaintext. Every check in `openSection`
 * passed and the dashboard rendered fabricated receivables under a green checkmark.
 *
 * The AAD and the contentHash bound this, and it is worth being precise about how little:
 * they stop a ciphertext being SHUFFLED between slots. They never stopped one being
 * FABRICATED. Only a signature by a key the server does not hold can do that, so the Bridge
 * now signs every envelope with its Ed25519 device key and `openSection` refuses anything it
 * cannot verify against a PINNED public key. See trust.ts for where that pinned key must come
 * from — that is the part a naive version of this fix gets wrong.
 */

/**
 * Bumped when the SIGNATURE format changes. Separate from `ENVELOPE_VERSION` because the two
 * version different things and are owned by different packages: `aad.v` describes the sealed
 * payload's shape and is cross-checked by the server's ingest validator, while this describes
 * what bytes go under the Ed25519 signature — a thing the server has no opinion about and
 * cannot verify.
 */
export const ENVELOPE_SIG_VERSION = 1 as const;

/**
 * Domain separation, and it is load-bearing rather than hygienic.
 *
 * The Bridge signs TWO different things with this exact key: HTTP requests (RFC 9421, see
 * @tally-bridge/protocol) and now envelopes. Reusing one key across two signature schemes is
 * safe only if no byte string is a valid message in both — otherwise a signature harvested
 * from one becomes a forgery in the other. This prefix, plus protocol's signing string never
 * beginning with it, makes the two message spaces provably disjoint.
 */
const SIG_DOMAIN = 'tally-bridge/envelope-signature/v1';

/**
 * The one algorithm. NOT negotiated, and the envelope's `alg` is compared against this rather
 * than dispatched on — `alg` is an attacker-supplied string, and dispatching on it is how JWT
 * got `alg: none`.
 */
const SIG_ALG = 'ed25519';

/** The Ed25519 signature over an envelope. */
export interface EnvelopeSignature {
  v: typeof ENVELOPE_SIG_VERSION;
  alg: typeof SIG_ALG;
  /** Detached Ed25519 signature over `envelopeSigningBytes(...)`, base64. */
  sig: string;
  /**
   * NOTE what is deliberately ABSENT: the signing public key. Shipping it would be an
   * invitation to verify against it, which verifies that the envelope was signed by whoever
   * signed it — a tautology, and precisely the forgery this whole change exists to stop. The
   * key must come from the reader's pinned roster and nowhere else. `aad.deviceId` selects
   * which pinned key to use.
   */
}

/** What actually goes on the wire now. `sig` is not optional: an unsigned envelope is refused. */
export interface SignedEnvelope extends SealedEnvelope {
  sig: EnvelopeSignature;
}

/**
 * The parameter type for `openSection`, which accepts a plain `SealedEnvelope` too.
 *
 * Not because unsigned envelopes are tolerated — they are rejected at runtime, unconditionally
 * — but because everything that reads an envelope out of the server types it as
 * `SealedEnvelope` (the server cannot mint the `sig` field and @tally-bridge/core does not
 * know about it). Forcing those call sites to cast would produce exactly one thing: `as any`,
 * scattered across every reader, in the one place where a silent bypass would be fatal. So the
 * type is permissive and the CHECK is not: `openSection` has no path that returns plaintext
 * without a verified signature, so there is nothing a caller can pass that skips it.
 */
export type MaybeSignedEnvelope = SealedEnvelope & { sig?: EnvelopeSignature };

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const d = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(d);
}

/**
 * Serialize AAD deterministically.
 *
 * This MUST be byte-identical on the sealing and opening side or every decrypt fails, so it
 * goes through the same canonical serializer as the payload rather than JSON.stringify.
 */
function encodeAad(aad: EnvelopeAad): Uint8Array {
  return new TextEncoder().encode(canonicalStringify(aad as unknown as CanonicalValue));
}

export function makeAad(input: Omit<EnvelopeAad, 'v' | 'schemaVer'>): EnvelopeAad {
  return { ...input, v: ENVELOPE_VERSION, schemaVer: SCHEMA_VERSION };
}

/** The raw material the envelope signature commits to. */
export interface EnvelopeSigParts {
  sigVer: number;
  alg: string;
  /** Canonical AAD bytes — the same bytes fed to the AEAD. */
  aad: Uint8Array;
  nonce: Uint8Array;
  sealedCek: Uint8Array;
  ciphertext: Uint8Array;
  contentHash: Uint8Array;
}

const U32_MAX = 0xffffffff;

/**
 * Build the exact bytes that get signed. THIS FUNCTION IS THE CONTRACT — signer and verifier
 * both call it, so the two sides provably agree rather than agreeing by inspection.
 *
 * ---------------------------------------------------------------------------------------
 * THE FRAMING, AND WHY IT IS LENGTH-PREFIXED RATHER THAN DELIMITED.
 * ---------------------------------------------------------------------------------------
 *
 * A prior audit of this codebase found a real signing-string forgery of exactly this shape:
 * fields newline-joined with no length prefixes, so the framing was injective ONLY as long as
 * no field could contain a newline — which was asserted in a comment and checked nowhere. Two
 * DIFFERENT tuples then serialised to identical bytes, and one Ed25519 signature authenticated
 * both. Shift the boundary and a path swallows a body hash while a nonce swallows the rest;
 * same string out, so a signature over a ₹1 body verified a ₹999999 body. Ed25519 was doing
 * its job perfectly. The serialisation was lying to it.
 *
 * That class of bug is not fixable by validating harder, and the fields here are worse
 * candidates for it than protocol's were: `ciphertext` and `sealedCek` are ARBITRARY BINARY.
 * There is no delimiter to reserve. So the encoding is made injective by construction instead:
 *
 *   u32be(fieldCount) || for each field: u32be(len(field)) || field
 *
 * This parses back out exactly one way. Moving a byte across a field boundary necessarily
 * changes a length prefix, which changes the signed bytes, which invalidates the signature.
 * There is no "as long as nobody puts a newline in it" left to get wrong.
 *
 * WHAT IS SIGNED IS THE DECODED BYTES, not the base64 strings. The signature commits to the
 * cryptographic material rather than to a transport encoding, so a re-encoding that decodes
 * identically (base64 is not canonical — padding bits and whitespace vary) does not spuriously
 * invalidate an honest envelope. Injectivity is unaffected: the framing is over byte strings.
 */
export function envelopeSigningBytes(parts: EnvelopeSigParts): Uint8Array {
  if (!Number.isInteger(parts.sigVer) || parts.sigVer < 0 || parts.sigVer > U32_MAX) {
    throw new Error(`sigVer must be a u32, got ${parts.sigVer}`);
  }

  const enc = new TextEncoder();
  const sigVerBytes = new Uint8Array(4);
  new DataView(sigVerBytes.buffer).setUint32(0, parts.sigVer, false);

  // Fixed order, fixed count. Both are part of the format.
  const fields: Uint8Array[] = [
    enc.encode(SIG_DOMAIN),
    sigVerBytes,
    enc.encode(parts.alg),
    parts.aad,
    parts.nonce,
    parts.sealedCek,
    parts.ciphertext,
    parts.contentHash,
  ];

  let total = 4;
  for (const f of fields) {
    // Unreachable for anything this codebase produces (the compression cap is orders of
    // magnitude below 4GiB). Enforced anyway, because a length that silently truncates in a
    // u32 is the framing bug this whole encoding exists to prevent.
    if (f.length > U32_MAX) throw new Error(`signing field of ${f.length} bytes exceeds u32`);
    total += 4 + f.length;
  }

  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, fields.length, false);
  let o = 4;
  for (const f of fields) {
    dv.setUint32(o, f.length, false);
    o += 4;
    out.set(f, o);
    o += f.length;
  }
  return out;
}

/**
 * Seal a section for upload, and sign it.
 *
 * THE ASYMMETRY IS INTACT AND IS THE WHOLE POINT: `identityPublicKey` encrypts and cannot
 * decrypt; `deviceSecretKey` signs and cannot decrypt. There is still no parameter here that
 * opens what this function produces. After it returns, the calling process holds no key that
 * reads its own output — `crypto_box_seal` generates a throwaway ephemeral keypair per call
 * and discards the ephemeral secret internally.
 *
 * `deviceSecretKey` is the SAME Ed25519 key that signs uploads via RFC 9421 (see
 * @tally-bridge/protocol), reused deliberately rather than minting a second one:
 *
 *   - A second key would need its own registration, its own pinning path to the reader, and
 *     its own revocation. Every one of those is a place to get the trust chain wrong, bought
 *     in exchange for nothing — the two keys would live in the same file, in the same
 *     safeStorage blob, and be stolen in the same breath.
 *   - The security argument for keeping this key in safeStorage/DPAPI already covers this use
 *     exactly. Steal it and you can upload garbage until the owner clicks "revoke device"; you
 *     cannot read a single number. That is still true with envelope signing added: revocation
 *     kills forged envelopes and forged uploads in one click.
 *   - Cross-protocol reuse is safe here because the two message spaces are provably disjoint
 *     (see SIG_DOMAIN).
 */
export async function sealSection(
  payload: CanonicalValue,
  aad: EnvelopeAad,
  identityPublicKey: Uint8Array,
  deviceSecretKey: Uint8Array,
): Promise<SignedEnvelope> {
  const sodium = await sodiumReady();

  // Checked for presence BEFORE shape. These are typed as required, but the types are stripped
  // at runtime (`node --experimental-strip-types`) and every caller is on the other side of a
  // package boundary — so a call site that has not been updated arrives here as `undefined` and
  // would otherwise die on `.length` with a TypeError that names neither the parameter nor the
  // fix. A wire-format change deserves an error that says what to do.
  if (!(identityPublicKey instanceof Uint8Array)) {
    throw new Error('sealSection: identityPublicKey is missing (expected a Uint8Array)');
  }
  if (!(deviceSecretKey instanceof Uint8Array)) {
    throw new Error(
      'sealSection: deviceSecretKey is missing (expected the Bridge Ed25519 device signing key). ' +
        'Envelopes must be signed — a sealed box needs only the identity PUBLIC key, which the ' +
        'server also holds, so without a signature the server can fabricate financial data that ' +
        'passes every check the reader makes.',
    );
  }

  if (identityPublicKey.length !== sodium.crypto_box_PUBLICKEYBYTES) {
    throw new Error(
      `identity public key must be ${sodium.crypto_box_PUBLICKEYBYTES} bytes, got ${identityPublicKey.length}`,
    );
  }
  // Both parameters are Uint8Array, so nothing but this stops a caller passing the identity
  // SECRET key here — which would hand the Bridge a decryption key and quietly end the
  // product's only real security property. An X25519 secret is 32 bytes and an Ed25519 secret
  // is 64, so the length check is also a type check for the mistake that matters.
  if (deviceSecretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error(
      `device signing secret key must be ${sodium.crypto_sign_SECRETKEYBYTES} bytes, got ${deviceSecretKey.length}`,
    );
  }

  const canonical = new TextEncoder().encode(canonicalStringify(payload));

  // Hash the PLAINTEXT, before compression and padding. This is the upload idempotency key
  // and the section-hash gate. It does leak equality to the server ("unchanged since last
  // time") — but the upload simply not happening leaks that already, so it reveals nothing new.
  const contentHash = await sha256(canonical);

  const padded = pad(await compress(canonical));

  const cek = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  try {
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      padded,
      encodeAad(aad),
      null,
      nonce,
      cek,
    );
    const sealedCek = sodium.crypto_box_seal(cek, identityPublicKey);

    const sig = sodium.crypto_sign_detached(
      envelopeSigningBytes({
        sigVer: ENVELOPE_SIG_VERSION,
        alg: SIG_ALG,
        aad: encodeAad(aad),
        nonce,
        sealedCek,
        ciphertext,
        contentHash,
      }),
      deviceSecretKey,
    );

    return {
      aad,
      nonce: toBase64(nonce),
      sealedCek: toBase64(sealedCek),
      ciphertext: toBase64(ciphertext),
      contentHash: toBase64(contentHash),
      sig: { v: ENVELOPE_SIG_VERSION, alg: SIG_ALG, sig: toBase64(sig) },
    };
  } finally {
    // Best-effort: narrows the window for a heap dump, does not close it.
    wipe(sodium, cek);
  }
}

/**
 * The slot the reader ASKED FOR.
 *
 * These are exactly the fields a caller knows BEFORE it makes the request — "give me Acme's
 * receivables as of 2026-07-16" — which is what makes them checkable. `snapshotTs` and `seq`
 * are deliberately absent: nobody can state those up front, and pretending otherwise would
 * make this parameter unfillable and therefore faked.
 *
 * `deviceId` is absent for a different reason: it is not an expectation, it is a lookup. The
 * envelope names a device, that name selects a key from the pinned roster, and the signature
 * either verifies under it or does not. A reader asserting "I expected dev_001" on top of that
 * adds nothing the roster has not already decided.
 */
export interface AadExpectation {
  tenantId: string;
  companyGuid: string;
  section: Section;
  asOf: IsoDate;
}

export interface OpenSectionOptions {
  identityPublicKey: Uint8Array;
  identitySecretKey: Uint8Array;
  /**
   * REQUIRED. The attack this closes: a self-consistent, correctly signed envelope for company
   * A, returned by the server when the dashboard asked for company B. Every cryptographic check
   * passes — it is a genuine envelope, just not the one that was requested — and A's numbers
   * render under B's name. Authenticity was never the missing piece there; nobody was checking
   * that the answer answered the question.
   *
   * It has no default, and it is not optional, for that reason. A reader that does not state
   * what it asked for cannot be told that it got something else.
   */
  expect: AadExpectation;
  /**
   * REQUIRED. Pinned device public keys. READ trust.ts BEFORE POPULATING THIS — if these come
   * from the same server that might forge, this entire function is theatre.
   */
  trustedDevices: DeviceRoster;
}

/**
 * Open a sealed section.
 *
 * Requires the identity SECRET key — so only the dashboard, or the desktop app after the user
 * has unlocked it, can call this. The Bridge never can.
 *
 * The order of checks is chosen, not incidental: THE SIGNATURE IS VERIFIED BEFORE ANY OTHER
 * DECISION IS MADE. Everything in an envelope is attacker-supplied until then, including the
 * AAD, so checking the requested slot first would mean rejecting-or-accepting on the strength
 * of fields the attacker wrote. Verify first, then reason. It also means the identity secret
 * key is never fed an unauthenticated sealed box.
 */
export async function openSection(
  envelope: MaybeSignedEnvelope,
  opts: OpenSectionOptions,
): Promise<unknown> {
  const sodium = await sodiumReady();

  if (envelope.aad.v !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version ${envelope.aad.v}`);
  }

  // --- 1. Authenticity. -------------------------------------------------------------------

  const sig = envelope.sig;
  // UNSIGNED ENVELOPES ARE REFUSED OUTRIGHT. There is no compatibility path and there must not
  // be one: no unsigned data exists anywhere (this shipped before the first real upload), so a
  // fallback would be a downgrade path we do not need, guarding a downgrade attack we would
  // then certainly have. A server that strips `sig` gets a rejection, not a soft landing.
  if (!sig || typeof sig !== 'object') {
    throw new Error('envelope is not signed: refusing (a sealed box proves nothing about who wrote it)');
  }
  if (sig.v !== ENVELOPE_SIG_VERSION) {
    throw new Error(`unsupported envelope signature version ${String(sig.v)}`);
  }
  // Compared, never dispatched on. This is an attacker-supplied string.
  if (sig.alg !== SIG_ALG) {
    throw new Error(`unsupported envelope signature algorithm ${String(sig.alg)}`);
  }

  if (opts.trustedDevices.length === 0) {
    // An empty roster is what a bug or a failed fetch produces. Its meaning must never be
    // "then there is nothing to verify against, so let it through".
    throw new Error('no trusted device keys supplied: refusing to verify against nothing');
  }

  // The envelope NAMES a device; the roster decides whether that name has a key. A key pinned
  // for dev_A therefore cannot sign as dev_B. Multiple entries for one deviceId are legitimate
  // (key rotation) and every one of them is equally pinned, so any of them verifying is enough.
  const candidates = opts.trustedDevices.filter((d) => d.deviceId === envelope.aad.deviceId);
  if (candidates.length === 0) {
    throw new Error(`untrusted device ${envelope.aad.deviceId}: not in the pinned roster`);
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64(sig.sig);
  } catch {
    throw new Error('envelope signature is not valid base64');
  }

  const signed = envelopeSigningBytes({
    sigVer: ENVELOPE_SIG_VERSION,
    alg: SIG_ALG,
    aad: encodeAad(envelope.aad),
    nonce: fromBase64(envelope.nonce),
    sealedCek: fromBase64(envelope.sealedCek),
    ciphertext: fromBase64(envelope.ciphertext),
    contentHash: fromBase64(envelope.contentHash),
  });

  const verified = candidates.some((d) => {
    try {
      return sodium.crypto_sign_verify_detached(signature, signed, d.publicKey);
    } catch {
      // libsodium throws on a wrong-length signature or key rather than returning false.
      return false;
    }
  });
  if (!verified) {
    throw new Error(
      `bad envelope signature: not signed by a trusted key for device ${envelope.aad.deviceId}`,
    );
  }

  // --- 2. Is this the answer to the question that was asked? -------------------------------

  // Now — and only now — the AAD is authenticated data written by a device we trust, so it is
  // worth reasoning about. A trusted device's genuine envelope for the wrong slot is still the
  // wrong slot: the server chooses WHICH authentic envelope to return, and that choice is not
  // covered by any signature.
  const e = opts.expect;
  const a = envelope.aad;
  const mismatches: string[] = [];
  if (a.tenantId !== e.tenantId) mismatches.push(`tenantId (asked ${e.tenantId}, got ${a.tenantId})`);
  if (a.companyGuid !== e.companyGuid) {
    mismatches.push(`companyGuid (asked ${e.companyGuid}, got ${a.companyGuid})`);
  }
  if (a.section !== e.section) mismatches.push(`section (asked ${e.section}, got ${a.section})`);
  if (a.asOf !== e.asOf) mismatches.push(`asOf (asked ${e.asOf}, got ${a.asOf})`);
  if (mismatches.length > 0) {
    throw new Error(`envelope does not match the request: ${mismatches.join('; ')}`);
  }

  // NOTE what this still does NOT give you: FRESHNESS. The server may return an authentic,
  // correctly-slotted envelope from last quarter, and every check above passes. `snapshotTs`
  // and `seq` are signed and bound, but only a caller holding the newest values it has already
  // seen can tell that these are old. The dashboard MUST reject a snapshotTs older than its
  // high-water mark; this function cannot do it for them.

  // --- 3. Confidentiality. -----------------------------------------------------------------

  // crypto_box_seal_open needs the public key too: it reconstructs the ephemeral shared
  // secret from the sender's ephemeral public key prefixed to the sealed box.
  const cek = sodium.crypto_box_seal_open(
    fromBase64(envelope.sealedCek),
    opts.identityPublicKey,
    opts.identitySecretKey,
  );

  try {
    const padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64(envelope.ciphertext),
      // Any tampering with ANY aad field fails here: the server cannot re-slot a ciphertext
      // into a different section, company, or date.
      encodeAad(envelope.aad),
      fromBase64(envelope.nonce),
      cek,
    );

    const canonical = await decompress(unpad(padded));

    // Verify the plaintext matches the advertised hash. The AEAD already guarantees
    // integrity, so this catches OUR bugs (a compression or padding mismatch), not an
    // attacker. Cheap, and the failure it catches is otherwise silent corruption.
    //
    // Compared as BYTES, not as base64 strings: base64 has no canonical form, so a string
    // compare here would turn a harmless re-encoding into a decrypt failure.
    const actual = await sha256(canonical);
    const claimed = fromBase64(envelope.contentHash);
    if (actual.length !== claimed.length || !actual.every((b, i) => b === claimed[i])) {
      throw new Error(
        `content hash mismatch: envelope claims ${envelope.contentHash}, plaintext hashes to ${toBase64(actual)}`,
      );
    }

    return JSON.parse(new TextDecoder().decode(canonical));
  } finally {
    wipe(sodium, cek);
  }
}

/** The content hash of a payload, without sealing it. Used by the upload gate. */
export async function contentHashOf(payload: CanonicalValue): Promise<string> {
  const canonical = new TextEncoder().encode(canonicalStringify(payload));
  return toBase64(await sha256(canonical));
}
