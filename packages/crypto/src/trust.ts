import type { RosterDoc, WireTrustedDevice } from '@tally-bridge/core';
import { sodiumReady } from './sodium.ts';
import { fromBase64, toBase64 } from './kdf.ts';

/**
 * WHO IS ALLOWED TO HAVE WRITTEN THIS.
 *
 * ------------------------------------------------------------------------------------------
 * THE TRUST CHAIN. Read this before wiring anything to it — it is the whole point of the file.
 * ------------------------------------------------------------------------------------------
 *
 * Sealed boxes give CONFIDENTIALITY, not AUTHENTICITY. `crypto_box_seal` takes the identity
 * PUBLIC key and nothing else, and onboarding sets that public key as an env var ON THE SERVER
 * (the Bridge needs it to encrypt). So the server holds every input required to MINT an
 * envelope: a fresh CEK sealed to idPK, an AAD it chooses, a ciphertext over a plaintext it
 * invents, and a contentHash computed over that same invented plaintext. Every check in the
 * old `openSection` passed. "The server can't read your numbers but can make them up" is not
 * a threat model anyone would buy the product under, so envelopes are now SIGNED by the
 * Bridge's Ed25519 device key and the reader VERIFIES.
 *
 * That moves the entire problem to one question: HOW DOES THE READER LEARN THE LEGITIMATE
 * DEVICE PUBLIC KEY? Get this wrong and the signature is decoration.
 *
 *   THE SERVER ALSO KNOWS THE DEVICE PUBLIC KEY. It must — it verifies RFC 9421 upload
 *   signatures with it (see `lookupDevice` in @tally-bridge/protocol). If the dashboard asks
 *   the server "what is the public key for dev_001?", a malicious server answers with a key it
 *   generated, signs its forged envelope with the matching secret, and the dashboard verifies
 *   it happily. NOTHING HAS BEEN ACHIEVED. The signature would authenticate "whoever the
 *   server says is the device", which is the server.
 *
 * So this type is deliberately DATA, not a lookup function. There is no `fetchDeviceKey` here
 * and there must never be one: the roster has to arrive over a path the server cannot rewrite.
 * Exactly two such paths exist, and a caller MUST use one of them:
 *
 *   1. IT TRAVELS WITH THE IDENTITY MATERIAL. The wrapped identity secret (`WrappedKey`) is
 *      AEAD-sealed under a key derived from the user's passphrase or recovery key — neither of
 *      which the server has. Anything carried INSIDE that ciphertext is beyond the server's
 *      reach: it can withhold the blob or corrupt it, but a corrupted blob fails the Poly1305
 *      tag and the unwrap throws. It cannot substitute a device key. The user already types the
 *      passphrase to get idSK; the roster rides along for free, in the same authenticated step.
 *      IMPLEMENTED: `IdentityBundle.roster` in @tally-bridge/core, minted by `wrapIdentity()`
 *      and readable only through `openIdentity()`. Note there is deliberately NO roster field
 *      on `WrappedKey` itself — see the long comment there for why a field the server could
 *      populate would have achieved nothing.
 *
 *   2. IT IS PINNED AT PAIRING. The desktop app shows `deviceFingerprint(devicePublicKey)`;
 *      the user compares it against what the dashboard displays, once, out of band. This is
 *      SSH host-key verification and Signal's safety numbers, and it works — but it spends
 *      user attention, and attention spent on a hex string is attention mostly not spent.
 *      IMPLEMENTED: `admitPairedDevice()` in the Bridge's onboarding/pairing.ts.
 *
 * ------------------------------------------------------------------------------------------
 * THESE TWO ARE NOT ALTERNATIVES. PATH 1 DEPENDS ON PATH 2. Do not remove either.
 * ------------------------------------------------------------------------------------------
 *
 * Path 1 answers "how does the roster reach the reader". It does NOT answer "how did the right
 * key get INTO the roster", and for every device after the first, that is a separate question
 * with a hostile answer available. Device 2 generates its own keypair and registers it WITH THE
 * SERVER. If device 1 then fetches "device 2's public key" from the server in order to add it
 * to the roster, the server hands back a key it generated itself, the owner's passphrase seals
 * it into the bundle, and the reader pins the attacker. The sealing is flawless and the content
 * is the attacker's. A roster is only as good as the keys admitted to it.
 *
 * So the ONLY thing that may put a key into a roster is a human confirming, out of band, that
 * the fingerprint on the new machine's screen is the fingerprint the admitting machine is about
 * to seal. That is `deviceFingerprint()`, and `admitPairedDevice()` will not produce a roster
 * without it. Device 1 needs no such ceremony — it holds its own key directly, with no server
 * in between, which is exactly why onboarding is the one place trust can start.
 *
 * TOFU (accept whatever key shows up first, warn on change) is NOT one of the paths. The very
 * first thing the reader ever fetches comes from the server, so trust-on-first-use here is
 * trust-on-the-attacker's-first-use.
 */
export interface TrustedDevice {
  /** Matched against `aad.deviceId`. A key trusted for dev_A cannot sign as dev_B. */
  deviceId: string;
  /** Ed25519 public key, 32 bytes — the same device key that signs uploads via RFC 9421. */
  publicKey: Uint8Array;
}

/**
 * The set of devices whose envelopes this reader will accept.
 *
 * A list rather than a map, so that one deviceId may legitimately carry more than one key:
 * that is device-key rotation, and during it both the old and new key must verify. Every entry
 * is equally pinned, so accepting any of them for a matching deviceId adds no trust.
 *
 * An EMPTY roster is rejected rather than treated as "no devices, nothing to check" — an empty
 * roster is what a bug or a failed fetch produces, and its meaning must be "verify nothing"
 * nowhere.
 */
export type DeviceRoster = readonly TrustedDevice[];

/**
 * A roster plus the monotonic version it was minted at. The decoded form of `RosterDoc`.
 *
 * The version is not decoration and it is not a schema version — it is the ONLY defence against
 * rollback that exists here at all. See `RosterMemory`.
 */
export interface SealedRoster {
  /** Monotonic, starts at ROSTER_FIRST_VERSION, bumped on every roster change. */
  version: number;
  devices: DeviceRoster;
}

export const ROSTER_FIRST_VERSION = 1;

/**
 * Thrown for anything wrong with a roster: malformed, empty, missing, or ROLLED BACK.
 *
 * A distinct class because callers must be able to tell these apart from "your passphrase is
 * wrong". `attemptRecovery()` in the Bridge is the case that proves the need: it swallows every
 * unwrap failure and says "check your recovery sheet", which is right for a wrong key and
 * catastrophically wrong for a rollback — it would report an attack in progress as a typo.
 */
export class RosterError extends Error {
  constructor(message: string) {
    super(message);
    // Set explicitly rather than relying on the class name: this error crosses a package
    // boundary (the Bridge imports the built dist), and callers key off `name` as well as
    // `instanceof` precisely so a dual module instance cannot silently downgrade the check.
    this.name = 'RosterError';
  }
}

/** Exactly the 44 characters a base64'd 32-byte key occupies: 43 payload + one '='. */
const KEY_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

/**
 * Decode and VALIDATE a roster document that came out of a sealed bundle.
 *
 * This runs on plaintext that the AEAD has already authenticated, so it is not defending
 * against an attacker — it is defending against US: a future writer that ships an empty roster,
 * a truncated key, or a version of NaN. Every one of those fails OPEN if it is not checked
 * here, and the failure is silent.
 *
 * Note the base64 handling. `Buffer.from(x, 'base64')` SILENTLY DISCARDS every character
 * outside the alphabet and never throws, so it will manufacture a well-formed 32-byte "key" out
 * of very nearly anything — this repo has already shipped that bug once, when a WiFi QR code was
 * accepted as a recovery key. So the shape is matched BEFORE anything is decoded, the decoded
 * length is checked after, and a re-encode round-trip proves the decode was lossless rather
 * than trusting two implementations to agree.
 */
export function decodeRoster(doc: unknown): SealedRoster {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new RosterError(`roster is not an object (got ${doc === null ? 'null' : typeof doc})`);
  }
  const d = doc as Partial<RosterDoc>;
  if (d.v !== 1) {
    throw new RosterError(`unsupported roster version ${String(d.v)}`);
  }

  // Shape BEFORE value. `Number.isSafeInteger(NaN)` is false, so this is what stops a NaN
  // version reaching `acceptRosterVersion` — where every `<` comparison against it would be
  // false and the rollback check would wave it through. That bug has been found three times in
  // this repo; it does not get a fourth.
  if (!Number.isSafeInteger(d.version) || (d.version as number) < ROSTER_FIRST_VERSION) {
    throw new RosterError(
      `roster version must be an integer >= ${ROSTER_FIRST_VERSION}, got ${String(d.version)}`,
    );
  }

  if (!Array.isArray(d.devices)) {
    throw new RosterError('roster has no devices array');
  }
  if (d.devices.length === 0) {
    // An empty roster means "verify nothing" nowhere. `openSection` refuses one too; this is
    // the earlier and more specific of the two refusals, not a duplicate of it.
    throw new RosterError('roster is empty: refusing (an empty roster verifies nothing)');
  }

  const devices: TrustedDevice[] = [];
  const seen = new Set<string>();
  for (const [i, entry] of d.devices.entries()) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new RosterError(`roster device ${i} is not an object`);
    }
    const e = entry as Partial<WireTrustedDevice>;
    if (typeof e.deviceId !== 'string' || e.deviceId.length === 0) {
      throw new RosterError(`roster device ${i} has no deviceId`);
    }
    if (typeof e.publicKey !== 'string' || !KEY_BASE64.test(e.publicKey)) {
      throw new RosterError(
        `roster device ${i} (${e.deviceId}) does not carry a 32-byte base64 Ed25519 public key`,
      );
    }
    const publicKey = fromBase64(e.publicKey);
    if (publicKey.length !== 32 || toBase64(publicKey) !== e.publicKey) {
      throw new RosterError(`roster device ${i} (${e.deviceId}) has a malformed public key`);
    }
    // Duplicate (deviceId, key) pairs are not a security problem — the same key verifying twice
    // adds no trust — but they are a sign the roster was built by appending without checking,
    // and a roster that grows on every pairing of the same device eventually stops being
    // reviewable by the human who has to audit it.
    const fp = `${e.deviceId} ${e.publicKey}`;
    if (seen.has(fp)) {
      throw new RosterError(`roster lists ${e.deviceId} with the same key twice`);
    }
    seen.add(fp);
    devices.push({ deviceId: e.deviceId, publicKey });
  }

  return { version: d.version as number, devices };
}

/**
 * Encode a roster for sealing. The inverse of `decodeRoster`, and it validates on the way out
 * too — a malformed roster must fail where it is BUILT, not eight months later at an unlock.
 */
export function encodeRoster(roster: SealedRoster): RosterDoc {
  if (!Number.isSafeInteger(roster.version) || roster.version < ROSTER_FIRST_VERSION) {
    throw new RosterError(
      `roster version must be an integer >= ${ROSTER_FIRST_VERSION}, got ${String(roster.version)}`,
    );
  }
  if (roster.devices.length === 0) {
    throw new RosterError('refusing to seal an empty roster: it would verify nothing');
  }
  const doc: RosterDoc = {
    v: 1,
    version: roster.version,
    devices: roster.devices.map((d) => {
      if (typeof d.deviceId !== 'string' || d.deviceId.length === 0) {
        throw new RosterError('roster device has no deviceId');
      }
      if (!(d.publicKey instanceof Uint8Array) || d.publicKey.length !== 32) {
        throw new RosterError(
          `roster entry ${d.deviceId} must carry a 32-byte Ed25519 public key, got ` +
            `${d.publicKey instanceof Uint8Array ? `${d.publicKey.length} bytes` : typeof d.publicKey}`,
        );
      }
      return { deviceId: d.deviceId, publicKey: toBase64(d.publicKey) };
    }),
  };
  // Round-trip on the way out. This is the check that makes "encode and decode agree" a fact
  // rather than a hope, and it costs microseconds on a path that runs a handful of times in the
  // life of an install.
  decodeRoster(doc);
  return doc;
}

/**
 * ------------------------------------------------------------------------------------------
 * ROLLBACK, AND THE PART OF IT THAT IS NOT CLOSED.
 * ------------------------------------------------------------------------------------------
 *
 * AEAD gives INTEGRITY, not FRESHNESS — the same lesson this codebase already learned about
 * envelope replay, arriving again one layer down. The server cannot forge a bundle. It does not
 * need to. It stores every bundle the Bridge ever uploaded and it chooses which one to hand
 * back, and an OLD bundle is perfectly authentic. So:
 *
 *   - The owner revokes a device (stolen laptop, departed accountant). The Bridge re-wraps with
 *     roster version 5, which no longer lists it. The server serves version 4. The reader pins
 *     a device the owner revoked, and every forgery that device's key signs verifies.
 *   - The mirror image: the server serves version 4 to suppress a newly paired device. That is
 *     only a denial of service — the new device's envelopes are refused — but it is the same
 *     mechanism and the same fix.
 *
 * `version` plus a reader that remembers the highest it has seen closes this. The remembering
 * is the whole of it, and it is the part that cannot live in this package:
 *
 *   - THE DESKTOP APP has real local disk the server cannot reach. Rollback is closed there
 *     after the first successful unlock, fully.
 *   - THE WEB DASHBOARD is served BY the Vercel deployment it is fetching from, so its
 *     localStorage is reachable by the server's own JavaScript. Against an adversary who holds
 *     a Neon dump, the DATABASE_URL, or a subpoena — which is the threat this product's
 *     confidentiality claim is actually sold against, and the one that can roll a blob back —
 *     that memory is sound: those adversaries write rows, they do not serve the bundle. Against
 *     an adversary who can replace the served frontend, it is worthless — but so is every other
 *     client-side check, including this one, including the passphrase prompt itself. If the
 *     attacker writes the JavaScript, they take the passphrase directly and the roster is moot.
 *     State that boundary out loud; do not let this comment imply more.
 *
 *   - A FRESH READER HAS NO MEMORY, AND THIS IS THE RESIDUAL. First unlock on a new phone: the
 *     server serves version 4, the reader has never seen 5, and nothing in the bytes says 5
 *     exists. `{ kind: 'first-use' }` is that moment, named so a caller cannot reach it by
 *     accident. It is NOT closable by cryptography inside a blob the server chooses: freshness
 *     needs either memory or an out-of-band channel, and a fresh reader has neither. What it
 *     costs an attacker is real but finite — they must already hold the secret key of a device
 *     that was once legitimately in the roster. What narrows it further is human: show the
 *     roster at first unlock ("this dashboard trusts 1 device: Anil's PC — 1A2B 3C4D ...") and
 *     an owner who revoked a laptop last week can see it listed. That is a mitigation, not a
 *     proof, and it is the honest end of this defence.
 */
export type RosterMemory =
  /**
   * This reader has never opened a bundle for this identity. It will accept whatever version it
   * is handed. Spelled as a tagged variant rather than `undefined` or a missing argument so that
   * no caller arrives here without having written the words "first use" — the residual above is
   * not something to opt into by omission.
   */
  | { kind: 'first-use' }
  /** The highest roster version this reader has ever accepted, from storage the server cannot reach. */
  | { kind: 'seen'; highestVersionSeen: number };

/**
 * Decide whether a roster version may be accepted, and return the new high-water mark.
 *
 * THE CALLER MUST PERSIST THE RETURN VALUE, somewhere the server cannot write. This function
 * cannot do it and cannot check that it was done — that is a real limit, stated rather than
 * papered over. A caller that never persists has re-created `{ kind: 'first-use' }` on every
 * unlock and gets exactly the residual documented above.
 */
export function acceptRosterVersion(memory: RosterMemory, version: number): number {
  // Shape first, always. A NaN version compares false against everything, so a `version < hwm`
  // check placed before this one would accept NaN and then poison the high-water mark with it
  // forever after.
  if (!Number.isSafeInteger(version) || version < ROSTER_FIRST_VERSION) {
    throw new RosterError(
      `roster version must be an integer >= ${ROSTER_FIRST_VERSION}, got ${String(version)}`,
    );
  }

  if (memory.kind === 'first-use') return version;

  const seen = memory.highestVersionSeen;
  if (!Number.isSafeInteger(seen) || seen < ROSTER_FIRST_VERSION) {
    // A corrupt high-water mark must not be read as "no mark, accept anything". It is read as
    // "this reader's memory is broken", which is a refusal — the caller can decide to reset it
    // to first-use deliberately, which is a different and visible act.
    throw new RosterError(
      `stored roster high-water mark is not an integer >= ${ROSTER_FIRST_VERSION}, got ` +
        `${String(seen)}: refusing to treat unreadable memory as no memory`,
    );
  }

  if (version < seen) {
    throw new RosterError(
      `roster rolled back: this bundle carries version ${version} but version ${seen} has ` +
        `already been seen. The server is serving an old wrapped key — it cannot forge one, but ` +
        `it can withhold the current one, and an old roster may still list a revoked device.`,
    );
  }

  return version;
}

/**
 * A short, human-comparable fingerprint of a device public key. For the pairing screen.
 *
 * Hashed rather than shown raw, and domain-separated: this string is for eyeballs, and 64 hex
 * characters of raw key gets compared by looking at the first four and the last four. 8 bytes
 * is 64 bits — far too short for collision resistance, which is fine because this is not a
 * collision setting. An attacker must find a SECOND PREIMAGE of a specific key's fingerprint,
 * with a key whose secret they hold, and 64 bits of second-preimage work is not free.
 */
export async function deviceFingerprint(publicKey: Uint8Array): Promise<string> {
  const sodium = await sodiumReady();
  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new Error(
      `device public key must be ${sodium.crypto_sign_PUBLICKEYBYTES} bytes, got ${publicKey.length}`,
    );
  }
  const tag = new TextEncoder().encode('tally-bridge/device-fingerprint/v1');
  const input = new Uint8Array(tag.length + publicKey.length);
  input.set(tag, 0);
  input.set(publicKey, tag.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input as BufferSource));
  const hex = Array.from(digest.subarray(0, 8), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return (hex.match(/.{4}/g) ?? []).join(' ');
}
