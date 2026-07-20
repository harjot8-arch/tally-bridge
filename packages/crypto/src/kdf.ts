import type { KdfParams } from '@tally-bridge/core';
import { sodiumReady } from './sodium.ts';

/**
 * Key derivation.
 *
 * Argon2id for the human passphrase; HKDF for everything else.
 *
 * Argon2id over PBKDF2: PBKDF2-SHA256's only real advantage is being WebCrypto-native with
 * zero bundle cost. We need libsodium wasm anyway (XChaCha20, sealed boxes), so that advantage
 * evaporates. What remains is that PBKDF2-SHA256 is the most GPU-friendly KDF still in
 * respectable use — trivially parallel, no memory hardness. Against the passphrases this
 * audience actually chooses ("tally123", "Ramesh@1985") that difference is the whole ballgame:
 * Argon2id at 64 MiB collapses GPU parallelism to roughly memory-bandwidth ÷ 64 MiB.
 */

/**
 * Argon2id parameters.
 *
 * m=64MiB is ~3x OWASP's floor (19 MiB), which is a minimum for SERVER-SIDE login hashing at
 * request rates — not a target for a once-per-session client-side unlock. We can afford more.
 * 64 MiB is also comfortably inside wasm's 32-bit memory and safe on mobile Safari, which is
 * the real ceiling (>256 MiB risks OOM on iOS).
 *
 * Measured: ~475ms on an Apple laptop, ~124ms at the m=46MiB/t=2 fallback. Still to be
 * measured on a low-end Windows laptop and a mid-range Android; if unlock exceeds ~3s there,
 * drop to m=46MiB/t=2 rather than abandoning Argon2id.
 */
export const ARGON2ID_MEMLIMIT_BYTES = 64 * 1024 * 1024;
export const ARGON2ID_OPSLIMIT = 3;

/**
 * The band of Argon2id parameters we will HONOUR from a blob.
 *
 * `deriveRoot` takes its params from the blob rather than from the constants above, which is
 * correct and deliberate — it is what allows parameters to be raised later without orphaning
 * existing wrapped keys. But it also means these are attacker-reachable input. The blob comes
 * from a server we explicitly do not trust, and `WrappedKey` does not bind its `kdf` descriptor
 * to the ciphertext, so a Neon dump holder or anyone with the `DATABASE_URL` can rewrite them.
 * Unbounded, both directions are exploitable:
 *
 *   Too weak: libsodium's own floor is MEMLIMIT_MIN = 8192 bytes and OPSLIMIT_MIN = 1, and it
 *   honours them without complaint — measured at ~10ms against ~3000ms for our defaults. That
 *   is a ~300x speedup for an offline cracker grinding "tally123", i.e. the entire security
 *   margin of the passphrase path. Note this is defence in depth rather than a live hole: the
 *   only writer of params is `defaultKdfParams`, so no blob in existence is below the floor,
 *   and swapped-in weak params make the unwrap fail rather than succeed. It closes the door on
 *   a future setup path that takes params from anywhere else.
 *
 *   Too expensive: this is the direction that reaches users today. This dashboard is meant to
 *   be opened on a phone; m=1GiB measured at 50s and m=64MiB/t=40 at 46s, and nothing stopped
 *   m=16GiB/t=2^31. A hostile blob is a hard OOM on iOS Safari, which the note above pins as
 *   the real ceiling at ~256MiB.
 *
 * The floor MUST stay at or below the shipped defaults or this build rejects its own blobs —
 * `kdf.test.ts` asserts exactly that. The floor is OWASP's Argon2id minimum (19MiB, t=2), which
 * also leaves room for the m=46MiB/t=2 fallback the comment above contemplates.
 */
export const ARGON2ID_MIN_MEMLIMIT_BYTES = 19 * 1024 * 1024;
export const ARGON2ID_MIN_OPSLIMIT = 2;
export const ARGON2ID_MAX_MEMLIMIT_BYTES = 256 * 1024 * 1024;
export const ARGON2ID_MAX_OPSLIMIT = 10;

/**
 * These are RAW INTEGERS on purpose.
 *
 * Never use libsodium's crypto_pwhash_MEMLIMIT_* / OPSLIMIT_* named constants here. Their
 * values have changed across libsodium releases, so a silent dependency bump would change
 * every derivation and make every existing wrapped key permanently underivable — a
 * self-inflicted mass data-loss event, discovered only when users cannot log in.
 *
 * (For reference: this libsodium build reports MEMLIMIT_MODERATE = 268435456 and
 * OPSLIMIT_MODERATE = 3. We do not use them.)
 */
export function defaultKdfParams(salt: Uint8Array): KdfParams {
  return {
    v: 1,
    kdf: 'argon2id',
    m: ARGON2ID_MEMLIMIT_BYTES,
    t: ARGON2ID_OPSLIMIT,
    p: 1,
    salt: toBase64(salt),
  };
}

export async function randomSalt(): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
}

/**
 * Derive the root key from a passphrase using the params CARRIED IN THE BLOB.
 *
 * Deriving from `params` rather than from this module's compiled-in defaults is what makes
 * it possible to raise parameters later: an old blob keeps deriving with its own params while
 * new blobs use stronger ones. Without this, the parameters are frozen forever at whatever
 * shipped first.
 */
export async function deriveRoot(passphrase: string, params: KdfParams): Promise<Uint8Array> {
  if (params.kdf !== 'argon2id') {
    throw new Error(`unsupported kdf: ${String(params.kdf)}`);
  }
  if (params.p !== 1) {
    // libsodium's crypto_pwhash pins parallelism to 1 internally; a blob asking for more
    // cannot be honoured and must not be silently downgraded.
    throw new Error(`unsupported argon2id parallelism: ${String(params.p)}`);
  }
  // The params are hostile input — see the band constants above. Validate shape before cost,
  // so a non-integer never reaches libsodium as a coerced value.
  if (!Number.isSafeInteger(params.m) || !Number.isSafeInteger(params.t)) {
    throw new Error(
      `argon2id params must be integers, got m=${String(params.m)} t=${String(params.t)}`,
    );
  }
  if (params.m < ARGON2ID_MIN_MEMLIMIT_BYTES || params.t < ARGON2ID_MIN_OPSLIMIT) {
    throw new Error(
      `argon2id params too weak: m=${params.m} t=${params.t} ` +
        `(floor m=${ARGON2ID_MIN_MEMLIMIT_BYTES} t=${ARGON2ID_MIN_OPSLIMIT}). ` +
        `Refusing to derive — a blob asking for less is not one we wrote.`,
    );
  }
  if (params.m > ARGON2ID_MAX_MEMLIMIT_BYTES || params.t > ARGON2ID_MAX_OPSLIMIT) {
    throw new Error(
      `argon2id params too expensive: m=${params.m} t=${params.t} ` +
        `(ceiling m=${ARGON2ID_MAX_MEMLIMIT_BYTES} t=${ARGON2ID_MAX_OPSLIMIT}). ` +
        `Refusing to derive — this would hang or OOM the device.`,
    );
  }
  const sodium = await sodiumReady();
  const salt = fromBase64(params.salt);
  if (salt.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error(
      `bad salt length: expected ${sodium.crypto_pwhash_SALTBYTES}, got ${salt.length}`,
    );
  }
  return sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    params.t,
    params.m,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Domain-separation labels.
 *
 * The Argon2id output is a ROOT, never used as a key directly. Branching through HKDF is free
 * and means a future second use of the root cannot become a cross-protocol attack.
 */
export const KDF_INFO = {
  /** Wraps the identity secret key under the passphrase. */
  kek: 'tally/v1/kek',
  /** Wraps the identity secret key under the recovery key. */
  recovery: 'tally/v1/recovery',
  /** Wraps the identity secret key under the device-bound key (opt-in "remember this PC"). */
  device: 'tally/v1/device',
  /**
   * Proves to the SERVER that the caller knows the passphrase — and proves nothing else.
   *
   * This is the sibling of `kek`, and the whole security argument is that they are siblings
   * rather than derivations of one another. One Argon2id run over the owner's passphrase yields
   * a root; `kek` unwraps their identity secret and NEVER leaves the browser; `auth` is sent to
   * the server, which stores only SHA-256 of it. HKDF siblings do not reveal each other, so a
   * server holding the auth token — or an attacker holding the whole database — cannot walk back
   * to the KEK. It is the same split Bitwarden and 1Password make, for the same reason.
   *
   * WHY THE SERVER-SIDE HASH IS PLAIN SHA-256 AND NOT ANOTHER ARGON2ID. The auth token already
   * carries 256 bits behind a ~475ms Argon2id. An attacker with the dump can brute-force
   * passphrases against that hash — but they can ALREADY do exactly that against the
   * `wrapped_key` blob sitting in the same dump, at the same Argon2id cost. Measured: the hash
   * path costs Argon2id + 2×HKDF + SHA-256; the wrapped-key path costs Argon2id + HKDF + one
   * AEAD-open of a sub-kilobyte blob. The difference is single-digit microseconds on a 475ms
   * operation — under 0.01% — so storing it adds no oracle that the dump did not already
   * contain. (This was checked before it was written down, and it is the kind of claim that is
   * repeated far more often than it is verified.)
   *
   * WHAT THE SESSION IS FOR, since it is not the security boundary — the crypto is. It stops the
   * deployment URL from being a PUBLIC OFFLINE-ATTACK ORACLE. Without it, anyone with the URL
   * fetches every sealed envelope and every wrapped key and attacks them at leisure, and this
   * audience will choose `tally123`. That is what the door is buying.
   *
   * THE SALT SUBTLETY, which is easy to miss and fatal: `wrapUnderPassphrase` mints a FRESH salt
   * per wrap. The auth token is therefore only derivable if the server's prelogin endpoint
   * serves back the SAME params that are sealed in the `pass` blob. apps/server writes
   * `login_credential.kdf` from the pass blob's own kdf object in the same request, so the two
   * cannot drift; one Argon2id run in the browser then serves both login and unwrap.
   */
  auth: 'tally/v1/auth',
} as const;

/**
 * HKDF-SHA256 via WebCrypto.
 *
 * WebCrypto rather than libsodium: libsodium-wrappers does not expose
 * crypto_kdf_hkdf_sha256_*, and HKDF is native and identical in Node 22 and every browser.
 *
 * Note this is NOT a password KDF and must never be fed a passphrase. It is for inputs that
 * already carry full entropy — the Argon2id root, or a 256-bit recovery key. Running Argon2id
 * over a 256-bit random recovery key would be cargo-cult: there is nothing to slow down.
 */
export async function hkdf(
  ikm: Uint8Array,
  info: string,
  length = 32,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      // Empty salt is correct per RFC 5869 when the IKM is already uniformly random;
      // the domain separation lives in `info`.
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

export function toBase64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
}

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
