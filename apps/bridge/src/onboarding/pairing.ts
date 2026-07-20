import {
  ROSTER_FIRST_VERSION,
  RosterError,
  deviceFingerprint,
  sodiumReady,
  timingSafeEqual,
  wipe,
  type SealedRoster,
} from '@tally-bridge/crypto';

/**
 * Pairing a second device — in practice, the accountant's PC.
 *
 * WHY THIS EXISTS AT ALL, WHEN BOOTSTRAP_SECRET ALREADY ENROLS A DEVICE.
 *
 * Because BOOTSTRAP_SECRET is one-shot and self-disabling, and those properties are the entire
 * reason it is safe. It is the only door on the server that opens without a device key, so it
 * closes after the first success (and after 24h regardless) — see `handleRegister` in the
 * server. Anyone who ever learns it from a log line, a screenshot, or a support ticket could
 * otherwise enrol devices forever.
 *
 * So the tempting shortcut — "the accountant needs a device, just re-send BOOTSTRAP_SECRET" —
 * is not a shortcut. It is a request to un-close the one door that must stay closed, and it
 * arrives disguised as a five-minute feature request roughly every quarter. THE ANSWER IS NO.
 * Pairing is a second mechanism precisely so that the first can stay one-shot:
 *
 *   BOOTSTRAP_SECRET  minted by us during provisioning, one-shot, 24h, no session required.
 *                     It bootstraps trust from nothing, which is why it gets one use.
 *   PAIRING CODE      minted only FROM AN ALREADY-TRUSTED, AUTHENTICATED SESSION. It delegates
 *                     trust that already exists, which is why it can be issued repeatedly.
 *
 * Six digits is 20 bits — trivially brute-forceable if you let someone try. So nobody gets to
 * try: 10-minute TTL, single use, five attempts then locked. Those three together are what
 * make a number small enough to read down a phone line acceptable. Remove any one and the
 * short code becomes indefensible; the entropy was never doing the work.
 *
 * The code is also generated from libsodium's CSPRNG, never `Math.random()`. `Math.random` is
 * xorshift128+ in V8 — unseeded from a weak source, and its internal state is recoverable from
 * a handful of outputs. A pairing code drawn from it is not a secret at all.
 */

/** Ten minutes: long enough to read down a phone line, short enough to be worthless if leaked. */
export const PAIRING_TTL_MS = 10 * 60 * 1000;

/**
 * Five wrong guesses, then the code is dead.
 *
 * 5/1_000_000 is the attacker's entire budget per issued code, which makes the 20 bits
 * irrelevant. The counter must therefore be the ONLY thing standing between an attacker and
 * the code space — so it is checked before the comparison and it never resets.
 */
export const MAX_ATTEMPTS = 5;

export const CODE_DIGITS = 6;

const CODE_SPACE = 10 ** CODE_DIGITS;

/**
 * Draw an unbiased 6-digit code from the CSPRNG.
 *
 * Rejection sampling, not `% 1_000_000`. 2^32 is not a multiple of 10^6, so a bare modulo
 * makes the first 967_296 codes ~0.0000002% likelier than the rest. That bias is far too small
 * to matter here — and it is written correctly anyway, because the day someone copies this
 * function to draw something with a smaller range (a 4-digit PIN, an index into a wordlist)
 * the bias stops being negligible and nobody re-derives the maths at the copy site.
 */
export async function generatePairingCode(): Promise<string> {
  const sodium = await sodiumReady();
  const limit = Math.floor(0x1_0000_0000 / CODE_SPACE) * CODE_SPACE;
  for (;;) {
    const b = sodium.randombytes_buf(4);
    const n = ((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
    wipe(sodium, b);
    if (n >= limit) continue;
    // padStart, because "042931" is a perfectly good code and dropping the zero both shrinks
    // the space by 10% and produces a 5-digit string the accountant will mistype.
    return String(n % CODE_SPACE).padStart(CODE_DIGITS, '0');
  }
}

/**
 * A pairing code in flight.
 *
 * The code itself is NOT stored — only a hash of it. This costs nothing and means a heap dump,
 * a log of this object, or an accidental IPC round-trip of the wizard state does not hand
 * anyone a live code. It also makes the comparison fixed-width, which is what lets the
 * constant-time check be genuinely constant-time (see `claim`).
 */
export interface Pairing {
  id: string;
  /** What the owner sees in the device list afterwards, e.g. "Anil's PC". */
  label: string;
  digest: Uint8Array;
  issuedAt: number;
  expiresAt: number;
  attempts: number;
  usedAt: number | undefined;
}

export type ClaimResult =
  | { ok: true; pairingId: string; label: string }
  | {
      ok: false;
      reason: 'no_code' | 'expired' | 'used' | 'locked' | 'wrong';
      message: string;
      /** Only on `wrong`, so the accountant knows the budget is finite before it runs out. */
      attemptsLeft?: number | undefined;
    };

export interface PairingServiceOptions {
  now: () => number;
  /** Injected so tests are deterministic; production passes `generatePairingCode`. */
  generateCode?: (() => Promise<string>) | undefined;
}

async function digestOf(code: string): Promise<Uint8Array> {
  const sodium = await sodiumReady();
  // Hash first, compare second. This is not about hiding the code from an offline attacker —
  // 10^6 is instantly enumerable and no hash saves it. It is about making both sides of the
  // comparison exactly 32 bytes, so a wrong LENGTH cannot short-circuit the compare and leak
  // "your code is the wrong shape" through timing.
  // Unkeyed (BLAKE2b with a null key) is correct here: this is a domain-local digest used to
  // fix the comparison width, not a MAC. A key would imply a secret this has no way to hold.
  return sodium.crypto_generichash(32, sodium.from_string(code), null);
}

/**
 * Issues and redeems pairing codes.
 *
 * ONE LIVE CODE AT A TIME, by construction. Issuing replaces whatever was outstanding, so an
 * owner who clicks "pair a device" three times because the first code did not arrive has not
 * quietly left three live codes on the table. It also means the attempt counter cannot be
 * reset by an attacker: only the owner can issue, and issuing invalidates the code the
 * attacker was working on.
 */
export class PairingService {
  private readonly now: () => number;
  private readonly generateCode: () => Promise<string>;
  private active: Pairing | undefined;
  private counter = 0;
  /**
   * Serialises `claim`. See the comment on `claim` — without this the attempt counter and the
   * single-use flag are both racy, and both of them are load-bearing.
   */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: PairingServiceOptions) {
    // Written out rather than declared as constructor parameter properties: Node's
    // --experimental-strip-types is strip-only and cannot emit the assignments they imply.
    this.now = opts.now;
    this.generateCode = opts.generateCode ?? generatePairingCode;
  }

  /**
   * Mint a code.
   *
   * CALLERS: this must only ever be reachable from an authenticated session on an already-paired
   * device. That is the whole distinction from BOOTSTRAP_SECRET (see the header) and it cannot
   * be enforced from inside this class — enforce it at the IPC boundary.
   */
  issue(label: string): Promise<{ code: string; pairing: Pairing }> {
    // On the same queue as `claim`, for the same reason: both mutate `active`, and an issue that
    // interleaves with an in-flight claim would let that claim resolve against a pairing that is
    // no longer the live one.
    const run = this.queue.then(() => this.issueNow(label));
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async issueNow(label: string): Promise<{ code: string; pairing: Pairing }> {
    const code = await this.generateCode();
    const issuedAt = this.now();
    this.counter += 1;
    const pairing: Pairing = {
      id: `pair_${issuedAt}_${this.counter}`,
      label,
      digest: await digestOf(code),
      issuedAt,
      expiresAt: issuedAt + PAIRING_TTL_MS,
      attempts: 0,
      usedAt: undefined,
    };
    this.active = pairing;
    return { code, pairing };
  }

  /** The live code's public facts. Never includes anything that could reconstruct the code. */
  peek(): Omit<Pairing, 'digest'> | undefined {
    if (!this.active) return undefined;
    const { digest, ...rest } = this.active;
    void digest;
    return rest;
  }

  /**
   * Redeem a code.
   *
   * ORDER IS LOAD-BEARING. Every disqualifying condition is checked BEFORE the comparison, so
   * that a used, expired, or locked code cannot be probed at all — not even to learn whether a
   * guess was right. A `locked` code that still answered "correct!" would make the lockout
   * decorative.
   *
   * SERIALISED, AND THAT IS ALSO LOAD-BEARING. Ordering the checks is worthless if the checks
   * can be run concurrently: `claim` reads `attempts` before its first `await` and increments it
   * several awaits later, so every claim issued in the same tick passed the gate while the
   * counter still read 0. Verified — 1000 concurrent guesses against a budget of 5, and the
   * correct one was accepted. The counter is the ONLY thing that makes 20 bits defensible (see
   * the header), so it cannot be left to the caller to never parallelise its IPC. `usedAt` had
   * the same race, which let one single-use code enrol two devices.
   *
   * The whole read-compare-write is therefore run under a promise chain: one claim at a time,
   * process-wide. Throughput is irrelevant here — this runs at human speed, a handful of times
   * in the life of an install.
   */
  claim(code: string): Promise<ClaimResult> {
    const run = this.queue.then(() => this.claimNow(code));
    // Keep the chain alive regardless of outcome, and never let it reject: a rejected queue
    // would wedge every future claim.
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async claimNow(code: string): Promise<ClaimResult> {
    const p = this.active;
    if (!p) {
      return { ok: false, reason: 'no_code', message: 'There is no pairing code waiting. Start again on the first computer.' };
    }
    if (p.usedAt !== undefined) {
      return { ok: false, reason: 'used', message: 'That code has already been used. Create a new one on the first computer.' };
    }
    if (p.attempts >= MAX_ATTEMPTS) {
      // Note the ordering against `expired`: locked is reported even for a code that has also
      // since expired, because "too many wrong tries" is the fact worth telling the owner.
      return { ok: false, reason: 'locked', message: 'Too many wrong tries, so that code is now closed. Create a new one on the first computer.' };
    }
    if (this.now() >= p.expiresAt) {
      // Expiry does not burn an attempt. There is nothing to protect: the code is already dead.
      return { ok: false, reason: 'expired', message: 'That code has expired. Codes last ten minutes. Create a new one on the first computer.' };
    }

    const sodium = await sodiumReady();
    const given = await digestOf(code);
    const match = timingSafeEqual(sodium, given, p.digest);
    wipe(sodium, given);

    if (!match) {
      p.attempts += 1;
      const left = MAX_ATTEMPTS - p.attempts;
      if (left <= 0) {
        return { ok: false, reason: 'locked', message: 'Too many wrong tries, so that code is now closed. Create a new one on the first computer.', attemptsLeft: 0 };
      }
      return {
        ok: false,
        reason: 'wrong',
        message:
          left === 1
            ? 'That code is not right. You have one more try before it closes.'
            : `That code is not right. You have ${left} more tries.`,
        attemptsLeft: left,
      };
    }

    // Single use. Marked BEFORE returning, so a caller that throws downstream cannot leave a
    // spent code live — the device it enrolled is the only one that code will ever enrol.
    p.usedAt = this.now();
    return { ok: true, pairingId: p.id, label: p.label };
  }

  /** Owner clicked "cancel". The code dies immediately rather than lingering for ten minutes. */
  cancel(): void {
    this.active = undefined;
  }
}

/** How the code is read out loud: "042 931". Grouping halves the mis-transcription rate. */
export function formatPairingCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/* ------------------------------------------------------------------ *
 * Admission — putting the new device's key into the pinned roster
 * ------------------------------------------------------------------ */

/**
 * ==========================================================================================
 * THE CODE IS NOT THE HARD PART. THE KEY IS.
 * ==========================================================================================
 *
 * Everything above proves that whoever typed the code was told the code by the owner. That is
 * worth having and it is not what protects the roster.
 *
 * The roster is the reader's list of "device public keys whose envelopes are real financial
 * data rather than the server's fabrications" (read `packages/crypto/src/trust.ts`, all of it,
 * before touching this section). It travels to the reader sealed inside the wrapped identity,
 * where the server cannot rewrite it. So the attack moves to the only remaining soft spot:
 * GETTING A KEY INTO IT.
 *
 * Device 2 generates its own Ed25519 keypair and registers the public half WITH THE SERVER —
 * it has to; the server verifies device 2's RFC 9421 upload signatures with it. Now this
 * machine, device 1, needs that key in order to add it to the roster and re-seal. The obvious
 * implementation is:
 *
 *     const key = await api.getDevice(pairingId).publicKey;   // <-- CATASTROPHE
 *     roster.push({ deviceId, publicKey: key });
 *
 * A malicious server answers that call with a key IT generated. The owner's passphrase then
 * seals the attacker's key into the bundle. Every layer downstream works perfectly: the bundle
 * is authentic, the roster is pinned, the signature verifies — against the attacker's key. The
 * dashboard renders fabricated receivables under a green checkmark, and the sealed-roster
 * mechanism has done nothing except launder the server's key into a trusted one. The whole
 * chain is exactly as strong as this step.
 *
 * So the key that goes into the roster must be confirmed by a HUMAN, OUT OF BAND, against what
 * the new machine itself displays. That is SSH's host-key prompt and Signal's safety numbers,
 * and there is no cleverer answer available here: device 1 and device 2 share no secret except
 * a 6-digit code that device 2 learned over the phone, and 20 bits will not authenticate a
 * key exchange.
 *
 * THE CEREMONY:
 *   1. Owner, on device 1: "Pair a new PC" -> `issue(label)` -> reads the code down the phone.
 *   2. Device 2: generates its keypair, redeems the code, registers with the server, and shows
 *      `deviceFingerprint(itsOwnPublicKey)` on its own screen.
 *   3. Owner, on device 1: types the fingerprint the accountant reads back. `admitPairedDevice`
 *      recomputes the fingerprint FROM THE KEY IT IS ABOUT TO SEAL and refuses unless they
 *      match. A server-substituted key produces a different fingerprint, and the owner is
 *      reading the real one off the real machine, so the substitution is caught here.
 *   4. Device 1 prompts for the PASSPHRASE, opens the identity (`openIdentity`), and re-seals
 *      all three wraps with the new roster (`wrapIdentity`).
 *
 * ON STEP 4 AND WHETHER THE PASSPHRASE PROMPT IS ACCEPTABLE: it is not a policy choice, it is
 * arithmetic. Writing a new passphrase wrap means deriving the KEK, which means Argon2id over
 * the passphrase. Nobody holds the KEK afterwards — it is wiped — so there is no version of
 * this flow that adds a device without the owner typing the passphrase. Pairing already
 * requires an authenticated session on an already-trusted device (see the header), so the owner
 * is present at a keyboard by construction; asking them for the passphrase is one extra field
 * on a screen they are already looking at.
 *
 * A READER HOLDING AN OLDER BUNDLE, one sealed before device 2 existed, pins a roster without
 * device 2 and REFUSES device 2's envelopes — `openSection` throws "untrusted device". That is
 * fail-closed and it is self-healing: the next unlock fetches the current bundle. It is not a
 * silent wrong number, which is the only outcome that would matter.
 */

/** A device asking to be let in: what it calls itself, and the key it will sign with. */
export interface CandidateDevice {
  /** Must match `aad.deviceId` on the envelopes it will later upload. */
  deviceId: string;
  /** What the owner sees in the device list, e.g. "Anil's PC". */
  label: string;
  /** Ed25519 public key, 32 bytes — the key this device will sign envelopes AND uploads with. */
  publicKey: Uint8Array;
}

/**
 * What device 1 must show the owner so they can ask for the right thing.
 *
 * The fingerprint here is computed from the candidate key. It is NOT the thing being verified —
 * it is the thing being COMPARED AGAINST, and it is only worth anything if the owner obtains
 * the other copy from device 2's own screen, over the phone, out of band. A UI that displays
 * both halves of this comparison side by side and asks "do these match?" has verified nothing:
 * both would come from the same server-supplied key.
 */
export async function describeAdmission(
  candidate: CandidateDevice,
): Promise<{ fingerprint: string; prompt: string }> {
  const fingerprint = await deviceFingerprint(candidate.publicKey);
  return {
    fingerprint,
    prompt:
      `Ask the person at "${candidate.label}" to read out the eight groups shown on their ` +
      `screen, and type them here. Do not copy them from this screen — the point of the check ` +
      `is that the two came to you by different routes.`,
  };
}

export type AdmissionResult =
  | { ok: true; roster: SealedRoster }
  | {
      ok: false;
      reason: 'fingerprint_mismatch' | 'bad_key' | 'already_present' | 'stale_claim';
      message: string;
    };

/**
 * Normalize a fingerprint for comparison: "1a2b 3c4d..." and "1A2B3C4D..." are the same answer.
 *
 * Returns undefined for anything that is not 16 hex characters. Being strict is the point: a
 * fingerprint typed as "sounds right" must not compare equal to anything, and a caller that
 * passes an empty string must not find that it matches an empty expectation.
 */
function normalizeFingerprint(s: string): string | undefined {
  if (typeof s !== 'string') return undefined;
  const compact = s.replace(/\s+/g, '').toUpperCase();
  return /^[0-9A-F]{16}$/.test(compact) ? compact : undefined;
}

/**
 * Admit a device to the roster — the ONLY function that adds a key to one.
 *
 * There is deliberately no "just append this key" helper next to it. The confirmation is not an
 * option this function takes; it is the reason it exists, and the roster it returns is not
 * reachable without one.
 */
export async function admitPairedDevice(opts: {
  /**
   * The claim from redeeming the pairing code.
   *
   * NOT proof of redemption, however much the type looks like it. An earlier version of this line
   * said "Proof the code was actually redeemed" — that was FALSE: only `claim.label` is read below,
   * so a fabricated claim naming a `pairingId` that was never issued is admitted, and the
   * `stale_claim` reason name overpromises the same way. Enforcing redemption needs a registry of
   * live claims that this codebase does not have yet.
   *
   * This is not a hole, because the claim is NOT the gate — `confirmedFingerprint` is, and it
   * cannot be forged by anything the server says. But do not add a second caller on the belief
   * that passing a claim proves anything: it proves a label matched.
   */
  claim: Extract<ClaimResult, { ok: true }>;
  candidate: CandidateDevice;
  /** What the OWNER READ OFF DEVICE 2'S SCREEN and typed here. Not what any API returned. */
  confirmedFingerprint: string;
  /** The roster as it stands, from the currently-open bundle. */
  current: SealedRoster;
}): Promise<AdmissionResult> {
  const { candidate, current } = opts;

  if (typeof candidate.deviceId !== 'string' || candidate.deviceId.length === 0) {
    return { ok: false, reason: 'bad_key', message: 'That device did not give a device id.' };
  }
  if (!(candidate.publicKey instanceof Uint8Array) || candidate.publicKey.length !== 32) {
    // deviceFingerprint would throw on this; catching it here means the owner gets a sentence
    // rather than a stack trace, and means the length is checked before it reaches the roster.
    return {
      ok: false,
      reason: 'bad_key',
      message: 'That device did not give a usable signing key. Start the pairing again.',
    };
  }
  if (opts.claim.label !== candidate.label) {
    // The claim named the device the OWNER labelled when they issued the code. A candidate
    // arriving under a different label is not necessarily an attack, but it is not the pairing
    // the owner started, and silently sealing a key from a different flow into the roster is
    // exactly the kind of "probably fine" that this file must not do.
    return {
      ok: false,
      reason: 'stale_claim',
      message:
        `This pairing was started for "${opts.claim.label}" but the device calls itself ` +
        `"${candidate.label}". Start the pairing again.`,
    };
  }

  const expected = normalizeFingerprint(await deviceFingerprint(candidate.publicKey));
  const given = normalizeFingerprint(opts.confirmedFingerprint);
  if (!given) {
    return {
      ok: false,
      reason: 'fingerprint_mismatch',
      message:
        'That is not a complete safety code. It is eight groups of four characters, using the ' +
        'digits 0-9 and the letters A-F. Ask them to read it out again.',
    };
  }
  // `expected` is derived from a 32-byte key by `deviceFingerprint`, which always yields 16 hex
  // characters — so this cannot fire. It is here because if it ever did, `undefined === undefined`
  // would make the one gate in this flow that must be unskippable, skippable. That exact bug has
  // already been written once in this codebase, in `makeVerificationChallenge`.
  if (!expected) {
    return {
      ok: false,
      reason: 'bad_key',
      message: 'That device did not give a usable signing key. Start the pairing again.',
    };
  }
  if (expected !== given) {
    return {
      ok: false,
      reason: 'fingerprint_mismatch',
      message:
        'That safety code does not match this device. Do not continue: either the code was ' +
        'misread, or the key being offered is not the one on that computer. Read it out once ' +
        'more, and if it still does not match, stop and get help.',
    };
  }

  const b64 = Buffer.from(candidate.publicKey).toString('base64');
  const duplicate = current.devices.some(
    (d) => d.deviceId === candidate.deviceId && Buffer.from(d.publicKey).toString('base64') === b64,
  );
  if (duplicate) {
    // Not an error worth alarming anyone about, but it must not bump the version: a version
    // bump with no change would push every reader's high-water mark forward for nothing, and
    // the high-water mark is the entire rollback defence.
    return {
      ok: false,
      reason: 'already_present',
      message: `"${candidate.label}" is already paired with this exact key. Nothing to do.`,
    };
  }

  return {
    ok: true,
    roster: {
      version: current.version + 1,
      devices: [
        ...current.devices,
        { deviceId: candidate.deviceId, publicKey: candidate.publicKey },
      ],
    },
  };
}

/**
 * Remove a device. The other half of the roster's life, and the half rollback attacks target:
 * an old bundle still lists what this removed, which is why every write bumps the version and
 * why readers must remember the highest they have seen (see `RosterMemory` in trust.ts).
 *
 * Removes EVERY key for the deviceId, not the first match. A device may legitimately hold more
 * than one entry during key rotation, and a revocation that leaves the old key behind has
 * revoked nothing.
 */
export function revokeDevice(current: SealedRoster, deviceId: string): SealedRoster {
  const devices = current.devices.filter((d) => d.deviceId !== deviceId);
  if (devices.length === current.devices.length) {
    throw new RosterError(`${deviceId} is not in the roster: nothing to revoke`);
  }
  if (devices.length === 0) {
    // An empty roster is refused everywhere downstream (`encodeRoster`, `decodeRoster`,
    // `openSection`), so this would produce a bundle that cannot be sealed. Say why here, where
    // the owner's action is, instead of failing three layers down.
    throw new RosterError(
      `refusing to revoke ${deviceId}: it is the only device left, and an empty roster means ` +
        `the dashboard can verify nothing and will show nothing. Pair the replacement first, ` +
        `then revoke this one.`,
    );
  }
  return { version: current.version + 1, devices };
}

/**
 * The roster at onboarding: this machine, and only this machine.
 *
 * The one place a key enters a roster with no fingerprint ceremony, and the one place that is
 * correct: device 1 is holding its OWN freshly generated public key, in memory, with no server
 * anywhere in the path. There is nothing to confirm and nobody to confirm it against. Every
 * device after this one goes through `admitPairedDevice`.
 */
export function initialRoster(device: { deviceId: string; publicKey: Uint8Array }): SealedRoster {
  if (!(device.publicKey instanceof Uint8Array) || device.publicKey.length !== 32) {
    throw new RosterError('the first device must have a 32-byte Ed25519 public key');
  }
  if (typeof device.deviceId !== 'string' || device.deviceId.length === 0) {
    throw new RosterError('the first device must have a deviceId');
  }
  return {
    version: ROSTER_FIRST_VERSION,
    devices: [{ deviceId: device.deviceId, publicKey: device.publicKey }],
  };
}
