/**
 * Padme padding — Nikitin et al., PETS 2019 ("Reducing Metadata Leakage from Encrypted Files").
 *
 * Why pad at all: CRIME/BREACH do not apply here (they need attacker-chosen plaintext
 * co-compressed with a secret plus an adaptive oracle; the server operator does not inject
 * rows into a trader's books, and we compress once per sync). The leak that IS real is plain
 * ciphertext LENGTH observed as a time series. A Neon dump holder who sees a section's size
 * each day can sketch business activity: seasonality, growth, a sudden collapse in debtor
 * count. Cheap to blunt, so we blunt it.
 *
 * Why Padme over next-power-of-two or fixed buckets: Padme caps overhead at ~12% while
 * limiting leakage to O(log log n) bits. Power-of-two bucketing leaks a coarse bucket index
 * AND wastes up to 100%. Padme is better on both axes simultaneously, which is unusual enough
 * to be worth stating.
 */

/**
 * Round `len` up to the nearest Padme length.
 *
 *   E = floor(log2(L))          exponent
 *   S = floor(log2(E)) + 1      bits needed to represent the exponent
 *   z = E - S                   low bits to zero
 *   return (L + (2^z - 1)) & ~(2^z - 1)
 */
export function padmeLength(len: number): number {
  if (!Number.isInteger(len) || len < 0) {
    throw new RangeError(`padmeLength expects a non-negative integer, got ${len}`);
  }
  // Bit tricks below use int32 ops; our payloads are far below this, but be explicit.
  if (len >= 2 ** 30) {
    throw new RangeError(`payload too large to pad: ${len}`);
  }
  if (len < 2) return len;

  // `31 - clz32(x)` is an exact floor(log2(x)) for x >= 1. Math.log2 is not used here:
  // it is a float operation and can land just under an integer at powers of two, which
  // would silently change the padding class.
  const E = 31 - Math.clz32(len);
  if (E < 1) return len;
  const S = 31 - Math.clz32(E) + 1;
  const z = E - S;
  if (z <= 0) return len;

  const mask = (1 << z) - 1;
  return (len + mask) & ~mask;
}

/** Bytes used to carry the true length. Big-endian uint32, prefixed before the data. */
const LENGTH_PREFIX_BYTES = 4;

/**
 * Frame and pad a payload: `[uint32be trueLength][data][zero padding]`.
 *
 * The result is what gets encrypted, so the padding is authenticated by the Poly1305 tag —
 * the server cannot strip or tamper with it undetected.
 */
export function pad(data: Uint8Array): Uint8Array {
  const framed = LENGTH_PREFIX_BYTES + data.length;
  const target = padmeLength(framed);
  const out = new Uint8Array(target);
  new DataView(out.buffer, out.byteOffset, LENGTH_PREFIX_BYTES).setUint32(0, data.length, false);
  out.set(data, LENGTH_PREFIX_BYTES);
  return out;
}

/** Reverse `pad`. Only call on plaintext that has already passed AEAD verification. */
export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < LENGTH_PREFIX_BYTES) {
    throw new RangeError(`padded payload is too short to contain a length prefix`);
  }
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const trueLength = view.getUint32(0, false);
  if (trueLength > padded.length - LENGTH_PREFIX_BYTES) {
    // Unreachable for an authentic payload — the AEAD tag covers this prefix. Reaching it
    // means either a bug or an attempt to force an over-read, so refuse rather than clamp.
    throw new RangeError(
      `declared length ${trueLength} exceeds padded payload (${padded.length - LENGTH_PREFIX_BYTES} available)`,
    );
  }
  return padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + trueLength);
}
