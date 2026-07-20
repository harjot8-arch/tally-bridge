/**
 * Canonical serialization.
 *
 * This is load-bearing and its failure mode is silent. Section hashing gates every upload:
 * if the same data can serialize two different ways, the hash flaps, every cycle uploads,
 * and nothing ever errors — you just pay for bandwidth forever and never notice.
 * The `hashHitRate` health metric exists to catch exactly that.
 *
 * Rules:
 *   - object keys sorted by code unit
 *   - amounts fixed to 2 decimals, `-0` normalized to `0`
 *   - no whitespace
 *   - undefined/function/symbol values rejected rather than silently dropped
 */

/**
 * Amounts are money, and money is carried as integer paise.
 *
 * This bound is `MAX_SAFE_INTEGER / 100` and nothing else, because the *paise* result is what
 * has to be exact. The previous bound (1e15 rupees) was chosen for a different and wrong
 * reason — the point at which `toFixed` switches to exponential — and sat two orders of
 * magnitude ABOVE the precision limit: `toPaise(90071992547409.93)` returned 9007199254740994,
 * which is neither exact nor even the correctly-rounded answer. Money must throw, never come
 * back quietly wrong.
 *
 * ~Rs 900 billion. No Tally book this ships to comes close.
 */
const MAX_SAFE_AMOUNT = Number.MAX_SAFE_INTEGER / 100;

/**
 * Parse a decimal amount string straight to integer paise, without ever constructing a float.
 *
 * THIS IS THE EXTRACTION PATH. Tally hands us decimal strings ("125000.00", "-3421.50"), and
 * routing them through `Number()` re-introduces exactly the representation error we are trying
 * to avoid: `1.005 * 100` is `100.49999999999999` in float64, so it rounds DOWN to 100 paise.
 * Scaling before rounding does not help, because the multiply is itself lossy. Parsing the
 * digits directly means there is no rounding step to get wrong.
 *
 * Accepts an optional sign, digits, and up to two decimal places. Tally emits at most 2dp for
 * currency; more than that is a signal we are reading a field we think we understand and don't,
 * so it throws rather than silently truncating.
 */
export function parseAmountToPaise(s: string): number {
  const m = /^\s*([+-]?)(\d+)(?:\.(\d{1,2}))?\s*$/.exec(s);
  if (!m) {
    throw new TypeError(
      `not a 2dp decimal amount: ${JSON.stringify(s)}. ` +
        `Tally amounts must be normalized (Dr/Cr resolved, "(-)" rewritten) before parsing.`,
    );
  }
  const [, sign, whole, frac = ''] = m;
  const paiseStr = whole! + frac.padEnd(2, '0');
  const paise = Number(paiseStr);
  if (!Number.isSafeInteger(paise)) {
    throw new RangeError(`amount out of range: ${s}`);
  }
  // `-0` must not escape: Tally does emit "-0.00", and negating zero yields negative zero,
  // which is !== 0 under Object.is and would make otherwise-identical data hash differently.
  if (paise === 0) return 0;
  return sign === '-' ? -paise : paise;
}

/**
 * Convert a float rupee value to integer paise.
 *
 * Prefer `parseAmountToPaise` wherever the source is a string — this function is for values
 * that are already numbers (test fixtures, arithmetic results).
 *
 * Caveat, stated because it bit us: this is NOT exact at half-paise boundaries. `toPaise(1.005)`
 * is 100, not 101, because 1.005 has no exact float64 representation and lands just below the
 * midpoint. That is acceptable only because half-paise values never arise here: extracted
 * amounts come from `parseAmountToPaise` (exact), and computed amounts come from summing
 * integer paise (exact). If you find yourself relying on this function's rounding behaviour,
 * you have a float somewhere upstream that shouldn't be there.
 */
export function toPaise(rupees: number): number {
  if (!Number.isFinite(rupees)) {
    throw new TypeError(`amount is not finite: ${rupees}`);
  }
  if (Math.abs(rupees) > MAX_SAFE_AMOUNT) {
    throw new RangeError(`amount out of range: ${rupees}`);
  }
  const paise = Math.round(rupees * 100);
  // Belt and braces: the bound above is derived from MAX_SAFE_INTEGER, so this cannot fire.
  // It is here because the failure it guards is silent, and a future edit to MAX_SAFE_AMOUNT
  // must not be able to reintroduce it.
  if (!Number.isSafeInteger(paise)) {
    throw new RangeError(`amount out of range: ${rupees}`);
  }
  return paise;
}

export function fromPaise(paise: number): number {
  return paise / 100;
}

/**
 * The inverse of `canonicalAmount`: a canonical 2dp decimal string back to a rupee number.
 *
 * THIS IS THE HYDRATION PATH, and it is the seam that BUG-6 fell through. `canonicalAmount`
 * turns a rupee number into the wire string; nothing turned it back, so amounts arrived at the
 * card layer as strings while `Amount` claimed to be `number`. Cards that did arithmetic threw;
 * cards that did string concatenation silently rendered plausible nonsense.
 *
 * It parses via `parseAmountToPaise`, so it inherits that function's exactness and — the part
 * that matters — its LOUDNESS. Garbage throws. It must never coerce: `Number("₹1,00,000")` is
 * `NaN` and `Number("")` is `0`, and a silent zero in a money product is a wrong number wearing
 * a confident face.
 *
 * Prefer `parseAmountToPaise` directly when you are about to do arithmetic — summing integer
 * paise is exact, whereas summing the rupee floats this returns re-introduces the rounding step
 * the wire format exists to avoid.
 */
export function parseAmount(s: string): number {
  return fromPaise(parseAmountToPaise(s));
}

/** Sum rupee amounts exactly, via paise. */
export function sumAmounts(amounts: readonly number[]): number {
  let paise = 0;
  for (const a of amounts) paise += toPaise(a);
  return fromPaise(paise);
}

/**
 * Sum integer paise, refusing to lose a paisa quietly.
 *
 * Addition of safe integers is exact right up until the total leaves the safe range, at which
 * point `+` starts rounding and says nothing — `2**53 + 1 === 2**53`. That is the same class of
 * silent-wrong-answer `toPaise` throws for, so it throws here too. Reaching it needs ~Rs 900
 * billion in one card; the check exists because the failure would otherwise be invisible, not
 * because we expect it.
 *
 * Every input must already BE integer paise (from `parseAmountToPaise` or `toPaise`); a float
 * sneaking in here would defeat the entire point of the paise representation, so it throws.
 */
export function sumPaise(paise: readonly number[]): number {
  let total = 0;
  for (const p of paise) {
    if (!Number.isSafeInteger(p)) {
      throw new TypeError(
        `not integer paise: ${p}. Parse with parseAmountToPaise() or convert with toPaise() ` +
          `before summing — a float here reintroduces the rounding the paise representation exists to avoid.`,
      );
    }
    total += p;
    if (!Number.isSafeInteger(total)) {
      throw new RangeError(`paise total out of range at ${total}: the sum can no longer be exact`);
    }
  }
  return total;
}

/**
 * Render an amount to its canonical string.
 * `-0`, `-0.001` and `0` all collapse to `"0.00"` — without this, a computed `-0` and a
 * literal `0` would hash differently.
 */
export function canonicalAmount(rupees: number): string {
  const paise = toPaise(rupees);
  // `Object.is(-0, 0)` is false, and (-0).toFixed(2) === "0.00" already, but a value like
  // -0.001 rounds to -0 paise and would render "-0.00" without this guard.
  const normalized = paise === 0 ? 0 : paise;
  return (normalized / 100).toFixed(2);
}

/**
 * Render integer paise to the canonical wire string, without going through a float.
 *
 * `canonicalAmount` takes RUPEES, so a producer holding exact paise reaches the wire via
 * `canonicalAmount(fromPaise(p))` — dividing an exact integer into a float and multiplying it
 * back. **That round trip is exact.** It was measured across the safe integer range, including
 * MAX_SAFE_INTEGER, and it agrees with this function everywhere; the error in `p/100 * 100` stays
 * far below the 0.5 that `Math.round` needs to recover `p`. An earlier version of this comment
 * claimed otherwise and was wrong.
 *
 * So this exists for three smaller reasons, not to fix a live rounding bug:
 *   - It says what it means. The aggregator sums bills in paise; `fromPaise` then `toPaise` is a
 *     detour that a reader has to prove correct before trusting, and the proof above is not
 *     obvious enough to re-derive at every call site.
 *   - Its correctness needs no argument about double spacing near 2^53. Slicing a digit string is
 *     unconditionally exact; `String(n)` is exact for every safe integer and never reaches
 *     exponent notation below 1e21.
 *   - It REFUSES a float. `canonicalAmount(fromPaise(x))` silently accepts a rupee float that was
 *     never integer paise to begin with, which is the actual way precision leaks into this path.
 */
export function canonicalAmountFromPaise(paise: number): string {
  if (!Number.isSafeInteger(paise)) {
    throw new TypeError(
      `not integer paise: ${paise}. Use canonicalAmount() for a rupee number, or parse with ` +
        `parseAmountToPaise() first — a float here defeats the point of the paise representation.`,
    );
  }
  // `-0` and `0` must render identically or a computed -0 flaps the section hash against a
  // literal 0 and defeats the upload gate. Same guard as canonicalAmount, same reason.
  const n = paise === 0 ? 0 : paise;
  const digits = String(Math.abs(n)).padStart(3, '0');
  return `${n < 0 ? '-' : ''}${digits.slice(0, -2)}.${digits.slice(-2)}`;
}

export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | readonly CanonicalValue[]
  | { readonly [k: string]: CanonicalValue };

/**
 * Deterministic JSON. Distinct from JSON.stringify in three ways that matter:
 *   - keys are sorted, so object construction order cannot change the hash
 *   - `undefined` throws instead of vanishing (a dropped field is a silent data change)
 *   - non-integer numbers are rejected; amounts must be pre-rendered via `canonicalAmount`
 *     so that float formatting can never differ between Node and the browser
 */
export function canonicalStringify(value: CanonicalValue): string {
  return serialize(value, []);
}

function serialize(value: CanonicalValue, path: string[]): string {
  if (value === null) return 'null';

  const t = typeof value;

  if (t === 'string') return JSON.stringify(value);
  if (t === 'boolean') return value ? 'true' : 'false';

  if (t === 'number') {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new TypeError(`non-finite number at ${fmtPath(path)}: ${n}`);
    }
    if (!Number.isInteger(n)) {
      throw new TypeError(
        `non-integer number at ${fmtPath(path)}: ${n}. ` +
          `Render amounts with canonicalAmount() before hashing — float formatting is not ` +
          `guaranteed identical across runtimes.`,
      );
    }
    // Integer, so no -0 (Object.is(-0,0) aside, JSON.stringify(-0) is already "0").
    return String(n === 0 ? 0 : n);
  }

  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      // A hole is not `undefined`: `Array.prototype.map` SKIPS holes rather than calling the
      // callback, so `[,,1]` would join to "[,,1]" — which JSON.parse rejects. That makes the
      // section permanently unreadable on the open side, not merely mis-hashed.
      if (!(i in value)) {
        throw new TypeError(
          `hole at ${fmtPath([...path, String(i)])}. A sparse array's holes serialize to ` +
            `nothing, producing invalid JSON. Use null explicitly.`,
        );
      }
      parts.push(serialize(value[i]!, [...path, String(i)]));
    }
    return `[${parts.join(',')}]`;
  }

  if (t === 'object') {
    // Only plain objects may be canonicalized.
    //
    // This guard is the difference between a flap and a COLLISION. `Object.keys()` returns []
    // for a Date, Map, Set, RegExp, boxed primitive, or any class instance whose state lives
    // in getters or private fields — so every one of them serializes to "{}", identical to
    // each other and to the empty object. A `{lastSync: new Date()}` field would silently
    // vanish from the sealed payload AND hash the same forever, so the section-hash gate would
    // skip every upload after the first and the dashboard would sit at stale numbers behind a
    // green checkmark. A typed array is the mirror image: Uint8Array([1,2]) serializes to
    // {"0":1,"1":2}, colliding with the plain object {0:1,1:2}.
    //
    // TypeScript's CanonicalValue type nominally prevents this, but the extraction path parses
    // XML and casts, so the type is an assertion rather than a proof. Check at runtime.
    const proto = Object.getPrototypeOf(value) as unknown;
    if (proto !== Object.prototype && proto !== null) {
      const name = (value as object).constructor?.name ?? 'object';
      throw new TypeError(
        `cannot canonicalize ${name} at ${fmtPath(path)}: only plain objects and arrays are ` +
          `canonicalizable. Values like Date/Map/Set/typed arrays have no own enumerable keys ` +
          `and would silently serialize to "{}" — colliding with every other such value. ` +
          `Convert to a plain object or a string first.`,
      );
    }
    const obj = value as { readonly [k: string]: CanonicalValue };
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) {
        throw new TypeError(
          `undefined at ${fmtPath([...path, k])}. Use null explicitly — a silently dropped ` +
            `key is an undetectable data change.`,
        );
      }
      parts.push(`${JSON.stringify(k)}:${serialize(v, [...path, k])}`);
    }
    return `{${parts.join(',')}}`;
  }

  throw new TypeError(`cannot canonicalize ${t} at ${fmtPath(path)}`);
}

function fmtPath(path: string[]): string {
  return path.length === 0 ? '<root>' : path.join('.');
}

/**
 * Sort rows by a stable key so that Tally's collection ordering — which is not guaranteed
 * stable across runs — cannot change the hash.
 */
export function sortRows<T>(rows: readonly T[], key: (row: T) => string): T[] {
  return [...rows].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    // Explicit comparison rather than localeCompare: locale-aware collation differs across
    // platforms and ICU builds, which would make the hash machine-dependent.
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}
