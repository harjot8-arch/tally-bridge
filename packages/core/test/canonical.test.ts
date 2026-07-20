import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalAmount,
  canonicalAmountFromPaise,
  canonicalStringify,
  fromPaise,
  parseAmount,
  parseAmountToPaise,
  sortRows,
  sumAmounts,
  sumPaise,
  toPaise,
} from '../src/canonical.ts';

test('key order cannot change the hash', () => {
  const a = canonicalStringify({ b: 1, a: 2 });
  const b = canonicalStringify({ a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":2,"b":1}');
});

test('nested keys are sorted at every level', () => {
  const s = canonicalStringify({ z: { y: 1, x: 2 }, a: [{ n: 1, m: 2 }] });
  assert.equal(s, '{"a":[{"m":2,"n":1}],"z":{"x":2,"y":1}}');
});

test('undefined throws rather than silently vanishing', () => {
  // A dropped key is a data change the hash would not see.
  assert.throws(
    () => canonicalStringify({ a: undefined as never }),
    /undefined at a/,
  );
});

test('non-integer numbers are rejected', () => {
  // Float formatting is not guaranteed identical across runtimes; amounts must go
  // through canonicalAmount first.
  assert.throws(() => canonicalStringify({ a: 1.5 }), /non-integer number/);
});

test('non-finite numbers are rejected', () => {
  assert.throws(() => canonicalStringify({ a: NaN }), /non-finite/);
  assert.throws(() => canonicalStringify({ a: Infinity }), /non-finite/);
});

test('-0 and 0 are indistinguishable', () => {
  assert.equal(canonicalStringify({ a: -0 }), canonicalStringify({ a: 0 }));
});

test('canonicalAmount collapses negative zero', () => {
  assert.equal(canonicalAmount(-0), '0.00');
  assert.equal(canonicalAmount(0), '0.00');
  // Rounds to -0 paise, which must not render as "-0.00".
  assert.equal(canonicalAmount(-0.001), '0.00');
  assert.equal(canonicalAmount(0.001), '0.00');
});

test('canonicalAmount is stable for realistic Indian amounts', () => {
  assert.equal(canonicalAmount(125000), '125000.00');
  assert.equal(canonicalAmount(-3421.5), '-3421.50');
  assert.equal(canonicalAmount(342110.75), '342110.75');
  // A crore and change.
  assert.equal(canonicalAmount(12345678.9), '12345678.90');
});

test('canonicalAmount round-trips values parsed from Tally decimal strings', () => {
  // Tally emits 2dp decimal strings; parse -> render must be identity.
  for (const s of ['0.00', '1.05', '-1.05', '99999999.99', '-99999999.99', '0.01']) {
    assert.equal(canonicalAmount(Number(s)), s === '-0.00' ? '0.00' : s);
  }
});

test('summation is exact via paise, not float', () => {
  // The float trap: 0.1 + 0.2 !== 0.3
  assert.notEqual(0.1 + 0.2, 0.3);
  assert.equal(sumAmounts([0.1, 0.2]), 0.3);
});

test('summing many bills does not drift', () => {
  // 2000 bills at 0.01 is exactly 20.00. Naive float summation drifts here.
  const bills = Array.from({ length: 2000 }, () => 0.01);
  assert.equal(sumAmounts(bills), 20);

  const naive = bills.reduce((a, b) => a + b, 0);
  assert.notEqual(naive, 20); // demonstrates why toPaise exists
});

test('parseAmountToPaise is exact where float rounding is not', () => {
  // The reason this function exists. 1.005 has no exact float64 representation:
  // 1.005 * 100 === 100.49999999999999, so Math.round gives 100 (i.e. 1.00), not 101.
  assert.equal(toPaise(1.005), 100); // float path: rounds DOWN, surprisingly
  assert.equal(parseAmountToPaise('1.00'), 100); // string path: no rounding to get wrong

  // Realistic Tally output round-trips exactly.
  assert.equal(parseAmountToPaise('125000.00'), 12500000);
  assert.equal(parseAmountToPaise('-3421.50'), -342150);
  assert.equal(parseAmountToPaise('0.01'), 1);
  assert.equal(parseAmountToPaise('0'), 0);
  assert.equal(parseAmountToPaise('1234'), 123400);
  assert.equal(parseAmountToPaise('-0.00'), 0);
  assert.equal(parseAmountToPaise('  42.5  '), 4250); // Tally pads fields with spaces
});

test('parseAmountToPaise rejects anything it does not fully understand', () => {
  // Silent truncation here would corrupt money. Fail loudly instead.
  assert.throws(() => parseAmountToPaise('1.005'), /not a 2dp decimal/); // 3dp
  assert.throws(() => parseAmountToPaise('1,234.00'), /not a 2dp decimal/); // Indian grouping
  assert.throws(() => parseAmountToPaise('(-)500'), /not a 2dp decimal/); // un-normalized Tally
  assert.throws(() => parseAmountToPaise('500 Dr'), /not a 2dp decimal/); // un-normalized Tally
  assert.throws(() => parseAmountToPaise(''), /not a 2dp decimal/);
  assert.throws(() => parseAmountToPaise('abc'), /not a 2dp decimal/);
  assert.throws(() => parseAmountToPaise('1e3'), /not a 2dp decimal/);
});

test('amounts beyond safe range are rejected, not silently mangled', () => {
  assert.throws(() => toPaise(1e16), /out of range/);
  assert.throws(() => toPaise(NaN), /not finite/);
});

test('sortRows is deterministic and locale-independent', () => {
  const rows = [{ k: 'b' }, { k: 'A' }, { k: 'a' }, { k: 'B' }];
  const sorted = sortRows(rows, (r) => r.k);
  // Code-unit order: uppercase before lowercase. Locale collation would interleave these
  // differently on different ICU builds, making the hash machine-dependent.
  assert.deepEqual(sorted.map((r) => r.k), ['A', 'B', 'a', 'b']);
});

test('sortRows does not mutate its input', () => {
  const rows = [{ k: 'b' }, { k: 'a' }];
  sortRows(rows, (r) => r.k);
  assert.equal(rows[0]!.k, 'b');
});

test('the same section data hashes identically regardless of construction order', () => {
  const rowsA = [
    { party: 'Zed', amount: canonicalAmount(100) },
    { party: 'Abe', amount: canonicalAmount(200) },
  ];
  const rowsB = [
    { amount: canonicalAmount(200), party: 'Abe' },
    { amount: canonicalAmount(100), party: 'Zed' },
  ];
  const a = canonicalStringify(sortRows(rowsA, (r) => r.party));
  const b = canonicalStringify(sortRows(rowsB, (r) => r.party));
  assert.equal(a, b);
});

// ---------------------------------------------------------------------------
// Adversarial: collision resistance of the section-hash gate.
//
// A collision here is worse than a flap. A flap costs bandwidth and is caught by the
// `hashHitRate` metric. A collision means two DIFFERENT payloads hash the same, the gate
// concludes "unchanged", the upload never happens, and the dashboard shows stale numbers
// under a green checkmark — with no metric that can see it.
// ---------------------------------------------------------------------------

test('non-plain objects are rejected rather than collapsing to {}', () => {
  // Every one of these has no own enumerable keys, so Object.keys() returns [] and they all
  // serialize to "{}" — colliding with each other AND with the empty object. A `Date` field
  // (e.g. `{lastSync: new Date()}`) would silently vanish from the sealed payload and hash
  // identically forever, so the gate would skip every upload after the first.
  for (const v of [new Date(2020, 1, 1), new Map([[1, 2]]), new Set([1, 2, 3]), /re/g]) {
    assert.throws(() => canonicalStringify(v as never), /only plain objects/);
  }
});

test('boxed primitives are rejected', () => {
  // `new Number(5)` -> "{}", indistinguishable from `{}` itself.
  assert.throws(() => canonicalStringify(new Number(5) as never), /only plain objects/);
  assert.throws(() => canonicalStringify(new String('xy') as never), /only plain objects/);
});

test('class instances are rejected', () => {
  class Row {
    name: string;
    constructor(name: string) {
      this.name = name;
    }
  }
  // A class with only constructor-assigned fields does have own keys, but one with getters or
  // private fields does not — and would serialize to "{}".
  class Opaque {
    get name(): string {
      return 'x';
    }
  }
  assert.throws(() => canonicalStringify(new Opaque() as never), /only plain objects/);
  // Even a well-behaved instance is rejected: allowing it invites the Opaque case.
  assert.throws(() => canonicalStringify(new Row('a') as never), /only plain objects/);
});

test('a typed array cannot collide with a plain object', () => {
  // Uint8Array([1,2]) and {0:1,1:2} both serialize to {"0":1,"1":2}.
  assert.throws(() => canonicalStringify(new Uint8Array([1, 2]) as never), /only plain objects/);
});

test('sparse array holes are rejected, not serialized as invalid JSON', () => {
  // `[,,1]` joins to "[,,1]", which JSON.parse rejects — so openSection would throw and the
  // section would be permanently unreadable rather than merely mis-hashed.
  const sparse = [, , 1] as unknown as number[];
  assert.throws(() => canonicalStringify(sparse), /hole at/);
});

test('every canonical output is parseable JSON', () => {
  // The output is JSON.parse'd on the open side; anything that is not valid JSON is a
  // permanently unreadable section.
  const payloads: unknown[] = [
    {},
    [],
    { a: 1, b: [1, 2, { c: null }] },
    { '': 0 },
    { 'é': 'café', '😀': true },
    [[[[1]]]],
    { __proto__: 1, a: 2 },
    JSON.parse('{"__proto__":1,"a":2}'),
  ];
  for (const p of payloads) {
    const s = canonicalStringify(p as never);
    assert.deepEqual(JSON.parse(s), JSON.parse(JSON.stringify(JSON.parse(s))), `not JSON: ${s}`);
  }
});

test('an object with a JSON.parse-created __proto__ key round-trips without polluting', () => {
  const evil = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
  const s = canonicalStringify(evil);
  assert.equal(s, '{"__proto__":{"polluted":true},"a":1}');
  // The serializer must read the OWN property, not walk the prototype chain.
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

test('toPaise refuses amounts whose paise value is not exactly representable', () => {
  // The old bound (1e15 rupees) permitted results above Number.MAX_SAFE_INTEGER: toPaise
  // silently returned 9007199254740994 for 90071992547409.93 — a value that is not even the
  // correctly-rounded answer. Money must never come back wrong instead of throwing.
  assert.throws(() => toPaise(1e15), /out of range/);
  assert.throws(() => toPaise(1e14), /out of range/);
  assert.throws(() => toPaise(90071992547409.93), /out of range/);
  // Everything a real business could plausibly hold still works: ~Rs 900 billion.
  assert.equal(toPaise(1e13), 1e15);
  assert.ok(Number.isSafeInteger(toPaise(1e13)));
});

// ---------------------------------------------------------------- parseAmount

test('parseAmount is the exact inverse of canonicalAmount', () => {
  // THE round trip that did not exist, and whose absence was BUG-6: canonicalAmount rendered
  // money to the wire and nothing brought it back, so the card layer did arithmetic on strings.
  for (const rupees of [0, 1, -1, 125000, -3421.5, 342110.75, -220000.75, 12345678.9, 0.01, -0.01]) {
    assert.equal(parseAmount(canonicalAmount(rupees)), rupees, `round trip failed for ${rupees}`);
  }
});

test('parseAmount FAILS LOUDLY rather than coercing', () => {
  // The whole point. `Number("")` is 0 and `Number("₹1,00,000")` is NaN — a hydration layer that
  // coerces turns a malformed row into a confident wrong number on a dashboard about money.
  for (const garbage of ['', '  ', 'abc', '₹1,00,000', '1,000.00', '1.005', '1e5', 'NaN', 'Infinity', '--1', '1.2.3']) {
    assert.throws(() => parseAmount(garbage), `${JSON.stringify(garbage)} was coerced instead of throwing`);
  }
});

test('parseAmount never returns negative zero', () => {
  // -0 !== 0 under Object.is and would make otherwise-identical data hash differently.
  assert.ok(Object.is(parseAmount('-0.00'), 0), '"-0.00" must parse to +0');
  assert.ok(Object.is(parseAmount('0.00'), 0));
});

test('parseAmount does not route through a float', () => {
  // 1.005 * 100 is 100.49999999999999 in float64. Parsing the digits means there is no rounding
  // step to get wrong — and 3dp throws rather than silently truncating to the "close enough" one.
  assert.equal(parseAmount('87500.50'), 87500.5);
  assert.equal(parseAmountToPaise('87500.50'), 8750050);
  assert.throws(() => parseAmount('1.005'), /2dp decimal/);
});

// ---------------------------------------------------------------- sumPaise

test('sumPaise adds integer paise exactly', () => {
  assert.equal(sumPaise([]), 0);
  // 0.1 + 0.2 = 0.30000000000000004 as rupee floats; as paise it is simply 30.
  assert.equal(sumPaise([10, 20]), 30);
  assert.equal(sumPaise([-12500000, -8750050, -250025]), -21500075);
});

test('sumPaise rejects a float rather than silently rounding it', () => {
  // A float here means someone upstream skipped the parse — which is exactly how money bugs get
  // in. Refuse it at the boundary instead of quietly making it look like it worked.
  assert.throws(() => sumPaise([10.5]), /not integer paise/);
  assert.throws(() => sumPaise([NaN]), /not integer paise/);
  assert.throws(() => sumPaise([Infinity]), /not integer paise/);
});

test('sumPaise throws when the total leaves the exact range', () => {
  // `2**53 + 1 === 2**53`: past here, `+` starts rounding and says nothing. Money must throw
  // rather than come back quietly wrong.
  assert.throws(() => sumPaise([Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]), /out of range/);
});

test('the wire round trip is exact for a whole realistic payload', () => {
  // The seam, in miniature: render every amount the producer would, parse every amount the card
  // layer would, and the sum must be the sum. This is the property the two halves disagreed on.
  const books = [-125000, -87500.5, -2500.25, -5000];
  const wire = books.map(canonicalAmount);
  assert.deepEqual(wire, ['-125000.00', '-87500.50', '-2500.25', '-5000.00']);
  assert.equal(sumPaise(wire.map(parseAmountToPaise)), -22000075);
  assert.equal(sumAmounts(wire.map(parseAmount)), -220000.75);
});

test('canonicalAmountFromPaise: exact for the whole safe range, no float in the path', () => {
  // The pairs that matter: sub-rupee, the carry, negatives, and the -0 that flaps the hash.
  assert.equal(canonicalAmountFromPaise(0), '0.00');
  assert.equal(canonicalAmountFromPaise(-0), '0.00'); // -0 must never reach the wire
  assert.equal(canonicalAmountFromPaise(1), '0.01');
  assert.equal(canonicalAmountFromPaise(99), '0.99');
  assert.equal(canonicalAmountFromPaise(100), '1.00');
  assert.equal(canonicalAmountFromPaise(-1), '-0.01');
  assert.equal(canonicalAmountFromPaise(-100), '-1.00');
  assert.equal(canonicalAmountFromPaise(12500000), '125000.00');
  assert.equal(canonicalAmountFromPaise(-34211075), '-342110.75');

  // The top of the safe range. NOTE: the float route (canonicalAmount(fromPaise(p))) is exact
  // here too — measured, see the sibling test. This pins the boundary, it does not demonstrate a
  // float bug, and claiming otherwise is how a comment starts lying.
  assert.equal(canonicalAmountFromPaise(Number.MAX_SAFE_INTEGER), '90071992547409.91');
  assert.equal(canonicalAmountFromPaise(-Number.MAX_SAFE_INTEGER), '-90071992547409.91');
});

test('canonicalAmountFromPaise round-trips through parseAmountToPaise for every shape', () => {
  const cases = [0, 1, 99, 100, 101, 999, -1, -99, -100, 12345678, -12345678, 2 ** 40, -(2 ** 40)];
  for (const p of cases) {
    assert.equal(parseAmountToPaise(canonicalAmountFromPaise(p)), p === 0 ? 0 : p, `paise ${p}`);
  }
});

test('canonicalAmountFromPaise agrees with canonicalAmount wherever a float can represent it', () => {
  // Where both are exact they must agree, or the wire format depends on which producer emitted it
  // and the section hash flaps between them.
  for (let p = -100_000; p <= 100_000; p += 7) {
    assert.equal(canonicalAmountFromPaise(p), canonicalAmount(p / 100), `paise ${p}`);
  }
});

test('the float route it replaces is exact too — the reason is clarity, not a rounding bug', () => {
  // Pinning the honest version of the story. `canonicalAmount(fromPaise(p))` divides an exact
  // integer into a float and multiplies it back; the intuition is that this must eventually lose
  // a paisa, and that intuition is WRONG across the whole safe range. If this test ever fails,
  // the intuition became right and the comment on canonicalAmountFromPaise needs rewriting again.
  for (const p of [Number.MAX_SAFE_INTEGER, 999999999999999, 12345678901234, 1, 99, -1]) {
    assert.equal(canonicalAmountFromPaise(p), canonicalAmount(fromPaise(p)), `paise ${p}`);
  }

  // What the float route does NOT do is refuse a value that was never integer paise. That is the
  // real difference between the two, and the only one worth writing a function over.
  assert.equal(canonicalAmount(fromPaise(150.7)), '1.51'); // silently rounds
  assert.throws(() => canonicalAmountFromPaise(150.7), /not integer paise/); // refuses
});

test('canonicalAmountFromPaise refuses a float rather than rounding it silently', () => {
  assert.throws(() => canonicalAmountFromPaise(1.5), /not integer paise/);
  assert.throws(() => canonicalAmountFromPaise(NaN), /not integer paise/);
  assert.throws(() => canonicalAmountFromPaise(Infinity), /not integer paise/);
  assert.throws(() => canonicalAmountFromPaise(2 ** 53), /not integer paise/);
});
