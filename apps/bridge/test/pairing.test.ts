import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CODE_DIGITS,
  MAX_ATTEMPTS,
  PAIRING_TTL_MS,
  PairingService,
  formatPairingCode,
  generatePairingCode,
} from '../src/onboarding/pairing.ts';

/**
 * Six digits is 20 bits. On its own that is indefensible — a laptop enumerates it instantly.
 * What makes it acceptable is that nobody is ever allowed to enumerate it: ten minutes, one
 * use, five tries. These tests are therefore not "nice to have" coverage; they are the only
 * thing standing between a short code and a trivially guessable one.
 */

/** A clock the tests move by hand, so nothing here sleeps. */
function clock(start = 1_700_000_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

const CODE = '042931';

function service(code = CODE) {
  const c = clock();
  const svc = new PairingService({ now: c.now, generateCode: async () => code });
  return { svc, c };
}

// ---------------------------------------------------------------- the code itself

test('a code is exactly six digits', async () => {
  for (let i = 0; i < 50; i++) {
    const code = await generatePairingCode();
    assert.match(code, /^\d{6}$/);
    assert.equal(code.length, CODE_DIGITS);
  }
});

test('MATH.RANDOM IS NEVER TOUCHED', async () => {
  // V8's Math.random is xorshift128+: unseeded from a weak source, and its internal state is
  // recoverable from a handful of outputs. A pairing code drawn from it is not a secret, it is
  // a formality. This is the cheapest possible test of the most likely mistake.
  const real = Math.random;
  let called = 0;
  Math.random = () => {
    called++;
    return real();
  };
  try {
    for (let i = 0; i < 100; i++) await generatePairingCode();
  } finally {
    Math.random = real;
  }
  assert.equal(called, 0, 'the pairing code was drawn from Math.random');
});

test('CODES ARE UNPREDICTABLE: 1000 draws are near-unique and uniform', async () => {
  const codes: string[] = [];
  for (let i = 0; i < 1000; i++) codes.push(await generatePairingCode());

  // NOT "assert zero duplicates". Over 10^6 codes the birthday bound gives ~0.5 expected
  // collisions in 1000 draws, so a zero-duplicate assertion would fail ~39% of the time on a
  // PERFECT generator — a test that teaches the team to re-run CI until it goes green is worse
  // than no test. Collisions are Poisson(≈0.5), so P(6 or more) ≈ 1.4e-5: this bound catches a
  // broken generator and effectively never fires on a working one.
  const unique = new Set(codes).size;
  assert.ok(unique >= 994, `only ${unique}/1000 codes were unique — the generator is not random`);

  // Leading zeros survive. Without padStart, "042931" would render as "42931": a 5-digit code
  // the accountant mistypes, drawn from a space 10% smaller than advertised.
  assert.ok(codes.some((c) => c.startsWith('0')), 'no code began with 0 — padding is broken');

  // Digit uniformity. 6000 digits, 10 bins, 600 expected each. chi-square with 9 df exceeds 60
  // with probability ~1e-9 on a fair generator, and a modulo bias or a stuck byte blows past it.
  const counts = new Array<number>(10).fill(0);
  for (const c of codes) for (const ch of c) counts[Number(ch)]! += 1;
  const expected = (1000 * CODE_DIGITS) / 10;
  const chi2 = counts.reduce((acc, n) => acc + (n - expected) ** 2 / expected, 0);
  assert.ok(chi2 < 60, `digit distribution is not plausible (chi-square ${chi2.toFixed(1)})`);

  // Not a counter dressed up as randomness.
  const ascending = codes.filter((c, i) => i > 0 && Number(c) === Number(codes[i - 1]) + 1).length;
  assert.ok(ascending < 5, 'codes look sequential');
});

test('the code is read out as two groups, because that is how it goes down a phone line', () => {
  assert.equal(formatPairingCode('042931'), '042 931');
});

// ---------------------------------------------------------------- the happy path

test('a code issued on the owner PC pairs the accountant PC', async () => {
  const { svc } = service();
  const { code, pairing } = await svc.issue("Anil's PC");
  assert.equal(code, CODE);

  const r = await svc.claim(code);
  assert.ok(r.ok);
  assert.equal(r.pairingId, pairing.id);
  assert.equal(r.label, "Anil's PC");
});

test('the live code is never stored in the clear — only a digest', async () => {
  // So that a heap dump, a stray log of this object, or an accidental IPC round-trip of the
  // wizard state does not hand anyone a live code.
  const { svc } = service();
  const { pairing } = await svc.issue('Accountant');
  assert.equal(JSON.stringify(pairing).includes(CODE), false);
  assert.equal(pairing.digest.length, 32);

  const peeked = svc.peek()!;
  assert.equal('digest' in peeked, false);
  assert.equal(JSON.stringify(peeked).includes(CODE), false);
});

test('claiming before anything was issued says so, plainly', async () => {
  const { svc } = service();
  const r = await svc.claim(CODE);
  assert.equal(r.ok, false);
  assert.equal(r.ok === false ? r.reason : '', 'no_code');
});

// ---------------------------------------------------------------- TTL

test('A CODE EXPIRES after ten minutes', async () => {
  const { svc, c } = service();
  await svc.issue('Accountant');
  assert.equal(PAIRING_TTL_MS, 10 * 60 * 1000);

  c.advance(PAIRING_TTL_MS - 1);
  const stillOk = await svc.claim(CODE);
  assert.equal(stillOk.ok, true);

  // A fresh code, then step over the boundary exactly.
  const { svc: svc2, c: c2 } = service();
  await svc2.issue('Accountant');
  c2.advance(PAIRING_TTL_MS);
  const dead = await svc2.claim(CODE);
  assert.equal(dead.ok, false);
  assert.equal(dead.ok === false ? dead.reason : '', 'expired');
  assert.match(dead.ok === false ? dead.message : '', /ten minutes/);
});

test('an expired code is dead even for the correct code, and long after', async () => {
  const { svc, c } = service();
  await svc.issue('Accountant');
  c.advance(PAIRING_TTL_MS * 100);
  const r = await svc.claim(CODE);
  assert.equal(r.ok === false ? r.reason : '', 'expired');
});

test('expiry does not burn attempts — there is nothing left to protect', async () => {
  const { svc, c } = service();
  await svc.issue('Accountant');
  c.advance(PAIRING_TTL_MS);
  for (let i = 0; i < 20; i++) {
    const r = await svc.claim('999999');
    assert.equal(r.ok === false ? r.reason : '', 'expired');
  }
  assert.equal(svc.peek()!.attempts, 0);
});

// ---------------------------------------------------------------- single use

test('A CODE IS SINGLE-USE', async () => {
  const { svc } = service();
  await svc.issue('Accountant');

  assert.equal((await svc.claim(CODE)).ok, true);

  const second = await svc.claim(CODE);
  assert.equal(second.ok, false);
  assert.equal(second.ok === false ? second.reason : '', 'used');
});

test('a spent code stays spent even inside its TTL, and cannot be probed', async () => {
  const { svc, c } = service();
  await svc.issue('Accountant');
  await svc.claim(CODE);
  c.advance(60_000);

  // Neither the right code nor a wrong one gets anything back but "used" — a spent code must
  // not become a free oracle for guessing.
  assert.equal((await svc.claim(CODE)).ok === false && (await svc.claim(CODE)).ok === false, true);
  const wrong = await svc.claim('111111');
  assert.equal(wrong.ok === false ? wrong.reason : '', 'used');
  assert.equal(svc.peek()!.attempts, 0);
});

// ---------------------------------------------------------------- brute force

test('BRUTE FORCE IS LOCKED OUT AFTER FIVE TRIES — and the correct code no longer works', async () => {
  // This is the assertion that makes 20 bits acceptable. Without it, the code space is a
  // formality: 10^6 guesses is seconds of work over a local IPC channel.
  const { svc } = service();
  await svc.issue('Accountant');
  assert.equal(MAX_ATTEMPTS, 5);

  for (let i = 1; i <= MAX_ATTEMPTS - 1; i++) {
    const r = await svc.claim('000000');
    assert.equal(r.ok === false ? r.reason : '', 'wrong');
    assert.equal(r.ok === false ? r.attemptsLeft : -1, MAX_ATTEMPTS - i);
  }

  const last = await svc.claim('000000');
  assert.equal(last.ok === false ? last.reason : '', 'locked');
  assert.equal(last.ok === false ? last.attemptsLeft : -1, 0);

  // THE ONE THAT MATTERS: the real code is now worthless too. A lockout that still honours a
  // correct guess is decorative — the attacker's 5 tries would simply become unlimited tries
  // with a 5-guess delay.
  const correct = await svc.claim(CODE);
  assert.equal(correct.ok, false);
  assert.equal(correct.ok === false ? correct.reason : '', 'locked');
});

test('the lock never lifts with time', async () => {
  const { svc, c } = service();
  await svc.issue('Accountant');
  for (let i = 0; i < MAX_ATTEMPTS; i++) await svc.claim('000000');
  c.advance(60_000);
  assert.equal((await svc.claim(CODE)).ok, false);
});

test('the attempt budget counts wrong guesses only', async () => {
  const { svc } = service();
  await svc.issue('Accountant');
  await svc.claim('000000');
  await svc.claim('000001');
  assert.equal(svc.peek()!.attempts, 2);
  assert.equal((await svc.claim(CODE)).ok, true);
});

test('a wrong code of any length is just wrong — no length oracle, no crash', async () => {
  // The compare is over 32-byte digests precisely so a wrong LENGTH cannot short-circuit it
  // and leak "your code is the wrong shape" through timing. A fresh service per guess, because
  // sharing one would hit the lockout after five and stop testing what this test is about.
  for (const bad of ['', '1', '12345', '1234567', 'abcdef', '04293 1', '0429310000000', '042931\n']) {
    const { svc } = service();
    await svc.issue('Accountant');
    const r = await svc.claim(bad);
    assert.equal(r.ok, false, `"${bad}" was accepted`);
    assert.equal(r.ok === false ? r.reason : '', 'wrong');
    assert.equal(r.ok === false ? r.attemptsLeft : -1, MAX_ATTEMPTS - 1);
  }
});

// ---------------------------------------------------------------- issuance

test('ISSUING REPLACES the outstanding code, so three clicks do not leave three live codes', async () => {
  const c = clock();
  let n = 0;
  const svc = new PairingService({ now: c.now, generateCode: async () => ['111111', '222222'][n++]! });

  await svc.issue('Accountant');
  await svc.issue('Accountant');

  const old = await svc.claim('111111');
  assert.equal(old.ok, false);
  assert.equal((await svc.claim('222222')).ok, true);
});

test('a re-issue resets the attempt budget, and only the owner can re-issue', async () => {
  // The counter is resettable ONLY by issuing, and issuing requires the owner's authenticated
  // session — which is why `issue` invalidates the code the attacker was working on. An
  // attacker who could reset the counter would have unlimited guesses.
  const c = clock();
  const svc = new PairingService({ now: c.now, generateCode: async () => CODE });
  await svc.issue('Accountant');
  for (let i = 0; i < MAX_ATTEMPTS; i++) await svc.claim('000000');
  assert.equal((await svc.claim(CODE)).ok, false);

  await svc.issue('Accountant');
  assert.equal(svc.peek()!.attempts, 0);
  assert.equal((await svc.claim(CODE)).ok, true);
});

test('each issue gets a distinct id and a fresh ten-minute window', async () => {
  const c = clock();
  const svc = new PairingService({ now: c.now, generateCode: async () => CODE });
  const a = await svc.issue('One');
  c.advance(1000);
  const b = await svc.issue('Two');
  assert.notEqual(a.pairing.id, b.pairing.id);
  assert.equal(b.pairing.expiresAt - b.pairing.issuedAt, PAIRING_TTL_MS);
});

test('cancelling kills the code immediately rather than leaving it live for ten minutes', async () => {
  const { svc } = service();
  await svc.issue('Accountant');
  svc.cancel();
  assert.equal(svc.peek(), undefined);
  const r = await svc.claim(CODE);
  assert.equal(r.ok === false ? r.reason : '', 'no_code');
});

test('real codes flow through the real generator end to end', async () => {
  const c = clock();
  const svc = new PairingService({ now: c.now });
  const { code } = await svc.issue("Anil's PC");
  assert.match(code, /^\d{6}$/);
  assert.equal((await svc.claim(code)).ok, true);
});

// ---------------------------------------------------------------- wording

test('every pairing failure is a sentence with a next step, not a code', async () => {
  const { svc, c } = service();
  const seen = new Map<string, string>();

  const collect = (r: Awaited<ReturnType<PairingService['claim']>>) => {
    assert.equal(r.ok, false);
    if (!r.ok) seen.set(r.reason, r.message);
  };

  collect(await svc.claim(CODE)); // no_code
  await svc.issue('Accountant');
  collect(await svc.claim('000000')); // wrong
  for (let i = 0; i < MAX_ATTEMPTS; i++) await svc.claim('000000');
  collect(await svc.claim(CODE)); // locked
  await svc.issue('Accountant');
  assert.equal((await svc.claim(CODE)).ok, true);
  collect(await svc.claim(CODE)); // used
  await svc.issue('Accountant');
  c.advance(PAIRING_TTL_MS);
  collect(await svc.claim(CODE)); // expired

  // Every reason in the union has a sentence. A new failure mode without one goes red here.
  assert.deepEqual([...seen.keys()].sort(), ['expired', 'locked', 'no_code', 'used', 'wrong']);
  const messages = [...seen.values()];
  for (const m of messages) {
    assert.match(m, /^[A-Z]/);
    assert.match(m, /[.]$/);
    assert.equal(/[{}[\]]|Error|undefined|null|\bat \w+\(/.test(m), false, `jargon in: ${m}`);
    assert.equal(m.includes(CODE), false, `the message leaks the code: ${m}`);
  }
});

// ---------------------------------------------------------------- ADVERSARIAL: the lockout

test('THE LOCKOUT: concurrent guesses cannot exceed the attempt budget', async () => {
  // `claim` reads `p.attempts` BEFORE its first `await`, then increments it several awaits
  // later. Every claim issued in the same tick therefore passes the gate while the counter is
  // still 0. The counter is the ONLY thing making 20 bits acceptable (see the header), so a
  // caller that does not serialise its IPC hands the attacker the whole 10^6 space.
  const t = clock();
  const svc = new PairingService({ now: t.now, generateCode: async () => '424242' });
  await svc.issue('Accountant PC');

  const guesses = Array.from({ length: 1000 }, (_, i) => String(100_000 + i));
  guesses[900] = '424242'; // the real code, buried in the spray
  const results = await Promise.all(guesses.map((g) => svc.claim(g)));

  const claimed = results.filter((r) => r.ok);
  assert.equal(claimed.length, 0, 'the code must not be claimable after the budget is spent');
  assert.ok(
    svc.peek()!.attempts <= MAX_ATTEMPTS,
    `at most ${MAX_ATTEMPTS} guesses may ever be compared, saw ${svc.peek()!.attempts}`,
  );
});

test('SINGLE USE: two simultaneous correct claims enrol exactly one device', async () => {
  // The same race on `usedAt`: both claims see `usedAt === undefined`, both compare, both win.
  // One code, two devices — and the second one is whoever else was holding the code.
  const t = clock();
  const svc = new PairingService({ now: t.now, generateCode: async () => '424242' });
  await svc.issue('PC');
  const both = await Promise.all([svc.claim('424242'), svc.claim('424242')]);
  assert.equal(both.filter((r) => r.ok).length, 1, 'a single-use code must succeed exactly once');
});

test('the ordinary sequential path is unchanged by serialisation', async () => {
  const t = clock();
  const svc = new PairingService({ now: t.now, generateCode: async () => '424242' });
  await svc.issue('PC');
  const a = await svc.claim('111111');
  assert.equal(a.ok, false);
  assert.equal((a as { attemptsLeft?: number }).attemptsLeft, MAX_ATTEMPTS - 1);
  const b = await svc.claim('424242');
  assert.ok(b.ok, 'a correct code still works after a wrong one');
});
