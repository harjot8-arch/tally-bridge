import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import type { WrappedKey } from '@tally-bridge/core';
import {
  RosterError,
  openIdentity,
  type DeviceRoster,
  type RosterMemory,
} from '@tally-bridge/crypto';

/**
 * Recovery.
 *
 * BE BLUNT ABOUT WHERE THIS PRODUCT ACTUALLY FAILS. It is not a broken cipher. It is a
 * 55-year-old business owner who set a passphrase during a two-minute setup, never typed it
 * again because the desktop app remembered it, and now wants the dashboard on his phone eight
 * months later. Cryptographic soundness that produces a support call nobody can resolve is a
 * bug, not a feature.
 *
 * THE FACT THAT DE-RISKS ALL OF THIS: the server is a derivative CACHE. Tally is the source of
 * truth. So the worst case — passphrase gone, sheet gone, PC dead — is: generate a new
 * identity, re-sync from Tally, lose only the dashboard's historical snapshots, which Tally can
 * regenerate anyway. That is an inconvenience, not a catastrophe, and the UI should say so out
 * loud. It removes the terror from the entire feature.
 *
 * Three paths, in the order real users hit them:
 *   1. Device key   — "remember on this PC" is on and the PC boots. Resolves ~90% of cases.
 *   2. Recovery sheet — the printed QR/words.
 *   3. Clean reset  — new identity, re-sync. No shame, one screen.
 *
 * WHAT WE WILL NEVER BUILD: server-side passphrase reset, vendor-held escrow, security
 * questions. Each silently voids the end-to-end claim. If a client wants escrow, that is a
 * different product with a different promise, and it must be labelled as such.
 */

/** Words the user must confirm before setup can continue. 1-indexed, as printed. */
export const VERIFY_WORD_POSITIONS = [4, 17] as const;

export interface RecoverySheet {
  /** 24 BIP39 words. */
  words: string[];
  /** The raw 256-bit key, base64 — what the QR encodes. */
  keyBase64: string;
  businessName: string;
  /** ISO date, printed so a drawer full of sheets can be ordered. */
  createdOn: string;
}

/**
 * Render a recovery key as a sheet.
 *
 * BIP39 rather than any 24 words: the checksum catches transcription errors, which WILL happen.
 *
 * BUT BE HONEST ABOUT ITS STRENGTH, because the number is small and the docs here used to claim
 * more than it delivers. A 24-word mnemonic carries an 8-BIT checksum. That is 1/256, so
 * ROUGHLY 0.4% OF SINGLE-WORD TYPOS AND WORD SWAPS PASS THE CHECKSUM AND YIELD A WRONG KEY —
 * measured over 4,000 random mnemonics at 0.47% for single-word typos and 0.40% for swaps,
 * both sitting on the 0.39% the maths predicts. Do not read anything into which of the two is
 * larger: the gap is sampling noise around a single 1/256 rate, and an earlier version of this
 * comment quoted the two figures the other way round. The checksum is a typo filter that catches
 * ~255 in 256, not a proof of correctness, and no amount of care in this module changes that: it
 * is a property of BIP39. `test/recovery.test.ts` re-measures the rate rather than trusting this
 * paragraph.
 *
 * WHAT THIS MEANS FOR THE CALLER, AND IT IS NOT OPTIONAL. `parseRecoveryWords` returning
 * `ok: true` means "these words are well-formed", NOT "this is your key". The ONLY proof a key
 * is the right one is that it unwraps the identity — so a caller must attempt the unwrap and
 * report failure as "those words are not right", never as "decryption failed". Treating a
 * checksum pass as success would leave ~1 in 250 typo-ing users staring at a crypto error, which
 * is the exact support call this module exists to prevent.
 *
 * That obligation is now DISCHARGED BY CODE rather than by this comment: `attemptRecovery()`
 * does the unwrap and is the only exported way to get an identity back. Use it. `parseRecovery*`
 * remain exported for it and for tests — a caller reaching past it for a raw key is reintroducing
 * the bug.
 */
export function makeRecoverySheet(key: Uint8Array, businessName: string, createdOn: string): RecoverySheet {
  if (key.length !== 32) {
    throw new RangeError(`recovery key must be 32 bytes (256 bits), got ${key.length}`);
  }
  return {
    words: entropyToMnemonic(key, wordlist).split(' '),
    keyBase64: Buffer.from(key).toString('base64'),
    businessName,
    createdOn,
  };
}

export type RecoveryParseResult =
  | { ok: true; key: Uint8Array }
  | { ok: false; reason: 'wrong_length' | 'unknown_word'; message: string; badWords?: string[] }
  | { ok: false; reason: 'checksum'; message: string };

/**
 * Parse words the user typed back.
 *
 * Every failure names what to fix. "Invalid mnemonic" is useless to someone holding a printed
 * sheet and squinting at their own handwriting.
 */
export function parseRecoveryWords(input: string): RecoveryParseResult {
  const words = input
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 0);

  if (words.length !== 24) {
    return {
      ok: false,
      reason: 'wrong_length',
      message: `Your recovery sheet has 24 words. You have entered ${words.length}.`,
    };
  }

  // Name the specific words that are wrong. The BIP39 list has unique 4-letter prefixes, so a
  // misread word is nearly always a real word that simply is not on the list.
  const bad = words.filter((w) => !wordlist.includes(w));
  if (bad.length > 0) {
    return {
      ok: false,
      reason: 'unknown_word',
      message:
        bad.length === 1
          ? `"${bad[0]}" is not one of the recovery words. Check that word on your sheet.`
          : `These are not recovery words: ${bad.join(', ')}. Check them on your sheet.`,
      badWords: bad,
    };
  }

  const phrase = words.join(' ');
  if (!validateMnemonic(phrase, wordlist)) {
    // All 24 are real words but the checksum fails — so one is in the wrong PLACE, or a word
    // was misread as another valid word. Saying "one is wrong or out of order" is actionable;
    // "invalid mnemonic" is not.
    return {
      ok: false,
      reason: 'checksum',
      message:
        'Those 24 words do not match. One of them is probably wrong or out of order — ' +
        'check them against your sheet, in order.',
    };
  }

  return { ok: true, key: new Uint8Array(mnemonicToEntropy(phrase, wordlist)) };
}

/** Exactly the 44 characters a base64'd 32-byte key occupies: 43 payload + one '='. */
const KEY_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

/**
 * Parse a scanned QR. The QR carries the raw key, so recovery is a camera, not typing.
 *
 * STRICT, because `Buffer.from(s, 'base64')` is not. It silently DISCARDS every character
 * outside the base64 alphabet instead of failing, so it never throws and will happily
 * manufacture 32 bytes out of whatever it was handed. A WiFi QR taped inside the office cupboard
 * decodes to a perfectly well-formed 32-byte "key" — verified, it did. The owner is told "scan
 * the code", scans the wrong sticker, and gets a confidently wrong key; the error then surfaces
 * much later as "decryption failed", pointing nowhere. That is precisely the failure this module
 * exists to prevent, so the payload is matched against the exact shape a real key has before it
 * is decoded at all.
 */
export function parseRecoveryQr(scanned: string): RecoveryParseResult {
  const s = scanned.trim();
  const notAKey: RecoveryParseResult = {
    ok: false,
    reason: 'wrong_length',
    message: 'That QR code is not a recovery key. Scan the square code on your recovery sheet.',
  };
  if (!KEY_BASE64.test(s)) return notAKey;

  const key = new Uint8Array(Buffer.from(s, 'base64'));
  if (key.length !== 32) return notAKey;
  // Belt and braces: the regex already forbids non-canonical padding, but a round-trip proves
  // the decode was lossless rather than trusting two implementations to agree.
  if (Buffer.from(key).toString('base64') !== s) return notAKey;
  return { ok: true, key };
}

// ---------------------------------------------------------------- the authoritative attempt

/**
 * The one thing the owner can do next. One action, never a menu — see the wizard's header.
 *
 * Only the value this module actually produces is listed. The other real option — give up and
 * reset — is `describeReset()`'s job and belongs to the screen, not to a failed attempt; naming
 * it here would be a state this code never returns, which is the kind of claim-without-an-
 * enforcer that this file has been burned by before.
 */
/**
 * `get_help` exists because one failure here is NOT the owner's sheet being wrong.
 *
 * A roster failure means the words were RIGHT — the AEAD tag verified, so the key is correct —
 * and what came out is unusable: no roster, a malformed one, or one older than this device has
 * already seen, which is a server rolling the wrapped key back (see `RosterMemory` in
 * @tally-bridge/crypto). Telling that owner "check your sheet" would send them to re-read a
 * piece of paper that is perfectly fine, forever, while an attack or a real bug goes unreported.
 * The sheet is not the thing to look at, so it is not the thing we say.
 */
export type RecoveryActionKind = 'check_the_sheet' | 'get_help';

export type RecoveryOutcome =
  | {
      ok: true;
      identitySecretKey: Uint8Array;
      /** The pinned roster, from inside the sealed bundle. Feed to `openSection`, nothing else. */
      roster: DeviceRoster;
      rosterVersion: number;
      /** MUST be persisted where the server cannot write it. See `UnwrappedIdentity`. */
      highestVersionSeen: number;
    }
  | {
      ok: false;
      /** One plain sentence. Never a stack trace, never the word "decrypt". */
      message: string;
      action: RecoveryActionKind;
      /**
       * For tests and logs ONLY — never rendered. `rejected_by` records WHICH check said no,
       * and it exists to make the property in this module's header testable: the unwrap, not
       * the checksum, must be what rejects a wrong key.
       */
      rejectedBy: 'parse' | 'unwrap' | 'roster';
    };

/**
 * Recover the identity secret from what the owner typed or scanned. THE ONLY WAY IN.
 *
 * WHY THIS FUNCTION EXISTS AT ALL, RATHER THAN A CALLER COMPOSING THE TWO STEPS ITSELF.
 *
 * `parseRecoveryWords` returning `ok: true` means "well-formed", NOT "correct" — the 8-bit
 * BIP39 checksum passes ~1 in 256 wrong mnemonics (measured: 0.47% of single-word typos, 0.40%
 * of swaps). A caller that treats a checksum pass as success tells ~1 in 250 typo-ing owners
 * "key accepted" and then hands them a WRONG KEY, which fails later and elsewhere as a crypto
 * error pointing nowhere. That is the false-confidence bug, and leaving the two steps separate
 * is what makes it writable. So they are not separate: parsing is not exported as a way to
 * obtain a key that anyone acts on — this is.
 *
 * THE AUTHORITY IS THE AEAD, NOT THE CHECKSUM. The wrap is XChaCha20-Poly1305; its 128-bit
 * authentication tag either verifies or it does not, and a wrong key fails it with probability
 * ~1 - 2^-128. The checksum is kept only as a fast, friendly PRE-FILTER: it catches ~255 in 256
 * typos before we spend an HKDF on them and, more importantly, it can say "one word is out of
 * order", which the AEAD cannot. When the checksum misses, the unwrap catches it — and the
 * owner sees the same plain sentence either way, because to them it is the same situation: the
 * words are not right, look at the paper again.
 */
export async function attemptRecovery(
  input: { kind: 'words' | 'qr'; value: string },
  blob: WrappedKey,
  memory: RosterMemory,
): Promise<RecoveryOutcome> {
  const parsed = input.kind === 'words' ? parseRecoveryWords(input.value) : parseRecoveryQr(input.value);

  if (!parsed.ok) {
    // A parse failure is the ONLY place we can be specific ("word 4 is not a recovery word"),
    // so that specificity is passed straight through. It is a better error, not a stronger one.
    return { ok: false, message: parsed.message, action: 'check_the_sheet', rejectedBy: 'parse' };
  }

  try {
    // `openIdentity`, not `unwrapWithRecoveryKey`: recovery must return an identity that can
    // actually be USED, and an identity without a roster can decrypt sections but cannot verify
    // that any of them are real — `openSection` requires pinned device keys and has no default.
    // Handing back a bare secret key would make "recovered" mean "recovered into a state where
    // the only remaining defence is missing", which is not recovery.
    const opened = await openIdentity(blob, { kind: 'recovery', recoveryKey: parsed.key }, memory);
    // The AEAD tag verified. THIS, and nothing before it, is what makes the key correct.
    return {
      ok: true,
      identitySecretKey: opened.identitySecretKey,
      roster: opened.roster,
      rosterVersion: opened.rosterVersion,
      highestVersionSeen: opened.highestVersionSeen,
    };
  } catch (e) {
    // NOT a blanket catch, and the distinction is the whole reason this is not one line.
    //
    // A RosterError means the tag VERIFIED — the words were right — and the bundle inside is
    // unusable or stale. Reporting that as "check your sheet" would tell an owner whose sheet is
    // perfect to keep re-typing it, and would present a rolled-back wrapped key (an attack, or a
    // real bug) as a transcription error. Two different situations, two different sentences.
    if (e instanceof RosterError || (e as Error | undefined)?.name === 'RosterError') {
      return {
        ok: false,
        message:
          'Those words are right, but the dashboard data that came back with them is not usable ' +
          'yet. This is not something you can fix by re-typing — please get in touch.',
        action: 'get_help',
        rejectedBy: 'roster',
      };
    }
    // Swallowed deliberately, and this is the point of the whole function. What lands here is
    // either a wrong key or a checksum-passing typo, and the owner can do nothing with
    // "crypto_aead_xchacha20poly1305_ietf_decrypt failed". They can do something with a
    // sentence about their sheet. ARCHITECTURE.md: no stack trace ever reaches the owner.
    return {
      ok: false,
      message: notRightMessage(input.kind),
      action: 'check_the_sheet',
      rejectedBy: 'unwrap',
    };
  } finally {
    // The recovery key is 32 bytes that open everything. It has done its job by here.
    parsed.key.fill(0);
  }
}

function notRightMessage(kind: 'words' | 'qr'): string {
  return kind === 'words'
    ? 'Those 24 words are not the ones for this dashboard. Check them against your recovery ' +
        'sheet, in order — or use the square code at the top of the sheet instead.'
    : 'That code is not the one for this dashboard. Scan the square code on your own recovery ' +
        'sheet, or type the 24 words instead.';
}

export interface VerificationChallenge {
  /** 1-indexed positions as printed on the sheet. */
  positions: number[];
  /** Checks the user's answers. */
  check: (answers: string[]) => boolean;
}

/**
 * The verification gate.
 *
 * FORCED, AND UNSKIPPABLE. An unverified recovery key is worse than no recovery key, because it
 * manufactures false confidence: the owner believes they are covered, files the sheet away, and
 * discovers eight months later that they printed nothing, or printed it wrong, or the printer
 * ate it. Two words is a small enough tax that people will actually do it.
 */
export function makeVerificationChallenge(sheet: RecoverySheet): VerificationChallenge {
  const positions = [...VERIFY_WORD_POSITIONS];
  return {
    positions,
    check: (answers: string[]) => {
      if (!Array.isArray(answers) || answers.length !== positions.length) return false;
      return positions.every((pos, i) => {
        const expected = sheet.words[pos - 1];
        const given = answers[i];
        // Both of these were previously `undefined` when the sheet was short and the answer was
        // missing — and `undefined === undefined` opened the one gate in this product that is
        // supposed to be unskippable. The gate must not assume its inputs are well-formed:
        // `answers` arrives over IPC from the renderer, and `sheet` could be a truncated
        // restore. Anything that is not two real strings is a failed check, not a passed one.
        if (typeof expected !== 'string' || expected.length === 0) return false;
        if (typeof given !== 'string') return false;
        return given.trim().toLowerCase() === expected;
      });
    },
  };
}

/**
 * The printable sheet, as HTML for Electron's printToPDF.
 *
 * Design notes that are not cosmetic:
 *   - The QR is PRIMARY and the words are the fallback. Recovery by phone camera beats typing
 *     24 English words, and this audience is not English-first. (Flagged as worth real user
 *     testing — I lean QR-primary, but that is a judgement, not data.)
 *   - Numbered grid, large type: this gets read under a tube light in a back office, possibly
 *     by someone who needs reading glasses they are not wearing.
 *   - Business name and date printed: a drawer accumulates these.
 *   - The reassurance is printed ON the sheet, because the sheet outlives the app's UI.
 */
/**
 * The one image on the sheet, as a self-contained data URL.
 *
 * Validated rather than escaped, and the distinction matters: `src` is a URL context, not a text
 * context, so escaping alone would still admit `javascript:` and friends. Only a base64 image
 * payload is a legitimate value here — the QR is rendered locally and handed straight over — so
 * anything else is a bug in the caller, and it fails loudly at print time rather than quietly
 * emitting markup. Electron's printToPDF renders this HTML, so an injected attribute would
 * execute with whatever privileges that renderer has, against a page that has the raw recovery
 * key printed on it.
 */
const QR_DATA_URL = /^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/]+={0,2}$/;

export function recoverySheetHtml(sheet: RecoverySheet, qrDataUrl: string): string {
  if (!QR_DATA_URL.test(qrDataUrl)) {
    throw new TypeError('recovery sheet QR must be a base64 image data URL');
  }

  const cells = sheet.words
    .map(
      (w, i) =>
        `<div class="cell"><span class="n">${i + 1}</span><span class="w">${escapeHtml(w)}</span></div>`,
    )
    .join('');

  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Recovery Sheet</title>
<style>
  @page { size: A4; margin: 18mm; }
  body { font: 12pt/1.5 system-ui, sans-serif; color: #000; }
  h1 { font-size: 19pt; margin: 0 0 2mm; }
  .meta { color: #444; margin-bottom: 6mm; font-size: 10.5pt; }
  .warn { border: 1.5pt solid #000; padding: 4mm; margin-bottom: 6mm; font-size: 11pt; }
  .warn b { display: block; margin-bottom: 1.5mm; }
  .split { display: flex; gap: 8mm; align-items: flex-start; }
  .qr { flex: none; text-align: center; }
  .qr img { width: 46mm; height: 46mm; }
  .qr .cap { font-size: 9.5pt; color: #444; margin-top: 1.5mm; }
  .grid { flex: 1; display: grid; grid-template-columns: repeat(3, 1fr); gap: 2mm 4mm; }
  .cell { border-bottom: 0.5pt solid #bbb; padding: 1.2mm 0; display: flex; gap: 2.5mm; align-items: baseline; }
  .n { color: #888; font-size: 9pt; width: 5mm; text-align: right; flex: none; }
  .w { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5pt; letter-spacing: 0.2pt; }
  .foot { margin-top: 7mm; font-size: 10pt; color: #444; border-top: 0.5pt solid #ccc; padding-top: 3mm; }
</style></head>
<body>
  <h1>Tally Bridge — Recovery Sheet</h1>
  <div class="meta">${escapeHtml(sheet.businessName)} &nbsp;·&nbsp; ${escapeHtml(sheet.createdOn)}</div>

  <div class="warn">
    <b>Keep this paper safe. Store it with your Tally backup.</b>
    Anyone holding this sheet can read your dashboard. Nobody — including us — can recover your
    data without it if you also forget your passphrase.
  </div>

  <div class="split">
    <div class="qr">
      <img src="${escapeHtml(qrDataUrl)}" alt="Recovery QR code" />
      <div class="cap">Scan this to recover</div>
    </div>
    <div class="grid">${cells}</div>
  </div>

  <div class="foot">
    Scanning the code is the easiest way to recover. The 24 words are a backup if the code will
    not scan — type them in order.<br />
    If you lose this sheet <b>and</b> your passphrase, you can still start again: your figures
    are rebuilt from Tally. Only the dashboard's history is lost.
  </div>
</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * What a reset actually costs — shown before the user confirms.
 *
 * The honest framing IS the feature. An owner told "you will lose everything" will not click,
 * and becomes a support ticket nobody can close. An owner told the truth — that the numbers
 * come back from Tally and only the dashboard's history goes — will click, and is unblocked in
 * a minute.
 */
export function describeReset(): { title: string; body: string; confirmLabel: string } {
  return {
    title: 'Start again with a new passphrase?',
    body:
      'Your figures are safe — they are rebuilt from Tally, which has always been the real ' +
      'record. You will lose only the dashboard\'s saved history, and it fills back in as you ' +
      'work. You will set a new passphrase and print a new recovery sheet.',
    confirmLabel: 'Start again',
  };
}
