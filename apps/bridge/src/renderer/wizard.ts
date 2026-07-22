import { formatMoney } from '@tally-bridge/viewmodel';
import type { BridgeApi } from '../main/ipc.ts';
import type { ProvisionStep } from '../onboarding/vercel.ts';
import type { RecoverySheet } from '../onboarding/recovery.ts';
import type {
  ActionKind,
  TallyCompany,
  WizardEvent,
  WizardState,
} from '../onboarding/wizard.ts';
import { clear, el, mount } from './dom.ts';
import { LOCALES, LOCALE_NAMES, isLocale, type Locale } from './i18n.ts';

/**
 * The setup wizard, as seen.
 *
 * WHAT THIS FILE IS NOT: a second state machine. `src/onboarding/wizard.ts` already holds the
 * only one, it is pure, and it is where the unskippable recovery gate lives with a test that
 * throws every event in the union at it. Writing another one here would mean the gate exists
 * twice and is authoritative in neither — and the copy that renders is the copy a future
 * contributor edits.
 *
 * So this is a VIEW over that machine, in three layers:
 *
 *   describeWizard(state, lang) -> ScreenModel   pure data, no DOM. Every rule worth testing
 *                                                lives here, and `test/wizard.renderer.test.ts`
 *                                                tests it with no browser in sight.
 *   renderWizard(root, model, ...)               ScreenModel -> DOM nodes. textContent only.
 *   mountWizard(root, host, ...)                 the driver loop: state in, events out.
 *
 * WHY THE IMPORTS FROM ../onboarding ARE `import type`, AND WHY THAT IS LOAD-BEARING.
 *
 * They are erased at emit, so nothing from that directory is in the renderer's module graph at
 * runtime. They must stay that way. `onboarding/wizard.ts` value-imports `./recovery.ts`, which
 * imports `@scure/bip39` and `@tally-bridge/crypto` and uses `Buffer` — none of which a browser
 * resolves, and none of which `scripts/build-assets.mjs` vendors (it only rewrites
 * `@tally-bridge/*`, and only under `dist/renderer/`). A single value import here would emit a
 * bare specifier into `dist/onboarding/`, where the build's unresolved-specifier check does not
 * look, and the first user-visible symptom would be a blank window on a customer's PC.
 *
 * Types, though, are exactly what we want to share: `ScreenModel` is derived from `WizardState`
 * by a `switch` the compiler checks for exhaustiveness, so a new phase in the machine fails THIS
 * file's build rather than rendering as a blank panel.
 *
 * THE HOST PORT. The renderer has no Node, no network (CSP `connect-src 'none'`) and no key. It
 * cannot probe Tally, call Vercel, derive Argon2id or drive a printer. `WizardHost` is the
 * enumerated set of things it needs the main process to do, and `hostFromBridge` feature-detects
 * them off `window.bridge`. Detection rather than assumption: `ipcRenderer.invoke` on a channel
 * with no handler REJECTS, and a rejected promise in a wizard is a spinner that never resolves —
 * the exact failure this app has already shipped once ("Syncing…" forever).
 */

// ---------------------------------------------------------------- language

/**
 * Language.
 *
 * English and Hindi from day one, and the structure — not the good intentions — is what lets a
 * third language land later. Two rules hold it together:
 *
 *   1. NO ENGLISH IN LOGIC. Nothing here branches on the text of a string. Every decision is
 *      made on a discriminant the machine already carries (`reason`, `step`, `kind`, `phase`),
 *      and the text is looked up afterwards. This is why `describeWizard` can translate the
 *      first screen's "Tally is not open" at all: it never reads that sentence, it reads
 *      `reason: 'not_running'`.
 *   2. THE DICTIONARY IS TYPE-CHECKED. `Strings` is derived from `EN`, so a key added to English
 *      and forgotten in Hindi fails the build instead of shipping a blank label.
 */
/**
 * `Locale` from `./i18n.ts`, not a second union of the same two strings.
 *
 * The dashboard already owns the renderer's language vocabulary. Declaring `'en' | 'hi'` again
 * here would type-check perfectly and still be a bug: the wizard is where the language is
 * actually CHOSEN — it runs before the dashboard exists — and two independent notions of
 * "language" is how an owner picks हिंदी during setup and lands on an English dashboard thirty
 * seconds later. Aliased rather than re-declared so a third locale is added in one file.
 */
export type Lang = Locale;

export const LANGS: readonly Lang[] = LOCALES;

/** What the language toggle says. A language's own name, never a translation of it. */
export const LANG_NAMES: Record<Lang, string> = LOCALE_NAMES;

/**
 * Where the dashboard looks for the language. Duplicated from `dashboard.ts`, which owns it and
 * does not export it — and duplication of a STRING KEY is drift waiting to happen, so
 * `test/wizard.renderer.test.ts` reads both files and fails the build if they stop matching.
 * That is the cheap half of a fix; the real one is a shared helper in `i18n.ts` once the
 * dashboard is not being written underneath this file.
 */
const LOCALE_STORAGE_KEY = 'tally-bridge.locale';

/** The language the owner last chose, from the same drawer the dashboard reads. */
export function storedLang(): Lang | undefined {
  try {
    const v = globalThis.localStorage?.getItem(LOCALE_STORAGE_KEY);
    return isLocale(v) ? v : undefined;
  } catch {
    // localStorage throws rather than returns null when storage is disabled. A language
    // preference is not worth a broken setup screen.
    return undefined;
  }
}

/** Remember it, so setup's choice is the dashboard's default rather than a fresh guess. */
export function rememberLang(lang: Lang): void {
  try {
    globalThis.localStorage?.setItem(LOCALE_STORAGE_KEY, lang);
  } catch {
    // Ignored on purpose: see storedLang.
  }
}

const EN = {
  step_of: 'Step {n} of 3',
  language: 'Language',

  // ---- Screen 1
  s1_step: 'Find Tally',
  s1_probing_title: 'Looking for Tally',
  s1_probing_body: 'This takes a moment.',
  s1_ready_title: 'Tally is open',
  s1_ready_one: 'We found your company. Nothing has left this computer yet.',
  s1_ready_many: 'Choose the company you want on your dashboard.',
  s1_wait_not_running: 'Tally is not open on this computer.',
  s1_wait_no_company: 'Tally is open, but no company is loaded.',
  s1_wait_title: 'Waiting for Tally',
  s1_wait_calm: 'This is normal. Open Tally, then try again.',
  s1_problem_title: 'We could not read Tally',

  // ---- Screen 2
  s2_step: 'Connect your dashboard',
  s2_cost_title: 'What this costs',
  s2_cost_body:
    'Your dashboard runs on your own Vercel account, so the figures stay yours. Vercel’s free plan is for personal use only — a business needs their Pro plan, about {inr} a month (US${usd}), paid to Vercel and not to us.',
  s2_identity_title: 'Getting ready',
  s2_identity_body: 'Preparing the lock for your figures.',
  s2_token_title: 'Connect your Vercel account',
  s2_token_body:
    'We will open Vercel in your browser. Copy the code it shows you and paste it here. This is the one thing we cannot do for you.',
  s2_token_label: 'Paste the code from Vercel',
  s2_token_open: 'Open Vercel',
  s2_token_submit: 'Continue',
  s2_progress_title: 'Setting up your dashboard',
  s2_progress_calm: 'This takes about a minute. You can leave this window open.',
  s2_neon_title: 'One click, then come back',
  s2_neon_body:
    'Your dashboard needs a free database called Neon. We just opened its page in your browser — here is exactly what to do there:',
  s2_neon_step1: '1.  If Vercel asks you to sign in, sign in with the same account.',
  s2_neon_step2: '2.  Click the “Install” button, then confirm with “Install” once more.',
  s2_neon_step3: '3.  Come back to this window — you are done. It continues on its own.',
  s2_neon_waiting: 'Waiting for you to click Install…',
  s2_problem_title: 'That did not work',

  // ---- Screen 3
  s3_step: 'Set your passphrase',
  s3_entry_title: 'Choose a passphrase',
  s3_only_key_title: 'This is the only key',
  s3_only_key_body:
    'Your passphrase is the only thing that opens your figures. We do not keep a copy, and we cannot reset it for you. That is exactly what stops anyone else — including us — from reading them.',
  s3_forget_title: 'If you forget it, you have not lost your figures',
  s3_forget_body:
    'Tally is the real record and always has been. You would set a new passphrase, and your figures come back from Tally on their own. You would lose only the history this dashboard has saved — nothing from Tally.',
  s3_pass_label: 'Passphrase',
  s3_confirm_label: 'Type it again',
  s3_hint: 'A short sentence you will remember works better than a short word.',
  s3_entry_submit: 'Continue',
  s3_wrapping_title: 'Locking your figures',
  s3_wrapping_body: 'This takes a few seconds.',

  s3_sheet_title: 'Your recovery sheet',
  s3_sheet_body:
    'Print this and keep it with your Tally backup. If you ever forget your passphrase, this paper is the way back in.',
  s3_sheet_qr: 'Scan this with your phone to get back in.',
  s3_sheet_words: 'Or type these 24 words, in order.',
  s3_sheet_for: '{business} · {date}',
  s3_print: 'Print again',
  s3_sheet_submit: 'I have printed it',

  s3_verify_title: 'Check the paper',
  s3_verify_body:
    'Read the two words off the sheet you just printed. This is how we both know it printed properly — an unchecked sheet is worse than none, because you would only find out on the day you need it.',
  s3_word_label: 'Word {n}',
  s3_verify_submit: 'Finish setup',
  s3_verify_incomplete: 'Type both words from the sheet.',
  s3_problem_title: 'That did not work',

  // ---- Done
  done_title: 'You are set up',
  done_body: '{business} is syncing now. Your figures will appear here in a few minutes.',
  done_open: 'Open my dashboard',

  // ---- Actions, by kind. Never by the label the machine carries.
  action_retry_probe: 'Try again',
  action_open_neon: 'Open the page',
  action_paste_new_token: 'Paste a new code',
  action_open_vercel_billing: 'Open Vercel billing',
  action_choose_another_name: 'Choose another name',
  action_retry_provision: 'Try again',
  action_choose_another_passphrase: 'Try another passphrase',
  action_print_again: 'Print again',
  action_start_again: 'Start again',

  // ---- The renderer's own failures.
  host_missing:
    'Setup cannot start because part of the app did not load. Restarting usually fixes this.',
  host_failed: 'Something went wrong. Nothing was saved — you can try again.',
} as const;

type Key = keyof typeof EN;
type Strings = Record<Key, string>;

/**
 * Hindi.
 *
 * Written for the reader this product actually has: a business owner, not a developer. So
 * "passphrase" stays a recognisable word rather than becoming a coined Sanskrit compound nobody
 * says out loud, and "Tally" and "Vercel" are product names and stay as they are.
 */
const HI: Strings = {
  step_of: 'चरण {n} / 3',
  language: 'भाषा',

  s1_step: 'Tally खोजें',
  s1_probing_title: 'Tally खोजा जा रहा है',
  s1_probing_body: 'एक क्षण लगेगा।',
  s1_ready_title: 'Tally खुला है',
  s1_ready_one: 'आपकी कंपनी मिल गई। अभी तक कुछ भी इस कंप्यूटर से बाहर नहीं गया है।',
  s1_ready_many: 'जिस कंपनी को डैशबोर्ड पर देखना है, उसे चुनें।',
  s1_wait_not_running: 'इस कंप्यूटर पर Tally खुला नहीं है।',
  s1_wait_no_company: 'Tally खुला है, लेकिन कोई कंपनी लोड नहीं है।',
  s1_wait_title: 'Tally का इंतज़ार',
  s1_wait_calm: 'यह सामान्य है। Tally खोलें, फिर दोबारा कोशिश करें।',
  s1_problem_title: 'हम Tally को पढ़ नहीं सके',

  s2_step: 'डैशबोर्ड जोड़ें',
  s2_cost_title: 'इसका खर्च',
  s2_cost_body:
    'आपका डैशबोर्ड आपके अपने Vercel खाते पर चलता है, इसलिए आँकड़े आपके ही रहते हैं। Vercel का मुफ़्त प्लान केवल निजी उपयोग के लिए है — व्यापार के लिए उनका Pro प्लान चाहिए, लगभग {inr} प्रति माह (US${usd}), जो Vercel को जाता है, हमें नहीं।',
  s2_identity_title: 'तैयारी हो रही है',
  s2_identity_body: 'आपके आँकड़ों का ताला तैयार किया जा रहा है।',
  s2_token_title: 'अपना Vercel खाता जोड़ें',
  s2_token_body:
    'हम आपके ब्राउज़र में Vercel खोलेंगे। वहाँ दिखने वाला कोड कॉपी करके यहाँ चिपकाएँ। यह एक काम हम आपके लिए नहीं कर सकते।',
  s2_token_label: 'Vercel से मिला कोड यहाँ चिपकाएँ',
  s2_token_open: 'Vercel खोलें',
  s2_token_submit: 'आगे बढ़ें',
  s2_progress_title: 'आपका डैशबोर्ड तैयार हो रहा है',
  s2_progress_calm: 'इसमें लगभग एक मिनट लगेगा। यह विंडो खुली रहने दें।',
  s2_neon_title: 'एक क्लिक, फिर यहाँ लौटें',
  s2_neon_body:
    'आपके डैशबोर्ड के लिए “Neon” नाम का एक मुफ़्त डेटाबेस चाहिए। हमने उसका पेज आपके ब्राउज़र में खोल दिया है — वहाँ बस इतना करें:',
  s2_neon_step1: '1.  अगर Vercel साइन-इन माँगे, तो उसी अकाउंट से साइन-इन करें।',
  s2_neon_step2: '2.  “Install” बटन दबाएँ, फिर एक बार और “Install” दबाकर पुष्टि करें।',
  s2_neon_step3: '3.  इस विंडो में लौट आएँ — बस हो गया। बाकी काम यह खुद कर लेगी।',
  s2_neon_waiting: 'आपके Install पर क्लिक करने का इंतज़ार…',
  s2_problem_title: 'यह नहीं हो सका',

  s3_step: 'पासफ़्रेज़ बनाएँ',
  s3_entry_title: 'अपना पासफ़्रेज़ चुनें',
  s3_only_key_title: 'यही एकमात्र चाबी है',
  s3_only_key_body:
    'आपका पासफ़्रेज़ ही आपके आँकड़े खोलता है। हमारे पास इसकी कोई नक़ल नहीं है, और हम इसे रीसेट नहीं कर सकते। इसी वजह से कोई और — हम भी — इन्हें पढ़ नहीं सकता।',
  s3_forget_title: 'भूल गए तो भी आपके आँकड़े नहीं जाते',
  s3_forget_body:
    'असली रिकॉर्ड हमेशा Tally ही है। आप नया पासफ़्रेज़ बनाएँगे और आँकड़े Tally से अपने आप वापस आ जाएँगे। सिर्फ़ इस डैशबोर्ड का पुराना इतिहास जाएगा — Tally से कुछ नहीं।',
  s3_pass_label: 'पासफ़्रेज़',
  s3_confirm_label: 'दोबारा लिखें',
  s3_hint: 'एक छोटा शब्द नहीं, बल्कि एक छोटा वाक्य चुनें जो आपको याद रहे।',
  s3_entry_submit: 'आगे बढ़ें',
  s3_wrapping_title: 'आपके आँकड़ों पर ताला लग रहा है',
  s3_wrapping_body: 'कुछ सेकंड लगेंगे।',

  s3_sheet_title: 'आपका रिकवरी पेज',
  s3_sheet_body:
    'इसे प्रिंट करके अपने Tally बैकअप के साथ रखें। पासफ़्रेज़ भूल जाने पर यही कागज़ वापस अंदर आने का रास्ता है।',
  s3_sheet_qr: 'वापस आने के लिए इसे अपने फ़ोन से स्कैन करें।',
  s3_sheet_words: 'या ये 24 शब्द क्रम से लिखें।',
  s3_sheet_for: '{business} · {date}',
  s3_print: 'दोबारा प्रिंट करें',
  s3_sheet_submit: 'मैंने प्रिंट कर लिया',

  s3_verify_title: 'कागज़ जाँचें',
  s3_verify_body:
    'अभी प्रिंट किए कागज़ से ये दो शब्द पढ़कर लिखें। इससे हम दोनों को पक्का पता चलता है कि प्रिंट ठीक हुआ — बिना जाँचा कागज़ न होने से भी बुरा है, क्योंकि पता उसी दिन चलेगा जिस दिन ज़रूरत होगी।',
  s3_word_label: 'शब्द {n}',
  s3_verify_submit: 'सेटअप पूरा करें',
  s3_verify_incomplete: 'कागज़ से दोनों शब्द लिखें।',
  s3_problem_title: 'यह नहीं हो सका',

  done_title: 'सेटअप पूरा हुआ',
  done_body: '{business} का सिंक शुरू हो गया है। कुछ ही मिनटों में आँकड़े यहाँ दिखने लगेंगे।',
  done_open: 'मेरा डैशबोर्ड खोलें',

  action_retry_probe: 'दोबारा कोशिश करें',
  action_open_neon: 'पेज खोलें',
  action_paste_new_token: 'नया कोड चिपकाएँ',
  action_open_vercel_billing: 'Vercel बिलिंग खोलें',
  action_choose_another_name: 'दूसरा नाम चुनें',
  action_retry_provision: 'दोबारा कोशिश करें',
  action_choose_another_passphrase: 'दूसरा पासफ़्रेज़ आज़माएँ',
  action_print_again: 'दोबारा प्रिंट करें',
  action_start_again: 'फिर से शुरू करें',

  host_missing: 'सेटअप शुरू नहीं हो सका क्योंकि ऐप का एक हिस्सा लोड नहीं हुआ। ऐप दोबारा खोलने से आमतौर पर ठीक हो जाता है।',
  host_failed: 'कुछ गड़बड़ हो गई। कुछ भी सेव नहीं हुआ — आप दोबारा कोशिश कर सकते हैं।',
};

export const STRINGS: Record<Lang, Strings> = { en: EN, hi: HI };

/** Look up a string. Missing keys fall back to English rather than rendering blank. */
export function t(lang: Lang, key: Key, vars?: Record<string, string>): string {
  const s = STRINGS[lang][key] ?? EN[key];
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (whole, name: string) => vars[name] ?? whole);
}

/**
 * Pick a starting language from the platform's tag.
 *
 * Best-effort and overridable: the toggle is always on screen. An owner whose Windows is set to
 * en-IN but who reads Hindi must not have to hunt through a settings screen to find that out.
 */
export function pickLang(tag: string | undefined): Lang {
  const primary = (tag ?? '').toLowerCase().split('-')[0];
  return primary === 'hi' ? 'hi' : 'en';
}

// ---------------------------------------------------------------- the cost conversation

/**
 * Vercel Pro, per month. THIS IS A PRODUCT FACT, NOT A FOOTNOTE.
 *
 * Vercel's Hobby plan is non-commercial: a business running on it is in breach and is
 * suspendable, and the way that surfaces is an angry phone call after the dashboard has already
 * gone dark. So the number goes on the screen, before the owner has spent a single minute on
 * setup, in the language they are reading. Burying it is how you sell someone a product that
 * gets switched off.
 */
export const PRO_PLAN_USD = 20;

/**
 * A rupee figure for a dollar price, deliberately rough.
 *
 * Vercel bills in USD, so USD is the fact and the rupee number is a courtesy — an owner should
 * not have to do arithmetic to find out whether this is affordable. A hardcoded rate drifts, so
 * this rounds hard to the nearest hundred and is always shown behind "about": a number that
 * claims two decimals of precision it cannot have is worse than a vague one, because someone
 * will hold us to it.
 */
const USD_INR_APPROX = 88;

/** `₹1,800` — lakh/crore grouping, via the one formatter that does it. */
export function proPlanRupees(): string {
  const rupees = Math.round((PRO_PLAN_USD * USD_INR_APPROX) / 100) * 100;
  // formatMoney, never Intl.NumberFormat: ARCHITECTURE.md pins this because Intl's grouping
  // depends on the ICU data the runtime shipped with, and a runtime without full ICU silently
  // falls back to en-US — i.e. `₹123,456`, the one thing this market must never see. formatMoney
  // is hand-rolled for exactly that reason and is tested.
  return formatMoney(rupees);
}

// ---------------------------------------------------------------- the screen model

export type Tone = 'calm' | 'waiting' | 'problem';

/** A thing the owner can ask for. Never a raw event — the driver reads inputs and builds those. */
export type Intent =
  | { kind: 'continue' }
  | { kind: 'select_company'; guid: string }
  | { kind: 'retry' }
  | { kind: 'open'; url: string }
  | { kind: 'submit_token' }
  | { kind: 'submit_passphrase' }
  | { kind: 'submit_verify' }
  | { kind: 'print' };

export interface FieldModel {
  id: string;
  label: string;
  /** `secret` masks; `word` is a single recovery word; `token` is a paste target. */
  kind: 'secret' | 'token' | 'word';
}

export interface NoteModel {
  title: string;
  body: string;
  /** `hard` is the consequence you must not soften; `soft` is the floor under it. */
  weight: 'hard' | 'soft';
}

export interface ButtonModel {
  label: string;
  intent: Intent;
}

export interface ScreenModel {
  step: 1 | 2 | 3;
  stepLabel: string;
  stepOf: string;
  title: string;
  /** Paragraphs. Never markup — these are set with textContent. */
  body: string[];
  tone: Tone;
  notes: NoteModel[];
  fields: FieldModel[];
  companies: Array<TallyCompany & { selected: boolean }>;
  progress: { percent: number; label: string } | undefined;
  sheet: { sheet: RecoverySheet; qrDataUrl: string | undefined } | undefined;
  /** The thing that moves forward. Absent when nothing can move yet. */
  primary: ButtonModel | undefined;
  /** The one recovery action. Exactly one, ever — see `WizardAction` in the machine. */
  action: (ButtonModel & { url: string | undefined }) | undefined;
  complete: boolean;
}

/**
 * Where the progress bar is.
 *
 * ONE bar, and the label is a sentence the machine already wrote ("Creating your database…"),
 * never the step's name. `provision_database` is our vocabulary; it means nothing to an owner
 * and reads as a leaked internal, which is the moment a non-technical user decides the software
 * is not for them.
 */
const STEP_ORDER: readonly ProvisionStep[] = [
  'verify_token',
  'resolve_team',
  'check_neon',
  'await_neon_install',
  'create_project',
  'provision_database',
  'connect_database',
  'set_env',
  'upload_files',
  'deploy',
  'await_ready',
  'done',
];

/** 0–100, monotonic in STEP_ORDER. An unknown step reads as "just started", never as done. */
export function progressPercent(step: ProvisionStep): number {
  const i = STEP_ORDER.indexOf(step);
  if (i < 0) return 0;
  return Math.round(((i + 1) / STEP_ORDER.length) * 100);
}

/**
 * The action label, chosen by KIND.
 *
 * The machine's own `label` is English, baked into `onboarding/wizard.ts`, and it is not
 * translated — but `kind` is a closed union, so the renderer can translate it without ever
 * reading the English. `label` is the fallback for a kind added later: a real sentence in the
 * wrong language beats a blank button.
 */
export function actionLabel(lang: Lang, kind: ActionKind, fallback: string): string {
  const key = `action_${kind}` as Key;
  return key in EN ? t(lang, key) : fallback;
}

const EMPTY = {
  notes: [] as NoteModel[],
  fields: [] as FieldModel[],
  companies: [] as Array<TallyCompany & { selected: boolean }>,
  progress: undefined,
  sheet: undefined,
  primary: undefined,
  action: undefined,
  complete: false,
};

/**
 * WizardState -> ScreenModel. PURE, and the reason every rule below is testable without a DOM.
 *
 * Exhaustive by construction: the `switch` has no default, so a phase added to the machine is a
 * compile error here rather than a screen that renders as nothing.
 */
export function describeWizard(
  state: WizardState,
  lang: Lang,
  qrDataUrl?: string | undefined,
): ScreenModel {
  const base = { stepOf: '', ...EMPTY };

  switch (state.screen) {
    case 'findTally': {
      const head = {
        ...base,
        step: 1 as const,
        stepLabel: t(lang, 's1_step'),
        stepOf: t(lang, 'step_of', { n: '1' }),
      };
      switch (state.phase) {
        case 'probing':
          return {
            ...head,
            title: t(lang, 's1_probing_title'),
            body: [t(lang, 's1_probing_body')],
            tone: 'calm',
          };
        case 'ready':
          return {
            ...head,
            title: t(lang, 's1_ready_title'),
            body: [state.companies.length === 1 ? t(lang, 's1_ready_one') : t(lang, 's1_ready_many')],
            tone: 'calm',
            companies: state.companies.map((c) => ({ ...c, selected: c.guid === state.selectedGuid })),
            // Inert until a company is picked, and the machine agrees: `continue` with no
            // selection is a no-op there. Showing a live button that does nothing is how an
            // owner concludes the app is broken.
            primary:
              state.selectedGuid === undefined
                ? undefined
                : { label: t(lang, 's2_token_submit'), intent: { kind: 'continue' } },
          };
        case 'waiting':
          /**
           * TALLY BEING CLOSED IS THE NORMAL OVERNIGHT STATE. It renders `waiting`, not
           * `problem`: calm title, one sentence, one button. Note the sentence is chosen by
           * `state.reason`, never by reading `state.message` — that is what makes it translate.
           */
          return {
            ...head,
            title: t(lang, 's1_wait_title'),
            body: [
              state.reason === 'not_running'
                ? t(lang, 's1_wait_not_running')
                : t(lang, 's1_wait_no_company'),
              t(lang, 's1_wait_calm'),
            ],
            tone: 'waiting',
            action: {
              label: actionLabel(lang, state.action.kind, state.action.label),
              intent: { kind: 'retry' },
              url: state.action.url,
            },
          };
        case 'problem':
          return {
            ...head,
            title: t(lang, 's1_problem_title'),
            // Untranslated on purpose: this is the machine's prose, and it is the one place it
            // may carry Tally's own sanitised fault text ("Licence not active"). Inventing a
            // Hindi sentence for an unknown fault would be a lie; showing the English one is a
            // gap, and a gap is honest. Every state ABOVE this is translated because its
            // discriminant told us what happened.
            body: [state.message],
            tone: 'problem',
            action: {
              label: actionLabel(lang, state.action.kind, state.action.label),
              intent: { kind: 'retry' },
              url: state.action.url,
            },
          };
      }
      break;
    }

    case 'connectCloud': {
      const head = {
        ...base,
        step: 2 as const,
        stepLabel: t(lang, 's2_step'),
        stepOf: t(lang, 'step_of', { n: '2' }),
      };
      /** Shown before a single minute is spent, not after. */
      const cost: NoteModel = {
        title: t(lang, 's2_cost_title'),
        body: t(lang, 's2_cost_body', { inr: proPlanRupees(), usd: String(PRO_PLAN_USD) }),
        weight: 'hard',
      };

      switch (state.phase) {
        case 'awaitIdentity':
          return {
            ...head,
            title: t(lang, 's2_identity_title'),
            body: [t(lang, 's2_identity_body')],
            tone: 'calm',
            notes: [cost],
          };
        case 'awaitToken':
          /**
           * MANUAL STEP 1 OF 2, and it is unavoidable: no Vercel API mints a PAT. So it is not
           * apologised for and not hidden — we open the page, they paste, we do the rest.
           */
          return {
            ...head,
            title: t(lang, 's2_token_title'),
            body: [t(lang, 's2_token_body')],
            tone: 'calm',
            notes: [cost],
            fields: [{ id: 'token', label: t(lang, 's2_token_label'), kind: 'token' }],
            primary: { label: t(lang, 's2_token_submit'), intent: { kind: 'submit_token' } },
            action: {
              label: t(lang, 's2_token_open'),
              intent: { kind: 'open', url: VERCEL_TOKENS_URL },
              url: VERCEL_TOKENS_URL,
            },
          };
        case 'provisioning':
          return {
            ...head,
            title: t(lang, 's2_progress_title'),
            body: [t(lang, 's2_progress_calm')],
            tone: 'calm',
            // The machine's own sentence, verbatim. Piping it through means the bar and the
            // provisioner cannot drift apart.
            progress: { percent: progressPercent(state.step), label: state.message },
          };
        case 'needsHuman':
          /**
           * MANUAL STEP 2 OF 2: the single Neon "Install" click. Vercel has NO REST endpoint for
           * marketplace terms — it is a contract between the client and Neon, and their own CLI
           * docs say it needs human confirmation.
           *
           * So it renders `calm`, not `problem`. Nobody did anything wrong, and the driver is
           * already polling every 3s: the owner clicks once, comes back, and the screen has
           * moved on by itself. That is what turns an unavoidable step into a guided ~20
           * seconds rather than a dead end with a "Continue" button they have to find.
           */
          return {
            ...head,
            title: t(lang, 's2_neon_title'),
            body: [
              t(lang, 's2_neon_body'),
              t(lang, 's2_neon_step1'),
              t(lang, 's2_neon_step2'),
              t(lang, 's2_neon_step3'),
            ],
            tone: 'calm',
            progress: { percent: progressPercent('await_neon_install'), label: t(lang, 's2_neon_waiting') },
            action: {
              label: actionLabel(lang, state.action.kind, state.action.label),
              intent: state.action.url === undefined
                ? { kind: 'retry' }
                : { kind: 'open', url: state.action.url },
              url: state.action.url,
            },
          };
        case 'problem':
          return {
            ...head,
            title: t(lang, 's2_problem_title'),
            body: [state.message],
            tone: 'problem',
            action: {
              label: actionLabel(lang, state.action.kind, state.action.label),
              intent: state.action.url === undefined
                ? { kind: 'retry' }
                : { kind: 'open', url: state.action.url },
              url: state.action.url,
            },
          };
      }
      break;
    }

    case 'setPassphrase': {
      const head = {
        ...base,
        step: 3 as const,
        stepLabel: t(lang, 's3_step'),
        stepOf: t(lang, 'step_of', { n: '3' }),
      };
      /**
       * THE TWO NOTES THAT MUST TRAVEL TOGETHER.
       *
       * `hard` states the consequence without softening it: there is no reset, and there is no
       * copy. Softening it would be a lie, and it is also the entire value proposition — the
       * reason nobody at Vercel, Neon, or here can read the owner's receivables is precisely
       * that we cannot.
       *
       * `soft` is the floor, and it is why the hard note does not send people running. The
       * server is a derivative CACHE; Tally is the source of truth. Total key loss is a re-sync,
       * not a disaster. An owner told only the first half abandons setup; an owner told only the
       * second half does not print the sheet. Both, in this order, or neither.
       */
      const stakes: NoteModel[] = [
        { title: t(lang, 's3_only_key_title'), body: t(lang, 's3_only_key_body'), weight: 'hard' },
        { title: t(lang, 's3_forget_title'), body: t(lang, 's3_forget_body'), weight: 'soft' },
      ];

      switch (state.phase) {
        case 'entry':
          return {
            ...head,
            title: t(lang, 's3_entry_title'),
            body: [t(lang, 's3_hint')],
            tone: 'calm',
            notes: stakes,
            fields: [
              { id: 'passphrase', label: t(lang, 's3_pass_label'), kind: 'secret' },
              { id: 'confirm', label: t(lang, 's3_confirm_label'), kind: 'secret' },
            ],
            primary: { label: t(lang, 's3_entry_submit'), intent: { kind: 'submit_passphrase' } },
          };
        case 'wrapping':
          return {
            ...head,
            title: t(lang, 's3_wrapping_title'),
            body: [t(lang, 's3_wrapping_body')],
            tone: 'calm',
          };
        case 'sheet':
          return {
            ...head,
            title: t(lang, 's3_sheet_title'),
            body: [
              t(lang, 's3_sheet_body'),
              t(lang, 's3_sheet_for', {
                business: state.sheet.businessName,
                date: state.sheet.createdOn,
              }),
            ],
            tone: 'calm',
            sheet: { sheet: state.sheet, qrDataUrl },
            // "I have printed it" leads to the CHECK, not past it. The machine's `continue` from
            // `sheet` goes to `verify` and nowhere else.
            primary: { label: t(lang, 's3_sheet_submit'), intent: { kind: 'continue' } },
            action: { label: t(lang, 's3_print'), intent: { kind: 'print' }, url: undefined },
          };
        case 'verify':
          /**
           * THE GATE.
           *
           * Note what this model does NOT contain and can never contain: an intent that skips.
           * `Intent` has no such member, so a "Skip for now" button is not something a hurried
           * contributor can add here without adding it to the union, to the driver, and to the
           * machine — three files and a reviewer. And `primary` is `submit_verify`, which the
           * driver turns into `verify_submitted`; only the MACHINE can produce `done`, only from
           * a correct answer, and `test/wizard.test.ts` throws the entire event union at it.
           *
           * An unverified recovery sheet is worse than no sheet: it manufactures false
           * confidence. The owner files the paper away believing they are covered and finds out
           * eight months later, at the one moment there is no other way in.
           */
          return {
            ...head,
            title: t(lang, 's3_verify_title'),
            body: state.message === undefined
              ? [t(lang, 's3_verify_body')]
              : [t(lang, 's3_verify_body'), state.message],
            tone: state.message === undefined ? 'calm' : 'waiting',
            fields: state.positions.map((pos) => ({
              id: `word-${pos}`,
              label: t(lang, 's3_word_label', { n: String(pos) }),
              kind: 'word' as const,
            })),
            primary: { label: t(lang, 's3_verify_submit'), intent: { kind: 'submit_verify' } },
          };
        case 'problem':
          return {
            ...head,
            title: t(lang, 's3_problem_title'),
            body: [state.message],
            tone: 'problem',
            action: {
              label: actionLabel(lang, state.action.kind, state.action.label),
              intent: state.action.kind === 'print_again' ? { kind: 'print' } : { kind: 'retry' },
              url: state.action.url,
            },
          };
      }
      break;
    }

    case 'done':
      return {
        ...base,
        step: 3,
        stepLabel: t(lang, 's3_step'),
        stepOf: t(lang, 'step_of', { n: '3' }),
        title: t(lang, 'done_title'),
        body: [t(lang, 'done_body', { business: state.company.name })],
        tone: 'calm',
        complete: true,
        primary: { label: t(lang, 'done_open'), intent: { kind: 'continue' } },
      };
  }

  // Unreachable: every screen/phase above returns. This exists so the function is total even if
  // a malformed state arrives over IPC, and it fails CALM rather than throwing into a blank window.
  return {
    ...base,
    step: 1,
    stepLabel: t(lang, 's1_step'),
    stepOf: t(lang, 'step_of', { n: '1' }),
    title: t(lang, 's1_problem_title'),
    body: [t(lang, 'host_failed')],
    tone: 'problem',
    action: { label: t(lang, 'action_start_again'), intent: { kind: 'retry' }, url: undefined },
  };
}

// ---------------------------------------------------------------- gates

/**
 * Is setup finished?
 *
 * FAILS CLOSED, and the shape of that matters more than it looks. The bug this replaces was
 * `state.screen === undefined` matching a state that had not loaded — `undefined === undefined`
 * is `true`, and the one gate in the product that must not be walked past was walked past by an
 * IPC call that had not resolved yet. So: only the literal string 'done' on a real object is
 * done. Anything else — undefined, null, `{}`, a rejected call's fallback — is NOT done, and the
 * wizard stays on screen.
 */
export function isWizardComplete(state: unknown): boolean {
  if (typeof state !== 'object' || state === null) return false;
  return (state as { screen?: unknown }).screen === 'done';
}

/** Should the wizard be shown? Fails CLOSED: if we cannot tell, set up rather than pretend. */
export function shouldShowWizard(provisioned: unknown): boolean {
  return provisioned !== true;
}

/** What the content area should hold. See `decideContent`. */
export type ContentDecision = 'wizard-owns-content' | 'show-wizard' | 'show-dashboard';

/**
 * Who owns the content area right now.
 *
 * This is a pure function in a tested file rather than an `if` inside the renderer entry point,
 * and the reason is the bug it exists to prevent. `main.ts` exports nothing and runs on load, so
 * NOTHING TESTS IT — and the decision it was making wrong is the one that destroys the owner's
 * recovery sheet:
 *
 *   `isProvisioned()` flips during the WRAP, when the keystore persists. That is after the
 *   passphrase is submitted but two screens before the wizard finishes. The status bar lives
 *   outside the content area, so it stays clickable throughout setup, and its buttons call
 *   `refresh()`. Reading a true `isProvisioned` there, `refresh` concluded setup was over and
 *   disposed the wizard while the recovery sheet was on screen. It never came back — the flag
 *   stays true — so the sheet was gone, unverified, and `completeSetup` mints that key once.
 *
 * The mistake was one of AUTHORITY: `isProvisioned` reports what the KEYSTORE holds. It was
 * being asked whether the WIZARD had finished, which is a question about a state machine, and it
 * answers early by construction. A live wizard therefore outranks the flag — always. The wizard
 * announces completion exactly one way, through `onDone`, and its caller clears the handle
 * before refreshing, which is why 'wizard-owns-content' cannot wedge the app: the one legitimate
 * transition passes `wizardLive: false`.
 *
 * Note the ORDER of the two checks. `wizardLive` is first, so a live wizard survives regardless
 * of what `provisioned` says — including the failure case where it cannot be read at all.
 */
export function decideContent(wizardLive: boolean, provisioned: unknown): ContentDecision {
  if (wizardLive) return 'wizard-owns-content';
  return shouldShowWizard(provisioned) ? 'show-wizard' : 'show-dashboard';
}

/**
 * Is this a QR image we are willing to put in an `img src`?
 *
 * `src` is a URL context, not a text context, so `textContent` discipline does not help here and
 * escaping would not either — `javascript:` and `data:text/html` are both perfectly well-formed
 * URLs. This codebase has already had an HTML injection through a QR data URL, and the sheet is
 * the one screen with the raw recovery key on it, so the value is validated against the exact
 * shape a real QR has rather than sanitised.
 *
 * Deliberately NOT imported from `onboarding/recovery.ts`, which has the same regex: a value
 * import from there drags `@scure/bip39` and `Buffer` into the browser bundle. Duplicated on
 * purpose, and both are tested.
 */
const QR_DATA_URL = /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

export function isQrDataUrl(url: string): boolean {
  // svg+xml is on recovery.ts's list because printToPDF renders it in a throwaway process. It is
  // NOT on this one: an SVG in an <img> on THIS page is a document, and this page holds the
  // bridge. A QR is raster; nothing legitimate is lost.
  return QR_DATA_URL.test(url);
}

// ---------------------------------------------------------------- the host port

export const VERCEL_TOKENS_URL = 'https://vercel.com/account/tokens';

/**
 * What the wizard needs the main process to do.
 *
 * The renderer has no Node, no network and no key: it cannot probe Tally, call Vercel, run
 * Argon2id or drive a printer. Every one of those is a verb here, and the state machine lives on
 * the other side — so the renderer sends events and receives states, and the gate is enforced
 * where it is already tested rather than in a click handler on this side of the bridge.
 */
export interface WizardHost {
  getState(): Promise<WizardState>;
  /** Returns the state AFTER the event. The machine is the authority; this is not optimistic. */
  send(event: WizardEvent): Promise<WizardState>;
  subscribe(cb: (s: WizardState) => void): () => void;
  /** Allowlisted in main (`safeExternalUrl`); this is not a general opener. */
  openExternal(url: string): Promise<void>;
  /** A data: URL for the current sheet's QR. Rendered in main, where `qrcode` lives. */
  recoveryQr(): Promise<string>;
  /** Auto-opens the print dialog. Resolves when the dialog closes; rejects if printing failed. */
  printRecoverySheet(): Promise<void>;
}

/** The verbs `main/ipc.ts` must add. Optional here because a third agent is wiring them now. */
type WizardChannels = {
  getWizardState(): Promise<WizardState>;
  sendWizardEvent(e: WizardEvent): Promise<WizardState>;
  onWizardStateChanged(cb: (s: WizardState) => void): () => void;
  recoveryQr(): Promise<string>;
  printRecoverySheet(): Promise<void>;
};

const WIZARD_VERBS = [
  'getWizardState',
  'sendWizardEvent',
  'onWizardStateChanged',
  'recoveryQr',
  'printRecoverySheet',
] as const;

/**
 * Adapt `window.bridge` to the port, or report that it cannot be done.
 *
 * FEATURE-DETECTED, NOT ASSUMED. `ipcRenderer.invoke` on a channel with no handler REJECTS — so
 * calling a verb that is not wired yet does not throw somewhere visible, it leaves a spinner on
 * screen forever. That exact bug has already shipped in this renderer once ("Syncing…"). A
 * missing verb is a broken install, and a broken install gets one sentence and one button.
 */
export function hostFromBridge(bridge: BridgeApi | undefined): WizardHost | undefined {
  if (!bridge) return undefined;
  const b = bridge as BridgeApi & Partial<WizardChannels>;
  for (const verb of WIZARD_VERBS) {
    if (typeof b[verb] !== 'function') return undefined;
  }
  const w = b as BridgeApi & WizardChannels;
  return {
    getState: () => w.getWizardState(),
    send: (e) => w.sendWizardEvent(e),
    subscribe: (cb) => w.onWizardStateChanged(cb),
    openExternal: (url) => w.openExternal(url),
    recoveryQr: () => w.recoveryQr(),
    printRecoverySheet: () => w.printRecoverySheet(),
  };
}

// ---------------------------------------------------------------- rendering

function paragraphs(into: HTMLElement, lines: string[]): void {
  for (const line of lines) mount(into, el('p', 'wz-p', line));
}

function renderNotes(notes: NoteModel[]): HTMLElement | undefined {
  if (notes.length === 0) return undefined;
  const box = el('div', 'wz-notes');
  for (const n of notes) {
    const note = el('div', `wz-note wz-note-${n.weight}`);
    mount(note, el('div', 'wz-note-title', n.title), el('div', 'wz-note-body', n.body));
    mount(box, note);
  }
  return box;
}

function renderCompanies(
  companies: Array<TallyCompany & { selected: boolean }>,
  dispatch: (i: Intent) => void,
): HTMLElement | undefined {
  if (companies.length === 0) return undefined;
  const list = el('div', 'wz-companies');
  for (const c of companies) {
    const row = el('button', `wz-company${c.selected ? ' is-selected' : ''}`);
    row.type = 'button';
    // textContent. A company name is typed by whoever set Tally up and arrives from a file we
    // do not control; it is exactly the attacker-influenced string the no-innerHTML rule exists
    // for.
    mount(row, el('span', 'wz-company-name', c.name));
    row.addEventListener('click', () => dispatch({ kind: 'select_company', guid: c.guid }));
    mount(list, row);
  }
  return list;
}

function renderFields(fields: FieldModel[], values: Map<string, string>): HTMLElement | undefined {
  if (fields.length === 0) return undefined;
  const box = el('div', 'wz-fields');
  for (const f of fields) {
    const wrap = el('label', `wz-field wz-field-${f.kind}`);
    mount(wrap, el('span', 'wz-field-label', f.label));
    const input = el('input', 'wz-input');
    input.type = f.kind === 'secret' ? 'password' : 'text';
    // A recovery word is a lowercase dictionary word being copied off paper. Autocorrect,
    // capitalisation and spellcheck all fight that, and the gate then reads as broken.
    input.autocapitalize = 'off';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.value = values.get(f.id) ?? '';
    input.addEventListener('input', () => values.set(f.id, input.value));
    mount(wrap, input);
    mount(box, wrap);
  }
  return box;
}

function renderSheet(
  model: NonNullable<ScreenModel['sheet']>,
  lang: Lang,
): HTMLElement {
  const box = el('div', 'wz-sheet');

  const qr = el('div', 'wz-qr');
  // Validated, not escaped — see isQrDataUrl. An invalid one renders as no image rather than as
  // an attribute we did not intend.
  if (model.qrDataUrl !== undefined && isQrDataUrl(model.qrDataUrl)) {
    const img = el('img', 'wz-qr-img');
    img.src = model.qrDataUrl;
    img.alt = t(lang, 's3_sheet_qr');
    mount(qr, img);
  }
  mount(qr, el('div', 'wz-qr-cap', t(lang, 's3_sheet_qr')));
  mount(box, qr);

  const grid = el('div', 'wz-words');
  mount(box, el('div', 'wz-words-cap', t(lang, 's3_sheet_words')));
  model.sheet.words.forEach((word, i) => {
    const cell = el('div', 'wz-word');
    mount(cell, el('span', 'wz-word-n', String(i + 1)), el('span', 'wz-word-w', word));
    mount(grid, cell);
  });
  mount(box, grid);
  return box;
}

function renderProgress(p: NonNullable<ScreenModel['progress']>): HTMLElement {
  const box = el('div', 'wz-progress');
  const track = el('div', 'wz-track');
  const fill = el('div', 'wz-fill');
  fill.style.width = `${Math.max(0, Math.min(100, p.percent))}%`;
  mount(track, fill);
  mount(box, track, el('div', 'wz-progress-label', p.label));
  return box;
}

function renderLangToggle(lang: Lang, onLang: (l: Lang) => void): HTMLElement {
  const box = el('div', 'wz-langs');
  for (const l of LANGS) {
    const b = el('button', `wz-lang${l === lang ? ' is-selected' : ''}`, LANG_NAMES[l]);
    b.type = 'button';
    b.addEventListener('click', () => onLang(l));
    mount(box, b);
  }
  return box;
}

/** ScreenModel -> DOM. No decisions here; everything was decided in describeWizard. */
export function renderWizard(
  root: HTMLElement,
  model: ScreenModel,
  lang: Lang,
  values: Map<string, string>,
  dispatch: (i: Intent) => void,
  onLang: (l: Lang) => void,
): void {
  clear(root);

  const shell = el('div', `wz wz-tone-${model.tone}`);
  const head = el('div', 'wz-head');
  mount(head, el('div', 'wz-step', model.stepOf), el('div', 'wz-steplabel', model.stepLabel));
  mount(head, renderLangToggle(lang, onLang));
  mount(shell, head);

  const card = el('div', 'wz-card');
  mount(card, el('h1', 'wz-title', model.title));
  paragraphs(card, model.body);
  mount(card, renderNotes(model.notes));
  mount(card, renderCompanies(model.companies, dispatch));
  if (model.progress) mount(card, renderProgress(model.progress));
  if (model.sheet) mount(card, renderSheet(model.sheet, lang));
  mount(card, renderFields(model.fields, values));

  const buttons = el('div', 'wz-buttons');
  if (model.action) {
    const a = model.action;
    const b = el('button', 'wz-btn wz-btn-secondary', a.label);
    b.type = 'button';
    b.addEventListener('click', () => dispatch(a.intent));
    mount(buttons, b);
  }
  if (model.primary) {
    const p = model.primary;
    const b = el('button', 'wz-btn wz-btn-primary', p.label);
    b.type = 'button';
    b.addEventListener('click', () => dispatch(p.intent));
    mount(buttons, b);
  }
  mount(card, buttons);

  mount(shell, card);
  mount(root, shell);
}

// ---------------------------------------------------------------- the driver

/**
 * Mount the wizard and run it until setup is done.
 *
 * `onDone` fires only when the MACHINE says `done` — `isWizardComplete` is the only test, and it
 * fails closed. The renderer never decides that setup finished.
 */
export function mountWizard(
  root: HTMLElement,
  host: WizardHost,
  opts: { lang?: Lang; onDone: () => void },
): () => void {
  // The order is the policy: an explicit choice beats a remembered one, which beats the OS. The
  // OS sniff only ever decides the FIRST paint of the first screen — the toggle is always there.
  let lang = opts.lang ?? storedLang() ?? pickLang(globalThis.navigator?.language);
  let state: WizardState | undefined;
  let qrDataUrl: string | undefined;
  /** Field text lives here, not in the model: a passphrase must not survive a re-render. */
  let values = new Map<string, string>();
  let disposed = false;

  /**
   * Every host call can reject, and a rejection must never be silence. `.finally()` does not
   * handle one — it re-throws — which is how this renderer once left a button reading "Syncing…"
   * forever. The fallback is a VALUE.
   */
  async function ask<T>(call: () => Promise<T>, fallback: T): Promise<T> {
    try {
      return await call();
    } catch (e) {
      console.error('[wizard] host call failed:', e);
      return fallback;
    }
  }

  function paint(): void {
    if (disposed || !state) return;
    const model = describeWizard(state, lang, qrDataUrl);
    renderWizard(root, model, lang, values, dispatch, (l) => {
      lang = l;
      // Persist immediately, not at the end of setup: the owner who switches to हिंदी on screen
      // one must not be handed an English dashboard, and setup is exactly where they tell us.
      rememberLang(l);
      // Screen readers and the CSS `lang` selectors both key off this, and Devanagari needs the
      // font stack to know before it paints.
      document.documentElement.setAttribute('lang', l);
      paint();
    });
  }

  function apply(next: WizardState | undefined): void {
    if (disposed || !next) return;
    const changedPhase =
      state === undefined ||
      state.screen !== next.screen ||
      ('phase' in state ? state.phase : '') !== ('phase' in next ? next.phase : '');
    state = next;

    if (changedPhase) {
      // Inputs are per-phase. Carrying a passphrase across a screen change would leave it in a
      // live DOM node long after the one moment it was needed.
      values = new Map();
    }

    if (isWizardComplete(state)) {
      paint();
      opts.onDone();
      return;
    }

    if (state.screen === 'setPassphrase' && state.phase === 'sheet') {
      if (qrDataUrl === undefined) void loadQr();
      // Auto-open the print dialog: the sheet is the point of this screen, and a "Print" button
      // is a button a hurried owner walks past. Fire-and-forget — the machine does not advance
      // on `printed` (the printer may have been out of toner), so nothing waits on this.
      if (changedPhase) void print();
    } else {
      qrDataUrl = undefined;
    }
    paint();
  }

  async function loadQr(): Promise<void> {
    const url = await ask(() => host.recoveryQr(), undefined);
    if (disposed || url === undefined) return;
    qrDataUrl = url;
    paint();
  }

  async function print(): Promise<void> {
    try {
      await host.printRecoverySheet();
      apply(await ask(() => host.send({ type: 'printed' }), undefined));
    } catch (e) {
      apply(await ask(() => host.send({ type: 'print_failed', error: e }), undefined));
    }
  }

  function dispatch(intent: Intent): void {
    if (disposed || !state) return;
    const s = state;

    switch (intent.kind) {
      case 'open':
        // Allowlisted in main. A rejection here is not worth a screen: the button did nothing,
        // and the sentence next to it already says what to do.
        void ask(() => host.openExternal(intent.url), undefined);
        return;
      case 'print':
        void print();
        return;
      case 'select_company':
        void send({ type: 'select_company', guid: intent.guid });
        return;
      case 'continue':
        if (isWizardComplete(s)) {
          opts.onDone();
          return;
        }
        void send({ type: 'continue' });
        return;
      case 'retry':
        void send({ type: 'retry' });
        return;
      case 'submit_token': {
        const token = values.get('token') ?? '';
        void send({ type: 'token_pasted', token });
        return;
      }
      case 'submit_passphrase': {
        const passphrase = values.get('passphrase') ?? '';
        const confirm = values.get('confirm') ?? '';
        void send({ type: 'passphrase_submitted', passphrase, confirm });
        return;
      }
      case 'submit_verify': {
        if (s.screen !== 'setPassphrase' || s.phase !== 'verify') return;
        // Positions, in the machine's order. `?? ''` rather than a skipped entry: the gate must
        // receive two real strings and judge them, never a short array it might read as absent.
        const answers = s.positions.map((pos) => values.get(`word-${pos}`) ?? '');
        void send({ type: 'verify_submitted', answers });
        return;
      }
    }
  }

  async function send(event: WizardEvent): Promise<void> {
    const next = await ask(() => host.send(event), undefined);
    if (next === undefined) {
      // The machine could not be reached. Say so, once, with one button — never a dead screen.
      renderFatal(root, lang, () => void boot());
      return;
    }
    apply(next);
  }

  const unsubscribe = host.subscribe((s) => apply(s));

  async function boot(): Promise<void> {
    const first = await ask(() => host.getState(), undefined);
    if (first === undefined) {
      renderFatal(root, lang, () => void boot());
      return;
    }
    apply(first);
  }

  void boot();

  return () => {
    disposed = true;
    unsubscribe();
  };
}

/** The one screen for "the wizard itself is broken": one sentence, one button. */
function renderFatal(root: HTMLElement, lang: Lang, onRetry: () => void): void {
  clear(root);
  const card = el('div', 'wz-card wz-tone-problem');
  mount(card, el('p', 'wz-p', t(lang, 'host_failed')));
  const b = el('button', 'wz-btn wz-btn-primary', t(lang, 'action_retry_probe'));
  b.type = 'button';
  b.addEventListener('click', onRetry);
  mount(card, b);
  mount(root, card);
}

/**
 * Mount the wizard, or explain why it cannot be mounted.
 *
 * The entry point `main.ts` uses. Feature detection happens here so that a not-yet-wired IPC verb
 * produces a sentence rather than a spinner.
 */
export function startWizard(
  root: HTMLElement,
  bridge: BridgeApi | undefined,
  opts: { lang?: Lang; onDone: () => void },
): () => void {
  const host = hostFromBridge(bridge);
  const lang = opts.lang ?? storedLang() ?? pickLang(globalThis.navigator?.language);
  if (!host) {
    clear(root);
    const card = el('div', 'wz-card wz-tone-problem');
    mount(card, el('p', 'wz-p', t(lang, 'host_missing')));
    mount(root, card);
    return () => undefined;
  }
  return mountWizard(root, host, opts);
}
