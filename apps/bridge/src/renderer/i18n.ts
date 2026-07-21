import { formatRelativeTime } from '@tally-bridge/viewmodel';

/**
 * Strings for the dashboard.
 *
 * English and Hindi ship on day one. The structure is what matters for the languages that come
 * after (Gujarati, Marathi, Tamil, Telugu — the four that follow the customer base):
 *
 *   1. Every user-visible string in the dashboard has a KEY here. A renderer that writes a
 *      literal is a string that cannot be translated, and it will not be found again.
 *   2. A dictionary is `Partial<Dict>` over the English one, so a half-finished translation
 *      falls back per-key to English rather than shipping `undefined` or an empty card.
 *      Adding a key to `en` therefore never breaks another locale's build; it just leaves one
 *      line in English until a translator reaches it.
 *   3. Interpolation is `{name}` placeholders substituted at call time, never string
 *      concatenation at the call site. "₹5,000 overdue" and "₹5,000 बकाया" put the number in
 *      different places relative to the words, and a language with a different word order
 *      (or a different plural rule) needs the whole sentence in the dictionary, not half of it.
 *
 * BUCKET LABELS AND MONTH NAMES ARE TRANSLATED HERE, NOT READ OFF THE VIEW MODEL.
 * `AgeingCard.buckets[].label` and `TrendPoint.label` are English — the card layer is
 * surface-agnostic but not locale-agnostic, and it must not become locale-aware (it has no DOM
 * and no place to put a locale). So the renderer keys off the SEMANTIC token (`b.bucket`,
 * `p.period`) and looks the wording up here. The English text stays byte-identical to the
 * viewmodel's, so nothing reads inconsistently.
 */

export const LOCALES = ['en', 'hi'] as const;
export type Locale = (typeof LOCALES)[number];

export const LOCALE_NAMES: Record<Locale, string> = { en: 'English', hi: 'हिंदी' };

/** The English dictionary is the contract: every other locale is a Partial of it. */
const en = {
  'app.title': 'Your business today',

  'status.synced': 'Synced {when}',
  'status.never': 'Not synced yet',
  'status.syncing': 'Syncing…',
  'action.sync': 'Sync now',
  'action.showAll': 'Show all {n}',
  'action.showLess': 'Show less',

  'freshness.asOf': 'Figures as of {date}',
  'freshness.stale': 'These numbers are from the last successful sync. They may have changed.',

  'card.cash': 'Cash & Bank',
  'card.receivables': 'Receivables',
  'card.payables': 'Payables',
  'card.profit': 'Profit this month',
  'card.sales': 'Sales',
  'card.stock': 'Stock value',
  'card.sheet': 'Balance sheet',
  'card.duties': 'GST & taxes',

  'duties.net': 'Net GST payable',
  'duties.credit': 'Net input credit — the tax office owes you',
  'duties.empty': 'No Duties & Taxes ledgers found in Tally.',

  'cash.empty': 'No cash or bank ledgers found in Tally.',
  'cash.overdrawn': 'Your accounts are overdrawn.',
  'cash.accounts': '{n} accounts',
  'cash.oneAccount': '1 account',
  'cash.noSparkline': 'Tally sends one closing balance, so there is no cash history to chart yet.',

  'ageing.overdue': '{amount} overdue',
  'ageing.nothingOverdue': 'Nothing overdue',
  'ageing.topDebtors': 'Who owes you most',
  'ageing.topCreditors': 'Who you owe most',
  'ageing.empty.receivable': 'Nobody owes you anything. Every bill is settled.',
  'ageing.empty.payable': 'You owe nobody. Every bill is settled.',
  'ageing.everyoneElse': 'Everyone else',
  'ageing.bills': '{n} bills',
  'ageing.oneBill': '1 bill',
  'ageing.total': 'total',

  /*
   * The three reasons a ring is refused. Each is a real state of a real business, so each is a
   * plain sentence that says what is true and where to look — never "chart unavailable".
   * `{amount}` is the SIGNED total from the card layer, so these read naturally with a minus.
   */
  'ageing.credit.receivable':
    'Your customers have paid more in advance than they owe: the book nets {amount}. The buckets below show where it sits.',
  'ageing.credit.payable':
    'You have paid your suppliers more in advance than you owe: the book nets {amount}. The buckets below show where it sits.',
  'ageing.netZero': 'What is owed and what has been advanced cancel out exactly.',
  'ageing.mixed': 'One bucket holds an advance, so a share chart would misread it. The bars below are exact.',

  'bucket.not_due': 'Not due',
  'bucket.0_30': '1–30 days',
  'bucket.31_60': '31–60 days',
  'bucket.61_90': '61–90 days',
  'bucket.91_180': '91–180 days',
  'bucket.180_plus': '180+ days',

  'bucket.short.not_due': 'current',
  'bucket.short.0_30': '1–30d',
  'bucket.short.31_60': '31–60d',
  'bucket.short.61_90': '61–90d',
  'bucket.short.91_180': '91–180d',
  'bucket.short.180_plus': '180d+',

  'profit.vsLast': 'vs {amount} last month',
  'profit.empty': 'No sales or expenses recorded this month yet.',
  'profit.lastMonth': 'Last',
  'profit.thisMonth': 'This',

  'trend.subtitle': 'Last {n} months',
  'trend.peak': 'Peak {amount}',
  'trend.empty': 'Not enough history yet. This fills in as months close.',
  'trend.none': 'No sales recorded yet.',

  'stock.empty': 'No stock groups in Tally. Most service businesses see this.',

  'sheet.empty': 'No balance sheet groups yet.',
  // Says what the screen shows, in the owner's terms. The old copy explained the DEBUGGING
  // convention ("assets show as negative … Tally's own Dr/Cr convention") — honest about the
  // internals and useless to a shop owner, who has never seen his assets rendered negative in
  // Tally itself.
  'sheet.hint': 'What you own, and what you owe. Tap a group to open it.',
  'sheet.assets': 'What you own',
  'sheet.liabilities': 'What you owe',
  'sheet.nil': 'Nil balance: {names}',

  'company.switch': 'Company',

  'error.card': 'This card could not be read from the last sync.',
  'error.cards': 'Some figures are missing from this view. The next sync usually fills them in.',
  'error.generic': 'Your data could not be read.',
  'error.unreachable': 'Tally Bridge is not responding. Restarting the app usually fixes this.',
  'action.retry': 'Try again',

  'locked.body': 'Your data is locked. Enter your passphrase to see your figures.',
  'locked.action': 'Unlock',
  'unlock.title': 'Enter your passphrase',
  'unlock.sub': 'This unlocks your figures on this computer. It takes a few seconds.',
  'unlock.placeholder': 'Passphrase',
  'unlock.working': 'Unlocking…',
  'unlock.wrong': 'That passphrase did not work. Please try again.',
  'unlock.cancel': 'Cancel',

  'empty.all': 'No data yet. Once Tally has been open for one sync, your numbers appear here.',
} satisfies Record<string, string>;

export type StringKey = keyof typeof en;

const hi: Partial<Record<StringKey, string>> = {
  'app.title': 'आपका व्यापार आज',

  'status.synced': '{when} सिंक हुआ',
  'status.never': 'अभी तक सिंक नहीं हुआ',
  'status.syncing': 'सिंक हो रहा है…',
  'action.sync': 'अभी सिंक करें',
  'action.showAll': 'सभी {n} दिखाएँ',
  'action.showLess': 'कम दिखाएँ',

  'freshness.asOf': '{date} तक के आँकड़े',
  'freshness.stale': 'ये आँकड़े पिछले सफल सिंक के हैं। इनमें बदलाव हो सकता है।',

  'card.cash': 'नकद और बैंक',
  'card.receivables': 'लेना है',
  'card.payables': 'देना है',
  'card.profit': 'इस महीने का लाभ',
  'card.sales': 'बिक्री',
  'card.stock': 'स्टॉक मूल्य',
  'card.sheet': 'बैलेंस शीट',
  'card.duties': 'GST और कर',

  'duties.net': 'शुद्ध GST देय',
  'duties.credit': 'शुद्ध इनपुट क्रेडिट — कर विभाग आपका बकाया है',
  'duties.empty': 'Tally में कोई Duties & Taxes खाता नहीं मिला।',

  'cash.empty': 'Tally में कोई नकद या बैंक खाता नहीं मिला।',
  'cash.overdrawn': 'आपके खातों में शेष ऋणात्मक है।',
  'cash.accounts': '{n} खाते',
  'cash.oneAccount': '1 खाता',
  'cash.noSparkline': 'Tally केवल आज का शेष भेजता है, इसलिए अभी नकद का इतिहास नहीं है।',

  'ageing.overdue': '{amount} बकाया',
  'ageing.nothingOverdue': 'कुछ भी बकाया नहीं',
  'ageing.topDebtors': 'सबसे ज़्यादा किससे लेना है',
  'ageing.topCreditors': 'सबसे ज़्यादा किसे देना है',
  'ageing.empty.receivable': 'किसी से कुछ लेना बाकी नहीं। सभी बिल चुक गए।',
  'ageing.empty.payable': 'किसी को कुछ देना बाकी नहीं। सभी बिल चुक गए।',
  'ageing.everyoneElse': 'बाकी सब',
  'ageing.bills': '{n} बिल',
  'ageing.oneBill': '1 बिल',
  'ageing.total': 'कुल',

  'ageing.credit.receivable':
    'आपके ग्राहकों ने बकाया से ज़्यादा अग्रिम भुगतान किया है: कुल {amount} है। नीचे बकेट में विवरण देखें।',
  'ageing.credit.payable':
    'आपने अपने आपूर्तिकर्ताओं को देय राशि से ज़्यादा अग्रिम दिया है: कुल {amount} है। नीचे बकेट में विवरण देखें।',
  'ageing.netZero': 'बकाया और अग्रिम राशि बिलकुल बराबर हैं।',
  'ageing.mixed': 'एक बकेट में अग्रिम राशि है, इसलिए हिस्सेदारी चार्ट भ्रामक होगा। नीचे दिए बार सटीक हैं।',

  'bucket.not_due': 'बाकी नहीं',
  'bucket.0_30': '1–30 दिन',
  'bucket.31_60': '31–60 दिन',
  'bucket.61_90': '61–90 दिन',
  'bucket.91_180': '91–180 दिन',
  'bucket.180_plus': '180+ दिन',

  'bucket.short.not_due': 'चालू',
  'bucket.short.0_30': '1–30द',
  'bucket.short.31_60': '31–60द',
  'bucket.short.61_90': '61–90द',
  'bucket.short.91_180': '91–180द',
  'bucket.short.180_plus': '180द+',

  'profit.vsLast': 'पिछले महीने {amount} की तुलना में',
  'profit.empty': 'इस महीने अभी कोई बिक्री या ख़र्च दर्ज नहीं हुआ।',
  'profit.lastMonth': 'पिछला',
  'profit.thisMonth': 'यह',

  'trend.subtitle': 'पिछले {n} महीने',
  'trend.peak': 'सर्वाधिक {amount}',
  'trend.empty': 'अभी पर्याप्त इतिहास नहीं है। महीने पूरे होने पर यह भरता जाएगा।',
  'trend.none': 'अभी कोई बिक्री दर्ज नहीं हुई।',

  'stock.empty': 'Tally में कोई स्टॉक समूह नहीं। सेवा व्यवसायों में यह सामान्य है।',

  'sheet.empty': 'अभी कोई बैलेंस शीट समूह नहीं।',
  'sheet.hint': 'आपके पास क्या है, और आप पर क्या बाकी है। किसी समूह को खोलने के लिए दबाएँ।',
  'sheet.assets': 'आपके पास क्या है',
  'sheet.liabilities': 'आप पर क्या बाकी है',
  'sheet.nil': 'शून्य शेष: {names}',

  'company.switch': 'कंपनी',

  'error.card': 'पिछले सिंक से यह कार्ड पढ़ा नहीं जा सका।',
  'error.cards': 'इस दृश्य में कुछ आँकड़े नहीं हैं। अगला सिंक आमतौर पर उन्हें भर देता है।',
  'error.generic': 'आपका डेटा पढ़ा नहीं जा सका।',
  'error.unreachable': 'Tally Bridge जवाब नहीं दे रहा। ऐप को दोबारा शुरू करने से यह ठीक हो जाता है।',
  'action.retry': 'फिर कोशिश करें',

  'locked.body': 'आपका डेटा लॉक है। आँकड़े देखने के लिए अपना पासफ़्रेज़ डालें।',
  'locked.action': 'अनलॉक करें',
  'unlock.title': 'अपना पासफ़्रेज़ डालें',
  'unlock.sub': 'यह इस कंप्यूटर पर आपके आँकड़े खोलता है। इसमें कुछ सेकंड लगते हैं।',
  'unlock.placeholder': 'पासफ़्रेज़',
  'unlock.working': 'खोल रहे हैं…',
  'unlock.wrong': 'यह पासफ़्रेज़ काम नहीं आया। कृपया फिर से आज़माएँ।',
  'unlock.cancel': 'रद्द करें',

  'empty.all': 'अभी कोई डेटा नहीं। Tally के एक बार खुलने और सिंक होते ही आपके आँकड़े यहाँ दिखेंगे।',
};

const DICTS: Record<Locale, Partial<Record<StringKey, string>>> = { en, hi };

export function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (LOCALES as readonly string[]).includes(value);
}

/**
 * Look up a string and substitute `{placeholders}`.
 *
 * Falls back to English per KEY, not per dictionary: a locale that translates 90% of the app
 * shows 90% Hindi and 10% English, which is usable. Falling back per dictionary would make one
 * missing key revert the whole screen.
 */
export function t(locale: Locale, key: StringKey, params: Record<string, string | number> = {}): string {
  const raw = DICTS[locale]?.[key] ?? en[key];
  return raw.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const v = params[name];
    return v === undefined ? whole : String(v);
  });
}

/** A translator bound to one locale — what the card renderers actually take. */
export type T = (key: StringKey, params?: Record<string, string | number>) => string;

export function translator(locale: Locale): T {
  return (key, params) => t(locale, key, params);
}

const MONTHS: Record<Locale, readonly string[]> = {
  en: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
  hi: ['जन', 'फ़र', 'मार्च', 'अप्रैल', 'मई', 'जून', 'जुल', 'अग', 'सित', 'अक्तू', 'नव', 'दिस'],
};

/**
 * `YYYY-MM` -> a short month name. Falls back to the input, never to a wrong month.
 *
 * String slicing, not `new Date(period)`: `new Date('2026-07')` is parsed as UTC midnight and
 * then rendered in the machine's LOCAL timezone, so every user west of Greenwich sees the
 * previous month on every label. A financial period is a label, not an instant.
 */
export function monthLabel(locale: Locale, period: string): string {
  const m = /^(\d{4})-(\d{2})/.exec(period);
  if (!m) return period;
  return MONTHS[locale][Number(m[2]) - 1] ?? period;
}

/** `YYYY-MM-DD` -> "16 Jul 2026". Same string-slicing reasoning as `monthLabel`. */
export function dateLabel(locale: Locale, iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return iso;
  const month = MONTHS[locale][Number(m[2]) - 1] ?? m[2]!;
  return `${Number(m[3])} ${month} ${m[1]}`;
}

/**
 * The relative-time words, per locale. `{n}` is substituted.
 *
 * `Record<Locale, …>` and not a partial: adding a locale to `LOCALES` FAILS THE BUILD until it
 * appears here. An empty object is a perfectly good answer (see `en`) — the point is that the
 * decision is made deliberately rather than by falling off the end of an `if`.
 */
const RELATIVE: Record<Locale, Partial<Record<'now' | 'min' | 'hour' | 'day', string>>> = {
  // Empty ON PURPOSE. English comes from the viewmodel's `formatRelativeTime`, which is the
  // shared formatter the tray and every other surface already use; re-typing the words here
  // would be a second copy to drift.
  en: {},
  hi: { now: 'अभी', min: '{n} मिनट पहले', hour: '{n} घंटे पहले', day: '{n} दिन पहले' },
};

/**
 * "2 min ago" in the caller's locale.
 *
 * THIS WAS `if (locale === 'en') … else <Hindi>`, AND THAT WAS A BUG WAITING FOR A COMMIT.
 * It gave the right answer for both locales that existed, and the moment a third was added —
 * Gujarati is next, and someone tried exactly that while this file was being written — every
 * Gujarati user would have been shown HINDI timestamps. Not English, which is the documented
 * fallback and would merely be untranslated: another Indian language, close enough to look
 * deliberate and wrong enough to be insulting. No test would have failed, because the test
 * suite only knew about the two locales that worked.
 *
 * So the fallback is now explicit and it is the same one the rest of this file uses: a locale
 * with no words of its own gets ENGLISH, never a neighbour's. `relativeTime` cannot serve a
 * locale a language it did not ask for, because there is no branch that can reach one.
 */
export function relativeTime(locale: Locale, then: number, now: number): string {
  const words = RELATIVE[locale] as Partial<Record<'now' | 'min' | 'hour' | 'day', string>> | undefined;
  // No dictionary, or an untranslated one: fall back to the shared English formatter. Tested by
  // handing this an unknown locale, which is what the next language looks like on day one.
  if (!words?.now) return formatRelativeTime(then, now);

  const fill = (template: string, n: number): string => template.replace('{n}', String(n));

  // The thresholds mirror `formatRelativeTime` exactly — minute, hour, day, same boundaries —
  // so two locales never disagree about whether a sync was "just now".
  const s = Math.max(0, Math.floor((now - then) / 1000));
  if (s < 60) return words.now;
  const m = Math.floor(s / 60);
  if (m < 60 && words.min) return fill(words.min, m);
  const h = Math.floor(m / 60);
  if (h < 24 && words.hour) return fill(words.hour, h);
  if (words.day) return fill(words.day, Math.floor(h / 24));
  return formatRelativeTime(then, now);
}
