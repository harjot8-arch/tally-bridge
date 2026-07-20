# `@tally-bridge/web` — the data layer for your dashboard UI

This package is **the backend for the web dashboard**. It does the cryptography, the login, the
fetching, and the decryption, and hands you finished numbers. **You write the HTML, CSS, and
JavaScript** that draws them; you never touch a cipher, a key, or a hash.

There is **no UI in this package on purpose.** The one thing you cannot safely write yourself is
the crypto, so that is the one thing this package is. Everything below is the contract between
your UI and it.

> If you are a UI developer and not a cryptographer: good. You are the intended reader, and you
> do not need to understand a word about Argon2id or sealed boxes to use this correctly. Follow
> the MUST / MUST NOT list at the bottom and you cannot break the security properties.

---

## The whole flow, in one screen

```js
// Served at your site root by the deploy bundle. A bare specifier like '@tally-bridge/web'
// does NOT resolve in a browser without a bundler or import map — use the real path:
import { unlock, loadDashboard, lockSession, localStorageKV, UnlockError } from '/tally-data.js';

const deps = { fetch: window.fetch.bind(window), storage: localStorageKV(window.localStorage) };

// 1. The owner types their Tally ID and passphrase into YOUR form, then:
let session;
try {
  session = await unlock(
    { ...deps, onStage: (s) => showSpinnerLabel(s) },  // s tells you which slow step is running
    tenantId,        // the "Tally ID" — from your input
    passphrase,      // from your password input
  );
} catch (e) {
  if (e instanceof UnlockError) showOnePlainSentence(e.message);   // e.message is safe to display
  return;
}

// 2. Load and decrypt the figures.
const result = await loadDashboard(deps, session);

if (result.state === 'ready') {
  for (const company of result.companies) drawCompany(company);   // company.cashBank, .receivables, …
  if (result.incomplete) showBanner('Some figures could not be shown.');
  if (result.staleRefused > 0) showBanner('The server offered out-of-date figures; they were ignored.');
} else if (result.state === 'empty') {
  showBanner('No figures have synced yet. Open the desktop app.');
} else {
  showOnePlainSentence(result.message);
}

// 3. When the owner logs out or leaves:
await lockSession(session);   // zeroes the decryption key in memory
```

That is the entire integration. The rest of this document is detail on each piece.

---

## `unlock(deps, tenantId, passphrase) → Promise<UnlockedSession>`

Turns a passphrase into a session. **This is slow — 1 to 8 seconds** — because it runs Argon2id
twice (once to prove knowledge of the passphrase to the server, once to unwrap the identity key).
That is deliberate: it is what makes a weak passphrase expensive to attack. Your UI **must** show
a spinner, and should use `onStage` to say what is happening so it never looks frozen.

`deps`:

| field | what it is |
| --- | --- |
| `fetch` | `window.fetch.bind(window)`. Injected so it can be faked in tests. |
| `storage` | `localStorageKV(window.localStorage)` normally; `memoryKV()` if storage is unavailable. |
| `onStage` | optional `(stage) => void`. Stages in order: `contacting`, `deriving`, `signing-in`, `fetching-keys`, `opening`, `verifying`. `deriving` and `opening` are the multi-second ones — label them. |
| `deriveAuthToken`, `openPassIdentity` | optional worker seams. See "Keeping the page responsive". |

**On success** you get an `UnlockedSession`. The only fields your UI reads:

| field | use |
| --- | --- |
| `firstUse` | `true` the first time this browser has ever unlocked this account. Consider showing the device list so the owner can confirm it — see the security note on rollback. |
| `persistentMemory` | `false` when the browser has no durable storage. Rollback protection then lasts only this session; **tell the owner** (e.g. private browsing warning). |

The other fields (`identitySecretKey`, `roster`, …) are for `loadDashboard` only. **Do not read,
log, copy, or store them.**

**On failure** it throws an `UnlockError` with a `.failure` code and a `.message` you can show
verbatim (it is one plain sentence, never a stack or a status code):

| `.failure` | meaning | what your UI should do |
| --- | --- | --- |
| `credentials` | wrong Tally ID **or** passphrase (indistinguishable, on purpose) | "That Tally ID and passphrase were not accepted." Let them retry. |
| `rate-limited` | too many attempts | Ask them to wait. |
| `not-set-up` | the deployment has no passphrase-locked key yet | "Finish setup in the desktop app first." |
| `rollback` | **the server offered older data than this browser has already seen** | Show `.message` prominently. Do **not** treat as a typo. This may be an attack — see below. |
| `damaged-memory` | this browser's saved safety record is unreadable | Offer to clear site data (which resets it). |
| `no-storage` | the safety record could not be saved | The browser is blocking storage; unlock cannot proceed safely. |
| `network` / `server` | the server could not be reached / refused a step | Retry later. |

---

## `loadDashboard(deps, session) → Promise<DashboardResult>`

Fetches every sealed snapshot, verifies and decrypts each one, and assembles cards. `deps` is
the same `{ fetch, storage }` (no `onStage`; this is fast).

Returns one of:

- `{ state: 'empty' }` — unlocked, but nothing has synced yet.
- `{ state: 'error', message }` — nothing could be read; show `message`.
- `{ state: 'ready', companies, incomplete, staleRefused }`:
  - `companies` — an array of `CompanyCards` (below).
  - `incomplete: true` — at least one figure was dropped (couldn't decrypt, or failed a check).
    Show a quiet banner; do **not** present a partial screen as complete.
  - `staleRefused: N` — N snapshots were **authentic but older** than this browser had already
    seen, and were refused. `N > 0` means the server tried to show you stale data — worth a
    visible note.

### `CompanyCards` — what you draw

Every money value is a **finished display string** — `₹1,23,456`, correctly grouped in the Indian
lakh/crore style. You do no formatting and no math.

```ts
interface CompanyCards {
  companyGuid: string;
  name: string;            // the company name — safe to show as text (use textContent, see MUST NOT)
  asOf: IsoDate;           // 'YYYY-MM-DD', the date the figures are from
  cashBank?:    CashBankCard;   // total + per-account balances
  receivables?: AgeingCard;     // who owes the owner, by age bucket + top parties
  payables?:    AgeingCard;     // who the owner owes
  profit?:      ProfitCard;     // this month vs last, with a direction and delta
  stock?:       StockCard;      // inventory value by group
  salesTrend?:  TrendCard;      // last several months, chart-ready
  balanceSheet?: TreeNode[];    // the group tree — see the desktop dashboard for the two-sided layout
}
```

Any card can be **absent** (`undefined`) when its section hasn't synced. That is a normal state,
not an error — draw the ones that are present and leave a gap for the rest.

The exact shape of each card type (`CashBankCard`, `AgeingCard`, …) is defined and documented in
**`packages/viewmodel/src/cards.ts`**. Each carries a `.display` string for showing, a `.compact`
string (`₹1.42Cr`) for tight spaces, a signed `.raw` number **for charts only**, and a `tone`
(`good` / `warn` / `bad` / `neutral`) you map to your own colours. The desktop dashboard
(`apps/bridge/src/renderer/cards.ts`) is a complete worked example of drawing every one of them —
read it for layout ideas, but note it is built for a wide screen; **your phone layout is a
different design problem**, not a port.

---

## Keeping the page responsive (the worker)

Argon2id will freeze the main thread for seconds if you run it there, and a frozen page during
unlock is the worst possible impression. This package ships a worker for it.

The simplest correct setup: run `src/worker-entry.ts` as a Web Worker and pass its seams into
`unlock`:

```js
import { workerUnlockSeams } from '/tally-data.js';
const worker = new Worker('/tally-worker.js', { type: 'module' });
const seams = workerUnlockSeams(worker);
await unlock({ ...deps, ...seams, onStage }, tenantId, passphrase);
```

If you skip this, unlock still works — it just blocks the thread. The **rollback safety check is
NOT in the worker**; it always runs in the main flow, so wiring the worker in or out can never
weaken security.

---

## MUST / MUST NOT — the security contract

Follow these and you cannot break the guarantees. They exist because the whole product promise is
"the server that stores your figures cannot read them," and a careless UI is the one place that
promise can leak.

**MUST**

- **Show `UnlockError.message` and `result.message` verbatim.** They are written to be shown.
- **Treat `failure: 'rollback'` as serious.** It means the server served older data than the
  browser has already seen — for example, a device list from before a phone was revoked. Show the
  warning; do not let the owner click past it into a dashboard.
- **Surface `session.persistentMemory === false`** as reduced protection (typically private/
  incognito browsing).
- **Consider showing the device list on `session.firstUse`.** The first unlock on a new browser
  has no memory to catch a rolled-back device list, so a human glance is the backstop.
- **Serve the whole app over HTTPS with a strict Content-Security-Policy, no inline scripts, no
  third-party origins.** NOTE, corrected: the Vercel deployment does **not** set these headers
  today — `config.json` carries no `headers` block, and the only CSP in this repo is the Electron
  window's. Treat this as a requirement you must not violate (no CDN scripts, no remote fonts),
  not as a guarantee already enforced for you. Adding the headers to the deployment is tracked.

**MUST NOT**

- **Never log, store, send, or copy the `UnlockedSession`** or any field inside it. The
  `identitySecretKey` is the key that decrypts everything; it lives in memory for the session and
  nowhere else. Do not put it in `localStorage`, a cookie, a URL, analytics, or a console log.
- **Never render a company name or any decrypted string with `innerHTML`.** Use `textContent` (or
  your framework's default text binding). A party name can legitimately contain `<`, `&`, and
  `>` — e.g. `A & B Traders <Mumbai>` — and `innerHTML` would execute it. Every string this
  package returns is untrusted text.
- **Never build your own crypto, your own login, or your own fetch of the snapshots.** If you find
  yourself importing from `@tally-bridge/crypto` in your UI, stop — that is this package's job, and
  a second implementation of the trust chain is how it gets got wrong.
- **Never pass anything from the server into `loadDashboard` as trusted.** You don't have to think
  about this — `loadDashboard` already does — but do not "help" by pre-filtering snapshots or
  reading `envelope.aad` yourself.

---

## What is deliberately not here

- **The UI.** By design. You are writing it.
- **A framework.** Plain functions returning plain data. Use React, Vue, Svelte, or hand-written
  DOM — the data layer does not care.
- **A router or a build step for your UI.** When your UI is ready, it drops into the deploy
  bundle's static output (`scripts/deploy-bundle/build.ts`); ask the maintainer to wire it in.

## Running the tests

```
npm test            # in apps/web — the real crypto runs, so it is slow (~real Argon2id)
```

The suite (`test/*.test.ts`) drives the real chain end to end, including the forgery test that
proves a malicious server signing its own fabricated envelope never becomes a number on a card
(`read.test.ts`). Nothing in it is mocked crypto; that is why it is trustworthy and why it is slow.
