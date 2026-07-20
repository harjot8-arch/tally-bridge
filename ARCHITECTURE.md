# Tally Bridge — architecture

Read this before adding a surface (mobile, web, native). It records the decisions that are
expensive to reverse, and why.

## The shape

```
Tally (localhost:9000, XML)
   |  packages/tally     extract, aggregate at the edge
   v
packages/sync            AlterID gate -> hash gate -> outbox (SQLite)
   |  packages/crypto    canonical JSON -> gzip -> Padme -> XChaCha20-Poly1305
   |                     CEK sealed to idPK  <-- the Bridge cannot read this
   v
apps/server              verify signature, freshness, quota -> store opaque blob
   |                     (Next.js on the CLIENT'S Vercel + Neon)
   v
any surface              fetch ciphertext -> unlock with passphrase -> packages/viewmodel
```

## The one property everything protects

**The server never holds a key that reads the data.** The Bridge is given only a public key and
uses sealed boxes, so it can write and never read. A Neon dump, a leaked `DATABASE_URL`, RCE on a
Vercel function, or a subpoena all yield ciphertext.

Note precisely what that sentence is and is not. It is a **confidentiality** claim, and it holds.
It is **not** an authenticity claim, and the difference is not academic — see below.

### Confidentiality is not authenticity

`crypto_box_seal` takes the identity PUBLIC key and nothing else, and onboarding sets that public
key as an env var **on the server** because the Bridge needs it to encrypt. So the server holds
every input needed to **fabricate** an envelope: a fresh CEK sealed to `idPK`, an AAD of its
choosing, a ciphertext over a plaintext it invented, and a matching `contentHash`. Sealed boxes
would let it do this undetectably. *"The server cannot read your numbers, but it can make them
up"* is not a threat model this product can be sold under.

The mitigation is that the Bridge **signs every envelope** with its Ed25519 device key
(`packages/crypto/src/envelope.ts`; `sig` is required, and `openSection` refuses an envelope it
cannot verify). That much is implemented and wired into the upload path.

A signature is only worth the key distribution behind it, and the server also knows the device
public key — it verifies RFC 9421 upload signatures with it. If a reader asks the server "what is
the key for `dev_001`?", a malicious server names its own key and the forgery verifies. So the
reader must learn the device key over a path the server cannot rewrite. Both such paths are now
implemented, and **they are not alternatives — the second is what makes the first mean anything**:

1. **Roster carried inside the wrapped identity.** `IdentityBundle` (`packages/core`) is the
   plaintext sealed inside a `WrappedKey`, and it carries the roster. The server stores that blob
   and cannot read or alter it — it lacks the passphrase, and tampering fails the Poly1305 tag.
   `openIdentity()` is the only way to obtain a roster. Note that `WrappedKey` itself deliberately
   has **no** roster field: a field there would be outside the ciphertext, i.e. a value the server
   picks, and `blob.roster` passed to `openSection` by a dashboard developer in a hurry would be a
   silent total defeat. There is no field to misuse.
2. **Pinned at pairing**, SSH/Signal style, via `deviceFingerprint()` —
   `admitPairedDevice()` in the Bridge's `onboarding/pairing.ts`. This is **required**, because
   path 1 answers "how does the roster reach the reader" and says nothing about how the right key
   got *into* it. Device 2 registers its public key with the server; if device 1 fetched that key
   from the server to add it to the roster, the owner's passphrase would seal the attacker's key
   into the bundle and every layer downstream would work perfectly, authenticating the attacker.
   So a human confirms the fingerprint off the new machine's screen, out of band, before the
   re-wrap. Device 1 needs no ceremony — it holds its own key, with no server in the path.

Adding or revoking a device therefore requires the **passphrase**, and that is arithmetic rather
than policy: writing a new passphrase wrap means deriving the KEK, and nobody holds the KEK
afterwards. Pairing already requires an authenticated session, so the owner is at a keyboard.

TOFU is **not** an option: the reader's first fetch comes from the server, so trust-on-first-use is
trust on the attacker's first use.

**What is NOT closed: rollback.** AEAD gives integrity, not freshness. The server cannot forge a
bundle; it does not need to, because it chooses *which* stored bundle to serve, and an old one is
perfectly authentic — including one whose roster still lists a revoked device. The defence is a
monotonic `roster.version` plus a reader that remembers the highest it has seen, in storage the
server cannot reach. That closes it for the desktop app after first unlock. It does **not** close
it for a **fresh reader with no memory**: first unlock on a new phone accepts whatever version it
is handed. That residual is real, is documented at `RosterMemory` in `packages/crypto/src/trust.ts`,
and has a test asserting it (`THE RESIDUAL, STATED HONESTLY`) so nobody "fixes" it by accident. It
is not closable by cryptography inside a blob the server chooses — freshness needs memory or an
out-of-band channel, and a fresh reader has neither. The mitigation is human: show the roster and
its fingerprints at first unlock. Exploiting it also requires the attacker to already hold the
secret key of a device that was once legitimately rostered.

Note the boundary this all lives inside: it holds against an adversary with **database-level**
access (a Neon dump, a leaked `DATABASE_URL`, a subpoena) — the adversary this product's
confidentiality claim is actually sold against, and the one who can roll a blob back. It does not
hold against an adversary who can **replace the served frontend**, but neither does anything else
client-side, including the passphrase prompt itself: if the attacker writes the JavaScript, they
take the passphrase directly and the roster is moot.

What this does **not** protect: malware running as the Windows user on the Tally PC. Tally's data
files are plaintext on that disk and port 9000 has no auth — an attacker there reads Tally
directly and ignores us. **Marketing must never imply otherwise.**

Consequence that de-risks everything else: **the server is a derivative cache; Tally is the source
of truth.** Total key loss is a re-sync, not data loss.

## Adding a mobile surface

The mobile decision (web view vs React Native vs fully native) is deliberately still open. These
are the seams that keep it open.

### What you reuse as-is

- **`packages/core`** — the normalized model, canonical serializer, envelope/AAD types.
- **`packages/crypto`** — the whole security boundary.
- **`packages/viewmodel`** — every card. Pure TypeScript; its tsconfig has **no `DOM` lib**, so
  the build fails if anyone reaches for `document` or `window`. That is enforcement, not style.
- **`packages/protocol`** — request signing, if the surface uploads (it probably doesn't; only
  the Bridge writes).

### Web view or React Native

Both consume `@tally-bridge/viewmodel` verbatim and supply only rendering. Nothing in the data
path changes. This is the cheap path.

### Fully native (Swift / Kotlin)

Also viable, because the crypto was chosen with this in mind:

- **libsodium has native bindings on every platform.** Argon2id, XChaCha20-Poly1305 and
  `crypto_box_seal` are libsodium proper, not wasm-only. Had this used WebCrypto AES-GCM, a
  native client would need a *different* implementation of the security boundary — a second
  chance to get it wrong.
- **HKDF** comes from WebCrypto here, but CryptoKit and Android both ship HKDF. Match
  `KDF_INFO` labels exactly (`tally/v1/kek`, etc.) or nothing unwraps.
- **gzip** is universal.
- The wire format is documented by `packages/core/src/envelope.ts` and implemented in
  `packages/crypto/src/envelope.ts`. Port `packages/viewmodel` mechanically — it is ~200 lines
  with nothing JavaScript-specific in it.

Pair a new device with the 6-digit code flow from an authenticated session; never reuse
`BOOTSTRAP_SECRET`, which is one-shot and self-disables.

### Rules that keep the seam open

1. **Nothing in `packages/viewmodel` may return markup, a component, a colour, or a pixel
   value.** It returns numbers, strings, and semantic tones (`good | warn | bad | neutral`).
   What red means is the renderer's problem.
2. **Never re-derive a headline number in a renderer.** The card layer owns the arithmetic so
   every surface agrees. Two surfaces computing "total receivables" independently is two
   surfaces that will eventually disagree, in front of a customer.
3. **Never format money by hand.** `formatMoney` does Indian lakh/crore grouping and is
   hand-rolled precisely because `Intl` depends on the ICU data the runtime was built with —
   React Native ships without full ICU and would silently fall back to `en-US` grouping.

## Conventions you must not break

- **Dr negative, Cr positive**, fixed at the extraction boundary (`packages/tally/src/tdl.ts`,
  `expr.amount`). Profit falls out as a plain sum because of it. Assets therefore arrive negative
  and the card layer flips them for display — see `cashBankCard`.
  **The stock case is resolved at runtime, not assumed.** `expr.amount` applies `$$IsDebit`, and
  a `StockGroup`'s `$ClosingValue` is a computed inventory valuation rather than a ledger's Dr/Cr
  balance — so whether `$$IsDebit` is even true there cannot be known from a desk, and if it is
  false in the field the extraction hands `stockCard` a positive, the card flips it, and **every
  stock figure in the product renders negative**. The probe therefore measures it per install
  (`packages/tally/src/stocksign.ts`): the Σ of the stock idiom's own output is sign-compared
  against the `Stock-in-Hand` group's closing balance, which arrives through the group idiom the
  sign canary has already verified. Same sign → the flip is right; opposite → the extraction
  negates (`stockValueSign: 'positive_magnitude'` in quirks) — a measured correction, unlike the
  group-canary case where refusal is the only option because sign collapse has no global fix.
  When the book cannot adjudicate (no inventory, or no material Stock-in-Hand to cross-check —
  a non-integrated book), the verdict is `'unknown'`, the documented idiom is assumed
  UNCORRECTED, and the quirks cache ages out daily instead of monthly so the verdict lands as
  soon as the book can supply one. Whether `$$IsDebit` actually fires on a real Tally's
  StockGroup remains unmeasured — the mechanism decides it per install so shipping does not
  wait on the answer.
- **A component's tests prove it WORKS. They never prove it RUNS. Only a caller does.**
  This has bitten three times, and every time the whole suite stayed green: `openSection` had no
  production caller; `balanceSheetTree` had no field on `CompanyCards` to travel in; and
  `mountDashboard` had **thirty test call sites and zero in `src`** while the real entry point
  rendered `renderInto(content, [])` — a literal empty array — so the entire dashboard was
  unreachable by any user. When you add a component, the reviewable question is not "is it
  tested" but "what in `src` calls it, and is there a test that fails if that call is deleted".
- **Paths come from `packages/protocol/src/routes.ts`, never from a literal.** The request path
  is inside the Ed25519 signature, so a path written twice is a silent 401 on the owner's own
  deployment, at setup, with a correct signature over a correct body.
- **HKDF labels come from `KDF_INFO`, never restated.** Two copies of a label is a total
  authentication failure the day one is edited. `apps/server` imports `KDF_INFO.auth`; it does
  not declare its own.
- **Money never touches a float on the extraction path.** `parseAmountToPaise` parses Tally's
  decimal strings straight to integer paise. `1.005 * 100` is `100.49999999999999`, so
  scale-then-round silently loses a paisa.
- **Company GUID is the identity, never the name.** Names get edited and are duplicated across
  financial years.
- **Advance section hashes on ACK, never on send.** A crash in between otherwise loses a section
  permanently and silently. **But the hash is not the only gate, and believing it was is how the
  bug below got written:** the AlterID **watermark** is advanced at *enqueue* time and
  `decideGate` consults it *first*. So dropping an outbox row (4xx, or a spent retry budget)
  while its watermark stands means `extract()` is never called for that company again and the
  section re-enqueues on **no** cycle — a frozen number under a green checkmark. Whenever a row
  is abandoned, `SyncStore.invalidateWatermark()` must be called too; `drainOutbox` does this.
  The cost is a full re-pull while the failure lasts, which is the right trade: noisy and
  self-healing beats quietly stale.
- **Totals come from `totals[]`, never from the truncated `rows[]` matrix.**

## Where the risk actually is

- **The ageing query.** Resolved at runtime per install by `probeCapabilities()`
  (`packages/tally/src/flavour.ts`) rather than hardcoded, because sources conflict and a wrong
  method name returns a **silently empty column**, not an error. `scripts/spike-a-ageing.ts`
  answers it sooner against a real Tally, but shipping does not wait on it.
- **Vercel OAuth scope.** Unknown whether an OAuth token can `POST /v11/projects`. If it cannot,
  PAT-paste is not a fallback — it is the design. Spike before writing onboarding.
- **Recovery.** The likeliest product failure is not a broken cipher; it is an owner who set a
  passphrase once and needs the dashboard eight months later. Three paths exist; see the plan.
  **The BIP39 checksum is a typo filter, not a proof of correctness.** 24 words carry only an
  **8-bit** checksum, so ~1 in 256 corruptions pass it and yield a wrong key — measured over
  4,000 mnemonics at 0.47% of single-word typos and 0.40% of word swaps, both on top of the 0.39%
  the maths predicts (the gap between the two is noise, not signal). A caller
  that reports "valid key" on a checksum pass is wrong about ~1 user in 250. The authority is the
  **AEAD tag** on the unwrap (128-bit), which is why `attemptRecovery()` in
  `apps/bridge/src/onboarding/recovery.ts` performs the unwrap and is the only supported way to
  turn words or a QR into an identity. Reaching past it to `parseRecovery*` for a raw key
  reintroduces the bug.
- **Vercel Hobby is non-commercial.** Clients need Pro (~$20/mo) plus Neon. A sales
  conversation, not an engineering one — but it surfaces as an angry call after suspension.
- **The prebuilt deploy signal is an UNDOCUMENTED query parameter**, `POST /v13/deployments?prebuilt=1`.
  Established from `vercel/vercel` source (`packages/client/src/utils/query-string.ts`): it is not
  in the request body, not a header, not `builds.json`, not `projectSettings`. Vercel's API is
  closed, so whether it is *required* or merely *sufficient* cannot be proven from anything
  readable. We send exactly what the official CLI sends and claim nothing more. One real token
  settles it.
- **Nothing about layout is tested, because the tests have no layout.** `test/dashboard.dom.ts`
  is a fake DOM: it can prove text lands in the right node and is structurally incapable of
  seeing that a card is off-screen, overflowing, or sitting in a void. Two real defects lived
  behind a green suite — a grid hole that ate 40% of a 1366×768 screen, and a dead column at
  1024×768 — and both were obvious in the first screenshot ever taken.
  `apps/bridge/scripts/visual-harness.mjs` renders the real renderer in a real Electron window
  against a stubbed `window.bridge` and writes PNGs; it needs no `better-sqlite3` rebuild. **Look
  at the output after any change to `styles.css` or `paintContent`.** Its fixtures are built by
  the real card layer from real wire rows, deliberately: the first draft hand-wrote card objects,
  invented fields, and killed the page — nothing typechecks a CJS stub.
