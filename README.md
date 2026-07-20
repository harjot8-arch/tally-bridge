# Tally Bridge

A live, card-based dashboard of a small business's financial position — cash, debtors, ageing,
profit — read from TallyPrime / Tally.ERP 9 and viewable from anywhere, **without the server ever
being able to read the numbers**.

```
Tally (localhost:9000, XML)
   │  extract, aggregate at the edge
   ▼
Bridge (Electron, on the client's PC)
   │  canonical JSON → gzip → Padmé → XChaCha20-Poly1305
   │  content key sealed to a PUBLIC key ── the Bridge cannot read what it sends
   ▼
Server (Next.js on the CLIENT'S OWN Vercel + Neon)   ── stores opaque blobs
   ▼
Dashboard (desktop app, and a web app for mobile)    ── unlock with a passphrase
```

## Quick start

```bash
npm install
npm run build
npm test          # 332+ tests
```

Requires Node 22+. Tests run the TypeScript sources directly via `--experimental-strip-types`;
no build step needed to test.

## What you need to run against real Tally

Two things cannot be answered from code. Both need ten minutes and real credentials.

### Spike A — the ageing query

```bash
node --experimental-strip-types scripts/spike-a-ageing.ts
```

Run this on a Windows PC with Tally open and **a company that has unpaid invoices** (against a
company with no debtors, every variant returns zero rows and the spike proves nothing — it will
tell you so rather than pretend).

It redacts party names and amounts by default, so the output is safe to share. Pass
`--show-data` only if you understand you are printing real financial data.

This is a *diagnostic*, not a blocker: `probeCapabilities()` resolves the same question at
runtime on every install. The spike just answers it sooner.

### Spike B — Vercel OAuth scope

Unknown whether an OAuth token can `POST /v11/projects`. The published scope list has no
explicit "create project" scope, and OAuth tokens have historically been scoped to *granted*
projects rather than the account. **If OAuth cannot create projects, the PAT paste is not a
fallback — it is the design.** One day of spiking; it forks the onboarding UX.

## Packages

| Package | What it is |
|---|---|
| `packages/core` | Normalized model, canonical serializer, envelope/AAD types |
| `packages/crypto` | The security boundary: Argon2id/HKDF, XChaCha20-Poly1305, sealed boxes, envelope signing + the trust roster (`trust.ts`), Padmé, gzip |
| `packages/tally` | Transport (encoding sniff, mutex), TDL catalog, runtime capability probing, ageing |
| `packages/sync` | AlterID gate, hash gate, outbox |
| `packages/protocol` | Ed25519 request signing (RFC 9421), quotas |
| `packages/viewmodel` | **The card layer — pure TS, no DOM.** Shared by desktop and the web dashboard |
| `apps/bridge` | Electron: keystore, scheduler, onboarding, recovery, renderer |
| `apps/server` | Next.js ingest + read API on Neon |

## For the web dashboard

The mobile surface is a **web app**. It consumes `@tally-bridge/viewmodel` directly, so its
numbers agree with the desktop's by construction rather than by discipline.

Three rules keep that true:

1. **Never re-derive a headline number in the UI.** The card layer owns the arithmetic. Two
   surfaces computing "total receivables" independently is two surfaces that will eventually
   disagree, in front of a customer.
2. **Never format money by hand.** Use `formatMoney` — it does Indian lakh/crore grouping
   (`₹1,23,456`, not `₹123,456`), and it is hand-rolled because `Intl` depends on the ICU data
   the runtime was *built* with.
3. **The viewmodel returns tones, not colours** (`good | warn | bad | neutral`). What red means
   is the UI's decision.

The dashboard fetches ciphertext and decrypts **in the browser** with a passphrase-derived key.
The server holds no key that opens it.

## What this protects, and what it does not

**Protects the confidentiality of your numbers against:** Vercel/Neon staff, a subpoena, a Neon
dump, a leaked `DATABASE_URL`, RCE on a Vercel function, and the vendor being compelled or
hacked. All of them yield ciphertext.

**Does NOT protect against:** malware running as the Windows user on the Tally PC. Tally's data
files are plaintext on that disk and port 9000 has no auth — an attacker there reads Tally
directly and ignores us entirely. **Marketing must never imply otherwise.** That promise becomes
a liability the first time someone tests it.

**Reading and writing are different promises.** Everything above is about *reading*. Sealed boxes
give confidentiality, **not authenticity**: the server is handed the identity public key so the
Bridge can encrypt, and that is all anyone needs to *fabricate* a well-formed envelope. So a
hostile server cannot read your figures but could, on the sealed-box design alone, invent them.
The Bridge therefore signs every envelope with its Ed25519 device key and readers verify —
implemented, and wired into the upload path.

That guarantee is **not complete yet**, and this README will not pretend otherwise. The server
also knows the device public key (it checks upload signatures with it), so a reader that *asks the
server* for that key learns whatever the server wants and verifies a forgery. The reader needs the
key over a path the server cannot rewrite — carried inside the passphrase-wrapped identity, or
pinned by fingerprint at pairing — and **neither is implemented yet** (see
`packages/crypto/src/trust.ts` and the authenticity section of `ARCHITECTURE.md`). Until one
lands, treat "the numbers are provably yours" as **in progress**; "the server cannot read them" is
the claim that holds today.

The consequence that de-risks everything: **the server is a derivative cache; Tally is the
source of truth.** Total key loss is a re-sync, not data loss — which is why the recovery flow
can tell the truth instead of manufacturing terror.

## Costs the sales conversation must cover

**Vercel Hobby is non-commercial.** A business running its accounting dashboard on Hobby
violates Vercel's ToS and is suspendable. Clients need **Pro (~$20/mo)** plus Neon beyond the
free tier. This surfaces as an angry call after suspension if it is not said up front.

**Code signing:** OV certificate, ~$230/yr, hardware token mandatory. Do **not** buy EV —
Microsoft removed EV's SmartScreen bypass in 2024, so it now buys nothing over OV. From
1 Mar 2026 certificates cap at 458 days.

## Conventions you must not break

See `ARCHITECTURE.md`. The short version:

- **Dr negative, Cr positive**, fixed at the extraction boundary. Profit falls out as a plain sum.
- **Money never touches a float on the extraction path.** `1.005 * 100` is `100.49999999999999`.
- **Company GUID is the identity, never the name.**
- **Advance section hashes on ACK, never on send** — *and* void the watermark when an upload is
  abandoned. The hash is not the only gate: the watermark advances at enqueue, so dropping a row
  without `invalidateWatermark()` freezes the company forever under a green checkmark.
- **Totals come from `totals[]`, never the truncated matrix.**
- **A BIP39 checksum pass is not a correct key.** 24 words carry an 8-bit checksum (~1 in 256
  typos pass). Recover via `attemptRecovery()`, which lets the AEAD decide.

Several of these are enforced by tests in `apps/bridge/test/hardening.test.ts`, which fail the
build if someone adds `nodeIntegration: true`, reaches for `innerHTML`, or gives
`packages/viewmodel` a DOM lib.
