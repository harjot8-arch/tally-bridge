# Shrinking the Bridge without compromise — Electron → Tauri

## The demand

Same UI. Every feature. **No security compromise.** Extremely small (target well under 60 MB;
realistically ~10 MB). Automation unchanged/maximal.

## Why Electron can't and Tauri can — this is physics, not preference

Electron bundles **Chromium**. Chromium alone compresses to ~55–60 MB; that is the installer
*floor* before a line of our code. The 100 MB build is already near it. No config flag crosses it.

Tauri ships **no browser**. It renders in the OS WebView (**WebView2** on Windows 10/11, already
present or auto-installed at ~0 shipped bytes) and its shell is a small Rust binary. Real-world
Tauri Windows installers are **~3–12 MB**. That is the only way to "extremely small" while keeping
a real desktop app.

## The no-compromise principle: REUSE the security code — but mind WHERE it runs

Our security-critical logic is **framework-free TypeScript that already runs in a browser context**:
the web dashboard (`apps/web`) performs Argon2id derivation and sealed-box identity unwrap **in a
browser Web Worker today**. The primitives, wire format, sealed-box model, and roster check are
reusable byte-for-byte. The crypto is **not** reimplemented in Rust.

**But "reuse the code" is not "run it in the WebView" — and the port spec caught this.** On the
Bridge, **the WebView IS the renderer**, and the product's one non-negotiable property is that *the
renderer never holds the key that reads the data* (`idSK`). Today that key lives only in the Electron
**main** process; the renderer gets computed cards, never the key. `apps/web` runs crypto in the
browser legitimately because *that* browser is the **owner's own reader device** — a different trust
context. That licence does **not** transfer to the Bridge's renderer.

So the reuse splits by trust context, not by language:

- **Encrypt-only + pure formatters** (viewmodel/formatMoney, canonical serializer, sealing to the
  public `idPK`, RFC 9421 signing prep) — safe to run as reused TS anywhere; sealing cannot read.
- **Anything that handles `idSK`** (passphrase unwrap at `unlock`, opening sealed sections to read
  history in `getCards`, roster unseal, `lock`'s key-zeroing) — must run in a **privileged, non-
  renderer context.** The audited TS is reused, but it runs **behind Rust `invoke`, not in the page.**

Only the **Node-only I/O glue** moves to Rust for I/O reasons. The `idSK`-custody split above moves
to a privileged context for a **security** reason. Both are load-bearing.

### Component map (Electron today → Tauri, and where the risk is)

| Piece | Today (Electron) | Tauri | Compromise? |
|---|---|---|---|
| **Renderer UI** | plain DOM in Chromium | same DOM in WebView2 | **None** — ported verbatim |
| **viewmodel / cards / formatMoney** | TS in renderer | same TS in WebView | **None** |
| **crypto — encrypt-only + formatters** (seal to `idPK`, Padmé, canonical) | TS + libsodium-wasm | same TS (WebView OK — cannot read) | **None** |
| **crypto — `idSK` custody** (Argon2id unwrap, open sealed sections, roster unseal, `lock`) | TS in **main** (renderer never sees `idSK`) | **same TS, but PRIVILEGED — behind Rust `invoke`, NOT the renderer WebView** | **Compromise if run in the WebView** — this is the port's one real design fork |
| **protocol** (RFC 9421 sign/verify, route table, quotas) | TS | same TS in WebView | **None** |
| **core** (model, canonical serializer, AAD) | TS | same TS | **None** |
| **Tally transport** (HTTP to `localhost:9000`, encoding sniff, mutex) | `node:net`/`node:http` in main | **Rust command** (`reqwest`/raw TCP) exposed via `invoke` | I/O only — no secrets |
| **offline outbox / watermarks / hashes** | `better-sqlite3` (native) | **`rusqlite`** (same SQLite engine) | Same DB engine, no logic change |
| **snapshot store** (encrypted files) | `node:fs` | Rust fs command | Ciphertext only; encryption stays in TS |
| **keystore** (KEK-wrapped secrets) | Electron `safeStorage` (DPAPI) | **`keyring` crate / DPAPI direct** | Same OS-keychain guarantee |
| **open-external allowlist** (`urls.ts`) | TS + `shell.openExternal` | same TS allowlist + Tauri `shell` (allowlisted) | **None** — same predicate |
| **IPC preload bridge** | `contextBridge` | Tauri `invoke` commands (capability-scoped) | Equivalent isolation |
| **auto-update, OV signing** | electron-updater | Tauri updater + same OV cert | Same signing story |

**Where the crypto runs (the one question an auditor asks):** the `idSK`-custody crypto runs in a
**privileged context behind Rust `invoke`, never in the renderer WebView** — preserving today's
guarantee that the renderer holds only computed cards, never the key. Encrypt-only sealing and the
pure formatters may run as reused TS in the WebView (sealing cannot read). This is the **one design
fork the port has to resolve**, and it has two viable answers, both keeping the audited TS:

  1. **Rust-hosted JS runtime** (e.g. embed a small JS engine, or run the crypto TS in a privileged
     Tauri sidecar webview with no page content) — reuses the exact audited module, out of the
     renderer. Preferred: no new crypto.
  2. **Rust-native crypto** via `libsodium-sys` — rejected unless (1) proves unworkable, because
     reimplementing the envelope in Rust is *new, unaudited crypto* and violates "one audited module."

What does NOT change either way: the server still never holds a decrypt key; sealed boxes,
per-envelope signing, and the passphrase-sealed roster are byte-identical.

> ⚠️ The earlier draft of this doc said the crypto "runs unchanged in a WebView." That was wrong for
> the Bridge and is corrected above — the WebView is the renderer, which must never hold `idSK`.

## Automation — the honest final word

- **Playwright is not, and will not be, in the app.** It bundles/downloads Chromium (~150–300 MB) —
  it is the single most size-destructive dependency possible and directly defeats this whole effort.
- **A lighter browser-driver unlocks nothing.** The only steps we don't already automate — creating
  a Vercel PAT and accepting Neon's Marketplace terms — are blocked by **ToS + law**, not by tool
  weight. Automating a user's account login or clicking a legal "I accept" on their behalf is a ToS
  violation and a contract only the human may make (Vercel deliberately blocks third-party
  click-through). No tool changes that.
- **What is already automated (unchanged in Tauri):** everything reachable by Vercel's REST API —
  project create, Neon provision, DB connect, env vars, file upload, deploy, readiness + the new
  post-deploy health probe. Two human touches remain (paste one token, click Install once), each
  auto-opened to the exact page and auto-polled.
- **The one real future automation win** is OAuth-instead-of-PAT (a legitimate redirect, not
  scraping) — gated on Spike B (does a Vercel OAuth token have project-create scope?), which needs a
  real Vercel token to answer. It removes the token-paste, not the Neon click.

## Milestones (each independently shippable/measurable)

0. **Toolchain + size spike — DONE, MEASURED (2026-07-23).** Built a real Tauri release bundle
   locally (macOS, x64) with Rust 1.97.1. Empty shell: **9.56 MiB** binary. With the *real*
   crypto frontend embedded (`apps/web/dist` — libsodium + the web dashboard that runs Argon2id
   and sealed-box unwrap in a Web Worker, i.e. the exact Tauri model): **9.90 MiB** binary,
   **~10.4 MB** `.app` on disk. The 1.2 MB frontend added only ~360 KB — tauri-codegen compresses
   embedded assets. **That is a ~10× cut vs the 100 MB Electron build, and clears "under 60 MB"
   with ~50 MB to spare. Claim proven with real code, not asserted.**
   - Caveat, stated honestly: this is the macOS `.app` (system WebKit). The *shipping* target is
     Windows/WebView2, which cannot be measured on this Mac. Windows Tauri installers are typically
     *smaller* (~6–12 MB), but that number must come from CI on `windows-latest` before the port
     is committed. That CI spike is the only remaining Milestone-0 item.
1. **Shell + UI** — load the real renderer in WebView2; wire `invoke` for the handful of IPC channels.
2. **Storage** — `rusqlite` outbox + watermarks + section hashes; port `packages/sync` store tests.
3. **Transport** — Rust Tally client (encoding sniff, single-slot mutex, timeouts); reuse the TSV/TDL
   TS by feeding it bytes from Rust.
4. **Keychain** — DPAPI/`keyring` for the wrapped secrets; hard-fail if unavailable (as today).
5. **Onboarding** — deploy bundle + provisioner over Rust/JS `fetch`; keep the health probe.
6. **Parity gate** — every existing package test green against the Tauri wiring; real-Electron visual
   screenshots replaced with real-WebView2 screenshots.
7. **Sign + auto-update + ship**; delete the Electron app.

## What this costs, plainly

Milestones 1–7 are **weeks**, and they rewrite the `apps/bridge/src/main` glue and native storage in
Rust. The security **math** is not touched — that is what makes "no compromise" true and testable
(the crypto/protocol/core/sync/viewmodel test suites carry over unchanged). The risk lives in the
I/O port, which is exactly where tests are cheap and deterministic.

## What I need to start

- Rust + Tauri CLI in CI (this Mac has neither, and WebView2 is a Windows target).
- Milestone 0's size number is the go/no-go: if the spike isn't well under 60 MB, we stop and
  reconsider before porting anything.
