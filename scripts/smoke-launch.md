# Smoke launch — what happens when you actually run this thing

**Date:** 2026-07-16 · **Platform:** macOS (darwin 21.6.0) · **Electron:** 43.1.1 · **Node:** 22.23.1

This is the report of the first time the assembled app was ever launched, and of the first time
the pipeline was run end to end against itself (`scripts/e2e-simulation.ts`).

The short version:

> **The app does not start.** There are five independent, individually-fatal defects between
> `npx electron .` and a window with numbers in it. Every one of them is in the ~200 lines of
> code that no test covers: the wiring.
>
> **Separately and more seriously: the sealed wire format and the card layer disagree about the
> type of every amount.** The Bridge writes amounts as strings; `packages/viewmodel` declares
> them as numbers. Three of the seven cards break on real data — and the balance sheet breaks
> _silently_, rendering `₹—` where a number should be.

457 unit tests pass. Not one of them starts the app, and not one of them connects the module
that writes the wire format to the module that reads it. That is exactly where all six bugs are.

> ### ⚠️ Status note — BUG-1 was fixed while this report was being written
>
> This repo was being edited by other agents concurrently. **BUG-1 (`app.enableSandbox()` inside
> `whenReady`) has since been fixed** in `apps/bridge/src/main/index.ts` — `enableSandbox()` now
> runs in a `bootstrap()` function before `whenReady`, and the promise now has a
> `.catch(onFatalStartup)`. I re-verified this: startup failures are now **reported** instead of
> silent. BUG-1 is kept below because it is the best worked example in this codebase of the
> failure class that matters here, and because its *silence* — not its throw — was the real
> defect.
>
> **Re-verified against current source (2026-07-16 23:24): BUGS 2, 3, 4, 5 and 6 all still
> reproduce.** The front-line blocker for `npx electron .` is now BUG-2.

---

## How this was tested

`timeout` does not exist on macOS, so every launch used `perl -e 'alarm N; exec @ARGV'`.

Bugs behind bugs cannot be found without getting past the one in front, and I own no file in
`apps/` or `packages/`. So the launch probing ran against an **isolated copy** of the workspace
in a scratch directory (sources copied, `node_modules` symlinked per-entry, `better-sqlite3`
shadowed by a stub). Nothing in the repo was modified to produce these findings. Each fix below
was applied **only** to that throwaway copy, purely to reveal the next failure.

Reproduce the current front-line failure (BUG-2) directly, with no copies and no patches:

```bash
npx tsc -p apps/bridge/tsconfig.json
cd apps/bridge && perl -e 'alarm 20; exec @ARGV' npx electron .
# [bridge] fatal during startup: Error: The module '.../better_sqlite3.node'
# was compiled against a different Node.js version using NODE_MODULE_VERSION 127...
```

---

## BUG-1 — `app.enableSandbox()` is called after the app is ready. Nothing runs. **[FIXED — see status note]**

**Severity as found: CRITICAL.** The app was a dead process. No window, no tray, no sync, no
auto-start.

As found, `apps/bridge/src/main/index.ts:71` was the **first statement inside
`app.whenReady()`**, and produced this on every launch:

```
(node:58495) UnhandledPromiseRejectionWarning: Error: app.enableSandbox() can only be called
before app is ready
    at file:///Users/hsa/Desktop/Tally/apps/bridge/dist/main/index.js:63:9
```

`enableSandbox()` must be called *before* the ready event. It is called *inside* the ready
handler, so it throws on every launch, 100% of the time, on every platform.

Because it is the first statement, the throw takes the entire body with it. None of this ever
executes:

| Never runs | Consequence |
|---|---|
| `new Keystore(...)` | no keys |
| `new SyncStore(...)` | no local state |
| `new TallyTransport()` | never talks to Tally |
| `new Scheduler(...)` / `scheduler.start()` | **never syncs** |
| `registerIpc()` | every renderer IPC call hangs forever |
| `createTray()` | no tray icon — and the tray is the ONLY way to quit |
| `showMainWindow()` | no window |
| `app.setLoginItemSettings(...)` | auto-start never configured |

And it fails **silently**. `app.whenReady().then(...)` returns a floating promise nobody
catches, so this is an `UnhandledPromiseRejectionWarning` on stderr — which nobody sees in a
packaged app — and the process then sits there alive and idle forever. The user double-clicks
the icon and *nothing happens at all*. No error dialog; `showFatal()` is unreachable because it
lives past the throw.

There is a cruel irony here: `window-all-closed` is deliberately a no-op ("the Bridge's job is
to keep syncing"), and `before-quit` is the only exit. With no tray, there is no way to quit the
app from the UI at all.

**Fix (since applied by another agent, and verified by me).** Move it above `app.whenReady()`,
and — the part that actually mattered — **catch the promise**:

```ts
app.enableSandbox();                                   // must precede 'ready'
app.whenReady().then(onReady).catch(onFatalStartup);   // a startup that fails must SAY so
```

The lasting lesson is the `.catch`, not the move. `app.whenReady().then(...)` was a floating
promise, so *any* throw anywhere in startup vanished into an unhandled-rejection warning and the
process idled forever. With the catch in place, BUG-2 below now prints
`[bridge] fatal during startup: ...` instead of nothing at all — which is how I was able to
confirm the fix.

---

## BUG-2 — `better-sqlite3` is built for Node's ABI, not Electron's

**Severity: CRITICAL in development.** Not shipped-product-affecting (see below).

With BUG-1 neutralised:

```
Error: The module '.../better-sqlite3/build/Release/better_sqlite3.node'
was compiled against a different Node.js version using NODE_MODULE_VERSION 127.
This version of Node.js requires NODE_MODULE_VERSION 148.
```

`npm install` builds native modules against local Node (22 → ABI 127). Electron 43 embeds its
own Node (ABI 148). `SyncStore` is constructed in `whenReady`, so this kills startup just as
dead as BUG-1 — and via the same unhandled rejection, so again: silent.

**Important nuance — this does NOT affect the shipped installer.** `electron-builder.yml` sets
`npmRebuild: true` and `asarUnpack: ["**/*.node", "**/better_sqlite3.node"]`, both correct. The
packaged app gets a properly rebuilt binary. This is a **developer-experience** bug: nobody can
run the app from source.

**Fix.** Add `@electron/rebuild` and a postinstall script:

```jsonc
// apps/bridge/package.json
"scripts": { "postinstall": "electron-rebuild -f -w better-sqlite3" }
```

**Do not just run `npm rebuild`.** It flips the binary to ABI 148, and then
`npm test` — which runs under plain Node — fails everywhere with the mirror-image error. The two
ABIs cannot coexist in one `node_modules`. (This is why the probing above stubbed the module in
a scratch copy instead: rebuilding in place would have broken the test suite for everyone else.)
A tool that rebuilds on demand, or separate install trees, is the real answer.

---

## BUG-3 — the preload script is ESM; a sandboxed preload must be CommonJS

**Severity: CRITICAL.** `window.bridge` is `undefined`. The renderer is dead on arrival.

With BUGs 1–2 neutralised and the HTML present (BUG-5), the renderer console says:

```
"Unable to load preload script: .../dist/preload/index.js"
"SyntaxError: Cannot use import statement outside a module"
```

`package.json` has `"type": "module"` and the tsconfig emits `NodeNext`, so
`dist/preload/index.js` is ESM. `createSecureWindow` sets `sandbox: true`
(`apps/bridge/src/main/window.ts:48`) — and a **sandboxed preload must be CommonJS**. Electron
loads it as a classic script; `import { contextBridge } from 'electron'` is a syntax error.

So `contextBridge.exposeInMainWorld('bridge', api)` never runs, and every call in
`renderer/main.ts` (`window.bridge.getStatus()`, `.isProvisioned()`, `.onStatusChanged()`) throws
`TypeError: Cannot read properties of undefined`.

This one is genuinely awkward, because `sandbox: true` is load-bearing security that
`hardening.test.ts` enforces. **Do not fix this by turning the sandbox off.** Compile the preload
separately to CJS:

```jsonc
// apps/bridge/tsconfig.preload.json
{ "compilerOptions": { "module": "CommonJS", "outDir": "./dist/preload-cjs" },
  "include": ["src/preload/**/*"] }
```

emit it as `.cjs`, and point `preloadPath` at it (both in `index.ts:258` and the default in
`window.ts:60`). Bundling the preload with esbuild (`--format=cjs --platform=node`) is the
tidier route and solves BUG-4 in the same step.

---

## BUG-4 — the renderer imports a bare specifier, and there is no bundler

**Severity: CRITICAL.** The renderer never executes a single line.

```
Uncaught TypeError: Failed to resolve module specifier "@tally-bridge/viewmodel".
Relative references must start with either "/", "./", or "../".
```

`apps/bridge/src/renderer/main.ts:1` is
`import { formatRelativeTime } from '@tally-bridge/viewmodel';`, and `tsc` is a *compiler*, not a
bundler — it rewrites relative specifiers and leaves bare ones exactly as written. Confirmed in
the emitted output:

```js
// apps/bridge/dist/renderer/main.js:1
import { formatRelativeTime } from '@tally-bridge/viewmodel';   // browser cannot resolve this
import { clear, el, mount } from "./dom.js";                    // fine
```

A browser context has no `node_modules` resolution. `<script type="module">` hits the bare
specifier and throws before `boot()` is reached — so the "Starting Tally Bridge…" placeholder in
`index.html` stays on screen forever. The app looks *hung*, not broken.

This is structural, not a typo: `packages/viewmodel` is explicitly designed to be shared with
the renderer and a web dashboard. There is no bundler in `devDependencies` and no bundle step in
the `build` script.

**Fix.** Add esbuild and bundle the renderer (and the preload, per BUG-3):

```jsonc
"build": "tsc -p tsconfig.json && npm run bundle",
"bundle": "esbuild src/renderer/main.ts --bundle --format=esm --outfile=dist/renderer/main.js
           && esbuild src/preload/index.ts --bundle --format=cjs --platform=node
              --external:electron --outfile=dist/preload/index.cjs"
```

An import map in `index.html` would also resolve the specifier, but CSP is `script-src 'self'`
and every dependency would need mapping by hand. Bundle it.

---

## BUG-5 — `index.html` and `styles.css` are never copied to `dist/`

**Severity: CRITICAL.** Blank window.

```
electron: Failed to load URL: file:///.../dist/renderer/index.html
with error: ERR_FILE_NOT_FOUND
```

`tsc` emits `.js` and `.d.ts`. Nothing else. `index.html` and `styles.css` live in
`src/renderer/` and are not copied, so `dist/renderer/` contains only compiled JS:

```
$ ls apps/bridge/dist/renderer/
cards.d.ts  cards.js  dom.d.ts  dom.js  main.d.ts  main.js   ← no index.html, no styles.css
```

`showMainWindow()` (`index.ts:259`) loads `../renderer/index.html` relative to
`import.meta.dirname` — the path arithmetic is **correct**; the file just is not there.

Two aggravating factors:

1. `void mainWindow.loadFile(...)` — the `void` discards the rejected promise. The failure never
   reaches a handler, so the app cannot know its own UI failed to load.
2. The window is created `show: false` and revealed on `ready-to-show`. Whether that event fires
   for a failed load I did not verify — either way the user gets nothing.

This also affects **the packaged app**: `electron-builder.yml` ships `files: [dist/**/*]`, so the
installer would ship a renderer with no HTML.

**Fix.** Copy assets in the build, and reference `main.js` (bundled, per BUG-4):

```jsonc
"build": "tsc -p tsconfig.json && npm run bundle && cp src/renderer/index.html src/renderer/styles.css dist/renderer/"
```

---

## BUG-6 — the wire carries amount STRINGS; the card layer expects NUMBERS

**Severity: CRITICAL for data correctness. This is the most important finding in this report.**

This is not a launch bug. It is a disagreement between two modules that each pass their own
tests, and it is what `scripts/e2e-simulation.ts` was written to find.

### The two halves

`apps/bridge/src/main/cycle.ts` writes every amount as a **string**, deliberately and correctly:

```ts
function amountFrom(col: string | undefined): string {   // <- string
  return paiseToDecimalString(parseAmountToPaise(col));  // "-342110.75"
}
```

This is right, and `ARCHITECTURE.md` explains why: `canonicalStringify` rejects non-integer
numbers so a float can never re-enter the money path.

`packages/core/src/model.ts` declares the decrypted model as **numbers**:

```ts
export type Amount = number;
export interface CashBankBalance { ...; closing: Amount; }
```

`packages/viewmodel` consumes that model and does arithmetic on it. **Nothing converts between
the two.** There is no parse step, no hydration layer — I grepped for one; it does not exist.

### Why TypeScript never caught it

`ExtractedSection.payload` is typed `CanonicalValue`, not `SectionPayload`. `cycle.ts` asserts
`satisfies CanonicalValue` — which a string satisfies fine. The producer is never type-checked
against the model the consumer uses. The two halves are joined only at runtime, and until now
nothing had ever joined them: **`openSection()` is called in tests and nowhere else**, and
`ipcMain.handle(CHANNELS.getCards, async () => null)` is a stub.

### What actually happens (measured, on real decrypted data)

| Card | Result | How it fails |
|---|---|---|
| `cashBankCard` | ✅ correct | by **accident** — `-r.closing` coerces the string |
| `ageingCard` | ✅ correct | by **accident** — `r.amount * flip` coerces |
| `stockCard` | ✅ correct | by **accident** — unary minus coerces |
| `profitCard` | 💥 **throws** | `sumAmounts` → `toPaise` → `Number.isFinite("500000.00")` is `false` |
| `salesTrendCard` | 💥 **throws** | same path |
| `balanceSheetTree` | ☠️ **silently wrong** | `money(r.closing)` → `formatMoney` → not finite → **`₹—`** |

The three that "work" are worse news than the three that break, because they work by implicit
coercion — one refactor away from silently producing garbage.

`balanceSheetTree` is the dangerous one. It does not throw. It renders the entire balance sheet
as `₹—` under a green checkmark:

```
  Balance sheet    Bank OD A/c=₹—  Current Assets=₹—  Current Liabilities=₹—
```

An earlier run (before a concurrent fix landed in `cards.ts`) showed `salesTrendCard` doing
something even worse than throwing — `0 + "500000.00"` string-concatenating to `"0500000.00"`,
which then formatted to `₹—`. That is exactly the "silently empty column" failure class this
codebase works so hard to prevent everywhere else, reintroduced at the last mile.

### Fix

The wire format is right; the model is right; **the missing piece is the inverse of
`canonicalAmount`.** Add it to `packages/core` next to `canonicalAmount`, and call it on the read
path between `openSection()` and the cards:

```ts
/** The inverse of canonicalAmount. Wire string -> model number, via integer paise, no float. */
export function parseAmount(s: string): Amount {
  return fromPaise(parseAmountToPaise(s));
}
```

with a per-section `parseSection(payload): SectionPayload` that walks the known amount fields.
Then type `ExtractedSection.payload` as `SectionPayload` so the compiler enforces the contract
that this bug slipped through, instead of `CanonicalValue`.

Whatever the shape, **the rule from `ARCHITECTURE.md` applies: the conversion belongs in the
shared layer, not in each renderer.** Two surfaces parsing amounts independently is two surfaces
that will eventually disagree in front of a customer.

---

## What DOES work — and it is most of it

The E2E simulation (`node --experimental-strip-types scripts/e2e-simulation.ts`) wires the real
modules together with fakes only at Tally and Vercel. **26 of 31 checks pass**; the 5 failures
are all BUG-6.

Everything below is now verified working *together*, not just in isolation:

- **The runtime capability prober is the real thing.** Pointed at a Tally speaking the
  `Bill` + `$LedgerName` dialect — one the documented default would never find — it tried
  `Bills+$PartyName`, `Bills+$LedgerName`, `Bills+$..Name`, `Bill+$PartyName`, and converged on
  `Bill+$LedgerName`. It **rejected** the variants that returned rows with blank party names
  rather than accepting the first thing that returned rows. This is the single riskiest unknown
  in the product and it resolves itself correctly.
- **Encoding negotiation** — UTF-16LE with a BOM, sniffed, round-tripped.
- **The codec survives real Indian SMB data.** `A & B Traders <Mumbai>` (bare `&`, angle
  brackets), `श्री गणेश ट्रेडर्स` (Devanagari), and `Caf&#233; Traders` → `Café Traders` all came
  out of the far end byte-identical.
- **The money path has no float in it.** `-87500.50` and `-2500.25` summed to exactly
  `-220000.75` after extraction → canonical JSON → gzip → Padmé → XChaCha20 → base64 → HTTP →
  ingest → decrypt.
- **The security property holds.** The stored envelope was searched for `342110`, `Ganesh`,
  `A & B Traders`, `125000` — none present. The Bridge was handed only `identity.publicKey`; the
  numbers only came back after `openSection` with the secret key.
- **Signing, freshness, quota, and AAD cross-checks** — all 7 sections passed the real
  `handleIngest` with zero 4xx.
- **Both gates hold.** A second cycle over unchanged data: `gate decision: skip`, **0 uploads**.
- **The Dr/Cr flip is right where it matters.** A funded bank account displays `₹3,42,111`,
  **not** negative. An overdraft correctly pulls the total down: `342110.75 + 48250 − 125000 =
  ₹2,65,361`.
- **Indian grouping** — `₹2,20,001`, `₹1,23,45,678`. Lakh/crore, not thousands.

---

## Bug summary

| # | Bug | Severity | Status | Blast radius |
|---|---|---|---|---|
| 1 | `app.enableSandbox()` inside `whenReady()` | CRITICAL | **FIXED** by another agent; verified | App did nothing at all, silently |
| 2 | `better-sqlite3` ABI mismatch | CRITICAL (dev only) | **OPEN** — now the front-line blocker | Cannot run from source; installer OK |
| 3 | ESM preload under `sandbox: true` | CRITICAL | **OPEN** | `window.bridge` undefined |
| 4 | Renderer bare specifier, no bundler | CRITICAL | **OPEN** | Renderer never executes |
| 5 | `index.html`/`styles.css` not copied | CRITICAL | **OPEN** | Blank window; also ships broken |
| 6 | **Wire strings vs model numbers** | **CRITICAL** | **OPEN** | **3/7 cards break; balance sheet fails silently** |

Bugs 3, 4 and 5 must be fixed together — each one alone still leaves a dead renderer. One
esbuild step plus a `cp` closes all three.

## What I could not verify

- **Windows.** This is a Windows product; I ran macOS. `safeStorage`/DPAPI, the
  `HKCU\...\Run` auto-start, the tray, and NSIS packaging are all untested here. Bugs 1 and 3–6
  are platform-independent (logic and build-output facts, reproduced from the emitted files).
  Bug 2 will differ in detail on Windows but exists there too.
- **The keystore path.** `Keystore` construction is behind BUG-1 and was never reached, so
  `KeystoreUnavailableError` → `showFatal()` is unexercised. Worth a look: `showFatal` calls
  `createSecureWindow` with no `preloadPath`, which defaults to `../preload/index.js` from
  `window.ts` — and that preload is broken (BUG-3). The fatal-error window may itself be broken.
- **Whether `ready-to-show` fires after a failed `loadFile`.** Not isolated.
- **A real Tally.** The fake is built to the documented protocol and to
  `packages/tally/test/flavour.test.ts`. Spike A still needs a real Windows Tally with unpaid
  invoices — the prober is *verified to converge*, but only against hypotheses we invented.
- **Vercel OAuth scope** (Spike B) — untouched, still open.
- **Whether the onboarding wizard, pairing, recovery, or Vercel provisioning work.** They are
  behind BUG-1 and were never reached.

## A note on the source moving underfoot

Other agents were editing this repo concurrently while I worked. `apps/server/src/ingest.ts`
changed shape mid-run (`uploadsInLastHour` + `recordUpload` → an atomic `reserveUpload`;
`latestSnapshotTs` → `latestSnapshot`); the simulation is written against the **current**
contract and passes. `packages/tally/src/codec.ts` and `packages/viewmodel/src/cards.ts` also
changed under me. If `e2e-simulation.ts` fails to compile in future, check those interfaces
first.

Note also that **`packages/*/dist` goes stale silently** and `@tally-bridge/*` resolves to
`dist`, not `src`. An early run of the simulation reported `Café Traders` → `Caf Traders` purely
because `dist` predated a fix in `src`. **Run `npm run build` before the simulation**, or you
will debug yesterday's code.
