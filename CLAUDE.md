# Tally Bridge — Claude Code Configuration

Electron desktop app that reads an Indian SMB's books out of **Tally** on their office PC,
encrypts them, and pushes them to a dashboard on **the client's own** Vercel + Neon.

**`ARCHITECTURE.md` is authoritative.** Read it before touching `packages/crypto`,
`packages/tally`, or `apps/server`. This file is the short version that must always be in context.

## The one property everything protects

**The server never holds a key that reads the data.** The Bridge gets only a public key and uses
sealed boxes: it can write and never read. A Neon dump, a leaked `DATABASE_URL`, RCE on a Vercel
function, or a subpoena all yield ciphertext. Never add a server-side path that could decrypt.

Sealed boxes give **confidentiality, not authenticity** — the server knows `idPK` and could
fabricate an envelope. That is why the Bridge **signs** every envelope and the reader refuses
anything not signed by a key in the passphrase-sealed **roster**. Never accept a roster from the
server.

## Conventions you must not break

- **Dr negative, Cr positive**, fixed at extraction (`packages/tally/src/tdl.ts`, `expr.amount`).
  Assets arrive negative; the card layer flips for display.
- **Money never touches a float.** `parseAmountToPaise` is the only parser; `Amount` is a
  `string`. `1.005 * 100 === 100.49999999999999`, so scale-then-round silently loses a paisa.
- **`formatMoney`, never `Intl.NumberFormat('en-IN')`.** Without full ICU, Intl silently falls
  back to en-US grouping and prints `₹1,42,34,110` as `₹14,234,110` — the one thing this market
  must never see.
- **Company GUID is the identity, never the name.** Names get edited and repeat across years.
- **Totals come from `totals[]`, never the truncated `rows[]`.**
- **Paths come from `packages/protocol/src/routes.ts`**, never a literal — the request path is
  inside the Ed25519 signature, so a second copy is a silent 401 on the owner's own deployment.
- **HKDF labels come from `KDF_INFO`**, never restated. Two copies = total auth failure the day
  one is edited.
- **No invented numbers, ever.** If a figure has no data source, render nothing or `—`. A
  plausible fake figure in a financial product is worse than a blank.

## The lesson this codebase keeps re-teaching

**A component's tests prove it WORKS. They never prove it RUNS. Only a caller does.**
Four features here were fully built, fully tested, all green, and completely unreachable:
`openSection` had no caller; `balanceSheetTree` had no field to travel in; `mountDashboard` had
30 test call sites and 0 in `src`; a server endpoint nothing invoked. The review question is not
"is it tested" but **"what in `src` calls it, and does a test fail if that call is deleted?"**

Two corollaries, both learned the hard way here:
- **Bugs cluster where comments are most confident.** Eight confidently-false comments have been
  found and corrected. Treat "cannot", "never", "immune", "idempotent", "atomic" as claims to
  test, not facts.
- **Mutate the defence, confirm the test goes red, revert.** Several headline security tests
  stayed green while the guard they were named after was deleted. A test that cannot fail is
  worse than no test.

## Layout (npm workspaces — not `/src`, `/tests`, `/docs`)

```
packages/core       model, canonical serializer, envelope/AAD types
packages/crypto     THE security boundary — Argon2id, XChaCha20, sealed box, roster
packages/protocol   RFC 9421 signing, quotas, the shared ROUTE TABLE
packages/tally      transport, TDL catalog, runtime capability probing
packages/viewmodel  cards — no DOM lib, so it cannot reach for `document`
apps/bridge         Electron main + preload + renderer (desktop dashboard, setup wizard)
apps/server         handlers + router, deployed to the client's Vercel
apps/web            the web dashboard's DATA layer (owner writes the UI — see its README)
```

## Verify like this

```bash
npm test -w <workspace>                 # node --test, no framework
npx tsc -p <ws>/tsconfig.json --noEmit
npm run build:deploy-bundle             # emits .vercel/output — health smoke + sodium probe run
cd apps/bridge && npm run visual        # REAL Electron screenshots
```

macOS has **no `timeout`** — use `perl -e 'alarm 600; exec @ARGV' -- <cmd>`.

The fake DOM in `apps/bridge/test/dashboard.dom.ts` has **no layout engine**: it cannot see a card
off-screen, overflowing, or sitting in a void. Two real defects hid behind a green suite. **Look at
the screenshots after any change to `styles.css` or `paintContent`.**

## Known-open, deliberately

- Stock sign resolves at runtime per install (`packages/tally/src/stocksign.ts`) — the mechanism
  ships; a real Tally would confirm the answer.
- Whether Vercel's `?prebuilt=1` is *required* vs merely *sufficient* is unprovable from readable
  source; we send exactly what the official CLI sends.
- The deployed dashboard has **no CSP headers yet** (`config.json` sets none). Do not claim it
  does — an earlier comment did, falsely.

---

# Ruflo — agent orchestration (installed tooling)

- Do what has been asked; nothing more, nothing less.
- Prefer editing existing files over creating new ones. ALWAYS read a file before editing it.
- NEVER commit secrets, credentials, or `.env` files.
- Validate input at system boundaries.

## Agent Comms (SendMessage-first)

Named agents coordinate via `SendMessage`, not polling or shared state.

- ALWAYS name agents — `name: "role"` makes them addressable.
- ALWAYS say who to message next and what to send.
- Spawn ALL agents in ONE message with `run_in_background: true`.
- NEVER poll status — agents message back or complete automatically.

| Pattern | Flow | Use When |
|---------|------|----------|
| **Pipeline** | A → B → C → D | Sequential dependencies |
| **Fan-out** | Lead → A, B, C → Lead | Independent parallel work |
| **Supervisor** | Lead ↔ workers | Ongoing coordination |

**When to swarm** — YES: 3+ files, new features, cross-module refactors, security, performance.
NO: single-file edits, 1–2 line fixes, docs, config, questions.

**Agents**: `coder`, `reviewer`, `tester`, `planner`, `researcher`, `system-architect`,
`backend-dev`, `security-architect`, `performance-engineer`, `hierarchical-coordinator`,
`mesh-coordinator`. Any string works as a custom type.

**MCP** (discover via `ToolSearch`): memory (`memory_store`, `memory_search`), swarm
(`swarm_init`, `swarm_status`), agents (`agent_spawn`), hooks (`hooks_route`), security
(`aidefence_scan`).

```bash
npx @claude-flow/cli@latest swarm init --topology hierarchical --max-agents 8
npx @claude-flow/cli@latest memory search --query "[keywords]" --namespace patterns
npx @claude-flow/cli@latest doctor --fix
```

> The background `daemon` is optional and spawns headless sessions continuously — start it only
> if you want those sweeps: `npx ruflo@latest daemon start`.

**Agent tool** executes (files, code, git). **MCP tools** coordinate (swarm, memory, hooks).
