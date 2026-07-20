# Testing Tally Bridge on a real Windows PC

This is the first time this software meets a real Tally. Everything in it has been tested against
a **fake** Tally that we wrote — which proves the code does what we think Tally does, and proves
nothing about what Tally actually does.

**You are not checking whether it works. You are checking where it is wrong.** A run that finds
three problems is a good run. A run that finds none most likely means a step was skipped.

Read the whole of Part 1 before you start. It takes about 10 minutes and will save an hour.

---

## Part 0 — What you need

| | |
|---|---|
| **A Windows PC** | Windows 10 or 11. The same machine Tally runs on. |
| **TallyPrime or Tally.ERP 9** | With at least one real company that has real data in it. |
| **Node.js 22 or newer** | https://nodejs.org — take the LTS installer, click through. |
| **Git** | https://git-scm.com/download/win — click through. |
| **About 2 hours** | Most of it waiting and looking, not typing. |

**Use a company with messy real data if you can.** A clean demo company will pass everything and
teach us nothing. What we most want is a company with overdue bills, a party name containing `&`
or `<`, and more than one bank account.

> **Do not point this at a client's live books on the first run.** Use your own company, or a
> restored backup of one. Nothing here writes to Tally — every request is a read — but "nothing
> writes" is a claim you should let us earn before you bet a client's data on it.

---

## Part 1 — Turn on Tally's connector

Tally can serve its data over HTTP, but it ships with that turned **off**. Nothing works until
this is done.

1. Open Tally. Open a company. **Tally must stay open the whole time** — the connector only exists
   while Tally is running with a company loaded. This is not a limitation we can code around; it
   is how Tally works.
2. Press **F1** → **Settings** → **Connectivity** → **Client/Server configuration**.
   (On Tally.ERP 9: **F12** → **Advanced Configuration**.)
3. Set:
   - **TallyPrime acts as** → `Both` (or `Server`)
   - **Enable ODBC** → `Yes`
   - **Port** → `9000`
4. Accept, and let Tally restart if it asks.

**Check it worked.** Open a browser on the same PC and go to:

```
http://localhost:9000
```

You should get a small blob of XML, or a blank page — **not** "can't reach this page". If you get
"can't reach this page", the connector is off; go back to step 2. This is the single most common
reason nothing works, and it is worth being certain before you go further.

---

## Part 2 — Get the code and run the tests

Open **PowerShell** (press Start, type `powershell`, Enter) and run these one at a time:

```powershell
cd $HOME\Desktop
git clone <YOUR-REPO-URL> Tally
cd Tally
npm install
```

`npm install` takes a few minutes and prints a lot. Warnings are normal; a red `ERR!` is not.

Now run the test suite. This proves the code arrived intact before you blame Tally for anything:

```powershell
npm test --workspaces --if-present
```

**Expected: about 1,216 tests pass and 0 fail.** If anything fails here, stop and send me the
output — that is a real bug and everything after this point would be misleading.

---

## Part 3 — THE IMPORTANT ONE: does it read your Tally correctly?

This is the single most valuable thing you can do, and it takes two minutes.

With Tally open and a company loaded:

```powershell
npm run spike:tally
```

This asks your Tally the questions the product depends on, and prints what comes back. It writes
nothing, changes nothing, and uploads nothing — it is a read and a printout.

### What to send me

**Send me the entire output.** Copy the whole thing, not a summary. If it is long, redirect it to
a file and send that:

```powershell
npm run spike:tally > spike-output.txt 2>&1
```

⚠️ **Before sending: open `spike-output.txt` and look at it.** It contains real figures and real
party names from your books. If that is sensitive, redact the names and amounts — the shapes and
the error messages are what matter to me, not the values. I would rather have a redacted file than
have you send something you regret.

### What I am looking for, and why

| Thing | Why it matters |
|---|---|
| **Do party names come back at all?** | The single riskiest unknown in the product. Tally has several possible method names for this and a wrong one returns an **empty column, not an error**. If names are blank, ageing is broken and would have shipped silently. |
| **Which "Bills" variant answered** | We try six and pick the winner. I want to know which one your Tally accepted. |
| **Does the balance sheet balance?** | We assert assets + liabilities ≈ 0. A non-zero residual means a sign error somewhere. |
| **Are amounts sensible?** | Roughly the numbers you would see in Tally itself. |
| **Any `<LINEERROR>`** | Tally telling us a query was malformed. |

---

## Part 4 — Run the actual app

```powershell
npm run build
cd apps\bridge
npm start
```

The setup wizard opens. Walk through it as a **complete beginner would** — that is the point of
this pass. Do not use your knowledge of how it works to get past a confusing screen; if you are
confused, write down where.

### Screen 1 — Find Tally
Should find Tally on its own and list your companies.
- ✅ Works: it names your real company.
- ❌ **Tell me if:** it cannot find Tally (and `http://localhost:9000` DID work in Part 1), lists
  the wrong companies, or shows an error code instead of a plain sentence.

### Screen 2 — Connect cloud

**Stop and read this before you click.**

This step creates a **real Vercel account project and a real Neon database**, and can cost real
money. For a first test you have two options:

1. **Skip it.** Test everything else first. Screens 1 and 3, the sync engine, and the desktop
   dashboard all work without a cloud. This is what I recommend for the first run.
2. **Do it properly**, knowing:
   - **Vercel's Hobby (free) plan forbids commercial use.** For your own testing that is fine. For
     a paying client it is a **ToS violation and their deployment can be suspended.** Real clients
     need **Vercel Pro, about $20/month.** Please price this in before you sell anything.
   - You will paste a Vercel token, and click "Install" once on the Neon marketplace page. Those
     two steps cannot be automated — Vercel and Neon both require a human to accept terms.

- ❌ **Tell me if:** it hangs, the deployment never goes green, or the error is a status code
  rather than a sentence.

### Screen 3 — Passphrase and recovery sheet

**This is the most important screen in the product**, and the one I most want your eyes on.

The passphrase is the only thing that decrypts your figures. **There is no reset.** Not by me, not
by you, not by a support call — that is exactly what stops anyone else, including the server, from
reading the data. If the recovery sheet is unclear here, a real owner loses their history.

- **Print the recovery sheet.** Actually print it, on actual paper. It is designed for A4.
- It will make you type back two of the words. **This is deliberate** — an unverified recovery key
  is worse than none, because it manufactures false confidence.
- Scan the QR code with your phone camera and confirm it reads.
- ❌ **Tell me if:** the sheet is confusing, the print is cut off, the QR does not scan, or the
  Hindi text reads oddly.

---

## Part 5 — Does it show the right numbers?

Now the dashboard. **Put Tally and the dashboard side by side and compare.**

Open the same figures in Tally (Gateway → Balance Sheet, Ratio Analysis, Stock Summary) and check
each one against the app.

| Check | How |
|---|---|
| **Cash & bank** | Each bank ledger and its balance. Must be your **real ledger names**. |
| **Receivables total** | Tally: Display → Statements → Outstandings → Receivables |
| **Ageing bands** | Does "over 90 days" match Tally's ageing? |
| **Payables** | Same, Payables |
| **Stock value** | Gateway → Stock Summary. **⚠️ Check the SIGN carefully — see below.** |
| **Sales this month** | Profit & Loss |
| **Balance sheet groups** | Assets and liabilities on the correct sides |

### Two known-uncertain things — please look hardest here

1. **Stock sign.** This is the one item I know is uncertain. The app decides at runtime whether
   your Tally reports stock as positive or negative, and no real Tally has ever confirmed it.
   **If stock shows as negative, or wildly wrong, tell me immediately** — it is a known open risk,
   not a surprise.
2. **A party name with `&` or `<` in it.** If you have one (e.g. `A & B Traders`), find it on the
   dashboard. It must appear **exactly as text**. If you see `&amp;` or the name vanishes, that is
   a real bug — tell me.

**⛔ If any number is wrong, stop and tell me before doing anything else.** A wrong figure in a
financial product is the worst possible defect: it is worse than a crash, because a crash is
obvious and a wrong number is believed. Do not try to work out why. Just send me: what the app
said, what Tally said, and which screen.

---

## Part 6 — The awkward situations

These are the ones that break software in the field. Please actually do them.

| Do this | Should happen |
|---|---|
| **Close Tally** while the app runs | Quiet "Tally not running" message. **Not** an error code or a crash. This is the normal overnight state. |
| **Close the company** but leave Tally open | "Waiting for Tally", not a failure. |
| **Unplug the internet**, wait, plug back in | Queues up, sends later. Nothing lost, nothing duplicated. |
| **Sleep the laptop**, wake it | Syncs shortly after waking. |
| **Add a voucher in Tally**, wait ~15 min | The figure changes. |
| **Change nothing**, wait 30 min | **Ideally ZERO uploads.** An idle company should cost nothing. If it uploads anyway, tell me — that is money off your client's bill. |
| **Restart the PC** | Comes back by itself, no re-setup. |
| **Switch to a different company** in Tally | Figures follow. Must **never** mix two companies' numbers together. |

---

## Part 7 — The phone

The dashboard is meant for phones. Open your Vercel URL on an actual phone (only if you did the
cloud step).

- Log in with your Tally ID and passphrase. It takes **1–8 seconds and that is on purpose** — it
  is what makes a weak passphrase expensive to attack. There must be a spinner, never a frozen screen.
- ❌ **Tell me if:** anything runs off the side of the screen, text is too small, a number is cut
  off, or it feels broken while loading.

---

## How to report back

Just write it plainly. Do not format it for me.

**For anything wrong, I need three things:**
1. **What you did** — "Screen 2, clicked Connect"
2. **What you expected**
3. **What actually happened** — the exact message, or a photo of the screen

Photos of the screen are genuinely useful. So is "this bit confused me" — confusion is a real
defect in a product for non-technical owners, not a soft one.

**Please also tell me the boring things:** which Tally version and edition, Windows version, how
many companies, roughly how many ledgers and stock items, and whether Tally felt slower while the
app was running. That last one matters — Tally is single-threaded and the owner is typing into it.

### If it all works

Say so, and send me the Part 3 spike output anyway. That output is what turns "we think Tally
does this" into "we know Tally does this", and it is the last unknown in the product.

---

## Two honest warnings

**This does not protect the Windows PC.** The encryption stops the *server* from reading your
figures — that is real and that is the point. It does **not** protect against malware on the Tally
PC itself: Tally's own data files sit unencrypted on that disk and port 9000 has no password, so
anything running as that Windows user can read Tally directly and ignore us entirely. Never tell a
client this software secures their PC. It secures the cloud.

**Vercel Hobby is not for business use.** Covered above, repeated because it surfaces as an angry
call after a suspension: real clients need Vercel Pro (~$20/mo).
