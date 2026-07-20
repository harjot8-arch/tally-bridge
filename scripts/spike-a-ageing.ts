/**
 * SPIKE A — resolve the ageing query against a real Tally.
 *
 * This is the highest-risk unknown in the whole product and it cannot be settled from
 * documentation: sources genuinely conflict on whether the collection is `Bills` or `Bill`, and
 * on whether the party is reachable as `$PartyName`, `$LedgerName`, or `$..Name` under a
 * CHILDOF walk. The ageing card is the feature the dashboard exists for.
 *
 * What makes this dangerous rather than merely unknown: a wrong method name does NOT raise an
 * error in Tally. It returns an EMPTY COLUMN. Left undetected, the product ships a confident
 * dashboard full of blank debtors.
 *
 * PRIVACY: this runs against a real business's live books. It redacts party names and amounts
 * by default and reports only shapes and counts, so the output is safe to share. Pass
 * --show-data only if you understand you are about to print real financial data.
 *
 * Usage:
 *   node --experimental-strip-types scripts/spike-a-ageing.ts
 *   node --experimental-strip-types scripts/spike-a-ageing.ts --port 9000 --show-data
 */

import {
  SPIKE_A_VARIANTS,
  TallyTransport,
  TIMEOUTS,
  cashBankRequest,
  describeFailure,
  groupsRequest,
  parseBillRow,
  probeRequest,
  billsRequest,
  xmlTagResponseToRows,
} from '../packages/tally/src/index.ts';

const args = process.argv.slice(2);
const showData = args.includes('--show-data');
const portIdx = args.indexOf('--port');
const port = portIdx >= 0 ? Number(args[portIdx + 1]) : 9000;

const log = (s = '') => console.log(s);
const ok = (s: string) => log(`  \x1b[32mPASS\x1b[0m  ${s}`);
const bad = (s: string) => log(`  \x1b[31mFAIL\x1b[0m  ${s}`);
const warn = (s: string) => log(`  \x1b[33mWARN\x1b[0m  ${s}`);

/** Never print a real party name unless explicitly asked. */
function redact(s: string): string {
  if (showData) return s;
  if (s.length === 0) return '<empty>';
  // Keep enough shape to diagnose (length, charset) without revealing the customer.
  return `<${s.length} chars, starts "${s.slice(0, 1)}">`;
}

function redactAmount(s: string): string {
  return showData ? s : `<${s.length} digits>`;
}

async function main() {
  log();
  log('='.repeat(72));
  log('  SPIKE A — Tally ageing query resolution');
  log('='.repeat(72));
  log(`  port: ${port}   privacy: ${showData ? 'SHOWING REAL DATA' : 'redacted (safe to share)'}`);
  log();

  const transport = new TallyTransport({ port });

  // ---------------------------------------------------------------- 1. reachability + encoding
  log('1. Tally reachability and request encoding');
  const encoding = await transport.detectEncoding(probeRequest());
  if (!encoding) {
    const res = await transport.request(probeRequest(), TIMEOUTS.probeMs);
    if (!res.ok) {
      bad(describeFailure(res.failure));
      log();
      log('  Cannot continue. Check that:');
      log('    - TallyPrime / Tally.ERP 9 is running');
      log('    - a company is open');
      log('    - F1 > Settings > Advanced Configuration > Tally as Server is Yes');
      log(`    - the port really is ${port}`);
      process.exit(1);
    }
  }
  ok(`request encoding: ${encoding}`);

  // ---------------------------------------------------------------- 2. probe / companies
  log();
  log('2. Company probe and AlterID watermarks');
  const probeRes = await transport.request(probeRequest(), TIMEOUTS.probeMs);
  if (!probeRes.ok) {
    bad(describeFailure(probeRes.failure));
    process.exit(1);
  }
  const companies = xmlTagResponseToRows(probeRes.xml);
  if (companies.length === 0) {
    bad('probe returned no companies (Tally running but nothing open?)');
    process.exit(1);
  }
  ok(`${companies.length} open compan${companies.length === 1 ? 'y' : 'ies'}`);
  for (const c of companies) {
    const [name, guid, altMst, altVch, booksFrom, lastVch, isActive, state] = c;
    log(`        name        : ${redact(name ?? '')}`);
    log(`        guid        : ${guid ? 'present' : '\x1b[31mMISSING\x1b[0m'}`);
    log(`        AltMstId    : ${altMst ?? '<none>'}   <- masters watermark`);
    log(`        AltVchId    : ${altVch ?? '<none>'}   <- vouchers watermark`);
    log(`        booksFrom   : ${booksFrom ?? '<none>'}`);
    log(`        lastVoucher : ${lastVch ?? '<none>'}`);
    log(`        isActive    : ${isActive ?? '<none>'}`);
    log(`        state       : ${redact(state ?? '')}`);
  }
  if (!companies[0]?.[2] || !companies[0]?.[3]) {
    warn('AlterID watermarks missing — delta sync would degrade to a full pull every cycle.');
  }

  const [firstName, , , , booksFromRaw] = companies[0]!;
  const company = firstName!;
  const booksFrom = isoFromTallyInt(booksFromRaw) ?? '2026-04-01';
  const asOf = new Date().toISOString().slice(0, 10);
  log(`        -> using company #1, booksFrom=${booksFrom}, asOf=${asOf}`);

  // ---------------------------------------------------------------- 3. group oracle
  log();
  log('3. Group collection (the oracle every other probe is checked against)');
  const groupsRes = await transport.request(groupsRequest({ company, booksFrom, asOf }));
  let debtorsHaveBalance = false;
  if (!groupsRes.ok) {
    bad(describeFailure(groupsRes.failure));
  } else {
    const rows = xmlTagResponseToRows(groupsRes.xml);
    ok(`${rows.length} groups (expect ~40-90)`);

    const withPrimary = rows.filter((r) => (r[2] ?? '').length > 0).length;
    if (withPrimary === 0) {
      warn('$_PrimaryGroup is EMPTY for every row -> set usePrimaryGroup:false and walk $Parent');
    } else {
      ok(`$_PrimaryGroup resolves (${withPrimary}/${rows.length} rows populated)`);
    }

    const revenue = rows.filter((r) => r[3] === '1').length;
    ok(`$IsRevenue splits the tree: ${revenue} P&L groups, ${rows.length - revenue} Balance Sheet`);

    // Does the business actually have debtors? This is what tells us whether an empty Bills
    // response below means "broken query" or "genuinely nobody owes anything".
    const debtors = rows.find((r) => /sundry debtors/i.test(r[0] ?? ''));
    if (debtors) {
      const bal = debtors[5] ?? '0';
      debtorsHaveBalance = Number(bal) !== 0;
      ok(`Sundry Debtors closing balance is ${debtorsHaveBalance ? 'NON-ZERO' : 'zero'} (${redactAmount(bal)})`);
    } else {
      warn('no "Sundry Debtors" group found — unusual; the ageing check below is inconclusive');
    }
  }

  // ---------------------------------------------------------------- 4. cash/bank
  log();
  log('4. Cash/Bank reserved group functions ($$GroupBank / $$GroupBankOD)');
  const cbRes = await transport.request(cashBankRequest({ company, asOf }));
  if (!cbRes.ok) {
    bad(`${describeFailure(cbRes.failure)} -> likely $$GroupBank/$$GroupBankOD unsupported`);
    warn('set useGroupBankFunctions:false to use the _PrimaryGroup fallback');
  } else {
    const rows = xmlTagResponseToRows(cbRes.xml);
    if (rows.length === 0) {
      warn('0 cash/bank ledgers. If this business has a bank account, the reserved group');
      warn('functions are unsupported -> set useGroupBankFunctions:false');
    } else {
      ok(`${rows.length} cash/bank ledgers (expect 2-15)`);
    }
  }

  // ---------------------------------------------------------------- 5. THE SPIKE
  log();
  log('5. Ageing collection — the actual unknown');
  log('   Trying every (collection type x party method) combination.');
  log();

  const results: Array<{
    variant: string;
    rows: number;
    named: number;
    verdict: 'WORKS' | 'EMPTY_COLUMN' | 'NO_ROWS' | 'ERROR';
    detail: string;
  }> = [];

  for (const v of SPIKE_A_VARIANTS) {
    const label = `${v.collectionType.padEnd(5)} + ${v.partyMethod}`;
    const res = await transport.request(
      billsRequest({
        company,
        booksFrom,
        asOf,
        side: 'receivable',
        collectionType: v.collectionType,
        partyMethod: v.partyMethod,
      }),
    );

    if (!res.ok) {
      results.push({
        variant: label,
        rows: 0,
        named: 0,
        verdict: 'ERROR',
        detail: describeFailure(res.failure),
      });
      bad(`${label}  ${describeFailure(res.failure)}`);
      continue;
    }

    const raw = xmlTagResponseToRows(res.xml);
    const bills = raw.map(parseBillRow).filter((b) => b !== undefined);
    const named = bills.filter((b) => b.partyName.trim().length > 0).length;

    if (raw.length === 0) {
      const verdict = debtorsHaveBalance ? 'NO_ROWS' : 'NO_ROWS';
      results.push({
        variant: label,
        rows: 0,
        named: 0,
        verdict,
        detail: debtorsHaveBalance
          ? 'no rows, but Sundry Debtors is non-zero -> WRONG COLLECTION TYPE'
          : 'no rows, and Sundry Debtors is zero -> inconclusive',
      });
      if (debtorsHaveBalance) bad(`${label}  0 rows but debtors exist -> wrong collection`);
      else warn(`${label}  0 rows (no debtors to find — inconclusive)`);
      continue;
    }

    if (named === 0) {
      // THE characteristic failure. Rows came back, the party column is blank.
      results.push({
        variant: label,
        rows: raw.length,
        named: 0,
        verdict: 'EMPTY_COLUMN',
        detail: 'rows returned but EVERY party name is empty -> wrong party method',
      });
      bad(`${label}  ${raw.length} rows, but party column is EMPTY -> wrong party method`);
      continue;
    }

    results.push({
      variant: label,
      rows: raw.length,
      named,
      verdict: 'WORKS',
      detail: `${named}/${raw.length} rows have party names`,
    });
    ok(`${label}  ${raw.length} rows, ${named} with party names`);
    log(`             sample party : ${redact(bills[0]!.partyName)}`);
    log(`             sample amount: ${redactAmount(String(bills[0]!.amountPaise / 100))}`);
    log(`             days/credit  : ${bills[0]!.daysSinceBill} / ${bills[0]!.creditPeriodDays}`);
  }

  // ---------------------------------------------------------------- verdict
  log();
  log('='.repeat(72));
  log('  VERDICT');
  log('='.repeat(72));

  const winners = results.filter((r) => r.verdict === 'WORKS');
  if (winners.length > 0) {
    log();
    log('  Working variant(s), best first:');
    for (const w of winners) log(`    ${w.variant}   (${w.detail})`);
    log();
    log(`  -> Set billsRequest defaults to: ${winners[0]!.variant}`);
  } else if (results.every((r) => r.verdict === 'NO_ROWS') && !debtorsHaveBalance) {
    log();
    warn('INCONCLUSIVE. No variant returned rows, but this company has no outstanding');
    warn('debtors either, so there was nothing to find. Re-run against a company that has');
    warn('unpaid invoices — otherwise this spike proves nothing.');
  } else {
    log();
    bad('NO VARIANT WORKED, and this company DOES have debtors.');
    log('  Send this output back. The next things to try are widening the collection');
    log('  (drop CHILDOF/BELONGSTO) and dumping the raw response to inspect what Tally');
    log('  actually returns for a bill object.');
  }

  log();
  log('  Also confirm and report:');
  log(`    - encoding detected      : ${encoding}`);
  log(`    - AlterID watermarks     : ${companies[0]?.[2] ?? '?'} / ${companies[0]?.[3] ?? '?'}`);
  log('    - Tally flavour/version  : (Prime or ERP 9, and the version string)');
  log();
}

/** The probe returns dates as YYYYMMDD integers. */
function isoFromTallyInt(v: string | undefined): string | undefined {
  if (!v || !/^\d{8}$/.test(v)) return undefined;
  return `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}`;
}

main().catch((e) => {
  console.error();
  console.error('Spike crashed:', e instanceof Error ? e.message : e);
  console.error();
  process.exit(1);
});
