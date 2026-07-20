import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRequest, esc, expr, fieldCountOfRequest, toTallyDate } from '../src/tdl.ts';
import { billsRequest, groupsRequest, probeRequest, revenueRequest } from '../src/requests.ts';
import { xmlTagResponseToRows } from '../src/codec.ts';

/**
 * A company name is NOT our data. It comes out of the Tally file, it is edited by whoever uses
 * Tally, and it is interpolated into the TDL we inject. If it can break out of its element it
 * can redefine our REPORT, our FILTER, or SVEXPORTFORMAT — and the response would still look
 * perfectly plausible. This is the one genuine injection surface in the package, so it is
 * pinned rather than trusted.
 */
const HOSTILE_NAMES = [
  `</SVCURRENTCOMPANY></STATICVARIABLES><TDL><TDLMESSAGE><SYSTEM TYPE="Formulae" NAME="Evil">$$Sys:Evil</SYSTEM>`,
  `Acme</SVCURRENTCOMPANY><SVEXPORTFORMAT>ASCII</SVEXPORTFORMAT><SVCURRENTCOMPANY>`,
  `A & B <Traders> "Quoted" 'Apos'`,
  `]]><![CDATA[evil`,
  `<!-- comment -->`,
  `&amp;lt;`,
  `&#60;/SVCURRENTCOMPANY&#62;`,
];

test('a hostile company name cannot break out of the XML we generate', () => {
  for (const company of HOSTILE_NAMES) {
    const xml = groupsRequest({ company, booksFrom: '2026-04-01', asOf: '2026-07-16' });
    assert.equal((xml.match(/<SVCURRENTCOMPANY>/g) ?? []).length, 1, company);
    assert.equal((xml.match(/<\/SVCURRENTCOMPANY>/g) ?? []).length, 1, company);
    // Exactly the export format WE chose, and no injected TDL of any kind.
    assert.equal((xml.match(/<SVEXPORTFORMAT>/g) ?? []).length, 1, company);
    assert.match(xml, /<SVEXPORTFORMAT>XML \(Data Interchange\)<\/SVEXPORTFORMAT>/);
    assert.equal((xml.match(/<SYSTEM /g) ?? []).length, 0, company);
    assert.equal((xml.match(/<TDLMESSAGE>/g) ?? []).length, 1, company);
    assert.equal((xml.match(/<ENVELOPE>/g) ?? []).length, 1, company);
  }
});

test('escaping is lossless: the company name Tally receives is the one it has', () => {
  // Over-escaping is a real bug too — SVCURRENTCOMPANY must MATCH, so a mangled name silently
  // targets no company (or the wrong one).
  const unescape = (s: string) =>
    s
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&amp;/g, '&');
  for (const name of [...HOSTILE_NAMES, 'A & B Traders', 'Café & Sons', 'देवनागरी']) {
    assert.equal(unescape(esc(name)), name, name);
  }
});

test('& is escaped before < and >, never after', () => {
  // The classic double-escape bug: escaping < first turns "<" into "&lt;" and then the &-pass
  // turns it into "&amp;lt;".
  assert.equal(esc('<'), '&lt;');
  assert.equal(esc('&'), '&amp;');
  assert.equal(esc('&lt;'), '&amp;lt;');
  assert.equal(esc('A & B <C>'), 'A &amp; B &lt;C&gt;');
});

test('omitting the company targets the active one, and never emits an empty element', () => {
  // An empty <SVCURRENTCOMPANY></SVCURRENTCOMPANY> is not the same request as no element at
  // all: it names a company called "", which matches nothing.
  const xml = groupsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16' });
  assert.doesNotMatch(xml, /SVCURRENTCOMPANY/);
});

// ---------------------------------------------------------------- the tag alphabet contract

test('the tag alphabet is enforced where it is DECLARED, not where it is decoded', () => {
  // codec.ts decodes by tag NUMBER — the value of <F04> is column 4 — which is only sound if the
  // request declares F01..FNN contiguous and two-digit. Nothing checked it, so a catalog typo
  // would have produced a perfectly plausible response that decodes into the wrong shape.
  const coll = { type: 'Group', fetch: ['Name'] };
  const ok = { id: 'X', collection: coll, fields: [{ tag: 'F01', set: '$Name' }] };
  assert.doesNotThrow(() => buildRequest(ok));

  for (const fields of [
    [{ tag: 'F02', set: '$Name' }], // does not start at F01
    [{ tag: 'F01', set: '$Name' }, { tag: 'F03', set: '$Parent' }], // a gap
    [{ tag: 'F01', set: '$Name' }, { tag: 'F1', set: '$Parent' }], // one digit: inert on return
    [{ tag: 'F01', set: '$Name' }, { tag: 'F002', set: '$Parent' }], // three digits: ditto
    [{ tag: 'F02', set: '$Name' }, { tag: 'F01', set: '$Parent' }], // out of order
    [], // no fields at all
  ]) {
    assert.throws(() => buildRequest({ id: 'X', collection: coll, fields }), JSON.stringify(fields));
  }
});

test('every request in the catalog satisfies the contract its own decoder depends on', () => {
  // The guard above is only worth anything if the shipping requests pass it.
  const catalog = [
    probeRequest(),
    groupsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16' }),
    billsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16', side: 'receivable' }),
    revenueRequest({ from: '2026-07-01', to: '2026-07-16' }),
  ];
  for (const xml of catalog) {
    const tags = [...xml.matchAll(/<XMLTAG>(.*?)<\/XMLTAG>/g)].map((m) => m[1]);
    assert.deepEqual(
      tags,
      tags.map((_, i) => `F${String(i + 1).padStart(2, '0')}`),
    );
    assert.equal(fieldCountOfRequest(xml), tags.length);
  }
});

test('fieldCountOfRequest reads the request on the wire, so it cannot drift from it', () => {
  // The alternative — a hand-maintained FIELD_COUNTS table — is a second source of truth that
  // goes stale the first time someone adds a field, and goes stale SILENTLY.
  assert.equal(fieldCountOfRequest(probeRequest()), 8);
  assert.equal(fieldCountOfRequest(groupsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16' })), 7);
  assert.equal(
    fieldCountOfRequest(billsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16', side: 'payable' })),
    6,
  );
  assert.equal(fieldCountOfRequest('<ENVELOPE/>'), 0);
  // A field count is about the SCHEMA, so a company named "<XMLTAG>F01</XMLTAG>" must not vote.
  const hostile = groupsRequest({ company: '<XMLTAG>F01</XMLTAG>', booksFrom: '2026-04-01', asOf: '2026-07-16' });
  assert.equal(fieldCountOfRequest(hostile), 7);
});

test('expr.amount is the only place the Dr/Cr convention is decided', () => {
  // Pinned because the convention is unverifiable without a real Tally and load-bearing for every
  // number in the product: if $$NumValue is signed rather than a magnitude, this negates an
  // already-negative debit and the whole dashboard inverts. See signs.ts for the runtime canary.
  assert.match(expr.amount('$ClosingBalance'), /if \$\$IsDebit:\$ClosingBalance then -\$\$NumValue/);
});

// ------------------------------------------- revenueRequest: the parent column that makes
// ------------------------------------------- profitCard's de-duplication actually run

/**
 * `profitCard` sums TOP-LEVEL revenue rows only, because `$IsRevenue` returns nested groups and a
 * Tally parent's closing balance already contains its children's. That fix was INERT until this
 * request actually asked Tally for the parent: the column was always absent, every row read as
 * top-level, and the double-count survived. These tests pin the column into existence.
 */

const REVENUE_FIELDS = 3;

/**
 * A fake Tally emitting the revenue schema. `parent: ''` models a TOP-LEVEL group, whose F03 our
 * TDL evaluates to "".
 *
 * Which spelling Tally uses for that empty field is the open FLDBLANK question, so `blank` picks
 * between the two live hypotheses instead of assuming one. The codec indexes by tag, so both must
 * decode identically — and the tests below assert exactly that rather than trusting it.
 */
const revenueXml = (
  rows: ReadonlyArray<{ name: string; amount: string; parent: string }>,
  blank: 'omit' | 'emit' = 'omit',
) =>
  '<ENVELOPE>' +
  rows
    .map(
      (r) =>
        `<F01>${r.name}</F01><F02>${r.amount}</F02>` +
        (r.parent === '' && blank === 'omit' ? '' : `<F03>${r.parent}</F03>`),
    )
    .join('') +
  '</ENVELOPE>';

test('revenueRequest actually asks Tally for the parent', () => {
  // The whole point. Without FETCH Parent and an F03 that reads it, the de-duplication in
  // profitCard is dead code operating on a column that is never populated.
  const xml = revenueRequest({ from: '2026-07-01', to: '2026-07-16' });

  assert.match(xml, /<FETCH>Name,Parent,ClosingBalance<\/FETCH>/, 'Parent must be FETCHed');
  assert.match(xml, /<FIELD NAME="F03">.*?<XMLTAG>F03<\/XMLTAG><\/FIELD>/, 'F03 must exist');
  assert.match(xml, /\$Parent/, 'F03 must read $Parent');
  assert.equal(fieldCountOfRequest(xml), REVENUE_FIELDS);

  // The parent is APPENDED after the amount, because cycle.ts reads amount at index 1 and parent
  // at index 2. Pinned because inserting it at F02 instead would misread every number on the card.
  const tags = [...xml.matchAll(/<XMLTAG>(.*?)<\/XMLTAG>/g)].map((m) => m[1]);
  assert.deepEqual(tags, ['F01', 'F02', 'F03']);
  assert.match(xml, /<FIELD NAME="F02"><SET>\$\$StringFindAndReplace:\(if \$\$IsDebit/, 'F02 amount');
});

test('revenueRequest maps a top-level $Parent to "", rather than shipping raw $Parent', () => {
  // THE trap in this change. A top-level group's $Parent is NOT empty — it is Tally's reserved
  // `Primary` sysname — while PeriodRevenueRow.parent is specified as '' at root. Raw $Parent
  // would put "Primary" in every root group's parent column, and would then be saved only by the
  // accident that no group is named "Primary". A book that HAS one would see its roots read as
  // children of it and drop out of the sum: profit understated, or ₹0.
  //
  // $$SysName:Primary resolves the reserved name instead of matching an English literal, so this
  // survives a localized Tally. Same guard groupsRequest uses; kept identical on purpose.
  const xml = revenueRequest({ from: '2026-07-01', to: '2026-07-16' });
  const guard = 'if $$IsEqual:$Parent:$$SysName:Primary then "" else $Parent';
  assert.match(xml, /<FIELD NAME="F03"><SET>if \$\$IsEqual:\$Parent:\$\$SysName:Primary then/);
  assert.ok(xml.includes(`<SET>${guard}</SET>`), 'F03 is the guard, not a bare $Parent read');
  assert.ok(!xml.includes('<SET>$Parent</SET>'), 'a bare $Parent read would strand "Primary"');

  // And the same guard the groups request already ships — one idiom, not two.
  assert.ok(groupsRequest({ booksFrom: '2026-04-01', asOf: '2026-07-16' }).includes(guard));
});

test('a nested revenue response decodes with the parent in F03 and the amount UNMOVED in F02', () => {
  // The double-count this whole change exists to kill: Sales Accounts already CONTAINS
  // Sales - Domestic, so the two rows must be distinguishable.
  const rows = xmlTagResponseToRows(
    revenueXml([
      { name: 'Sales Accounts', amount: '500000.00', parent: '' },
      { name: 'Sales - Domestic', amount: '300000.00', parent: 'Sales Accounts' },
      { name: 'Indirect Expenses', amount: '-120000.00', parent: '' },
    ]),
    { fieldCount: REVENUE_FIELDS },
  );

  assert.deepEqual(rows, [
    ['Sales Accounts', '500000.00', ''],
    ['Sales - Domestic', '300000.00', 'Sales Accounts'],
    ['Indirect Expenses', '-120000.00', ''],
  ]);
  // Stated separately from the deepEqual: the amount staying at index 1 is the property that
  // makes adding this column safe, and it should fail LOUDLY and by name if it ever moves.
  for (const r of rows) assert.match(r[1]!, /^-?\d+\.\d{2}$/, 'index 1 is still the amount');
});

test('a top-level group reads as top-level however Tally spells its blank F03', () => {
  // The catastrophic direction. The consumer treats a row as a child only when its parent is
  // PRESENT AS A ROW in the same pull; if every root carried a non-empty parent that happened to
  // resolve, every row would be excluded and profit would be reported as exactly ₹0 — an
  // understatement is not better than the overstatement we started with.
  const book = [
    { name: 'Sales Accounts', amount: '500000.00', parent: '' },
    { name: 'Sales - Domestic', amount: '300000.00', parent: 'Sales Accounts' },
  ];

  for (const blank of ['omit', 'emit'] as const) {
    const rows = xmlTagResponseToRows(revenueXml(book, blank), { fieldCount: REVENUE_FIELDS });
    assert.equal(rows.length, 2, blank);
    assert.equal(rows[0]![2], '', `a root group's parent is empty (${blank})`);
    assert.equal(rows[0]![1], '500000.00', `and its amount is untouched (${blank})`);
    assert.equal(rows[1]![2], 'Sales Accounts', blank);
  }

  // Both spellings must be the SAME decode — the codec indexes by tag, so an omitted F03 leaves
  // its own column empty and shifts nothing.
  assert.deepEqual(
    xmlTagResponseToRows(revenueXml(book, 'omit'), { fieldCount: REVENUE_FIELDS }),
    xmlTagResponseToRows(revenueXml(book, 'emit'), { fieldCount: REVENUE_FIELDS }),
  );
});

test('the parent survives the NO-fieldCount path, which is the one production actually uses', () => {
  // cycle.ts calls xmlTagResponseToRows(res.xml) with no fieldCount, so row width falls back to
  // the widest tag IN THAT ROW — a root group whose F03 is omitted decodes to a length-2 row.
  // That is fine (the consumer reads `c[2] ?? ''`), but it is only fine by agreement, so pin it:
  // the parent must still land at index 2 and the amount must still be at index 1 on the ragged
  // rows, not just on the uniform ones the fieldCount path produces.
  const rows = xmlTagResponseToRows(
    revenueXml([
      { name: 'Sales Accounts', amount: '500000.00', parent: '' },
      { name: 'Sales - Domestic', amount: '300000.00', parent: 'Sales Accounts' },
    ]),
  );

  assert.deepEqual(rows, [
    ['Sales Accounts', '500000.00'], // ragged: F03 omitted, so no third cell at all
    ['Sales - Domestic', '300000.00', 'Sales Accounts'],
  ]);
  // What cycle.ts reads. A root must read as parentless, NOT as a child of something.
  assert.equal(rows[0]![2] ?? '', '', 'a root group reads as top-level on the ragged path');
  assert.equal(rows[1]![2] ?? '', 'Sales Accounts');
  assert.equal(rows[0]![1], '500000.00', 'and the amount never moved');
});

test('the presence rule: roots stay top-level and only real children are suppressed', () => {
  // A local mirror of the rule profitCard applies (a row is a child only when its parent is
  // present as a row in the same pull), so that this package can show the column it emits
  // actually drives that rule the intended way. The real implementation lives in viewmodel.
  const rows = xmlTagResponseToRows(
    revenueXml([
      { name: 'Sales Accounts', amount: '500000.00', parent: '' },
      { name: 'Sales - Domestic', amount: '300000.00', parent: 'Sales Accounts' },
      { name: 'Indirect Expenses', amount: '-120000.00', parent: '' },
      // A child whose parent was filtered out of this pull: top-level, or we understate.
      { name: 'Orphaned Income', amount: '9000.00', parent: 'Some Unfetched Group' },
    ]),
    { fieldCount: REVENUE_FIELDS },
  );

  const names = new Set(rows.map((r) => r[0]!));
  const topLevel = rows.filter((r) => r[2] === '' || !names.has(r[2]!)).map((r) => r[0]!);

  assert.deepEqual(topLevel, ['Sales Accounts', 'Indirect Expenses', 'Orphaned Income']);
  assert.ok(topLevel.length > 0, 'never zero rows: that would report profit as exactly Rs 0');
});

// ------------------------------------------- the same rule, but bound to the REQUEST rather
// ------------------------------------------- than to a fixture that agrees with it

/**
 * Every `revenueXml` test above builds its response BY HAND. That fixture is written to agree with
 * what `revenueRequest` is supposed to emit, but nothing ties it to what `revenueRequest` actually
 * emits — so all four of them stay green when F03 is deleted from the request outright, which is
 * precisely the inert-fix state this change exists to undo (verified by mutation: dropping the F03
 * field leaves those four passing and only the two request-SHAPE tests fail).
 *
 * These tests close that gap by deriving the response from the request's real `<SET>` expressions.
 * A fake Tally that can only evaluate the idioms we actually ship is the point, not a limitation:
 * if the catalog changes to an expression this cannot interpret, the test fails loudly rather than
 * silently testing a request nobody sends.
 */

/** Stands in for Tally's reserved root sysname. Deliberately not the string "Primary": a book may
 *  legitimately contain a GROUP named "Primary", and the two must never be conflated. */
const PRIMARY_SYSNAME = ' $$SysName:Primary';
const PARENT_GUARD = 'if $$IsEqual:$Parent:$$SysName:Primary then "" else $Parent';

interface FakeGroup {
  name: string;
  closing: string;
  /** `PRIMARY_SYSNAME` for a root. */
  parent: string;
}

/** A fake Tally: reads the FIELD/SET pairs out of the request and evaluates them per group. */
function respondAsTally(
  requestXml: string,
  groups: readonly FakeGroup[],
  blank: 'omit' | 'emit' = 'omit',
): string {
  const fields = [...requestXml.matchAll(/<FIELD NAME="(F\d\d)"><SET>(.*?)<\/SET><XMLTAG>/g)].map(
    (m) => ({ tag: m[1]!, set: m[2]! }),
  );
  assert.ok(fields.length > 0, 'the request declares no fields at all');

  const evalSet = (set: string, g: FakeGroup): string => {
    if (set === expr.text('$Name')) return g.name;
    if (set === expr.amount('$ClosingBalance')) return g.closing;
    if (set === PARENT_GUARD) return g.parent === PRIMARY_SYSNAME ? '' : g.parent;
    // A bare `$Parent` read: Tally hands back the reserved sysname's rendering, not "".
    if (set === expr.text('$Parent')) return g.parent === PRIMARY_SYSNAME ? 'Primary' : g.parent;
    throw new Error(`this fake Tally cannot evaluate ${JSON.stringify(set)}`);
  };

  // Tally escapes `&` but emits `<` and `>` raw — see the canary in codec.test.ts.
  const escAmp = (s: string) => s.replace(/&/g, '&amp;');
  return (
    '<ENVELOPE>' +
    groups
      .map((g) =>
        fields
          .map(({ tag, set }) => {
            const v = evalSet(set, g);
            return v === '' && blank === 'omit' ? '' : `<${tag}>${escAmp(v)}</${tag}>`;
          })
          .join(''),
      )
      .join('') +
    '</ENVELOPE>'
  );
}

/** What cycle.ts reads out of a decoded row: `c[2] ?? ''`, on the no-fieldCount production path. */
const parentOfRow = (r: readonly string[]) => r[2] ?? '';

const askRevenue = (groups: readonly FakeGroup[], blank: 'omit' | 'emit' = 'omit') =>
  // No fieldCount: exactly what cycle.ts's `ask` does.
  xmlTagResponseToRows(respondAsTally(revenueRequest({ from: '2026-07-01', to: '2026-07-16' }), groups, blank));

test('the request the catalog actually ships makes roots read "" and children read their parent', () => {
  // Bound to revenueRequest's own SET expressions: delete F03, or read $Parent bare, and this
  // fails. The hand-written-fixture tests above do not.
  const book: FakeGroup[] = [
    { name: 'Sales Accounts', closing: '500000.00', parent: PRIMARY_SYSNAME },
    { name: 'Sales - Domestic', closing: '300000.00', parent: 'Sales Accounts' },
    { name: 'Indirect Expenses', closing: '-120000.00', parent: PRIMARY_SYSNAME },
  ];

  for (const blank of ['omit', 'emit'] as const) {
    const rows = askRevenue(book, blank);
    assert.equal(rows.length, 3, blank);
    assert.deepEqual(rows.map(parentOfRow), ['', 'Sales Accounts', ''], `parents (${blank})`);
    // The amount must not have moved to make room for the parent.
    assert.deepEqual(rows.map((r) => r[1]), ['500000.00', '300000.00', '-120000.00'], blank);
    assert.deepEqual(rows.map((r) => r[0]), book.map((g) => g.name), blank);
  }
});

test('the shipped request de-duplicates a nested tree and leaves a flat tree alone', () => {
  // A local mirror of profitCard's rule (a row is a child only when its parent is present as a row
  // in the same pull). viewmodel owns the real one; this asserts the COLUMN drives it correctly.
  const topLevelOf = (rows: string[][]) => {
    const names = new Set(rows.map((r) => r[0]!));
    return rows.filter((r) => parentOfRow(r) === '' || !names.has(parentOfRow(r))).map((r) => r[0]!);
  };

  for (const blank of ['omit', 'emit'] as const) {
    // Nested: the child must be suppressed, or its parent's balance counts it twice.
    assert.deepEqual(
      topLevelOf(
        askRevenue(
          [
            { name: 'Sales Accounts', closing: '500000.00', parent: PRIMARY_SYSNAME },
            { name: 'Sales - Domestic', closing: '300000.00', parent: 'Sales Accounts' },
            { name: 'Indirect Expenses', closing: '-120000.00', parent: PRIMARY_SYSNAME },
          ],
          blank,
        ),
      ),
      ['Sales Accounts', 'Indirect Expenses'],
      `nested (${blank})`,
    );

    // Flat: every row is top-level, exactly as before this column existed.
    assert.deepEqual(
      topLevelOf(
        askRevenue(
          [
            { name: 'Sales Accounts', closing: '500000.00', parent: PRIMARY_SYSNAME },
            { name: 'Indirect Expenses', closing: '-120000.00', parent: PRIMARY_SYSNAME },
          ],
          blank,
        ),
      ),
      ['Sales Accounts', 'Indirect Expenses'],
      `flat (${blank})`,
    );
  }
});

test('a book containing a GROUP named "Primary" does not lose its roots', () => {
  // The understatement trap, driven through the real request. With a bare `$Parent` read every root
  // carries "Primary", and here that string RESOLVES to a real row — so both roots would read as
  // children of it and drop out of the sum. $$SysName:Primary is what stops that, and this is the
  // book that tells the two apart. (Raw $Parent survives every other test in this file by accident.)
  for (const blank of ['omit', 'emit'] as const) {
    const rows = askRevenue(
      [
        { name: 'Primary', closing: '400000.00', parent: PRIMARY_SYSNAME },
        { name: 'Indirect Expenses', closing: '-120000.00', parent: PRIMARY_SYSNAME },
      ],
      blank,
    );
    assert.deepEqual(rows.map(parentOfRow), ['', ''], `both roots are parentless (${blank})`);

    const names = new Set(rows.map((r) => r[0]!));
    const topLevel = rows.filter((r) => parentOfRow(r) === '' || !names.has(parentOfRow(r)));
    assert.equal(topLevel.length, 2, `neither root is swallowed by the group named Primary (${blank})`);
  }
});

test('a root reads as top-level even when its own name is Devanagari or contains an ampersand', () => {
  // `&` is the one character Tally does escape, and it is unescaped LAST, per cell — so a name
  // containing it must survive into the parent column byte-for-byte or the presence rule misses.
  const rows = askRevenue([
    { name: 'Café & Sons', closing: '500000.00', parent: PRIMARY_SYSNAME },
    { name: 'देवनागरी बिक्री', closing: '300000.00', parent: 'Café & Sons' },
  ]);
  assert.deepEqual(rows.map((r) => r[0]), ['Café & Sons', 'देवनागरी बिक्री']);
  assert.deepEqual(rows.map(parentOfRow), ['', 'Café & Sons']);
  // The child's parent must MATCH the parent row's name, or the child is wrongly counted again.
  assert.equal(parentOfRow(rows[1]!), rows[0]![0], 'the parent column must join to the name column');
});

test('a revenue group whose NAME forges a field tag loses the section loudly, not one row quietly', () => {
  // The product rule: a wrong number is worse than a missing one. Both the low tag (which cuts the
  // row) and a high tag (which extends it) must be refused rather than published with a truncated
  // parent that silently reads as top-level and double-counts.
  for (const hostile of ['Sales <F02> Ltd', 'Sales <F09> Ltd', '<F01>']) {
    assert.throws(
      () =>
        askRevenue([
          { name: hostile, closing: '500000.00', parent: PRIMARY_SYSNAME },
          { name: 'Sales - Domestic', closing: '300000.00', parent: hostile },
        ]),
      /structurally invalid/,
      hostile,
    );
  }
});

test('a malformed date is refused rather than sent to Tally', () => {
  for (const bad of ['2026-13-01', '2026-00-01', '2026-1-1', '99999-01-01', '', 'today']) {
    assert.throws(() => toTallyDate(bad), bad);
  }
  assert.equal(toTallyDate('2026-01-01'), '1-Jan-2026');
  assert.equal(toTallyDate('2026-12-31'), '31-Dec-2026');
});
