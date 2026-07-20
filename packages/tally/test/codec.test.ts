import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TallyRowStructureError,
  decodeTallyResponse,
  extractTallyError,
  looksLikeTallyResponse,
  parseTagRows,
  xmlTagResponseToRows,
} from '../src/codec.ts';

test('parses a flat XMLTAG response into rows', () => {
  const xml =
    '<ENVELOPE>' +
    '<F01>Cash-in-Hand</F01><F02>Current Assets</F02><F03>125000.00</F03>' +
    '<F01>Bank Accounts</F01><F02>Current Assets</F02><F03>342110.75</F03>' +
    '</ENVELOPE>';
  assert.deepEqual(xmlTagResponseToRows(xml), [
    ['Cash-in-Hand', 'Current Assets', '125000.00'],
    ['Bank Accounts', 'Current Assets', '342110.75'],
  ]);
});

test('THE canary: a bare ampersand and angle brackets in a party name do not break the parse', () => {
  // This is the entire justification for not using an XML parser. `A & B Traders <Mumbai>` is
  // invalid XML as Tally emits it, and a conforming parser throws. We must survive it.
  const xml =
    '<ENVELOPE>' +
    '<F01>A & B Traders <Mumbai></F01><F02>100.00</F02>' +
    '<F01>Normal Party</F01><F02>200.00</F02>' +
    '</ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  assert.equal(rows.length, 2);
  assert.equal(rows[0]![0], 'A & B Traders <Mumbai>');
  assert.equal(rows[1]![0], 'Normal Party');
});

test('escaped entities are unescaped, and &amp; is handled last', () => {
  const xml = '<ENVELOPE><F01>A &amp;amp; B</F01><F02>&lt;tag&gt;</F02></ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  // If &amp; were unescaped first, "&amp;amp;" would collapse to "&" instead of "&amp;".
  assert.equal(rows[0]![0], 'A &amp; B');
  assert.equal(rows[0]![1], '<tag>');
});

test('numeric control-character references are stripped', () => {
  // Tally emits &#4; and friends; they are never meaningful and would corrupt JSON.
  const xml = '<ENVELOPE><F01>Party&#4;Name</F01><F02>1.00</F02></ENVELOPE>';
  assert.equal(xmlTagResponseToRows(xml)[0]![0], 'PartyName');
});

test('literal newlines and tabs inside a value cannot forge delimiters', () => {
  // Order matters: CR/LF/TAB must be neutralized BEFORE they are introduced as delimiters.
  const xml = '<ENVELOPE><F01>Line\r\nBreak\tParty</F01><F02>1.00</F02></ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  assert.equal(rows.length, 1, 'an embedded newline must not split a row');
  assert.equal(rows[0]!.length, 2, 'an embedded tab must not split a column');
  assert.equal(rows[0]![0], 'Line Break Party');
});

test('a field containing the literal text of a delimiter tag is inert', () => {
  // Unescaping happens LAST, so "&lt;F01&gt;" becomes text after splitting, never a delimiter.
  const xml = '<ENVELOPE><F01>weird &lt;F01&gt; party</F01><F02>1.00</F02></ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]![0], 'weird <F01> party');
});

test('unclosed tags do not break the parse', () => {
  // End tags are discarded wholesale, so a missing one changes nothing.
  const xml = '<ENVELOPE><F01>Party<F02>100.00</F02><F01>Two</F01><F02>200.00</F02></ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  assert.equal(rows.length, 2);
  assert.equal(rows[0]![0], 'Party');
});

test('an empty FIRST column does not shift every other column left', () => {
  // Regression. `line.trim()` before splitting ate the leading delimiter, so a blank party
  // name silently promoted the bill date into the party column — a non-empty-looking name that
  // passes every sanity check and renders debtors called "2026-01-01".
  const xml =
    '<ENVELOPE><F01></F01><F02>2026-01-01</F02><F03>30</F03><F04>125000.00</F04></ENVELOPE>';
  const rows = xmlTagResponseToRows(xml);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.length, 4, 'the empty first column must still occupy a slot');
  assert.deepEqual(rows[0], ['', '2026-01-01', '30', '125000.00']);
});

test('an empty middle column does not shift the columns after it', () => {
  const xml = '<ENVELOPE><F01>Party</F01><F02></F02><F03>30</F03></ENVELOPE>';
  assert.deepEqual(xmlTagResponseToRows(xml), [['Party', '', '30']]);
});

test('an empty trailing column is preserved', () => {
  const xml = '<ENVELOPE><F01>Party</F01><F02>x</F02><F03></F03></ENVELOPE>';
  assert.deepEqual(xmlTagResponseToRows(xml), [['Party', 'x', '']]);
});

test('FLDBLANK markers are dropped', () => {
  const xml = '<ENVELOPE><F01>P</F01><F02><FLDBLANK></FLDBLANK></F02><F03>1.00</F03></ENVELOPE>';
  assert.deepEqual(xmlTagResponseToRows(xml), [['P', '', '1.00']]);
});

test('an empty response yields no rows', () => {
  assert.deepEqual(xmlTagResponseToRows('<ENVELOPE></ENVELOPE>'), []);
});

test('devanagari survives', () => {
  const xml = '<ENVELOPE><F01>देवनागरी व्यापारी</F01><F02>1.00</F02></ENVELOPE>';
  assert.equal(xmlTagResponseToRows(xml)[0]![0], 'देवनागरी व्यापारी');
});

// ------------------------------------------------- the delimiter alphabet in field CONTENT
//
// The claim this file used to make — "malformed CONTENT cannot break the parse, the parse is
// structurally immune" — was FALSE for content containing our own delimiter alphabet, which the
// canary test above proves Tally emits raw. These pin the fix.

/** The bills schema: F01 party, F02 date, F03 credit days, F04 amount, F05 advance, F06 age. */
const BILLS = { fieldCount: 6 };
const bill = (party: string) =>
  `<F01>${party}</F01><F02>2026-01-01</F02><F03>30</F03><F04>125000.00</F04><F05>0</F05><F06>90</F06>`;

test('THE BUG: a party named <F02> can no longer shift the amount into another column', () => {
  // A party literally named `A & B <F02> Traders` used to produce SEVEN columns where six were
  // expected. Every consumer reads fixed indices — `parseBillRow` takes the amount from index 3 —
  // so the shift silently handed the dashboard a number from the wrong column. It did not error,
  // it did not look wrong, and it was the worst thing this product can do.
  const xml = `<ENVELOPE>${bill('A & B <F02> Traders')}${bill('Normal Party')}</ENVELOPE>`;

  assert.throws(() => xmlTagResponseToRows(xml, BILLS), TallyRowStructureError);

  // And no row that survives may be a MISALIGNED one. The old parser produced seven columns for
  // the hostile bill — ['A & B ', ' Traders', '2026-01-01', '30', '125000.00', '0', '90'] — so
  // `parseBillRow`, reading index 3, took the CREDIT PERIOD as the amount: Rs 30.00.
  const { rows, rejected } = parseTagRows(xml, BILLS);
  assert.ok(rejected.length > 0, 'the injected row must be rejected, not silently reshaped');
  for (const r of rows) {
    assert.equal(r.length, 6, 'a surviving row is exactly the width we asked for');
    assert.match(r[3]!, /^$|^\d+\.\d{2}$/, 'the amount column holds an amount or nothing');
    assert.notEqual(r[3], '30', 'never the credit period');
    assert.notEqual(r[3], '2026-01-01', 'never the bill date');
  }
});

test('THE OTHER BUG: a party named <F01> can no longer fabricate a row', () => {
  // `<F01>` was rewritten to the ROW delimiter, so a name containing it split one bill into two
  // and invented a debtor out of a fragment of a name.
  const xml = `<ENVELOPE>${bill('A & B <F01> Traders')}${bill('Normal Party')}</ENVELOPE>`;
  assert.throws(() => xmlTagResponseToRows(xml, BILLS), /structurally invalid/);

  const { rejected } = parseTagRows(xml, BILLS);
  assert.ok(
    rejected.some((r) => /F01 and nothing else/.test(r.reason)),
    'the fragment left behind by the split is debris and must be named as such',
  );
});

test('one hostile party name loses ONE row at most — never the amount of a DIFFERENT party', () => {
  // The product rule: a wrong number is far worse than a missing one. `Normal Party` is a
  // bystander and its figures must be untouched by its neighbour's name.
  const { rows } = parseTagRows(
    `<ENVELOPE>${bill('<F02>')}${bill('Normal Party')}${bill('Zed Enterprises')}</ENVELOPE>`,
    BILLS,
  );
  const named = rows.filter((r) => r[0] === 'Normal Party' || r[0] === 'Zed Enterprises');
  assert.equal(named.length, 2, 'bystanders survive');
  for (const r of named) assert.deepEqual(r.slice(1), ['2026-01-01', '30', '125000.00', '0', '90']);
});

test('positions come from the TAG, not from arrival order', () => {
  // The whole fix in one line: F04 is column 4 because it says F04, not because it arrived
  // fourth. This is what makes a column shift inexpressible rather than merely unlikely.
  assert.deepEqual(xmlTagResponseToRows('<ENVELOPE><F01>P</F01><F04>9.00</F04></ENVELOPE>', BILLS), [
    ['P', '', '', '9.00', '', ''],
  ]);
});

test('RESIDUAL 2: an OMITTED tag leaves its own column empty and moves nothing', () => {
  // The unverifiable that blocked the previous fix: if `$_PrimaryGroup` is unsupported, does
  // Tally emit `<F03></F03>` or omit F03 entirely? This parser does not need to know. Under the
  // OMISSION hypothesis the old parser shifted every later column left, which silently turned
  // the group oracle's `debtorsHaveBalance` into `IsDeemedPositive` — and the oracle is what the
  // prober cross-checks every variant against, so a wrong oracle picks a wrong dialect with
  // total confidence.
  const groups = { fieldCount: 7 };
  const emitted =
    '<ENVELOPE><F01>Sundry Debtors</F01><F02>Current Assets</F02><F03></F03>' +
    '<F04>0</F04><F05>0.00</F05><F06>-130000.00</F06><F07>0</F07></ENVELOPE>';
  const omitted =
    '<ENVELOPE><F01>Sundry Debtors</F01><F02>Current Assets</F02>' +
    '<F04>0</F04><F05>0.00</F05><F06>-130000.00</F06><F07>0</F07></ENVELOPE>';

  // Both hypotheses decode identically, so the product never has to know which is true.
  assert.deepEqual(xmlTagResponseToRows(omitted, groups), xmlTagResponseToRows(emitted, groups));
  assert.equal(xmlTagResponseToRows(omitted, groups)[0]![5], '-130000.00', 'closing stays at F06');
});

test('the "fails every row" objection: blank fields cost nothing, however Tally spells them', () => {
  // The reason a strict parser keyed on the expected field COUNT was rejected: if Tally omits
  // tags for blank fields, that parser fails EVERY row instead of one. This one requires no tag
  // but F01, so a book full of blank optional fields parses cleanly.
  const groups = { fieldCount: 7 };
  const xml =
    '<ENVELOPE>' +
    // A primary group: $Parent is deliberately "" and _PrimaryGroup is unsupported. Both omitted.
    '<F01>Capital Account</F01><F04>0</F04><F05>0.00</F05><F06>500000.00</F06><F07>1</F07>' +
    '<F01>Sales Accounts</F01><F04>1</F04><F05>0.00</F05><F06>500000.00</F06><F07>0</F07>' +
    '</ENVELOPE>';
  const rows = xmlTagResponseToRows(xml, groups);
  assert.equal(rows.length, 2, 'every row survives');
  assert.deepEqual(rows[0], ['Capital Account', '', '', '0', '0.00', '500000.00', '1']);
});

test('a row whose F01 was omitted is rejected, not merged into the row above it', () => {
  // Rows are cut where the tag number stops increasing, not at F01. The old parser only ever
  // started a row at F01, so a row missing one was appended to its predecessor — quietly losing
  // a bill from a total that still looked authoritative.
  const xml =
    '<ENVELOPE>' +
    bill('Real Party') +
    '<F02>2026-02-01</F02><F03>0</F03><F04>5000.00</F04><F05>0</F05><F06>10</F06>' +
    '</ENVELOPE>';
  const { rows, rejected } = parseTagRows(xml, BILLS);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], ['Real Party', '2026-01-01', '30', '125000.00', '0', '90']);
  assert.equal(rejected.length, 1);
  assert.match(rejected[0]!.reason, /no F01/);
});

test('a tag beyond the schema we asked for is rejected', () => {
  assert.throws(() => xmlTagResponseToRows(`<ENVELOPE>${bill('<F09>')}</ENVELOPE>`, BILLS), {
    name: 'TallyRowStructureError',
  });
  const { rejected } = parseTagRows(`<ENVELOPE>${bill('<F09>')}</ENVELOPE>`, BILLS);
  assert.match(rejected[0]!.reason, /beyond the 6 fields/);
});

test('only EXACTLY two digits are delimiters; anything else is inert content', () => {
  // The alphabet is what buildRequest emits and nothing wider. Honouring `<F1>` or `<F001>` too
  // would only widen the set of party names that can forge a delimiter.
  for (const name of ['<F1>', '<F001>', '<F0>', '<F>', '</F01>x']) {
    const rows = xmlTagResponseToRows(`<ENVELOPE>${bill(name)}</ENVELOPE>`, BILLS);
    assert.equal(rows.length, 1, name);
    assert.equal(rows[0]![3], '125000.00', `${name} must not disturb the amount`);
  }
});

test('realistic hostile party names survive intact and in the right columns', () => {
  for (const name of [
    'A & B Traders <Mumbai>',
    'Café Traders',
    'देवनागरी व्यापारी',
    '__OTHERS__', // collides with core's OTHERS_PARTY sentinel: a codec concern only in that
    '', // it must arrive UNCHANGED for the layer above to notice
    'M/s. O\'Brien & Sons "Ltd" 100% <=50',
  ]) {
    const rows = xmlTagResponseToRows(`<ENVELOPE>${bill(name)}</ENVELOPE>`, BILLS);
    assert.equal(rows.length, 1, name);
    assert.equal(rows[0]![0], name, name);
    assert.equal(rows[0]![3], '125000.00', name);
  }
});

test('the error names the shape of the problem and leaks no customer data', () => {
  // This message reaches logs and support. The single most useful diagnostic — the offending
  // party name — is exactly the financial data this product exists to keep private.
  try {
    xmlTagResponseToRows(`<ENVELOPE>${bill('Ravi Kumar Secret Ltd <F02> x')}</ENVELOPE>`, BILLS);
    assert.fail('must throw');
  } catch (e) {
    const err = e as TallyRowStructureError;
    assert.ok(err instanceof TallyRowStructureError);
    assert.doesNotMatch(err.message, /Ravi|Secret/, 'must not quote the book back at the logs');
    assert.match(err.message, /wrong column/);
    assert.deepEqual(err.rejected[0]!.tags, [2, 3, 4, 5, 6]);
  }
});

test('parseTagRows reports instead of throwing, for the one caller with a policy', () => {
  // The capability prober's whole job is rejecting variants; a throw there would abort the probe
  // on exactly the evidence it exists to weigh.
  const { rows, rejected } = parseTagRows(`<ENVELOPE>${bill('<F02>')}${bill('Ok')}</ENVELOPE>`, BILLS);
  assert.equal(rows.length + rejected.length, 3);
  assert.ok(rows.some((r) => r[0] === 'Ok'));
});

// ---------------------------------------------------------------- encoding

test('decodes UTF-16LE with a BOM', () => {
  const text = '<ENVELOPE><F01>Test</F01></ENVELOPE>';
  const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
  assert.equal(decodeTallyResponse(buf), text);
});

test('decodes UTF-16BE with a BOM', () => {
  const text = '<ENVELOPE><F01>Test</F01></ENVELOPE>';
  const le = Buffer.from(text, 'utf16le');
  const be = Buffer.from(le).swap16();
  assert.equal(decodeTallyResponse(Buffer.concat([Buffer.from([0xfe, 0xff]), be])), text);
});

test('decodes UTF-8 with a BOM', () => {
  const text = '<ENVELOPE><F01>Test</F01></ENVELOPE>';
  const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, 'utf8')]);
  assert.equal(decodeTallyResponse(buf), text);
});

test('sniffs BOM-less UTF-16LE via NUL bytes at odd offsets', () => {
  // The realistic case: production Tally reportedly answers in UTF-16LE without a BOM.
  const text = '<ENVELOPE><F01>Cash-in-Hand</F01><F02>125000.00</F02></ENVELOPE>';
  assert.equal(decodeTallyResponse(Buffer.from(text, 'utf16le')), text);
});

test('sniffs BOM-less UTF-8', () => {
  const text = '<ENVELOPE><F01>Cash-in-Hand</F01><F02>125000.00</F02></ENVELOPE>';
  assert.equal(decodeTallyResponse(Buffer.from(text, 'utf8')), text);
});

test('sniffs BOM-less UTF-8 carrying multi-byte characters', () => {
  // Devanagari in UTF-8 has no NUL bytes, so the heuristic must not misfire into UTF-16.
  const text = '<ENVELOPE><F01>देवनागरी</F01></ENVELOPE>';
  assert.equal(decodeTallyResponse(Buffer.from(text, 'utf8')), text);
});

test('an odd-length UTF-16BE body does not throw', () => {
  // swap16 requires an even length; a truncated response must degrade, not crash.
  const be = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from([0x00, 0x41, 0x00])]);
  assert.doesNotThrow(() => decodeTallyResponse(be));
});

// ---------------------------------------------------------------- faults

test('detects a LINEERROR fault', () => {
  const xml = '<ENVELOPE><LINEERROR>Could not find Report TSGroups</LINEERROR></ENVELOPE>';
  assert.equal(extractTallyError(xml), 'Could not find Report TSGroups');
});

test('unescapes entities inside a fault message', () => {
  const xml = '<ENVELOPE><LINEERROR>Bad &amp; broken</LINEERROR></ENVELOPE>';
  assert.equal(extractTallyError(xml), 'Bad & broken');
});

test('a normal response is not mistaken for a fault', () => {
  const xml = '<ENVELOPE><F01>Cash</F01><F02>1.00</F02></ENVELOPE>';
  assert.equal(extractTallyError(xml), undefined);
});

test('recognizes Tally responses and rejects impostors on port 9000', () => {
  assert.ok(looksLikeTallyResponse('<ENVELOPE><F01>x</F01></ENVELOPE>'));
  assert.ok(looksLikeTallyResponse('<RESPONSE><DESC>x</DESC></RESPONSE>'));
  // Something else squatting on :9000 — must be a hard, distinguishable error.
  assert.equal(looksLikeTallyResponse('<!DOCTYPE html><html><body>Hi</body></html>'), false);
  assert.equal(looksLikeTallyResponse('{"jsonrpc":"2.0"}'), false);
});

// ---------------------------------------------------------------- entity decoding (regression)

test('a numeric reference for a REAL character is decoded, not deleted', () => {
  // Regression. The stripper was `/&#\d+;/g -> ''`, justified by "Tally emits &#4; and friends;
  // they are never meaningful". That is true of CONTROL characters and false of everything else.
  // `&#233;` is `é`. Deleting it renamed "Café Traders" to "Caf Traders" — a real party silently
  // reattributed, with no error anywhere.
  assert.equal(
    xmlTagResponseToRows('<ENVELOPE><F01>Caf&#233; Traders</F01><F02>1.00</F02></ENVELOPE>')[0]![0],
    'Café Traders',
  );
  assert.equal(
    xmlTagResponseToRows('<ENVELOPE><F01>&#8377; Store</F01><F02>1.00</F02></ENVELOPE>')[0]![0],
    '₹ Store',
  );
});

test('a party name written entirely as numeric references does not become an EMPTY name', () => {
  // Worse than corruption: deleting every reference emptied the party column, which is the exact
  // signature `assertBillsLookSane` treats as "the party method is wrong". A Devanagari-named
  // customer could therefore make the Bridge refuse to sync, or make the capability probe
  // reject a CORRECT variant.
  const rows = xmlTagResponseToRows('<ENVELOPE><F01>&#2342;&#2375;&#2357;</F01><F02>1.00</F02></ENVELOPE>');
  assert.equal(rows[0]![0], 'देव');
});

test('THE money case: a numeric reference inside an amount is decoded, not deleted', () => {
  // `&#48;` is the digit `0`. Deleting it turned "100.00" into "10.00" — a silently correct-
  // looking amount, off by a factor of ten, that parses cleanly and reaches the dashboard.
  assert.equal(
    xmlTagResponseToRows('<ENVELOPE><F01>P</F01><F02>1&#48;0.00</F02></ENVELOPE>')[0]![1],
    '100.00',
  );
});

test('hex numeric references are handled too', () => {
  // `&#x4;` is the same control character as `&#4;` and must be dropped the same way; the
  // decimal-only stripper left the literal text "&#x4;" sitting in a party name.
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>P&#x4;Q</F01><F02>1.00</F02></ENVELOPE>')[0]![0], 'PQ');
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>&#x41;&#X42;</F01></ENVELOPE>')[0]![0], 'AB');
});

test('control-character references are still dropped', () => {
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>P&#4;Q</F01><F02>1.00</F02></ENVELOPE>')[0]![0], 'PQ');
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>P&#0;&#31;&#127;Q</F01></ENVELOPE>')[0]![0], 'PQ');
});

test('a numeric reference cannot forge a delimiter or an unpaired surrogate', () => {
  // Decoding happens after splitting, so even `&#10;` (newline) and `&#9;` (tab) are inert as
  // delimiters — but they must not survive into the value either. And a lone surrogate would
  // produce a string that cannot be JSON-encoded downstream.
  const rows = xmlTagResponseToRows('<ENVELOPE><F01>A&#10;B&#9;C</F01><F02>1.00</F02></ENVELOPE>');
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.length, 2);
  assert.equal(rows[0]![0], 'ABC');

  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>A&#55296;B</F01></ENVELOPE>')[0]![0], 'AB');
  // Out of Unicode range entirely: drop rather than throw.
  assert.doesNotThrow(() => xmlTagResponseToRows('<ENVELOPE><F01>A&#99999999;B</F01></ENVELOPE>'));
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>A&#99999999;B</F01></ENVELOPE>')[0]![0], 'AB');
});

test('entity decoding is single-pass: a decoded entity is never re-decoded', () => {
  // `&#38;` is `&`. If numeric refs were decoded in a separate pass before `&amp;`, then
  // "&#38;amp;" would decode to "&amp;" and then to "&" — losing a level of escaping.
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>A&#38;amp;B</F01></ENVELOPE>')[0]![0], 'A&amp;B');
  // And the mirror: "&amp;#4;" must stay literal text, not become a control ref and vanish.
  assert.equal(xmlTagResponseToRows('<ENVELOPE><F01>A&amp;#4;B</F01></ENVELOPE>')[0]![0], 'A&#4;B');
});

// ---------------------------------------------------------------- FLDBLANK (regression)

test('FLDBLANK is recognized in every shape Tally might emit it', () => {
  // The matcher was the exact literal `<FLDBLANK></FLDBLANK>`. Any other shape left the MARKUP
  // sitting in the cell as a non-empty string — and a party column reading
  // "<FLDBLANK></FLDBLANK>" passes every "is this name non-empty" gate we have, so the
  // capability probe would ACCEPT a party method that returns nothing.
  const cell = (xml: string) => xmlTagResponseToRows(xml)[0]![1];
  assert.equal(cell('<ENVELOPE><F01>P</F01><F02><FLDBLANK/></F02><F03>1.00</F03></ENVELOPE>'), '');
  assert.equal(cell('<ENVELOPE><F01>P</F01><F02><FLDBLANK />"</F02><F03>1.00</F03></ENVELOPE>'), '"');
  assert.equal(cell('<ENVELOPE><F01>P</F01><F02><FLDBLANK>\n</FLDBLANK></F02><F03>1.00</F03></ENVELOPE>'), '');
  assert.equal(cell('<ENVELOPE><F01>P</F01><F02><FLDBLANK>&#4;</FLDBLANK></F02><F03>1.00</F03></ENVELOPE>'), '');
  assert.equal(cell('<ENVELOPE><F01>P</F01><F02><fldblank></fldblank></F02><F03>1.00</F03></ENVELOPE>'), '');
});

// ---------------------------------------------------------------- encoding (regression)

test('BOM-less UTF-16BE is decoded, not handed back as NUL-laced mojibake', () => {
  // The sniffer only counted NULs at ODD offsets, so it saw UTF-16BE (NULs at EVEN offsets) as
  // UTF-8. The result decoded to "\0<\0E\0N\0V..." which does not match the envelope probe, so
  // the owner was told "Another program is using port 9000" while Tally was answering fine.
  const text = '<ENVELOPE><F01>Cash-in-Hand</F01><F02>125000.00</F02></ENVELOPE>';
  const be = Buffer.from(Buffer.from(text, 'utf16le')).swap16();
  assert.equal(decodeTallyResponse(be), text);
  assert.ok(looksLikeTallyResponse(decodeTallyResponse(be)));
});

test('a short BOM-less UTF-16LE body is still sniffed as UTF-16', () => {
  // The `probe.length >= 4` floor meant a 2-byte body decoded as UTF-8 and kept its NUL.
  assert.equal(decodeTallyResponse(Buffer.from('A', 'utf16le')), 'A');
});

test('a UTF-8 response is never mistaken for UTF-16', () => {
  // The other direction of the same knob, and the more dangerous one: mojibake instead of an
  // error. Valid UTF-8 text contains no NULs at all, so no legitimate payload can trip it.
  for (const text of [
    '<ENVELOPE><F01>Cash-in-Hand</F01><F02>125000.00</F02></ENVELOPE>',
    '<ENVELOPE><F01>देवनागरी व्यापारी</F01></ENVELOPE>',
    '<ENVELOPE><F01>A</F01></ENVELOPE>',
    '<ENVELOPE></ENVELOPE>',
  ]) {
    assert.equal(decodeTallyResponse(Buffer.from(text, 'utf8')), text, text);
  }
});

test('degenerate bodies decode without throwing', () => {
  assert.equal(decodeTallyResponse(Buffer.alloc(0)), '');
  assert.equal(decodeTallyResponse(Buffer.from([0xff, 0xfe])), '');
  assert.equal(decodeTallyResponse(Buffer.from([0xfe, 0xff])), '');
  assert.equal(decodeTallyResponse(Buffer.from([0xef, 0xbb, 0xbf])), '');
  assert.equal(decodeTallyResponse(Buffer.from([0x41])), 'A');
});

// ---------------------------------------------------------------- ReDoS

test('no regex in the parser backtracks catastrophically', () => {
  // Party names are attacker-influenceable — a supplier names themselves whatever they like —
  // and the parser is a pile of regexes. Every one of them must be linear.
  const inputs = [
    '<ENVELOPE>' + '<F01>'.repeat(50_000) + '</ENVELOPE>',
    '<ENVELOPE><F' + '9'.repeat(50_000) + '</ENVELOPE>',
    '<ENVELOPE><F01>' + '&#'.repeat(50_000) + '</F01></ENVELOPE>',
    '<ENVELOPE><F01>' + '&amp;'.repeat(50_000) + '</F01></ENVELOPE>',
    '<ENVELOPE><F01>' + '<FLDBLANK>'.repeat(50_000) + '</F01></ENVELOPE>',
    '<ENVELOPE><F01>' + '&#x'.repeat(50_000) + '</F01></ENVELOPE>',
    // The tokenizer's own shapes. Every one of these is a row boundary, so they are also the
    // worst case for row construction, not just for the regex.
    '<ENVELOPE>' + '<F99>'.repeat(50_000) + '</ENVELOPE>',
    '<ENVELOPE>' + '<F01><F02>'.repeat(25_000) + '</ENVELOPE>',
    '<ENVELOPE>' + '<F01></F01>'.repeat(25_000) + '</ENVELOPE>',
    '<ENVELOPE><F01>' + '<F'.repeat(50_000) + '</F01></ENVELOPE>',
  ];
  for (const input of inputs) {
    const t = Date.now();
    // These are hostile SHAPES; whether they parse or are rejected is the point of other tests.
    try {
      xmlTagResponseToRows(input);
    } catch {
      /* a rejection is a fine outcome — taking two seconds to reach it is not */
    }
    extractTallyError(input);
    assert.ok(Date.now() - t < 2_000, `parse blew up on a ${input.length}-char input`);
  }

  // A single `<F99>` must not let a response inflate every row to 99 columns: rows are only
  // widened to the schema when the CALLER states it, and the caller gets it from its own request.
  const inflate = '<ENVELOPE>' + '<F01>x<F02>y'.repeat(20_000) + '<F99>z</ENVELOPE>';
  const t0 = Date.now();
  const { rows } = parseTagRows(inflate);
  assert.ok(rows.every((r) => r.length <= 2 || r.length === 99));
  assert.ok(Date.now() - t0 < 2_000, 'a widened tag must not make row construction quadratic');
  // An unterminated fault marker must not make the lazy scan quadratic.
  const t = Date.now();
  extractTallyError('<LINEERROR>' + 'a'.repeat(1_000_000));
  assert.ok(Date.now() - t < 2_000);
});
