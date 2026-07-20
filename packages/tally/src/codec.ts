/**
 * Decoding Tally's responses.
 *
 * Two independent problems live here: what ENCODING the bytes are in, and the fact that the
 * "XML" Tally produces is frequently not well-formed XML at all.
 */

export type TallyEncoding = 'utf16le' | 'utf8';

/**
 * Decode a response body, sniffing the encoding rather than assuming it.
 *
 * The research conflicts here and both sides are probably right for different builds: the one
 * serious production implementation uses UTF-16LE with `charset=utf-16`, while Tally's own docs
 * say UTF-8. Tally also has an ASCII/Unicode export toggle. Hardcoding either is the single
 * most likely cause of "works on my machine, garbage on the customer's", so we detect.
 */
export function decodeTallyResponse(buf: Buffer): string {
  // BOMs are unambiguous, take them first.
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le');
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    return decodeUtf16be(buf.subarray(2));
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.subarray(3).toString('utf8');
  }

  // No BOM. Tally's payload is overwhelmingly ASCII-range characters, so if it is UTF-16 then
  // one byte of every character is 0x00 — at ODD offsets for LE, at EVEN offsets for BE.
  // Sampling the head is enough: we only need to choose between three candidates, not identify
  // an arbitrary charset.
  //
  // Both parities must be counted. Counting only the odd ones left BOM-less UTF-16BE looking
  // like UTF-8, which decodes to NUL-laced mojibake that fails `looksLikeTallyResponse` — so a
  // Tally answering perfectly well was reported to the owner as "another program is using port
  // 9000". Mojibake must never be a decode outcome; the two-parity test makes the choice total.
  const probe = buf.subarray(0, Math.min(512, buf.length));
  let zerosAtOdd = 0;
  let zerosAtEven = 0;
  for (let i = 0; i < probe.length; i++) {
    if (probe[i] === 0) {
      if (i % 2 === 0) zerosAtEven++;
      else zerosAtOdd++;
    }
  }
  // A quarter of the sampled bytes being NUL is decisive: valid UTF-8 text never contains NUL
  // at all, so any meaningful count means UTF-16. The floor is 2 bytes rather than 4 — a
  // 2-byte UTF-16LE body is still UTF-16, and decoding it as UTF-8 kept the NUL.
  if (probe.length >= 2) {
    const decisive = probe.length / 4;
    if (zerosAtOdd > decisive) return buf.toString('utf16le');
    if (zerosAtEven > decisive) return decodeUtf16be(buf);
  }
  return buf.toString('utf8');
}

/** Node has no 'utf16be'; swap to LE first. swap16 needs an even length. */
function decodeUtf16be(body: Buffer): string {
  const even = body.length % 2 === 0 ? body : body.subarray(0, body.length - 1);
  return Buffer.from(even).swap16().toString('utf16le');
}

export function encodeTallyRequest(xml: string, encoding: TallyEncoding): Buffer {
  return encoding === 'utf16le' ? Buffer.from(xml, 'utf16le') : Buffer.from(xml, 'utf8');
}

/** The Content-Type Tally expects for each request encoding. */
export function contentTypeFor(encoding: TallyEncoding): string {
  return encoding === 'utf16le' ? 'text/xml;charset=utf-16' : 'text/xml;charset=utf-8';
}

/**
 * Turn an XMLTAG response into rows of fields.
 *
 * ## What this is, and the claim that used to be here
 *
 * Tally's XML is routinely invalid: bare `&` in party names, unescaped `<` in narrations,
 * `&#4;` control characters, unclosed tags. A conforming XML parser is the wrong tool for a
 * non-conforming producer — it will throw on exactly the payloads we must survive. So we do not
 * use one. We control the output schema (we inject our own TDL with `<XMLTAG>F01</XMLTAG>`), so
 * the response is flat, unnested, attribute-free, and uses a fixed two-digit `F\d\d` alphabet:
 *
 *     <ENVELOPE><F01>Cash-in-Hand</F01><F02>Current Assets</F02><F03>125000.00</F03><F01>Bank...
 *
 * This file used to claim the parse was "structurally immune to malformed content". **That was
 * false, and it was false in the one direction that matters.** The old parser rewrote `<F01>`
 * to a newline and every other `<F\d+>` to a tab, then split. Content is not immune to a
 * delimiter alphabet it can contain: a party genuinely named `A & B <F02> Traders` produced
 * THREE columns where two were expected, so every consumer that reads a fixed index read the
 * amount from the wrong column; a name containing `<F01>` fabricated an entire row. The canary
 * test one screen down proves Tally emits raw `<` and `>` in field content, so this is not
 * theoretical. Both failures were silent, and a silently wrong number is the worst thing this
 * product can do.
 *
 * ## What replaces it
 *
 * Positions are no longer derived from ARRIVAL ORDER. They are derived from the TAG ITSELF:
 * the value of `<F04>` lands at column 4, always, whatever else the stream contains. That single
 * change makes a column shift IMPOSSIBLE rather than unlikely — the wrong-column read cannot be
 * expressed any more. It also makes the parse robust to the open FLDBLANK question (does Tally
 * emit a tag for a blank field, or omit it?) *without answering it*: an omitted tag leaves its
 * own column empty and moves nothing.
 *
 * That last property is the answer to the obvious objection — "a strict parser keyed on the
 * expected field count fails EVERY row if Tally omits blank tags". This parser requires NO tag
 * to be present except F01, so omission costs nothing.
 *
 * Rows are cut where the tag number stops increasing (`F06` then `F02` = a new row), not at
 * F01 — so a row whose F01 was omitted is not silently merged into its predecessor.
 *
 * A row that cannot be trusted is REJECTED WHOLE and reported, never repaired and never
 * silently dropped:
 *   - no F01 at all — debris left behind by a `<F02>`-shaped injection, or a genuinely blank
 *     party under the omission hypothesis, which is the exact condition `assertBillsLookSane`
 *     already refuses to sync;
 *   - only F01 and nothing else, when the schema is wider — debris from a `<F01>`-shaped
 *     injection. No request in the catalog can legitimately produce this: every field after
 *     F01 is an `if $$IsEmpty ... else ...` idiom or a logical, so it always has a value;
 *   - a tag outside the schema (`F00`, or beyond `fieldCount` when the caller supplies it).
 *
 * `xmlTagResponseToRows` THROWS on any rejection. That is deliberate and it is the product rule:
 * one hostile party name should lose the SECTION loudly, not one row quietly, because a dropped
 * row makes the "Total Receivables" card quietly wrong — and a wrong number on the dashboard is
 * far worse than a missing one. Callers that must survive a bad row (the capability prober,
 * which is *supposed* to reject variants) use `parseTagRows` and inspect the rejections.
 *
 * Order of operations still matters and is still not arbitrary:
 *   1. strip the envelope
 *   2. drop FLDBLANK markers
 *   3. neutralize any literal CR/LF/TAB in CONTENT (values must not carry them downstream)
 *   4. drop end tags
 *   5. tokenize on START tags only; the tag number IS the column index
 *   6. unescape entities LAST, per cell — so a field containing the literal text `&lt;F01&gt;`
 *      cannot turn into a delimiter after we have already tokenized
 */

/**
 * The delimiter alphabet, pinned to EXACTLY two digits.
 *
 * `<F\d+>` was looser than the schema `buildRequest` can emit, which bought nothing and cost
 * reach: it made `<F1>` and `<F0001>` delimiters too, widening the set of party names that can
 * forge one. Two digits is what we ask for and two digits is all we honour; anything else is
 * inert content. `buildRequest` enforces the other half of this contract.
 */
const START_TAG = /<F(\d{2})>/g;
const END_TAG = /<\/F\d{2}>/g;
const MAX_FIELD_TAG = 99;

export interface RowRejection {
  /** Index of the row within the response, counting rejected rows. */
  row: number;
  reason: string;
  /** Tag numbers seen, in arrival order. */
  tags: number[];
}

export interface TagRowsResult {
  rows: string[][];
  rejected: RowRejection[];
}

/**
 * A response that does not match the schema we asked Tally for.
 *
 * Carries tag numbers and counts and NOTHING ELSE. The diagnostic that would help most — the
 * offending party name — is exactly the customer's financial data, and this message travels to
 * logs and to support. The tags are enough to identify the shape of the problem.
 */
export class TallyRowStructureError extends Error {
  readonly rejected: RowRejection[];
  readonly acceptedRows: number;

  constructor(rejected: RowRejection[], acceptedRows: number) {
    const first = rejected[0];
    super(
      `Tally's response does not match the schema we asked for: ${rejected.length} of ` +
        `${rejected.length + acceptedRows} rows are structurally invalid` +
        (first ? ` (row ${first.row}: ${first.reason}; tags ${JSON.stringify(first.tags)})` : '') +
        '. The usual cause is a name in the book that contains our own field-tag text, such as ' +
        'a party literally named "<F02>". Refusing to parse rather than publish a number read ' +
        'from the wrong column.',
    );
    this.name = 'TallyRowStructureError';
    this.rejected = rejected;
    this.acceptedRows = acceptedRows;
  }
}

export interface TagRowsOptions {
  /**
   * How many fields the REQUEST declared — see `fieldCountOfRequest`.
   *
   * Optional, and the parse is correct without it: tag-indexing does not need to know the width.
   * Supplying it only buys extra checks (a tag beyond the schema) and a uniform row width.
   */
  fieldCount?: number | undefined;
}

/**
 * Parse, and report structurally invalid rows instead of throwing.
 *
 * The primitive. Prefer `xmlTagResponseToRows` unless you genuinely have a policy for bad rows.
 */
export function parseTagRows(xml: string, opts: TagRowsOptions = {}): TagRowsResult {
  let s = xml;

  // 1. Envelope wrapper.
  s = s.replace(/<\/?ENVELOPE>/g, '');

  // 2. Tally emits FLDBLANK for empty fields; it carries no information.
  //
  //    Matched permissively, because the exact spelling is NOT verified against a real Tally and
  //    the cost of missing it is not a missing empty string — it is the literal markup
  //    "<FLDBLANK></FLDBLANK>" sitting in the cell as a NON-EMPTY value. In the party column
  //    that defeats every "is this name blank" gate we have (`assertBillsLookSane`,
  //    `probeBillsVariant`), so the capability probe would happily ACCEPT a party method that
  //    resolves to nothing and publish a dashboard of debtors named "<FLDBLANK></FLDBLANK>".
  //    Self-closing, whitespace, mixed case and Tally's `&#4;` padding are all accepted.
  //
  //    The inner alternation is unambiguous on its first character (whitespace vs `&`), so this
  //    cannot backtrack catastrophically on a run of unclosed <FLDBLANK> tags.
  s = s.replace(/<FLDBLANK\s*\/>|<FLDBLANK\s*>(?:\s|&#[0-9a-fA-FxX]+;)*<\/FLDBLANK\s*>/gi, '');

  // 3. A literal newline or tab inside a value has no business travelling downstream into JSON
  //    and canonical serialization. Collapse to spaces.
  s = s.replace(/[\r\n\t]+/g, ' ');

  // 4. End tags carry no information once the schema is flat.
  s = s.replace(END_TAG, '');

  // 5. Tokenize on START tags. Text before the first tag is envelope noise and is discarded.
  const toks: Array<{ tag: number; value: string }> = [];
  let openTag = -1;
  let openAt = 0;
  for (const m of s.matchAll(START_TAG)) {
    if (openTag >= 0) toks.push({ tag: openTag, value: s.slice(openAt, m.index) });
    openTag = Number(m[1]);
    openAt = m.index + m[0].length;
  }
  if (openTag >= 0) toks.push({ tag: openTag, value: s.slice(openAt) });

  // The schema width, for the "F01 and nothing else" check. When the caller did not tell us, the
  // widest tag in the response is a sound stand-in: it cannot be inflated below the truth, and
  // over-inflating it (an injected `<F42>`) only ever costs padding, never a position.
  const observedWidth = toks.reduce((a, t) => Math.max(a, t.tag), 0);
  const schemaWidth = opts.fieldCount ?? observedWidth;

  const rows: string[][] = [];
  const rejected: RowRejection[] = [];
  let rowIndex = 0;

  let cur = new Map<number, string>();
  let curTags: number[] = [];
  let lastTag = MAX_FIELD_TAG + 1;

  const flush = () => {
    if (curTags.length === 0) return;
    const reason = rejectionReason(curTags, schemaWidth, opts.fieldCount);
    if (reason) {
      // Deliberately NOT materialized: a hostile response could otherwise make us allocate a
      // padded row per token.
      rejected.push({ row: rowIndex, reason, tags: curTags });
    } else {
      const width = opts.fieldCount ?? Math.max(...curTags);
      const out: string[] = new Array(width);
      for (let i = 0; i < width; i++) out[i] = unescapeEntities(cur.get(i + 1) ?? '').trim();
      rows.push(out);
    }
    rowIndex++;
  };

  for (const t of toks) {
    // A tag that does not advance ends the row. Cutting here rather than at F01 is what stops a
    // row with an omitted F01 from being swallowed by its predecessor.
    if (t.tag <= lastTag) {
      flush();
      cur = new Map();
      curTags = [];
    }
    cur.set(t.tag, t.value);
    curTags.push(t.tag);
    lastTag = t.tag;
  }
  flush();

  return { rows, rejected };
}

function rejectionReason(
  tags: number[],
  schemaWidth: number,
  fieldCount: number | undefined,
): string | undefined {
  for (const t of tags) {
    if (t < 1) return `tag F${String(t).padStart(2, '0')} is not in the schema`;
    if (fieldCount !== undefined && t > fieldCount) {
      return `tag F${String(t).padStart(2, '0')} is beyond the ${fieldCount} fields we asked for`;
    }
  }
  if (!tags.includes(1)) return 'row has no F01';
  // Every field after F01 in the catalog is a logical, a number, or an `if $$IsEmpty` idiom, so
  // it always carries a value. A row with F01 alone is debris, not data.
  if (schemaWidth >= 2 && tags.length < 2) return 'row has F01 and nothing else';
  return undefined;
}

/**
 * Turn an XMLTAG response into rows of fields, throwing if any row is structurally invalid.
 *
 * The default and the one you want. See the essay above for why throwing is the correct policy
 * and not merely the conservative one.
 */
export function xmlTagResponseToRows(xml: string, opts: TagRowsOptions = {}): string[][] {
  const { rows, rejected } = parseTagRows(xml, opts);
  if (rejected.length > 0) throw new TallyRowStructureError(rejected, rows.length);
  return rows;
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

/** Decimal ref, hex ref, or one of the five named entities — matched as ONE alternation. */
const ENTITY = /&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));/g;

/**
 * Decode XML entities in a SINGLE pass.
 *
 * Two things are load-bearing here.
 *
 * **One pass, not a chain of `.replace()` calls.** `String.replace` with a global regex resumes
 * scanning AFTER each replacement and never re-examines what it just wrote, so a decoded entity
 * can never be decoded twice. A chain has to be ordered by hand and is wrong in both directions
 * at once: with `&amp;` last, `&#38;amp;` decodes to `&amp;` and then to `&`; with `&amp;`
 * first, `&amp;lt;` decodes to `&lt;` and then to `<`. One pass makes the ordering question
 * disappear rather than answering it.
 *
 * **Only CONTROL references are dropped.** This previously deleted every `&#\d+;`, justified by
 * "Tally emits &#4; and friends; they are never meaningful data". That is true of C0 controls
 * and false of every other character: `&#233;` is `é` and `&#8377;` is `₹`. The old rule renamed
 * "Café Traders" to "Caf Traders", emptied a Devanagari party name entirely (which reads as the
 * signature of a broken extraction), and — worst — deleted digits, turning an amount of
 * `1&#48;0.00` into `10.00`. Every one of those is silent.
 */
function unescapeEntities(s: string): string {
  return s.replace(ENTITY, (_match, dec?: string, hex?: string, named?: string) => {
    if (named !== undefined) return NAMED_ENTITIES[named]!;

    const code = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex!, 16);

    // Outside Unicode: `String.fromCodePoint` would throw. Drop it.
    if (!Number.isFinite(code) || code > 0x10ffff) return '';
    // C0/C1 controls: Tally's `&#4;` padding. Never data, and would corrupt downstream JSON.
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return '';
    // A lone surrogate is an unpaired code unit that survives into a string but cannot be
    // encoded downstream. Tally has no reason to emit one and we have no way to repair it.
    if (code >= 0xd800 && code <= 0xdfff) return '';

    return String.fromCodePoint(code);
  });
}

/**
 * Tally signals errors inside an otherwise normal-looking response rather than via HTTP status.
 * Detect them by scanning for the fault markers directly — reaching for an XML parser here
 * would reintroduce the throw-on-malformed problem we just designed away.
 */
export function extractTallyError(xml: string): string | undefined {
  const lineError = /<LINEERROR>([\s\S]*?)<\/LINEERROR>/i.exec(xml);
  if (lineError) return unescapeEntities(lineError[1]!.trim());

  const desc = /<DESC>([\s\S]*?)<\/DESC>/i.exec(xml);
  if (/<RESPONSE>/i.test(xml) && desc && /error|invalid|unknown/i.test(desc[1]!)) {
    return unescapeEntities(desc[1]!.trim());
  }
  return undefined;
}

/** Does this look like a Tally response at all, or is something else squatting on :9000? */
export function looksLikeTallyResponse(xml: string): boolean {
  return /<ENVELOPE>|<RESPONSE>|<LINEERROR>/i.test(xml);
}
