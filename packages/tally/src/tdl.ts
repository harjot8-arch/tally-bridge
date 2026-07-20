/**
 * TDL request construction.
 *
 * The governing decision: WE INJECT OUR OWN TDL AND NEVER REQUEST A BUILT-IN REPORT.
 *
 * Asking Tally for `<ID>Balance Sheet</ID>` looks easier and is a trap. Built-in reports return
 * display-oriented tag soup (DSPACCNAME/DSPDISPNAME/DSPCLDRAMT), nest by display-explosion
 * depth, change shape with the user's Alt+F1 detail level, and — critically — are the one
 * surface that genuinely differs between Tally.ERP 9 and TallyPrime. Injecting our own
 * REPORT/FORM/PART/LINE/FIELD walking a COLLECTION means we own the output schema completely.
 *
 * That single choice is what collapses the ERP 9 vs Prime compatibility problem to near zero
 * (we inject no UI, and the object model is materially identical across both), and it is what
 * makes the flat XMLTAG parse in codec.ts possible.
 */

/** Escape a value being interpolated into XML we generate. */
export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Tally wants `d-MMM-yyyy`, e.g. `1-Apr-2026`. */
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function toTallyDate(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) throw new TypeError(`expected YYYY-MM-DD, got ${JSON.stringify(iso)}`);
  const [, y, mo, d] = m;
  const monthName = MONTHS[Number(mo) - 1];
  if (!monthName) throw new RangeError(`bad month in ${iso}`);
  return `${Number(d)}-${monthName}-${y}`;
}

/**
 * Field expression idioms.
 *
 * These normalize Tally's internal representations into things a computer can parse. They are
 * mined from the one battle-tested production implementation (tally-database-loader, MIT) —
 * read as documentation rather than vendored as a dependency.
 */
export const expr = {
  text: (field: string) => field,

  logical: (field: string) => `if ${field} then 1 else 0`,

  /** Empty dates become a sentinel character rather than an empty column. */
  date: (field: string) =>
    `if $$IsEmpty:${field} then $$StrByCharCode:241 else $$PyrlYYYYMMDDFormat:${field}:"-"`,

  number: (field: string) =>
    `if $$IsEmpty:${field} then "0" else $$StringFindAndReplace:($$String:${field}):"(-)":"-"`,

  /**
   * THE important one.
   *
   * Tally stores amounts with an internal Dr/Cr sign and renders negatives as "(-)". This
   * converts both into a plain signed decimal with **Dr negative, Cr positive** — a convention
   * that then holds everywhere in this codebase, all the way to the dashboard.
   */
  amount: (field: string) =>
    `$$StringFindAndReplace:(if $$IsDebit:${field} then -$$NumValue:${field} else $$NumValue:${field}):"(-)":"-"`,
} as const;

export interface FieldSpec {
  /** F01, F02, ... — F01 is special: codec.ts treats it as the row delimiter. */
  tag: string;
  /** The TDL expression, usually via `expr.*`. */
  set: string;
}

export interface CollectionSpec {
  type: string;
  fetch: string[];
  childOf?: string;
  belongsTo?: boolean;
  /** Name of a SYSTEM Formulae filter; pair with `systemFormulae`. */
  filter?: string;
}

export interface RequestSpec {
  /** Report id; arbitrary but must be unique within the request. */
  id: string;
  company?: string | undefined;
  fromDate?: string | undefined;
  toDate?: string | undefined;
  fields: FieldSpec[];
  collection: CollectionSpec;
  systemFormulae?: Record<string, string>;
}

/**
 * The other half of the codec's contract.
 *
 * `codec.ts` decodes a response by TAG NUMBER — the value of `<F04>` is column 4 — and honours
 * exactly two digits. That is only sound if the request declares `F01, F02, ... FNN` contiguous
 * and in order. Nothing enforced it: a field list of `['F01', 'F03']` or a tenth field written
 * `F10` (fine) versus a hundredth written `F100` (not fine, and silently inert on the way back)
 * would have produced a plausible response that decodes into the wrong shape.
 *
 * Cheap to check, and it fails at request-construction time — in the catalog, where the mistake
 * is — instead of surfacing as a misaligned number three packages away.
 */
function assertTagAlphabet(fields: readonly FieldSpec[]): void {
  if (fields.length === 0) throw new TypeError('a request must declare at least one field');
  if (fields.length > 99) {
    throw new RangeError(`the F\\d\\d tag alphabet holds 99 fields, not ${fields.length}`);
  }
  fields.forEach((f, i) => {
    const expected = `F${String(i + 1).padStart(2, '0')}`;
    if (f.tag !== expected) {
      throw new TypeError(
        `field ${i} must be tagged ${expected}, not ${JSON.stringify(f.tag)}: codec.ts decodes ` +
          'by tag number, so tags must be two digits and contiguous from F01.',
      );
    }
  });
}

/**
 * How many fields a request we built declares.
 *
 * Lets a caller hand the response parser the schema width without a second source of truth that
 * can drift from the request actually on the wire.
 */
export function fieldCountOfRequest(requestXml: string): number {
  return (requestXml.match(/<XMLTAG>F\d{2}<\/XMLTAG>/g) ?? []).length;
}

export function buildRequest(spec: RequestSpec): string {
  assertTagAlphabet(spec.fields);
  const fieldNames = spec.fields.map((f) => f.tag).join(',');

  const fieldDefs = spec.fields
    .map(
      (f) =>
        `<FIELD NAME="${f.tag}"><SET>${f.set}</SET><XMLTAG>${f.tag}</XMLTAG></FIELD>`,
    )
    .join('');

  const formulae = Object.entries(spec.systemFormulae ?? {})
    .map(([name, e]) => `<SYSTEM TYPE="Formulae" NAME="${name}">${e}</SYSTEM>`)
    .join('');

  const c = spec.collection;
  const collection =
    `<COLLECTION NAME="TSColl">` +
    `<TYPE>${c.type}</TYPE>` +
    (c.childOf ? `<CHILDOF>${c.childOf}</CHILDOF>` : '') +
    (c.belongsTo ? `<BELONGSTO>Yes</BELONGSTO>` : '') +
    `<FETCH>${c.fetch.join(',')}</FETCH>` +
    (c.filter ? `<FILTER>${c.filter}</FILTER>` : '') +
    `</COLLECTION>`;

  // Omit SVCURRENTCOMPANY *entirely* (not as an empty element) to target the active company.
  const staticVars =
    `<SVEXPORTFORMAT>XML (Data Interchange)</SVEXPORTFORMAT>` +
    (spec.company ? `<SVCURRENTCOMPANY>${esc(spec.company)}</SVCURRENTCOMPANY>` : '') +
    (spec.fromDate ? `<SVFROMDATE TYPE="Date">${toTallyDate(spec.fromDate)}</SVFROMDATE>` : '') +
    (spec.toDate ? `<SVTODATE TYPE="Date">${toTallyDate(spec.toDate)}</SVTODATE>` : '');

  return (
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<ENVELOPE>` +
    `<HEADER><VERSION>1</VERSION><TALLYREQUEST>Export</TALLYREQUEST><TYPE>Data</TYPE><ID>${spec.id}</ID></HEADER>` +
    `<BODY><DESC>` +
    `<STATICVARIABLES>${staticVars}</STATICVARIABLES>` +
    `<TDL><TDLMESSAGE>` +
    `<REPORT NAME="${spec.id}"><FORMS>TSForm</FORMS></REPORT>` +
    `<FORM NAME="TSForm"><PARTS>TSPart</PARTS></FORM>` +
    `<PART NAME="TSPart"><LINES>TSLine</LINES><REPEAT>TSLine : TSColl</REPEAT><SCROLLED>Vertical</SCROLLED></PART>` +
    `<LINE NAME="TSLine"><FIELDS>${fieldNames}</FIELDS></LINE>` +
    fieldDefs +
    collection +
    formulae +
    `</TDLMESSAGE></TDL>` +
    `</DESC></BODY>` +
    `</ENVELOPE>`
  );
}
