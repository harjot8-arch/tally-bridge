// M3 wiring: Tally detection over the Rust byte-pipe.
//
// The Rust `tally_request` command moves bytes; the encoding and parsing are the REUSED, audited TS
// codec (packages/tally, now browser-clean). So detection runs the exact same parse the Electron
// app runs (apps/bridge/src/main/detect.ts `probeCompanyList`) — GUID is identity, a row without
// one is skipped, F07 flags the active company.
// Subpath imports of the browser-clean modules ONLY — never the barrel, whose `export * from
// './transport'` would drag node:http into the WebView bundle.
import {
  contentTypeFor,
  decodeTallyResponse,
  encodeTallyRequest,
  xmlTagResponseToRows,
} from '@tally-bridge/tally/codec';
import { probeRequest } from '@tally-bridge/tally/requests';
import { fieldCountOfRequest } from '@tally-bridge/tally/tdl';

export interface TallyCompany {
  guid: string;
  name: string;
  isActive: boolean;
}

export interface TallyDetectResult {
  reachable: boolean;
  /** A sentence for a human. Never an error code, never a stack trace. */
  message: string;
  companies: TallyCompany[];
}

/**
 * PURE: turn Tally's XMLTAG company-list response into companies. Mirrors `probeCompanyList`
 * exactly — a row with no GUID has no identity and is skipped (names are edited; GUIDs are not).
 * Unit-tested below; the impure round-trip in `detectTallyViaBridge` is what needs a live Tally.
 */
export function parseCompanies(xml: string): TallyCompany[] {
  const companies: TallyCompany[] = [];
  for (const cols of xmlTagResponseToRows(xml, { fieldCount: fieldCountOfRequest(probeRequest()) })) {
    const [name, guid, , , , , isActive] = cols;
    if (!guid || guid.length === 0) continue;
    companies.push({ guid, name: name ?? '', isActive: isActive === '1' });
  }
  return companies;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

/**
 * detectTally over the byte-pipe: encode the company-list request, POST it through Rust, decode +
 * parse with the reused codec. Tally's field-observed default is UTF-16LE; the codec sniffs the
 * response regardless. A connection failure is NOT an error — it is the normal "Tally is closed".
 */
export async function detectTallyViaBridge(invoke: Invoke): Promise<TallyDetectResult> {
  const requestBytes = encodeTallyRequest(probeRequest(), 'utf16le');
  try {
    const res = await invoke<{ status: number; body: number[] }>('tally_request', {
      body: Array.from(requestBytes),
      contentType: contentTypeFor('utf16le'),
      timeoutMs: 10_000,
    });
    const companies = parseCompanies(decodeTallyResponse(Uint8Array.from(res.body)));
    if (companies.length === 0) {
      return { reachable: true, message: 'Tally is open, but no company is loaded.', companies: [] };
    }
    return {
      reachable: true,
      message:
        companies.length === 1
          ? 'Found your company in Tally.'
          : `Found ${companies.length} companies in Tally.`,
      companies,
    };
  } catch {
    return {
      reachable: false,
      message: 'Tally is not open on this computer. Open it, then try again.',
      companies: [],
    };
  }
}
