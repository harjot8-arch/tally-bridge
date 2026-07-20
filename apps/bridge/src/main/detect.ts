import { TIMEOUTS, fieldCountOfRequest, probeRequest, xmlTagResponseToRows, type TallyResult } from '@tally-bridge/tally';
import type { TallyDetectResult } from './ipc.ts';

/**
 * The real "is Tally there?" probe behind the detectTally IPC verb.
 *
 * Everything here is a SENTENCE FOR AN OWNER, decided per failure kind — never `describeFailure`
 * from the transport (which says things like "(HTTP 502)") and never an exception. Two states
 * are explicitly NOT errors, because they are the normal life of a desktop accounting app:
 *
 *   ECONNREFUSED (kind 'not_running')   Tally is closed. Overnight, weekends, lunch.
 *   empty 200 body ('no_company_open')  Tally is open, books are not. `reachable` is TRUE here:
 *                                       Tally answered; there is simply nothing to list yet.
 *
 * And one state that looks like Tally but is not: a 200 whose body is not a Tally envelope means
 * something else owns port 9000, which is worth its own sentence because "try again" cannot fix it.
 */

/** The slice of TallyTransport this needs. An interface so tests can drive every branch. */
export interface ProbeTransport {
  readonly currentEncoding: string | undefined;
  detectEncoding(probeXml: string): Promise<unknown>;
  request(xml: string, timeoutMs?: number): Promise<TallyResult>;
}

export interface ProbedCompany {
  guid: string;
  name: string;
  isActive: boolean;
}

export type ProbeOutcome =
  | { ok: true; companies: ProbedCompany[] }
  | { ok: false; failure: Extract<TallyResult, { ok: false }>['failure'] };

/**
 * Run the probe and parse the company list. The shared primitive under both `detectTally` (the
 * dashboard's status verb) and the setup wizard's first screen — one probe, one parser, so the
 * two cannot disagree about what Tally said.
 */
export async function probeCompanyList(transport: ProbeTransport): Promise<ProbeOutcome> {
  if (!transport.currentEncoding) {
    // Settle the request encoding once; the transport caches the winner for the process.
    await transport.detectEncoding(probeRequest());
  }
  const res = await transport.request(probeRequest(), TIMEOUTS.probeMs);
  if (!res.ok) return { ok: false, failure: res.failure };

  const companies: ProbedCompany[] = [];
  for (const cols of xmlTagResponseToRows(res.xml, { fieldCount: fieldCountOfRequest(probeRequest()) })) {
    const [name, guid, , , , , isActive] = cols;
    // A row with no GUID has no identity and is skipped — same rule as the sync path, for the
    // same reason: names are edited; GUIDs are not.
    if (!guid || guid.length === 0) continue;
    companies.push({ guid, name: name ?? '', isActive: isActive === '1' });
  }
  return { ok: true, companies };
}

export async function detectTally(transport: ProbeTransport): Promise<TallyDetectResult> {
  try {
    const res = await probeCompanyList(transport);
    if (!res.ok) return describeProbeFailure(res);
    if (res.companies.length === 0) {
      // Tally answered with an envelope but offered nothing — to the owner this is the same
      // situation as "no company open", so it gets the same sentence.
      return { reachable: true, message: 'Tally is open, but no company is loaded.', companies: [] };
    }
    return {
      reachable: true,
      message:
        res.companies.length === 1
          ? 'Found your company in Tally.'
          : `Found ${res.companies.length} companies in Tally.`,
      companies: res.companies,
    };
  } catch (e) {
    // The transport is written not to throw, so this is a genuine surprise — which is exactly
    // why it must not reach the renderer as one. Detail goes to the log; the owner gets a plan.
    console.error('[bridge] detectTally failed unexpectedly:', e);
    return { reachable: false, message: 'We could not check Tally just now. Try again.', companies: [] };
  }
}

function describeProbeFailure(res: Extract<ProbeOutcome, { ok: false }>): TallyDetectResult {
  switch (res.failure.kind) {
    case 'not_running':
      return { reachable: false, message: 'Tally is not open on this computer.', companies: [] };
    case 'no_company_open':
      return { reachable: true, message: 'Tally is open, but no company is loaded.', companies: [] };
    case 'not_tally':
      return {
        reachable: false,
        message: 'Another program on this computer is using the port Tally needs. Close it, then try again.',
        companies: [],
      };
    case 'tally_error':
      return {
        reachable: true,
        message: `Tally reported a problem: ${cleanFault(res.failure.message)}`,
        companies: [],
      };
    case 'timeout':
      return {
        reachable: false,
        message: 'Tally did not answer in time. It may be busy, or waiting on a dialog box that is open on screen.',
        companies: [],
      };
    case 'http_status':
    case 'network':
      return {
        reachable: false,
        message: 'We could not reach Tally on this computer. Check that Tally is open, then try again.',
        companies: [],
      };
  }
}

/**
 * Make Tally's own fault text safe to show: strip markup, collapse whitespace, clip, terminate.
 * (Mirrors the wizard's private `cleanFault`; the rule is small enough that sharing it would
 * mean exporting a wizard internal across territory for one regex.)
 */
function cleanFault(raw: string): string {
  const flat = raw
    .replace(/<[^>]*>/g, ' ')
    .replace(/[{}[\]<>]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (flat.length === 0) return 'no details were given.';
  const clipped = flat.length > 120 ? `${flat.slice(0, 117).trimEnd()}…` : flat;
  return /[.!?…]$/.test(clipped) ? clipped : `${clipped}.`;
}
