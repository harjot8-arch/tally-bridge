import type { IsoDate, Section } from '@tally-bridge/core';
import { openSection, type MaybeSignedEnvelope } from '@tally-bridge/crypto';
import { snapshots, type FetchLike, type SnapshotRow } from './api.ts';
import { assembleCompanyCards, type CompanyCards, type CompanySections } from './assemble.ts';
import { loadSlotMark, saveSlotMark, type KV } from './marks.ts';
import type { UnlockedSession } from './unlock.ts';

/**
 * Fetch ciphertext, open it against what THIS reader can independently state, build cards.
 *
 * This is the web twin of the desktop's reader (apps/bridge/src/main/reader.ts). The two
 * security-critical arguments to `openSection` deserve the same spelled-out provenance there
 * and here, because the web's situation is genuinely weaker and pretending otherwise would be
 * the worst kind of comment:
 *
 * `trustedDevices` COMES FROM THE UNLOCKED SESSION — the roster `openIdentity` unwrapped from
 * INSIDE the passphrase-sealed bundle. Same as the desktop, and with the same structural
 * guarantee: this module has no other roster in scope to pass. The snapshot listing carries no
 * key material, `WrappedKey` deliberately has no roster field to pluck, and there is no
 * fetch-a-device-key endpoint. An envelope signed by any key the bundle does not pin is refused
 * however valid its seal and hash — including one minted by the server, which knows the
 * identity public key and every device public key but can never know a roster it cannot
 * decrypt.
 *
 * `expect` IS WEAKER HERE THAN ON THE DESKTOP, and that is stated rather than papered over.
 * The desktop builds `expect` from sidecar metadata its OWN sync cycle recorded — a record the
 * server never touched, so "what was asked for" and "what the envelope claims" are independent
 * facts. The web has no such record: the question it asked was "all snapshots for my tenant",
 * and the per-slot metadata (companyGuid, section, asOf) comes from the SERVER'S OWN listing.
 * Building `expect` from that listing is therefore NOT the desktop's defence, and it is
 * emphatically not built from `envelope.aad` either (that would be the tautology reader.ts
 * warns about — the envelope confirming itself). What each field honestly buys:
 *
 *   - `tenantId` comes from THE OWNER'S OWN LOGIN INPUT, not from the server. Genuinely
 *     independent, same strength as the desktop: an authentic envelope for some other tenant
 *     is refused even when the signing device happens to be in this roster (one owner, two
 *     deployments, shared PC — a real configuration).
 *   - `companyGuid`/`section`/`asOf` from the row are a CONSISTENCY check: the server's index
 *     must agree with what the signed AAD says, or the slot is refused. That catches a lazy
 *     forger and every honest mix-up; it does NOT constrain a careful server, which simply
 *     copies the AAD into its index. Against that server the remaining lever is SELECTION —
 *     serving old-but-authentic envelopes — which is exactly what the freshness mark below is
 *     for, and (for the roster itself) what the rollback mark closes at unlock.
 *
 * FRESHNESS: `openSection` proves authenticity, never freshness — its own comment says the
 * caller MUST reject a `snapshotTs` older than its high-water mark, and here the caller finally
 * exists. After a slot's signature verifies, its AAD `snapshotTs` (now device-authenticated) is
 * compared against this browser's persisted per-slot mark; older is REFUSED and counted, newer
 * advances the mark. A fresh browser has no mark and accepts what it is given — the same
 * fresh-reader residual as the roster, disclosed the same way.
 */

export type DashboardResult =
  | { state: 'empty' }
  | { state: 'error'; message: string }
  | {
      state: 'ready';
      companies: CompanyCards[];
      /** True when any slot or card was dropped. The UI must say so, not render a partial silently. */
      incomplete: boolean;
      /** Slots refused because they were OLDER than what this browser had already seen. */
      staleRefused: number;
    };

export interface ReadDeps {
  fetch: FetchLike;
  storage: KV;
  log?: ((message: string) => void) | undefined;
}

export async function loadDashboard(deps: ReadDeps, session: UnlockedSession): Promise<DashboardResult> {
  const log = deps.log ?? (() => {});

  let listing: { rows: SnapshotRow[]; malformed: number };
  try {
    listing = await snapshots(deps.fetch);
  } catch (e) {
    log(`[web] snapshot listing failed: ${(e as Error).message}`);
    return { state: 'error', message: 'your figures could not be fetched from the server' };
  }

  let incomplete = listing.malformed > 0;
  let staleRefused = 0;

  // One row per (company, section): the NEWEST by the server's own ordering claims. This choice
  // is convenience, not security — the server picks what it lists regardless; the signature
  // check decides authenticity and the freshness mark below decides staleness.
  const bySlot = new Map<string, SnapshotRow>();
  for (const row of listing.rows) {
    const key = JSON.stringify([row.companyGuid, row.section]);
    const cur = bySlot.get(key);
    if (!cur || isNewer(row, cur)) bySlot.set(key, row);
  }

  const companies = new Map<string, { companyGuid: string; asOf: IsoDate; sections: Map<Section, unknown> }>();

  for (const row of bySlot.values()) {
    let payload: unknown;
    try {
      payload = await openSlot(row, session, deps.storage);
    } catch (e) {
      if ((e as { stale?: boolean }).stale === true) staleRefused++;
      incomplete = true;
      log(`[web] snapshot for ${row.section} could not be opened: ${(e as Error).message}`);
      continue;
    }

    const acc = companies.get(row.companyGuid) ?? {
      companyGuid: row.companyGuid,
      asOf: row.asOf,
      sections: new Map<Section, unknown>(),
    };
    if (row.asOf > acc.asOf) acc.asOf = row.asOf;
    acc.sections.set(row.section, payload);
    companies.set(row.companyGuid, acc);
  }

  if (companies.size === 0) {
    return incomplete
      ? { state: 'error', message: 'your saved figures could not be read in this browser' }
      : { state: 'empty' };
  }

  const out: CompanyCards[] = [];
  for (const acc of companies.values()) {
    const { cards, failed } = assembleCompanyCards(acc as CompanySections, log);
    if (failed) incomplete = true;
    out.push(cards);
  }
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.companyGuid < b.companyGuid ? -1 : 1));

  return { state: 'ready', companies: out, incomplete, staleRefused };
}

function isNewer(a: SnapshotRow, b: SnapshotRow): boolean {
  if (a.asOf !== b.asOf) return a.asOf > b.asOf;
  if (a.snapshotTs !== b.snapshotTs) return a.snapshotTs > b.snapshotTs;
  return a.seq > b.seq;
}

/** A refusal that must be counted separately: authentic, but older than already seen. */
class StaleSlotError extends Error {
  readonly stale = true;
}

async function openSlot(row: SnapshotRow, session: UnlockedSession, storage: KV): Promise<unknown> {
  const idSK = session.identitySecretKey;
  const idPK = fromB64(session.identityPublicKeyB64);

  const payload = await openSection(row.envelope as MaybeSignedEnvelope, {
    identityPublicKey: idPK,
    identitySecretKey: idSK,
    // See the header for exactly what each field is worth here. tenantId is the owner's own
    // login input; the rest is the server's index held to consistency with the signed AAD.
    // NEVER row.envelope.aad — that would compare the envelope with itself.
    expect: {
      tenantId: session.tenantId,
      companyGuid: row.companyGuid,
      section: row.section,
      asOf: row.asOf,
    },
    trustedDevices: session.roster,
  });

  // The signature has verified, so aad is now device-authenticated data — usable for the
  // freshness decision `openSection` cannot make for us.
  const ts = row.envelope.aad.snapshotTs;
  let mark: number | undefined;
  try {
    mark = loadSlotMark(storage, session.identityPublicKeyB64, row.companyGuid, row.section);
  } catch (e) {
    throw new Error(`freshness mark unreadable: ${(e as Error).message}`);
  }
  if (mark !== undefined && Number.isSafeInteger(ts) && ts < mark) {
    throw new StaleSlotError(
      `authentic but OLDER than already seen (snapshotTs ${ts} < mark ${mark}): the server may be replaying an old snapshot`,
    );
  }
  if (Number.isSafeInteger(ts) && ts >= 0) {
    saveSlotMark(storage, session.identityPublicKeyB64, row.companyGuid, row.section, ts);
  }

  // Payload discriminant vs the slot, same as the desktop reader: "written by us" is a claim
  // about a past version of this codebase, so it is checked, not trusted.
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('section payload is not an object');
  }
  const section = (payload as { section?: unknown }).section;
  if (section !== row.section) {
    throw new Error(`payload names section ${String(section)}, slot is ${row.section}`);
  }
  return payload;
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
