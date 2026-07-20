import { ROSTER_FIRST_VERSION, RosterError, type RosterMemory } from '@tally-bridge/crypto';

/**
 * The browser's rollback memory — the web equivalent of the desktop's `RosterMarkStore`
 * (apps/bridge/src/main/snapshots.ts). Same contract, different disk.
 *
 * ------------------------------------------------------------------------------------------
 * WHY localStorage, AND WHAT IT IS HONESTLY WORTH.
 * ------------------------------------------------------------------------------------------
 *
 * The mark's job (trust.ts, `RosterMemory`): remember the highest roster version ever accepted,
 * in storage the ADVERSARY WHO ROLLS A BLOB BACK cannot write. That adversary is the one this
 * product is sold against — a Neon dump, a leaked DATABASE_URL, a subpoena. They write database
 * rows; they do not run JavaScript in this browser. Against them, localStorage is sound.
 *
 * localStorage over IndexedDB, deliberately: both are same-origin, both survive a tab close,
 * both die to "clear site data", and both are writable by any script served from the origin —
 * there is NO security difference between them here, because the only adversary who can reach
 * either is one who already replaced the served frontend, and that adversary takes the
 * passphrase at the prompt and never needs to touch a mark (trust.ts states this boundary; it
 * applies to every client-side check equally, including the passphrase field itself).
 * IndexedDB would buy async complexity and a schema for a single small value. localStorage is
 * synchronous, which also means the "load mark → unlock → save mark" sequence has no await gap
 * for a racing tab to interleave into.
 *
 * WHAT IS WEAKER THAN THE DESKTOP, stated rather than implied:
 *
 *   1. THE MEMORY IS EASIER TO LOSE. "Clear browsing data" wipes it; Safari deletes
 *      script-writable storage for sites not interacted with in ~7 days of use; a new phone or
 *      a private window has none. Every loss resets this reader to `{ kind: 'first-use' }` —
 *      the documented residual in trust.ts: a fresh reader accepts whatever roster version it
 *      is handed. The desktop loses its mark only when someone deletes the app's userData. The
 *      cost is real: a phone-only owner re-enters the residual window far more often than a
 *      desktop owner. The mitigation is the same human one ARCHITECTURE.md prescribes — the
 *      dashboard shows the roster and its fingerprints at unlock, loudest on first use.
 *   2. A BROWSER WITH NO STORAGE AT ALL (storage access throwing, quota zero) is a PERMANENT
 *      fresh reader. The caller must know that and say it on screen; `memoryKV()` exists for
 *      exactly that fallback and is labelled not-persistent so the UI cannot claim protection
 *      it does not have.
 *
 * CORRUPTION FAILS CLOSED, same as the desktop store: a mark that exists but does not parse to
 * an integer >= 1 throws, and is never read as "no mark". Degrading would let one scribbled
 * byte reset the rollback defence to zero. Recovering from genuinely broken storage is a
 * deliberate visible act (the browser's own "clear site data"), not a default.
 *
 * KEYED BY IDENTITY PUBLIC KEY, like the desktop store: "reset dashboard" on the Bridge mints a
 * new identity whose roster legitimately restarts at version 1, and a mark scoped to the old
 * idPK simply stops applying instead of refusing the new identity forever.
 */

/** The storage seam. `set` MUST throw when the write did not happen (quota, disabled storage). */
export interface KV {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
  /** False when writes do not survive this session. The UI must disclose that. */
  readonly persistent: boolean;
}

/** Wrap real localStorage. Returns undefined when the browser refuses storage entirely. */
export function localStorageKV(storage: Storage): KV {
  return {
    get: (key) => storage.getItem(key) ?? undefined,
    set: (key, value) => {
      // localStorage.setItem throws on quota (and in some private modes). Let it: the caller
      // fails closed on a mark it could not persist.
      storage.setItem(key, value);
      if (storage.getItem(key) !== value) {
        throw new Error('storage write did not stick');
      }
    },
    persistent: true,
  };
}

/** In-memory fallback for a browser with no usable storage. A PERMANENT fresh reader. */
export function memoryKV(): KV {
  const m = new Map<string, string>();
  return {
    get: (k) => m.get(k),
    set: (k, v) => {
      m.set(k, v);
    },
    persistent: false,
  };
}

const rosterKey = (idPkB64: string): string => `tb/v1/roster-mark/${idPkB64}`;
const slotKey = (idPkB64: string, companyGuid: string, section: string): string =>
  // JSON.stringify of the tuple: unambiguous however weird a Tally company GUID is. The GUID is
  // customer data and never becomes a delimiter-parsed string.
  `tb/v1/snap-mark/${JSON.stringify([idPkB64, companyGuid, section])}`;

/**
 * Load the roster high-water mark for an identity.
 *
 * Missing → first-use (typed, deliberate — see trust.ts). Corrupt → THROW.
 */
export function loadRosterMemory(kv: KV, idPkB64: string): RosterMemory {
  const raw = kv.get(rosterKey(idPkB64));
  if (raw === undefined) return { kind: 'first-use' };
  const version = parseStrictInt(raw);
  if (version === undefined || version < ROSTER_FIRST_VERSION) {
    throw new RosterError(
      'the saved roster safety mark in this browser is damaged: refusing to treat unreadable ' +
        'memory as no memory',
    );
  }
  return { kind: 'seen', highestVersionSeen: version };
}

/**
 * Persist the mark. MONOTONIC: never lowers an existing readable mark — `acceptRosterVersion`
 * already refused a rollback upstream on the happy path; this guard is for every OTHER caller,
 * and it lets a test prove the property against this module alone (the same reasoning as
 * `RosterMarkStore.save`). A corrupt existing mark may be overwritten by a valid one: that is
 * the one legitimate repair, and it only strengthens the defence relative to "throw forever".
 */
export function saveRosterMark(kv: KV, idPkB64: string, highestVersionSeen: number): void {
  if (!Number.isSafeInteger(highestVersionSeen) || highestVersionSeen < ROSTER_FIRST_VERSION) {
    throw new RosterError(`refusing to save a roster mark of ${String(highestVersionSeen)}`);
  }
  let current: RosterMemory | undefined;
  try {
    current = loadRosterMemory(kv, idPkB64);
  } catch {
    current = undefined;
  }
  if (current?.kind === 'seen' && highestVersionSeen < current.highestVersionSeen) {
    throw new RosterError(
      `refusing to lower the roster mark from ${current.highestVersionSeen} to ${highestVersionSeen}`,
    );
  }
  kv.set(rosterKey(idPkB64), String(highestVersionSeen));
}

/**
 * The freshness high-water mark for one (company, section) slot: the highest AAD `snapshotTs`
 * this browser has ever accepted from a VERIFIED envelope.
 *
 * This is the caller-side freshness check `openSection` documents and cannot do itself ("the
 * dashboard MUST reject a snapshotTs older than its high-water mark"). The desktop reader does
 * not need it — its slots come off its own disk, written by its own sync cycle. The web reader's
 * slots come from the server, which chooses WHICH authentic envelope to serve; without this
 * mark, last quarter's genuine numbers replay silently under today's date line.
 *
 * Corrupt → THROW, same rule as the roster mark: the caller treats that slot as unreadable.
 */
export function loadSlotMark(
  kv: KV,
  idPkB64: string,
  companyGuid: string,
  section: string,
): number | undefined {
  const raw = kv.get(slotKey(idPkB64, companyGuid, section));
  if (raw === undefined) return undefined;
  const ts = parseStrictInt(raw);
  if (ts === undefined || ts < 0) {
    throw new RosterError('the saved freshness mark for a section is damaged: refusing it');
  }
  return ts;
}

/** Monotonic, like the roster mark. */
export function saveSlotMark(
  kv: KV,
  idPkB64: string,
  companyGuid: string,
  section: string,
  snapshotTs: number,
): void {
  if (!Number.isSafeInteger(snapshotTs) || snapshotTs < 0) {
    throw new RosterError(`refusing to save a freshness mark of ${String(snapshotTs)}`);
  }
  let current: number | undefined;
  try {
    current = loadSlotMark(kv, idPkB64, companyGuid, section);
  } catch {
    current = undefined;
  }
  if (current !== undefined && snapshotTs < current) {
    throw new RosterError(`refusing to lower a freshness mark from ${current} to ${snapshotTs}`);
  }
  kv.set(slotKey(idPkB64, companyGuid, section), String(snapshotTs));
}

/**
 * Digits only, whole string, then integer-parsed. `Number('')` is 0 and `parseInt('12x')` is
 * 12 — both are exactly the silent coercions a damaged mark must not survive.
 */
function parseStrictInt(raw: string): number | undefined {
  if (!/^\d{1,15}$/.test(raw)) return undefined;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : undefined;
}
