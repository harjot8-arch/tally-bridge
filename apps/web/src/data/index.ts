/**
 * THE DATA LAYER — the whole of this app. There is deliberately no UI in this package.
 *
 * Everything a presentation needs enters through these exports: unlock with a passphrase,
 * load the decrypted card view models, lock. Nothing in here touches the DOM. The owner
 * writes the HTML/CSS/JS themselves and calls these functions from it — see apps/web/README.md
 * for the exact contract. Until that UI exists, NOTHING in src calls this module; it is a
 * library awaiting its caller, and the tests prove it works, not that it runs.
 */
export { ApiError, logout, type FetchLike, type SnapshotRow } from './api.ts';
export {
  localStorageKV,
  memoryKV,
  loadRosterMemory,
  saveRosterMark,
  loadSlotMark,
  saveSlotMark,
  type KV,
} from './marks.ts';
export {
  unlock,
  lockSession,
  deriveAuthTokenInline,
  openPassIdentityInline,
  UnlockError,
  type OpenedPass,
  type UnlockDeps,
  type UnlockFailure,
  type UnlockStage,
  type UnlockedSession,
} from './unlock.ts';
export { loadDashboard, type DashboardResult, type ReadDeps } from './read.ts';
export { workerUnlockSeams, type WorkerLike } from './workerClient.ts';
export { assembleCompanyCards, type CompanyCards, type CompanySections } from './assemble.ts';
