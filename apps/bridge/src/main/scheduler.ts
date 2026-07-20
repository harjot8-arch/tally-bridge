/**
 * The sync scheduler.
 *
 * WHY THIS IS NOT A WINDOWS SERVICE — the trap worth documenting where someone will be tempted.
 *
 * A background syncer "obviously" wants to be a Windows Service. It does not. Tally's XML server
 * lives in the INTERACTIVE USER SESSION: it exists only while the owner has Tally open on their
 * desktop. A service in session 0 gains nothing — Tally is not there when the user is logged out
 * — and costs elevation, an installer, and DPAPI key-scoping problems (a service running as
 * SYSTEM cannot read a key sealed to the user's profile).
 *
 * So the Electron main process IS the background worker. Auto-start via
 * `app.setLoginItemSettings` writes HKCU\...\Run and needs no admin rights.
 *
 * WHY setInterval AND NOT CRON.
 *
 * We want "every 15 minutes WHILE THE MACHINE IS AWAKE". setInterval drifts across sleep — and
 * that drift is correct, not a bug. Cron semantics would fire a thundering herd of missed jobs
 * the instant a laptop wakes, hammering a single-threaded Tally the owner just sat down at.
 * The powerMonitor 'resume' hook covers the gap with exactly one tick.
 */

export const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

/** The slice of Electron's powerMonitor we use. Injected so this is testable. */
export interface PowerMonitorLike {
  on(event: 'resume' | 'suspend', listener: () => void): void;
}

export interface SchedulerDeps {
  runCycle: () => Promise<void>;
  intervalMs?: number;
  setInterval: (fn: () => void, ms: number) => unknown;
  clearInterval: (handle: unknown) => void;
  powerMonitor?: PowerMonitorLike;
  now: () => number;
  onError?: (e: unknown) => void;
}

export class Scheduler {
  private readonly deps: SchedulerDeps;
  private readonly intervalMs: number;
  private handle: unknown;
  private running = false;
  private stopped = true;
  /** A tick that arrived while a cycle was in flight. Collapsed, never queued. */
  private pending = false;
  private lastRunAt = 0;

  constructor(deps: SchedulerDeps) {
    this.deps = deps;
    this.intervalMs = deps.intervalMs ?? DEFAULT_INTERVAL_MS;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.handle = this.deps.setInterval(() => this.fireAndForget('interval'), this.intervalMs);

    // A laptop lid closes far more often than this app restarts. Without this, an owner who
    // opens their machine at 9am waits up to 15 minutes for data that is already stale.
    this.deps.powerMonitor?.on('resume', () => this.fireAndForget('resume'));
  }

  stop(): void {
    this.stopped = true;
    if (this.handle !== undefined) this.deps.clearInterval(this.handle);
    this.handle = undefined;
  }

  /** Force a cycle now — the tray's "Sync now", and used after Tally reconnects. */
  async syncNow(): Promise<void> {
    await this.tick('manual');
  }

  /**
   * Start a tick from a callback that cannot await it — a timer, a powerMonitor event.
   *
   * The `.catch` is the load-bearing part. `void somePromise` does NOT mark a rejection as
   * handled; it only silences the linter. A rejection escaping here is an unhandled rejection
   * in the main process, which Node kills the process for by default — so this is the
   * difference between "a tick failed" and "the Bridge is gone until someone reboots".
   */
  private fireAndForget(source: 'interval' | 'resume'): void {
    void this.tick(source).catch((e: unknown) => this.report(e));
  }

  get isRunning(): boolean {
    return this.running;
  }

  get lastRun(): number {
    return this.lastRunAt;
  }

  private async tick(source: 'interval' | 'resume' | 'manual'): Promise<void> {
    if (this.stopped && source !== 'manual') return;

    // COLLAPSE, DO NOT QUEUE.
    //
    // If a cycle is already in flight, remember that another was wanted and run exactly one
    // more afterwards. Queueing would let a slow Tally accumulate a backlog of ticks and then
    // fire them all back to back at the desktop app the owner is typing into — precisely the
    // thundering herd the interval was chosen to avoid.
    if (this.running) {
      this.pending = true;
      return;
    }

    this.running = true;
    try {
      do {
        this.pending = false;
        this.lastRunAt = this.deps.now();
        try {
          await this.deps.runCycle();
        } catch (e) {
          // A throwing cycle must never kill the scheduler. Tally being closed, the network
          // being down, the server 500ing — all of it is routine, and the next tick retries.
          this.report(e);
        }
      } while (this.pending && !this.stopped);
    } finally {
      this.running = false;
    }
  }

  /**
   * Report a cycle failure — and survive a reporter that itself throws.
   *
   * This looks paranoid and is not. `onError` in the real app repaints the tray and pushes IPC
   * to a window that may have been destroyed a millisecond ago, so it CAN throw. Without this
   * catch, that throw escapes `tick`, and `tick` is invoked as `void this.tick(...)` from a
   * timer — so it becomes an unhandled rejection, which Node terminates the process for by
   * default. The failure mode is the entire Bridge dying silently at 3am because a window
   * closed while Tally happened to be down. An error handler must be the one thing that cannot
   * fail.
   */
  private report(e: unknown): void {
    if (!this.deps.onError) return;
    try {
      this.deps.onError(e);
    } catch (reporterFailure) {
      console.error('[bridge] the error reporter itself threw:', reporterFailure);
    }
  }
}

/**
 * Human-readable sync status for the tray and the cards.
 *
 * The owner must always be able to see whether the numbers they are looking at are current.
 * A dashboard that silently shows week-old figures is worse than one that says it is broken.
 */
export type SyncStatus =
  | { state: 'never'; message: string }
  | { state: 'ok'; message: string; lastRun: number }
  | { state: 'waiting'; message: string; action: string }
  | { state: 'error'; message: string; action: string };

export function describeStatus(
  // `| undefined` explicitly: under exactOptionalPropertyTypes, "absent" and "present but
  // undefined" are different types, and callers naturally hold a `string | undefined`.
  input: { lastRun: number; lastError?: string | undefined; tallyReachable: boolean; now: number },
): SyncStatus {
  if (!input.tallyReachable) {
    // Not an error. This is the normal state every night and every weekend.
    return { state: 'waiting', message: 'Waiting for Tally to open', action: 'Open Tally' };
  }
  if (input.lastError) {
    return { state: 'error', message: input.lastError, action: 'Try again' };
  }
  if (input.lastRun === 0) {
    return { state: 'never', message: 'Not synced yet' };
  }
  return { state: 'ok', message: 'Synced', lastRun: input.lastRun };
}
