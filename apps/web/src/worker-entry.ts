import { startWorker, type WorkerScopeLike } from './worker.ts';

/**
 * The Web Worker bootstrap — the file the owner's UI points `new Worker(...)` at (bundled;
 * see README.md). It contains no logic: `worker.ts` is the protocol, this is the two lines
 * that connect it to the real worker global scope.
 *
 * Guarded so that importing this module OUTSIDE a worker (Node tests, or a bundler that
 * accidentally pulls it into the page) is a no-op instead of hijacking the page's
 * `self.onmessage`: a dedicated worker scope has `postMessage`; a page has it too, but a page
 * has `document` and a worker never does.
 */
if (
  typeof self !== 'undefined' &&
  typeof document === 'undefined' &&
  typeof self.postMessage === 'function'
) {
  startWorker(self as unknown as WorkerScopeLike);
}
