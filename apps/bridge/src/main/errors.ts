import { TallyTransportError, describeFailure } from '@tally-bridge/tally';

/**
 * Turning a throw into a sentence an owner can act on.
 *
 * THIS IS AN ALLOWLIST, AND IT HAS TO BE.
 *
 * The previous implementation was a denylist: take `e.message`, and show it unless it looks
 * like a stack trace. That inverts the burden onto a regex, and the regex loses — every one of
 * these is a real message from a real dependency on this path that a "does it look scary" test
 * waves through:
 *
 *   node:http        `connect ECONNREFUSED 127.0.0.1:9000`
 *                    `getaddrinfo ENOTFOUND acme-dash.vercel.app`   <- leaks the client's host
 *   better-sqlite3   `database is locked`
 *   libsodium        `incorrect key pair for the given ciphertext`
 *   V8               `Cannot read properties of undefined (reading 'rows')`
 *
 * None of those is actionable by a business owner, several name internals, and one leaks the
 * deployment hostname into a screenshot that ends up in a WhatsApp support thread.
 *
 * So: an error is human ONLY if a human wrote it FOR this audience. That is knowable from the
 * TYPE, never from the text. Everything else gets the generic sentence, and the detail goes to
 * the log where an engineer can read it.
 */

/** The generic. Says what happened, says what happens next, blames nobody. */
export const GENERIC_ERROR = 'Something went wrong while syncing. We will try again shortly.';

/**
 * An error whose `message` was written to be read by the owner of the business.
 *
 * Extending this is a claim about the AUDIENCE, not about severity. If the message contains an
 * errno, a class name, a file path, a hostname, or the word "undefined", it does not belong here.
 */
export class HumanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HumanError';
  }
}

/**
 * The one function that decides what an owner sees. Never throws, never returns a stack.
 */
export function humanError(e: unknown): string {
  // Tally's failures are already a closed set of sentences written for this audience —
  // `describeFailure` is that mapping, and it is exhaustive over TallyFailure.
  if (e instanceof TallyTransportError) return describeFailure(e.failure);

  if (e instanceof HumanError) {
    const msg = e.message.trim();
    // A HumanError with an empty message is a bug in the thrower, not a message for the owner.
    if (msg.length > 0 && msg.length <= 200) return msg;
  }

  return GENERIC_ERROR;
}
