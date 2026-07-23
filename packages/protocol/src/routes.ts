/**
 * The route table. One place, both sides.
 *
 * THIS FILE EXISTS BECAUSE THE PATH IS INSIDE THE SIGNATURE.
 *
 * `signRequest` binds the request path into the signed bytes (see signing.ts), and
 * `verifyRequest` compares it. That is a real defence — it stops a signature captured on one
 * endpoint being replayed against another — but it has a consequence that is easy to miss:
 *
 *   the client's path string and the server's path string must be the SAME STRING,
 *   or every request 401s.
 *
 * Before this file they were independent literals. `cycle.ts` declared `SYNC_PATH = '/api/sync'`.
 * `ingest.ts` separately hardcoded `'/api/sync'` into its `verifyRequest` call. `wizard-effects.ts`
 * built `'/api/register'` from a string literal that matched nothing at all, because no route
 * constant existed to match. They agreed by luck.
 *
 * The failure mode that buys is the worst kind this product has. It is not a crash: it is a 401
 * on the OWNER'S OWN DEPLOYMENT, at setup time, with a correct signature over a correct body,
 * on a server we wrote, reachable only after the owner has already paid Vercel — and the only
 * available diagnosis is "invalid signature", which is the one thing that is not wrong. A typo
 * in a string becomes a support call that cannot be closed remotely.
 *
 * So the paths are not written down twice. Everything imports from here: the Bridge that signs,
 * the handler that verifies, and the router that mounts. Rename a route and the type checker
 * finds every side of it, because there is only one side.
 *
 * ## Why the values are frozen literals and not a `string`
 *
 * `as const` is load-bearing. It makes `ROUTES.sync.path` the literal type `'/api/sync'` rather
 * than `string`, so a handler that verifies against the wrong constant is a type error rather
 * than a runtime 401. The narrow type is the check.
 *
 * ## The two doors
 *
 * `auth` records which door a route uses, and it is documentation the compiler enforces rather
 * than a comment that rots:
 *
 *   - `'device'` — Ed25519, RFC 9421, signed by a device key. WRITES only. The Bridge.
 *   - `'session'` — a session cookie held by a human. READS only. The browser.
 *   - `'none'`   — deliberately unauthenticated. There are exactly four — `register`, `prelogin`,
 *                  `login`, and `health` — and each is justified at its definition, because "why is
 *                  this open" is the question an auditor will ask first and must be able to answer
 *                  without reading the handler.
 *
 * See read.ts for why the doors do not overlap: a stolen device key must not read the dashboard,
 * and a stolen session must not forge an upload.
 */

/** Which door a route admits callers through. */
export type RouteAuth = 'device' | 'session' | 'none';

export interface RouteDef {
  readonly method: string;
  readonly path: string;
  readonly auth: RouteAuth;
}

export const ROUTES = {
  /**
   * The Bridge uploads a sealed envelope. The product's only write path for business data.
   */
  sync: { method: 'POST', path: '/api/sync', auth: 'device' },

  /**
   * The Bridge enrols itself using the one-shot BOOTSTRAP_SECRET.
   *
   * `auth: 'none'` in the sense that no device key exists YET — this is the endpoint that
   * creates the first one, so requiring a device signature would be circular. It is not open:
   * it demands the bootstrap secret, which was set as a sensitive env var before first deploy,
   * self-disables after one use, and expires in 24h. See handleRegister.
   */
  register: { method: 'POST', path: '/api/register', auth: 'none' },

  /**
   * The Bridge stores the wrapped identity secret so a browser can later unwrap it.
   *
   * A WRITE, so it goes through the device door, not the session door. This is the endpoint
   * whose absence meant `wrapped_key` could be read but never written — the table had a
   * SELECT and no INSERT, so the dashboard's unlock could never have worked.
   */
  putWrappedKey: { method: 'PUT', path: '/api/wrapped-keys', auth: 'device' },

  /**
   * The KDF parameters for this tenant's passphrase.
   *
   * `auth: 'none'`, and this one deserves the scrutiny. It is the chicken-and-egg of any
   * passphrase-derived auth: the browser cannot authenticate until it has derived the auth
   * token, it cannot derive the token without the Argon2id salt and params, and the salt lives
   * on the server. So the salt must be fetchable by an unauthenticated caller.
   *
   * What this leaks to anyone holding the URL: that a deployment exists, and its KDF cost
   * parameters. Not the passphrase, not a hash of it, and nothing that shortens an attack — a
   * salt is public input by construction; its job is to defeat precomputation, not to be
   * secret. Bitwarden's `/accounts/prelogin` is the same endpoint for the same reason.
   *
   * It is rate-limited regardless, because an unauthenticated endpoint that hits the database
   * is a DoS surface on the client's own Neon bill even when it leaks nothing.
   */
  prelogin: { method: 'GET', path: '/api/prelogin', auth: 'none' },

  /** Exchange a passphrase-derived auth token for a session cookie. */
  login: { method: 'POST', path: '/api/login', auth: 'none' },

  /** Destroy the caller's session server-side. Requires the session it is destroying. */
  logout: { method: 'POST', path: '/api/logout', auth: 'session' },

  /** The sealed envelopes. Ciphertext out; the browser decrypts. */
  snapshots: { method: 'GET', path: '/api/snapshots', auth: 'session' },

  /** The wrapped identity secrets, so the browser can unwrap one with the passphrase. */
  wrappedKeys: { method: 'GET', path: '/api/wrapped-keys', auth: 'session' },

  /** The device list, for the revocation screen. */
  devices: { method: 'GET', path: '/api/devices', auth: 'session' },

  /** Revoke a device. A human decision, so: session door. */
  revokeDevice: { method: 'POST', path: '/api/devices/revoke', auth: 'session' },

  /** Liveness. Returns no tenant data and touches no table. */
  health: { method: 'GET', path: '/api/health', auth: 'none' },
} as const satisfies Record<string, RouteDef>;

export type RouteName = keyof typeof ROUTES;

/**
 * Every route, as a list.
 *
 * The router iterates this rather than carrying its own copy of the table. A route that exists
 * here but is not mounted is then a test failure, not a 404 discovered by a customer.
 */
export const ALL_ROUTES: readonly (RouteDef & { name: RouteName })[] = Object.entries(ROUTES).map(
  ([name, def]) => ({ name: name as RouteName, ...def }),
);
