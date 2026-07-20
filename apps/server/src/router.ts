import { ALL_ROUTES, ROUTES, type RouteAuth, type RouteName } from '@tally-bridge/protocol';

/**
 * The router. It dispatches on the shared route table and NOTHING else.
 *
 * Two properties are load-bearing, and both exist because of the signature:
 *
 * 1. THE PATH IS MATCHED BYTE-FOR-BYTE against `ROUTES[x].path`. `signRequest` binds the path
 *    into the signed bytes, so a router that "helpfully" normalised `/api/sync/` to `/api/sync`
 *    would verify a signature over a string the device never signed — a silent 401 on the
 *    owner's own deployment. A trailing slash is therefore a 404 here, on purpose.
 *
 * 2. THE TABLE IS `ALL_ROUTES`, NOT A LOCAL COPY. A route added to the table is a compile error
 *    in the handler map (the mapped type below requires every `RouteName`) and a construction
 *    error at runtime (the loop below refuses a missing or mis-tagged entry). "Defined but not
 *    mounted" cannot survive to a customer's 404.
 *
 * ## How `auth` is enforced, honestly
 *
 * Each mounted handler DECLARES which door it implements, and construction refuses a handler
 * whose declaration disagrees with the route table. That makes "session handler mounted on the
 * device route" a startup crash instead of a quiet security downgrade.
 *
 * On top of the declaration, the router enforces what it can enforce STRUCTURALLY at runtime:
 *
 *   - `'session'` — the router itself calls `requireSession` and refuses with 401 BEFORE the
 *     handler runs. The read handlers also check (they were written before this router existed);
 *     the entry memoises the session lookup per request so the two checks cost one query. The
 *     router's copy is the one a future handler cannot forget.
 *   - `'device'`  — NOT verifiable here. Ed25519 verification needs the raw body, the exact
 *     signed path, and the nonce/quota machinery, all of which live in `verifyRequest` behind
 *     the handler (see handleIngest). The router enforces only the declaration; the handler is
 *     the door. This is a real limitation, stated rather than papered over.
 *   - `'none'`    — no gate, by decision recorded in routes.ts.
 */

export interface RouterRequest {
  method: string;
  /** Pathname only, exactly as the client sent it — it is inside the Ed25519 signature. */
  path: string;
  headers: Record<string, string | undefined>;
  /** Raw bytes. Handlers that verify signatures must see exactly what was sent. */
  body: Uint8Array;
  clientIp?: string | undefined;
  /**
   * Query parameters, for the one route that takes one (prelogin's `tenant`). NOT part of the
   * dispatch key — the path is matched without it, because the query is not inside the Ed25519
   * signature and must never influence which door a request goes through.
   */
  query?: Record<string, string | undefined> | undefined;
}

export interface RouterResponse {
  status: number;
  /** JSON-serialisable. Every body in this server is `{ok: true, ...}` or `{ok: false, error}`. */
  body: unknown;
  /**
   * When present, the transport MUST emit this verbatim as a Set-Cookie header. Only the
   * session endpoints (login, logout) produce one; see sessionCookie in auth.ts for the
   * attribute reasoning.
   */
  setCookie?: string;
}

export type RouteHandler = (req: RouterRequest) => Promise<RouterResponse>;

/**
 * A handler plus its claim about which door it implements. The claim is checked against the
 * route table at construction, so it cannot silently rot when a route's `auth` changes.
 */
export interface MountedHandler {
  readonly auth: RouteAuth;
  readonly handle: RouteHandler;
}

/**
 * The complete map. A mapped type over `RouteName`, so adding a route to `ROUTES` breaks the
 * build of every handler map until someone mounts something — which is the point.
 */
export type RouterHandlers = { readonly [K in RouteName]: MountedHandler };

/** Same contract as read.ts's RequireSession: tenant id or undefined, never a throw-as-denial. */
export type SessionCheck = (
  headers: Record<string, string | undefined>,
) => Promise<string | undefined>;

const err = (status: number, error: string): RouterResponse => ({
  status,
  body: { ok: false, error },
});

export type Dispatch = (req: RouterRequest) => Promise<RouterResponse>;

/**
 * Build a dispatcher. Throws — does not degrade — when the handler map and the route table
 * disagree. The type system already forbids a missing route, but callers can lie with a cast
 * and concurrent edits can change a route's door, so the table is re-checked at runtime.
 */
export function createRouter(handlers: RouterHandlers, requireSession: SessionCheck): Dispatch {
  const table = new Map<string, { name: RouteName; auth: RouteAuth; handle: RouteHandler }>();
  const knownPaths = new Set<string>();

  for (const route of ALL_ROUTES) {
    const mounted = (handlers as Record<string, MountedHandler | undefined>)[route.name];
    if (!mounted) {
      throw new Error(`route '${route.name}' is defined in ROUTES but not mounted`);
    }
    if (mounted.auth !== route.auth) {
      throw new Error(
        `route '${route.name}' is declared '${route.auth}' in ROUTES but its handler claims '${mounted.auth}'`,
      );
    }
    table.set(`${route.method} ${route.path}`, {
      name: route.name,
      auth: route.auth,
      handle: mounted.handle,
    });
    knownPaths.add(route.path);
  }

  return async (req) => {
    const method = typeof req.method === 'string' ? req.method.toUpperCase() : '';
    const entry = table.get(`${method} ${req.path}`);
    if (!entry) {
      // 405 only when the PATH exists under another method — that is a caller bug worth naming.
      // Everything else is an opaque 404: this server is on the public internet, and which
      // routes exist is not information a scanner needs confirmed.
      if (knownPaths.has(req.path)) return err(405, 'method not allowed');
      return err(404, 'not found');
    }

    if (entry.auth === 'session') {
      // THE ROUTER'S OWN GATE. It runs even when the handler forgets its check — the mutation
      // test replaces a session handler with one that returns data unconditionally and asserts
      // this 401 still stands.
      const tenantId = await requireSession(req.headers);
      if (!tenantId) return err(401, 'unauthorized');
    }

    return entry.handle(req);
  };
}

// Re-exported so the entry and tests key off the same table object this router mounts.
export { ALL_ROUTES, ROUTES };
