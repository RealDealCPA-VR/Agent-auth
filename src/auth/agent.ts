import { eq } from 'drizzle-orm';
import { db, schema, pingDb } from '../db/index.js';
import { parseApiKey, verifySecret } from '../crypto/secrets.js';

/**
 * Agent authentication — FAIL CLOSED.
 *
 * Every agent request resolves to one of a fixed set of outcomes. If the
 * datastore is unreachable, or the agent is revoked/expired/inactive, or the key
 * is wrong, the result is a denial — never a default-allow.
 */

export interface AgentIdentity {
  agentId: string;
  passportId: string;
  scopes: string[];
}

export type AuthFailure =
  | 'malformed'
  | 'unknown'
  | 'revoked'
  | 'expired'
  | 'bad_secret'
  | 'store_unavailable';

export type AuthResult = { ok: true; agent: AgentIdentity } | { ok: false; reason: AuthFailure };

export async function authenticateAgent(apiKey: string): Promise<AuthResult> {
  const parsed = parseApiKey(apiKey);
  if (!parsed) return { ok: false, reason: 'malformed' };

  // Fail closed: if we cannot confirm the revocation store is reachable, deny.
  if (!(await pingDb())) return { ok: false, reason: 'store_unavailable' };

  let row;
  try {
    [row] = await db
      .select()
      .from(schema.agents)
      .where(eq(schema.agents.id, parsed.agentId))
      .limit(1);
  } catch {
    return { ok: false, reason: 'store_unavailable' };
  }

  if (!row) return { ok: false, reason: 'unknown' };
  if (!row.active || row.revokedAt) return { ok: false, reason: 'revoked' };
  if (row.expiresAt && row.expiresAt.getTime() <= Date.now())
    return { ok: false, reason: 'expired' };

  const good = await verifySecret(row.secretHash, parsed.secret);
  if (!good) return { ok: false, reason: 'bad_secret' };

  // Best-effort last-used stamp; never block auth on it.
  db.update(schema.agents)
    .set({ lastUsedAt: new Date() })
    .where(eq(schema.agents.id, row.id))
    .catch(() => {});

  return {
    ok: true,
    agent: { agentId: row.id, passportId: row.passportId, scopes: row.scopes ?? [] },
  };
}

// --- Scopes -----------------------------------------------------------------

/** The complete set of grantable non-target scopes. Anything else is rejected. */
export const ALLOWED_SCOPES = ['vault:read', 'vault:use', 'vault:proxy'] as const;
export type AllowedScope = (typeof ALLOWED_SCOPES)[number];

const HOST_RE =
  /^(\*|(\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)$/i;

/** Validate a single requested scope string (plain scope or `target:<pattern>`). */
export function isValidScope(scope: string): boolean {
  if ((ALLOWED_SCOPES as readonly string[]).includes(scope)) return true;
  if (scope.startsWith('target:')) {
    const pat = scope.slice('target:'.length);
    return pat.length > 0 && pat.length <= 253 && HOST_RE.test(pat);
  }
  return false;
}

export function hasScope(scopes: string[], required: string): boolean {
  return scopes.includes(required);
}

/**
 * Reduce a stored target to a bare lowercase host so a `target:<host>` scope
 * matches regardless of how the credential was deposited. A target may be a bare
 * host (`github.com`), a URL (`https://api.acme.com/v1`), or `host:port`
 * (`localhost:8080`) — scopes are always bare hosts (HOST_RE), so we compare on
 * the host alone. Mirrors parseTarget()/hostnameOf() in lib/proxy.ts.
 */
export function targetHost(target: string): string {
  let h = target.trim();
  const scheme = h.match(/^https?:\/\//i);
  if (scheme) h = h.slice(scheme[0].length);
  const slash = h.indexOf('/');
  if (slash >= 0) h = h.slice(0, slash); // drop any path
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    if (end >= 0) h = h.slice(1, end); // bracketed IPv6
  } else {
    const colon = h.indexOf(':');
    if (colon >= 0) h = h.slice(0, colon); // drop :port
  }
  return h.replace(/\.$/, '').toLowerCase();
}

/**
 * Target scoping. Supports exact host (`github.com`), full wildcard (`*`), and
 * single-label subdomain wildcard (`*.example.com` matches `api.example.com` but
 * NOT the apex `example.com` and NOT a deeper `a.b.example.com` — grant those
 * explicitly). An agent with no `target:` scope is unconstrained.
 */
export function matchesTargetPattern(pattern: string, target: string): boolean {
  // Hostnames are case-insensitive — compare in lowercase. The stored target may
  // be a URL or host:port form, so reduce it to its bare host before comparing.
  const p = pattern.toLowerCase();
  const t = targetHost(target);
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    if (!t.endsWith('.' + suffix)) return false; // requires the dot separator
    const label = t.slice(0, t.length - suffix.length - 1);
    return label.length > 0 && !label.includes('.'); // exactly one subdomain label
  }
  return p === t;
}

export function allowsTarget(scopes: string[], target: string): boolean {
  const patterns = scopes
    .filter((s) => s.startsWith('target:'))
    .map((s) => s.slice('target:'.length));
  if (patterns.length === 0) return true;
  return patterns.some((pat) => matchesTargetPattern(pat, target));
}
