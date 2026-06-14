import { X509Certificate } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { FastifyRequest } from 'fastify';
import { eq } from 'drizzle-orm';
import { db, schema, pingDb } from '../db/index.js';
import { env } from '../env.js';
import type { AuthResult } from './agent.js';

/**
 * mTLS agent identity — an ALTERNATIVE to the bearer API key. A client
 * certificate is mapped to exactly one agent by its SHA-256 fingerprint. Like
 * API-key auth this is FAIL CLOSED: an unreachable store, or a revoked/expired/
 * inactive agent, or an unknown fingerprint, all resolve to a denial.
 *
 * Fingerprints are normalized everywhere to lowercase hex with no colons, which
 * is also how they are stored on the agent row (schema.agents.certFingerprint).
 */

/** Normalize a SHA-256 fingerprint to lowercase hex without colons. */
export function normalizeFingerprint(fp: string): string {
  return fp.replace(/:/g, '').trim().toLowerCase();
}

/**
 * Derive the SHA-256 fingerprint of a PEM-encoded X.509 certificate, normalized
 * to lowercase hex without colons. Throws if the PEM cannot be parsed.
 */
export function fingerprintFromPem(pem: string): string {
  const cert = new X509Certificate(pem);
  return normalizeFingerprint(cert.fingerprint256);
}

/**
 * Extract the client-cert fingerprint for a request, or null if none is present.
 *
 *  - proxy mode (MTLS_TRUSTED_PROXY): read MTLS_FP_HEADER, forwarded by a trusted
 *    TLS-terminating reverse proxy that already verified the client cert.
 *  - native mode: read the peer certificate off the TLS socket. We accept the
 *    cert's fingerprint whenever the socket presented one (the server runs with
 *    rejectUnauthorized:false so unauthenticated requests still reach handlers and
 *    can fall back to bearer auth); authorization is decided by the fingerprint
 *    lookup, not by the socket's `authorized` flag alone.
 */
export function extractClientFingerprint(req: FastifyRequest): string | null {
  if (!env.MTLS_ENABLED) return null;

  if (env.MTLS_TRUSTED_PROXY) {
    const raw = req.headers[env.MTLS_FP_HEADER.toLowerCase()];
    const v = Array.isArray(raw) ? raw[0] : raw;
    if (!v) return null;
    const fp = normalizeFingerprint(v);
    return fp.length > 0 ? fp : null;
  }

  // Native mode: pull the peer cert off the TLS socket.
  const socket = req.socket as TLSSocket;
  if (typeof socket.getPeerCertificate !== 'function') return null;
  const cert = socket.getPeerCertificate();
  if (!cert || !cert.fingerprint256) return null;
  const fp = normalizeFingerprint(cert.fingerprint256);
  return fp.length > 0 ? fp : null;
}

/**
 * Authenticate an agent by client-cert fingerprint. Mirrors authenticateAgent()
 * for API keys: fail-closed pingDb, then the same revoked/expired/inactive gates,
 * resolving to the shared AgentIdentity / AuthResult shape.
 */
export async function authenticateAgentByCert(fingerprint: string): Promise<AuthResult> {
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return { ok: false, reason: 'malformed' };

  // Fail closed: if we cannot confirm the revocation store is reachable, deny.
  if (!(await pingDb())) return { ok: false, reason: 'store_unavailable' };

  let row;
  try {
    [row] = await db
      .select()
      .from(schema.agents)
      .where(eq(schema.agents.certFingerprint, fp))
      .limit(1);
  } catch {
    return { ok: false, reason: 'store_unavailable' };
  }

  if (!row) return { ok: false, reason: 'unknown' };
  if (!row.active || row.revokedAt) return { ok: false, reason: 'revoked' };
  if (row.expiresAt && row.expiresAt.getTime() <= Date.now())
    return { ok: false, reason: 'expired' };

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
