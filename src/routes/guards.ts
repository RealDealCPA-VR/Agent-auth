import type { FastifyReply, FastifyRequest } from 'fastify';
import { verifySession, type HumanClaims } from '../auth/human.js';
import { authenticateAgent, type AgentIdentity } from '../auth/agent.js';
import { audit } from '../lib/audit.js';
import { fail } from '../lib/http.js';

declare module 'fastify' {
  interface FastifyRequest {
    human?: HumanClaims;
    agent?: AgentIdentity;
  }
}

function bearer(req: FastifyRequest): string | null {
  // Node collapses duplicate `authorization` headers to a single string, but
  // handle the array shape defensively anyway (mirrors x-request-id handling).
  const raw = req.headers.authorization;
  const h = Array.isArray(raw) ? raw[0] : raw;
  if (!h || !h.startsWith('Bearer ')) return null;
  return h.slice('Bearer '.length).trim();
}

/** Require a valid human session (Bearer JWT). Attaches req.human. */
export async function requireHuman(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = bearer(req);
  if (!token) {
    await fail(req, reply, 401, 'unauthorized', 'missing bearer token');
    return;
  }
  const claims = await verifySession(token);
  if (!claims) {
    await fail(req, reply, 401, 'unauthorized', 'invalid or expired session');
    return;
  }
  req.human = claims;
}

/**
 * Require a valid agent API key (Bearer). Attaches req.agent. Fail-closed:
 * a store outage yields 503, not access.
 */
export async function requireAgent(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = bearer(req);
  if (!token) {
    await fail(req, reply, 401, 'unauthorized', 'missing agent api key');
    return;
  }
  const result = await authenticateAgent(token);
  if (!result.ok) {
    if (result.reason === 'store_unavailable') {
      await fail(
        req,
        reply,
        503,
        'store_unavailable',
        'authorization store unavailable; access denied',
      );
      return;
    }
    await audit({
      action: 'auth.denied',
      success: false,
      detail: { reason: result.reason },
      ip: req.ip,
    });
    await fail(req, reply, 401, 'unauthorized', 'agent authentication failed');
    return;
  }
  req.agent = result.agent;
}
