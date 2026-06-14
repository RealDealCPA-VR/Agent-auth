import type { FastifyInstance } from 'fastify';
import { and, count, desc, eq, like, notLike, or, type SQL } from 'drizzle-orm';
import { schema } from '../db/index.js';
import { requireAgent } from './guards.js';
import { hasScope, allowsTarget } from '../auth/agent.js';
import { useCredential } from '../lib/vault.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

/**
 * Translate an agent's `target:` scopes into a SQL predicate equivalent to
 * allowsTarget(), so target-scoping is enforced in the query and pagination is
 * bounded at the database (never fetch-all-then-filter). Returns undefined when
 * the agent is unconstrained. Host patterns are validated at issuance to contain
 * no SQL-LIKE metacharacters.
 */
function targetCondition(scopes: string[]): SQL | undefined {
  const pats = scopes.filter((s) => s.startsWith('target:')).map((s) => s.slice('target:'.length));
  if (pats.length === 0 || pats.includes('*')) return undefined;
  const conds: SQL[] = [];
  for (const raw of pats) {
    const pat = raw.toLowerCase(); // targets are stored lowercase (case-insensitive hosts)
    if (pat.startsWith('*.')) {
      // Single-label subdomain only (api.example.com, not a.b.example.com or the
      // apex) — mirrors matchesTargetPattern(). Host patterns are validated at
      // issuance to contain no SQL-LIKE metacharacters.
      const suffix = pat.slice(2);
      conds.push(
        and(
          like(schema.credentials.target, `%.${suffix}`),
          notLike(schema.credentials.target, `%.%.${suffix}`),
        )!,
      );
    } else {
      conds.push(eq(schema.credentials.target, pat));
    }
  }
  return or(...conds);
}

/**
 * Agent-facing vault. Authenticated with an agent API key. This is where the
 * agent "logs in to anything" — it discovers the credentials it is scoped for
 * and unseals the one it needs, scoped and audited.
 */
export async function vaultRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireAgent);

  // Discover credential metadata — only for targets this agent is scoped for.
  app.get(
    '/v1/vault/credentials',
    {
      schema: {
        tags: ['vault'],
        summary: 'List credentials available to this agent',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const agent = req.agent!;
      if (!hasScope(agent.scopes, 'vault:read')) {
        return fail(req, reply, 403, 'forbidden', 'missing scope: vault:read');
      }
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());

      // Target-scoping is enforced in SQL so the query (and memory) is bounded by
      // the requested page, not the size of the passport's whole vault.
      const tcond = targetCondition(agent.scopes);
      const where = tcond
        ? and(eq(schema.credentials.passportId, agent.passportId), tcond)
        : eq(schema.credentials.passportId, agent.passportId);

      return readPage(
        q.data,
        (tx) =>
          tx
            .select({
              id: schema.credentials.id,
              target: schema.credentials.target,
              label: schema.credentials.label,
              type: schema.credentials.type,
              metadata: schema.credentials.metadata,
              expiresAt: schema.credentials.expiresAt,
            })
            .from(schema.credentials)
            .where(where)
            .orderBy(desc(schema.credentials.createdAt))
            .limit(q.data.limit)
            .offset(q.data.offset),
        async (tx) =>
          (await tx.select({ value: count() }).from(schema.credentials).where(where))[0]!.value,
      );
    },
  );

  // Unseal and return a credential secret for use against its target.
  app.post(
    '/v1/vault/credentials/:id/use',
    {
      schema: {
        tags: ['vault'],
        summary: 'Unseal a credential for use',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;

      const deny = async (reason: string, status = 403, code = 'forbidden', msg = reason) => {
        await audit({
          action: 'credential.use',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason },
          ip: req.ip,
        });
        return fail(req, reply, status, code, msg);
      };

      if (!hasScope(agent.scopes, 'vault:use')) return deny('missing scope: vault:use');

      const result = await useCredential(agent.passportId, id);
      if (result.status === 'not_found')
        return deny('not_found', 404, 'not_found', 'credential not found');
      if (result.status === 'expired')
        return deny('expired', 410, 'expired', 'credential has expired');
      if (result.status === 'not_yet_valid')
        return deny('not_yet_valid', 403, 'not_yet_valid', 'credential is not yet usable');
      if (result.status === 'window_expired')
        return deny('window_expired', 410, 'window_expired', 'credential usage window has ended');
      if (result.status === 'use_limit')
        return deny('use_limit', 429, 'use_limit_reached', 'credential use limit reached');
      if (result.status === 'approval_required')
        return deny('approval_required', 403, 'approval_required', 'use requires human approval');
      if (result.status === 'decrypt_error')
        return deny('decrypt_error', 500, 'internal', 'failed to unseal credential');

      // Enforce target-scoping after we know the target.
      if (!allowsTarget(agent.scopes, result.target)) {
        return deny(
          `target_not_allowed:${result.target}`,
          403,
          'forbidden',
          `agent not scoped for target: ${result.target}`,
        );
      }

      await audit({
        action: 'credential.use',
        success: true,
        agentId: agent.agentId,
        passportId: agent.passportId,
        credentialId: id,
        detail: { target: result.target, type: result.type },
        ip: req.ip,
      });

      // The only endpoint that returns cleartext secret material.
      return reply.send({
        id: result.id,
        target: result.target,
        label: result.label,
        type: result.type,
        metadata: result.metadata,
        secret: result.secret,
      });
    },
  );
}
