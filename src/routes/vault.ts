import type { FastifyInstance } from 'fastify';
import { and, count, desc, eq, like, notLike, or, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { schema } from '../db/index.js';
import { requireAgent } from './guards.js';
import { hasScope, allowsTarget } from '../auth/agent.js';
import { useCredential, getCredentialTarget } from '../lib/vault.js';
import { proxyRequest, precheckProxyTarget } from '../lib/proxy.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

// Body for proxy mode: the agent controls method/path/query/body/headers only —
// the host is pinned to the credential's target server-side.
const proxyBodySchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']).default('GET'),
  path: z.string().max(4096).startsWith('/', 'path must start with /').default('/'),
  query: z.record(z.string()).optional(),
  headers: z.record(z.string()).optional(),
  body: z.string().max(1_048_576).optional(),
});

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
      // The host may have been deposited bare (`api.acme.com`), as a URL
      // (`https://api.acme.com/v1`), or with a port (`api.acme.com:8080`). Match
      // the host at a boundary in each form. Patterns are anchored and host
      // scopes contain no SQL-LIKE metacharacters (validated at issuance), so
      // these can't over-match a different host (`api.acme.com.evil` won't match).
      conds.push(
        or(
          eq(schema.credentials.target, pat),
          like(schema.credentials.target, `${pat}:%`),
          like(schema.credentials.target, `${pat}/%`),
          like(schema.credentials.target, `http://${pat}`),
          like(schema.credentials.target, `https://${pat}`),
          like(schema.credentials.target, `http://${pat}:%`),
          like(schema.credentials.target, `https://${pat}:%`),
          like(schema.credentials.target, `http://${pat}/%`),
          like(schema.credentials.target, `https://${pat}/%`),
        )!,
      );
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
      // vault:read OR vault:proxy may list metadata. A proxy-only agent (granted
      // vault:proxy without vault:read so it can act through credentials it can
      // never read) still needs to resolve a target host to a credential id —
      // and listing returns metadata only (never a secret), bounded by the same
      // target-scoping, so this grants no extra reach than the proxy it already has.
      if (!hasScope(agent.scopes, 'vault:read') && !hasScope(agent.scopes, 'vault:proxy')) {
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

      const result = await useCredential(agent.passportId, id, { agentId: agent.agentId });
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
      if (result.status === 'approval_denied')
        return deny('approval_denied', 403, 'approval_denied', 'use was denied by an owner');
      if (result.status === 'approval_pending') {
        // Not a hard failure: the request is queued for a human. Return 202 with
        // the request id (not the error envelope), but still audit success:false
        // so the trail records that the secret was withheld pending approval.
        await audit({
          action: 'credential.use',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason: 'approval_pending', requestId: result.requestId },
          ip: req.ip,
        });
        return reply.code(202).send({
          status: 'pending',
          requestId: result.requestId,
          message: 'awaiting approval',
        });
      }
      if (result.status === 'refresh_failed')
        return deny('refresh_failed', 502, 'oauth_refresh_failed', 'failed to refresh oauth token');
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
        expiresAt: result.expiresAt,
        secret: result.secret,
      });
    },
  );

  // Proxy mode: AgentAuth makes the downstream request and injects the credential
  // server-side, so the raw secret never reaches the agent. The agent supplies
  // only method/path/query/body; the host is pinned to the credential's target.
  app.post(
    '/v1/vault/credentials/:id/proxy',
    {
      schema: {
        tags: ['vault'],
        summary: 'Proxy a request to the credential target with the secret injected server-side',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;

      const deny = async (reason: string, status = 403, code = 'forbidden', msg = reason) => {
        await audit({
          action: 'credential.proxy',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason },
          ip: req.ip,
        });
        return fail(req, reply, status, code, msg);
      };

      if (!hasScope(agent.scopes, 'vault:proxy')) return deny('missing scope: vault:proxy');

      const parsed = proxyBodySchema.safeParse(req.body);
      if (!parsed.success)
        return fail(
          req,
          reply,
          400,
          'invalid_request',
          'invalid proxy request',
          parsed.error.flatten(),
        );

      // Validate target-scope + the SSRF/path guards BEFORE charging a use, so a
      // rejected proxy never burns a maxUses slot or spends an approval grant.
      const meta = await getCredentialTarget(agent.passportId, id);
      if (!meta) return deny('not_found', 404, 'not_found', 'credential not found');
      if (!allowsTarget(agent.scopes, meta.target)) {
        return deny(
          `target_not_allowed:${meta.target}`,
          403,
          'forbidden',
          `agent not scoped for target: ${meta.target}`,
        );
      }
      const pre = await precheckProxyTarget(meta.target, parsed.data.path ?? '/');
      if (pre) {
        const status = pre.reason === 'bad_request' ? 400 : 403;
        const code = pre.reason === 'bad_request' ? 'invalid_request' : 'forbidden';
        return deny(pre.reason, status, code, pre.message);
      }

      const result = await useCredential(agent.passportId, id, { agentId: agent.agentId });
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
      if (result.status === 'approval_denied')
        return deny('approval_denied', 403, 'approval_denied', 'use was denied by an owner');
      if (result.status === 'approval_pending') {
        await audit({
          action: 'credential.proxy',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason: 'approval_pending', requestId: result.requestId },
          ip: req.ip,
        });
        return reply
          .code(202)
          .send({ status: 'pending', requestId: result.requestId, message: 'awaiting approval' });
      }
      if (result.status === 'refresh_failed')
        return deny('refresh_failed', 502, 'oauth_refresh_failed', 'failed to refresh oauth token');
      if (result.status === 'decrypt_error')
        return deny('decrypt_error', 500, 'internal', 'failed to unseal credential');

      const outcome = await proxyRequest({
        target: result.target,
        type: result.type,
        injection: result.injection,
        secret: result.secret,
        request: parsed.data,
      });
      if (!outcome.ok) {
        const status =
          outcome.reason === 'forbidden_target'
            ? 403
            : outcome.reason === 'bad_request'
              ? 400
              : outcome.reason === 'timeout'
                ? 504
                : 502;
        return deny(outcome.reason, status, outcome.reason, outcome.message);
      }

      await audit({
        action: 'credential.proxy',
        success: true,
        agentId: agent.agentId,
        passportId: agent.passportId,
        credentialId: id,
        // Never log the secret; record target + downstream status only.
        detail: {
          target: result.target,
          method: parsed.data.method ?? 'GET',
          path: parsed.data.path ?? '/',
          downstreamStatus: outcome.response.status,
        },
        ip: req.ip,
      });

      // Return the downstream response. The secret is never sent downstream to
      // the agent: it is injected server-side, and redacted from the returned
      // body and headers should the downstream reflect it.
      return reply.send(outcome.response);
    },
  );
}
