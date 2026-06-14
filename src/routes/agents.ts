import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { and, eq, desc, count } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { hashSecret, generateKeySecret, formatApiKey } from '../crypto/secrets.js';
import { isValidScope } from '../auth/agent.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, page } from '../lib/http.js';

const issueSchema = z.object({
  passportId: z.string().uuid(),
  name: z.string().min(1).max(120),
  scopes: z
    .array(z.string().max(280))
    .max(32, 'too many scopes')
    .default(['vault:read', 'vault:use']),
  expiresAt: z.coerce.date().optional(),
});

export async function agentRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireHuman);

  // Issue an agent bound to one of the caller's passports. Returns the API key ONCE.
  app.post(
    '/v1/agents',
    {
      schema: {
        tags: ['agents'],
        summary: 'Issue an agent key bound to a passport',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const parsed = issueSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());
      const { passportId, name, scopes, expiresAt } = parsed.data;

      // Reject unknown/over-broad scopes (e.g. "admin:*") before anything else.
      const invalid = scopes.filter((s) => !isValidScope(s));
      if (invalid.length > 0) {
        await audit({
          action: 'authz.denied',
          success: false,
          principalId: req.human!.sub,
          passportId,
          detail: { reason: 'invalid_scopes', invalid },
          ip: req.ip,
        });
        return fail(req, reply, 400, 'invalid_scope', `invalid scopes: ${invalid.join(', ')}`);
      }

      // Normalize target host patterns to lowercase (hostnames are case-insensitive)
      // so they match credential targets, which are also stored lowercase.
      const normScopes = scopes.map((s) =>
        s.startsWith('target:') ? `target:${s.slice('target:'.length).toLowerCase()}` : s,
      );

      const [owned] = await db
        .select({ id: schema.passports.id })
        .from(schema.passports)
        .where(
          and(
            eq(schema.passports.id, passportId),
            eq(schema.passports.principalId, req.human!.sub),
          ),
        )
        .limit(1);
      if (!owned) return fail(req, reply, 404, 'not_found', 'passport not found');

      const secret = generateKeySecret();
      const [row] = await db
        .insert(schema.agents)
        .values({
          passportId,
          name,
          secretHash: await hashSecret(secret),
          scopes: normScopes,
          expiresAt: expiresAt ?? null,
        })
        .returning({
          id: schema.agents.id,
          name: schema.agents.name,
          scopes: schema.agents.scopes,
        });

      await audit({
        action: 'agent.issue',
        success: true,
        principalId: req.human!.sub,
        passportId,
        agentId: row!.id,
        detail: { scopes: normScopes },
        ip: req.ip,
      });

      // The plaintext key is shown exactly once and never stored.
      return reply.code(201).send({
        id: row!.id,
        name: row!.name,
        scopes: row!.scopes,
        apiKey: formatApiKey(row!.id, secret),
        warning: 'Store this apiKey now — it cannot be retrieved again.',
      });
    },
  );

  // List agents on the caller's passports.
  app.get(
    '/v1/agents',
    { schema: { tags: ['agents'], summary: 'List your agents', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());
      const rows = await db
        .select({
          id: schema.agents.id,
          name: schema.agents.name,
          passportId: schema.agents.passportId,
          scopes: schema.agents.scopes,
          active: schema.agents.active,
          revokedAt: schema.agents.revokedAt,
          expiresAt: schema.agents.expiresAt,
          lastUsedAt: schema.agents.lastUsedAt,
        })
        .from(schema.agents)
        .innerJoin(schema.passports, eq(schema.agents.passportId, schema.passports.id))
        .where(eq(schema.passports.principalId, req.human!.sub))
        .orderBy(desc(schema.agents.createdAt))
        .limit(q.data.limit)
        .offset(q.data.offset);
      const [tc] = await db
        .select({ value: count() })
        .from(schema.agents)
        .innerJoin(schema.passports, eq(schema.agents.passportId, schema.passports.id))
        .where(eq(schema.passports.principalId, req.human!.sub));
      return page(rows, q.data, tc!.value);
    },
  );

  // Revoke an agent (fail-closed flag flips immediately). Revoke + audit are atomic.
  app.post(
    '/v1/agents/:id/revoke',
    { schema: { tags: ['agents'], summary: 'Revoke an agent', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const [row] = await db
        .select({ id: schema.agents.id, passportId: schema.agents.passportId })
        .from(schema.agents)
        .innerJoin(schema.passports, eq(schema.agents.passportId, schema.passports.id))
        .where(and(eq(schema.agents.id, id), eq(schema.passports.principalId, req.human!.sub)))
        .limit(1);
      if (!row) return fail(req, reply, 404, 'not_found', 'agent not found');

      await db.transaction(async (tx) => {
        await tx
          .update(schema.agents)
          .set({ active: false, revokedAt: new Date() })
          .where(eq(schema.agents.id, id));
        await audit(
          {
            action: 'agent.revoke',
            success: true,
            principalId: req.human!.sub,
            passportId: row.passportId,
            agentId: id,
            ip: req.ip,
          },
          tx,
        );
      });

      return reply.send({ id, revoked: true });
    },
  );
}
