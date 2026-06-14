import type { FastifyInstance } from 'fastify';
import { desc, eq, or, inArray, count } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { verifyAuditChain } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

export async function auditRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireHuman);

  // Audit trail scoped to the caller: their principal-level events plus events
  // on any passport they own.
  app.get(
    '/v1/audit',
    {
      schema: {
        tags: ['audit'],
        summary: 'Read your audit trail',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());

      const owned = await db
        .select({ id: schema.passports.id })
        .from(schema.passports)
        .where(eq(schema.passports.principalId, req.human!.sub));
      const passportIds = owned.map((p) => p.id);

      const scope =
        passportIds.length > 0
          ? or(
              eq(schema.auditEvents.principalId, req.human!.sub),
              inArray(schema.auditEvents.passportId, passportIds),
            )
          : eq(schema.auditEvents.principalId, req.human!.sub);

      return readPage(
        q.data,
        (tx) =>
          tx
            .select({
              id: schema.auditEvents.id,
              seq: schema.auditEvents.seq,
              action: schema.auditEvents.action,
              success: schema.auditEvents.success,
              passportId: schema.auditEvents.passportId,
              agentId: schema.auditEvents.agentId,
              credentialId: schema.auditEvents.credentialId,
              detail: schema.auditEvents.detail,
              createdAt: schema.auditEvents.createdAt,
            })
            .from(schema.auditEvents)
            .where(scope)
            .orderBy(desc(schema.auditEvents.seq))
            .limit(q.data.limit)
            .offset(q.data.offset),
        async (tx) =>
          (await tx.select({ value: count() }).from(schema.auditEvents).where(scope))[0]!.value,
      );
    },
  );

  // Verify the global audit hash-chain integrity (tamper detection).
  app.get(
    '/v1/audit/verify',
    {
      schema: {
        tags: ['audit'],
        summary: 'Verify audit log integrity (hash chain)',
        security: [{ humanBearer: [] }],
      },
    },
    async () => {
      const result = await verifyAuditChain();
      return result;
    },
  );
}
