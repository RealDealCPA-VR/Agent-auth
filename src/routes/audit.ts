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
              // NOTE: the global `seq` is intentionally NOT returned — it is a
              // cross-tenant bigserial, so exposing it would let a tenant infer
              // others' activity volume via gap analysis (the same reason
              // /v1/audit/verify withholds count/brokenAtSeq). Order by it server-
              // side, surface only the per-row `id` + `createdAt` to clients.
              id: schema.auditEvents.id,
              action: schema.auditEvents.action,
              success: schema.auditEvents.success,
              principalId: schema.auditEvents.principalId,
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
      // The chain spans all tenants (prevHash links every row), so verification is
      // necessarily global. Return ONLY the boolean integrity signal — exposing the
      // global event `count` / `brokenAtSeq` to any self-registered human would leak
      // cross-tenant aggregate activity. (Operators can read full detail from logs.)
      const result = await verifyAuditChain();
      return { ok: result.ok };
    },
  );
}
