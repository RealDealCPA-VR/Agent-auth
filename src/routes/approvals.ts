import type { FastifyInstance } from 'fastify';
import { and, count, desc, eq, gt, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { approve, deny } from '../lib/approvals.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, page, readPage } from '../lib/http.js';

/**
 * Human-facing approval queue. A passport owner lists the pending approval
 * requests raised against their credentials and approves or denies each one.
 * All routes are scoped to the caller's owned passports.
 */

/** Pending, non-expired requests against the given owned passports. */
function pendingWhere(passportIds: string[]) {
  return and(
    inArray(schema.approvalRequests.passportId, passportIds),
    eq(schema.approvalRequests.status, 'pending'),
    gt(schema.approvalRequests.expiresAt, new Date()),
  );
}

export async function approvalRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireHuman);

  // List pending requests across every passport the caller owns.
  app.get(
    '/v1/approvals',
    {
      schema: {
        tags: ['approvals'],
        summary: 'List pending approval requests for your passports',
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
      // Nothing owned => nothing to approve; short-circuit to an empty page.
      if (passportIds.length === 0) return page([], q.data, 0);

      const where = pendingWhere(passportIds);
      return readPage(
        q.data,
        (tx) =>
          tx
            .select({
              id: schema.approvalRequests.id,
              credentialId: schema.approvalRequests.credentialId,
              passportId: schema.approvalRequests.passportId,
              agentId: schema.approvalRequests.agentId,
              status: schema.approvalRequests.status,
              createdAt: schema.approvalRequests.createdAt,
              expiresAt: schema.approvalRequests.expiresAt,
            })
            .from(schema.approvalRequests)
            .where(where)
            .orderBy(desc(schema.approvalRequests.createdAt))
            .limit(q.data.limit)
            .offset(q.data.offset),
        async (tx) =>
          (
            await tx
              .select({ value: count() })
              .from(schema.approvalRequests)
              .where(where)
          )[0]!.value,
      );
    },
  );

  app.post(
    '/v1/approvals/:id/approve',
    {
      schema: {
        tags: ['approvals'],
        summary: 'Approve a pending request',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const result = await approve(id, req.human!.sub);
      if (!result) return fail(req, reply, 404, 'not_found', 'approval request not found');
      await audit({
        action: 'approval.approve',
        success: true,
        principalId: req.human!.sub,
        detail: { requestId: id },
        ip: req.ip,
      });
      return reply.send(result);
    },
  );

  app.post(
    '/v1/approvals/:id/deny',
    {
      schema: {
        tags: ['approvals'],
        summary: 'Deny a pending request',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const result = await deny(id, req.human!.sub);
      if (!result) return fail(req, reply, 404, 'not_found', 'approval request not found');
      await audit({
        action: 'approval.deny',
        success: true,
        principalId: req.human!.sub,
        detail: { requestId: id },
        ip: req.ip,
      });
      return reply.send(result);
    },
  );
}
