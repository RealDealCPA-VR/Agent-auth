import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { requireHuman } from './guards.js';
import { approveMfaRequest, denyMfaRequest, listPendingMfaFor } from '../lib/mfa.js';
import { fail, paginationSchema, page } from '../lib/http.js';

/**
 * Human-facing MFA queue. A credential owner (or a configured delegate) lists the
 * pending MFA challenges raised by their agents mid-browser-login and resolves
 * each one — approving with the one-time code (sealed at rest, never logged) or
 * denying. The code value never appears in the audit trail.
 */

const approveSchema = z.object({
  // The one-time code to seal. Omitted for push/webauthn ("I approved on my device").
  code: z.string().min(1).max(64).optional(),
});

export async function mfaRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireHuman);

  app.get(
    '/v1/mfa',
    { schema: { tags: ['mfa'], summary: 'List pending MFA requests you may approve', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());

      const { items, total } = await listPendingMfaFor(req.human!.sub, q.data);
      // Expose non-secret fields only — never sealedCode.
      const view = items.map((m) => ({
        id: m.id,
        challengeId: m.challengeId,
        credentialId: m.credentialId,
        passportId: m.passportId,
        agentId: m.agentId,
        kind: m.kind,
        channelHint: m.channelHint,
        promptText: m.promptText,
        status: m.status,
        createdAt: m.createdAt,
        expiresAt: m.expiresAt,
      }));
      return page(view, q.data, total);
    },
  );

  app.post(
    '/v1/mfa/:id/approve',
    { schema: { tags: ['mfa'], summary: 'Approve an MFA request (seals the one-time code)', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const parsed = approveSchema.safeParse(req.body ?? {});
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());

      const result = await approveMfaRequest(req.human!.sub, id, parsed.data.code ?? null, { ip: req.ip });
      if (!result.ok) {
        // forbidden (not owner/delegate) is surfaced as 404 so existence isn't leaked.
        if (result.reason === 'not_pending')
          return fail(req, reply, 409, 'conflict', 'mfa request is not pending');
        if (result.reason === 'code_required')
          return fail(req, reply, 400, 'invalid_request', 'a one-time code is required for this MFA kind');
        if (result.reason === 'seal_failed')
          return fail(req, reply, 500, 'internal', 'failed to seal the MFA code; try again');
        return fail(req, reply, 404, 'not_found', 'mfa request not found');
      }
      // mfa.approved is audited atomically inside approveMfaRequest's transaction.
      return reply.send({ id, status: 'approved' });
    },
  );

  app.post(
    '/v1/mfa/:id/deny',
    { schema: { tags: ['mfa'], summary: 'Deny an MFA request', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const result = await denyMfaRequest(req.human!.sub, id, { ip: req.ip });
      if (!result.ok) {
        if (result.reason === 'not_pending')
          return fail(req, reply, 409, 'conflict', 'mfa request is not pending');
        return fail(req, reply, 404, 'not_found', 'mfa request not found');
      }
      // mfa.denied is audited atomically inside denyMfaRequest's transaction.
      return reply.send({ id, status: 'denied' });
    },
  );
}
