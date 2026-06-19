import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { and, eq, desc, count } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { hashSecret, generateKeySecret, formatApiKey } from '../crypto/secrets.js';
import { isValidScope } from '../auth/agent.js';
import { fingerprintFromPem, normalizeFingerprint } from '../auth/mtls.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

// agent ids are Postgres uuid; a non-uuid would make the driver throw 22P02 (500).
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const issueSchema = z.object({
  passportId: z.string().uuid(),
  name: z.string().min(1).max(120),
  scopes: z
    .array(z.string().max(280))
    .max(32, 'too many scopes')
    .default(['vault:read', 'vault:use']),
  expiresAt: z.coerce.date().optional(),
});

// Bind an mTLS client cert to an agent. Provide either a PEM cert (the
// fingerprint is derived from it) or a pre-computed SHA-256 fingerprint.
const mtlsBindSchema = z.object({
  certPem: z.string().min(1).optional(),
  fingerprint: z.string().min(1).optional(),
});

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

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
      const where = eq(schema.passports.principalId, req.human!.sub);
      return readPage(
        q.data,
        (tx) =>
          tx
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
            .where(where)
            .orderBy(desc(schema.agents.createdAt))
            .limit(q.data.limit)
            .offset(q.data.offset),
        async (tx) =>
          (
            await tx
              .select({ value: count() })
              .from(schema.agents)
              .innerJoin(schema.passports, eq(schema.agents.passportId, schema.passports.id))
              .where(where)
          )[0]!.value,
      );
    },
  );

  // Revoke an agent (fail-closed flag flips immediately). Revoke + audit are atomic.
  app.post(
    '/v1/agents/:id/revoke',
    { schema: { tags: ['agents'], summary: 'Revoke an agent', security: [{ humanBearer: [] }] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      if (!UUID_RE.test(id)) return fail(req, reply, 404, 'not_found', 'agent not found');
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

  // Bind an mTLS client certificate to one of the caller's agents. The agent may
  // then authenticate with that client cert (by fingerprint) as an alternative to
  // its bearer API key. Accepts a PEM cert (fingerprint derived server-side) or a
  // pre-normalized SHA-256 fingerprint. Idempotent overwrite of the binding.
  app.post(
    '/v1/agents/:id/mtls',
    {
      schema: {
        tags: ['agents'],
        summary: 'Bind an mTLS client cert to an agent',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      if (!UUID_RE.test(id)) return fail(req, reply, 404, 'not_found', 'agent not found');
      const parsed = mtlsBindSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());
      const { certPem, fingerprint } = parsed.data;

      // Derive the fingerprint from the cert, or accept a normalized one directly.
      let fp: string;
      if (certPem) {
        try {
          fp = fingerprintFromPem(certPem);
        } catch {
          return fail(
            req,
            reply,
            400,
            'invalid_request',
            'certPem is not a valid X.509 certificate',
          );
        }
      } else if (fingerprint) {
        fp = normalizeFingerprint(fingerprint);
      } else {
        return fail(req, reply, 400, 'invalid_request', 'provide certPem or fingerprint');
      }
      if (!SHA256_HEX_RE.test(fp))
        return fail(req, reply, 400, 'invalid_request', 'fingerprint must be a SHA-256 hex digest');

      // Ownership: the agent's passport must belong to the caller.
      const [row] = await db
        .select({ id: schema.agents.id, passportId: schema.agents.passportId })
        .from(schema.agents)
        .innerJoin(schema.passports, eq(schema.agents.passportId, schema.passports.id))
        .where(and(eq(schema.agents.id, id), eq(schema.passports.principalId, req.human!.sub)))
        .limit(1);
      if (!row) return fail(req, reply, 404, 'not_found', 'agent not found');

      // certFingerprint is globally UNIQUE; binding one already held by another
      // agent must be a clean 409, not a leaked 500 (which would also be a
      // cross-tenant existence oracle). Mirror the 23505 handling in principals.ts.
      try {
        await db.transaction(async (tx) => {
          await tx
            .update(schema.agents)
            .set({ certFingerprint: fp })
            .where(eq(schema.agents.id, id));
          await audit(
            {
              action: 'agent.mtls_bind',
              success: true,
              principalId: req.human!.sub,
              passportId: row.passportId,
              agentId: id,
              detail: { fingerprint: fp },
              ip: req.ip,
            },
            tx,
          );
        });
      } catch (err) {
        if ((err as { code?: string }).code === '23505')
          return fail(req, reply, 409, 'conflict', 'fingerprint already bound to another agent');
        throw err;
      }

      return reply.send({ id, certFingerprint: fp });
    },
  );
}
