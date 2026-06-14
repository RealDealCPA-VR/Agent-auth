import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { and, eq, desc, count } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { createPassport, depositCredential } from '../lib/vault.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, page } from '../lib/http.js';

/** Confirm the authenticated human owns this passport, else 404 (no existence leak). */
async function ownsPassport(
  req: FastifyRequest,
  reply: FastifyReply,
  passportId: string,
): Promise<boolean> {
  const [p] = await db
    .select({ id: schema.passports.id })
    .from(schema.passports)
    .where(
      and(eq(schema.passports.id, passportId), eq(schema.passports.principalId, req.human!.sub)),
    )
    .limit(1);
  if (!p) {
    await fail(req, reply, 404, 'not_found', 'passport not found');
    return false;
  }
  return true;
}

const createSchema = z.object({ name: z.string().min(1).max(120) });

// Metadata must be a small, flat-ish JSON object — cap serialized size to 4 KiB.
const metadataSchema = z
  .record(z.unknown())
  .refine(
    (m) => Buffer.byteLength(JSON.stringify(m), 'utf8') <= 4096,
    'metadata too large (max 4 KiB)',
  );

const depositSchema = z.object({
  // Hostnames are case-insensitive; normalize so scope matching is consistent.
  target: z
    .string()
    .min(1)
    .max(255)
    .transform((s) => s.toLowerCase()),
  label: z.string().min(1).max(120),
  type: z.enum(schema.credentialType.enumValues),
  secret: z.string().min(1).max(8192),
  metadata: metadataSchema.optional(),
  expiresAt: z.coerce.date().optional(),
});

export async function passportRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireHuman);

  app.post(
    '/v1/passports',
    {
      schema: {
        tags: ['passports'],
        summary: 'Create a passport (vault)',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const parsed = createSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());
      const row = await createPassport(req.human!.sub, parsed.data.name);
      await audit({
        action: 'passport.create',
        success: true,
        principalId: req.human!.sub,
        passportId: row.id,
        ip: req.ip,
      });
      return reply.code(201).send(row);
    },
  );

  app.get(
    '/v1/passports',
    {
      schema: {
        tags: ['passports'],
        summary: 'List your passports',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());
      const where = eq(schema.passports.principalId, req.human!.sub);
      const rows = await db
        .select({
          id: schema.passports.id,
          name: schema.passports.name,
          createdAt: schema.passports.createdAt,
        })
        .from(schema.passports)
        .where(where)
        .orderBy(desc(schema.passports.createdAt))
        .limit(q.data.limit)
        .offset(q.data.offset);
      const [tc] = await db.select({ value: count() }).from(schema.passports).where(where);
      return page(rows, q.data, tc!.value);
    },
  );

  // Deposit a credential — the "log in once manually" step.
  app.post(
    '/v1/passports/:id/credentials',
    {
      schema: {
        tags: ['credentials'],
        summary: 'Deposit a credential into a passport',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      if (!(await ownsPassport(req, reply, id))) return;

      const parsed = depositSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());

      const row = await depositCredential({ passportId: id, ...parsed.data });
      if (!row) return fail(req, reply, 404, 'not_found', 'passport not found');

      await audit({
        action: 'credential.deposit',
        success: true,
        principalId: req.human!.sub,
        passportId: id,
        credentialId: row.id,
        detail: { target: row.target, type: row.type },
        ip: req.ip,
      });
      // Never echo the secret back.
      return reply.code(201).send(row);
    },
  );

  // List credential metadata in a passport (no secrets).
  app.get(
    '/v1/passports/:id/credentials',
    {
      schema: {
        tags: ['credentials'],
        summary: 'List credential metadata in a passport',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      if (!(await ownsPassport(req, reply, id))) return;
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());
      const where = eq(schema.credentials.passportId, id);
      const rows = await db
        .select({
          id: schema.credentials.id,
          target: schema.credentials.target,
          label: schema.credentials.label,
          type: schema.credentials.type,
          metadata: schema.credentials.metadata,
          expiresAt: schema.credentials.expiresAt,
          createdAt: schema.credentials.createdAt,
        })
        .from(schema.credentials)
        .where(where)
        .orderBy(desc(schema.credentials.createdAt))
        .limit(q.data.limit)
        .offset(q.data.offset);
      const [tc] = await db.select({ value: count() }).from(schema.credentials).where(where);
      return page(rows, q.data, tc!.value);
    },
  );
}
