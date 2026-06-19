import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { and, eq, desc, count } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { createPassport, depositCredential } from '../lib/vault.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

// passport ids are Postgres uuid; a non-uuid would make the driver throw 22P02 (500).
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Confirm the authenticated human owns this passport, else 404 (no existence leak). */
async function ownsPassport(
  req: FastifyRequest,
  reply: FastifyReply,
  passportId: string,
): Promise<boolean> {
  if (!UUID_RE.test(passportId)) {
    await fail(req, reply, 404, 'not_found', 'passport not found');
    return false;
  }
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

// An HTTP header field-name token (RFC 7230). Validated at deposit so a header-mode
// injection name can never be a value the HTTP client rejects at proxy time (which
// would leave the credential structurally unusable via proxy mode).
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// How the secret is injected into a server-side proxied request (proxy mode).
const injectionSchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('bearer') }),
  z.object({ mode: z.literal('basic') }),
  z.object({ mode: z.literal('cookie') }),
  z.object({
    mode: z.literal('header'),
    name: z.string().min(1).max(64).regex(HEADER_NAME_RE, 'invalid header name'),
    prefix: z.string().max(64).optional(),
  }),
  z.object({ mode: z.literal('query'), name: z.string().min(1).max(64) }),
]);

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
  injection: injectionSchema.optional(),
  expiresAt: z.coerce.date().optional(),
  // Optional usage policy.
  maxUses: z.number().int().positive().max(1_000_000).optional(),
  allowedFrom: z.coerce.date().optional(),
  allowedUntil: z.coerce.date().optional(),
  requireApproval: z.boolean().optional(),
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
      return readPage(
        q.data,
        (tx) =>
          tx
            .select({
              id: schema.passports.id,
              name: schema.passports.name,
              createdAt: schema.passports.createdAt,
            })
            .from(schema.passports)
            .where(where)
            .orderBy(desc(schema.passports.createdAt))
            .limit(q.data.limit)
            .offset(q.data.offset),
        async (tx) =>
          (await tx.select({ value: count() }).from(schema.passports).where(where))[0]!.value,
      );
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
              createdAt: schema.credentials.createdAt,
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
}
