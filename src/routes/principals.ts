import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { hashSecret, verifySecret, getDummyHash } from '../crypto/secrets.js';
import { issueSession, revokeSession } from '../auth/human.js';
import { requireHuman } from './guards.js';
import { audit } from '../lib/audit.js';
import { fail } from '../lib/http.js';
import { env } from '../env.js';

const credsSchema = z.object({
  // Email addresses are case-insensitive in practice; normalize to lowercase so
  // case variants can't create duplicate accounts or bypass the login lookup.
  email: z.string().email().max(254).toLowerCase(),
  password: z.string().min(10, 'password must be at least 10 characters').max(1024),
});

// Strict limits on auth endpoints to blunt brute-force + argon2 CPU-DoS.
const authRateLimit = {
  config: { rateLimit: { max: env.RATE_LIMIT_AUTH_MAX, timeWindow: env.RATE_LIMIT_WINDOW } },
};

export async function principalRoutes(app: FastifyInstance): Promise<void> {
  // Register a human principal.
  app.post(
    '/v1/principals',
    { ...authRateLimit, schema: { tags: ['auth'], summary: 'Register a principal (human owner)' } },
    async (req, reply) => {
      const parsed = credsSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(
          req,
          reply,
          400,
          'invalid_request',
          'invalid email or password',
          parsed.error.flatten(),
        );
      const { email, password } = parsed.data;

      const existing = await db
        .select({ id: schema.principals.id })
        .from(schema.principals)
        .where(eq(schema.principals.email, email))
        .limit(1);
      if (existing.length > 0) return fail(req, reply, 409, 'conflict', 'email already registered');

      let row;
      try {
        [row] = await db
          .insert(schema.principals)
          .values({ email, passwordHash: await hashSecret(password) })
          .returning({ id: schema.principals.id, email: schema.principals.email });
      } catch (err) {
        // Concurrent registration of the same email loses the unique-constraint
        // race (Postgres 23505) — return the same 409 as the pre-check path.
        if ((err as { code?: string }).code === '23505') {
          return fail(req, reply, 409, 'conflict', 'email already registered');
        }
        throw err;
      }

      await audit({
        action: 'principal.register',
        success: true,
        principalId: row!.id,
        ip: req.ip,
      });
      return reply.code(201).send({ id: row!.id, email: row!.email });
    },
  );

  // Interactive login — returns a session JWT.
  app.post(
    '/v1/auth/login',
    { ...authRateLimit, schema: { tags: ['auth'], summary: 'Log in, returns a session token' } },
    async (req, reply) => {
      const parsed = credsSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 401, 'unauthorized', 'invalid email or password');
      const { email, password } = parsed.data;

      const [row] = await db
        .select()
        .from(schema.principals)
        .where(eq(schema.principals.email, email))
        .limit(1);

      // Constant-time w.r.t. account existence: always run an argon2 verify, using
      // a dummy hash when the account is absent, so timing can't enumerate users.
      const ok = await verifySecret(row ? row.passwordHash : await getDummyHash(), password);
      if (!row || !ok) {
        await audit({ action: 'principal.login', success: false, detail: { email }, ip: req.ip });
        return fail(req, reply, 401, 'unauthorized', 'invalid email or password');
      }

      const session = await issueSession({ sub: row.id, email: row.email });
      await audit({ action: 'principal.login', success: true, principalId: row.id, ip: req.ip });
      return reply.send({
        token: session.token,
        tokenType: 'Bearer',
        expiresAt: session.expiresAt.toISOString(),
      });
    },
  );

  // Logout — revoke the presented session token.
  app.post(
    '/v1/auth/logout',
    {
      preHandler: requireHuman,
      schema: {
        tags: ['auth'],
        summary: 'Revoke the current session',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const human = req.human!;
      // Keep the denylist entry exactly until the token's own expiry, no longer.
      await revokeSession(human.jti, human.sub, new Date(human.exp * 1000));
      await audit({
        action: 'principal.logout',
        success: true,
        principalId: human.sub,
        ip: req.ip,
      });
      return reply.send({ loggedOut: true });
    },
  );
}
