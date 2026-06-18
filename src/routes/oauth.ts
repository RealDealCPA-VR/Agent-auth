import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { and, eq, gt } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { requireHuman } from './guards.js';
import { depositCredential } from '../lib/vault.js';
import { audit } from '../lib/audit.js';
import { fail } from '../lib/http.js';
import { env } from '../env.js';
import { getProvider, redirectUri } from '../oauth/registry.js';
import {
  buildAuthorizeUrl,
  exchangeCode,
  generatePkce,
  generateState,
  type TokenSet,
} from '../oauth/tokens.js';

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

const startSchema = z.object({
  // Optional override for where the credential will be used; defaults to the
  // provider name. Normalize like deposit targets (case-insensitive hosts).
  target: z
    .string()
    .min(1)
    .max(255)
    .transform((s) => s.toLowerCase())
    .optional(),
  label: z.string().min(1).max(120).optional(),
});

const callbackSchema = z.object({
  code: z.string().min(1),
  state: z.string().min(1),
});

/**
 * OAuth authorization-code capture. A human starts the flow for one of their
 * passports; the browser is sent to the provider; the provider redirects back to
 * the (unauthenticated) callback, where we exchange the code and seal the tokens
 * as an `oauth_token` credential the agent can later reuse (with transparent
 * refresh — see lib/vault.ts).
 */
export async function oauthRoutes(app: FastifyInstance): Promise<void> {
  // Start a flow (human-authenticated). Mints PKCE + state and returns the URL
  // the human's browser should visit to authorize.
  app.post(
    '/v1/passports/:id/oauth/:provider/start',
    {
      preHandler: requireHuman,
      schema: {
        tags: ['oauth'],
        summary: 'Begin an OAuth authorization-code flow for a passport',
        security: [{ humanBearer: [] }],
      },
    },
    async (req, reply) => {
      const { id, provider: providerName } = req.params as { id: string; provider: string };
      if (!(await ownsPassport(req, reply, id))) return;

      const provider = getProvider(providerName);
      if (!provider) return fail(req, reply, 404, 'unknown_provider', 'unknown oauth provider');
      if (!env.OAUTH_REDIRECT_BASE)
        return fail(req, reply, 500, 'oauth_misconfigured', 'OAUTH_REDIRECT_BASE is not set');

      const parsed = startSchema.safeParse(req.body ?? {});
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid body', parsed.error.flatten());

      const target = parsed.data.target ?? providerName;
      const label = parsed.data.label ?? `${providerName} oauth`;

      const { codeVerifier, codeChallenge } = generatePkce();
      const state = generateState();
      const expiresAt = new Date(Date.now() + env.OAUTH_STATE_TTL_SECONDS * 1000);

      await db.insert(schema.oauthFlows).values({
        state,
        codeVerifier,
        principalId: req.human!.sub,
        passportId: id,
        provider: providerName,
        target,
        label,
        expiresAt,
      });

      const authorizeUrl = buildAuthorizeUrl(provider, {
        redirectUri: redirectUri(),
        state,
        codeChallenge,
      });

      await audit({
        action: 'oauth.start',
        success: true,
        principalId: req.human!.sub,
        passportId: id,
        detail: { provider: providerName, target },
        ip: req.ip,
      });

      return reply.send({ authorizeUrl, state });
    },
  );

  // Provider redirect target. NO auth: the caller is the user's browser carrying
  // only ?code&state. The state is the CSRF binding back to the started flow.
  app.get(
    '/v1/oauth/callback',
    {
      schema: {
        tags: ['oauth'],
        summary: 'OAuth provider redirect — exchange the code and seal the tokens',
      },
    },
    async (req, reply) => {
      const parsed = callbackSchema.safeParse(req.query);
      if (!parsed.success) return fail(req, reply, 400, 'invalid_request', 'missing code or state');

      const now = new Date();
      const [flow] = await db
        .select()
        .from(schema.oauthFlows)
        .where(
          and(eq(schema.oauthFlows.state, parsed.data.state), gt(schema.oauthFlows.expiresAt, now)),
        )
        .limit(1);
      if (!flow) return fail(req, reply, 400, 'invalid_state', 'invalid or expired oauth state');

      const provider = getProvider(flow.provider);
      if (!provider) {
        // Provider was removed since the flow started; drop the stale flow.
        await db.delete(schema.oauthFlows).where(eq(schema.oauthFlows.id, flow.id));
        return fail(req, reply, 404, 'unknown_provider', 'unknown oauth provider');
      }

      let tokens: TokenSet;
      try {
        tokens = await exchangeCode(provider, {
          code: parsed.data.code,
          redirectUri: redirectUri(),
          codeVerifier: flow.codeVerifier,
        });
      } catch {
        // Never surface provider internals; delete the flow row so the spent
        // state/code can't be retried (a later attempt hits invalid_state above).
        await db.delete(schema.oauthFlows).where(eq(schema.oauthFlows.id, flow.id));
        return fail(
          req,
          reply,
          502,
          'oauth_exchange_failed',
          'failed to exchange authorization code',
        );
      }

      // Seal BOTH tokens together as the credential secret; expose only non-secret
      // hints (provider, expiry, scope) in metadata.
      const secret = JSON.stringify(tokens);
      const row = await depositCredential({
        passportId: flow.passportId,
        target: flow.target,
        label: flow.label,
        type: 'oauth_token',
        secret,
        metadata: {
          provider: flow.provider,
          scope: tokens.scope,
          tokenExpiresAt: tokens.expires_at,
        },
        expiresAt: null,
      });

      // One-time use: remove the flow regardless of seal outcome.
      await db.delete(schema.oauthFlows).where(eq(schema.oauthFlows.id, flow.id));

      if (!row) return fail(req, reply, 404, 'not_found', 'passport not found');

      await audit({
        action: 'oauth.capture',
        success: true,
        principalId: flow.principalId,
        passportId: flow.passportId,
        credentialId: row.id,
        detail: { provider: flow.provider, target: flow.target },
        ip: req.ip,
      });

      return reply.send({
        status: 'ok',
        credentialId: row.id,
        provider: flow.provider,
        target: row.target,
        label: row.label,
      });
    },
  );
}
