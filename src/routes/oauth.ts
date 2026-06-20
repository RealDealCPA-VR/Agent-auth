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

      // The caller here is the user's BROWSER (the provider redirect). When it
      // accepts HTML, render a small self-contained success page that signals the
      // opener (the admin UI) to refresh and invites the user to close the tab —
      // instead of dumping raw API JSON. Programmatic callers (and tests) get the
      // JSON envelope as before via content negotiation.
      if (acceptsHtml(req.headers.accept)) {
        return reply
          .type('text/html; charset=utf-8')
          .send(oauthSuccessHtml({ provider: flow.provider, target: row.target, label: row.label }));
      }

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

/** True when the request's Accept header prefers HTML (a real browser redirect). */
function acceptsHtml(accept: string | undefined): boolean {
  return typeof accept === 'string' && accept.toLowerCase().includes('text/html');
}

/** Minimal HTML entity escape for values interpolated into the success page. */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * A tiny, dependency-free success page shown in the OAuth popup. It notifies the
 * opener window (the admin UI) so it can reload its credential list, then tells
 * the user they may close the tab. Carries no secret — only the provider/target/
 * label already returned in the JSON form.
 */
function oauthSuccessHtml(args: { provider: string; target: string; label: string }): string {
  const provider = escapeHtml(args.provider);
  const target = escapeHtml(args.target);
  const label = escapeHtml(args.label);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected — AgentAuth</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#0b0c10; color:#e6e6e6;
         display:flex; min-height:100vh; align-items:center; justify-content:center; margin:0; }
  .card { max-width:420px; padding:2rem; background:#14161c; border:1px solid #2a2e39; border-radius:12px; }
  h1 { font-size:1.25rem; margin:0 0 .5rem; }
  .muted { color:#9aa0ac; font-size:.9rem; }
  code { color:#7ee0c0; }
</style>
</head>
<body>
  <div class="card">
    <h1>✓ Connected ${provider}</h1>
    <p class="muted">Sealed <strong>${label}</strong> for <code>${target}</code>. You can close this tab.</p>
  </div>
  <script>
    try { if (window.opener) window.opener.postMessage({ type: 'agentauth:oauth-captured' }, '*'); } catch (e) {}
  </script>
</body>
</html>`;
}
