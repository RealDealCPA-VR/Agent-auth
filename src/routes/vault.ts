import type { FastifyInstance } from 'fastify';
import { and, count, desc, eq, or, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { schema } from '../db/index.js';
import { requireAgent } from './guards.js';
import { hasScope, allowsTarget } from '../auth/agent.js';
import { useCredential, getCredentialTarget, getCredentialMeta, releaseUse } from '../lib/vault.js';
import { proxyRequest, precheckProxyTarget } from '../lib/proxy.js';
import { buildBrowserPlan, precheckBrowserSpec } from '../lib/browser.js';
import { createMfaRequest, fetchMfaCode } from '../lib/mfa.js';
import { audit } from '../lib/audit.js';
import { fail, paginationSchema, readPage } from '../lib/http.js';

// Header names must be valid HTTP tokens; values must be visible ASCII (+ SP/HT)
// with no CR/LF/NUL/control chars. Reject malformed agent headers here so they
// can't reach the HTTP client (which throws synchronously on them) — and so a
// bad header is a 400 BEFORE any credential use is charged.
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;
const headersSchema = z
  .record(z.string())
  .refine(
    (h) =>
      Object.entries(h).every(
        ([k, v]) => HEADER_NAME_RE.test(k) && HEADER_VALUE_RE.test(v),
      ),
    { message: 'invalid header name or value' },
  );

// Body for proxy mode: the agent controls method/path/query/body/headers only —
// the host is pinned to the credential's target server-side.
const proxyBodySchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']).default('GET'),
  path: z.string().max(4096).startsWith('/', 'path must start with /').default('/'),
  query: z.record(z.string()).optional(),
  headers: headersSchema.optional(),
  body: z.string().max(1_048_576).optional(),
});

/**
 * Translate an agent's `target:` scopes into a SQL predicate equivalent to
 * allowsTarget(), so target-scoping is enforced in the query and pagination is
 * bounded at the database (never fetch-all-then-filter). Returns undefined when
 * the agent is unconstrained. Host patterns are validated at issuance to contain
 * no SQL-LIKE metacharacters.
 */
function targetCondition(scopes: string[]): SQL | undefined {
  const pats = scopes.filter((s) => s.startsWith('target:')).map((s) => s.slice('target:'.length));
  if (pats.length === 0 || pats.includes('*')) return undefined;
  // Reduce the stored target to its bare host IN SQL — strip an http(s):// scheme,
  // everything from the first ':' or '/', and a trailing dot — so the list
  // predicate matches exactly what allowsTarget()/targetHost() authorize for
  // use/proxy, regardless of whether the target was deposited bare, as a URL, or
  // with a port/path. (Comparing on the real host avoids both the under-listing
  // and any LIKE over-matching of a host embedded in a path.)
  const host = sql`rtrim(regexp_replace(regexp_replace(lower(${schema.credentials.target}), '^https?://', ''), '[:/].*$', ''), '.')`;
  const conds: SQL[] = [];
  for (const raw of pats) {
    const pat = raw.toLowerCase(); // hosts are case-insensitive
    if (pat.startsWith('*.')) {
      // Single-label subdomain only (api.example.com, not a.b.example.com or the
      // apex) — mirrors matchesTargetPattern(). `pat` is bound as a parameter.
      const suffix = pat.slice(2);
      conds.push(sql`(${host} LIKE ${'%.' + suffix} AND ${host} NOT LIKE ${'%.%.' + suffix})`);
    } else {
      conds.push(sql`${host} = ${pat}`);
    }
  }
  return or(...conds);
}

/**
 * Agent-facing vault. Authenticated with an agent API key. This is where the
 * agent "logs in to anything" — it discovers the credentials it is scoped for
 * and unseals the one it needs, scoped and audited.
 */
export async function vaultRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preHandler', requireAgent);

  // Discover credential metadata — only for targets this agent is scoped for.
  app.get(
    '/v1/vault/credentials',
    {
      schema: {
        tags: ['vault'],
        summary: 'List credentials available to this agent',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const agent = req.agent!;
      // vault:read OR vault:proxy may list metadata. A proxy-only agent (granted
      // vault:proxy without vault:read so it can act through credentials it can
      // never read) still needs to resolve a target host to a credential id —
      // and listing returns metadata only (never a secret), bounded by the same
      // target-scoping, so this grants no extra reach than the proxy it already has.
      if (!hasScope(agent.scopes, 'vault:read') && !hasScope(agent.scopes, 'vault:proxy')) {
        return fail(req, reply, 403, 'forbidden', 'missing scope: vault:read');
      }
      const q = paginationSchema.safeParse(req.query);
      if (!q.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid pagination', q.error.flatten());

      // Target-scoping is enforced in SQL so the query (and memory) is bounded by
      // the requested page, not the size of the passport's whole vault.
      const tcond = targetCondition(agent.scopes);
      const where = tcond
        ? and(eq(schema.credentials.passportId, agent.passportId), tcond)
        : eq(schema.credentials.passportId, agent.passportId);

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

  // Unseal and return a credential secret for use against its target.
  app.post(
    '/v1/vault/credentials/:id/use',
    {
      schema: {
        tags: ['vault'],
        summary: 'Unseal a credential for use',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;

      const deny = async (reason: string, status = 403, code = 'forbidden', msg = reason) => {
        await audit({
          action: 'credential.use',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason },
          ip: req.ip,
        });
        return fail(req, reply, status, code, msg);
      };

      if (!hasScope(agent.scopes, 'vault:use')) return deny('missing scope: vault:use');

      // Validate target-scope BEFORE charging a use, so a rejected call never
      // burns a maxUses slot or spends an approval grant (mirrors the proxy route).
      const meta = await getCredentialTarget(agent.passportId, id);
      if (!meta) return deny('not_found', 404, 'not_found', 'credential not found');
      if (!allowsTarget(agent.scopes, meta.target)) {
        return deny(
          `target_not_allowed:${meta.target}`,
          403,
          'forbidden',
          `agent not scoped for target: ${meta.target}`,
        );
      }

      const result = await useCredential(agent.passportId, id, { agentId: agent.agentId });
      if (result.status === 'not_found')
        return deny('not_found', 404, 'not_found', 'credential not found');
      if (result.status === 'expired')
        return deny('expired', 410, 'expired', 'credential has expired');
      if (result.status === 'not_yet_valid')
        return deny('not_yet_valid', 403, 'not_yet_valid', 'credential is not yet usable');
      if (result.status === 'window_expired')
        return deny('window_expired', 410, 'window_expired', 'credential usage window has ended');
      if (result.status === 'use_limit')
        return deny('use_limit', 429, 'use_limit_reached', 'credential use limit reached');
      if (result.status === 'approval_denied')
        return deny('approval_denied', 403, 'approval_denied', 'use was denied by an owner');
      if (result.status === 'approval_pending') {
        // Not a hard failure: the request is queued for a human. Return 202 with
        // the request id (not the error envelope), but still audit success:false
        // so the trail records that the secret was withheld pending approval.
        await audit({
          action: 'credential.use',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason: 'approval_pending', requestId: result.requestId },
          ip: req.ip,
        });
        return reply.code(202).send({
          status: 'pending',
          requestId: result.requestId,
          message: 'awaiting approval',
        });
      }
      if (result.status === 'refresh_failed')
        return deny('refresh_failed', 502, 'oauth_refresh_failed', 'failed to refresh oauth token');
      if (result.status === 'decrypt_error')
        return deny('decrypt_error', 500, 'internal', 'failed to unseal credential');

      await audit({
        action: 'credential.use',
        success: true,
        agentId: agent.agentId,
        passportId: agent.passportId,
        credentialId: id,
        detail: { target: result.target, type: result.type },
        ip: req.ip,
      });

      // The only endpoint that returns cleartext secret material.
      return reply.send({
        id: result.id,
        target: result.target,
        label: result.label,
        type: result.type,
        metadata: result.metadata,
        expiresAt: result.expiresAt,
        secret: result.secret,
      });
    },
  );

  // Proxy mode: AgentAuth makes the downstream request and injects the credential
  // server-side, so the raw secret never reaches the agent. The agent supplies
  // only method/path/query/body; the host is pinned to the credential's target.
  app.post(
    '/v1/vault/credentials/:id/proxy',
    {
      schema: {
        tags: ['vault'],
        summary: 'Proxy a request to the credential target with the secret injected server-side',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;

      const deny = async (reason: string, status = 403, code = 'forbidden', msg = reason) => {
        await audit({
          action: 'credential.proxy',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason },
          ip: req.ip,
        });
        return fail(req, reply, status, code, msg);
      };

      if (!hasScope(agent.scopes, 'vault:proxy')) return deny('missing scope: vault:proxy');

      const parsed = proxyBodySchema.safeParse(req.body);
      if (!parsed.success)
        return fail(
          req,
          reply,
          400,
          'invalid_request',
          'invalid proxy request',
          parsed.error.flatten(),
        );

      // Validate target-scope + the SSRF/path guards BEFORE charging a use, so a
      // proxy rejected by these pre-charge checks never burns a maxUses slot or
      // spends an approval grant. A downstream failure AFTER the charge (timeout,
      // unreachable, or a connect-time rebind block) is compensated via releaseUse
      // below, so no rejected proxy ever permanently consumes a slot/grant.
      const meta = await getCredentialTarget(agent.passportId, id);
      if (!meta) return deny('not_found', 404, 'not_found', 'credential not found');
      if (!allowsTarget(agent.scopes, meta.target)) {
        return deny(
          `target_not_allowed:${meta.target}`,
          403,
          'forbidden',
          `agent not scoped for target: ${meta.target}`,
        );
      }
      const pre = await precheckProxyTarget(meta.target, parsed.data.path ?? '/');
      if (pre) {
        const status = pre.reason === 'bad_request' ? 400 : 403;
        // Surface the specific reason as the machine code (e.g. 'forbidden_target')
        // so a pre-charge SSRF rejection matches the connect-time path's code.
        const code = pre.reason === 'bad_request' ? 'invalid_request' : pre.reason;
        return deny(pre.reason, status, code, pre.message);
      }

      const result = await useCredential(agent.passportId, id, { agentId: agent.agentId });
      if (result.status === 'not_found')
        return deny('not_found', 404, 'not_found', 'credential not found');
      if (result.status === 'expired')
        return deny('expired', 410, 'expired', 'credential has expired');
      if (result.status === 'not_yet_valid')
        return deny('not_yet_valid', 403, 'not_yet_valid', 'credential is not yet usable');
      if (result.status === 'window_expired')
        return deny('window_expired', 410, 'window_expired', 'credential usage window has ended');
      if (result.status === 'use_limit')
        return deny('use_limit', 429, 'use_limit_reached', 'credential use limit reached');
      if (result.status === 'approval_denied')
        return deny('approval_denied', 403, 'approval_denied', 'use was denied by an owner');
      if (result.status === 'approval_pending') {
        await audit({
          action: 'credential.proxy',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason: 'approval_pending', requestId: result.requestId },
          ip: req.ip,
        });
        return reply
          .code(202)
          .send({ status: 'pending', requestId: result.requestId, message: 'awaiting approval' });
      }
      if (result.status === 'refresh_failed')
        return deny('refresh_failed', 502, 'oauth_refresh_failed', 'failed to refresh oauth token');
      if (result.status === 'decrypt_error')
        return deny('decrypt_error', 500, 'internal', 'failed to unseal credential');

      const outcome = await proxyRequest({
        target: result.target,
        type: result.type,
        injection: result.injection,
        secret: result.secret,
        request: parsed.data,
      });
      if (!outcome.ok) {
        // Refund the slot / approval grant ONLY when the secret-bearing request
        // never reached the target (pre-send failures: SSRF block, bad request,
        // connect failure). A response-phase timeout / post-send RST already
        // delivered the secret to the target, so the use counts at-most-once and
        // must NOT be refunded (else a retry could exceed maxUses / one approval).
        if (!outcome.delivered) await releaseUse(agent.passportId, id, result.consumedGrantId);
        const status =
          outcome.reason === 'forbidden_target'
            ? 403
            : outcome.reason === 'bad_request'
              ? 400
              : outcome.reason === 'timeout'
                ? 504
                : 502;
        return deny(outcome.reason, status, outcome.reason, outcome.message);
      }

      await audit({
        action: 'credential.proxy',
        success: true,
        agentId: agent.agentId,
        passportId: agent.passportId,
        credentialId: id,
        // Never log the secret; record target + downstream status only.
        detail: {
          target: result.target,
          method: parsed.data.method ?? 'GET',
          path: parsed.data.path ?? '/',
          downstreamStatus: outcome.response.status,
        },
        ip: req.ip,
      });

      // Return the downstream response. The secret is never sent downstream to
      // the agent: it is injected server-side, and redacted from the returned
      // body and headers should the downstream reflect it.
      return reply.send(outcome.response);
    },
  );

  // Browser-login mode: turn a credential into a concrete plan of browser actions
  // (set cookies / fill a login form / set an auth header) so an agent driving a
  // real browser can authenticate to a web app. Like /use, the returned plan
  // CARRIES secret material (it is the same vault:use trust level); the meaningful
  // "secret stays out of the agent's reasoning" boundary is the SDK helper, which
  // applies the plan to a page and never returns its values up to the caller.
  app.post(
    '/v1/vault/credentials/:id/browser-login',
    {
      schema: {
        tags: ['vault'],
        summary: 'Build a browser-login plan (cookies/form/header) for a credential',
        security: [{ agentKey: [] }],
      },
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;

      // raw=true is the LIABILITY path: the agent intends to receive the plan
      // (secret-bearing) and hold it itself (SDK getBrowserLoginPlan), rather than
      // letting the SDK helper apply it to a page and confine it. Gate it behind an
      // explicit, off-by-default scope so the unsafe affordance is opt-in per agent.
      // Robust parse: treat ANY presence of `raw` that isn't the literal "false" as
      // raw=true (incl. a duplicated `?raw=true&raw=true` that Fastify parses to an
      // array). A brittle `=== 'true'` would let an array evade the gate; here an
      // ambiguous/duplicated raw applies the STRICTER scope check, never bypasses it.
      // Computed up front so the deny() audit can record caller raw-intent too.
      const rawParam = (req.query as { raw?: unknown } | undefined)?.raw;
      const raw = rawParam !== undefined && rawParam !== 'false' && rawParam !== false;

      const deny = async (reason: string, status = 403, code = 'forbidden', msg = reason) => {
        await audit({
          action: 'credential.browser',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason, via: 'browser', raw },
          ip: req.ip,
        });
        return fail(req, reply, status, code, msg);
      };

      // Browser-login returns secret material, so it is gated on vault:use (same
      // trust level as /use), not the never-reaches-agent vault:proxy scope.
      if (!hasScope(agent.scopes, 'vault:use')) return deny('missing scope: vault:use');

      if (raw && !hasScope(agent.scopes, 'vault:browser:raw')) {
        return deny(
          'missing scope: vault:browser:raw',
          403,
          'missing_scope',
          'missing scope: vault:browser:raw (raw browser-login plans are off by default)',
        );
      }

      // Validate target-scope AND that a plan can be built (spec present/valid,
      // username available) BEFORE charging a use — so a misconfigured or
      // out-of-scope call never burns a maxUses slot or spends an approval grant.
      const meta = await getCredentialMeta(agent.passportId, id);
      if (!meta) return deny('not_found', 404, 'not_found', 'credential not found');
      if (!allowsTarget(agent.scopes, meta.target)) {
        return deny(
          `target_not_allowed:${meta.target}`,
          403,
          'forbidden',
          `agent not scoped for target: ${meta.target}`,
        );
      }
      const browserSpec = (meta.metadata as Record<string, unknown> | null)?.browser ?? null;
      const pre = precheckBrowserSpec(meta.type, meta.target, meta.metadata, browserSpec);
      if (pre) {
        // A host-pin violation is the same authorization class as the proxy
        // route's off-host rejection — surface it as 403 forbidden_target for
        // cross-route consistency; genuine spec-shape/username errors stay 422.
        const status = pre.reason === 'forbidden_target' ? 403 : 422;
        return deny(pre.reason, status, pre.reason, pre.message);
      }

      const result = await useCredential(agent.passportId, id, { agentId: agent.agentId });
      if (result.status === 'not_found')
        return deny('not_found', 404, 'not_found', 'credential not found');
      if (result.status === 'expired')
        return deny('expired', 410, 'expired', 'credential has expired');
      if (result.status === 'not_yet_valid')
        return deny('not_yet_valid', 403, 'not_yet_valid', 'credential is not yet usable');
      if (result.status === 'window_expired')
        return deny('window_expired', 410, 'window_expired', 'credential usage window has ended');
      if (result.status === 'use_limit')
        return deny('use_limit', 429, 'use_limit_reached', 'credential use limit reached');
      if (result.status === 'approval_denied')
        return deny('approval_denied', 403, 'approval_denied', 'use was denied by an owner');
      if (result.status === 'approval_pending') {
        await audit({
          action: 'credential.browser',
          success: false,
          agentId: agent.agentId,
          passportId: agent.passportId,
          credentialId: id,
          detail: { reason: 'approval_pending', via: 'browser', requestId: result.requestId },
          ip: req.ip,
        });
        return reply
          .code(202)
          .send({ status: 'pending', requestId: result.requestId, message: 'awaiting approval' });
      }
      if (result.status === 'refresh_failed')
        return deny('refresh_failed', 502, 'oauth_refresh_failed', 'failed to refresh oauth token');
      if (result.status === 'decrypt_error')
        return deny('decrypt_error', 500, 'internal', 'failed to unseal credential');

      const built = buildBrowserPlan({
        target: result.target,
        type: result.type,
        secret: result.secret,
        metadata: result.metadata,
        spec: (result.metadata as Record<string, unknown> | null)?.browser ?? null,
      });
      if (!built.ok) {
        // The use was charged but no usable plan came back (e.g. an empty-secret
        // cookie): refund so a misconfig never bricks a maxUses:1 credential.
        await releaseUse(agent.passportId, id, result.consumedGrantId);
        const status = built.reason === 'forbidden_target' ? 403 : 422;
        return deny(built.reason, status, built.reason, built.message);
      }

      await audit({
        action: 'credential.browser',
        success: true,
        agentId: agent.agentId,
        passportId: agent.passportId,
        credentialId: id,
        // Never log the plan/secret. `raw` is the raw-REQUEST flag (caller intent:
        // whether vault:browser:raw was exercised) — the server returns the same
        // secret-bearing plan either way and cannot attest that a non-raw caller
        // actually confined the secret in the SDK helper.
        detail: { target: result.target, type: result.type, via: 'browser', mode: built.plan.mode, raw },
        ip: req.ip,
      });

      return reply.send(built.plan);
    },
  );

  // MFA handoff — agent side. On detecting an MFA challenge mid-browser-login, the
  // SDK helper opens a request here; a human owner resolves it; the SDK then fetches
  // the one-time code (once) and injects it into the browser DOM. The code never
  // returns to the agent's reasoning layer — same confinement as the login plan.
  const mfaRequestSchema = z.object({
    challengeId: z.string().min(1).max(200),
    kind: z.enum(['otp', 'totp', 'sms', 'email', 'push', 'webauthn']),
    channelHint: z.string().max(256).optional(),
    promptText: z.string().max(1024).optional(),
  });

  app.post(
    '/v1/vault/credentials/:id/mfa/request',
    { schema: { tags: ['vault'], summary: 'Open an MFA approval request', security: [{ agentKey: [] }] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const agent = req.agent!;
      if (!hasScope(agent.scopes, 'vault:use'))
        return fail(req, reply, 403, 'forbidden', 'missing scope: vault:use');

      const meta = await getCredentialMeta(agent.passportId, id);
      if (!meta) return fail(req, reply, 404, 'not_found', 'credential not found');
      if (!allowsTarget(agent.scopes, meta.target))
        return fail(req, reply, 403, 'forbidden', `agent not scoped for target: ${meta.target}`);

      const parsed = mfaRequestSchema.safeParse(req.body);
      if (!parsed.success)
        return fail(req, reply, 400, 'invalid_request', 'invalid mfa request', parsed.error.flatten());

      const result = await createMfaRequest({
        passportId: agent.passportId,
        credentialId: id,
        agentId: agent.agentId,
        challengeId: parsed.data.challengeId,
        kind: parsed.data.kind,
        channelHint: parsed.data.channelHint ?? null,
        promptText: parsed.data.promptText ?? null,
        target: meta.target,
        ip: req.ip,
      });
      if (!result.ok) {
        if (result.reason === 'rate_limited')
          return fail(req, reply, 429, 'rate_limited', 'too many pending MFA requests');
        if (result.reason === 'bad_kind')
          return fail(req, reply, 400, 'invalid_request', 'unknown mfa kind');
        return fail(req, reply, 404, 'not_found', 'credential not found');
      }
      // mfa.requested is audited atomically inside createMfaRequest's transaction.
      return reply.send({ requestId: result.requestId, status: 'pending' });
    },
  );

  app.get(
    '/v1/vault/credentials/:id/mfa/request/:requestId',
    { schema: { tags: ['vault'], summary: 'Poll an MFA request; returns the code once approved', security: [{ agentKey: [] }] } },
    async (req, reply) => {
      const { id, requestId } = req.params as { id: string; requestId: string };
      const agent = req.agent!;
      if (!hasScope(agent.scopes, 'vault:use'))
        return fail(req, reply, 403, 'forbidden', 'missing scope: vault:use');

      const res = await fetchMfaCode(agent.passportId, id, agent.agentId, requestId, { ip: req.ip });
      switch (res.status) {
        case 'not_found':
          return fail(req, reply, 404, 'not_found', 'mfa request not found');
        case 'pending':
          return reply.send({ status: 'pending' });
        case 'denied':
          return reply.send({ status: 'denied' });
        case 'revoked':
          return reply.send({ status: 'revoked' });
        case 'gone':
          return fail(req, reply, 410, 'gone', 'mfa code already consumed');
        case 'expired':
          // The once-only mfa.expired audit is appended atomically inside
          // fetchMfaCode (transaction with the status flip), not here.
          return fail(req, reply, 410, 'expired', 'mfa request expired');
        case 'approved':
          // The mfa.consumed audit was appended atomically with the consume inside
          // fetchMfaCode — the code is only delivered if that row is durably chained.
          // `code` is secret-bearing (the SDK injects it into the DOM and never
          // returns it up to the caller's reasoning layer). no-store so the one-time
          // code can't be cached by any intermediary proxy/cache.
          return reply
            .header('cache-control', 'no-store')
            .header('pragma', 'no-cache')
            .send({ status: 'approved', code: res.code, by: res.by, at: res.at });
      }
    },
  );
}
