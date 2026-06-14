import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyError } from 'fastify';
import sensible from '@fastify/sensible';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { env } from './env.js';
import { pingDb } from './db/index.js';
import { errorBody } from './lib/http.js';
import { inc, render as renderMetrics } from './lib/metrics.js';
import { principalRoutes } from './routes/principals.js';
import { passportRoutes } from './routes/passports.js';
import { agentRoutes } from './routes/agents.js';
import { vaultRoutes } from './routes/vault.js';
import { auditRoutes } from './routes/audit.js';

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({
    bodyLimit: env.BODY_LIMIT_BYTES,
    trustProxy: env.isProd,
    // Accept an inbound correlation id or generate one; it appears in every log
    // line (Fastify logs reqId) and is echoed back to the caller.
    genReqId: (req) => {
      const hdr = req.headers['x-request-id'];
      const v = Array.isArray(hdr) ? hdr[0] : hdr;
      return v && v.length <= 200 ? v : randomUUID();
    },
    logger: {
      level: env.LOG_LEVEL,
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.body.password',
          'req.body.secret',
          'res.body.secret',
          'res.body.apiKey',
          'res.body.token',
        ],
        censor: '[redacted]',
      },
    },
  });

  // Track registered (method, path-pattern) pairs so the not-found handler can
  // distinguish a missing route (404) from an unsupported method (405). Added
  // before any route registration so onRoute fires for every route + plugin.
  const routeRegistry: { method: string; parts: string[] }[] = [];
  app.addHook('onRoute', (r) => {
    const methods = Array.isArray(r.method) ? r.method : [r.method];
    const parts = r.url.split('/').filter(Boolean);
    for (const m of methods) routeRegistry.push({ method: m.toUpperCase(), parts });
  });

  // --- Security & infrastructure plugins ------------------------------------
  await app.register(helmet, { contentSecurityPolicy: env.isProd ? undefined : false });
  await app.register(cors, {
    origin: env.corsOrigins.length > 0 ? env.corsOrigins : false,
    credentials: true,
  });
  await app.register(rateLimit, {
    max: env.RATE_LIMIT_GLOBAL_MAX,
    timeWindow: env.RATE_LIMIT_WINDOW,
    // Rate-limit responses also use the standard error envelope.
    errorResponseBuilder: (req, ctx) =>
      errorBody(req, 'rate_limited', `too many requests, retry in ${ctx.after}`),
  });
  await app.register(sensible);

  // Echo the correlation id on every response.
  app.addHook('onRequest', async (req, reply) => {
    reply.header('x-request-id', req.id);
  });
  // Count requests by method + status class (no secrets, low cardinality).
  app.addHook('onResponse', async (req, reply) => {
    inc('agentauth_http_requests_total', {
      method: req.method,
      status: `${Math.floor(reply.statusCode / 100)}xx`,
    });
  });

  // Accept only an empty body for content-types we don't parse (e.g. body-less
  // POSTs); a non-empty unsupported body is a clean 415, not a 500.
  app.addContentTypeParser('*', (_req, payload, done) => {
    let size = 0;
    payload.on('data', (c: Buffer) => (size += c.length));
    payload.on('end', () => {
      if (size === 0) return done(null, undefined);
      done(
        Object.assign(new Error('unsupported content-type'), {
          statusCode: 415,
          code: 'unsupported_media_type',
        }),
        undefined,
      );
    });
    payload.on('error', done);
  });

  // Consistent 404 + error envelope. MUST be registered before the route plugins
  // so child contexts inherit it (Fastify only propagates to plugins registered
  // after setErrorHandler) — otherwise thrown errors (e.g. body-parse failures)
  // fall back to Fastify's default serializer.
  app.setNotFoundHandler((req, reply) => {
    // If the path matches a known route pattern under a different method, that's
    // a 405 (with Allow), not a 404.
    const reqParts = (req.url.split('?')[0] ?? '').split('/').filter(Boolean);
    const allowed = new Set<string>();
    for (const r of routeRegistry) {
      if (r.parts.length !== reqParts.length) continue;
      if (r.parts.every((p, i) => p.startsWith(':') || p === '*' || p === reqParts[i])) {
        allowed.add(r.method);
      }
    }
    allowed.delete('HEAD'); // implied by GET; don't advertise separately
    if (allowed.size > 0) {
      reply.header('allow', [...allowed].sort().join(', '));
      return reply
        .code(405)
        .send(errorBody(req, 'method_not_allowed', `method ${req.method} not allowed`));
    }
    reply.code(404).send(errorBody(req, 'not_found', 'route not found'));
  });
  app.setErrorHandler((err: FastifyError, req, reply) => {
    const status = err.statusCode && err.statusCode >= 400 ? err.statusCode : 500;
    // Log full error server-side (with reqId), but never leak internals/stack.
    if (status >= 500) req.log.error({ err }, 'request failed');
    else req.log.warn({ msg: err.message }, 'request rejected');
    const code = status >= 500 ? 'internal' : (err.code ?? 'error');
    const message = status >= 500 ? 'internal server error' : err.message;
    reply.code(status).send(errorBody(req, String(code), message));
  });

  // --- OpenAPI docs ---------------------------------------------------------
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'AgentAuth — Agent Passport API',
        description: 'Credential vault and identity broker for AI agents.',
        version: '0.1.0',
      },
      components: {
        securitySchemes: {
          humanBearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          agentKey: { type: 'http', scheme: 'bearer', bearerFormat: 'aa_<id>.<secret>' },
        },
      },
    },
  });
  await app.register(swaggerUi, { routePrefix: '/docs' });

  // --- Operational endpoints ------------------------------------------------
  app.get('/healthz', { schema: { tags: ['ops'], summary: 'Liveness' } }, async (_req, reply) => {
    return reply.code(200).send({ status: 'ok' });
  });
  app.get(
    '/readyz',
    { schema: { tags: ['ops'], summary: 'Readiness (checks DB)' } },
    async (_req, reply) => {
      const dbUp = await pingDb();
      return reply.code(dbUp ? 200 : 503).send({ status: dbUp ? 'ready' : 'not_ready', db: dbUp });
    },
  );
  app.get(
    '/metrics',
    { schema: { tags: ['ops'], summary: 'Prometheus metrics' } },
    async (_req, reply) => {
      return reply
        .header('content-type', 'text/plain; version=0.0.4')
        .send(renderMetrics(process.uptime()));
    },
  );

  // --- API routes -----------------------------------------------------------
  await app.register(principalRoutes);
  await app.register(passportRoutes);
  await app.register(agentRoutes);
  await app.register(vaultRoutes);
  await app.register(auditRoutes);

  return app;
}
