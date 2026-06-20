import type { FastifyInstance } from 'fastify';
import type { LightMyRequestResponse } from 'fastify';
import { buildServer } from '../src/server.js';
import { sql } from '../src/db/index.js';

/** Fail fast (and clearly) when a fixture's setup request did not succeed. */
function ok(res: LightMyRequestResponse, expected: number, what: string): LightMyRequestResponse {
  if (res.statusCode !== expected) {
    throw new Error(`${what} expected ${expected} but got ${res.statusCode}: ${res.payload}`);
  }
  return res;
}

/** Build a ready Fastify instance for inject()-based testing. */
export async function makeApp(): Promise<FastifyInstance> {
  const app = await buildServer();
  await app.ready();
  return app;
}

// Same advisory lock the audit append path holds (src/lib/audit.ts AUDIT_LOCK).
const AUDIT_LOCK = 4242421;

/**
 * Truncate every table between tests for isolation. A best-effort audit write from
 * a just-finished request can still be in flight at a file boundary; its
 * transaction-scoped advisory lock + row insert into audit_events can deadlock
 * with a bare TRUNCATE (ACCESS EXCLUSIVE) acquired in the opposite order. We take
 * the SAME advisory lock first so the truncate serializes with any append instead,
 * and retry the rare deadlock/lock-timeout victim.
 */
export async function resetDb(): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await sql.begin(async (tx) => {
        await tx`SET LOCAL lock_timeout = '8s'`;
        await tx`SELECT pg_advisory_xact_lock(${AUDIT_LOCK})`;
        // audit_events now has a BEFORE TRUNCATE guard (append-only); disable it
        // just for the test reset (we own the table here), then restore it.
        await tx`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate`;
        await tx`TRUNCATE principals, passports, credentials, agents, approval_requests, mfa_requests, oauth_flows, revoked_sessions, audit_events RESTART IDENTITY CASCADE`;
        await tx`ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_truncate`;
      });
      return;
    } catch (err) {
      const code = (err as { code?: string }).code;
      // 40P01 = deadlock_detected, 55P03 = lock_not_available (lock_timeout).
      if ((code === '40P01' || code === '55P03') && attempt < 5) continue;
      throw err;
    }
  }
}

export function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

let emailCounter = 0;
export function uniqueEmail(): string {
  emailCounter += 1;
  return `user${emailCounter}.${process.pid}@example.test`;
}

export const PASSWORD = 'correct-horse-battery-staple';

/** Register a principal and return its id + email. */
export async function registerPrincipal(
  app: FastifyInstance,
  email = uniqueEmail(),
  password = PASSWORD,
): Promise<{ id: string; email: string; password: string }> {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/principals',
    payload: { email, password },
  });
  const body = ok(res, 201, 'registerPrincipal').json();
  return { id: body.id, email, password };
}

/** Log in and return the bearer token. */
export async function login(
  app: FastifyInstance,
  email: string,
  password = PASSWORD,
): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/auth/login',
    payload: { email, password },
  });
  return ok(res, 200, 'login').json().token;
}

/** Register + login in one step. */
export async function registerAndLogin(
  app: FastifyInstance,
): Promise<{ id: string; email: string; token: string }> {
  const p = await registerPrincipal(app);
  const token = await login(app, p.email, p.password);
  return { id: p.id, email: p.email, token };
}

export async function createPassport(
  app: FastifyInstance,
  token: string,
  name = 'vault',
): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/passports',
    headers: auth(token),
    payload: { name },
  });
  return ok(res, 201, 'createPassport').json().id;
}

export async function deposit(
  app: FastifyInstance,
  token: string,
  passportId: string,
  body: Record<string, unknown>,
): Promise<{ id: string }> {
  const res = await app.inject({
    method: 'POST',
    url: `/v1/passports/${passportId}/credentials`,
    headers: auth(token),
    payload: body,
  });
  return ok(res, 201, 'deposit').json();
}

export async function issueAgent(
  app: FastifyInstance,
  token: string,
  passportId: string,
  scopes: string[] = ['vault:read', 'vault:use'],
  name = 'agent',
): Promise<{ id: string; apiKey: string }> {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: auth(token),
    payload: { passportId, name, scopes },
  });
  return ok(res, 201, 'issueAgent').json();
}
