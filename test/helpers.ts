import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { sql } from '../src/db/index.js';

/** Build a ready Fastify instance for inject()-based testing. */
export async function makeApp(): Promise<FastifyInstance> {
  const app = await buildServer();
  await app.ready();
  return app;
}

/** Truncate every table between tests for isolation. */
export async function resetDb(): Promise<void> {
  await sql`TRUNCATE principals, passports, credentials, agents, revoked_sessions, audit_events RESTART IDENTITY CASCADE`;
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
  const body = res.json();
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
  return res.json().token;
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
  return res.json().id;
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
  return res.json();
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
  return res.json();
}
