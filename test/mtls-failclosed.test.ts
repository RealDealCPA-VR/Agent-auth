import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';

// Cert-path analogue of test/failclosed.test.ts: with mTLS enabled (trusted-proxy
// mode), force the DB liveness probe DOWN and present ONLY the client-cert
// fingerprint header (no bearer). authenticateAgentByCert() must fail closed with
// store_unavailable, so the agent-facing route returns 503 — never a default-allow.
//
// The pingDb mock below is hoisted by vitest above the imports. mTLS env must be
// set before src/env.ts first loads (env is read once at load), so buildServer is
// imported DYNAMICALLY inside beforeAll, after the env vars are set.

// Force the DB liveness probe to report DOWN for this entire file.
vi.mock('../src/db/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/db/index.js')>();
  return { ...actual, pingDb: vi.fn(async () => false) };
});

const saved: Record<string, string | undefined> = {};
const FP_HEADER = 'x-client-cert-fingerprint';
const HEX64 = 'a'.repeat(64);

let app: FastifyInstance;
beforeAll(async () => {
  for (const k of ['MTLS_ENABLED', 'MTLS_TRUSTED_PROXY', 'MTLS_FP_HEADER']) saved[k] = process.env[k];
  process.env.MTLS_ENABLED = 'true';
  process.env.MTLS_TRUSTED_PROXY = 'true';
  process.env.MTLS_FP_HEADER = FP_HEADER;

  // Import AFTER env is set so the env loader sees the mTLS proxy config.
  const { buildServer } = await import('../src/server.js');
  app = await buildServer();
  await app.ready();
});
afterAll(async () => {
  await app?.close();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

describe('mTLS fail-closed on the cert path (store unreachable)', () => {
  it('returns 503 store_unavailable for a cert-fingerprint request when the store is down', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: HEX64 },
    });
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('store_unavailable');
  });
});
