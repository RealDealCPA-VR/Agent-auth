import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { makeApp, resetDb } from './helpers.js';

let app: FastifyInstance;
beforeAll(async () => {
  app = await makeApp();
});
afterAll(async () => {
  await app.close();
});
beforeEach(async () => {
  await resetDb();
});

describe('HTTP / protocol concerns', () => {
  it('GET /healthz -> 200 {status:"ok"}', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('an unsupported content-type body is capped by bodyLimit (413, not unbounded read)', async () => {
    const big = 'x'.repeat(80 * 1024); // > BODY_LIMIT_BYTES (64 KiB)
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { 'content-type': 'application/octet-stream' },
      payload: big,
    });
    expect(res.statusCode).toBe(413);
  });

  it('a small unsupported content-type body is a clean 415', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { 'content-type': 'application/octet-stream' },
      payload: 'hello',
    });
    expect(res.statusCode).toBe(415);
  });

  it('a malformed x-request-id header does not 500 (rejected, not echoed verbatim)', async () => {
    // A control char in x-request-id would throw ERR_INVALID_CHAR when echoed back,
    // bypassing the error envelope. genReqId must reject it and use a fresh uuid.
    const res = await app.inject({
      method: 'GET',
      url: '/healthz',
      headers: { 'x-request-id': 'bad\r\nid\x01' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-request-id']).not.toBe('bad\r\nid\x01');
  });

  it('GET /readyz -> 200 {status:"ready", db:true}', async () => {
    const res = await app.inject({ method: 'GET', url: '/readyz' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe('ready');
    expect(body.db).toBe(true);
  });

  it('GET /metrics -> 200 and exposes agentauth_http_requests_total', async () => {
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.body).toContain('agentauth_http_requests_total');
  });

  it('unknown route -> 404 with not_found error envelope', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/does-not-exist' });
    expect(res.statusCode).toBe(404);
    const body = res.json();
    expect(body.error.code).toBe('not_found');
    expect(typeof body.error.requestId).toBe('string');
    expect(body.error.requestId.length).toBeGreaterThan(0);
  });

  it('responses include an x-request-id header', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-request-id']).toBeTruthy();
  });

  it('echoes a supplied x-request-id back to the caller', async () => {
    const rid = 'test-correlation-id-12345';
    const res = await app.inject({
      method: 'GET',
      url: '/healthz',
      headers: { 'x-request-id': rid },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-request-id']).toBe(rid);
  });

  it('a 404 error envelope carries the supplied request id', async () => {
    const rid = 'corr-404-abcdef';
    const res = await app.inject({
      method: 'GET',
      url: '/v1/nope',
      headers: { 'x-request-id': rid },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.requestId).toBe(rid);
  });

  it('sets security headers (helmet) on a normal response', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    // helmet defaults include x-frame-options + x-content-type-options
    expect(res.headers['x-frame-options']).toBeTruthy();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('malformed JSON body on POST /v1/auth/login -> 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { 'content-type': 'application/json' },
      payload: '{ "email": "x@y.test", ', // truncated / invalid JSON
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBeDefined();
    expect(typeof body.error.requestId).toBe('string');
  });

  it('body-less POST that requires auth -> 401 (not 415)', async () => {
    const res = await app.inject({ method: 'POST', url: '/v1/auth/logout' });
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('unauthorized');
  });

  it('GET /docs/json -> 200 and body.openapi is set', async () => {
    const res = await app.inject({ method: 'GET', url: '/docs/json' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.openapi).toBeTruthy();
    expect(typeof body.openapi).toBe('string');
  });

  it('unsupported content-type with a non-empty body -> 415 (not 500)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      headers: { 'content-type': 'application/octet-stream' },
      payload: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
    });
    expect(res.statusCode).toBe(415);
    expect(res.json().error.code).toBe('unsupported_media_type');
  });

  it('wrong method on an existing route -> 405 with Allow header', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/auth/login' });
    expect(res.statusCode).toBe(405);
    expect(res.json().error.code).toBe('method_not_allowed');
    expect((res.headers['allow'] ?? '').toString()).toContain('POST');
  });
});
