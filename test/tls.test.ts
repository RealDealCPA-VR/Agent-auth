import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:https';
import type { AddressInfo } from 'node:net';
import selfsigned from 'selfsigned';
import type { FastifyInstance } from 'fastify';

const certPath = join(tmpdir(), `aa-tls-cert-${process.pid}.pem`);
const keyPath = join(tmpdir(), `aa-tls-key-${process.pid}.pem`);

let app: FastifyInstance;
let port = 0;

beforeAll(async () => {
  const pems = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], { days: 1 });
  writeFileSync(certPath, pems.cert);
  writeFileSync(keyPath, pems.private);
  process.env.HTTPS_CERT = certPath;
  process.env.HTTPS_KEY = keyPath;
  // Import after env is set so the env loader sees the HTTPS config.
  const { buildServer } = await import('../src/server.js');
  app = await buildServer();
  await app.listen({ port: 0, host: '127.0.0.1' });
  port = (app.server.address() as AddressInfo).port;
});

afterAll(async () => {
  await app?.close();
  delete process.env.HTTPS_CERT;
  delete process.env.HTTPS_KEY;
  rmSync(certPath, { force: true });
  rmSync(keyPath, { force: true });
});

describe('native TLS termination', () => {
  it('serves /healthz over HTTPS', async () => {
    const body = await new Promise<string>((resolve, reject) => {
      const req = request(
        { host: '127.0.0.1', port, path: '/healthz', method: 'GET', rejectUnauthorized: false },
        (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve(d));
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(JSON.parse(body).status).toBe('ok');
  });
});
