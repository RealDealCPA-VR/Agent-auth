import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A tiny offline OAuth provider for tests. It stands in for a real authorization
 * server: `/authorize` simply echoes a code (the browser step is bypassed in the
 * test), and `/token` issues/refreshes tokens. Each refresh mints a NEW access
 * token so tests can assert that a refreshed `use` returns different material.
 */
export interface MockOAuthProvider {
  baseUrl: string;
  tokenUrl: string;
  authUrl: string;
  /** Force the next /token call (any grant) to fail with 400. */
  failNextToken: () => void;
  /** Most recent access token the provider issued (for assertions). */
  lastAccessToken: () => string | null;
  close: () => Promise<void>;
}

export async function startMockOAuthProvider(
  opts: { expiresIn?: number } = {},
): Promise<MockOAuthProvider> {
  const expiresIn = opts.expiresIn ?? 3600;
  let counter = 0;
  let lastAccess: string | null = null;
  let failOnce = false;

  const readBody = (req: import('node:http').IncomingMessage): Promise<string> =>
    new Promise((resolve) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => resolve(data));
    });

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');

    if (url.pathname === '/authorize') {
      // Stand-in for the consent screen: hand back a fixed authorization code.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ code: 'mock-auth-code', state: url.searchParams.get('state') }));
      return;
    }

    if (url.pathname === '/token' && req.method === 'POST') {
      const params = new URLSearchParams(await readBody(req));
      const grant = params.get('grant_type');
      if (failOnce) {
        failOnce = false;
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      counter += 1;
      const access = `access-token-${counter}`;
      lastAccess = access;
      const out: Record<string, unknown> = {
        access_token: access,
        token_type: 'bearer',
        expires_in: expiresIn,
        scope: 'read write',
      };
      // On the initial code exchange, also issue a refresh token. On refresh we
      // keep the same refresh token (omit it) but rotate the access token.
      if (grant === 'authorization_code') out.refresh_token = 'refresh-token-1';
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    tokenUrl: `${baseUrl}/token`,
    authUrl: `${baseUrl}/authorize`,
    failNextToken: () => {
      failOnce = true;
    },
    lastAccessToken: () => lastAccess,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
