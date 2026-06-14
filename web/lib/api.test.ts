import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  api,
  ApiError,
  getToken,
  setToken,
  clearToken,
  isAuthenticated,
  API_URL,
} from './api';

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

type MockResponseInit = {
  status?: number;
  body?: unknown;
  /** When true, send a non-JSON text body. */
  rawText?: string;
};

function mockFetchOnce({ status = 200, body, rawText }: MockResponseInit) {
  const text =
    rawText !== undefined
      ? rawText
      : body !== undefined
      ? JSON.stringify(body)
      : '';
  const res = {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status ${status}`,
    text: async () => text,
  } as unknown as Response;
  const fn = vi.fn(async () => res);
  vi.stubGlobal('fetch', fn);
  return fn;
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

describe('token storage', () => {
  it('round-trips a token through localStorage', () => {
    expect(getToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);

    setToken('jwt-123');
    expect(getToken()).toBe('jwt-123');
    expect(isAuthenticated()).toBe(true);

    clearToken();
    expect(getToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Request shaping + auth header
// ---------------------------------------------------------------------------

describe('request shaping', () => {
  it('attaches the bearer token on authed requests', async () => {
    setToken('jwt-abc');
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });

    await api.listPassports();

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/passports`);
    expect((init as RequestInit).method).toBe('GET');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['authorization']).toBe('Bearer jwt-abc');
  });

  it('omits the bearer token on unauthenticated endpoints (register)', async () => {
    setToken('jwt-should-not-leak');
    const fetchFn = mockFetchOnce({ body: { id: 'p1', email: 'a@b.c' } });

    await api.register('a@b.c', 'pw');

    const init = fetchFn.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers['authorization']).toBeUndefined();
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ email: 'a@b.c', password: 'pw' }));
  });

  it('builds pagination query strings', async () => {
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });
    await api.listAudit(25, 50);
    expect(fetchFn.mock.calls[0][0]).toBe(
      `${API_URL}/v1/audit?limit=25&offset=50`,
    );
  });

  it('url-encodes path params', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });
    await api.listCredentials('pa ss/id');
    expect(fetchFn.mock.calls[0][0]).toBe(
      `${API_URL}/v1/passports/pa%20ss%2Fid/credentials`,
    );
  });
});

// ---------------------------------------------------------------------------
// Login / logout side effects
// ---------------------------------------------------------------------------

describe('login & logout', () => {
  it('login stores the returned token', async () => {
    mockFetchOnce({
      body: { token: 'new-jwt', tokenType: 'Bearer', expiresAt: 'soon' },
    });
    const result = await api.login('a@b.c', 'pw');
    expect(result.token).toBe('new-jwt');
    expect(getToken()).toBe('new-jwt');
  });

  it('logout clears the token even when the server call fails', async () => {
    setToken('jwt-x');
    mockFetchOnce({ status: 500, body: { error: { message: 'boom' } } });
    await api.logout();
    expect(getToken()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Error envelope unwrapping
// ---------------------------------------------------------------------------

describe('error handling', () => {
  it('unwraps the API error envelope into ApiError', async () => {
    mockFetchOnce({
      status: 403,
      body: {
        error: {
          code: 'forbidden',
          message: 'scope denied',
          requestId: 'req-9',
          details: { scope: 'vault:use' },
        },
      },
    });

    await expect(api.listAgents()).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      code: 'forbidden',
      message: 'scope denied',
      requestId: 'req-9',
    });
  });

  it('falls back to a synthetic code when no envelope is present', async () => {
    mockFetchOnce({ status: 404, rawText: 'not found' });
    try {
      await api.listPassports();
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
      expect((err as ApiError).code).toBe('http_404');
    }
  });

  it('maps network failures to a network_error ApiError', async () => {
    const fn = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    vi.stubGlobal('fetch', fn);

    await expect(api.listPassports()).rejects.toMatchObject({
      name: 'ApiError',
      status: 0,
      code: 'network_error',
    });
  });

  it('returns undefined for 204 No Content', async () => {
    mockFetchOnce({ status: 204 });
    // logout hits 204-style empty responses; ensure no parse error.
    setToken('t');
    await expect(api.logout()).resolves.toBeUndefined();
    expect(getToken()).toBeNull();
  });
});
