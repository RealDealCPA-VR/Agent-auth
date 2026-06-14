/**
 * Typed AgentAuth API client.
 *
 * - Reads the API base URL from NEXT_PUBLIC_API_URL (browser-safe public config).
 * - Stores the human session JWT in localStorage and attaches it as a Bearer
 *   token on every authenticated request.
 * - Normalises the server's error envelope ({error:{code,message,...}}) into a
 *   single ApiError type so pages can render a consistent message.
 *
 * This client only ever holds the *human session token*. Agent API keys
 * (aa_<uuid>.<secret>) are shown once at issue-time and never persisted here.
 */

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, '') || 'http://localhost:8080';

const TOKEN_KEY = 'agentauth.token';

// ---------------------------------------------------------------------------
// Token storage (localStorage, guarded for SSR where window is undefined)
// ---------------------------------------------------------------------------

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return getToken() !== null;
}

// ---------------------------------------------------------------------------
// Error type mirroring the API's error envelope
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details?: unknown;

  constructor(
    status: number,
    code: string,
    message: string,
    requestId?: string,
    details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// Core request helper
// ---------------------------------------------------------------------------

interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Attach the stored session token as a Bearer header (default: true). */
  auth?: boolean;
  signal?: AbortSignal;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, auth = true, signal } = opts;

  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';

  if (auth) {
    const token = getToken();
    if (token) headers['authorization'] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (err) {
    // Network-level failure (server down, CORS, DNS). Surface a stable shape.
    throw new ApiError(
      0,
      'network_error',
      err instanceof Error ? err.message : 'Network request failed',
    );
  }

  // 204 / empty body — return undefined as T.
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      // Non-JSON body; leave parsed undefined and fall through to error/raw.
    }
  }

  if (!res.ok) {
    const envelope = (parsed as { error?: Record<string, unknown> } | undefined)
      ?.error;
    throw new ApiError(
      res.status,
      (envelope?.code as string) || `http_${res.status}`,
      (envelope?.message as string) || res.statusText || 'Request failed',
      envelope?.requestId as string | undefined,
      envelope?.details,
    );
  }

  return parsed as T;
}

// ---------------------------------------------------------------------------
// Domain types (mirror the API contract)
// ---------------------------------------------------------------------------

export type CredentialType = 'password' | 'oauth_token' | 'cookie' | 'api_key';

export interface Pagination {
  limit: number;
  offset: number;
  total: number;
  returned: number;
}

export interface Page<T> {
  items: T[];
  pagination: Pagination;
}

export interface LoginResult {
  token: string;
  tokenType: string;
  expiresAt: string;
}

export interface Principal {
  id: string;
  email: string;
}

export interface Passport {
  id: string;
  name: string;
  createdAt: string;
}

export interface Credential {
  id: string;
  target: string;
  label: string;
  type: CredentialType;
  metadata: Record<string, unknown> | null;
  expiresAt: string | null;
  createdAt: string;
}

/** Credential as returned from the vault use-endpoint, including the secret. */
export interface UnsealedCredential extends Omit<Credential, 'createdAt'> {
  secret: string;
}

export interface Agent {
  id: string;
  name: string;
  passportId: string;
  scopes: string[];
  active: boolean;
  revokedAt: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
}

/** The issue response — apiKey is present exactly once, here. */
export interface IssuedAgent {
  id: string;
  name: string;
  scopes: string[];
  apiKey: string;
  warning: string;
}

export interface AuditEvent {
  id?: string;
  seq?: number;
  type?: string;
  action?: string;
  actor?: string;
  target?: string;
  createdAt?: string;
  // The audit payload shape is open-ended; allow extra fields for display.
  [k: string]: unknown;
}

export interface AuditVerifyResult {
  ok: boolean;
  count: number;
  brokenAtSeq: number | null;
}

// ---------------------------------------------------------------------------
// Endpoint wrappers
// ---------------------------------------------------------------------------

function pageQuery(limit?: number, offset?: number): string {
  const q = new URLSearchParams();
  if (limit !== undefined) q.set('limit', String(limit));
  if (offset !== undefined) q.set('offset', String(offset));
  const s = q.toString();
  return s ? `?${s}` : '';
}

export const api = {
  // --- Identity ----------------------------------------------------------
  register(email: string, password: string): Promise<Principal> {
    return request<Principal>('/v1/principals', {
      method: 'POST',
      body: { email, password },
      auth: false,
    });
  },

  async login(email: string, password: string): Promise<LoginResult> {
    const result = await request<LoginResult>('/v1/auth/login', {
      method: 'POST',
      body: { email, password },
      auth: false,
    });
    setToken(result.token);
    return result;
  },

  async logout(): Promise<void> {
    try {
      await request<{ loggedOut: boolean }>('/v1/auth/logout', {
        method: 'POST',
      });
    } finally {
      // Always drop the local token, even if the server call fails.
      clearToken();
    }
  },

  // --- Passports ---------------------------------------------------------
  listPassports(limit?: number, offset?: number): Promise<Page<Passport>> {
    return request<Page<Passport>>(`/v1/passports${pageQuery(limit, offset)}`);
  },

  createPassport(name: string): Promise<Passport> {
    return request<Passport>('/v1/passports', {
      method: 'POST',
      body: { name },
    });
  },

  // --- Credentials (deposit) --------------------------------------------
  listCredentials(
    passportId: string,
    limit?: number,
    offset?: number,
  ): Promise<Page<Credential>> {
    return request<Page<Credential>>(
      `/v1/passports/${encodeURIComponent(passportId)}/credentials${pageQuery(
        limit,
        offset,
      )}`,
    );
  },

  depositCredential(
    passportId: string,
    input: {
      target: string;
      label: string;
      type: CredentialType;
      secret: string;
      metadata?: Record<string, unknown>;
      expiresAt?: string;
    },
  ): Promise<Credential> {
    return request<Credential>(
      `/v1/passports/${encodeURIComponent(passportId)}/credentials`,
      { method: 'POST', body: input },
    );
  },

  // --- Agents ------------------------------------------------------------
  listAgents(limit?: number, offset?: number): Promise<Page<Agent>> {
    return request<Page<Agent>>(`/v1/agents${pageQuery(limit, offset)}`);
  },

  issueAgent(input: {
    passportId: string;
    name: string;
    scopes: string[];
    expiresAt?: string;
  }): Promise<IssuedAgent> {
    return request<IssuedAgent>('/v1/agents', {
      method: 'POST',
      body: input,
    });
  },

  revokeAgent(id: string): Promise<{ id: string; revoked: boolean }> {
    return request<{ id: string; revoked: boolean }>(
      `/v1/agents/${encodeURIComponent(id)}/revoke`,
      { method: 'POST' },
    );
  },

  // --- Audit -------------------------------------------------------------
  listAudit(limit?: number, offset?: number): Promise<Page<AuditEvent>> {
    return request<Page<AuditEvent>>(`/v1/audit${pageQuery(limit, offset)}`);
  },

  verifyAudit(): Promise<AuditVerifyResult> {
    return request<AuditVerifyResult>('/v1/audit/verify');
  },
};
