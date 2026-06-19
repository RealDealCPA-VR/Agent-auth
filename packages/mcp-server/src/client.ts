/**
 * A tiny, self-contained HTTP client for the AgentAuth agent-facing vault API.
 *
 * Intentionally has NO dependency on the other AgentAuth SDK packages — it only
 * uses the global `fetch` (Node 20+). It speaks exactly the two endpoints an
 * agent needs:
 *
 *   • GET  /v1/vault/credentials            — list (metadata only, no secrets)
 *   • POST /v1/vault/credentials/:id/use    — unseal THE secret for one use
 *
 * There is no target-lookup endpoint on the server, so {@link AgentAuthClient.useCredential}
 * resolves a non-UUID `idOrTarget` by paginating the listing (at the max page
 * size of 200) and matching `items[].target === target`, then POSTing that id.
 *
 * Every non-2xx response is thrown as a typed {@link AgentAuthClientError} that
 * carries `status` + `code` + `message`. The approval-pending case (HTTP 202 on
 * /use) is surfaced as a clear {@link ApprovalPendingError} rather than being
 * mistaken for a successful result.
 */

/** A credential's type. Mirrors the server's enum. */
export type CredentialType = 'password' | 'oauth_token' | 'cookie' | 'api_key';

/** Pagination block returned by every list endpoint. */
export interface PaginationInfo {
  limit: number;
  offset: number;
  total: number;
  returned: number;
}

/**
 * A credential as seen by an agent in the vault listing. Note: NO `secret` here —
 * the secret is only ever returned by {@link AgentAuthClient.useCredential}.
 */
export interface VaultCredential {
  id: string;
  target: string;
  label: string;
  type: CredentialType;
  metadata: Record<string, unknown>;
  expiresAt: string | null;
}

/** A page of the vault listing. */
export interface CredentialsPage {
  items: VaultCredential[];
  pagination: PaginationInfo;
}

/** The result of using a credential — the only shape that carries `secret`. */
export interface UsedCredential extends VaultCredential {
  /** The unsealed secret. Use it immediately; never persist or log it. */
  secret: string;
}

/** The HTTP methods the proxy endpoint accepts. */
export type ProxyMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * A proxied downstream request. The host is pinned server-side to the
 * credential's target — the agent only controls method/path/query/headers/body.
 */
export interface ProxyRequest {
  /** HTTP method for the downstream request (default 'GET' server-side). */
  method?: ProxyMethod;
  /** Path on the pinned host; must start with '/' (default '/' server-side). */
  path?: string;
  /** Optional query parameters appended to the path. */
  query?: Record<string, string>;
  /** Optional request headers (the credential is injected server-side). */
  headers?: Record<string, string>;
  /** Optional request body (already serialized). */
  body?: string;
}

/**
 * The downstream response surfaced by the proxy. The injected secret is never
 * present here — it is redacted server-side before the body is returned.
 */
export interface ProxyResponse {
  /** The downstream HTTP status code. */
  status: number;
  /** The downstream response headers. */
  headers: Record<string, string>;
  /** The downstream response body (secret redacted). */
  body: string;
}

/** The server's error envelope shape. */
interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    requestId?: string;
  };
}

/**
 * Thrown for every non-2xx response from the AgentAuth API. Branch on
 * {@link AgentAuthClientError.status} or {@link AgentAuthClientError.code}.
 *
 * Statuses surfaced by the agent vault API:
 *   401 unauthorized · 403 forbidden (scope/target) · 404 not_found ·
 *   410 expired/window · 429 use_limit/rate · 503 store_unavailable.
 */
export class AgentAuthClientError extends Error {
  /** HTTP status code (0 if the request never completed — e.g. network error). */
  readonly status: number;
  /** Machine-readable error code from the envelope (e.g. `forbidden`). */
  readonly code: string;
  /** The server's request id, for correlating with logs/audit. */
  readonly requestId?: string;

  constructor(args: { status: number; code: string; message: string; requestId?: string }) {
    super(args.message);
    this.name = 'AgentAuthClientError';
    this.status = args.status;
    this.code = args.code;
    this.requestId = args.requestId;
    // Restore prototype chain for instanceof across transpilation targets.
    Object.setPrototypeOf(this, AgentAuthClientError.prototype);
  }
}

/**
 * Thrown by {@link AgentAuthClient.useCredential} when the credential's policy
 * requires human approval: the server queued a request (HTTP 202) and withholds
 * the secret until an owner approves. Retry the call after approval.
 */
export class ApprovalPendingError extends AgentAuthClientError {
  constructor(requestId: string | undefined, message = 'credential use is awaiting human approval') {
    super({ status: 202, code: 'approval_pending', message, requestId });
    this.name = 'ApprovalPendingError';
    Object.setPrototypeOf(this, ApprovalPendingError.prototype);
  }
}

/** A UUID v1–v5 matcher, used to decide id-vs-target in {@link AgentAuthClient.useCredential}. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** Options for {@link AgentAuthClient}. */
export interface AgentAuthClientOptions {
  /** Base URL of the AgentAuth API, e.g. `http://localhost:8080`. */
  baseUrl: string;
  /** The agent API key (`aa_<uuid>.<secret>`), shown once at agent creation. */
  apiKey: string;
  /** Optional custom fetch (testing / non-standard runtimes). Defaults to global fetch. */
  fetch?: typeof fetch;
}

/** Options accepted by the listing. */
export interface ListOptions {
  limit?: number;
  offset?: number;
}

/** The largest page the server accepts — fewest round-trips when resolving targets. */
const MAX_PAGE_SIZE = 200;

/**
 * A minimal agent-side client for the AgentAuth vault. Authenticates with an
 * agent API key and exposes exactly two operations.
 */
export class AgentAuthClient {
  private readonly baseUrl: string;
  private readonly authHeader: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: AgentAuthClientOptions) {
    if (!opts.baseUrl) {
      throw new TypeError('AgentAuth MCP: `baseUrl` is required');
    }
    if (!opts.apiKey) {
      throw new TypeError('AgentAuth MCP: `apiKey` is required');
    }
    // Normalise: drop any trailing slash so path joins are predictable.
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.authHeader = `Bearer ${opts.apiKey}`;
    const f = opts.fetch ?? globalThis.fetch;
    if (typeof f !== 'function') {
      throw new TypeError(
        'AgentAuth MCP: global `fetch` is not available; upgrade to Node 20+ or pass `fetch` explicitly',
      );
    }
    this.fetchImpl = f.bind(globalThis);
  }

  /**
   * List the credentials this agent is allowed to see (metadata only — never any
   * secrets). A narrowly-scoped agent only sees credentials matching its
   * `target:` globs.
   */
  listCredentials(opts: ListOptions = {}): Promise<CredentialsPage> {
    return this.request<CredentialsPage>({
      method: 'GET',
      path: '/v1/vault/credentials',
      query: { limit: opts.limit, offset: opts.offset },
    });
  }

  /**
   * Unseal and return a credential for use, identified either by its credential
   * **id** (a UUID — POSTed to /use directly) or by **target** (any other string,
   * e.g. `github.com` — resolved to an id via the listing, then used).
   *
   * The returned object includes the live `secret` — use it immediately and never
   * log or persist it.
   *
   * @throws {AgentAuthClientError} 404 if no credential matches the target; plus
   *   the usual 401/403/410/429/503 from the use endpoint.
   * @throws {ApprovalPendingError} when the credential requires human approval.
   */
  async useCredential(idOrTarget: string): Promise<UsedCredential> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth MCP: useCredential() requires an id or target');
    }
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    return this.request<UsedCredential>({
      method: 'POST',
      path: `/v1/vault/credentials/${encodeURIComponent(id)}/use`,
    });
  }

  /**
   * Make a downstream HTTP request server-side with the credential injected,
   * identified either by credential **id** (a UUID — used directly) or by
   * **target** (any other string, resolved to an id via the listing).
   *
   * AgentAuth pins the host to the credential's target and injects the secret
   * server-side; the raw secret NEVER appears in the returned response. Only the
   * downstream `{ status, headers, body }` (secret redacted) is returned.
   *
   * @throws {AgentAuthClientError} 404 if no credential matches the target; plus
   *   the usual 400/403/410/429/502/504/503 from the proxy endpoint.
   * @throws {ApprovalPendingError} when the credential requires human approval.
   */
  async proxy(idOrTarget: string, request: ProxyRequest = {}): Promise<ProxyResponse> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth MCP: proxy() requires an id or target');
    }
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    const body: Record<string, unknown> = {};
    if (request.method !== undefined) body.method = request.method;
    if (request.path !== undefined) body.path = request.path;
    if (request.query !== undefined) body.query = request.query;
    if (request.headers !== undefined) body.headers = request.headers;
    if (request.body !== undefined) body.body = request.body;
    return this.request<ProxyResponse>({
      method: 'POST',
      path: `/v1/vault/credentials/${encodeURIComponent(id)}/proxy`,
      body,
    });
  }

  /**
   * Resolve a target string to a single credential id by scanning the listing.
   * Pages (at {@link MAX_PAGE_SIZE}) until a match is found or the listing is
   * exhausted. If more than one credential shares the target, the first match
   * (by listing order) wins.
   */
  private async resolveTarget(target: string): Promise<string> {
    // Match the server's deposit canonicalization (trim + drop trailing dots + lowercase).
    const want = target.trim().replace(/\.+$/, '').toLowerCase();
    let offset = 0;
    for (;;) {
      const page = await this.listCredentials({ limit: MAX_PAGE_SIZE, offset });
      const match = page.items.find((c) => c.target.toLowerCase() === want);
      if (match) return match.id;

      offset += page.items.length;
      const { total } = page.pagination;
      // Stop when we've seen everything, or a short/empty page signals the end.
      if (page.items.length === 0 || offset >= total) break;
    }
    throw new AgentAuthClientError({
      status: 404,
      code: 'not_found',
      message: `no credential found for target "${target}"`,
    });
  }

  /** Low-level request: build URL, set auth+JSON headers, parse body, map errors. */
  private async request<T>(args: {
    method: 'GET' | 'POST';
    path: string;
    query?: Record<string, string | number | undefined>;
    body?: unknown;
  }): Promise<T> {
    const url = new URL(this.baseUrl + args.path);
    if (args.query) {
      for (const [key, value] of Object.entries(args.query)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      accept: 'application/json',
      authorization: this.authHeader,
    };

    const init: RequestInit = { method: args.method, headers };
    if (args.body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(args.body);
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url.toString(), init);
    } catch (cause) {
      // Network-level failure (DNS, refused, aborted). Surface as status 0 so
      // callers can branch on a typed error rather than a raw TypeError.
      throw new AgentAuthClientError({
        status: 0,
        code: 'network_error',
        message: cause instanceof Error ? cause.message : 'network request failed',
      });
    }

    const text = await res.text();
    const parsed: unknown = text.length > 0 ? safeJsonParse(text) : undefined;

    if (!res.ok) {
      throw toError(res.status, parsed);
    }
    // 202 is only ever the approval-pending response (body { status, requestId }).
    // Surface it as a typed error so callers can't mistake it for a real secret.
    if (res.status === 202) {
      const body = (parsed ?? {}) as { requestId?: string; message?: string };
      throw new ApprovalPendingError(body.requestId, body.message);
    }
    return parsed as T;
  }
}

/** Parse JSON without throwing; returns `undefined` on malformed bodies. */
function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Map an HTTP status + parsed body to a typed {@link AgentAuthClientError}. */
function toError(status: number, body: unknown): AgentAuthClientError {
  const envelope = (body ?? {}) as ErrorEnvelope;
  const err = envelope.error;
  return new AgentAuthClientError({
    status,
    code: err?.code ?? defaultCodeFor(status),
    message: err?.message ?? defaultMessageFor(status),
    requestId: err?.requestId,
  });
}

function defaultCodeFor(status: number): string {
  switch (status) {
    case 400:
      return 'bad_request';
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 410:
      return 'expired';
    case 429:
      return 'rate_limited';
    case 503:
      return 'store_unavailable';
    default:
      return 'error';
  }
}

function defaultMessageFor(status: number): string {
  return `request failed with status ${status}`;
}
