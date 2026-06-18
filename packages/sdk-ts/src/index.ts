/**
 * @agentauth/sdk — the official TypeScript client for AgentAuth.
 *
 * Two clients, two audiences:
 *
 *   • {@link AgentAuthClient}  — for the *agent* runtime. Holds an agent API key
 *     (`aa_<uuid>.<secret>`) and talks to the vault: discover credentials and
 *     unseal one for use, ideally in a single `useCredential(target)` call.
 *
 *   • {@link HumanClient}      — for the *human* operator / admin tooling. Holds a
 *     session JWT (from {@link HumanClient.login}) and manages passports,
 *     credentials, agents, and the audit log.
 *
 * Zero runtime dependencies: we use the global `fetch` (Node 20+, Deno, Bun,
 * browsers). All non-2xx responses are thrown as a typed {@link AgentAuthError}
 * so callers can branch on `.status` / `.code`. Secrets are never logged by this
 * SDK — they flow through return values only.
 */

// --- Wire types (mirror of the AgentAuth /v1 API contract) ------------------

/** A credential's type. Mirrors the server's enum. */
export type CredentialType = 'password' | 'oauth_token' | 'cookie' | 'api_key';

/** Pagination block returned by every list endpoint. */
export interface PaginationInfo {
  limit: number;
  offset: number;
  total: number;
  returned: number;
}

/** A page of `T` as returned by the API. */
export interface Page<T> {
  items: T[];
  pagination: PaginationInfo;
}

/** Options accepted by list endpoints. */
export interface ListOptions {
  limit?: number;
  offset?: number;
}

/**
 * A credential as seen by an agent in the vault listing — note there is NO
 * `secret` here; the secret is only revealed by {@link AgentAuthClient.useCredential}.
 */
export interface VaultCredential {
  id: string;
  target: string;
  label: string;
  type: CredentialType;
  metadata: Record<string, unknown>;
  expiresAt: string | null;
}

/** The result of using a credential — this is the only shape that carries `secret`. */
export interface UsedCredential extends VaultCredential {
  /** The unsealed secret. Use it immediately; do not persist or log it. */
  secret: string;
}

/** HTTP methods accepted by the proxy endpoint. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * A proxied downstream request. The agent controls only method/path/query/
 * headers/body — the **host is pinned server-side** to the credential's target,
 * and AgentAuth injects the secret. The raw secret never reaches the agent.
 */
export interface ProxyRequest {
  /** HTTP method for the downstream request. Defaults to `GET`. */
  method?: HttpMethod;
  /** Request path; must start with `/`. Defaults to `/`. */
  path?: string;
  /** Query string parameters to append. */
  query?: Record<string, string>;
  /** Extra request headers to send downstream. */
  headers?: Record<string, string>;
  /** Raw request body (already serialized). */
  body?: string;
}

/**
 * The downstream response, relayed back by AgentAuth with the injected secret
 * redacted. Nothing here carries the credential.
 */
export interface ProxyResponse {
  /** Downstream HTTP status code. */
  status: number;
  /** Downstream response headers. */
  headers: Record<string, string>;
  /** Downstream response body (secret redacted). */
  body: string;
}

/** A principal (human account). */
export interface Principal {
  id: string;
  email: string;
}

/** A login session token. */
export interface Session {
  token: string;
  tokenType: string;
  expiresAt: string;
}

/** A passport (a container for credentials, owned by a principal). */
export interface Passport {
  id: string;
  name: string;
  createdAt: string;
}

/** A deposited credential as returned to the human side (no secret). */
export interface DepositedCredential {
  id: string;
  target: string;
  label: string;
  type: CredentialType;
  metadata: Record<string, unknown>;
  expiresAt: string | null;
  createdAt: string;
}

/** A minted agent. The `apiKey` is only present at creation and shown once. */
export interface IssuedAgent {
  id: string;
  name: string;
  scopes: string[];
  /** Full agent API key (`aa_<uuid>.<secret>`). Returned ONCE, at creation. */
  apiKey: string;
  warning: string;
}

/** An agent as seen in listings (never carries the key). */
export interface AgentSummary {
  id: string;
  name: string;
  passportId: string;
  scopes: string[];
  active: boolean;
  revokedAt: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
}

/** An audit log event, matching the GET /v1/audit response shape. Context such
 * as the affected target lives inside `detail`. */
export interface AuditEvent {
  id: string;
  seq: number;
  action: string;
  success: boolean;
  passportId: string | null;
  agentId: string | null;
  credentialId: string | null;
  detail: Record<string, unknown>;
  createdAt: string;
  [key: string]: unknown;
}

/** Result of the audit chain verifier. The server returns only the boolean
 * integrity signal (the global event count / broken sequence are not exposed). */
export interface AuditVerification {
  ok: boolean;
}

/** A human approval request for a credential whose policy requires approval. */
export interface ApprovalRequest {
  id: string;
  credentialId: string;
  agentId: string;
  passportId: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  decidedAt?: string | null;
  expiresAt: string;
}

// --- Error type -------------------------------------------------------------

/** The server's error envelope shape. */
interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    requestId?: string;
    details?: unknown;
  };
}

/**
 * Thrown for every non-2xx response. Branch on {@link AgentAuthError.status} or
 * {@link AgentAuthError.code}. Common statuses surfaced by AgentAuth:
 *   401 unauthorized · 403 forbidden (scope/target) · 404 not found ·
 *   410 gone (expired credential) · 429 rate limited · 503 fail-closed.
 */
export class AgentAuthError extends Error {
  /** HTTP status code (0 if the request never completed — e.g. network error). */
  readonly status: number;
  /** Machine-readable error code from the envelope (e.g. `forbidden`). */
  readonly code: string;
  /** The server's request id, for correlating with logs/audit. */
  readonly requestId?: string;
  /** Optional structured details from the envelope. */
  readonly details?: unknown;

  constructor(args: {
    status: number;
    code: string;
    message: string;
    requestId?: string;
    details?: unknown;
  }) {
    super(args.message);
    this.name = 'AgentAuthError';
    this.status = args.status;
    this.code = args.code;
    this.requestId = args.requestId;
    this.details = args.details;
    // Restore prototype chain for instanceof across transpilation targets.
    Object.setPrototypeOf(this, AgentAuthError.prototype);
  }

  /** True for 401 — the key/token is missing, malformed, or rejected. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }
  /** True for 403 — authenticated but not permitted (scope or target glob). */
  get isForbidden(): boolean {
    return this.status === 403;
  }
  /** True for 404 — the resource does not exist (or isn't visible to you). */
  get isNotFound(): boolean {
    return this.status === 404;
  }
  /** True for 410 — the credential existed but is gone (e.g. expired). */
  get isGone(): boolean {
    return this.status === 410;
  }
  /** True for 429 — rate limited. Back off and retry. */
  get isRateLimited(): boolean {
    return this.status === 429;
  }
  /** True for 503 — the vault is fail-closed (auth store unreachable, etc.). */
  get isUnavailable(): boolean {
    return this.status === 503;
  }
  /** True for 202 — the credential requires human approval; see {@link ApprovalPendingError}. */
  get isApprovalPending(): boolean {
    return this.status === 202;
  }
}

/**
 * Thrown by {@link AgentAuthClient.useCredential} when the credential's policy
 * requires human approval: the server has queued a request (HTTP 202) and the
 * secret is withheld until an owner approves. Retry the call after approval.
 */
export class ApprovalPendingError extends AgentAuthError {
  constructor(requestId: string | undefined, message = 'credential use is awaiting human approval') {
    super({ status: 202, code: 'approval_pending', message, requestId });
    this.name = 'ApprovalPendingError';
    Object.setPrototypeOf(this, ApprovalPendingError.prototype);
  }
}

// --- Shared low-level transport ---------------------------------------------

/** A UUID v1–v5 matcher, used to decide id-vs-target in `useCredential`. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

interface RequestArgs {
  method: 'GET' | 'POST';
  path: string;
  query?: ListOptions & Record<string, string | number | undefined>;
  body?: unknown;
  /** The `Authorization` header value, if any. */
  authorization?: string;
}

/**
 * Base transport shared by both clients. Builds URLs, sets auth + JSON headers,
 * parses the JSON body, and maps non-2xx responses to {@link AgentAuthError}.
 *
 * Intentionally framework-free: it only depends on the global `fetch`.
 */
class Transport {
  protected readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: { baseUrl: string; fetch?: typeof fetch }) {
    if (!opts.baseUrl) {
      throw new TypeError('AgentAuth SDK: `baseUrl` is required');
    }
    // Normalise: drop any trailing slash so path joins are predictable.
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    // Allow injection for tests/runtimes; default to the global fetch (bound so
    // `this` is correct in browsers).
    const f = opts.fetch ?? globalThis.fetch;
    if (typeof f !== 'function') {
      throw new TypeError(
        'AgentAuth SDK: global `fetch` is not available; pass `fetch` explicitly (Node < 18?)',
      );
    }
    this.fetchImpl = f.bind(globalThis);
  }

  private buildUrl(path: string, query?: RequestArgs['query']): string {
    const url = new URL(this.baseUrl + path);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url.toString();
  }

  protected async request<T>(args: RequestArgs): Promise<T> {
    const url = this.buildUrl(args.path, args.query);
    const headers: Record<string, string> = { accept: 'application/json' };
    if (args.authorization) headers.authorization = args.authorization;

    const init: RequestInit = { method: args.method, headers };
    if (args.body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(args.body);
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url, init);
    } catch (cause) {
      // Network-level failure (DNS, refused, aborted). Surface as status 0 so
      // callers can still branch on a typed error rather than a raw TypeError.
      throw new AgentAuthError({
        status: 0,
        code: 'network_error',
        message: cause instanceof Error ? cause.message : 'network request failed',
      });
    }

    // 204/205 or an empty body: nothing to parse.
    const text = await res.text();
    const parsed: unknown = text.length > 0 ? safeJsonParse(text) : undefined;

    if (!res.ok) {
      throw toError(res.status, parsed);
    }
    // 202 is only ever the approval-pending response (body { status, requestId }).
    // Surface it as a typed error so callers can't mistake it for a real result.
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

/** Map an HTTP status + parsed body to a typed {@link AgentAuthError}. */
function toError(status: number, body: unknown): AgentAuthError {
  const envelope = (body ?? {}) as ErrorEnvelope;
  const err = envelope.error;
  return new AgentAuthError({
    status,
    code: err?.code ?? defaultCodeFor(status),
    message: err?.message ?? defaultMessageFor(status),
    requestId: err?.requestId,
    details: err?.details,
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
    case 405:
      return 'method_not_allowed';
    case 409:
      return 'conflict';
    case 410:
      return 'gone';
    case 415:
      return 'unsupported_media_type';
    case 429:
      return 'rate_limited';
    case 503:
      return 'unavailable';
    default:
      return 'error';
  }
}

function defaultMessageFor(status: number): string {
  return `request failed with status ${status}`;
}

// --- Agent client -----------------------------------------------------------

/** Options for {@link AgentAuthClient}. */
export interface AgentAuthClientOptions {
  /** Base URL of the AgentAuth API, e.g. `https://vault.example.com`. */
  baseUrl: string;
  /** The agent API key (`aa_<uuid>.<secret>`), shown once at agent creation. */
  apiKey: string;
  /** Optional custom fetch (testing / non-standard runtimes). */
  fetch?: typeof fetch;
}

/**
 * The agent-side client. Authenticates with an agent API key and exposes exactly
 * what an autonomous agent needs: discover the credentials it's scoped for, and
 * unseal one for immediate use.
 *
 * @example
 * ```ts
 * const aa = new AgentAuthClient({ baseUrl, apiKey: process.env.AGENTAUTH_KEY! });
 * const { secret } = await aa.useCredential('github.com'); // resolve by target
 * // ... use `secret` immediately; never log or persist it.
 * ```
 */
export class AgentAuthClient extends Transport {
  private readonly authHeader: string;

  constructor(opts: AgentAuthClientOptions) {
    super(opts);
    if (!opts.apiKey) {
      throw new TypeError('AgentAuth SDK: `apiKey` is required for AgentAuthClient');
    }
    this.authHeader = `Bearer ${opts.apiKey}`;
  }

  /**
   * List the credentials this agent is allowed to see. A narrowly-scoped agent
   * only sees credentials matching its `target:` globs.
   */
  listCredentials(opts: ListOptions = {}): Promise<Page<VaultCredential>> {
    return this.request<Page<VaultCredential>>({
      method: 'GET',
      path: '/v1/vault/credentials',
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /**
   * Unseal and return a credential for use, identified either by its credential
   * **id** (a UUID) or by **target** (any other string, e.g. `github.com`).
   *
   * When given a target, this resolves it to an id via {@link listCredentials}
   * (paging through results) and then calls the use endpoint. The returned object
   * includes the `secret` — use it immediately and never log it.
   *
   * @param idOrTarget A credential UUID, or a target host string to resolve.
   * @throws {AgentAuthError} 404 if no credential matches the target; plus the
   *   usual 401/403/410/429/503 from the use endpoint.
   */
  async useCredential(idOrTarget: string): Promise<UsedCredential> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth SDK: useCredential() requires an id or target');
    }
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    return this.use(id);
  }

  /** POST the use endpoint for a known credential id. */
  private use(id: string): Promise<UsedCredential> {
    return this.request<UsedCredential>({
      method: 'POST',
      path: `/v1/vault/credentials/${encodeURIComponent(id)}/use`,
      authorization: this.authHeader,
    });
  }

  /**
   * Proxy a request through AgentAuth: it makes the downstream call server-side,
   * injects the credential's secret, and relays the response back — **the raw
   * secret never reaches the agent**. Requires the `vault:proxy` scope.
   *
   * The credential is identified either by its **id** (a UUID) or by **target**
   * (any other string, e.g. `github.com`), resolved exactly like
   * {@link useCredential}. The host is pinned server-side to the credential's
   * target; the agent only controls method/path/query/headers/body.
   *
   * @param idOrTarget A credential UUID, or a target host string to resolve.
   * @param request The downstream request. Defaults to `GET /`.
   * @throws {ApprovalPendingError} 202 when the credential's policy requires
   *   human approval.
   * @throws {AgentAuthError} 403 (missing `vault:proxy` / target not scoped /
   *   forbidden target), 400 (invalid request/path), 410 (expired/window),
   *   429 (use limit reached), 502/504 (upstream/timeout), plus the usual
   *   401/404/503.
   */
  async proxy(idOrTarget: string, request: ProxyRequest = {}): Promise<ProxyResponse> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth SDK: proxy() requires an id or target');
    }
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    const body: ProxyRequest = {
      method: request.method ?? 'GET',
      path: request.path ?? '/',
      ...(request.query !== undefined ? { query: request.query } : {}),
      ...(request.headers !== undefined ? { headers: request.headers } : {}),
      ...(request.body !== undefined ? { body: request.body } : {}),
    };
    return this.request<ProxyResponse>({
      method: 'POST',
      path: `/v1/vault/credentials/${encodeURIComponent(id)}/proxy`,
      body,
      authorization: this.authHeader,
    });
  }

  /**
   * Resolve a target string to a single credential id by scanning the listing.
   * Pages until a match is found or the listing is exhausted. If more than one
   * credential shares the target, the first match (by listing order) wins.
   */
  private async resolveTarget(target: string): Promise<string> {
    const pageSize = 200; // max the server allows — fewest round-trips.
    let offset = 0;
    for (;;) {
      const pageResult = await this.listCredentials({ limit: pageSize, offset });
      const match = pageResult.items.find((c) => c.target === target);
      if (match) return match.id;

      offset += pageResult.items.length;
      const { total } = pageResult.pagination;
      // Stop when we've seen everything, or a short/empty page signals the end.
      if (pageResult.items.length === 0 || offset >= total) break;
    }
    throw new AgentAuthError({
      status: 404,
      code: 'not_found',
      message: `no credential found for target "${target}"`,
    });
  }
}

// --- Human client -----------------------------------------------------------

/** Options for {@link HumanClient}. */
export interface HumanClientOptions {
  /** Base URL of the AgentAuth API. */
  baseUrl: string;
  /** A session JWT obtained from {@link HumanClient.login}. */
  token: string;
  /** Optional custom fetch (testing / non-standard runtimes). */
  fetch?: typeof fetch;
}

/**
 * How AgentAuth injects the credential into a downstream {@link AgentAuthClient.proxy}
 * request. Defaults per credential type server-side (`bearer`, or `cookie` for
 * type `cookie`).
 */
export type CredentialInjection =
  | { mode: 'bearer' }
  | { mode: 'basic' }
  | { mode: 'cookie' }
  | { mode: 'header'; name: string; prefix?: string }
  | { mode: 'query'; name: string };

/** Input for {@link HumanClient.depositCredential}. */
export interface DepositCredentialInput {
  target: string;
  label: string;
  type: CredentialType;
  secret: string;
  metadata?: Record<string, unknown>;
  expiresAt?: string;
  /**
   * Optional injection strategy used when the credential is consumed via
   * proxy mode. Omit to use the server's per-type default.
   */
  injection?: CredentialInjection;
}

/** Input for {@link HumanClient.issueAgent}. */
export interface IssueAgentInput {
  passportId: string;
  name: string;
  scopes: string[];
  expiresAt?: string;
}

/**
 * The human/admin-side client. Authenticates with a session JWT and manages the
 * full lifecycle: register, create passports, deposit credentials, mint and
 * revoke agents, and read the audit log.
 *
 * @example
 * ```ts
 * const human = await HumanClient.login(baseUrl, 'me@example.com', 'pw');
 * const passport = await human.createPassport('work');
 * await human.depositCredential(passport.id, {
 *   target: 'github.com', label: 'GH token', type: 'api_key', secret: 'ghp_x',
 * });
 * const agent = await human.issueAgent({
 *   passportId: passport.id, name: 'ci-bot',
 *   scopes: ['vault:read', 'vault:use', 'target:github.com'],
 * });
 * console.log(agent.apiKey); // shown once
 * ```
 */
export class HumanClient extends Transport {
  private readonly authHeader: string;

  constructor(opts: HumanClientOptions) {
    super(opts);
    if (!opts.token) {
      throw new TypeError('AgentAuth SDK: `token` is required for HumanClient');
    }
    this.authHeader = `Bearer ${opts.token}`;
  }

  /**
   * Log in and return a ready-to-use {@link HumanClient}. This is the normal way
   * to construct the human client — it performs `POST /v1/auth/login` and wires
   * the returned session token in for you.
   */
  static async login(baseUrl: string, email: string, password: string): Promise<HumanClient> {
    const session = await HumanClient.loginRaw(baseUrl, email, password);
    return new HumanClient({ baseUrl, token: session.token });
  }

  /**
   * Perform a login and return the raw {@link Session} (token + expiry) without
   * constructing a client. Useful if you want to persist the token yourself.
   */
  static loginRaw(baseUrl: string, email: string, password: string): Promise<Session> {
    // A throwaway transport: login is unauthenticated, so no token yet.
    const transport = new PublicTransport({ baseUrl });
    return transport.post<Session>('/v1/auth/login', { email, password });
  }

  /** Register a new principal (human account). */
  static register(baseUrl: string, email: string, password: string): Promise<Principal> {
    const transport = new PublicTransport({ baseUrl });
    return transport.post<Principal>('/v1/principals', { email, password });
  }

  /**
   * Register a new principal. Instance method mirror of {@link HumanClient.register}
   * for ergonomics; registration itself does not require the session token.
   */
  register(email: string, password: string): Promise<Principal> {
    return this.request<Principal>({
      method: 'POST',
      path: '/v1/principals',
      body: { email, password },
    });
  }

  /** Invalidate the current session token server-side. */
  logout(): Promise<{ loggedOut: boolean }> {
    return this.request<{ loggedOut: boolean }>({
      method: 'POST',
      path: '/v1/auth/logout',
      authorization: this.authHeader,
    });
  }

  /** Create a new passport (a container for credentials). */
  createPassport(name: string): Promise<Passport> {
    return this.request<Passport>({
      method: 'POST',
      path: '/v1/passports',
      body: { name },
      authorization: this.authHeader,
    });
  }

  /** List your passports. */
  listPassports(opts: ListOptions = {}): Promise<Page<Passport>> {
    return this.request<Page<Passport>>({
      method: 'GET',
      path: '/v1/passports',
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /** Deposit (seal) a credential into a passport — this is the manual login. */
  depositCredential(
    passportId: string,
    input: DepositCredentialInput,
  ): Promise<DepositedCredential> {
    return this.request<DepositedCredential>({
      method: 'POST',
      path: `/v1/passports/${encodeURIComponent(passportId)}/credentials`,
      body: input,
      authorization: this.authHeader,
    });
  }

  /** List the credentials in a passport (metadata only — no secrets). */
  listCredentials(passportId: string, opts: ListOptions = {}): Promise<Page<DepositedCredential>> {
    return this.request<Page<DepositedCredential>>({
      method: 'GET',
      path: `/v1/passports/${encodeURIComponent(passportId)}/credentials`,
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /**
   * Mint a scoped agent key. The returned {@link IssuedAgent.apiKey} is shown
   * exactly once — capture it now.
   */
  issueAgent(input: IssueAgentInput): Promise<IssuedAgent> {
    return this.request<IssuedAgent>({
      method: 'POST',
      path: '/v1/agents',
      body: input,
      authorization: this.authHeader,
    });
  }

  /** List your agents (never returns keys). */
  listAgents(opts: ListOptions = {}): Promise<Page<AgentSummary>> {
    return this.request<Page<AgentSummary>>({
      method: 'GET',
      path: '/v1/agents',
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /** Revoke an agent immediately (fail-closed, effective on the next request). */
  revokeAgent(agentId: string): Promise<{ id: string; revoked: boolean }> {
    return this.request<{ id: string; revoked: boolean }>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/revoke`,
      authorization: this.authHeader,
    });
  }

  /** Read the tamper-evident audit log. */
  listAudit(opts: ListOptions = {}): Promise<Page<AuditEvent>> {
    return this.request<Page<AuditEvent>>({
      method: 'GET',
      path: '/v1/audit',
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /** Verify the audit hash-chain. `ok:false` means the chain was broken. */
  verifyAudit(): Promise<AuditVerification> {
    return this.request<AuditVerification>({
      method: 'GET',
      path: '/v1/audit/verify',
      authorization: this.authHeader,
    });
  }

  /** List pending approval requests across the passports you own. */
  listApprovals(opts: ListOptions = {}): Promise<Page<ApprovalRequest>> {
    return this.request<Page<ApprovalRequest>>({
      method: 'GET',
      path: '/v1/approvals',
      query: { limit: opts.limit, offset: opts.offset },
      authorization: this.authHeader,
    });
  }

  /** Approve a pending request, granting a single-use, TTL-bounded credential use. */
  approveRequest(requestId: string): Promise<ApprovalRequest> {
    return this.request<ApprovalRequest>({
      method: 'POST',
      path: `/v1/approvals/${encodeURIComponent(requestId)}/approve`,
      authorization: this.authHeader,
    });
  }

  /** Deny a pending request. */
  denyRequest(requestId: string): Promise<ApprovalRequest> {
    return this.request<ApprovalRequest>({
      method: 'POST',
      path: `/v1/approvals/${encodeURIComponent(requestId)}/deny`,
      authorization: this.authHeader,
    });
  }
}

/**
 * A minimal transport for the unauthenticated public endpoints (register/login).
 * Exposed only within this module so the static helpers can reuse the same URL
 * building + error mapping without a token.
 */
class PublicTransport extends Transport {
  post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>({ method: 'POST', path, body });
  }
}
