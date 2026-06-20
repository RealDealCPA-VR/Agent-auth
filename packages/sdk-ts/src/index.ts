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
  action: string;
  success: boolean;
  principalId: string | null;
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

// --- Browser-login wire types -----------------------------------------------

/**
 * A single cookie in a {@link BrowserLoginPlan} of mode `cookie`. Carries the
 * cookie **value** (secret material) — apply it to a browser context and never
 * log it.
 */
export interface PlanCookie {
  name: string;
  value: string;
  domain?: string;
  path: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None' | string;
}

/**
 * One step of a `form`-mode {@link BrowserLoginPlan}. Executed in order against
 * the page: navigate, fill a field, or click an element. `fill` actions carry the
 * field **value** (secret material).
 */
export type BrowserFormAction =
  | { type: 'goto'; url: string }
  | { type: 'fill'; selector: string; value: string }
  | { type: 'click'; selector: string };

/**
 * A plan for logging a browser into a target, returned by
 * {@link AgentAuthClient.getBrowserLoginPlan}. The shape is discriminated on
 * `mode`. **Every variant carries secret material** (cookie values, header
 * values, storage values, or form field values) at the same trust level as
 * {@link UsedCredential.secret} — apply it immediately and never log it.
 */
export type BrowserLoginPlan =
  | {
      mode: 'cookie';
      target: string;
      /** Where to navigate after the cookies are set. */
      url: string;
      cookies: PlanCookie[];
      /** Non-secret navigation allowlist (host globs); the SDK refuses off-list navigation. */
      allowedDomains?: string[];
    }
  | {
      mode: 'header';
      target: string;
      url: string;
      /** Extra HTTP headers to send (values are secret). */
      headers: Record<string, string>;
      allowedDomains?: string[];
    }
  | {
      mode: 'localStorage';
      target: string;
      /** The origin whose localStorage the items belong to. */
      origin: string;
      url: string;
      /** localStorage entries to seed (values are secret). */
      items: Record<string, string>;
      allowedDomains?: string[];
    }
  | {
      mode: 'form';
      target: string;
      url: string;
      /** Ordered steps to drive the login form (fill values are secret). */
      actions: BrowserFormAction[];
      /** If set, the login is considered submitted once the URL includes this. */
      successUrlIncludes?: string;
      /** Non-secret MFA hints (echoed from `metadata.browser.mfa`) for detection. */
      mfa?: MfaSpec;
      /** Non-secret navigation allowlist (host globs); the SDK refuses off-list navigation. */
      allowedDomains?: string[];
    };

/** The kind of MFA challenge a login may hit. */
export type MfaKind = 'otp' | 'totp' | 'sms' | 'email' | 'push' | 'webauthn';

/**
 * Non-secret MFA hints configured per credential (`metadata.browser.mfa`) and
 * echoed into a form plan. Carries no secret — only how to detect and where to
 * fill the eventual code.
 */
export interface MfaSpec {
  kind?: MfaKind;
  /** Override the detection strategy; `auto` (default) tries url/text/input. */
  detectBy?: 'url' | 'text' | 'input' | 'auto';
  /** A non-secret hint shown to the human approver, e.g. "code sent to ••••1234". */
  channelHint?: string;
  /** Selector of the code input (for Phase-2 injection / auto-detect if absent). */
  inputSelector?: string;
  /** Selector to submit the code (defaults to the form submit). */
  submitSelector?: string;
}

/**
 * A detected MFA challenge. **Non-secret** — `promptText` is what the page says
 * ("Enter the 6-digit code sent to ••••1234"), safe to surface to an LLM and to
 * log. The browser is left on the challenge page.
 */
export interface MfaChallenge {
  kind: MfaKind;
  /** The non-secret prompt the page shows the user. */
  promptText: string;
  /** ISO-8601 timestamp of detection. */
  detectedAt: string;
  /** Client-issued challenge id (Phase 2 ties it to a server approval request). */
  challengeId: string;
  /** Code input selector from the credential's `metadata.browser.mfa` (if set), so
   * {@link AgentAuthClient.resolveMfa} can inject the code without an explicit opt. */
  inputSelector?: string;
  /** Submit selector from the credential's `metadata.browser.mfa` (if set). */
  submitSelector?: string;
}

/** Options for {@link AgentAuthClient.resolveMfa}. */
export interface ResolveMfaOptions {
  /** Selector of the code input to fill (defaults to the spec's inputSelector). */
  inputSelector?: string;
  /** Selector to click after filling the code (defaults to the spec's submitSelector). */
  submitSelector?: string;
  /** A non-secret hint shown to the approver (e.g. "code sent to ••••1234"). */
  channelHint?: string;
  /** Give up waiting for approval after this long (default 5 minutes). */
  timeoutMs?: number;
  /** How often to poll for approval (default 2s). */
  pollIntervalMs?: number;
  /** Injectable delay (tests pass a no-op); defaults to a real timer. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * The outcome of an MFA resolution. **Non-secret** — never carries the code. The
 * code (when approved) flows only into the browser DOM.
 */
export interface MfaResolution {
  /** True only when an approved code was injected (or a push/webauthn confirmed). */
  resolved: boolean;
  status: 'approved' | 'denied' | 'revoked' | 'expired' | 'timeout';
  /** The approver's email (approved only). */
  by?: string | null;
  /** ISO-8601 decision time (approved only). */
  at?: string | null;
}

/**
 * A non-secret summary of what {@link applyBrowserLogin} / {@link AgentAuthClient.browserLogin}
 * applied to a page. **Carries no secret material** — only names/keys and counts —
 * so it is safe to log.
 */
export interface BrowserLoginSummary {
  mode: BrowserLoginPlan['mode'];
  target: string;
  url: string;
  /**
   * Whether the page appears authenticated. True for cookie/header/localStorage
   * (state applied) and for a form that reached its success URL with no MFA;
   * false when an MFA challenge was detected (see {@link mfa}).
   */
  authenticated: boolean;
  /** Set when a form login hit an MFA challenge — non-secret, browser left on it. */
  mfa?: MfaChallenge;
  /** Names of the cookies that were set (cookie mode). */
  cookieNames?: string[];
  /** Names of the headers that were set (header mode). */
  headerNames?: string[];
  /** Keys written to localStorage (localStorage mode). */
  storageKeys?: string[];
  /** Number of form fields that were filled (form mode). */
  filledFields?: number;
  /** Whether the form login appears to have been submitted (form mode). */
  submitted?: boolean;
}

/**
 * A minimal **structural** interface for a browser page, satisfied by both a
 * Playwright `Page` and a Puppeteer `Page`. Declared structurally (not imported)
 * so the SDK keeps zero runtime dependencies — you pass your own page object.
 *
 * {@link applyBrowserLogin} feature-detects which framework you handed it and
 * calls the matching methods; everything here is optional so either shape type-checks.
 */
export interface BrowserPage {
  /** Navigate to a URL (both Playwright and Puppeteer). */
  goto(url: string, options?: unknown): Promise<unknown>;
  /** Evaluate a function in the page (both Playwright and Puppeteer). */
  evaluate<R, A>(fn: (arg: A) => R, arg: A): Promise<R>;
  /** Playwright: the browsing context (cookies / headers live here). */
  context?: () => BrowserContextLike;
  /** Puppeteer: set cookies directly on the page. */
  setCookie?: (...cookies: PlanCookie[]) => Promise<unknown>;
  /** Puppeteer: read the page's cookies (used by force-logout). */
  cookies?: () => Promise<Array<{ name: string; domain?: string; path?: string; url?: string }>>;
  /** Puppeteer: delete cookies (force-logout a revoked agent's session). */
  deleteCookie?: (
    ...cookies: Array<{ name: string; domain?: string; path?: string; url?: string }>
  ) => Promise<unknown>;
  /** Puppeteer (and Playwright fallback): set extra HTTP headers. */
  setExtraHTTPHeaders?: (headers: Record<string, string>) => Promise<unknown>;
  /** Fill an input (Playwright; also present on recent Puppeteer). */
  fill?: (selector: string, value: string) => Promise<unknown>;
  /** Type into an input (Puppeteer fallback for `fill`). */
  type?: (selector: string, value: string) => Promise<unknown>;
  /** Click an element (both Playwright and Puppeteer). */
  click(selector: string): Promise<unknown>;
  /** Current page URL (used to detect form-login success). */
  url?: () => string;
  /** Full page HTML (Playwright + Puppeteer `page.content()`) — used for MFA detection. */
  content?: () => Promise<string>;
  /** Wait for navigation to settle after a submit (Playwright; best-effort). */
  waitForLoadState?: (state?: string) => Promise<unknown>;
}

/** The subset of a Playwright `BrowserContext` the SDK uses. */
export interface BrowserContextLike {
  addCookies?: (cookies: PlanCookie[]) => Promise<unknown>;
  setExtraHTTPHeaders?: (headers: Record<string, string>) => Promise<unknown>;
  /** Clear all cookies (used to force-logout a revoked agent's browser session). */
  clearCookies?: () => Promise<unknown>;
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

/**
 * Reduce a target to its bare host the same way the server does (targetHost in
 * src/auth/agent.ts) — strip an http(s):// scheme, the path, the port (or IPv6
 * brackets), a trailing dot, and lowercase. The server authorizes and lists by
 * host, so resolving a credential by host must compare hosts, not the raw stored
 * string (a URL-form credential stays usable by its bare host).
 */
function targetHost(target: string): string {
  let h = target.trim();
  const scheme = h.match(/^https?:\/\//i);
  if (scheme) h = h.slice(scheme[0].length);
  const slash = h.indexOf('/');
  if (slash >= 0) h = h.slice(0, slash);
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    if (end >= 0) h = h.slice(1, end);
  } else {
    const colon = h.indexOf(':');
    if (colon >= 0) h = h.slice(0, colon);
  }
  return h.replace(/\.$/, '').toLowerCase();
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

// --- Browser-login application ----------------------------------------------

// MFA challenge detection heuristics — all operate on NON-secret signals (the
// page URL and HTML structure), never on the secret. Tunable via the credential's
// metadata.browser.mfa.detectBy.
const MFA_URL_RE = /(?:mfa|2fa|twofactor|two-factor|otp|\/verify|\/challenge|verification)/i;
const MFA_TEXT_RE =
  /(enter the[^.<]{0,40}code|verification code|two-factor|one-time code|6-digit code|approve[^.<]{0,20}sign-?in|authenticator app)/i;
const MFA_INPUT_RE =
  /autocomplete\s*=\s*["']one-time-code["']|inputmode\s*=\s*["']numeric["']|maxlength\s*=\s*["']6["']/i;

/** A non-secret, best-effort prompt string pulled from the page's visible text. */
function extractPromptText(html: string): string | undefined {
  const text = html
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const m =
    text.match(/[^.<>]*?(enter the[^.<>]{0,40}code|verification code|one-time code|6-digit code|two-factor)[^.<>]*/i) ??
    text.match(/.{0,60}(authenticator|verification|one-time code).{0,60}/i);
  const snippet = m?.[0]?.trim();
  return snippet ? snippet.slice(0, 160) : undefined;
}

/** Reduce a URL to its bare lowercase host. */
function urlHost(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return '';
  }
}

/** Throw if navigating to `url` is not permitted by `allow` (the navigation
 * allowlist — browser host-pinning). An absent/empty list allows all. */
function assertNavAllowed(url: string, allow: string[] | undefined): void {
  if (allow && allow.length > 0 && !hostAllowed(urlHost(url), allow)) {
    throw new TypeError(`AgentAuth SDK: navigation to ${urlHost(url)} is not in allowedDomains`);
  }
}

/** True if `host` matches one of `allowed` (exact, `*` wildcard, or `*.suffix`). */
function hostAllowed(host: string, allowed: string[]): boolean {
  return allowed.some((raw) => {
    const p = raw.trim().toLowerCase();
    if (p === '*') return true;
    if (p.startsWith('*.')) {
      const suffix = p.slice(2);
      return host === suffix || host.endsWith('.' + suffix);
    }
    return host === p;
  });
}

/**
 * Force-logout a page after the agent is revoked: clear the context cookies and
 * navigate to a blank page so the authenticated session does not outlive the
 * revoked agent. Best-effort and never throws.
 */
async function forceLogout(page: BrowserPage): Promise<void> {
  try {
    const ctx = page.context?.();
    if (ctx?.clearCookies) {
      await ctx.clearCookies(); // Playwright
    } else if (page.cookies && page.deleteCookie) {
      // Puppeteer: no context().clearCookies — delete the page's cookies directly.
      const cs = await page.cookies();
      if (Array.isArray(cs) && cs.length > 0) await page.deleteCookie(...cs);
    }
  } catch {
    /* ignore */
  }
  try {
    await page.goto('about:blank');
  } catch {
    /* ignore */
  }
}

/** A client-side challenge id (Phase 2 replaces this with a server request id). */
function genChallengeId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return `mfa_${c?.randomUUID ? c.randomUUID() : Math.abs(Date.now() ^ (Math.random() * 1e9)).toString(36)}`;
}

/**
 * Detect an MFA challenge after a form submit using non-secret page signals.
 * Returns a {@link MfaChallenge} (browser left on the page) or undefined. The
 * detection strategy honours `spec.detectBy` (default `auto` = url|text|input).
 */
async function detectMfaChallenge(
  page: BrowserPage,
  currentUrl: string,
  spec: MfaSpec | undefined,
): Promise<MfaChallenge | undefined> {
  const html = (await page.content?.()) ?? '';
  const urlHit = MFA_URL_RE.test(currentUrl);
  const textHit = MFA_TEXT_RE.test(html);
  const inputHit = MFA_INPUT_RE.test(html);
  const by = spec?.detectBy ?? 'auto';
  const detected =
    by === 'url' ? urlHit : by === 'text' ? textHit : by === 'input' ? inputHit : urlHit || textHit || inputHit;
  if (!detected) return undefined;
  return {
    kind: spec?.kind ?? 'otp',
    promptText: spec?.channelHint ?? extractPromptText(html) ?? 'Multi-factor authentication required',
    detectedAt: new Date().toISOString(),
    challengeId: genChallengeId(),
    // Carry the configured selectors forward so resolveMfa can inject the code
    // without an explicit option (the per-credential spec drives it).
    ...(spec?.inputSelector !== undefined ? { inputSelector: spec.inputSelector } : {}),
    ...(spec?.submitSelector !== undefined ? { submitSelector: spec.submitSelector } : {}),
  };
}

/**
 * Apply a {@link BrowserLoginPlan} to a browser `page` and return a non-secret
 * {@link BrowserLoginSummary}. Most callers should use
 * {@link AgentAuthClient.browserLogin}, which fetches the plan first; this
 * standalone form is for advanced callers who already hold a plan.
 *
 * Supports **Playwright** (primary) and **Puppeteer** (fallback) via feature
 * detection on the page object — no framework is imported, so the SDK stays
 * dependency-free. The returned summary carries only names/keys/counts and
 * **never any secret value** (cookie value, header value, storage value, or form
 * field value); nothing here is logged by the SDK.
 *
 * @param page A Playwright or Puppeteer `Page` (see {@link BrowserPage}).
 * @param plan The plan to apply.
 */
export async function applyBrowserLogin(
  page: BrowserPage,
  plan: BrowserLoginPlan,
): Promise<BrowserLoginSummary> {
  switch (plan.mode) {
    case 'cookie': {
      const ctx = page.context?.();
      if (ctx?.addCookies) {
        // Playwright: cookies are set on the browsing context.
        await ctx.addCookies(plan.cookies);
      } else if (page.setCookie) {
        // Puppeteer: cookies are set on the page (spread args).
        await page.setCookie(...plan.cookies);
      } else {
        throw new TypeError(
          'AgentAuth SDK: page supports neither context().addCookies (Playwright) nor setCookie (Puppeteer)',
        );
      }
      assertNavAllowed(plan.url, plan.allowedDomains);
      await page.goto(plan.url);
      return {
        mode: plan.mode,
        target: plan.target,
        url: plan.url,
        authenticated: true,
        cookieNames: plan.cookies.map((c) => c.name),
      };
    }

    case 'header': {
      const ctx = page.context?.();
      if (ctx?.setExtraHTTPHeaders) {
        // Playwright: headers are set on the browsing context.
        await ctx.setExtraHTTPHeaders(plan.headers);
      } else if (page.setExtraHTTPHeaders) {
        // Puppeteer (and Playwright page-level fallback).
        await page.setExtraHTTPHeaders(plan.headers);
      } else {
        throw new TypeError(
          'AgentAuth SDK: page supports neither context().setExtraHTTPHeaders nor setExtraHTTPHeaders',
        );
      }
      assertNavAllowed(plan.url, plan.allowedDomains);
      await page.goto(plan.url);
      return {
        mode: plan.mode,
        target: plan.target,
        url: plan.url,
        authenticated: true,
        headerNames: Object.keys(plan.headers),
      };
    }

    case 'localStorage': {
      // Navigate first so the page's origin is loaded, then seed localStorage.
      assertNavAllowed(plan.url, plan.allowedDomains);
      await page.goto(plan.url);
      await page.evaluate((items: Record<string, string>) => {
        for (const [k, v] of Object.entries(items)) localStorage.setItem(k, v);
      }, plan.items);
      return {
        mode: plan.mode,
        target: plan.target,
        url: plan.url,
        authenticated: true,
        storageKeys: Object.keys(plan.items),
      };
    }

    case 'form': {
      const allow = plan.allowedDomains;
      let filledFields = 0;
      for (const action of plan.actions) {
        switch (action.type) {
          case 'goto':
            // Navigation allowlist: refuse to steer the flow to an off-list host
            // (browser analogue of proxy-mode host-pinning). Default = allow all.
            assertNavAllowed(action.url, allow);
            await page.goto(action.url);
            break;
          case 'fill':
            if (page.fill) await page.fill(action.selector, action.value);
            else if (page.type) await page.type(action.selector, action.value);
            else
              throw new TypeError(
                'AgentAuth SDK: page supports neither fill (Playwright) nor type (Puppeteer)',
              );
            filledFields += 1;
            break;
          case 'click':
            await page.click(action.selector);
            break;
          default:
            // Fail loud on an unknown action (a forward-incompatible plan) rather
            // than silently producing a partial login with a clean-looking summary.
            throw new TypeError(
              `AgentAuth SDK: unknown browser form action type: ${String((action as { type?: unknown }).type)}`,
            );
        }
      }
      // A submit click triggers async navigation that Playwright's click() does
      // not await; settle it before reading the URL/HTML so success/MFA detection
      // doesn't race against a still-loading page. Best-effort (Playwright only).
      try {
        await page.waitForLoadState?.('networkidle');
      } catch {
        /* ignore */
      }

      // Best-effort success detection: did we land on a URL that matches?
      const current = page.url?.();
      let submitted: boolean | undefined;
      if (plan.successUrlIncludes !== undefined) {
        submitted = typeof current === 'string' ? current.includes(plan.successUrlIncludes) : false;
      }

      // Resolve the outcome. If we already reached the success URL, we're in;
      // otherwise look for an MFA challenge before declaring success/failure.
      let authenticated: boolean;
      let mfa: MfaChallenge | undefined;
      if (submitted === true) {
        authenticated = true;
      } else {
        mfa = await detectMfaChallenge(page, current ?? '', plan.mfa);
        if (mfa) authenticated = false;
        // No success-URL configured and no MFA seen → best-effort success (the form
        // was submitted and no challenge appeared). With a success-URL configured
        // but unmatched and no MFA, treat it as not-yet-authenticated.
        else authenticated = plan.successUrlIncludes === undefined;
      }

      return {
        mode: plan.mode,
        target: plan.target,
        url: plan.url,
        authenticated,
        filledFields,
        ...(submitted !== undefined ? { submitted } : {}),
        ...(mfa ? { mfa } : {}),
      };
    }

    default:
      // Exhaustiveness guard: an unknown plan mode (forward-incompatible server)
      // throws rather than returning undefined, mirroring the Python SDK.
      throw new TypeError(
        `AgentAuth SDK: unknown browser-login plan mode: ${String((plan as { mode?: unknown }).mode)}`,
      );
  }
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
   * **The liability path.** Fetch the raw {@link BrowserLoginPlan} for a credential
   * — the recipe for logging a browser into the credential's target (cookies,
   * headers, localStorage, or a form-fill sequence). The returned plan **carries
   * the secret in plaintext to your process**. Treat the return like a decrypted
   * password: do not log it, do not pass it to an LLM, do not persist it. AgentAuth
   * cannot enforce this once it leaves the server — the trust boundary moves to
   * your process. **Prefer {@link browserLogin}** (which confines the secret) unless
   * you have a concrete reason you cannot use the page-applying helper.
   *
   * Requires the **`vault:browser:raw`** scope (off by default) IN ADDITION to
   * `vault:use`; without it the call is `403 missing_scope`. The credential is
   * identified by **id** (a UUID) or by **target**, resolved like {@link useCredential}.
   *
   * @param idOrTarget A credential UUID, or a target host string to resolve.
   * @throws {ApprovalPendingError} 202 when the credential's policy requires human approval.
   * @throws {AgentAuthError} 403 (missing vault:browser:raw / scope / target), 404
   *   (no match), 410 (expired/window), 422 (no/invalid browser spec), 429 (use
   *   limit), 502 (oauth refresh failed), plus the usual 401/503.
   */
  async getBrowserLoginPlan(idOrTarget: string): Promise<BrowserLoginPlan> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth SDK: getBrowserLoginPlan() requires an id or target');
    }
    // The LIABILITY path: returns the secret-bearing plan to YOUR process. It hits
    // the raw endpoint, which requires the `vault:browser:raw` scope (off by
    // default) IN ADDITION to vault:use. Treat the return like a decrypted
    // password — do not log it, do not pass it to an LLM, do not persist it.
    return this.fetchBrowserPlan(idOrTarget, true);
  }

  /** Fetch a browser-login plan. raw=true → vault:browser:raw gated (caller holds
   * the secret); raw=false → vault:use only (the SDK applies + confines it). */
  private async fetchBrowserPlan(idOrTarget: string, raw: boolean): Promise<BrowserLoginPlan> {
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    return this.request<BrowserLoginPlan>({
      method: 'POST',
      path: `/v1/vault/credentials/${encodeURIComponent(id)}/browser-login`,
      ...(raw ? { query: { raw: 'true' } } : {}),
      authorization: this.authHeader,
    });
  }

  /**
   * Log a browser `page` into a credential's target: fetch the
   * {@link BrowserLoginPlan} via {@link getBrowserLoginPlan}, apply it to the page,
   * and return a **non-secret** {@link BrowserLoginSummary}. The secret material in
   * the plan flows only into the browser — it is **never** placed in the return
   * value or logged.
   *
   * Works with both **Playwright** and **Puppeteer** pages (feature-detected; no
   * framework is imported). The `idOrTarget` is resolved exactly like
   * {@link useCredential}.
   *
   * @param page A Playwright or Puppeteer `Page` (see {@link BrowserPage}).
   * @param idOrTarget A credential UUID, or a target host string to resolve.
   * @throws {ApprovalPendingError} / {@link AgentAuthError} as {@link getBrowserLoginPlan}.
   */
  async browserLogin(page: BrowserPage, idOrTarget: string): Promise<BrowserLoginSummary> {
    if (!idOrTarget) {
      throw new TypeError('AgentAuth SDK: browserLogin() requires an id or target');
    }
    // The SAFE path: needs only vault:use. The plan is fetched non-raw, applied to
    // the page, and only a non-secret summary is returned — the secret never
    // leaves this helper. If the agent has been revoked (401), force-logout the
    // browser so the session can't outlive the revoked agent.
    let plan: BrowserLoginPlan;
    try {
      plan = await this.fetchBrowserPlan(idOrTarget, false);
    } catch (err) {
      if (err instanceof AgentAuthError && err.status === 401) await forceLogout(page);
      throw err;
    }
    return applyBrowserLogin(page, plan);
  }

  /**
   * Resolve a detected MFA {@link MfaChallenge} via the human approval queue:
   * opens a request, polls until a credential owner approves (or it is denied /
   * expires / times out), and on approval injects the one-time code into the page
   * and submits. **The code flows only into the browser DOM** — it is never placed
   * in the returned {@link MfaResolution} or logged.
   *
   * Call this when {@link browserLogin} returns a summary with an `mfa` block.
   *
   * @throws {AgentAuthError} 403 (missing vault:use), 404, 429 (too many pending).
   */
  async resolveMfa(
    page: BrowserPage,
    idOrTarget: string,
    challenge: MfaChallenge,
    opts: ResolveMfaOptions = {},
  ): Promise<MfaResolution> {
    const id = isUuid(idOrTarget) ? idOrTarget : await this.resolveTarget(idOrTarget);
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;
    const pollIntervalMs = opts.pollIntervalMs ?? 2000;

    // 1) Open the approval request (the owner's queue / phone lights up). A 401
    // means the agent was revoked — force-logout the browser before surfacing it.
    let opened: { requestId: string; status: string };
    try {
      opened = await this.request<{ requestId: string; status: string }>({
        method: 'POST',
        path: `/v1/vault/credentials/${encodeURIComponent(id)}/mfa/request`,
        body: {
          challengeId: challenge.challengeId,
          kind: challenge.kind,
          ...(opts.channelHint !== undefined ? { channelHint: opts.channelHint } : {}),
          promptText: challenge.promptText,
        },
        authorization: this.authHeader,
      });
    } catch (err) {
      if (err instanceof AgentAuthError && err.status === 401) await forceLogout(page);
      throw err;
    }
    const requestId = opened.requestId;

    // 2) Poll for the human's decision until resolved or the deadline passes.
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      let res: { status: string; code?: string | null; by?: string | null; at?: string | null };
      try {
        res = await this.request({
          method: 'GET',
          path: `/v1/vault/credentials/${encodeURIComponent(id)}/mfa/request/${encodeURIComponent(requestId)}`,
          authorization: this.authHeader,
        });
      } catch (err) {
        // 410 = expired/consumed: terminal, not approved.
        if (err instanceof AgentAuthError && err.status === 410) return { resolved: false, status: 'expired' };
        // 401 = agent revoked mid-flow: force-logout before surfacing.
        if (err instanceof AgentAuthError && err.status === 401) await forceLogout(page);
        throw err;
      }
      if (res.status === 'denied') return { resolved: false, status: 'denied' };
      if (res.status === 'revoked') return { resolved: false, status: 'revoked' };
      if (res.status === 'approved') {
        const inputSelector = opts.inputSelector ?? challenge.inputSelector;
        const submitSelector = opts.submitSelector ?? challenge.submitSelector;
        // 3) Inject the code into the DOM (never returned upward). A push/webauthn
        // approval carries no code — nothing to fill, the session already advanced.
        if (res.code) {
          if (!inputSelector) {
            // Approved + code, but no selector to fill it — the form was NOT
            // advanced. Report not-resolved so the caller learns the code was
            // consumed but not applied (rather than a silent false success).
            return { resolved: false, status: 'approved', by: res.by ?? null, at: res.at ?? null };
          }
          let filled = false;
          if (page.fill) {
            await page.fill(inputSelector, res.code);
            filled = true;
          } else if (page.type) {
            await page.type(inputSelector, res.code);
            filled = true;
          }
          // If the page exposes neither fill nor type, the code was never applied —
          // don't submit an empty field or claim success. (The Python SDK targets
          // Playwright sync, where page.fill always exists, so it has no fallback.)
          if (!filled) return { resolved: false, status: 'approved', by: res.by ?? null, at: res.at ?? null };
          if (submitSelector) {
            await page.click(submitSelector);
            // The submit triggers async navigation that click() doesn't await —
            // settle it so a caller reading page.url() right after sees the result.
            try {
              await page.waitForLoadState?.('networkidle');
            } catch {
              /* ignore */
            }
          }
        }
        return { resolved: true, status: 'approved', by: res.by ?? null, at: res.at ?? null };
      }
      // pending
      if (Date.now() >= deadline) return { resolved: false, status: 'timeout' };
      await sleep(pollIntervalMs);
    }
  }

  /**
   * Resolve a target string to a single credential id by scanning the listing.
   * Pages until a match is found or the listing is exhausted. If more than one
   * credential shares the target, the first match (by listing order) wins.
   */
  private async resolveTarget(target: string): Promise<string> {
    // Match on bare host (like the server's allowsTarget), so a URL- or host:port-
    // form credential resolves by its host too — not just the exact stored string.
    const want = targetHost(target);
    const pageSize = 200; // max the server allows — fewest round-trips.
    let offset = 0;
    for (;;) {
      const pageResult = await this.listCredentials({ limit: pageSize, offset });
      const match = pageResult.items.find((c) => targetHost(c.target) === want);
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
  /** Optional usage cap: the credential may be used at most this many times. */
  maxUses?: number;
  /** Optional ISO-8601 timestamp: the credential is not usable before this. */
  allowedFrom?: string;
  /** Optional ISO-8601 timestamp: the credential is not usable after this. */
  allowedUntil?: string;
  /** When true, each use must be approved by a human before the secret is released. */
  requireApproval?: boolean;
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

  /**
   * Bind an mTLS client certificate to one of your agents, so it can authenticate
   * with that client cert (by fingerprint) as an alternative to its bearer API key.
   * Provide either a PEM cert (the fingerprint is derived server-side) or a
   * pre-computed SHA-256 fingerprint. The binding is an idempotent overwrite.
   *
   * @param agentId The agent's UUID.
   * @param opts `{ certPem }` or `{ fingerprint }` (at least one is required).
   * @returns The agent id and the bound `certFingerprint` (SHA-256 hex).
   * @throws {AgentAuthError} 400 (no/invalid cert or fingerprint), 404 (agent not
   *   found / not yours), 409 (fingerprint already bound to another agent).
   */
  bindAgentMtls(
    agentId: string,
    opts: { certPem?: string; fingerprint?: string },
  ): Promise<{ id: string; certFingerprint: string }> {
    return this.request<{ id: string; certFingerprint: string }>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/mtls`,
      body: {
        ...(opts.certPem !== undefined ? { certPem: opts.certPem } : {}),
        ...(opts.fingerprint !== undefined ? { fingerprint: opts.fingerprint } : {}),
      },
      authorization: this.authHeader,
    });
  }

  /**
   * Begin an OAuth authorization-code flow for a passport. Returns the URL the
   * human's browser should visit to authorize, plus the CSRF `state`. After the
   * user authorizes, the provider redirects to the server callback, which seals
   * the tokens as an `oauth_token` credential the agent can later reuse.
   *
   * @param passportId The passport's UUID.
   * @param provider The provider name (e.g. `github`, `google`).
   * @param opts Optional `target` override (defaults to the provider name) and `label`.
   * @returns `{ authorizeUrl, state }`.
   * @throws {AgentAuthError} 404 (passport/provider not found), 400 (invalid body),
   *   500 (oauth misconfigured).
   */
  startOauth(
    passportId: string,
    provider: string,
    opts: { target?: string; label?: string } = {},
  ): Promise<{ authorizeUrl: string; state: string }> {
    return this.request<{ authorizeUrl: string; state: string }>({
      method: 'POST',
      path: `/v1/passports/${encodeURIComponent(passportId)}/oauth/${encodeURIComponent(provider)}/start`,
      body: {
        ...(opts.target !== undefined ? { target: opts.target } : {}),
        ...(opts.label !== undefined ? { label: opts.label } : {}),
      },
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
