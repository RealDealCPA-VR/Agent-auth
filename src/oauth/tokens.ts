import { createHash, randomBytes } from 'node:crypto';
import type { OAuthProvider } from './registry.js';
import { env } from '../env.js';

/**
 * OAuth token-exchange helpers: PKCE generation and the two token-endpoint calls
 * (authorization_code exchange and refresh_token refresh). All HTTP uses the
 * global `fetch`. Token values are never logged here.
 */

/** The token set we seal as the credential secret. `expires_at` is epoch ms. */
export interface TokenSet {
  access_token: string;
  refresh_token: string | null;
  token_type: string;
  scope: string | null;
  expires_at: number | null;
}

/** Raw token-endpoint response (snake_case per RFC 6749). */
interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  scope?: string;
  expires_in?: number;
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Generate a PKCE pair: a high-entropy verifier and its S256 challenge. */
export function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}

/** A URL-safe, unguessable CSRF state value. */
export function generateState(): string {
  return base64url(randomBytes(24));
}

/** Map a token-endpoint response onto our sealed TokenSet, computing absolute expiry. */
function toTokenSet(
  r: TokenResponse,
  now: number,
  prevRefresh: string | null,
  prevScope: string | null = null,
): TokenSet {
  return {
    access_token: r.access_token!,
    // Providers often omit refresh_token on refresh; keep the prior one.
    refresh_token: r.refresh_token ?? prevRefresh,
    token_type: r.token_type ?? 'bearer',
    // RFC 6749 §5.1: an omitted `scope` on a refresh means "identical to the scope
    // originally granted" — carry the prior scope forward instead of nulling it.
    scope: r.scope ?? prevScope,
    expires_at: typeof r.expires_in === 'number' ? now + r.expires_in * 1000 : null,
  };
}

/** Exchange an authorization code for a token set (PKCE). Throws on non-2xx / no token. */
export async function exchangeCode(
  provider: OAuthProvider,
  opts: { code: string; redirectUri: string; codeVerifier: string },
): Promise<TokenSet> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: opts.code,
    redirect_uri: opts.redirectUri,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    code_verifier: opts.codeVerifier,
  });
  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
    signal: AbortSignal.timeout(env.OAUTH_TOKEN_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  const json = (await res.json()) as TokenResponse;
  if (!json.access_token) throw new Error('token exchange returned no access_token');
  return toTokenSet(json, Date.now(), null);
}

/** Refresh an access token using a refresh_token. Throws on non-2xx / no token. */
export async function refreshToken(provider: OAuthProvider, current: TokenSet): Promise<TokenSet> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: current.refresh_token!,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
  });
  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
    signal: AbortSignal.timeout(env.OAUTH_TOKEN_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`token refresh failed: ${res.status}`);
  const json = (await res.json()) as TokenResponse;
  if (!json.access_token) throw new Error('token refresh returned no access_token');
  return toTokenSet(json, Date.now(), current.refresh_token, current.scope);
}

/**
 * True if the access token is missing an expiry-in-future (expired / within skew).
 *
 * Transparent proactive refresh requires the provider to return `expires_in` at
 * capture/refresh (so `expires_at` is known). A provider that issues a
 * refresh_token but OMITS expires_in (`expires_at === null`) is treated as
 * "freshness unknown" and is NOT refreshed proactively — refreshing on every use
 * would be wasteful and most such tokens are long-lived. Configure such providers
 * to return expires_in for transparent refresh; otherwise a server-side expiry is
 * surfaced as a downstream 401 to the caller. See docs/ROTATION.md / README.
 */
export function needsRefresh(tokens: TokenSet, skewMs = 60_000): boolean {
  if (!tokens.refresh_token) return false;
  if (tokens.expires_at === null) return false;
  return tokens.expires_at - skewMs <= Date.now();
}

/** Build the provider authorize URL with all PKCE/state query params. */
export function buildAuthorizeUrl(
  provider: OAuthProvider,
  opts: { redirectUri: string; state: string; codeChallenge: string },
): string {
  const url = new URL(provider.authUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.clientId);
  url.searchParams.set('redirect_uri', opts.redirectUri);
  if (provider.scopes.length > 0) url.searchParams.set('scope', provider.scopes.join(' '));
  url.searchParams.set('state', opts.state);
  url.searchParams.set('code_challenge', opts.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}
