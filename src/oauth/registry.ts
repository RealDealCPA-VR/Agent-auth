import { env } from '../env.js';

/**
 * OAuth provider registry. Parsed once from OAUTH_PROVIDERS (already validated in
 * env.ts) into a lookup keyed by provider name. The client secret lives here in
 * memory only — it is never returned to a caller and never logged.
 */
export interface OAuthProvider {
  name: string;
  authUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
}

function parseRegistry(): Map<string, OAuthProvider> {
  const map = new Map<string, OAuthProvider>();
  if (!env.OAUTH_PROVIDERS) return map;
  // Shape is guaranteed by the env superRefine; parse without re-validating.
  const raw = JSON.parse(env.OAUTH_PROVIDERS) as Record<
    string,
    {
      authUrl: string;
      tokenUrl: string;
      clientId: string;
      clientSecret: string;
      scopes?: string[];
    }
  >;
  for (const [name, cfg] of Object.entries(raw)) {
    map.set(name, {
      name,
      authUrl: cfg.authUrl,
      tokenUrl: cfg.tokenUrl,
      clientId: cfg.clientId,
      clientSecret: cfg.clientSecret,
      scopes: cfg.scopes ?? [],
    });
  }
  return map;
}

const registry = parseRegistry();

/** Look up a configured provider by name, or undefined if unknown. */
export function getProvider(name: string): OAuthProvider | undefined {
  return registry.get(name);
}

/** The URI the provider redirects back to after authorization (callback). */
export function redirectUri(): string {
  return `${env.OAUTH_REDIRECT_BASE}/v1/oauth/callback`;
}
