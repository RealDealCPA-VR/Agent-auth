import { readFileSync } from 'node:fs';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '../env.js';
import * as schema from './schema.js';

/**
 * Resolve the Postgres TLS setting from env. Production defaults to requiring
 * TLS; `verify` additionally checks the server certificate against a CA bundle.
 */
function resolveSsl(): postgres.Options<Record<string, never>>['ssl'] {
  switch (env.sslMode) {
    case 'disable':
      return false;
    case 'require':
      return 'require';
    case 'verify':
      return {
        rejectUnauthorized: true,
        ...(env.DATABASE_SSL_CA ? { ca: readFileSync(env.DATABASE_SSL_CA, 'utf8') } : {}),
      };
  }
}

// Single shared connection pool. `max` kept modest; this is an auth broker, not
// a high-throughput data plane.
const queryClient = postgres(env.DATABASE_URL, { max: 10, ssl: resolveSsl() });

export const db = drizzle(queryClient, { schema });
export { schema };
export { queryClient as sql };

/** Lightweight liveness check used by fail-closed agent auth and /healthz. */
export async function pingDb(): Promise<boolean> {
  try {
    await queryClient`select 1`;
    return true;
  } catch {
    return false;
  }
}

export async function closeDb(): Promise<void> {
  await queryClient.end({ timeout: 5 });
}
