import { readFileSync } from 'node:fs';
import { env } from '../env.js';

export type SslSetting = false | 'require' | { rejectUnauthorized: boolean; ca?: string };

/**
 * Resolve the Postgres TLS setting from env, shared by the runtime pool and the
 * migrate/rotate scripts so they enforce identical security. Production defaults
 * to requiring TLS; `verify` additionally checks the server cert against a CA.
 */
export function resolveSsl(): SslSetting {
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
