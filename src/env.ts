import 'dotenv/config';
import { accessSync, constants } from 'node:fs';
import { z } from 'zod';

/**
 * Strict, fail-fast environment loading. The process refuses to boot if a
 * security-critical secret is missing or malformed — there is no insecure
 * default for MASTER_KEY or JWT_SECRET.
 */
const base64Exact = (label: string, bytes: number) =>
  z
    .string()
    .min(1, `${label} is required`)
    .refine((v) => {
      try {
        return Buffer.from(v, 'base64').length === bytes;
      } catch {
        return false;
      }
    }, `${label} must decode to exactly ${bytes} bytes of base64`);

const schema = z
  .object({
    DATABASE_URL: z.string().url(),

    // Active key-encryption key. 32 bytes, base64. Identified by MASTER_KEY_ID
    // so credentials sealed under an older key remain decryptable after rotation.
    MASTER_KEY: base64Exact('MASTER_KEY', 32),
    MASTER_KEY_ID: z.string().min(1).default('k1'),
    // Optional retired keys for rotation, as JSON: {"k0":"<base64-32B>", ...}
    MASTER_KEYS_RETIRED: z.string().optional(),

    JWT_SECRET: base64Exact('JWT_SECRET', 32),
    JWT_TTL_SECONDS: z.coerce.number().int().positive().max(86400).default(3600),

    // Postgres TLS. In production we default to requiring TLS; local docker can
    // disable it. Accept a CA bundle path for verify-full setups.
    DATABASE_SSL: z.enum(['disable', 'require', 'verify']).optional(),
    DATABASE_SSL_CA: z.string().optional(),

    // Comma-separated CORS allowlist. Empty => no cross-origin browser access.
    CORS_ORIGINS: z.string().default(''),

    // Rate limits (requests/window). Global is generous; auth routes are strict.
    RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().positive().default(300),
    RATE_LIMIT_AUTH_MAX: z.coerce.number().int().positive().default(10),
    RATE_LIMIT_WINDOW: z.string().default('1 minute'),

    // Max JSON body size in bytes.
    BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(65536),

    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    PORT: z.coerce.number().int().positive().default(8080),
    HOST: z.string().default('0.0.0.0'),
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  })
  // Validate compound/dependent fields here so a bad value fails fast with the
  // clean env error message instead of throwing at module-import time.
  .superRefine((e, ctx) => {
    if (e.MASTER_KEYS_RETIRED) {
      let retired: unknown;
      try {
        retired = JSON.parse(e.MASTER_KEYS_RETIRED);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['MASTER_KEYS_RETIRED'],
          message: 'must be valid JSON: {"<kid>":"<base64-32B>"}',
        });
        retired = undefined;
      }
      if (retired && (typeof retired !== 'object' || Array.isArray(retired))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['MASTER_KEYS_RETIRED'],
          message: 'must be a JSON object of kid -> base64 key',
        });
      } else if (retired) {
        for (const [kid, val] of Object.entries(retired as Record<string, unknown>)) {
          if (typeof val !== 'string' || Buffer.from(val, 'base64').length !== 32) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: ['MASTER_KEYS_RETIRED'],
              message: `retired key "${kid}" must decode to exactly 32 bytes of base64`,
            });
          }
        }
      }
    }

    const sslMode = e.DATABASE_SSL ?? (e.NODE_ENV === 'production' ? 'require' : 'disable');
    if (sslMode === 'verify' && e.DATABASE_SSL_CA) {
      try {
        accessSync(e.DATABASE_SSL_CA, constants.R_OK);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['DATABASE_SSL_CA'],
          message: 'CA file not found or not readable',
        });
      }
    }
  })
  .transform((e) => ({
    ...e,
    isProd: e.NODE_ENV === 'production',
    // Effective SSL mode: explicit value wins, else require in prod / disable otherwise.
    sslMode: e.DATABASE_SSL ?? (e.NODE_ENV === 'production' ? 'require' : 'disable'),
    corsOrigins: e.CORS_ORIGINS.split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  }));

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
  console.error(
    `\nInvalid environment configuration:\n${issues}\n\nCopy .env.example to .env and fill in the secrets.\n`,
  );
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;
