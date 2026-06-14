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
    JWT_KEY_ID: z.string().min(1).default('j1'),
    // Optional retired JWT keys for rotation, as JSON {"<kid>":"<base64-32B>"}, so
    // tokens signed before a roll still verify until they expire.
    JWT_SECRETS_RETIRED: z.string().optional(),
    JWT_TTL_SECONDS: z.coerce.number().int().positive().max(86400).default(3600),

    // How long an approval request (pending or granted) stays valid. A grant's
    // validity is refreshed to this window at approval time.
    APPROVAL_TTL_SECONDS: z.coerce.number().int().positive().default(900),

    // OAuth provider registry, as JSON mapping provider name -> config:
    //   {"github":{"authUrl":"...","tokenUrl":"...","clientId":"...",
    //              "clientSecret":"...","scopes":["repo"]}}
    // Validated in the superRefine below (valid JSON object; each entry has string
    // authUrl/tokenUrl/clientId/clientSecret, optional string[] scopes).
    OAUTH_PROVIDERS: z.string().optional(),
    // Public base URL of this server; the provider redirects back to
    // `${OAUTH_REDIRECT_BASE}/v1/oauth/callback` after authorization.
    OAUTH_REDIRECT_BASE: z.string().url().optional(),
    // How long an in-flight authorization (PKCE/state) row stays valid.
    OAUTH_STATE_TTL_SECONDS: z.coerce.number().int().positive().default(600),

    // Key provider for the KEK layer that wraps per-passport data keys.
    //   local — wrap with MASTER_KEY in-process (default)
    //   kms   — wrap via an external KMS (see KMS_* below); MASTER_KEY never holds the KEK
    KEY_PROVIDER: z.enum(['local', 'kms']).default('local'),
    KMS_KEY_ID: z.string().optional(), // KMS key id/arn/alias for the active KEK
    KMS_REGION: z.string().optional(),
    KMS_ENDPOINT: z.string().optional(), // override for LocalStack / tests

    // Audit hash-chain signing key. If AUDIT_HMAC_SECRET is unset, the active key
    // is derived from MASTER_KEY (back-compat). AUDIT_KEY_ID labels the active key
    // on each row; AUDIT_KEYS_RETIRED holds prior raw keys so the chain verifies
    // across rotations.
    AUDIT_HMAC_SECRET: z
      .string()
      .optional()
      .refine(
        (v) => !v || Buffer.from(v, 'base64').length === 32,
        'AUDIT_HMAC_SECRET must be 32 bytes base64',
      ),
    AUDIT_KEY_ID: z.string().min(1).default('a1'),
    AUDIT_KEYS_RETIRED: z.string().optional(),

    // Postgres TLS. In production we default to requiring TLS; local docker can
    // disable it. Accept a CA bundle path for verify-full setups.
    DATABASE_SSL: z.enum(['disable', 'require', 'verify']).optional(),
    DATABASE_SSL_CA: z.string().optional(),

    // Optional native HTTPS. Provide BOTH a cert and key (PEM file paths) to have
    // the server terminate TLS directly; otherwise terminate at a reverse proxy.
    HTTPS_CERT: z.string().optional(),
    HTTPS_KEY: z.string().optional(),

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
    const validateRetired = (
      raw: string | undefined,
      field: 'MASTER_KEYS_RETIRED' | 'JWT_SECRETS_RETIRED' | 'AUDIT_KEYS_RETIRED',
    ) => {
      if (!raw) return;
      let retired: unknown;
      try {
        retired = JSON.parse(raw);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [field],
          message: 'must be valid JSON: {"<kid>":"<base64-32B>"}',
        });
        return;
      }
      if (typeof retired !== 'object' || retired === null || Array.isArray(retired)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [field],
          message: 'must be a JSON object of kid -> base64 key',
        });
        return;
      }
      for (const [kid, val] of Object.entries(retired as Record<string, unknown>)) {
        if (typeof val !== 'string' || Buffer.from(val, 'base64').length !== 32) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [field],
            message: `retired key "${kid}" must decode to exactly 32 bytes of base64`,
          });
        }
      }
    };
    validateRetired(e.MASTER_KEYS_RETIRED, 'MASTER_KEYS_RETIRED');
    validateRetired(e.JWT_SECRETS_RETIRED, 'JWT_SECRETS_RETIRED');
    validateRetired(e.AUDIT_KEYS_RETIRED, 'AUDIT_KEYS_RETIRED');

    // OAUTH_PROVIDERS: a JSON object of name -> {authUrl, tokenUrl, clientId,
    // clientSecret, scopes?:string[]}. Validated up-front so a malformed registry
    // fails the boot cleanly instead of throwing on first OAuth request.
    if (e.OAUTH_PROVIDERS) {
      let providers: unknown;
      try {
        providers = JSON.parse(e.OAUTH_PROVIDERS);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OAUTH_PROVIDERS'],
          message: 'must be valid JSON: {"<name>":{authUrl,tokenUrl,clientId,clientSecret}}',
        });
        return;
      }
      if (typeof providers !== 'object' || providers === null || Array.isArray(providers)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OAUTH_PROVIDERS'],
          message: 'must be a JSON object of provider name -> config',
        });
        return;
      }
      for (const [name, cfg] of Object.entries(providers as Record<string, unknown>)) {
        if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['OAUTH_PROVIDERS'],
            message: `provider "${name}" must be an object`,
          });
          continue;
        }
        const c = cfg as Record<string, unknown>;
        for (const key of ['authUrl', 'tokenUrl', 'clientId', 'clientSecret'] as const) {
          if (typeof c[key] !== 'string' || (c[key] as string).length === 0) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: ['OAUTH_PROVIDERS'],
              message: `provider "${name}" is missing string ${key}`,
            });
          }
        }
        if (
          c.scopes !== undefined &&
          (!Array.isArray(c.scopes) || c.scopes.some((s) => typeof s !== 'string'))
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['OAUTH_PROVIDERS'],
            message: `provider "${name}" scopes must be an array of strings`,
          });
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

    // Native HTTPS requires both cert and key, and both must be readable.
    if (Boolean(e.HTTPS_CERT) !== Boolean(e.HTTPS_KEY)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['HTTPS_CERT'],
        message: 'provide BOTH HTTPS_CERT and HTTPS_KEY, or neither',
      });
    }
    for (const k of ['HTTPS_CERT', 'HTTPS_KEY'] as const) {
      if (e[k]) {
        try {
          accessSync(e[k]!, constants.R_OK);
        } catch {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [k],
            message: `${k} file not readable`,
          });
        }
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
