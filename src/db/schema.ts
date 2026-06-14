import {
  pgTable,
  uuid,
  text,
  timestamp,
  jsonb,
  boolean,
  bigserial,
  index,
  pgEnum,
} from 'drizzle-orm/pg-core';

/**
 * principals — the humans who own passports. They authenticate interactively
 * (the "log in once manually" actor) and deposit credentials into a passport.
 */
export const principals = pgTable('principals', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(), // argon2id
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

/**
 * passports — a vault owned by a principal. Each passport carries its own data
 * encryption key (DEK), stored only in wrapped (KEK-encrypted) form. The wrapped
 * DEK records the id of the KEK that wrapped it, so keys can be rotated.
 */
export const passports = pgTable(
  'passports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    principalId: uuid('principal_id')
      .notNull()
      .references(() => principals.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    // Wrapped DEK: { v, alg, iv, ciphertext, tag, kid } — AES-256-GCM under a KEK.
    wrappedDek: jsonb('wrapped_dek').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    byPrincipal: index('passports_principal_idx').on(t.principalId),
  }),
);

export const credentialType = pgEnum('credential_type', [
  'password',
  'oauth_token',
  'cookie',
  'api_key',
]);

/**
 * credentials — vault entries. The secret material is sealed with the owning
 * passport's DEK (AES-256-GCM). Only non-secret metadata (target, label, type)
 * is stored in the clear so agents can discover what's available.
 */
export const credentials = pgTable(
  'credentials',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    passportId: uuid('passport_id')
      .notNull()
      .references(() => passports.id, { onDelete: 'cascade' }),
    target: text('target').notNull(), // e.g. "github.com", "https://api.acme.com"
    label: text('label').notNull(), // human-friendly name for the entry
    type: credentialType('type').notNull(),
    // Sealed secret: { v, alg, iv, ciphertext, tag } base64. Never logged, never
    // returned except via an explicit, scoped, audited `use` call.
    sealed: jsonb('sealed').notNull(),
    // Non-secret hints (username, scopes, expiry) — safe to expose.
    metadata: jsonb('metadata').notNull().default({}),
    // Optional expiry; expired credentials are treated as unavailable.
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => ({
    byPassport: index('credentials_passport_idx').on(t.passportId),
  }),
);

/**
 * agents — machine identities bound to exactly one passport. An agent
 * authenticates with an API key (`aa_<id>.<secret>`); only the argon2 hash of
 * the secret is stored. `active` is the fail-closed revocation flag.
 */
export const agents = pgTable(
  'agents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    passportId: uuid('passport_id')
      .notNull()
      .references(() => passports.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    secretHash: text('secret_hash').notNull(), // argon2id of the key secret
    // Scopes gate what the agent may do, e.g. ["vault:read", "vault:use"] and
    // optional target globs like "target:github.com".
    scopes: jsonb('scopes').notNull().$type<string[]>().default([]),
    active: boolean('active').notNull().default(true),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    byPassport: index('agents_passport_idx').on(t.passportId),
  }),
);

/**
 * revoked_sessions — jti denylist for human JWTs invalidated before expiry
 * (logout / forced revocation). Rows can be pruned once `expiresAt` passes.
 */
export const revokedSessions = pgTable(
  'revoked_sessions',
  {
    jti: text('jti').primaryKey(),
    principalId: uuid('principal_id'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    byExpiry: index('revoked_sessions_expiry_idx').on(t.expiresAt),
  }),
);

export const auditAction = pgEnum('audit_action', [
  'principal.register',
  'principal.login',
  'principal.logout',
  'passport.create',
  'credential.deposit',
  'credential.use',
  'agent.issue',
  'agent.revoke',
  'auth.denied',
  'authz.denied',
]);

/**
 * audit_events — append-only, tamper-evident record of every security-relevant
 * action. Each row is linked to the previous by a hash chain (`prevHash`->`hash`,
 * HMAC-keyed), so deletion or modification of any row breaks the chain. Stores
 * who/what/when and an outcome, never the secret itself. Reference columns are
 * intentionally NOT foreign keys, so audit rows survive deletion of the entities
 * they describe. A DB trigger blocks UPDATE/DELETE (see migrate.ts).
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    seq: bigserial('seq', { mode: 'number' }).notNull().unique(),
    action: auditAction('action').notNull(),
    principalId: uuid('principal_id'),
    passportId: uuid('passport_id'),
    agentId: uuid('agent_id'),
    credentialId: uuid('credential_id'),
    success: boolean('success').notNull(),
    detail: jsonb('detail').notNull().default({}), // non-secret context only
    ip: text('ip'),
    prevHash: text('prev_hash'),
    hash: text('hash').notNull(),
    hashKeyId: text('hash_key_id').notNull(), // which audit HMAC key signed this row
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    bySeq: index('audit_seq_idx').on(t.seq),
    byCreated: index('audit_created_idx').on(t.createdAt),
    byPassport: index('audit_passport_idx').on(t.passportId),
    byPrincipal: index('audit_principal_idx').on(t.principalId),
    byAgent: index('audit_agent_idx').on(t.agentId),
  }),
);
