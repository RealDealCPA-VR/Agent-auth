import {
  pgTable,
  uuid,
  text,
  timestamp,
  jsonb,
  boolean,
  bigserial,
  integer,
  index,
  uniqueIndex,
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
    // How to inject the secret into a server-side proxied request (proxy mode).
    // null => a sensible default per credential type. Shape:
    //   { mode:'bearer' } | { mode:'basic' } | { mode:'cookie' }
    //   | { mode:'header', name, prefix? } | { mode:'query', name }
    injection: jsonb('injection'),
    // Optional expiry; expired credentials are treated as unavailable.
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    // --- Usage policy (all optional) ---
    maxUses: integer('max_uses'), // null = unlimited
    useCount: integer('use_count').notNull().default(0),
    allowedFrom: timestamp('allowed_from', { withTimezone: true }), // usage window start
    allowedUntil: timestamp('allowed_until', { withTimezone: true }), // usage window end
    requireApproval: boolean('require_approval').notNull().default(false),
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
    // Optional mTLS client-cert binding. Stored as a lowercase SHA-256 hex
    // fingerprint with no colons; lets an agent authenticate with a client
    // certificate as an ALTERNATIVE to its bearer API key. Unique so a given
    // cert maps to at most one agent.
    certFingerprint: text('cert_fingerprint'),
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
    byCertFingerprint: uniqueIndex('agents_cert_fingerprint_idx').on(t.certFingerprint),
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

export const approvalStatus = pgEnum('approval_status', ['pending', 'approved', 'denied']);

/**
 * approval_requests — the human-in-the-loop gate for credentials whose policy
 * sets requireApproval. An agent's `use` call materializes a pending row; a human
 * owner approves or denies it. An approved row is single-use: it is consumed
 * (consumedAt set) by the next successful use, and a fresh request is required
 * after that. Rows carry their own TTL (`expiresAt`) so stale grants can't be
 * replayed; pending rows past TTL are ignored and re-requested.
 */
export const approvalRequests = pgTable(
  'approval_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    credentialId: uuid('credential_id')
      .notNull()
      .references(() => credentials.id, { onDelete: 'cascade' }),
    passportId: uuid('passport_id')
      .notNull()
      .references(() => passports.id, { onDelete: 'cascade' }),
    agentId: uuid('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    status: approvalStatus('status').notNull().default('pending'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    decidedAt: timestamp('decided_at', { withTimezone: true }),
    decidedBy: uuid('decided_by'), // principal who approved/denied
    consumedAt: timestamp('consumed_at', { withTimezone: true }), // set when an approval is spent
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (t) => ({
    byPassport: index('approval_requests_passport_idx').on(t.passportId),
    byCredAgentStatus: index('approval_requests_cred_agent_status_idx').on(
      t.credentialId,
      t.agentId,
      t.status,
    ),
  }),
);

/**
 * oauth_flows — short-lived state for an in-flight authorization-code flow. A
 * `start` call mints a row carrying the PKCE code_verifier, the random CSRF
 * `state`, and the context needed to seal the captured tokens at callback time
 * (which passport/principal, target, label). Rows are deleted once consumed and
 * are ignored past `expiresAt`. Nothing here is a secret at rest beyond the PKCE
 * verifier, which is single-use and short-lived.
 */
export const oauthFlows = pgTable(
  'oauth_flows',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    state: text('state').notNull().unique(),
    codeVerifier: text('code_verifier').notNull(),
    principalId: uuid('principal_id').notNull(),
    passportId: uuid('passport_id').notNull(),
    provider: text('provider').notNull(),
    target: text('target').notNull(),
    label: text('label').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  // `state` is already UNIQUE (its own btree index serves the equality lookup), so
  // no extra index is needed.
);

export const auditAction = pgEnum('audit_action', [
  'principal.register',
  'principal.login',
  'principal.logout',
  'passport.create',
  'credential.deposit',
  'credential.use',
  'credential.proxy',
  'credential.browser',
  'agent.issue',
  'agent.revoke',
  'agent.mtls_bind',
  'approval.approve',
  'approval.deny',
  'oauth.start',
  'oauth.capture',
  'auth.denied',
  'authz.denied',
]);

/**
 * audit_events — append-only, tamper-evident record of every security-relevant
 * action. Each row is linked to the previous by a forward hash chain
 * (`prevHash`->`hash`, HMAC-keyed), so modification/reorder or deletion of an
 * INTERIOR row breaks the chain (tail-truncation is caught by the triggers, not
 * the chain). Stores
 * who/what/when and an outcome, never the secret itself. Reference columns are
 * intentionally NOT foreign keys, so audit rows survive deletion of the entities
 * they describe. DB triggers block UPDATE/DELETE/TRUNCATE on the normal SQL path
 * (see migrate.ts) — preventive only against a role that can't disable triggers,
 * so run the runtime as a least-privilege non-owner role; the HMAC chain is the
 * detective backstop.
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
    // `seq` is already UNIQUE (its btree serves ordered scans + lookups) — no extra index.
    byCreated: index('audit_created_idx').on(t.createdAt),
    byPassport: index('audit_passport_idx').on(t.passportId),
    byPrincipal: index('audit_principal_idx').on(t.principalId),
    byAgent: index('audit_agent_idx').on(t.agentId),
  }),
);
