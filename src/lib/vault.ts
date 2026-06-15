import { and, eq, sql } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { generateDek, seal, open, type SealedBox, type WrappedKey } from '../crypto/envelope.js';
import { wrapDek, unwrapDek } from '../crypto/keyprovider/index.js';
import { requestOrConsume } from './approvals.js';
import { getProvider } from '../oauth/registry.js';
import { needsRefresh, refreshToken, type TokenSet } from '../oauth/tokens.js';
import type { Injection } from './proxy.js';

/**
 * Vault operations. All DEK material is unwrapped transiently per-call and never
 * persisted or logged in cleartext.
 */

export async function createPassport(principalId: string, name: string) {
  const dek = generateDek();
  const wrapped = await wrapDek(dek);
  dek.fill(0); // scrub after wrapping
  const [row] = await db
    .insert(schema.passports)
    .values({ principalId, name, wrappedDek: wrapped })
    .returning({
      id: schema.passports.id,
      name: schema.passports.name,
      createdAt: schema.passports.createdAt,
    });
  return row!;
}

async function loadDek(passportId: string): Promise<Buffer | null> {
  const [p] = await db
    .select({ wrappedDek: schema.passports.wrappedDek })
    .from(schema.passports)
    .where(eq(schema.passports.id, passportId))
    .limit(1);
  if (!p) return null;
  return await unwrapDek(p.wrappedDek as WrappedKey);
}

/** The "log in once manually" write path: seal a secret into the passport. */
export async function depositCredential(opts: {
  passportId: string;
  target: string;
  label: string;
  type: (typeof schema.credentialType.enumValues)[number];
  secret: string;
  metadata?: Record<string, unknown>;
  expiresAt?: Date | null;
  maxUses?: number | null;
  allowedFrom?: Date | null;
  allowedUntil?: Date | null;
  requireApproval?: boolean;
  injection?: Injection | null;
}) {
  const dek = await loadDek(opts.passportId);
  if (!dek) return null;
  const secretBuf = Buffer.from(opts.secret, 'utf8');
  // Bind the ciphertext to its passport + target so it can't be replayed elsewhere.
  const aad = Buffer.from(`${opts.passportId}:${opts.target}`);
  try {
    const sealed = seal(dek, secretBuf, aad);
    const [row] = await db
      .insert(schema.credentials)
      .values({
        passportId: opts.passportId,
        target: opts.target,
        label: opts.label,
        type: opts.type,
        sealed,
        metadata: opts.metadata ?? {},
        injection: opts.injection ?? null,
        expiresAt: opts.expiresAt ?? null,
        maxUses: opts.maxUses ?? null,
        allowedFrom: opts.allowedFrom ?? null,
        allowedUntil: opts.allowedUntil ?? null,
        requireApproval: opts.requireApproval ?? false,
      })
      .returning({
        id: schema.credentials.id,
        target: schema.credentials.target,
        label: schema.credentials.label,
        type: schema.credentials.type,
        metadata: schema.credentials.metadata,
        expiresAt: schema.credentials.expiresAt,
        createdAt: schema.credentials.createdAt,
      });
    return row!;
  } finally {
    dek.fill(0);
    secretBuf.fill(0); // scrub the plaintext secret from memory
    aad.fill(0); // scrub for consistency (AAD is non-secret, but keep one pattern)
  }
}

export type UseResult =
  | {
      status: 'ok';
      secret: string;
      target: string;
      label: string;
      type: string;
      metadata: unknown;
      expiresAt: Date | null;
      injection: Injection | null;
      id: string;
    }
  | { status: 'not_found' }
  | { status: 'expired' }
  | { status: 'not_yet_valid' }
  | { status: 'window_expired' }
  | { status: 'use_limit' }
  | { status: 'approval_pending'; requestId: string }
  | { status: 'approval_denied' }
  | { status: 'refresh_failed' }
  | { status: 'decrypt_error' };

// Per-credential advisory-lock namespace for serializing oauth token refresh.
// Distinct from the audit-chain lock so the two never contend.
const OAUTH_REFRESH_LOCK_NS = 4242422;

/**
 * Hash a credential id into the 32-bit lock-key space for pg_advisory_xact_lock,
 * so concurrent refreshers of the SAME credential serialize while different
 * credentials don't contend. Uses a cheap, stable string hash of the uuid.
 */
function credLockKey(credentialId: string): number {
  let h = 0;
  for (let i = 0; i < credentialId.length; i += 1) {
    h = (Math.imul(31, h) + credentialId.charCodeAt(i)) | 0;
  }
  return h;
}

/**
 * For an oauth_token credential: ensure the access token is fresh, refreshing it
 * (and re-sealing the updated token set) when it is expired or near expiry. The
 * refresh is serialized per-credential with a transaction-scoped advisory lock so
 * concurrent agents don't double-refresh; the loser re-reads the freshly re-sealed
 * tokens inside the same tx. Returns the (possibly new) access token, or null on
 * refresh failure. `aad` binds the re-seal to passport+target like the original.
 */
async function freshOauthAccessToken(
  passportId: string,
  cred: { id: string; target: string; metadata: unknown },
  tokens: TokenSet,
  dek: Buffer,
  aad: Buffer,
): Promise<string | null> {
  if (!needsRefresh(tokens)) return tokens.access_token;

  const meta = (cred.metadata ?? {}) as Record<string, unknown>;
  const provider = typeof meta.provider === 'string' ? getProvider(meta.provider) : undefined;
  // No provider configured (removed since capture) or no refresh token: we can't
  // refresh. Hand back the current (likely-expired) token rather than failing —
  // the policy/window checks already passed and the caller may still succeed.
  if (!provider || !tokens.refresh_token) return tokens.access_token;

  return db.transaction(async (tx) => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(${OAUTH_REFRESH_LOCK_NS}, ${credLockKey(cred.id)})`,
    );

    // Re-read under the lock: a concurrent winner may have already refreshed.
    const [fresh] = await tx
      .select({ sealed: schema.credentials.sealed })
      .from(schema.credentials)
      .where(eq(schema.credentials.id, cred.id))
      .limit(1);
    if (fresh) {
      try {
        const current = JSON.parse(
          open(dek, fresh.sealed as SealedBox, aad).toString('utf8'),
        ) as TokenSet;
        if (!needsRefresh(current)) return current.access_token;
        tokens = current;
      } catch {
        // Fall through to refresh with the tokens we already hold.
      }
    }

    let updated: TokenSet;
    try {
      updated = await refreshToken(provider, tokens);
    } catch {
      return null;
    }

    const reSealed = seal(dek, Buffer.from(JSON.stringify(updated), 'utf8'), aad);
    await tx
      .update(schema.credentials)
      .set({
        sealed: reSealed,
        metadata: {
          provider: provider.name,
          scope: updated.scope,
          tokenExpiresAt: updated.expires_at,
        },
      })
      .where(eq(schema.credentials.id, cred.id));
    return updated.access_token;
  });
}

/**
 * The agent reuse path: unseal a secret for use. Returns cleartext to the caller
 * only. Enforces per-credential policy (time window, max-uses, approval) before
 * unsealing. For require-approval creds, an approval request is materialized /
 * consumed via the approval workflow (needs the calling agent's id).
 */
export async function useCredential(
  passportId: string,
  credentialId: string,
  opts: { agentId?: string } = {},
): Promise<UseResult> {
  const [cred] = await db
    .select()
    .from(schema.credentials)
    .where(
      and(eq(schema.credentials.id, credentialId), eq(schema.credentials.passportId, passportId)),
    )
    .limit(1);
  if (!cred) return { status: 'not_found' };

  const now = Date.now();
  if (cred.expiresAt && cred.expiresAt.getTime() <= now) return { status: 'expired' };
  if (cred.allowedFrom && cred.allowedFrom.getTime() > now) return { status: 'not_yet_valid' };
  if (cred.allowedUntil && cred.allowedUntil.getTime() <= now) return { status: 'window_expired' };

  // Human-in-the-loop gate. Resolve approval BEFORE reserving a use so a pending
  // or denied attempt never consumes a maxUses slot. A live approval is consumed
  // here (single-use); on approval we fall through to unseal.
  if (cred.requireApproval) {
    const decision = await requestOrConsume(passportId, credentialId, opts.agentId!);
    if (decision.decision === 'pending')
      return { status: 'approval_pending', requestId: decision.requestId };
    if (decision.decision === 'denied') return { status: 'approval_denied' };
    // decision === 'approved' -> proceed.
  }

  // Reserve a use atomically so concurrent calls can't exceed maxUses.
  if (cred.maxUses !== null) {
    const reserved = await db
      .update(schema.credentials)
      .set({ useCount: sql`${schema.credentials.useCount} + 1` })
      .where(
        and(
          eq(schema.credentials.id, credentialId),
          eq(schema.credentials.passportId, passportId),
          sql`${schema.credentials.useCount} < ${schema.credentials.maxUses}`,
        ),
      )
      .returning({ useCount: schema.credentials.useCount });
    if (reserved.length === 0) return { status: 'use_limit' };
  } else {
    // Track usage for unlimited credentials too (best-effort).
    await db
      .update(schema.credentials)
      .set({ useCount: sql`${schema.credentials.useCount} + 1` })
      .where(eq(schema.credentials.id, credentialId));
  }

  const dek = await loadDek(passportId);
  if (!dek) return { status: 'not_found' };
  const aad = Buffer.from(`${passportId}:${cred.target}`);
  try {
    const plaintextBuf = open(dek, cred.sealed as SealedBox, aad);
    let secret = plaintextBuf.toString('utf8');
    plaintextBuf.fill(0); // scrub the decrypted buffer; the string is the caller's to use

    // oauth_token credentials seal a JSON token set, not a bare secret. Refresh
    // transparently near expiry and return only the (possibly new) access token.
    if (cred.type === 'oauth_token') {
      let tokens: TokenSet;
      try {
        tokens = JSON.parse(secret) as TokenSet;
      } catch {
        return { status: 'decrypt_error' };
      }
      const access = await freshOauthAccessToken(passportId, cred, tokens, dek, aad);
      if (access === null) return { status: 'refresh_failed' };
      secret = access;
    }

    return {
      status: 'ok',
      id: cred.id,
      target: cred.target,
      label: cred.label,
      type: cred.type,
      metadata: cred.metadata,
      expiresAt: cred.expiresAt,
      injection: (cred.injection ?? null) as Injection | null,
      secret,
    };
  } catch {
    // Tampering, wrong key, or corruption — never surface crypto internals.
    return { status: 'decrypt_error' };
  } finally {
    dek.fill(0);
    aad.fill(0); // scrub for consistency (AAD is non-secret)
  }
}
