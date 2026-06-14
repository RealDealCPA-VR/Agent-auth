import { and, eq, sql } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { generateDek, seal, open, type SealedBox, type WrappedKey } from '../crypto/envelope.js';
import { wrapDek, unwrapDek } from '../crypto/keyprovider/index.js';

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
      id: string;
    }
  | { status: 'not_found' }
  | { status: 'expired' }
  | { status: 'not_yet_valid' }
  | { status: 'window_expired' }
  | { status: 'use_limit' }
  | { status: 'approval_required' }
  | { status: 'decrypt_error' };

/**
 * The agent reuse path: unseal a secret for use. Returns cleartext to the caller
 * only. Enforces per-credential policy (time window, max-uses, approval) before
 * unsealing. `approved` is set by the approval workflow for require-approval creds.
 */
export async function useCredential(
  passportId: string,
  credentialId: string,
  opts: { approved?: boolean } = {},
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
  if (cred.requireApproval && !opts.approved) return { status: 'approval_required' };

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
    const secret = plaintextBuf.toString('utf8');
    plaintextBuf.fill(0); // scrub the decrypted buffer; the string is the caller's to use
    return {
      status: 'ok',
      id: cred.id,
      target: cred.target,
      label: cred.label,
      type: cred.type,
      metadata: cred.metadata,
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
