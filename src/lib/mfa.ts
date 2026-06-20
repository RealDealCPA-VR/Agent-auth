import { and, count, desc, eq, gt, or, sql } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import type { SealedBox } from '../crypto/envelope.js';
import { sealForPassport, openForPassport } from './vault.js';

/**
 * MFA handoff: the bridge between a browser-login MFA challenge detected by the
 * SDK and a human who can resolve it. Flow:
 *   1. agent (SDK) → createMfaRequest()  — a pending, TTL-bounded request
 *   2. human owner  → approveMfaRequest() — seals the one-time code at rest
 *   3. agent (SDK) → fetchMfaCode()       — gets the code ONCE, then consumed
 * The code is stored ONLY sealed (passport DEK, AAD bound to the challenge) and
 * is NEVER logged. Fail-closed: consumed/expired/denied/revoked → no code.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MFA_KINDS = new Set(['otp', 'totp', 'sms', 'email', 'push', 'webauthn']);

/** Approval TTL and per-(credential,agent) rate limits. Exported for tests. */
export const MFA_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const MFA_MAX_PENDING = 5; // concurrent pending requests
export const MFA_MAX_PER_HOUR = 20; // created per rolling hour

/** AAD for the sealed one-time code. Bound to the IMMUTABLE, server-issued unique
 * row id (and passport) — NOT the agent-supplied, non-unique challengeId — so the
 * sealed blob cannot be substituted between rows that happen to share a challengeId. */
function aadFor(passportId: string, rowId: string): Buffer {
  return Buffer.from(`mfa:${passportId}:${rowId}`);
}

export type CreateMfaResult =
  | { ok: true; requestId: string }
  | { ok: false; reason: 'not_found' | 'rate_limited' | 'bad_kind' };

/**
 * Create a pending MFA request bound to a credential + agent + the passport's
 * owning principal, with a TTL. Enforces per-(credential,agent) rate limits to
 * stop a runaway agent from spamming the approver. Stores only non-secret hints.
 */
export async function createMfaRequest(args: {
  passportId: string;
  credentialId: string;
  agentId: string;
  challengeId: string;
  kind: string;
  channelHint?: string | null;
  promptText?: string | null;
}): Promise<CreateMfaResult> {
  if (!MFA_KINDS.has(args.kind)) return { ok: false, reason: 'bad_kind' };

  const [p] = await db
    .select({ principalId: schema.passports.principalId })
    .from(schema.passports)
    .where(eq(schema.passports.id, args.passportId))
    .limit(1);
  if (!p) return { ok: false, reason: 'not_found' };

  const now = Date.now();
  const scope = and(
    eq(schema.mfaRequests.agentId, args.agentId),
    eq(schema.mfaRequests.credentialId, args.credentialId),
  );

  const pending = (
    await db
      .select({ value: count() })
      .from(schema.mfaRequests)
      .where(
        and(
          scope,
          eq(schema.mfaRequests.status, 'pending'),
          gt(schema.mfaRequests.expiresAt, new Date(now)),
        ),
      )
  )[0]!.value;
  if (pending >= MFA_MAX_PENDING) return { ok: false, reason: 'rate_limited' };

  const recent = (
    await db
      .select({ value: count() })
      .from(schema.mfaRequests)
      .where(and(scope, gt(schema.mfaRequests.createdAt, new Date(now - 3600_000))))
  )[0]!.value;
  if (recent >= MFA_MAX_PER_HOUR) return { ok: false, reason: 'rate_limited' };

  const [row] = await db
    .insert(schema.mfaRequests)
    .values({
      challengeId: args.challengeId,
      credentialId: args.credentialId,
      passportId: args.passportId,
      agentId: args.agentId,
      principalId: p.principalId,
      kind: args.kind,
      channelHint: args.channelHint ?? null,
      promptText: args.promptText ?? null,
      expiresAt: new Date(now + MFA_TTL_MS),
    })
    .returning({ id: schema.mfaRequests.id });
  return { ok: true, requestId: row!.id };
}

export type FetchMfaResult =
  | { status: 'pending' }
  | { status: 'approved'; code: string | null; by: string | null; at: string | null }
  | { status: 'denied' }
  | { status: 'revoked' }
  | { status: 'gone' } // already consumed
  | { status: 'expired'; first: boolean } // `first` true only on the pending/approved->expired transition
  | { status: 'not_found' };

/**
 * Agent-side: fetch the resolution of an MFA request. On 'approved' the sealed
 * code is unsealed and returned EXACTLY ONCE (the row flips to consumed atomically);
 * a later fetch is 'gone'. Expired rows flip to 'expired' lazily. The approver's
 * email is returned as `by` for the non-secret summary.
 */
export async function fetchMfaCode(
  passportId: string,
  credentialId: string,
  agentId: string,
  requestId: string,
): Promise<FetchMfaResult> {
  if (!UUID_RE.test(requestId)) return { status: 'not_found' };
  const [row] = await db
    .select()
    .from(schema.mfaRequests)
    .where(
      and(
        eq(schema.mfaRequests.id, requestId),
        eq(schema.mfaRequests.passportId, passportId),
        eq(schema.mfaRequests.credentialId, credentialId),
        eq(schema.mfaRequests.agentId, agentId),
      ),
    )
    .limit(1);
  if (!row) return { status: 'not_found' };

  if (row.status === 'consumed') return { status: 'gone' };
  if (row.status === 'denied') return { status: 'denied' };
  if (row.status === 'revoked') return { status: 'revoked' };
  if (row.expiresAt.getTime() <= Date.now()) {
    // Flip a still-live (pending/approved) row to expired exactly once. `first`
    // reflects whether THIS poll performed the transition, so the route audits
    // mfa.expired only on the transition — not on every subsequent poll (which
    // would let an agent amplify rows into the append-only audit chain).
    let first = false;
    if (row.status === 'pending' || row.status === 'approved') {
      const flipped = await db
        .update(schema.mfaRequests)
        .set({ status: 'expired' })
        .where(
          and(
            eq(schema.mfaRequests.id, row.id),
            or(eq(schema.mfaRequests.status, 'pending'), eq(schema.mfaRequests.status, 'approved')),
          ),
        )
        .returning({ id: schema.mfaRequests.id });
      first = flipped.length > 0;
    }
    return { status: 'expired', first };
  }
  if (row.status === 'pending') return { status: 'pending' };

  // status === 'approved': consume single-use (atomic guard against a race), then
  // unseal the code if one was provided (push/webauthn approvals carry no code).
  const consumed = await db
    .update(schema.mfaRequests)
    .set({ status: 'consumed', consumedAt: new Date() })
    .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'approved')))
    .returning({ id: schema.mfaRequests.id });
  if (consumed.length === 0) return { status: 'gone' };

  let code: string | null = null;
  if (row.sealedCode) {
    const buf = await openForPassport(passportId, row.sealedCode as SealedBox, aadFor(row.passportId, row.id));
    if (buf) {
      code = buf.toString('utf8');
      buf.fill(0);
    }
  }
  let by: string | null = null;
  if (row.decidedBy) {
    const [pr] = await db
      .select({ email: schema.principals.email })
      .from(schema.principals)
      .where(eq(schema.principals.id, row.decidedBy))
      .limit(1);
    by = pr?.email ?? null;
  }
  return { status: 'approved', code, by, at: row.decidedAt?.toISOString() ?? null };
}

/** True if `principalId` may approve `row`: the passport owner, or the credential's
 * configured `metadata.delegateApproverId`. */
async function mayApprove(
  row: { principalId: string; credentialId: string },
  principalId: string,
): Promise<boolean> {
  if (row.principalId === principalId) return true;
  const [cred] = await db
    .select({ metadata: schema.credentials.metadata })
    .from(schema.credentials)
    .where(eq(schema.credentials.id, row.credentialId))
    .limit(1);
  const delegate = (cred?.metadata as Record<string, unknown> | undefined)?.delegateApproverId;
  return typeof delegate === 'string' && delegate === principalId;
}

export type DecideMfaResult =
  | { ok: true; row: typeof schema.mfaRequests.$inferSelect }
  | { ok: false; reason: 'not_found' | 'forbidden' | 'not_pending' };

/**
 * Human-side: approve a pending MFA request, sealing the one-time `code` (if any)
 * at rest under the passport DEK. Owner-or-delegate only; an out-of-scope caller
 * gets `forbidden` (the route maps it to 404 so existence isn't leaked).
 */
export async function approveMfaRequest(
  principalId: string,
  requestId: string,
  code?: string | null,
): Promise<DecideMfaResult> {
  if (!UUID_RE.test(requestId)) return { ok: false, reason: 'not_found' };
  const [row] = await db
    .select()
    .from(schema.mfaRequests)
    .where(eq(schema.mfaRequests.id, requestId))
    .limit(1);
  if (!row) return { ok: false, reason: 'not_found' };
  if (!(await mayApprove(row, principalId))) return { ok: false, reason: 'forbidden' };
  if (row.status !== 'pending' || row.expiresAt.getTime() <= Date.now())
    return { ok: false, reason: 'not_pending' };

  let sealedCode: SealedBox | null = null;
  if (typeof code === 'string' && code.length > 0) {
    const codeBuf = Buffer.from(code, 'utf8');
    try {
      sealedCode = await sealForPassport(row.passportId, codeBuf, aadFor(row.passportId, row.id));
    } finally {
      codeBuf.fill(0);
    }
  }

  const [updated] = await db
    .update(schema.mfaRequests)
    .set({ status: 'approved', sealedCode, decidedAt: new Date(), decidedBy: principalId })
    .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'pending')))
    .returning();
  if (!updated) return { ok: false, reason: 'not_pending' };
  return { ok: true, row: updated };
}

/** Human-side: deny a pending MFA request. Owner-or-delegate only. */
export async function denyMfaRequest(principalId: string, requestId: string): Promise<DecideMfaResult> {
  if (!UUID_RE.test(requestId)) return { ok: false, reason: 'not_found' };
  const [row] = await db
    .select()
    .from(schema.mfaRequests)
    .where(eq(schema.mfaRequests.id, requestId))
    .limit(1);
  if (!row) return { ok: false, reason: 'not_found' };
  if (!(await mayApprove(row, principalId))) return { ok: false, reason: 'forbidden' };
  if (row.status !== 'pending') return { ok: false, reason: 'not_pending' };
  const [updated] = await db
    .update(schema.mfaRequests)
    .set({ status: 'denied', decidedAt: new Date(), decidedBy: principalId })
    .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'pending')))
    .returning();
  if (!updated) return { ok: false, reason: 'not_pending' };
  return { ok: true, row: updated };
}

/** List pending, non-expired MFA requests this principal may resolve (owner or a
 * credential delegate). For the admin MFA queue. */
export async function listPendingMfaFor(
  principalId: string,
  opts: { limit: number; offset: number },
): Promise<{ items: typeof schema.mfaRequests.$inferSelect[]; total: number }> {
  const where = and(
    eq(schema.mfaRequests.status, 'pending'),
    gt(schema.mfaRequests.expiresAt, new Date()),
    or(
      eq(schema.mfaRequests.principalId, principalId),
      sql`${schema.mfaRequests.credentialId} IN (SELECT id FROM credentials WHERE metadata->>'delegateApproverId' = ${principalId})`,
    ),
  );
  const items = await db
    .select()
    .from(schema.mfaRequests)
    .where(where)
    .orderBy(desc(schema.mfaRequests.createdAt))
    .limit(opts.limit)
    .offset(opts.offset);
  const total = (await db.select({ value: count() }).from(schema.mfaRequests).where(where))[0]!.value;
  return { items, total };
}

/**
 * Cancel all pending MFA requests for an agent (called on agent revocation —
 * fail-closed). Returns the cancelled rows so the caller can audit each one.
 */
export async function revokePendingMfaForAgent(
  agentId: string,
): Promise<typeof schema.mfaRequests.$inferSelect[]> {
  return db
    .update(schema.mfaRequests)
    .set({ status: 'revoked', decidedAt: new Date() })
    .where(and(eq(schema.mfaRequests.agentId, agentId), eq(schema.mfaRequests.status, 'pending')))
    .returning();
}
