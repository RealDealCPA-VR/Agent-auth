import { and, eq, gt, inArray, isNull, desc } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { env } from '../env.js';

/**
 * Human approval workflow. A credential with requireApproval=true cannot be
 * unsealed by an agent until a human owner approves a request for that specific
 * (credential, agent) pair. Approvals are single-use and TTL-bounded.
 */

const TTL_MS = env.APPROVAL_TTL_SECONDS * 1000;

function ttlFromNow(now: number): Date {
  return new Date(now + TTL_MS);
}

export type RequestDecision =
  | { decision: 'approved' }
  | { decision: 'pending'; requestId: string }
  | { decision: 'denied' };

/**
 * Resolve the approval state for an agent's use attempt, materializing a request
 * when none is actionable. Looks at the most-recent non-expired request for the
 * (credential, agent) pair:
 *   - approved + unconsumed + live  -> atomically consume it and return approved
 *   - denied + live                 -> return denied
 *   - pending + live                -> return pending (its id)
 *   - otherwise                     -> create a fresh pending row, return pending
 *
 * Consumption is a guarded UPDATE so two concurrent uses can't spend the same
 * grant; the loser falls through to create a new pending request.
 */
export async function requestOrConsume(
  passportId: string,
  credentialId: string,
  agentId: string,
): Promise<RequestDecision> {
  const now = Date.now();
  const nowDate = new Date(now);

  // Read the candidate row and decide atomically: SELECT ... FOR UPDATE locks the
  // row so a concurrent approve()/deny() can't change its status between our read
  // and our decision (avoids returning stale 'pending' after a 'denied').
  return db.transaction(async (tx) => {
    const [latest] = await tx
      .select()
      .from(schema.approvalRequests)
      .where(
        and(
          eq(schema.approvalRequests.credentialId, credentialId),
          eq(schema.approvalRequests.agentId, agentId),
          gt(schema.approvalRequests.expiresAt, nowDate),
        ),
      )
      .orderBy(desc(schema.approvalRequests.createdAt))
      .limit(1)
      .for('update');

    if (latest) {
      if (latest.status === 'approved' && latest.consumedAt === null) {
        // Single-use: spend the grant. Guarded so a concurrent use can't double-spend.
        const consumed = await tx
          .update(schema.approvalRequests)
          .set({ consumedAt: nowDate })
          .where(
            and(
              eq(schema.approvalRequests.id, latest.id),
              isNull(schema.approvalRequests.consumedAt),
            ),
          )
          .returning({ id: schema.approvalRequests.id });
        if (consumed.length > 0) return { decision: 'approved' as const };
      } else if (latest.status === 'denied') {
        return { decision: 'denied' as const };
      } else if (latest.status === 'pending') {
        return { decision: 'pending' as const, requestId: latest.id };
      }
      // approved-but-already-consumed falls through to a fresh request.
    }

    const [created] = await tx
      .insert(schema.approvalRequests)
      .values({ passportId, credentialId, agentId, expiresAt: ttlFromNow(now) })
      .returning({ id: schema.approvalRequests.id });
    return { decision: 'pending' as const, requestId: created!.id };
  });
}

/** Pending, non-expired requests across the given (owned) passports. */
export function listPending(passportIds: string[]) {
  if (passportIds.length === 0) return Promise.resolve([]);
  return db
    .select({
      id: schema.approvalRequests.id,
      credentialId: schema.approvalRequests.credentialId,
      passportId: schema.approvalRequests.passportId,
      agentId: schema.approvalRequests.agentId,
      status: schema.approvalRequests.status,
      createdAt: schema.approvalRequests.createdAt,
      expiresAt: schema.approvalRequests.expiresAt,
    })
    .from(schema.approvalRequests)
    .where(
      and(
        inArray(schema.approvalRequests.passportId, passportIds),
        eq(schema.approvalRequests.status, 'pending'),
        gt(schema.approvalRequests.expiresAt, new Date()),
      ),
    )
    .orderBy(desc(schema.approvalRequests.createdAt));
}

/**
 * Approve a pending request the caller owns. Verifies ownership via a passport
 * join in the WHERE so a non-owner gets a no-op (returns null -> route 404).
 * Only acts on status='pending'. Approval refreshes the grant's TTL so the
 * window starts at the moment of approval.
 */
const decisionFields = {
  id: schema.approvalRequests.id,
  credentialId: schema.approvalRequests.credentialId,
  agentId: schema.approvalRequests.agentId,
  passportId: schema.approvalRequests.passportId,
  status: schema.approvalRequests.status,
  createdAt: schema.approvalRequests.createdAt,
  decidedAt: schema.approvalRequests.decidedAt,
  expiresAt: schema.approvalRequests.expiresAt,
} as const;

export type ApprovalRequestRow = {
  id: string;
  credentialId: string;
  agentId: string;
  passportId: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: Date;
  decidedAt: Date | null;
  expiresAt: Date;
};

export async function approve(
  requestId: string,
  principalId: string,
): Promise<ApprovalRequestRow | null> {
  const now = Date.now();
  const owned = db
    .select({ id: schema.passports.id })
    .from(schema.passports)
    .where(eq(schema.passports.principalId, principalId));

  const updated = await db
    .update(schema.approvalRequests)
    .set({
      status: 'approved',
      decidedAt: new Date(now),
      decidedBy: principalId,
      expiresAt: ttlFromNow(now),
    })
    .where(
      and(
        eq(schema.approvalRequests.id, requestId),
        eq(schema.approvalRequests.status, 'pending'),
        inArray(schema.approvalRequests.passportId, owned),
      ),
    )
    .returning(decisionFields);
  return updated[0] ?? null;
}

/** Deny a pending request the caller owns (same ownership/status guards). */
export async function deny(
  requestId: string,
  principalId: string,
): Promise<ApprovalRequestRow | null> {
  const owned = db
    .select({ id: schema.passports.id })
    .from(schema.passports)
    .where(eq(schema.passports.principalId, principalId));

  const now = Date.now();
  const updated = await db
    .update(schema.approvalRequests)
    // Refresh TTL from the decision (like approve) so a denial sticks for the
    // full window instead of expiring at the original request's creation TTL.
    .set({ status: 'denied', decidedAt: new Date(now), decidedBy: principalId, expiresAt: ttlFromNow(now) })
    .where(
      and(
        eq(schema.approvalRequests.id, requestId),
        eq(schema.approvalRequests.status, 'pending'),
        inArray(schema.approvalRequests.passportId, owned),
      ),
    )
    .returning(decisionFields);
  return updated[0] ?? null;
}
