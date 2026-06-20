import { and, count, desc, eq, gt, or, sql } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import type { SealedBox } from '../crypto/envelope.js';
import { sealForPassport, openForPassport } from './vault.js';
import { audit } from './audit.js';

/**
 * MFA handoff: the bridge between a browser-login MFA challenge detected by the
 * SDK and a human who can resolve it. Flow:
 *   1. agent (SDK) → createMfaRequest()  — a pending, TTL-bounded request
 *   2. human owner  → approveMfaRequest() — seals the one-time code at rest
 *   3. agent (SDK) → fetchMfaCode()       — gets the code ONCE, then consumed
 * The code is stored ONLY sealed (passport DEK, AAD bound to the immutable request
 * id) and is NEVER logged. Fail-closed: consumed/expired/denied/revoked → no code.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MFA_KINDS = new Set(['otp', 'totp', 'sms', 'email', 'push', 'webauthn']);

/** Approval TTL and per-(credential,agent) rate limits. Exported for tests. */
export const MFA_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const MFA_MAX_PENDING = 5; // concurrent pending requests
export const MFA_MAX_PER_HOUR = 20; // created per rolling hour

// Advisory-lock namespace for serializing MFA-request creation per (credential,
// agent) so the count-then-insert rate-limit check is race-free. Distinct from
// the audit (4242421) and oauth-refresh (4242422) namespaces so they never contend.
const MFA_LOCK_NS = 4242423;

/** Hash (credentialId, agentId) into the 32-bit advisory-lock key space. */
function mfaLockKey(credentialId: string, agentId: string): number {
  let h = 0;
  const s = `${credentialId}:${agentId}`;
  for (let i = 0; i < s.length; i += 1) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return h;
}

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
  target?: string;
  ip?: string;
}): Promise<CreateMfaResult> {
  if (!MFA_KINDS.has(args.kind)) return { ok: false, reason: 'bad_kind' };

  const [p] = await db
    .select({ principalId: schema.passports.principalId })
    .from(schema.passports)
    .where(eq(schema.passports.id, args.passportId))
    .limit(1);
  if (!p) return { ok: false, reason: 'not_found' };

  const scope = and(
    eq(schema.mfaRequests.agentId, args.agentId),
    eq(schema.mfaRequests.credentialId, args.credentialId),
  );

  // Serialize the count-then-insert per (credential,agent) with a transaction-scoped
  // advisory lock, so N concurrent requests can't all pass the check before any
  // insert commits (the limit holds under concurrency).
  return db.transaction(async (tx): Promise<CreateMfaResult> => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(${MFA_LOCK_NS}, ${mfaLockKey(args.credentialId, args.agentId)})`,
    );
    const now = Date.now();

    const pending = (
      await tx
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
      await tx
        .select({ value: count() })
        .from(schema.mfaRequests)
        .where(and(scope, gt(schema.mfaRequests.createdAt, new Date(now - 3600_000))))
    )[0]!.value;
    if (recent >= MFA_MAX_PER_HOUR) return { ok: false, reason: 'rate_limited' };

    const [row] = await tx
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
    // Audit the request in the SAME transaction as the insert (chained-or-rolled-back).
    await audit(
      {
        action: 'mfa.requested',
        success: true,
        agentId: args.agentId,
        passportId: args.passportId,
        credentialId: args.credentialId,
        detail: { requestId: row!.id, challengeId: args.challengeId, kind: args.kind, target: args.target },
        ip: args.ip,
      },
      tx,
    );
    return { ok: true, requestId: row!.id };
  });
}

export type FetchMfaResult =
  | { status: 'pending' }
  | { status: 'approved'; code: string | null; by: string | null; at: string | null }
  | { status: 'denied' }
  | { status: 'revoked' }
  | { status: 'gone' } // already consumed
  | { status: 'expired' }
  | { status: 'not_found' };

/**
 * Agent-side: fetch the resolution of an MFA request. On 'approved' the sealed
 * code is unsealed and returned EXACTLY ONCE (the row flips to consumed atomically);
 * a later fetch is 'gone'. Expired rows flip to 'expired' lazily.
 *
 * The lifecycle audits (mfa.consumed on a secret release, mfa.expired on the
 * once-only expiry transition) are appended INSIDE the same transaction as the
 * state mutation: a one-time code is only delivered if its mfa.consumed row is
 * durably chained — an audit-write failure rolls the consume back and the code is
 * withheld (fail-closed), rather than releasing a secret with no audit record.
 */
export async function fetchMfaCode(
  passportId: string,
  credentialId: string,
  agentId: string,
  requestId: string,
  opts: { ip?: string } = {},
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
    // Flip a still-live (pending/approved) row to expired exactly once, auditing the
    // transition in the SAME transaction so the once-only mfa.expired event is
    // chained-or-rolled-back (a later poll then retries). Subsequent polls of an
    // already-expired row perform no flip and no audit (no amplification).
    if (row.status === 'pending' || row.status === 'approved') {
      await db.transaction(async (tx) => {
        const flipped = await tx
          .update(schema.mfaRequests)
          .set({ status: 'expired' })
          .where(
            and(
              eq(schema.mfaRequests.id, row.id),
              or(eq(schema.mfaRequests.status, 'pending'), eq(schema.mfaRequests.status, 'approved')),
            ),
          )
          .returning({ id: schema.mfaRequests.id });
        if (flipped.length > 0) {
          await audit(
            {
              action: 'mfa.expired',
              success: false,
              agentId,
              passportId,
              credentialId,
              detail: { requestId },
              ip: opts.ip,
            },
            tx,
          );
        }
      });
    }
    return { status: 'expired' };
  }
  if (row.status === 'pending') return { status: 'pending' };

  // status === 'approved'. UNSEAL FIRST so a transient unseal failure (KMS down,
  // KEK rotation, tamper) does NOT permanently burn the one-time row: we only flip
  // it to 'consumed' once a code is actually in hand. A failure leaves the row
  // 'approved' and reports 'pending' so a retry (or recovery) can still succeed.
  let code: string | null = null;
  if (row.sealedCode) {
    let buf: Buffer | null = null;
    try {
      buf = await openForPassport(passportId, row.sealedCode as SealedBox, aadFor(row.passportId, row.id));
    } catch {
      buf = null;
    }
    if (!buf) return { status: 'pending' }; // approved but not retrievable yet — do NOT consume
    code = buf.toString('utf8');
    buf.fill(0);
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

  // Consume single-use AND append mfa.consumed in ONE transaction: the secret is
  // delivered only if its audit row is durably chained. A concurrent poll loses the
  // status='approved' guard (-> 'gone'); an audit-write failure rolls the consume
  // back (row stays 'approved') so the code is withheld rather than released unlogged.
  const delivered = await db.transaction(async (tx): Promise<boolean> => {
    const consumed = await tx
      .update(schema.mfaRequests)
      .set({ status: 'consumed', consumedAt: new Date() })
      .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'approved')))
      .returning({ id: schema.mfaRequests.id });
    if (consumed.length === 0) return false; // a concurrent poll already consumed it
    await audit(
      {
        action: 'mfa.consumed',
        success: true,
        agentId,
        passportId,
        credentialId,
        detail: { requestId, by },
        ip: opts.ip,
      },
      tx,
    );
    return true;
  });
  if (!delivered) return { status: 'gone' };

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
  | { ok: false; reason: 'not_found' | 'forbidden' | 'not_pending' | 'code_required' | 'seal_failed' };

/** Kinds that REQUIRE a one-time code at approval (vs push/webauthn which don't). */
const CODE_KINDS = new Set(['otp', 'totp', 'sms', 'email']);

/**
 * Human-side: approve a pending MFA request, sealing the one-time `code` (if any)
 * at rest under the passport DEK. Owner-or-delegate only; an out-of-scope caller
 * gets `forbidden` (the route maps it to 404 so existence isn't leaked).
 */
export async function approveMfaRequest(
  principalId: string,
  requestId: string,
  code?: string | null,
  opts: { ip?: string } = {},
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
  // A code-kind challenge cannot be approved without a code — otherwise the agent
  // would get an empty 'approved' and the login form would never advance.
  if (CODE_KINDS.has(row.kind) && !(typeof code === 'string' && code.length > 0))
    return { ok: false, reason: 'code_required' };

  let sealedCode: SealedBox | null = null;
  if (typeof code === 'string' && code.length > 0) {
    const codeBuf = Buffer.from(code, 'utf8');
    try {
      sealedCode = await sealForPassport(row.passportId, codeBuf, aadFor(row.passportId, row.id));
    } finally {
      codeBuf.fill(0);
    }
  }
  // Fail closed: never commit a code-kind 'approved' with no sealed code (a
  // transient DEK-load failure at seal time would otherwise yield a silent
  // empty approval and burn the one-time row at fetch).
  if (CODE_KINDS.has(row.kind) && sealedCode === null) return { ok: false, reason: 'seal_failed' };

  // Decision + audit commit together: an audit-write failure rolls the approval back.
  return db.transaction(async (tx): Promise<DecideMfaResult> => {
    const [updated] = await tx
      .update(schema.mfaRequests)
      .set({ status: 'approved', sealedCode, decidedAt: new Date(), decidedBy: principalId })
      .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'pending')))
      .returning();
    if (!updated) return { ok: false, reason: 'not_pending' };
    await audit(
      {
        action: 'mfa.approved',
        success: true,
        principalId,
        passportId: updated.passportId,
        credentialId: updated.credentialId,
        agentId: updated.agentId,
        detail: { requestId, challengeId: updated.challengeId, kind: updated.kind },
        ip: opts.ip,
      },
      tx,
    );
    return { ok: true, row: updated };
  });
}

/** Human-side: deny a pending MFA request. Owner-or-delegate only. */
export async function denyMfaRequest(
  principalId: string,
  requestId: string,
  opts: { ip?: string } = {},
): Promise<DecideMfaResult> {
  if (!UUID_RE.test(requestId)) return { ok: false, reason: 'not_found' };
  const [row] = await db
    .select()
    .from(schema.mfaRequests)
    .where(eq(schema.mfaRequests.id, requestId))
    .limit(1);
  if (!row) return { ok: false, reason: 'not_found' };
  if (!(await mayApprove(row, principalId))) return { ok: false, reason: 'forbidden' };
  if (row.status !== 'pending') return { ok: false, reason: 'not_pending' };
  return db.transaction(async (tx): Promise<DecideMfaResult> => {
    const [updated] = await tx
      .update(schema.mfaRequests)
      .set({ status: 'denied', decidedAt: new Date(), decidedBy: principalId })
      .where(and(eq(schema.mfaRequests.id, row.id), eq(schema.mfaRequests.status, 'pending')))
      .returning();
    if (!updated) return { ok: false, reason: 'not_pending' };
    await audit(
      {
        action: 'mfa.denied',
        success: true,
        principalId,
        passportId: updated.passportId,
        credentialId: updated.credentialId,
        agentId: updated.agentId,
        detail: { requestId, challengeId: updated.challengeId },
        ip: opts.ip,
      },
      tx,
    );
    return { ok: true, row: updated };
  });
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
 * Cancel an agent's open MFA requests on revocation — fail-closed. Cancels BOTH
 * pending AND already-approved-but-unfetched rows, so a sealed-but-unconsumed code
 * is zeroed at revoke time (the MFA layer is fail-closed independent of the auth
 * check, which also already rejects the revoked agent). Returns the cancelled rows
 * so the caller can audit. Pass `exec` (the revoke transaction) for atomicity.
 */
export async function revokePendingMfaForAgent(
  agentId: string,
  exec: Pick<typeof db, 'update'> = db,
): Promise<typeof schema.mfaRequests.$inferSelect[]> {
  return exec
    .update(schema.mfaRequests)
    .set({ status: 'revoked', sealedCode: null, decidedAt: new Date() })
    .where(
      and(
        eq(schema.mfaRequests.agentId, agentId),
        or(eq(schema.mfaRequests.status, 'pending'), eq(schema.mfaRequests.status, 'approved')),
      ),
    )
    .returning();
}
