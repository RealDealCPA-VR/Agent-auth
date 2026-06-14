import { createHmac, timingSafeEqual } from 'node:crypto';
import { sql, desc } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { env } from '../env.js';

type Action = (typeof schema.auditAction.enumValues)[number];

export interface AuditInput {
  action: Action;
  success: boolean;
  principalId?: string | null;
  passportId?: string | null;
  agentId?: string | null;
  credentialId?: string | null;
  detail?: Record<string, unknown>;
  ip?: string | null;
}

// A transaction-like executor: either the root db or a tx handle.
type Executor = Pick<typeof db, 'select' | 'insert' | 'execute'>;

// Audit HMAC keyring (supports rotation). The active key is AUDIT_HMAC_SECRET, or
// — for back-compat — derived from MASTER_KEY. Retired keys verify older rows.
function deriveActiveAuditKey(): Buffer {
  if (env.AUDIT_HMAC_SECRET) return Buffer.from(env.AUDIT_HMAC_SECRET, 'base64');
  return createHmac('sha256', Buffer.from(env.MASTER_KEY, 'base64'))
    .update('agentauth-audit-chain-v1')
    .digest();
}

const AUDIT_KEY_ID = env.AUDIT_KEY_ID;
const auditKeys = new Map<string, Buffer>();
auditKeys.set(AUDIT_KEY_ID, deriveActiveAuditKey());
if (env.AUDIT_KEYS_RETIRED) {
  const retired = JSON.parse(env.AUDIT_KEYS_RETIRED) as Record<string, string>;
  for (const [kid, b64] of Object.entries(retired)) {
    if (!auditKeys.has(kid)) auditKeys.set(kid, Buffer.from(b64, 'base64'));
  }
}
const AUDIT_KEY = auditKeys.get(AUDIT_KEY_ID)!;

// Serializes audit appends so the hash chain stays linear under concurrency.
const AUDIT_LOCK = 4242421;

/**
 * Deterministic serializer with recursively sorted object keys. Required because
 * Postgres `jsonb` does not preserve key order, so a plain JSON.stringify would
 * hash differently at insert vs verify time for multi-key `detail` objects.
 */
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

/** Canonical, order-stable representation of the chained fields. */
function canonical(i: AuditInput, createdAtIso: string, prevHash: string | null): string {
  return stableStringify([
    i.action,
    i.principalId ?? null,
    i.passportId ?? null,
    i.agentId ?? null,
    i.credentialId ?? null,
    i.success,
    i.detail ?? {},
    i.ip ?? null,
    createdAtIso,
    prevHash ?? '',
  ]);
}

function chainHash(payload: string, key: Buffer): string {
  return createHmac('sha256', key).update(payload).digest('hex');
}

async function appendWith(exec: Executor, input: AuditInput): Promise<void> {
  // Serialize appends within this transaction so prevHash is read consistently.
  await exec.execute(sql`select pg_advisory_xact_lock(${AUDIT_LOCK})`);
  const [last] = await exec
    .select({ hash: schema.auditEvents.hash })
    .from(schema.auditEvents)
    .orderBy(desc(schema.auditEvents.seq))
    .limit(1);
  const prevHash = last?.hash ?? null;
  const createdAt = new Date();
  const hash = chainHash(canonical(input, createdAt.toISOString(), prevHash), AUDIT_KEY);

  await exec.insert(schema.auditEvents).values({
    action: input.action,
    success: input.success,
    principalId: input.principalId ?? null,
    passportId: input.passportId ?? null,
    agentId: input.agentId ?? null,
    credentialId: input.credentialId ?? null,
    detail: input.detail ?? {},
    ip: input.ip ?? null,
    prevHash,
    hash,
    hashKeyId: AUDIT_KEY_ID,
    createdAt,
  });
}

/**
 * Append an audit event to the tamper-evident chain.
 *
 * Best-effort when called standalone: auditing must never throw into the
 * request path, but failures are surfaced to the logger so they're not silent.
 * Pass `exec` (a transaction) to make the audit write atomic with another
 * mutation — there the caller owns error handling.
 *
 * `detail` must contain non-secret context only.
 */
export async function audit(input: AuditInput, exec?: Executor): Promise<void> {
  if (exec) {
    await appendWith(exec, input);
    return;
  }
  try {
    await db.transaction((tx) => appendWith(tx, input));
  } catch (err) {
    console.error(`[audit] failed to record ${input.action}:`, (err as Error)?.message);
  }
}

export interface ChainVerification {
  ok: boolean;
  count: number;
  brokenAtSeq: number | null;
}

/**
 * Recompute the hash chain over all audit rows in `seq` order and confirm each
 * row's stored hash matches and links to its predecessor. Detects any insert,
 * update, delete, or reordering.
 */
export async function verifyAuditChain(): Promise<ChainVerification> {
  const rows = await db.select().from(schema.auditEvents).orderBy(schema.auditEvents.seq);

  let prevHash: string | null = null;
  for (const r of rows) {
    const key = auditKeys.get(r.hashKeyId);
    if (!key) return { ok: false, count: rows.length, brokenAtSeq: r.seq };
    const expected = chainHash(
      canonical(
        {
          action: r.action,
          success: r.success,
          principalId: r.principalId,
          passportId: r.passportId,
          agentId: r.agentId,
          credentialId: r.credentialId,
          detail: r.detail as Record<string, unknown>,
          ip: r.ip,
        },
        new Date(r.createdAt).toISOString(),
        prevHash,
      ),
      key,
    );
    const a = Buffer.from(expected);
    const b = Buffer.from(r.hash);
    if (r.prevHash !== prevHash || a.length !== b.length || !timingSafeEqual(a, b)) {
      return { ok: false, count: rows.length, brokenAtSeq: r.seq };
    }
    prevHash = r.hash;
  }
  return { ok: true, count: rows.length, brokenAtSeq: null };
}
