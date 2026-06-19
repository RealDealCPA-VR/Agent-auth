import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';

// In derived mode (AUDIT_HMAC_SECRET unset) the audit-chain key comes from
// MASTER_KEY. Rotating MASTER_KEY must NOT break verification of rows signed under
// the old master: each master version signs under a distinct kid (a1~<MASTER_KEY_ID>)
// and the keyring derives an audit key from every retired MASTER_KEY. We reboot the
// audit/db modules with different env to simulate a rotation against the same DB.

const K1 = Buffer.alloc(32, 7).toString('base64');
const K2 = Buffer.alloc(32, 9).toString('base64');
const KEYS = [
  'MASTER_KEY',
  'MASTER_KEY_ID',
  'MASTER_KEYS_RETIRED',
  'AUDIT_HMAC_SECRET',
  'AUDIT_KEYS_RETIRED',
  'AUDIT_KEY_ID',
];
const saved: Record<string, string | undefined> = {};

beforeAll(() => {
  for (const k of KEYS) saved[k] = process.env[k];
});
afterAll(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

async function boot(env: Record<string, string | undefined>) {
  vi.resetModules();
  for (const k of KEYS) {
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  const dbMod = await import('../src/db/index.js');
  const auditMod = await import('../src/lib/audit.js');
  return { dbMod, auditMod };
}

const DERIVED = { AUDIT_HMAC_SECRET: undefined, AUDIT_KEYS_RETIRED: undefined, AUDIT_KEY_ID: 'a1' };

describe('audit chain survives MASTER_KEY rotation (derived mode)', () => {
  it('rows signed under the old master still verify after rotation; break only if it is not retired', async () => {
    // Boot 1: master k1, clean the table, write a couple of rows.
    const b1 = await boot({ MASTER_KEY: K1, MASTER_KEY_ID: 'k1', MASTER_KEYS_RETIRED: undefined, ...DERIVED });
    // audit_events has a BEFORE TRUNCATE append-only guard; disable it for the reset.
    await b1.dbMod.sql.unsafe('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate');
    await b1.dbMod.sql.unsafe('TRUNCATE audit_events RESTART IDENTITY CASCADE');
    await b1.dbMod.sql.unsafe('ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_truncate');
    await b1.auditMod.audit({ action: 'principal.register', success: true });
    await b1.auditMod.audit({ action: 'agent.issue', success: true });
    const rows = await b1.dbMod.sql.unsafe<{ n: number }[]>(
      'SELECT count(*)::int AS n FROM audit_events',
    );
    expect(Number(rows[0]?.n ?? 0)).toBeGreaterThanOrEqual(2);
    expect((await b1.auditMod.verifyAuditChain()).ok).toBe(true);

    // Boot 2: rotate to k2 with k1 RETIRED — old rows (kid a1~k1) must still verify.
    const b2 = await boot({
      MASTER_KEY: K2,
      MASTER_KEY_ID: 'k2',
      MASTER_KEYS_RETIRED: JSON.stringify({ k1: K1 }),
      ...DERIVED,
    });
    expect((await b2.auditMod.verifyAuditChain()).ok).toBe(true);

    // Boot 3: rotate to k2 but FORGET to retire k1 — verification now fails,
    // proving the retired-master derivation is what keeps the chain intact.
    const b3 = await boot({ MASTER_KEY: K2, MASTER_KEY_ID: 'k2', MASTER_KEYS_RETIRED: undefined, ...DERIVED });
    expect((await b3.auditMod.verifyAuditChain()).ok).toBe(false);
  });
});
