import { eq } from 'drizzle-orm';
import { db, schema, closeDb } from './index.js';
import { rotateWrappedDek, activeKeyId, type WrappedKey } from '../crypto/envelope.js';

/**
 * Key rotation: re-wrap every passport's data key under the current active KEK
 * (MASTER_KEY / MASTER_KEY_ID), leaving retired keys configured in
 * MASTER_KEYS_RETIRED only long enough to unwrap the old DEKs. Idempotent — a
 * passport already on the active key is skipped.
 *
 * This rotates the KEK, not the DEK: the unwrapped DEK bytes are identical
 * before and after, so credentials sealed with that DEK stay decryptable and a
 * deposit running concurrently with rotation cannot be corrupted (it seals with
 * the same DEK regardless of which KEK currently wraps it).
 *
 * Run after deploying a new KEK:
 *
 *   MASTER_KEY=<new> MASTER_KEY_ID=k2 MASTER_KEYS_RETIRED='{"k1":"<old>"}' pnpm db:rotate
 */
async function main(): Promise<void> {
  const passports = await db
    .select({ id: schema.passports.id, wrappedDek: schema.passports.wrappedDek })
    .from(schema.passports);

  let rotated = 0;
  for (const p of passports) {
    const next = rotateWrappedDek(p.wrappedDek as WrappedKey);
    if (next) {
      await db
        .update(schema.passports)
        .set({ wrappedDek: next })
        .where(eq(schema.passports.id, p.id));
      rotated += 1;
    }
  }
  console.warn(
    `rotated ${rotated}/${passports.length} passport keys to active KEK "${activeKeyId}"`,
  );
  await closeDb();
}

main().catch((err) => {
  console.error('key rotation failed:', (err as Error)?.message ?? 'unknown error');
  process.exit(1);
});
