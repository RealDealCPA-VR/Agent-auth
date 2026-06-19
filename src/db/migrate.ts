import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { env } from '../env.js';
import { resolveSsl } from './ssl.js';

/**
 * Apply generated SQL migrations from ./drizzle, then install database-level
 * guards that the ORM cannot express. Idempotent. Run after `pnpm db:generate`.
 */
async function main(): Promise<void> {
  const client = postgres(env.DATABASE_URL, { max: 1, ssl: resolveSsl() });
  const db = drizzle(client);

  await migrate(db, { migrationsFolder: './drizzle' });

  // Enforce append-only on the audit log at the database level: block UPDATE,
  // DELETE, and TRUNCATE on the normal SQL path. Row-level triggers do NOT fire on
  // TRUNCATE, so a separate statement-level BEFORE TRUNCATE trigger is required to
  // stop a one-shot history wipe. NB: this is preventive only against a role that
  // cannot disable triggers — the table OWNER/superuser can `DISABLE TRIGGER`, so
  // in production run the runtime under a least-privilege, non-owner role (the HMAC
  // hash chain remains the detective backstop). See SECURITY.md.
  await client.unsafe(`
    CREATE OR REPLACE FUNCTION agentauth_audit_append_only()
    RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS audit_events_no_mutate ON audit_events;
    CREATE TRIGGER audit_events_no_mutate
      BEFORE UPDATE OR DELETE ON audit_events
      FOR EACH ROW EXECUTE FUNCTION agentauth_audit_append_only();

    DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
    CREATE TRIGGER audit_events_no_truncate
      BEFORE TRUNCATE ON audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION agentauth_audit_append_only();
  `);

  await client.end();
  console.warn('migrations applied + audit append-only trigger installed');
}

main().catch((err) => {
  console.error('migration failed:', (err as Error)?.message ?? 'unknown error');
  process.exit(1);
});
