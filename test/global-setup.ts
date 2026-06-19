import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';

/**
 * One-time test bootstrap: ensure the dedicated test database exists, then apply
 * migrations and the audit append-only trigger to it. Runs once per `vitest`.
 */
const TEST_DB = 'agentauth_test';
// Connect to the always-present `postgres` maintenance DB to create the test DB.
// (Using the app `agentauth` DB would break CI, where only `agentauth_test` exists.)
const ADMIN_URL = 'postgres://agentauth:agentauth@localhost:5433/postgres';
const TEST_URL = `postgres://agentauth:agentauth@localhost:5433/${TEST_DB}`;

export default async function setup(): Promise<void> {
  // Create the test database if it does not yet exist (cannot run inside a tx).
  const admin = postgres(ADMIN_URL, { max: 1 });
  try {
    const exists = await admin`select 1 from pg_database where datname = ${TEST_DB}`;
    if (exists.length === 0) await admin.unsafe(`CREATE DATABASE ${TEST_DB}`);
  } finally {
    await admin.end();
  }

  const client = postgres(TEST_URL, { max: 1 });
  const db = drizzle(client);
  await migrate(db, { migrationsFolder: './drizzle' });
  await client.unsafe(`
    CREATE OR REPLACE FUNCTION agentauth_audit_append_only()
    RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP; END;
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
}
