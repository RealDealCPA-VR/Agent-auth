import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { db, schema, closeDb } from '../db/index.js';
import { hashSecret, generateKeySecret, formatApiKey } from '../crypto/secrets.js';
import { createPassport } from '../lib/vault.js';
import { isValidScope } from '../auth/agent.js';
import { env } from '../env.js';

/**
 * One-command bootstrap: create a principal + passport + agent and print a
 * ready-to-use agent API key, so an operator can go from a running server to a
 * working agent credential in a single step.
 *
 *   pnpm agentauth:init
 *
 * Configurable via env (all optional):
 *   AGENTAUTH_INIT_EMAIL, AGENTAUTH_INIT_PASSWORD, AGENTAUTH_INIT_PASSPORT,
 *   AGENTAUTH_INIT_AGENT, AGENTAUTH_INIT_SCOPES (comma-separated)
 *
 * Assumes the database is already migrated (`pnpm db:migrate`).
 */
async function main(): Promise<void> {
  // Default to a valid email domain — the API's login validator requires a real
  // domain (a dotless host like "@local" is rejected and the principal couldn't
  // log in to deposit credentials).
  const email =
    process.env.AGENTAUTH_INIT_EMAIL ??
    `bootstrap+${randomBytes(4).toString('hex')}@agentauth.local`;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.error(`AGENTAUTH_INIT_EMAIL must be a valid email (got "${email}")`);
    process.exit(1);
  }
  const password = process.env.AGENTAUTH_INIT_PASSWORD ?? randomBytes(18).toString('base64url');
  const passportName = process.env.AGENTAUTH_INIT_PASSPORT ?? 'default';
  const agentName = process.env.AGENTAUTH_INIT_AGENT ?? 'agent';
  const scopes = (process.env.AGENTAUTH_INIT_SCOPES ?? 'vault:read,vault:use')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) =>
      s.startsWith('target:') ? `target:${s.slice('target:'.length).toLowerCase()}` : s,
    );

  const invalid = scopes.filter((s) => !isValidScope(s));
  if (invalid.length > 0) {
    console.error(`invalid scopes: ${invalid.join(', ')}`);
    process.exit(1);
  }

  // Reuse an existing principal with this email, else create one.
  let principalId: string;
  const [existing] = await db
    .select({ id: schema.principals.id })
    .from(schema.principals)
    .where(eq(schema.principals.email, email))
    .limit(1);
  if (existing) {
    principalId = existing.id;
  } else {
    const [created] = await db
      .insert(schema.principals)
      .values({ email, passwordHash: await hashSecret(password) })
      .returning({ id: schema.principals.id });
    principalId = created!.id;
  }

  const passport = await createPassport(principalId, passportName);

  const secret = generateKeySecret();
  const [agent] = await db
    .insert(schema.agents)
    .values({
      passportId: passport.id,
      name: agentName,
      secretHash: await hashSecret(secret),
      scopes,
    })
    .returning({ id: schema.agents.id });
  const apiKey = formatApiKey(agent!.id, secret);

  const baseUrl = `http://localhost:${env.PORT}`;
  // Print a clear, copy-pasteable block. The agent key is shown once.
  process.stdout.write(
    [
      '',
      '✅ AgentAuth bootstrap complete.',
      '',
      `  Base URL     : ${baseUrl}`,
      `  Principal    : ${email}`,
      existing ? '  (reused existing principal)' : `  Password     : ${password}`,
      `  Passport     : ${passport.name} (${passport.id})`,
      `  Agent        : ${agentName} (${agent!.id})`,
      `  Scopes       : ${scopes.join(' ')}`,
      '',
      '  AGENT API KEY (store now — it cannot be retrieved again):',
      `    ${apiKey}`,
      '',
      '  Point an agent / the MCP server / an SDK at it:',
      `    export AGENTAUTH_BASE_URL=${baseUrl}`,
      `    export AGENTAUTH_API_KEY=${apiKey}`,
      '',
      '  Deposit a credential to use (as the human owner) — log in, then:',
      `    POST ${baseUrl}/v1/passports/${passport.id}/credentials`,
      `      { "target":"github.com","label":"GH","type":"api_key","secret":"<your-secret>" }`,
      '',
    ].join('\n'),
  );

  await closeDb();
}

main().catch((err) => {
  console.error('bootstrap failed:', (err as Error)?.message ?? 'unknown error');
  process.exit(1);
});
