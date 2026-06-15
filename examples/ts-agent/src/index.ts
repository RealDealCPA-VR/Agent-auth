/**
 * AgentAuth — TypeScript agent example.
 *
 * What this does (the whole agent loop, in ~40 lines):
 *   1. Construct an AgentAuthClient from env (AGENTAUTH_BASE_URL / AGENTAUTH_API_KEY).
 *   2. List the credentials this agent is scoped to see (metadata only — no secrets).
 *   3. Use one credential *by target* (env TARGET, default "github.com").
 *   4. Print a REDACTED confirmation. The raw secret is NEVER printed in full —
 *      we only show its type, length, and a short prefix so you can see it worked.
 *
 * Run:  AGENTAUTH_API_KEY=aa_... pnpm start   (after `pnpm build`)
 * See ../README.md for how to boot the server and mint an agent key.
 */

import { AgentAuthClient, AgentAuthError, ApprovalPendingError } from '@agentauth/sdk';

/** Show a secret without leaking it: length + a tiny prefix only. */
function redact(secret: string): string {
  const prefix = secret.slice(0, 4);
  return `<redacted ${secret.length} chars, starts "${prefix}…">`;
}

async function main(): Promise<void> {
  const baseUrl = process.env.AGENTAUTH_BASE_URL ?? 'http://localhost:8080';
  const apiKey = process.env.AGENTAUTH_API_KEY;
  const target = process.env.TARGET ?? 'github.com';

  if (!apiKey) {
    console.error(
      'Missing AGENTAUTH_API_KEY. Mint an agent key and export it:\n' +
        '  export AGENTAUTH_API_KEY=aa_<uuid>.<secret>\n' +
        'See examples/README.md for the full bootstrap.',
    );
    process.exitCode = 1;
    return;
  }

  const client = new AgentAuthClient({ baseUrl, apiKey });
  console.log(`AgentAuth agent example → ${baseUrl}`);

  // 1) Discover what this agent can see (never any secrets here).
  const page = await client.listCredentials({ limit: 200 });
  console.log(`\nVisible credentials (${page.pagination.total} total):`);
  if (page.items.length === 0) {
    console.log('  (none — deposit a credential and scope the agent to it)');
  }
  for (const c of page.items) {
    console.log(`  • ${c.target}  [${c.type}]  ${c.label}`);
  }

  // 2) Use one by target. The SDK resolves target → id, then unseals the secret.
  console.log(`\nUsing credential for target "${target}"…`);
  try {
    const used = await client.useCredential(target);
    console.log('  ✓ got a sealed secret, unsealed for this instant:');
    console.log(`    target:  ${used.target}`);
    console.log(`    type:    ${used.type}`);
    console.log(`    secret:  ${redact(used.secret)}`);
    // In a real agent you'd hand `used.secret` straight to the downstream call
    // (HTTP header, login form, etc.) and never persist or log it.
  } catch (err) {
    if (err instanceof ApprovalPendingError) {
      console.log(
        `  ⏳ this credential requires human approval (requestId=${err.requestId}). ` +
          'Approve it in the console, then re-run.',
      );
      return;
    }
    if (err instanceof AgentAuthError) {
      console.error(`  ✗ ${err.status} ${err.code}: ${err.message}`);
      if (err.isNotFound) {
        console.error(
          `    No credential for target "${target}". Set TARGET=<host> to one you can see above.`,
        );
      }
      process.exitCode = 1;
      return;
    }
    throw err;
  }
}

main().catch((err: unknown) => {
  console.error('Unexpected error:', err);
  process.exitCode = 1;
});
