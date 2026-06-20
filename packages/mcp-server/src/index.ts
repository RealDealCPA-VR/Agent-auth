#!/usr/bin/env node
/**
 * @agentauth/mcp-server — a Model Context Protocol (MCP) stdio server that
 * exposes the AgentAuth vault as MCP tools.
 *
 * Drop it into any MCP-capable agent host (Claude Desktop, etc.) and the agent
 * gains three tools with zero code:
 *
 *   • list_credentials — enumerate the vault (metadata only, NO secrets)
 *   • use_credential   — unseal and return THE live secret for one credential
 *   • proxy_request    — call the target with the credential injected server-side
 *                        (the raw secret is NEVER exposed to the agent)
 *
 * Browser-login is intentionally an SDK-only feature (see @agentauth/sdk): its
 * secret-confinement requires a real browser page to apply the plan to, which a
 * stdio MCP bridge does not have.
 *
 * Configuration comes from the environment:
 *   • AGENTAUTH_BASE_URL — the AgentAuth API base (default http://localhost:8080)
 *   • AGENTAUTH_API_KEY  — the agent API key `aa_<uuid>.<secret>` (REQUIRED)
 *
 * The server speaks stdio (the standard MCP transport for locally-spawned
 * servers), so the host launches it as a child process and talks JSON-RPC over
 * stdin/stdout. Nothing is ever written to stdout except the protocol stream;
 * diagnostics go to stderr.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AgentAuthClient, AgentAuthClientError, ApprovalPendingError, type ProxyMethod } from './client.js';

const DEFAULT_BASE_URL = 'http://localhost:8080';

/**
 * Read + validate configuration from the environment. Exits the process with a
 * clear message (on stderr) if the required API key is missing — there is no
 * point starting a vault bridge with no credentials to reach.
 */
function readConfig(): { baseUrl: string; apiKey: string } {
  const baseUrl = process.env.AGENTAUTH_BASE_URL?.trim() || DEFAULT_BASE_URL;
  const apiKey = process.env.AGENTAUTH_API_KEY?.trim();
  if (!apiKey) {
    process.stderr.write(
      'agentauth-mcp: AGENTAUTH_API_KEY is required.\n' +
        'Set it to your agent API key (aa_<uuid>.<secret>) in the MCP server config env.\n' +
        `Optionally set AGENTAUTH_BASE_URL (default ${DEFAULT_BASE_URL}).\n`,
    );
    process.exit(1);
  }
  return { baseUrl, apiKey };
}

/** A successful text result for an MCP tool call. */
function textResult(text: string) {
  return { content: [{ type: 'text' as const, text }] };
}

/** An error result for an MCP tool call (sets isError so the host can react). */
function errorResult(text: string) {
  return { content: [{ type: 'text' as const, text }], isError: true };
}

/**
 * Turn any thrown value from the client into a readable MCP tool error string.
 * Maps the AgentAuth status/code envelope and the approval-pending case to
 * human-readable guidance.
 */
function describeError(err: unknown): string {
  if (err instanceof ApprovalPendingError) {
    const ref = err.requestId ? ` (request ${err.requestId})` : '';
    return (
      `This credential requires human approval before it can be used${ref}. ` +
      'A request has been queued — ask the vault owner to approve it, then try again.'
    );
  }
  if (err instanceof AgentAuthClientError) {
    const hint = hintForStatus(err.status);
    const ref = err.requestId ? ` [request ${err.requestId}]` : '';
    return `AgentAuth error ${err.status} (${err.code}): ${err.message}${hint}${ref}`;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

/** A short actionable hint for the common vault error statuses. */
function hintForStatus(status: number): string {
  switch (status) {
    case 0:
      return ' — could not reach the AgentAuth server; check AGENTAUTH_BASE_URL and that it is running.';
    case 401:
      return ' — the agent API key is missing, malformed, or rejected; check AGENTAUTH_API_KEY.';
    case 403:
      return " — this agent is not permitted to access that credential (scope or target glob).";
    case 404:
      return ' — no such credential id/target is visible to this agent.';
    case 410:
      return ' — the credential is expired or outside its allowed time window.';
    case 429:
      return ' — rate limited or use-limit reached; back off and retry later.';
    case 503:
      return ' — the vault is temporarily unavailable (fail-closed); retry shortly.';
    default:
      return '';
  }
}

/** Build and wire up the MCP server with the vault tools. */
export function buildServer(client: AgentAuthClient): McpServer {
  const server = new McpServer({
    name: 'agentauth',
    version: '0.1.0',
  });

  server.registerTool(
    'list_credentials',
    {
      title: 'List vault credentials',
      description:
        'List the credentials this agent is allowed to access in the AgentAuth vault. ' +
        'Returns metadata only (id, target, label, type, metadata, expiresAt) as JSON — ' +
        'NO secrets are returned. Use this to discover which credential to fetch, then ' +
        'call use_credential with the id or target.',
      inputSchema: {},
    },
    async () => {
      try {
        const page = await client.listCredentials({ limit: 200 });
        return textResult(JSON.stringify(page, null, 2));
      } catch (err) {
        return errorResult(describeError(err));
      }
    },
  );

  server.registerTool(
    'use_credential',
    {
      title: 'Use a vault credential (returns a live secret)',
      description:
        'Unseal and return a single credential from the AgentAuth vault for immediate use. ' +
        'WARNING: this returns a LIVE SECRET (password, API key, token, or cookie) in plain ' +
        'text — use it to authenticate and never log, store, or echo it back to the user. ' +
        'Identify the credential either by its UUID id, or by its target string (e.g. ' +
        '"github.com"), which is resolved against the listing. If the credential requires ' +
        'human approval, an approval request is queued and an error explaining this is returned.',
      inputSchema: {
        idOrTarget: z
          .string()
          .min(1)
          .describe('The credential UUID, or its target host string (e.g. "github.com").'),
      },
    },
    async ({ idOrTarget }) => {
      try {
        const used = await client.useCredential(idOrTarget);
        return textResult(JSON.stringify(used, null, 2));
      } catch (err) {
        return errorResult(describeError(err));
      }
    },
  );

  server.registerTool(
    'proxy_request',
    {
      title: 'Make a request with a credential injected (secret never exposed)',
      description:
        'Make an HTTP request to the credential\'s pinned target, with the credential ' +
        'injected server-side — the secret is NEVER exposed to the agent. AgentAuth sends ' +
        'the downstream request itself and returns the downstream response ' +
        '({ status, headers, body }) with the secret redacted. The host is pinned to the ' +
        'credential\'s target; you only control method, path, query, headers, and body. ' +
        'Identify the credential by its UUID id, or by its target string (e.g. "github.com"), ' +
        'which is resolved against the listing. Prefer this over use_credential whenever you ' +
        'only need to CALL the target — the raw secret stays inside AgentAuth. If the ' +
        'credential requires human approval, an approval request is queued and an error ' +
        'explaining this is returned.',
      inputSchema: {
        idOrTarget: z
          .string()
          .min(1)
          .describe('The credential UUID, or its target host string (e.g. "github.com").'),
        method: z
          .enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
          .optional()
          .describe('HTTP method for the downstream request (default GET).'),
        path: z
          .string()
          .optional()
          .describe('Path on the pinned host; must start with "/" (default "/").'),
        query: z
          .record(z.string())
          .optional()
          .describe('Optional query parameters appended to the path.'),
        headers: z
          .record(z.string())
          .optional()
          .describe('Optional request headers (the credential is injected server-side).'),
        body: z.string().optional().describe('Optional request body (already serialized).'),
      },
    },
    async ({ idOrTarget, method, path, query, headers, body }) => {
      try {
        const response = await client.proxy(idOrTarget, {
          method: method as ProxyMethod | undefined,
          path,
          query,
          headers,
          body,
        });
        return textResult(JSON.stringify(response, null, 2));
      } catch (err) {
        return errorResult(describeError(err));
      }
    },
  );

  // NOTE: browser-login is intentionally NOT exposed as an MCP tool. Its whole
  // value over use_credential is that the secret is confined to an SDK helper
  // applying the plan to a real browser PAGE — the agent's reasoning never sees it.
  // A stdio MCP bridge has no page to apply the plan to, so a browser_login tool
  // could only serialize live cookie/header/form secret values into the model's
  // tool-result stream — strictly more exposure than use_credential, with none of
  // the confinement. MCP agents authenticate via use_credential or proxy_request;
  // browser-login lives in the TS/Python SDKs (see @agentauth/sdk browserLogin).

  return server;
}

/** Entry point: read config, connect the stdio transport, run forever. */
async function main(): Promise<void> {
  const { baseUrl, apiKey } = readConfig();
  const client = new AgentAuthClient({ baseUrl, apiKey });
  const server = buildServer(client);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `agentauth-mcp: connected (vault ${baseUrl}); tools: list_credentials, use_credential, proxy_request\n`,
  );
}

// Run when executed directly as the bin (not when imported, e.g. by tests).
// Under NodeNext ESM, comparing import.meta.url to the invoked argv[1] (as a
// file:// URL) is the portable "is this the main module?" check. The Vitest
// importer URL never matches the bin path, so importing for tests is a no-op.
function isMainModule(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === new URL(`file://${entry}`).href || import.meta.url === pathToFileUrlHref(entry);
  } catch {
    return false;
  }
}

/** Best-effort file:// URL for a filesystem path, tolerant of Windows separators. */
function pathToFileUrlHref(p: string): string {
  const normalized = p.replace(/\\/g, '/');
  return normalized.startsWith('/') ? `file://${normalized}` : `file:///${normalized}`;
}

if (isMainModule()) {
  main().catch((err: unknown) => {
    process.stderr.write(`agentauth-mcp: fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
