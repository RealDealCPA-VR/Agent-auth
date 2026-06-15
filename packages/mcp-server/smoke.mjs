// Live smoke test: spawn the MCP server (dist/index.js) over stdio, list tools,
// and call use_credential against a running AgentAuth instance. Requires env
// AGENTAUTH_BASE_URL + AGENTAUTH_API_KEY (an agent key whose passport holds a
// credential for SMOKE_TARGET). Prints TOOLS and RESULT; exits non-zero on error.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({
  command: 'node',
  args: ['dist/index.js'],
  env: { ...process.env },
});
const client = new Client({ name: 'smoke', version: '0' }, { capabilities: {} });
await client.connect(transport);

const tools = await client.listTools();
console.log('TOOLS ' + tools.tools.map((t) => t.name).sort().join(','));

const res = await client.callTool({
  name: 'use_credential',
  arguments: { idOrTarget: process.env.SMOKE_TARGET ?? 'github.com' },
});
console.log('RESULT ' + JSON.stringify(res.content));

await client.close();
process.exit(0);
