import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Pure unit tests — global fetch is stubbed (vi.stubGlobal), so there is no
    // network, no MCP transport, and no external setup. Isolated from the server suite.
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
