import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Pure unit tests — global fetch is stubbed, so there is no network, DB,
    // or external setup. Keep this package's tests isolated from the server suite.
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
