import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Deterministic non-production secrets + a dedicated test database.
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgres://agentauth:agentauth@localhost:5433/agentauth_test',
      MASTER_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      JWT_SECRET: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      MASTER_KEY_ID: 'k1',
      RATE_LIMIT_AUTH_MAX: '1000',
      RATE_LIMIT_GLOBAL_MAX: '5000',
      LOG_LEVEL: 'silent',
    },
    globalSetup: ['./test/global-setup.ts'],
    // One shared Postgres + advisory-locked audit chain → run files serially.
    fileParallelism: false,
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    hookTimeout: 30000,
    testTimeout: 30000,
  },
});
