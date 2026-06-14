import { defineConfig } from 'vitest/config';

/**
 * Vitest config for the web client unit tests. We test the pure-logic parts
 * of the API client (token storage, error-envelope unwrapping, request
 * shaping) against a mocked fetch + a jsdom-backed localStorage.
 */
export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['**/*.test.ts', '**/*.test.tsx'],
  },
  resolve: {
    alias: {
      '@': new URL('.', import.meta.url).pathname,
    },
  },
});
