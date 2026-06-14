// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'drizzle/**',
      'coverage/**',
      'packages/**', // self-contained SDK packages with their own tooling
      'web/**', // Next.js app with its own eslint config
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    rules: {
      'no-console': ['warn', { allow: ['error', 'warn'] }],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      eqeqeq: ['error', 'smart'],
    },
  },
  {
    // Tests may use console freely and loosen a few rules.
    files: ['**/*.test.ts', 'src/db/migrate.ts'],
    rules: {
      'no-console': 'off',
    },
  },
);
