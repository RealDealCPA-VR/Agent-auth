import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { FakeKmsKeyProvider } from '../src/crypto/keyprovider/kms.js';
import { setKeyProvider, getKeyProvider } from '../src/crypto/keyprovider/index.js';
import {
  makeApp,
  resetDb,
  auth,
  registerAndLogin,
  createPassport,
  deposit,
  issueAgent,
} from './helpers.js';

let app: FastifyInstance;

beforeAll(async () => {
  // Route the whole KEK layer through a (fake) KMS for this file, proving the
  // KMS provider interface works end-to-end with the vault — no AWS SDK needed.
  setKeyProvider(new FakeKmsKeyProvider('test-kms-key'));
  app = await makeApp();
});
afterAll(async () => {
  await app.close();
});
beforeEach(async () => {
  await resetDb();
});

describe('KMS key provider (FakeKms)', () => {
  it('wraps/unwraps a DEK via the provider (alg=KMS, kid set)', async () => {
    const provider = getKeyProvider();
    expect(provider.activeKeyId).toBe('test-kms-key');
    const dek = Buffer.alloc(32, 9);
    const wrapped = await provider.wrap(dek);
    expect(wrapped.alg).toBe('KMS');
    expect(wrapped.kid).toBe('test-kms-key');
    const back = await provider.unwrap(wrapped);
    expect(back.equals(dek)).toBe(true);
  });

  it('deposits and uses a credential with KMS-wrapped passport keys', async () => {
    const { token } = await registerAndLogin(app);
    const pp = await createPassport(app, token);
    const cred = await deposit(app, token, pp, {
      target: 'github.com',
      label: 'gh',
      type: 'api_key',
      secret: 'ghp_kms_secret',
    });
    const agent = await issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:github.com',
    ]);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${cred.id}/use`,
      headers: auth(agent.apiKey),
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().secret).toBe('ghp_kms_secret');
  });
});
