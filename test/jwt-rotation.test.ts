import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SignJWT } from 'jose';

const KEY_A = Buffer.alloc(32, 1).toString('base64'); // retired
const KEY_B = Buffer.alloc(32, 2).toString('base64'); // active
const SUB = '11111111-1111-1111-1111-111111111111';

let human: typeof import('../src/auth/human.js');
const saved: Record<string, string | undefined> = {};

beforeAll(async () => {
  for (const k of ['JWT_KEY_ID', 'JWT_SECRET', 'JWT_SECRETS_RETIRED']) saved[k] = process.env[k];
  process.env.JWT_KEY_ID = 'j2';
  process.env.JWT_SECRET = KEY_B;
  process.env.JWT_SECRETS_RETIRED = JSON.stringify({ j1: KEY_A });
  human = await import('../src/auth/human.js');
});

afterAll(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function signWith(b64key: string, kid: string, jti: string) {
  return new SignJWT({ email: 'a@b.c' })
    .setProtectedHeader({ alg: 'HS256', kid })
    .setSubject(SUB)
    .setJti(jti)
    .setIssuer('agentauth')
    .setAudience('agentauth:human')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new Uint8Array(Buffer.from(b64key, 'base64')));
}

describe('JWT key rotation', () => {
  it('accepts a token signed with the active key', async () => {
    const s = await human.issueSession({ sub: SUB, email: 'a@b.c' });
    expect(await human.verifySession(s.token)).not.toBeNull();
  });

  it('accepts a token signed with a retired key (kid j1)', async () => {
    const t = await signWith(KEY_A, 'j1', '00000000-0000-0000-0000-000000000001');
    const claims = await human.verifySession(t);
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe(SUB);
  });

  it('rejects a token with an unknown kid', async () => {
    const t = await signWith(KEY_A, 'jX', '00000000-0000-0000-0000-000000000002');
    expect(await human.verifySession(t)).toBeNull();
  });

  it('rejects a token whose kid does not match its signing key', async () => {
    // Signed with KEY_A but advertises kid j2 (active=KEY_B) → signature mismatch.
    const t = await signWith(KEY_A, 'j2', '00000000-0000-0000-0000-000000000003');
    expect(await human.verifySession(t)).toBeNull();
  });
});
