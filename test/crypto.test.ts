import { describe, it, expect, beforeAll } from 'vitest';

// Provide required env before importing modules that validate it.
beforeAll(() => {
  process.env.MASTER_KEY ??= Buffer.alloc(32, 7).toString('base64');
  process.env.JWT_SECRET ??= Buffer.alloc(32, 9).toString('base64');
  process.env.DATABASE_URL ??= 'postgres://u:p@localhost:5433/db';
});

describe('envelope encryption', () => {
  it('round-trips a sealed secret', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const dek = generateDek();
    const box = seal(dek, Buffer.from('hunter2'));
    expect(open(dek, box).toString('utf8')).toBe('hunter2');
  });

  it('rejects tampered ciphertext', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const dek = generateDek();
    const box = seal(dek, Buffer.from('secret'));
    const tampered = { ...box, ciphertext: Buffer.from('garbage').toString('base64') };
    expect(() => open(dek, tampered)).toThrow();
  });

  it('fails to open with the wrong DEK', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const box = seal(generateDek(), Buffer.from('x'));
    expect(() => open(generateDek(), box)).toThrow();
  });

  it('wraps and unwraps a DEK under the master key', async () => {
    const { generateDek } = await import('../src/crypto/envelope.js');
    const { wrapDek, unwrapDek } = await import('../src/crypto/keyprovider/index.js');
    const dek = generateDek();
    const back = await unwrapDek(await wrapDek(dek));
    expect(back.equals(dek)).toBe(true);
  });

  it('records the active key id on wrapped DEKs', async () => {
    const { generateDek } = await import('../src/crypto/envelope.js');
    const { wrapDek, getActiveKeyId } = await import('../src/crypto/keyprovider/index.js');
    const wrapped = await wrapDek(generateDek());
    expect(wrapped.kid).toBe(getActiveKeyId());
  });

  it('rotateWrappedDek is a no-op when already on the active key', async () => {
    const { generateDek } = await import('../src/crypto/envelope.js');
    const { wrapDek, rotateWrappedDek } = await import('../src/crypto/keyprovider/index.js');
    expect(await rotateWrappedDek(await wrapDek(generateDek()))).toBeNull();
  });

  it('rejects an unknown format version', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const dek = generateDek();
    const box = seal(dek, Buffer.from('x'));
    expect(() => open(dek, { ...box, v: 999 })).toThrow(/format version/);
  });

  it('rejects an unknown algorithm id', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const dek = generateDek();
    const box = seal(dek, Buffer.from('x'));
    expect(() => open(dek, { ...box, alg: 'BOGUS' as 'A256GCM' })).toThrow(/alg/);
  });

  it('enforces AAD binding (passport:target)', async () => {
    const { seal, open, generateDek } = await import('../src/crypto/envelope.js');
    const dek = generateDek();
    const box = seal(dek, Buffer.from('s'), Buffer.from('p1:github.com'));
    expect(open(dek, box, Buffer.from('p1:github.com')).toString()).toBe('s');
    expect(() => open(dek, box, Buffer.from('p2:github.com'))).toThrow();
  });
});

describe('api key parse/format', () => {
  const uuid = '5822259f-b8d5-4aaa-9bbb-0123456789ab';
  const secret = 'a'.repeat(43); // base64url of 32 bytes is 43 chars

  it('round-trips a UUID agent id and secret', async () => {
    const { formatApiKey, parseApiKey } = await import('../src/crypto/secrets.js');
    const key = formatApiKey(uuid, secret);
    expect(parseApiKey(key)).toEqual({ agentId: uuid, secret });
  });

  it('rejects a non-UUID agent id', async () => {
    const { parseApiKey } = await import('../src/crypto/secrets.js');
    expect(parseApiKey('aa_abc-123.' + secret)).toBeNull();
  });

  it('rejects a too-short secret', async () => {
    const { parseApiKey } = await import('../src/crypto/secrets.js');
    expect(parseApiKey(`aa_${uuid}.short`)).toBeNull();
  });

  it('rejects malformed keys', async () => {
    const { parseApiKey } = await import('../src/crypto/secrets.js');
    expect(parseApiKey('nope')).toBeNull();
    expect(parseApiKey('aa_onlyid')).toBeNull();
    expect(parseApiKey(`aa_${uuid}.`)).toBeNull();
  });
});
