import { randomBytes, timingSafeEqual } from 'node:crypto';
import argon2 from 'argon2';

/**
 * Password / API-key secret helpers. Human passwords and agent key secrets are
 * both stored only as argon2id hashes.
 */

const ARGON_OPTS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB — OWASP-recommended floor
  timeCost: 3,
  parallelism: 1,
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function hashSecret(secret: string): Promise<string> {
  return argon2.hash(secret, ARGON_OPTS);
}

export async function verifySecret(hash: string, secret: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, secret);
  } catch {
    return false;
  }
}

/**
 * A real argon2id hash used to equalize work when an account does not exist, so
 * login response time does not reveal whether an email is registered. Computed
 * once and cached.
 */
let dummyHashPromise: Promise<string> | null = null;
export function getDummyHash(): Promise<string> {
  // Cache the promise (not the resolved value) so concurrent callers share a
  // single argon2 computation instead of racing to recompute it.
  if (!dummyHashPromise) dummyHashPromise = hashSecret('agentauth::timing::equalizer');
  return dummyHashPromise;
}

/**
 * Agent API key format: `aa_<agentId>.<secret>`
 *   - agentId is the row id (a UUID) so we can locate the hash to verify against.
 *   - secret is 32 random bytes, base64url, shown to the caller exactly once.
 */
const KEY_PREFIX = 'aa_';

export function generateKeySecret(): string {
  return randomBytes(32).toString('base64url');
}

export function formatApiKey(agentId: string, secret: string): string {
  return `${KEY_PREFIX}${agentId}.${secret}`;
}

export function parseApiKey(key: string): { agentId: string; secret: string } | null {
  if (!key.startsWith(KEY_PREFIX)) return null;
  const body = key.slice(KEY_PREFIX.length);
  const dot = body.indexOf('.');
  if (dot <= 0 || dot === body.length - 1) return null;
  const agentId = body.slice(0, dot);
  const secret = body.slice(dot + 1);
  // agentId must be a UUID (the agents.id column) and the secret must be sane —
  // reject early so a malformed key never reaches a DB lookup or argon2 verify.
  if (!UUID_RE.test(agentId)) return null;
  if (secret.length < 16 || secret.length > 512) return null;
  return { agentId, secret };
}

/** Constant-time string compare for non-hashed tokens. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
