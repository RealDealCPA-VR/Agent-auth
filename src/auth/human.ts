import { randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { eq } from 'drizzle-orm';
import { env } from '../env.js';
import { db, schema, pingDb } from '../db/index.js';

/**
 * Human session tokens. Issued on interactive login, carried as a Bearer token
 * on principal-facing endpoints (passport/credential/agent management).
 *
 * Each token has a unique `jti` so it can be revoked before expiry (logout).
 */

// JWT signing keyring: active key (id JWT_KEY_ID) plus any retired keys, so the
// signing secret can rotate while tokens signed before the roll still verify
// until they expire. Use the raw decoded key bytes directly.
const jwtKeys = new Map<string, Uint8Array>();
jwtKeys.set(env.JWT_KEY_ID, new Uint8Array(Buffer.from(env.JWT_SECRET, 'base64')));
if (env.JWT_SECRETS_RETIRED) {
  const retired = JSON.parse(env.JWT_SECRETS_RETIRED) as Record<string, string>;
  for (const [kid, b64] of Object.entries(retired)) {
    if (!jwtKeys.has(kid)) jwtKeys.set(kid, new Uint8Array(Buffer.from(b64, 'base64')));
  }
}
const activeKid = env.JWT_KEY_ID;
const activeKey = jwtKeys.get(activeKid)!;

const ISS = 'agentauth';
const AUD = 'agentauth:human';
const ALG = 'HS256';

export interface HumanClaims {
  sub: string; // principalId
  email: string;
  jti: string;
  exp: number; // token expiry (epoch seconds), as signed
}

export interface IssuedSession {
  token: string;
  jti: string;
  expiresAt: Date;
}

export async function issueSession(input: { sub: string; email: string }): Promise<IssuedSession> {
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + env.JWT_TTL_SECONDS * 1000);
  const token = await new SignJWT({ email: input.email })
    .setProtectedHeader({ alg: ALG, kid: activeKid })
    .setSubject(input.sub)
    .setJti(jti)
    .setIssuer(ISS)
    .setAudience(AUD)
    .setIssuedAt()
    .setExpirationTime(`${env.JWT_TTL_SECONDS}s`)
    .sign(activeKey);
  return { token, jti, expiresAt };
}

/**
 * Verify a session token: signature/claims, then revocation. Fail-closed — if
 * the revocation store cannot be consulted, the session is rejected.
 */
export async function verifySession(token: string): Promise<HumanClaims | null> {
  let claims: HumanClaims;
  try {
    const { payload } = await jwtVerify(
      token,
      // Resolve the verification key from the token's kid (supports rotation).
      // An unknown/missing kid throws, which is caught below as a rejection.
      (header) => {
        const key = header.kid ? jwtKeys.get(header.kid) : undefined;
        if (!key) throw new Error('unknown kid');
        return key;
      },
      { issuer: ISS, audience: AUD, algorithms: [ALG] },
    );
    if (
      typeof payload.sub !== 'string' ||
      typeof payload.email !== 'string' ||
      typeof payload.jti !== 'string' ||
      typeof payload.exp !== 'number'
    ) {
      return null;
    }
    claims = { sub: payload.sub, email: payload.email, jti: payload.jti, exp: payload.exp };
  } catch {
    return null;
  }

  // Fail closed on revocation lookup.
  if (!(await pingDb())) return null;
  try {
    const [revoked] = await db
      .select({ jti: schema.revokedSessions.jti })
      .from(schema.revokedSessions)
      .where(eq(schema.revokedSessions.jti, claims.jti))
      .limit(1);
    if (revoked) return null;
  } catch {
    return null;
  }
  return claims;
}

/** Add a session's jti to the denylist until its natural expiry. */
export async function revokeSession(
  jti: string,
  principalId: string,
  expiresAt: Date,
): Promise<void> {
  await db
    .insert(schema.revokedSessions)
    .values({ jti, principalId, expiresAt })
    .onConflictDoNothing();
}
