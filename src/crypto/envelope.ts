import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { env } from '../env.js';

/**
 * Envelope encryption with AES-256-GCM.
 *
 *   MASTER_KEY (KEK) ──wraps──▶ per-passport DEK ──seals──▶ each credential secret
 *
 * Compromising one passport's DEK never exposes another passport. KEKs live only
 * in the process environment and are never written to the database.
 *
 * Every sealed value carries a small self-describing header (`v`, `alg`) so the
 * format can evolve, and every wrapped DEK records the `kid` of the KEK that
 * wrapped it so keys can be rotated without losing access to old data.
 */

const ALGO = 'aes-256-gcm';
const ALG_ID = 'A256GCM';
const FORMAT_VERSION = 1;
const IV_BYTES = 12; // GCM standard nonce length
const KEY_BYTES = 32; // AES-256

export interface SealedBox {
  v: number; // format version
  alg: typeof ALG_ID;
  iv: string; // base64
  ciphertext: string; // base64
  tag: string; // base64 auth tag
}

export interface WrappedKey extends SealedBox {
  kid: string; // id of the KEK that wrapped this DEK
}

// --- KEK keyring ------------------------------------------------------------

function buildKeyring(): { activeId: string; keys: Map<string, Buffer> } {
  const keys = new Map<string, Buffer>();
  const active = Buffer.from(env.MASTER_KEY, 'base64');
  if (active.length !== KEY_BYTES) throw new Error('MASTER_KEY must decode to exactly 32 bytes');
  keys.set(env.MASTER_KEY_ID, active);

  if (env.MASTER_KEYS_RETIRED) {
    let retired: Record<string, string>;
    try {
      retired = JSON.parse(env.MASTER_KEYS_RETIRED);
    } catch {
      throw new Error('MASTER_KEYS_RETIRED must be valid JSON: {"<kid>":"<base64-32B>"}');
    }
    for (const [kid, b64] of Object.entries(retired)) {
      const k = Buffer.from(b64, 'base64');
      if (k.length !== KEY_BYTES) throw new Error(`retired key ${kid} must decode to 32 bytes`);
      if (!keys.has(kid)) keys.set(kid, k);
    }
  }
  return { activeId: env.MASTER_KEY_ID, keys };
}

const keyring = buildKeyring();

function kek(kid: string): Buffer {
  const k = keyring.keys.get(kid);
  if (!k) throw new Error(`unknown KEK id: ${kid}`);
  return k;
}

// --- Core AEAD --------------------------------------------------------------

/** Encrypt `plaintext` under `key` (32 bytes). Optional AAD binds context. */
export function seal(key: Buffer, plaintext: Buffer, aad?: Buffer): SealedBox {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: FORMAT_VERSION,
    alg: ALG_ID,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
}

/** Decrypt a SealedBox under `key`. Throws if the auth tag fails (tamper/wrong key). */
export function open(key: Buffer, box: SealedBox, aad?: Buffer): Buffer {
  if (box.v !== FORMAT_VERSION) throw new Error(`unsupported format version: ${box.v}`);
  if (box.alg !== ALG_ID) throw new Error(`unsupported alg: ${box.alg}`);
  const decipher = createDecipheriv(ALGO, key, Buffer.from(box.iv, 'base64'));
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(box.ciphertext, 'base64')), decipher.final()]);
}

// --- DEK lifecycle ----------------------------------------------------------

/** Mint a fresh 256-bit data encryption key for a new passport. */
export function generateDek(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** Wrap a passport DEK under the active KEK for storage, binding the kid via AAD. */
export function wrapDek(dek: Buffer): WrappedKey {
  const kid = keyring.activeId;
  const box = seal(kek(kid), dek, Buffer.from(`kek:${kid}`));
  return { ...box, kid };
}

/** Unwrap a stored DEK using the KEK named in its `kid`. */
export function unwrapDek(wrapped: WrappedKey): Buffer {
  return open(kek(wrapped.kid), wrapped, Buffer.from(`kek:${wrapped.kid}`));
}

/**
 * Re-wrap a DEK under the active KEK (key rotation). Returns null when the DEK
 * is already wrapped under the active key, so callers can skip a DB write.
 */
export function rotateWrappedDek(wrapped: WrappedKey): WrappedKey | null {
  if (wrapped.kid === keyring.activeId) return null;
  const dek = unwrapDek(wrapped);
  try {
    return wrapDek(dek);
  } finally {
    dek.fill(0);
  }
}

export const activeKeyId = keyring.activeId;
