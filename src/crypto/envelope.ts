import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

/**
 * AES-256-GCM authenticated encryption primitives.
 *
 *   KEK (held by a KeyProvider) ──wraps──▶ per-passport DEK ──seals──▶ credential
 *
 * This module owns the inner AEAD only: sealing a credential under a passport's
 * data key, and the box format. The outer KEK layer (wrapping the DEK) lives in
 * `crypto/keyprovider/`, so it can be backed by an in-process key or an external
 * KMS without touching credential sealing.
 *
 * Every sealed value carries a small self-describing header (`v`, `alg`) so the
 * format can evolve; every wrapped DEK additionally records the `kid` of the KEK
 * that wrapped it, enabling key rotation.
 */

const ALGO = 'aes-256-gcm';
export const ALG_ID = 'A256GCM';
export const FORMAT_VERSION = 1;
const IV_BYTES = 12; // GCM standard nonce length
export const KEY_BYTES = 32; // AES-256

export interface SealedBox {
  v: number; // format version
  alg: string; // 'A256GCM' for AES-GCM, or a provider tag (e.g. 'KMS') for wrapped DEKs
  iv: string; // base64 (empty for non-AEAD provider wraps)
  ciphertext: string; // base64
  tag: string; // base64 auth tag (empty for non-AEAD provider wraps)
}

export interface WrappedKey extends SealedBox {
  kid: string; // id of the KEK that wrapped this DEK
}

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

/** Mint a fresh 256-bit data encryption key for a new passport. */
export function generateDek(): Buffer {
  return randomBytes(KEY_BYTES);
}
