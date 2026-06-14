import { env } from '../../env.js';
import type { WrappedKey } from '../envelope.js';
import { LocalKeyProvider } from './local.js';

/**
 * A KeyProvider owns the KEK and performs the outer envelope step: wrapping and
 * unwrapping per-passport data keys (DEKs). Implementations:
 *   - LocalKeyProvider — wraps with MASTER_KEY in-process (AES-256-GCM)
 *   - KmsKeyProvider   — wraps via an external KMS; the KEK never enters memory
 *
 * Operations are async so a network-backed KMS fits the same interface.
 */
export interface KeyProvider {
  readonly activeKeyId: string;
  /** Wrap a 32-byte DEK under the active KEK. */
  wrap(dek: Buffer): Promise<WrappedKey>;
  /** Unwrap a stored DEK using the KEK named by its `kid`. */
  unwrap(wrapped: WrappedKey): Promise<Buffer>;
}

let provider: KeyProvider | null = null;

function build(): KeyProvider {
  switch (env.KEY_PROVIDER) {
    case 'kms':
      // Wired in by configureKmsProvider() at boot (see crypto/keyprovider/kms.ts)
      // via setKeyProvider(); reaching here means it wasn't configured.
      throw new Error('KEY_PROVIDER=kms requires KMS configuration at startup');
    case 'local':
    default:
      return new LocalKeyProvider();
  }
}

export function getKeyProvider(): KeyProvider {
  if (!provider) provider = build();
  return provider;
}

/** Allow tests / KMS wiring to inject a provider. */
export function setKeyProvider(p: KeyProvider): void {
  provider = p;
}

export const activeKeyId = getKeyProvider().activeKeyId;

export function wrapDek(dek: Buffer): Promise<WrappedKey> {
  return getKeyProvider().wrap(dek);
}

export function unwrapDek(wrapped: WrappedKey): Promise<Buffer> {
  return getKeyProvider().unwrap(wrapped);
}

/**
 * Re-wrap a DEK under the active KEK (key rotation). Returns null when the DEK is
 * already wrapped under the active key, so callers can skip a DB write.
 */
export async function rotateWrappedDek(wrapped: WrappedKey): Promise<WrappedKey | null> {
  const p = getKeyProvider();
  if (wrapped.kid === p.activeKeyId) return null;
  const dek = await p.unwrap(wrapped);
  try {
    return await p.wrap(dek);
  } finally {
    dek.fill(0);
  }
}
