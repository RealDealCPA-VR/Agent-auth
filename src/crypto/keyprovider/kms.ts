import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { FORMAT_VERSION, type WrappedKey } from '../envelope.js';
import type { KeyProvider } from './index.js';

/**
 * KMS-backed KEK provider: the DEK is wrapped by an external KMS, so the key that
 * protects every passport never enters this process's memory. The wrapped form
 * stores the KMS ciphertext blob in `ciphertext` and tags `alg: 'KMS'`; the
 * AES-GCM iv/tag fields are unused for KMS wraps.
 *
 * The AWS SDK is imported lazily so it is only required when KEY_PROVIDER=kms.
 */
export interface KmsOptions {
  keyId: string;
  region?: string;
  endpoint?: string;
}

const ALG_KMS = 'KMS';
// Non-literal specifier: TS won't statically resolve (so it compiles without the
// optional dep installed); resolved at runtime only when KMS is actually used.
const KMS_PKG: string = '@aws-sdk/client-kms';

export class KmsKeyProvider implements KeyProvider {
  readonly activeKeyId: string;
  private readonly opts: KmsOptions;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sdk: any = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client: any = null;

  constructor(opts: KmsOptions) {
    this.opts = opts;
    this.activeKeyId = opts.keyId;
  }

  private async mod() {
    if (this.sdk) return this.sdk;
    try {
      this.sdk = await import(KMS_PKG);
    } catch {
      throw new Error(
        "KEY_PROVIDER=kms requires the optional dependency '@aws-sdk/client-kms' — install it to use KMS",
      );
    }
    return this.sdk;
  }

  private async getClient() {
    if (this.client) return this.client;
    const sdk = await this.mod();
    this.client = new sdk.KMSClient({
      ...(this.opts.region ? { region: this.opts.region } : {}),
      ...(this.opts.endpoint ? { endpoint: this.opts.endpoint } : {}),
    });
    return this.client;
  }

  async wrap(dek: Buffer): Promise<WrappedKey> {
    const sdk = await this.mod();
    const client = await this.getClient();
    const out = await client.send(
      new sdk.EncryptCommand({ KeyId: this.opts.keyId, Plaintext: dek }),
    );
    return {
      v: FORMAT_VERSION,
      alg: ALG_KMS,
      iv: '',
      tag: '',
      ciphertext: Buffer.from(out.CiphertextBlob as Uint8Array).toString('base64'),
      kid: this.activeKeyId,
    };
  }

  async unwrap(wrapped: WrappedKey): Promise<Buffer> {
    const sdk = await this.mod();
    const client = await this.getClient();
    const out = await client.send(
      new sdk.DecryptCommand({
        KeyId: wrapped.kid,
        CiphertextBlob: Buffer.from(wrapped.ciphertext, 'base64'),
      }),
    );
    return Buffer.from(out.Plaintext as Uint8Array);
  }
}

/**
 * Offline stand-in for KMS used in tests: wraps the DEK with a deterministic
 * in-memory key via AES-256-GCM, mimicking an external KMS without the AWS SDK.
 * Same WrappedKey shape (alg 'KMS') so it exercises the KMS code path end-to-end.
 */
export class FakeKmsKeyProvider implements KeyProvider {
  readonly activeKeyId: string;
  private readonly key: Buffer;

  constructor(keyId = 'fake-kms-key') {
    this.activeKeyId = keyId;
    // Derive a stable 32-byte key from the id so wraps are reproducible per id.
    this.key = Buffer.alloc(32);
    Buffer.from(keyId).copy(this.key);
  }

  async wrap(dek: Buffer): Promise<WrappedKey> {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(dek), c.final()]);
    return {
      v: FORMAT_VERSION,
      alg: ALG_KMS,
      iv: iv.toString('base64'),
      tag: c.getAuthTag().toString('base64'),
      ciphertext: ct.toString('base64'),
      kid: this.activeKeyId,
    };
  }

  async unwrap(wrapped: WrappedKey): Promise<Buffer> {
    const iv = Buffer.from(wrapped.iv, 'base64');
    const tag = Buffer.from(wrapped.tag, 'base64');
    if (iv.length !== 12) throw new Error('invalid IV length');
    if (tag.length !== 16) throw new Error('invalid auth tag length');
    const d = createDecipheriv('aes-256-gcm', this.key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(Buffer.from(wrapped.ciphertext, 'base64')), d.final()]);
  }
}
