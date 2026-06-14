import { env } from '../../env.js';
import { seal, open, KEY_BYTES, type WrappedKey } from '../envelope.js';
import type { KeyProvider } from './index.js';

/**
 * In-process KEK provider. The active key comes from MASTER_KEY (id MASTER_KEY_ID);
 * retired keys from MASTER_KEYS_RETIRED allow rotation. Each wrapped DEK records
 * the kid so old data stays decryptable after a key roll. The kid is bound into
 * the wrap via AAD.
 */
export class LocalKeyProvider implements KeyProvider {
  readonly activeKeyId: string;
  private readonly keys = new Map<string, Buffer>();

  constructor() {
    const active = Buffer.from(env.MASTER_KEY, 'base64');
    if (active.length !== KEY_BYTES) throw new Error('MASTER_KEY must decode to exactly 32 bytes');
    this.activeKeyId = env.MASTER_KEY_ID;
    this.keys.set(env.MASTER_KEY_ID, active);

    if (env.MASTER_KEYS_RETIRED) {
      // Validated in env.ts; parse is safe here.
      const retired = JSON.parse(env.MASTER_KEYS_RETIRED) as Record<string, string>;
      for (const [kid, b64] of Object.entries(retired)) {
        if (!this.keys.has(kid)) this.keys.set(kid, Buffer.from(b64, 'base64'));
      }
    }
  }

  private kek(kid: string): Buffer {
    const k = this.keys.get(kid);
    if (!k) throw new Error(`unknown KEK id: ${kid}`);
    return k;
  }

  async wrap(dek: Buffer): Promise<WrappedKey> {
    const kid = this.activeKeyId;
    const box = seal(this.kek(kid), dek, Buffer.from(`kek:${kid}`));
    return { ...box, kid };
  }

  async unwrap(wrapped: WrappedKey): Promise<Buffer> {
    return open(this.kek(wrapped.kid), wrapped, Buffer.from(`kek:${wrapped.kid}`));
  }
}
