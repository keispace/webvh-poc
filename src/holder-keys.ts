import { randomUUID } from 'node:crypto';
import { generateEd25519Key, ss58EncodePublicKey, type GeneratedKeyMaterial } from './crypto';
import { AppError } from './errors';

const PENDING_KEY_TTL_MS = 10 * 60 * 1000;

export interface PendingHolderKey {
  keyId: string;
  key: GeneratedKeyMaterial;
  pathId: string;
  createdAt: string;
  expiresAt: string;
}

export function publicPendingKey(pending: PendingHolderKey) {
  return {
    keyId: pending.keyId,
    algorithm: 'Ed25519',
    purpose: 'authentication + WebVH update (PoC combined key)',
    publicKeyMultibase: pending.key.publicKeyMultibase,
    publicJwk: pending.key.publicJwk,
    privateJwk: pending.key.privateJwk,
    ss58Prefix: 42,
    pathId: pending.pathId,
    createdAt: pending.createdAt,
    expiresAt: pending.expiresAt,
    privateKeyReturned: true,
  };
}

export class PendingHolderKeyStore {
  readonly #keys = new Map<string, PendingHolderKey>();

  generate(): PendingHolderKey {
    this.#pruneExpired();
    const key = generateEd25519Key('authentication');
    const createdAt = new Date();
    const pending: PendingHolderKey = {
      keyId: randomUUID(),
      key,
      pathId: ss58EncodePublicKey(key.publicKey),
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + PENDING_KEY_TTL_MS).toISOString(),
    };
    this.#keys.set(pending.keyId, pending);
    return pending;
  }

  consume(keyId: string): PendingHolderKey {
    this.#pruneExpired();
    const pending = this.#keys.get(keyId);
    if (!pending) {
      throw new AppError(404, 'pending_key_not_found', 'Pending holder key was not found or has expired');
    }
    this.#keys.delete(keyId);
    return pending;
  }

  #pruneExpired(): void {
    const now = Date.now();
    for (const [keyId, pending] of this.#keys) {
      if (Date.parse(pending.expiresAt) <= now) this.#keys.delete(keyId);
    }
  }
}
