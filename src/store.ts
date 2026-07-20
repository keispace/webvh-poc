import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AppError } from './errors.js';
import type { StoredIdentity } from './types.js';

export class IdentityStore {
  readonly #identities = new Map<string, StoredIdentity>();
  readonly #paths = new Map<string, string>();
  readonly #privateDir: string;

  constructor(dataDir: string) {
    this.#privateDir = join(dataDir, 'private');
  }

  async init(): Promise<void> {
    await mkdir(this.#privateDir, { recursive: true, mode: 0o700 });
    const files = await readdir(this.#privateDir);
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const raw = await readFile(join(this.#privateDir, file), 'utf8');
      const identity = JSON.parse(raw) as StoredIdentity;
      this.#index(identity);
    }
  }

  list(): StoredIdentity[] {
    return [...this.#identities.values()];
  }

  getByDid(did: string): StoredIdentity | undefined {
    return this.#identities.get(did);
  }

  requireByDid(did: string): StoredIdentity {
    const identity = this.getByDid(did);
    if (!identity) throw new AppError(404, 'did_not_found', `Unknown DID: ${did}`);
    return identity;
  }

  getByPath(path: string): StoredIdentity | undefined {
    const did = this.#paths.get(path);
    return did ? this.#identities.get(did) : undefined;
  }

  async save(identity: StoredIdentity): Promise<void> {
    if (this.#identities.has(identity.did) || this.#paths.has(identity.path)) {
      throw new AppError(409, 'did_already_exists', `Identity path already exists: ${identity.path}`);
    }

    const safeName = Buffer.from(identity.path).toString('base64url');
    const target = join(this.#privateDir, `${safeName}.json`);
    const temporary = `${target}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, target);
    this.#index(identity);
  }

  async update(identity: StoredIdentity): Promise<void> {
    const existing = this.#identities.get(identity.did);
    if (!existing || existing.path !== identity.path || existing.role !== identity.role) {
      throw new AppError(404, 'did_not_found', `Cannot update unknown DID: ${identity.did}`);
    }

    const safeName = Buffer.from(identity.path).toString('base64url');
    const target = join(this.#privateDir, `${safeName}.json`);
    const temporary = `${target}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, target);
    this.#identities.set(identity.did, identity);
    this.#paths.set(identity.path, identity.did);
  }

  #index(identity: StoredIdentity): void {
    if (!identity.did || !identity.path || !identity.key?.privateJwk?.d) {
      throw new Error('Invalid persisted identity record');
    }
    if (this.#identities.has(identity.did) || this.#paths.has(identity.path)) {
      throw new Error(`Duplicate persisted identity: ${identity.did}`);
    }
    this.#identities.set(identity.did, identity);
    this.#paths.set(identity.path, identity.did);
  }
}
