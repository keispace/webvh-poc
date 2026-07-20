import { createDID, resolveDIDFromLog, updateDID } from 'didwebvh-ts';
import type { AppConfig } from './config.js';
import {
  Ed25519WebVhCrypto,
  Ed25519WebVhVerifier,
  generateEd25519Key,
  requireEd25519PublicJwk,
  ss58EncodePublicKey,
  type GeneratedKeyMaterial,
} from './crypto.js';
import { AppError, asErrorMessage } from './errors.js';
import { IdentityStore } from './store.js';
import type { DIDDocument, DIDLog, IdentityRole, ResolutionResult, StoredIdentity, VerificationMethod } from './types.js';

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

function didTemplate(domain: string, path: string): string {
  return `did:webvh:{SCID}:${domain}:${path.split('/').join(':')}`;
}

function jwkVerificationMethod(key: GeneratedKeyMaterial, controller: string): VerificationMethod {
  return {
    ...key.verificationMethod,
    id: `${controller}#${key.publicJwk.kid ?? key.publicJwk.x}`,
    controller,
  };
}

export class WebVhService {
  readonly verifier = new Ed25519WebVhVerifier();

  constructor(
    readonly config: AppConfig,
    readonly store: IdentityStore,
  ) {}

  async ensureIssuer(): Promise<StoredIdentity> {
    const path = `issuer/${this.config.issuerSlug}`;
    const existing = this.store.getByPath(path);
    if (existing) return this.ensureJoseSigningMethod(existing.did);
    return this.createIssuerIdentity(this.config.issuerSlug);
  }

  /**
   * Records created by older PoC versions used a Multikey verification method
   * for VC/VP signing. VC JOSE/COSE requires JsonWebKey/publicKeyJwk, so rotate
   * those records in place while preserving their DID and WebVH history.
   */
  async ensureJoseSigningMethod(did: string): Promise<StoredIdentity> {
    const current = this.store.requireByDid(did);
    const relationship = current.role === 'issuer' ? 'assertionMethod' : 'authentication';
    const resolution = await this.resolveStored(did);
    const allowed = resolution.didDocument[relationship] ?? [];
    const method = resolution.didDocument.verificationMethod?.find(
      (candidate) => candidate.id === current.key.kid && allowed.includes(current.key.kid),
    );

    if (method?.type === 'JsonWebKey' && method.publicKeyJwk) {
      try {
        const publicJwk = requireEd25519PublicJwk(method.publicKeyJwk);
        if (publicJwk.x === current.key.publicJwk.x) return current;
      } catch {
        // A malformed legacy method is migrated through a signed WebVH update below.
      }
    }

    return (await this.rotateIdentity(did)).identity;
  }

  async createHolderIdentity(key: GeneratedKeyMaterial): Promise<StoredIdentity> {
    const pathId = ss58EncodePublicKey(key.publicKey);
    return this.#createIdentity({
      role: 'holder',
      slug: pathId,
      path: pathId,
      key,
    });
  }

  async createIssuerIdentity(slug: string): Promise<StoredIdentity> {
    const normalizedSlug = slug.trim().toLowerCase();
    if (!SLUG_PATTERN.test(normalizedSlug)) {
      throw new AppError(400, 'invalid_slug', 'slug must contain lowercase letters, digits, and internal hyphens');
    }
    const key = generateEd25519Key('assertionMethod');
    return this.#createIdentity({
      role: 'issuer',
      slug,
      path: `issuer/${normalizedSlug}`,
      key,
    });
  }

  async #createIdentity({
    role,
    slug,
    path,
    key,
  }: {
    role: IdentityRole;
    slug: string;
    path: string;
    key: ReturnType<typeof generateEd25519Key>;
  }): Promise<StoredIdentity> {
    if (this.store.getByPath(path)) {
      throw new AppError(409, 'did_already_exists', `Identity path already exists: ${path}`);
    }

    const signer = new Ed25519WebVhCrypto(key.publicKeyMultibase, key.privateJwk);
    const created = await createDID({
      address: this.config.didDomain,
      paths: path.split('/'),
      signer,
      verifier: signer,
      updateKeys: [key.publicKeyMultibase],
      verificationMethods: [jwkVerificationMethod(key, didTemplate(this.config.didDomain, path))],
      portable: false,
    });

    const verificationMethod = created.doc.verificationMethod?.[0];
    if (!verificationMethod?.id) throw new Error('didwebvh-ts did not create a verification method id');

    const identity: StoredIdentity = {
      role,
      slug,
      path,
      did: created.did,
      didDocument: created.doc,
      log: created.log,
      key: {
        kid: verificationMethod.id,
        publicKeyMultibase: key.publicKeyMultibase,
        publicJwk: key.publicJwk,
        privateJwk: key.privateJwk,
      },
      createdAt: new Date().toISOString(),
    };
    await this.store.save(identity);
    return identity;
  }

  async resolveStored(did: string): Promise<ResolutionResult> {
    const identity = this.store.requireByDid(did);
    return this.validateLog(did, identity.log);
  }

  async rotateIdentity(did: string): Promise<{
    identity: StoredIdentity;
    previousKid: string;
    currentKid: string;
    previousPublicKeyMultibase: string;
    currentPublicKeyMultibase: string;
    versionId: string;
  }> {
    const current = this.store.requireByDid(did);
    const purpose = current.role === 'issuer' ? 'assertionMethod' : 'authentication';
    const nextKey = generateEd25519Key(purpose);
    const currentSigner = new Ed25519WebVhCrypto(current.key.publicKeyMultibase, current.key.privateJwk);
    const rotated = await updateDID({
      log: current.log,
      signer: currentSigner,
      verifier: this.verifier,
      updateKeys: [nextKey.publicKeyMultibase],
      verificationMethods: [jwkVerificationMethod(nextKey, current.did)],
    });
    if (rotated.did !== current.did) {
      throw new Error('Key rotation unexpectedly changed the DID');
    }
    const verificationMethod = rotated.doc.verificationMethod?.[0];
    if (!verificationMethod?.id) throw new Error('didwebvh-ts did not create a rotated verification method id');

    const identity: StoredIdentity = {
      ...current,
      didDocument: rotated.doc,
      log: rotated.log,
      key: {
        kid: verificationMethod.id,
        publicKeyMultibase: nextKey.publicKeyMultibase,
        publicJwk: nextKey.publicJwk,
        privateJwk: nextKey.privateJwk,
      },
      updatedAt: new Date().toISOString(),
    };
    await this.store.update(identity);
    const resolution = await this.resolveStored(did);
    return {
      identity,
      previousKid: current.key.kid,
      currentKid: identity.key.kid,
      previousPublicKeyMultibase: current.key.publicKeyMultibase,
      currentPublicKeyMultibase: identity.key.publicKeyMultibase,
      versionId: resolution.didDocumentMetadata.versionId,
    };
  }

  async validateLog(did: string, log: DIDLog): Promise<ResolutionResult> {
    this.#assertAllowedDid(did);
    if (!Array.isArray(log) || log.length === 0 || log.length > 100) {
      throw new AppError(400, 'invalid_did_log', 'DID log must contain between 1 and 100 entries');
    }

    try {
      const result = await resolveDIDFromLog(log, { verifier: this.verifier, requestedDid: did });
      if (result.meta.error || !result.doc || result.did !== did || result.doc.id !== did) {
        throw new Error(result.meta.problemDetails?.detail ?? 'Resolved DID does not match the requested DID');
      }
      return {
        did,
        didDocument: result.doc,
        didDocumentMetadata: {
          scid: result.meta.scid,
          versionId: result.meta.versionId,
          created: result.meta.created,
          updated: result.meta.updated,
          deactivated: result.meta.deactivated,
        },
        verified: true,
      };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError(400, 'did_log_verification_failed', asErrorMessage(error));
    }
  }

  async resolveVerificationMethod(
    did: string,
    kid: string,
    relationship: 'authentication' | 'assertionMethod',
  ): Promise<{ method: VerificationMethod; document: DIDDocument }> {
    const resolution = await this.resolveStored(did);
    const allowed = resolution.didDocument[relationship] ?? [];
    if (!allowed.includes(kid)) {
      throw new AppError(400, 'verification_method_not_authorized', `${kid} is not authorized for ${relationship}`);
    }
    const method = resolution.didDocument.verificationMethod?.find((candidate) => candidate.id === kid);
    if (method?.type !== 'JsonWebKey' || !method.publicKeyJwk) {
      throw new AppError(400, 'verification_method_not_found', `No supported JsonWebKey found for ${kid}`);
    }
    requireEd25519PublicJwk(method.publicKeyJwk);
    return { method, document: resolution.didDocument };
  }

  logUrl(identity: StoredIdentity): string {
    return `https://${this.config.didDomain}/${identity.path}/did.jsonl`;
  }

  serializeLog(log: DIDLog): string {
    return `${log.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
  }

  #assertAllowedDid(did: string): void {
    const parts = did.split(':');
    if (parts.length < 5 || parts[0] !== 'did' || parts[1] !== 'webvh' || !parts[2]) {
      throw new AppError(400, 'invalid_did', 'Expected a path-based did:webvh identifier');
    }
    if (parts[3]?.toLowerCase() !== this.config.didDomain) {
      throw new AppError(400, 'did_domain_not_allowed', `Only ${this.config.didDomain} DIDs are accepted`);
    }
    if (parts.some((part) => part.includes('/') || part.includes('\\'))) {
      throw new AppError(400, 'invalid_did', 'DID method-specific path segments must use colon separators');
    }
  }
}
