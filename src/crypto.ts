import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  MultibaseEncoding,
  multibaseEncode,
  prepareDataForSigning,
} from 'didwebvh-ts';
import type { Ed25519PrivateJwk, Ed25519PublicJwk, VerificationMethod } from './types';

interface SigningInput {
  document: unknown;
  proof: {
    type: 'DataIntegrityProof';
    cryptosuite: 'eddsa-jcs-2022';
    verificationMethod: string;
    created: string;
    proofPurpose: 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';
  };
}

interface SigningOutput {
  proofValue: string;
}

const ED25519_PUBLIC_MULTICODEC = new Uint8Array([0xed, 0x01]);
const SS58_PREFIX = 42;
const SS58_PRE = new TextEncoder().encode('SS58PRE');

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function fromBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export interface GeneratedKeyMaterial {
  seed: Uint8Array;
  publicKey: Uint8Array;
  publicKeyMultibase: string;
  publicJwk: Ed25519PublicJwk;
  privateJwk: Ed25519PrivateJwk;
  verificationMethod: VerificationMethod;
}

export function generateEd25519Key(purpose: 'authentication' | 'assertionMethod'): GeneratedKeyMaterial {
  const { secretKey: seed, publicKey } = ed25519.keygen();
  const publicKeyMultibase = multibaseEncode(
    new Uint8Array([...ED25519_PUBLIC_MULTICODEC, ...publicKey]),
    MultibaseEncoding.BASE58_BTC,
  );
  const publicJwk: Ed25519PublicJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: toBase64Url(publicKey),
    alg: 'EdDSA',
  };
  publicJwk.kid = createHash('sha256')
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x }))
    .digest('base64url');

  return {
    seed,
    publicKey,
    publicKeyMultibase,
    publicJwk,
    privateJwk: { ...publicJwk, d: toBase64Url(seed) },
    verificationMethod: {
      type: 'JsonWebKey',
      publicKeyJwk: publicJwk,
      purpose,
    },
  };
}

/**
 * Standard SS58 address for a 32-byte Ed25519 public key.
 * Prefix 42 is the generic Substrate network prefix used by this PoC path convention.
 */
export function ss58EncodePublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('SS58 encoding requires a 32-byte Ed25519 public key');
  const addressBody = new Uint8Array(1 + publicKey.length);
  addressBody[0] = SS58_PREFIX;
  addressBody.set(publicKey, 1);
  const checksum = createHash('blake2b512')
    .update(SS58_PRE)
    .update(addressBody)
    .digest()
    .subarray(0, 2);
  return multibaseEncode(new Uint8Array([...addressBody, ...checksum]), MultibaseEncoding.BASE58_BTC).slice(1);
}

export class Ed25519WebVhVerifier {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  }
}

export class Ed25519WebVhCrypto extends Ed25519WebVhVerifier {
  readonly #seed: Uint8Array | undefined;
  readonly #verificationMethodId: string;

  constructor(publicKeyMultibase: string, privateJwk?: Ed25519PrivateJwk) {
    super();
    this.#verificationMethodId = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    this.#seed = privateJwk ? fromBase64Url(privateJwk.d) : undefined;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    if (!this.#seed) throw new Error('Private key is required for signing');
    const message = await prepareDataForSigning(input.document, input.proof);
    const signature = ed25519.sign(message, this.#seed);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  getVerificationMethodId(): string {
    return this.#verificationMethodId;
  }
}

export function requireEd25519PublicJwk(value: unknown): Ed25519PublicJwk {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Verification method must contain a public JWK');
  }
  const jwk = value as Record<string, unknown>;
  if (
    jwk.kty !== 'OKP' ||
    jwk.crv !== 'Ed25519' ||
    typeof jwk.x !== 'string' ||
    (jwk.alg !== undefined && jwk.alg !== 'EdDSA') ||
    (jwk.kid !== undefined && typeof jwk.kid !== 'string') ||
    'd' in jwk
  ) {
    throw new Error('Only public Ed25519 JsonWebKey verification methods are supported');
  }
  const publicKey = Buffer.from(jwk.x, 'base64url');
  if (publicKey.length !== 32 || publicKey.toString('base64url') !== jwk.x) {
    throw new Error('Ed25519 public JWK x must be a canonical 32-byte base64url value');
  }
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: jwk.x,
    ...(jwk.alg === 'EdDSA' ? { alg: jwk.alg } : {}),
    ...(typeof jwk.kid === 'string' ? { kid: jwk.kid } : {}),
  };
}
