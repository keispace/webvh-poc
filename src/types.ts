export interface VerificationMethod {
  id?: string;
  type: string;
  controller?: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Ed25519PublicJwk;
  purpose?: 'authentication' | 'assertionMethod';
}

export interface DIDDocument {
  '@context'?: unknown;
  id?: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  authentication?: string[];
  assertionMethod?: string[];
  verificationMethod?: VerificationMethod[];
  service?: unknown[];
  [key: string]: unknown;
}

export interface DIDLogEntry {
  versionId: string;
  versionTime: string;
  parameters: Record<string, unknown>;
  state: DIDDocument;
  proof?: Array<Record<string, unknown>>;
}

export type DIDLog = DIDLogEntry[];

export type IdentityRole = 'holder' | 'issuer';

export interface StoredIdentity {
  role: IdentityRole;
  slug: string;
  path: string;
  did: string;
  didDocument: DIDDocument;
  log: DIDLog;
  key: {
    kid: string;
    publicKeyMultibase: string;
    publicJwk: Ed25519PublicJwk;
    privateJwk: Ed25519PrivateJwk;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface Ed25519PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  alg?: 'EdDSA';
  kid?: string;
}

export interface Ed25519PrivateJwk extends Ed25519PublicJwk {
  d: string;
}

export interface ResolutionResult {
  did: string;
  didDocument: DIDDocument;
  didDocumentMetadata: {
    scid: string;
    versionId: string;
    created: string;
    updated: string;
    deactivated: boolean;
  };
  verified: true;
}

export interface VerificationResult {
  verified: true;
  challengeId: string;
  holderDid: string;
  credentialId: string;
  issuerDid: string;
  credentialType: string[];
  checks: {
    challenge: true;
    audience: true;
    nonce: true;
    replay: true;
    holderDidLog: true;
    presentationSignature: true;
    issuerDidLog: true;
    credentialSignature: true;
    subjectBinding: true;
  };
}
