type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

type DataIntegrityProofPurpose =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

export interface VerificationMethod {
  id?: string;
  type: string;
  controller?: string;
  publicKeyMultibase?: string;
  secretKeyMultibase?: string;
  purpose?: DataIntegrityProofPurpose;
  publicKeyJwk?: JsonObject;
  use?: string;
}

export interface DIDDocument {
  '@context'?: string | string[] | object | object[];
  id?: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  verificationMethod?: VerificationMethod[];
  service?: Array<{
    id?: string;
    type: string | string[];
    serviceEndpoint?: string | string[] | JsonValue;
    [key: string]: unknown;
  }>;
}

interface DataIntegrityProof {
  id?: string;
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  verificationMethod: string;
  created: string;
  proofValue: string;
  proofPurpose: DataIntegrityProofPurpose;
}

interface WitnessEntry {
  id: string;
}

interface WitnessParameter {
  threshold?: number;
  witnesses?: WitnessEntry[];
}

export interface DIDLogEntry {
  versionId: string;
  versionTime: string;
  parameters: {
    method?: string;
    scid?: string;
    updateKeys?: string[];
    nextKeyHashes?: string[];
    portable?: boolean;
    witness?: WitnessParameter;
    watchers?: string[] | null;
    deactivated?: boolean;
  };
  state: DIDDocument;
  proof?: DataIntegrityProof[];
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

export interface Ed25519PublicJwk extends JsonObject {
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
