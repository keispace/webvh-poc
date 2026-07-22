import { randomUUID } from 'node:crypto';
import {
  SignJWT,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWTPayload,
} from 'jose';
import type { AppConfig } from './config';
import { ChallengeStore } from './challenges';
import { requireEd25519PublicJwk } from './crypto';
import { AppError, asErrorMessage } from './errors';
import type { StoredIdentity, VerificationResult } from './types';
import { WebVhService } from './webvh';

const VC_TYPE = 'WebVHExampleCredential';
const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const UNDEFINED_TERMS_CONTEXT = 'https://www.w3.org/ns/credentials/undefined-terms/v2';
const ENVELOPED_VC_TYPE = 'EnvelopedVerifiableCredential';
const ENVELOPED_VC_PREFIX = 'data:application/vc+jwt,';
const CLOCK_TOLERANCE_MS = 2_000;

type ContextValue = string | string[];
type TypeValue = string | string[];

interface CredentialPayload extends JWTPayload {
  '@context': ContextValue;
  id: string;
  type: TypeValue;
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: Record<string, unknown> & { id: string };
}

interface EnvelopedCredential {
  '@context': ContextValue;
  id: string;
  type: TypeValue;
}

interface PresentationPayload extends JWTPayload {
  '@context': ContextValue;
  id: string;
  type: TypeValue;
  holder: string;
  nonce: string;
  verifiableCredential: EnvelopedCredential[];
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AppError(400, 'invalid_token_claim', `${field} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new AppError(400, 'invalid_token_claim', `${field} must be a non-empty string`);
  }
  return value;
}

function requireBaseContext(value: unknown, field: string): ContextValue {
  if (value === VC_CONTEXT) return value;
  if (Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'string') && value[0] === VC_CONTEXT) {
    return value;
  }
  throw new AppError(400, 'invalid_token_claim', `${field} must start with the W3C VC Data Model 2.0 context`);
}

function requireTypes(value: unknown, required: string, field: string): string[] {
  const types = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(types) || types.length === 0 || !types.every((item) => typeof item === 'string')) {
    throw new AppError(400, 'invalid_token_claim', `${field} must be a string or string array`);
  }
  if (!types.includes(required)) {
    throw new AppError(400, 'invalid_token_claim', `${field} must include ${required}`);
  }
  return types;
}

function requireDateTimeStamp(value: unknown, field: string): { value: string; epochMs: number } {
  const timestamp = requireString(value, field);
  const epochMs = Date.parse(timestamp);
  if (!Number.isFinite(epochMs) || !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(timestamp)) {
    throw new AppError(400, 'invalid_token_claim', `${field} must be an XML Schema dateTimeStamp`);
  }
  return { value: timestamp, epochMs };
}

function assertNoLegacyClaims(payload: JWTPayload): void {
  if ('vc' in payload || 'vp' in payload) {
    throw new AppError(400, 'legacy_vc_claim_not_allowed', 'VCDM 2.0 JWT payloads must not contain vc or vp claims');
  }
}

function asCredentialPayload(payload: JWTPayload): {
  credential: CredentialPayload;
  credentialId: string;
  issuerDid: string;
  subjectDid: string;
  types: string[];
} {
  assertNoLegacyClaims(payload);
  requireBaseContext(payload['@context'], '@context');
  const types = requireTypes(payload.type, 'VerifiableCredential', 'type');
  if (!types.includes(VC_TYPE)) {
    throw new AppError(400, 'credential_type_not_allowed', `Credential must include ${VC_TYPE}`);
  }

  const credentialId = requireString(payload.id, 'id');
  const issuerDid = requireString(payload.issuer, 'issuer');
  const subject = requireRecord(payload.credentialSubject, 'credentialSubject');
  const subjectDid = requireString(subject.id, 'credentialSubject.id');
  const validFrom = requireDateTimeStamp(payload.validFrom, 'validFrom');
  const validUntil = requireDateTimeStamp(payload.validUntil, 'validUntil');
  const now = Date.now();
  if (validFrom.epochMs > validUntil.epochMs) {
    throw new AppError(400, 'invalid_credential_validity', 'validFrom must not be after validUntil');
  }
  if (validFrom.epochMs > now + CLOCK_TOLERANCE_MS) {
    throw new AppError(400, 'credential_not_yet_valid', 'Credential is not valid yet');
  }
  if (validUntil.epochMs <= now - CLOCK_TOLERANCE_MS) {
    throw new AppError(400, 'credential_expired', 'Credential has expired');
  }

  if (payload.iss !== undefined && payload.iss !== issuerDid) {
    throw new AppError(400, 'credential_issuer_mismatch', 'JWT iss and credential issuer must be equal');
  }
  if (payload.sub !== undefined && payload.sub !== subjectDid) {
    throw new AppError(400, 'credential_subject_mismatch', 'JWT sub and credentialSubject.id must be equal');
  }
  if (payload.jti !== undefined && payload.jti !== credentialId) {
    throw new AppError(400, 'credential_id_mismatch', 'JWT jti and credential id must be equal');
  }

  return {
    credential: payload as CredentialPayload,
    credentialId,
    issuerDid,
    subjectDid,
    types,
  };
}

function credentialJwtFromEnvelope(value: unknown): string {
  const envelope = requireRecord(value, 'verifiableCredential[0]');
  requireBaseContext(envelope['@context'], 'verifiableCredential[0].@context');
  requireTypes(envelope.type, ENVELOPED_VC_TYPE, 'verifiableCredential[0].type');
  const id = requireString(envelope.id, 'verifiableCredential[0].id');
  if (!id.startsWith(ENVELOPED_VC_PREFIX) || id.length === ENVELOPED_VC_PREFIX.length) {
    throw new AppError(
      400,
      'invalid_enveloped_credential',
      `Enveloped credential id must use ${ENVELOPED_VC_PREFIX}<compact-jwt>`,
    );
  }
  return id.slice(ENVELOPED_VC_PREFIX.length);
}

function asPresentationPayload(payload: JWTPayload): {
  presentation: PresentationPayload;
  holderDid: string;
  credentialJwt: string;
} {
  assertNoLegacyClaims(payload);
  requireBaseContext(payload['@context'], '@context');
  requireTypes(payload.type, 'VerifiablePresentation', 'type');
  const presentationId = requireString(payload.id, 'id');
  const holderDid = requireString(payload.holder, 'holder');
  requireString(payload.nonce, 'nonce');
  if (!Array.isArray(payload.verifiableCredential) || payload.verifiableCredential.length !== 1) {
    throw new AppError(400, 'invalid_presentation', 'This PoC requires exactly one enveloped credential');
  }
  if (payload.jti !== undefined && payload.jti !== presentationId) {
    throw new AppError(400, 'presentation_id_mismatch', 'JWT jti and presentation id must be equal');
  }
  return {
    presentation: payload as PresentationPayload,
    holderDid,
    credentialJwt: credentialJwtFromEnvelope(payload.verifiableCredential[0]),
  };
}

function assertJoseHeader(
  header: ReturnType<typeof decodeProtectedHeader>,
  expectedType: 'vc+jwt' | 'vp+jwt',
  expectedContentType: 'vc' | 'vp',
): string {
  if (header.typ !== expectedType || header.alg !== 'EdDSA') {
    throw new AppError(400, 'invalid_jose_header', `JWT must use typ=${expectedType} and alg=EdDSA`);
  }
  if (header.cty !== undefined && header.cty !== expectedContentType) {
    throw new AppError(400, 'invalid_jose_header', `JWT cty must be ${expectedContentType} when present`);
  }
  return requireString(header.kid, 'kid');
}

export class CredentialService {
  constructor(
    readonly config: AppConfig,
    readonly webvh: WebVhService,
    readonly challenges: ChallengeStore,
    readonly issuer: StoredIdentity,
  ) {}

  async issueCredential(holderDid: string, claims: Record<string, unknown> = {}): Promise<{ credentialJwt: string; credentialId: string }> {
    await this.webvh.resolveStored(holderDid);
    await this.webvh.resolveStored(this.issuer.did);

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + this.config.vcTtlSeconds;
    const credentialId = `urn:uuid:${randomUUID()}`;
    const signer = await importJWK(this.issuer.key.privateJwk, 'EdDSA');
    const credentialJwt = await new SignJWT({
      '@context': [VC_CONTEXT, UNDEFINED_TERMS_CONTEXT],
      id: credentialId,
      type: ['VerifiableCredential', VC_TYPE],
      issuer: this.issuer.did,
      validFrom: new Date(now * 1000).toISOString(),
      validUntil: new Date(expiresAt * 1000).toISOString(),
      credentialSubject: { ...claims, id: holderDid },
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc', kid: this.issuer.key.kid })
      .setIssuer(this.issuer.did)
      .setSubject(holderDid)
      .setJti(credentialId)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .sign(signer);

    return { credentialJwt, credentialId };
  }

  createChallenge(holderDid: string) {
    this.webvh.store.requireByDid(holderDid);
    return this.challenges.create(holderDid, this.config.verifierAudience);
  }

  async createPresentation(challengeId: string, holderDid: string, credentialJwt: string): Promise<{ presentationJwt: string }> {
    const challenge = this.challenges.getOpen(challengeId);
    if (challenge.expectedHolderDid !== holderDid) {
      throw new AppError(400, 'holder_mismatch', 'Challenge was issued for a different holder DID');
    }
    const identity = await this.webvh.ensureJoseSigningMethod(holderDid);
    if (identity.role !== 'holder') throw new AppError(400, 'holder_required', 'An issuer identity cannot create a holder presentation');
    const credential = await this.verifyCredential(credentialJwt);
    if (credential.subjectDid !== holderDid) {
      throw new AppError(400, 'credential_subject_mismatch', 'Credential subject does not match presentation holder');
    }

    const now = Math.floor(Date.now() / 1000);
    const presentationId = `urn:uuid:${randomUUID()}`;
    const signer = await importJWK(identity.key.privateJwk, 'EdDSA');
    const presentationJwt = await new SignJWT({
      '@context': [VC_CONTEXT, UNDEFINED_TERMS_CONTEXT],
      id: presentationId,
      type: ['VerifiablePresentation'],
      holder: holderDid,
      nonce: challenge.nonce,
      verifiableCredential: [
        {
          '@context': VC_CONTEXT,
          id: `${ENVELOPED_VC_PREFIX}${credentialJwt}`,
          type: ENVELOPED_VC_TYPE,
        },
      ],
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'vp+jwt', cty: 'vp', kid: identity.key.kid })
      .setAudience(challenge.audience)
      .setJti(presentationId)
      .setIssuedAt(now)
      .setExpirationTime(Math.min(now + 120, Math.floor(Date.parse(challenge.expiresAt) / 1000)))
      .sign(signer);
    return { presentationJwt };
  }

  async verifyPresentation(challengeId: string, presentationJwt: string): Promise<VerificationResult> {
    const challenge = this.challenges.beginVerification(challengeId);
    try {
      const unverifiedPayload = decodeJwt(presentationJwt);
      const header = decodeProtectedHeader(presentationJwt);
      const kid = assertJoseHeader(header, 'vp+jwt', 'vp');
      const holderDid = requireString(unverifiedPayload.holder, 'holder');
      const { method } = await this.webvh.resolveVerificationMethod(holderDid, kid, 'authentication');
      const verifier = await importJWK(requireEd25519PublicJwk(method.publicKeyJwk), 'EdDSA');
      const verifiedJwt = await jwtVerify(presentationJwt, verifier, {
        algorithms: ['EdDSA'],
        audience: challenge.audience,
        clockTolerance: 2,
      });
      const { presentation, holderDid: verifiedHolderDid, credentialJwt } = asPresentationPayload(verifiedJwt.payload);

      if (holderDid !== verifiedHolderDid || holderDid !== challenge.expectedHolderDid) {
        throw new AppError(400, 'holder_mismatch', 'VP holder and expected holder must be equal');
      }
      if (presentation.nonce !== challenge.nonce) {
        throw new AppError(400, 'nonce_mismatch', 'Presentation nonce does not match the challenge');
      }

      const credential = await this.verifyCredential(credentialJwt);
      if (credential.subjectDid !== holderDid) {
        throw new AppError(400, 'credential_subject_mismatch', 'Credential subject is not bound to the VP holder');
      }

      this.challenges.finishVerification(challengeId);
      return {
        verified: true,
        challengeId,
        holderDid,
        credentialId: credential.credentialId,
        issuerDid: credential.issuerDid,
        credentialType: credential.types,
        checks: {
          challenge: true,
          audience: true,
          nonce: true,
          replay: true,
          holderDidLog: true,
          presentationSignature: true,
          issuerDidLog: true,
          credentialSignature: true,
          subjectBinding: true,
        },
      };
    } catch (error) {
      this.challenges.abortVerification(challengeId);
      if (error instanceof AppError) throw error;
      throw new AppError(400, 'presentation_verification_failed', asErrorMessage(error));
    }
  }

  async verifyCredential(credentialJwt: string): Promise<{
    credentialId: string;
    issuerDid: string;
    subjectDid: string;
    types: string[];
    payload: CredentialPayload;
  }> {
    try {
      const unverifiedPayload = decodeJwt(credentialJwt);
      const header = decodeProtectedHeader(credentialJwt);
      const kid = assertJoseHeader(header, 'vc+jwt', 'vc');
      const issuerDid = requireString(unverifiedPayload.issuer, 'issuer');
      if (issuerDid !== this.issuer.did) throw new AppError(400, 'issuer_not_allowed', 'Credential issuer is not trusted');
      const { method } = await this.webvh.resolveVerificationMethod(issuerDid, kid, 'assertionMethod');
      const verifier = await importJWK(requireEd25519PublicJwk(method.publicKeyJwk), 'EdDSA');
      const verifiedJwt = await jwtVerify(credentialJwt, verifier, {
        algorithms: ['EdDSA'],
        clockTolerance: 2,
      });
      const credential = asCredentialPayload(verifiedJwt.payload);
      if (credential.issuerDid !== this.issuer.did) {
        throw new AppError(400, 'issuer_not_allowed', 'Credential issuer is not trusted');
      }
      await this.webvh.resolveStored(credential.subjectDid);
      return {
        credentialId: credential.credentialId,
        issuerDid: credential.issuerDid,
        subjectDid: credential.subjectDid,
        types: credential.types,
        payload: credential.credential,
      };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError(400, 'credential_verification_failed', asErrorMessage(error));
    }
  }
}
