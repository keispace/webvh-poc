import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { updateDID } from 'didwebvh-ts';
import type { FastifyInstance } from 'fastify';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { afterEach, describe, expect, test } from 'vitest';
import { createApp, type AppServices } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Ed25519WebVhCrypto, generateEd25519Key } from '../src/crypto.js';

interface Fixture {
    app: FastifyInstance;
    services: AppServices;
    dataDir: string;
}

const fixtures: Fixture[] = [];

async function fixture(): Promise<Fixture> {
    const dataDir = await mkdtemp(join(tmpdir(), 'webvh-poc-'));
    const created = await createApp(
        loadConfig({
            DID_DOMAIN: 'example.com',
            DATA_DIR: dataDir,
            ISSUER_SLUG: 'poc',
            VERIFIER_AUDIENCE: 'https://example.com/verifier',
            CHALLENGE_TTL_SECONDS: '300',
            VC_TTL_SECONDS: '3600',
        }),
    );
    const result = { ...created, dataDir };
    fixtures.push(result);
    return result;
}

afterEach(async () => {
    await Promise.all(
        fixtures.splice(0).map(async ({ app, dataDir }) => {
            await app.close();
            await rm(dataDir, { recursive: true, force: true });
        }),
    );
});

async function createHolder(app: FastifyInstance) {
    const keyResponse = await app.inject({ method: 'POST', url: '/api/keys' });
    expect(keyResponse.statusCode).toBe(201);
    const initialKey = keyResponse.json() as {
        keyId: string;
        pathId: string;
        publicKeyMultibase: string;
        privateJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string };
        privateKeyReturned: boolean;
    };
    const response = await app.inject({ method: 'POST', url: '/api/dids', payload: { keyId: initialKey.keyId } });
    expect(response.statusCode).toBe(201);
    const holder = response.json() as {
        did: string;
        pathId: string;
        logPath: string;
        logUrl: string;
        currentPublicKeyMultibase: string;
        sourceKeyId: string;
        pathDerivedFromInitialPublicKey: boolean;
    };
    return { ...holder, initialKey };
}

async function issue(app: FastifyInstance, holderDid: string) {
    const response = await app.inject({
        method: 'POST',
        url: '/api/credentials',
        payload: { holderDid, claims: { name: 'Alice', participation: 'active' } },
    });
    expect(response.statusCode).toBe(201);
    return response.json() as { credentialJwt: string; credentialId: string; issuerDid: string };
}

async function present(app: FastifyInstance, holderDid: string, credentialJwt: string) {
    const challengeResponse = await app.inject({
        method: 'POST',
        url: '/api/presentations/challenges',
        payload: { holderDid },
    });
    expect(challengeResponse.statusCode).toBe(201);
    const challenge = challengeResponse.json() as { id: string; nonce: string; audience: string };

    const presentationResponse = await app.inject({
        method: 'POST',
        url: '/api/presentations',
        payload: { challengeId: challenge.id, holderDid, credentialJwt },
    });
    expect(presentationResponse.statusCode).toBe(201);
    const presentation = presentationResponse.json() as { presentationJwt: string };
    return { challenge, presentation };
}

describe('independent did:webvh VC/VP server', () => {
    test('serves the interactive PoC viewer', async () => {
        const { app } = await fixture();
        const response = await app.inject({ method: 'GET', url: '/' });
        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toContain('text/html');
        expect(response.body).toContain('did:webvh VC / VP PoC Console');
        expect(response.body).toContain('전체 E2E 실행');
        expect(response.body).toContain('Holder Key 생성');
        expect(response.body).toContain('DID Key Rotation');
        expect(response.body).toContain('API Doc');
    });

    test('serves an interactive API document for all PoC operations', async () => {
        const { app } = await fixture();
        const response = await app.inject({ method: 'GET', url: '/api-doc' });
        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toContain('text/html');
        expect(response.body).toContain('Same-origin API explorer');
        expect(response.body).toContain("path:'/api/keys'");
        expect(response.body).toContain("path:'/api/dids/rotate'");
        expect(response.body).toContain("path:'/api/verifications'");
        expect(response.body).toContain('권장 E2E 호출');
    });

    test('creates and resolves a WebVH DID, issues a VC, and verifies a holder VP once', async () => {
        const { app } = await fixture();
        const holder = await createHolder(app);

        expect(holder.pathId).toMatch(/^5[1-9A-HJ-NP-Za-km-z]{47}$/);
        expect(holder.pathId).toBe(holder.initialKey.pathId);
        expect(holder.sourceKeyId).toBe(holder.initialKey.keyId);
        expect(holder.currentPublicKeyMultibase).toBe(holder.initialKey.publicKeyMultibase);
        expect(holder.initialKey.privateKeyReturned).toBe(true);
        expect(holder.initialKey.privateJwk).toMatchObject({
            kty: 'OKP',
            crv: 'Ed25519',
            x: expect.any(String),
            d: expect.any(String),
        });
        expect(holder.pathDerivedFromInitialPublicKey).toBe(true);
        expect(holder.did).toBe(`did:webvh:${holder.did.split(':')[2]}:example.com:${holder.pathId}`);
        expect(holder.logUrl).toBe(`https://example.com/${holder.pathId}/did.jsonl`);

        const reusedKey = await app.inject({
            method: 'POST',
            url: '/api/dids',
            payload: { keyId: holder.initialKey.keyId },
        });
        expect(reusedKey.statusCode).toBe(404);
        expect(reusedKey.json()).toMatchObject({ error: { code: 'pending_key_not_found' } });

        const logResponse = await app.inject({ method: 'GET', url: holder.logPath });
        expect(logResponse.statusCode).toBe(200);
        expect(logResponse.headers['content-type']).toContain('text/jsonl');
        expect(logResponse.body.trim().split('\n')).toHaveLength(1);

        const resolutionResponse = await app.inject({
            method: 'GET',
            url: `/api/dids/resolve?did=${encodeURIComponent(holder.did)}`,
        });
        expect(resolutionResponse.statusCode).toBe(200);
        expect(resolutionResponse.json()).toMatchObject({
            did: holder.did,
            verified: true,
            didDocument: {
                id: holder.did,
                verificationMethod: [{
                    type: 'JsonWebKey',
                    controller: holder.did,
                    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: expect.any(String) },
                }],
            },
        });

        const credential = await issue(app, holder.did);
        const credentialHeader = decodeProtectedHeader(credential.credentialJwt);
        const credentialPayload = decodeJwt(credential.credentialJwt);
        expect(credentialHeader).toMatchObject({ alg: 'EdDSA', typ: 'vc+jwt', cty: 'vc' });
        expect(credentialPayload).not.toHaveProperty('vc');
        expect(credentialPayload).not.toHaveProperty('vp');
        expect(credentialPayload).toMatchObject({
            '@context': [
                'https://www.w3.org/ns/credentials/v2',
                'https://www.w3.org/ns/credentials/undefined-terms/v2',
            ],
            id: credential.credentialId,
            type: ['VerifiableCredential', 'WebVHExampleCredential'],
            issuer: credential.issuerDid,
            iss: credential.issuerDid,
            sub: holder.did,
            jti: credential.credentialId,
            validFrom: expect.any(String),
            validUntil: expect.any(String),
            credentialSubject: { id: holder.did, name: 'Alice', participation: 'active' },
        });
        const credentialVerification = await app.inject({
            method: 'POST',
            url: '/api/credentials/verify',
            payload: { credentialJwt: credential.credentialJwt },
        });
        expect(credentialVerification.statusCode).toBe(200);
        expect(credentialVerification.json()).toMatchObject({
            verified: true,
            credentialId: credential.credentialId,
            subjectDid: holder.did,
        });

        const { challenge, presentation } = await present(app, holder.did, credential.credentialJwt);
        const presentationHeader = decodeProtectedHeader(presentation.presentationJwt);
        const presentationPayload = decodeJwt(presentation.presentationJwt);
        expect(presentationHeader).toMatchObject({ alg: 'EdDSA', typ: 'vp+jwt', cty: 'vp' });
        expect(presentationPayload).not.toHaveProperty('vc');
        expect(presentationPayload).not.toHaveProperty('vp');
        expect(presentationPayload).toMatchObject({
            '@context': [
                'https://www.w3.org/ns/credentials/v2',
                'https://www.w3.org/ns/credentials/undefined-terms/v2',
            ],
            id: expect.stringMatching(/^urn:uuid:/),
            type: ['VerifiablePresentation'],
            holder: holder.did,
            aud: challenge.audience,
            nonce: challenge.nonce,
            verifiableCredential: [{
                '@context': 'https://www.w3.org/ns/credentials/v2',
                type: 'EnvelopedVerifiableCredential',
                id: `data:application/vc+jwt,${credential.credentialJwt}`,
            }],
        });
        const verificationResponse = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: { challengeId: challenge.id, presentationJwt: presentation.presentationJwt },
        });
        expect(verificationResponse.statusCode).toBe(200);
        expect(verificationResponse.json()).toMatchObject({
            verified: true,
            holderDid: holder.did,
            credentialId: credential.credentialId,
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
        });

        const replayResponse = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: { challengeId: challenge.id, presentationJwt: presentation.presentationJwt },
        });
        expect(replayResponse.statusCode).toBe(409);
        expect(replayResponse.json()).toMatchObject({ error: { code: 'challenge_replayed' } });
    });

    test('rejects a tampered DID log', async () => {
        const { app, services } = await fixture();
        const holder = await createHolder(app);
        const stored = services.store.requireByDid(holder.did);
        const tampered = structuredClone(stored.log);
        tampered[0]!.state.alsoKnownAs = ['did:key:tampered'];

        const response = await app.inject({
            method: 'POST',
            url: '/api/dids/validate',
            payload: { did: holder.did, log: tampered },
        });
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ error: { code: 'did_log_verification_failed' } });
    });

    test('rejects a tampered VP without consuming the valid challenge', async () => {
        const { app } = await fixture();
        const holder = await createHolder(app);
        const credential = await issue(app, holder.did);
        const { challenge, presentation } = await present(app, holder.did, credential.credentialJwt);
        const [header, payload, encodedSignature] = presentation.presentationJwt.split('.');
        const signature = Buffer.from(encodedSignature!, 'base64url');
        signature[0] = signature[0]! ^ 0x01;
        const tamperedJwt = `${header}.${payload}.${signature.toString('base64url')}`;

        const rejected = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: { challengeId: challenge.id, presentationJwt: tamperedJwt },
        });
        expect(rejected.statusCode).toBe(400);

        const accepted = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: { challengeId: challenge.id, presentationJwt: presentation.presentationJwt },
        });
        expect(accepted.statusCode).toBe(200);
        expect(accepted.json()).toMatchObject({ verified: true });
    });

    test('rejects presenting a credential for a different holder', async () => {
        const { app } = await fixture();
        const alice = await createHolder(app);
        const bob = await createHolder(app);
        const aliceCredential = await issue(app, alice.did);

        const challenge = await app.inject({
            method: 'POST',
            url: '/api/presentations/challenges',
            payload: { holderDid: bob.did },
        });
        const challengeId = (challenge.json() as { id: string }).id;
        const response = await app.inject({
            method: 'POST',
            url: '/api/presentations',
            payload: { challengeId, holderDid: bob.did, credentialJwt: aliceCredential.credentialJwt },
        });
        expect(response.statusCode).toBe(400);
        expect(response.json()).toMatchObject({ error: { code: 'credential_subject_mismatch' } });
    });

    test('rotates the holder key without changing the DID and rejects the old VP key', async () => {
        const { app } = await fixture();
        const holder = await createHolder(app);
        const credential = await issue(app, holder.did);
        const beforeRotation = await present(app, holder.did, credential.credentialJwt);

        const rotationResponse = await app.inject({
            method: 'POST',
            url: '/api/dids/rotate',
            payload: { did: holder.did },
        });
        expect(rotationResponse.statusCode).toBe(200);
        const rotation = rotationResponse.json() as {
            did: string;
            pathId: string;
            logEntries: number;
            rotation: {
                previousKid: string;
                currentKid: string;
                previousPublicKeyMultibase: string;
                currentPublicKeyMultibase: string;
                didChanged: boolean;
                pathChanged: boolean;
                versionId: string;
            };
        };
        expect(rotation.did).toBe(holder.did);
        expect(rotation.pathId).toBe(holder.pathId);
        expect(rotation.logEntries).toBe(2);
        expect(rotation.rotation.previousKid).not.toBe(rotation.rotation.currentKid);
        expect(rotation.rotation.previousPublicKeyMultibase).toBe(holder.initialKey.publicKeyMultibase);
        expect(rotation.rotation.currentPublicKeyMultibase).not.toBe(rotation.rotation.previousPublicKeyMultibase);
        expect(rotation.rotation.didChanged).toBe(false);
        expect(rotation.rotation.pathChanged).toBe(false);
        expect(rotation.rotation.versionId).toMatch(/^2-/);

        const oldKeyVerification = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: {
                challengeId: beforeRotation.challenge.id,
                presentationJwt: beforeRotation.presentation.presentationJwt,
            },
        });
        expect(oldKeyVerification.statusCode).toBe(400);
        expect(oldKeyVerification.json()).toMatchObject({ error: { code: 'verification_method_not_authorized' } });

        const rotatedPresentation = await app.inject({
            method: 'POST',
            url: '/api/presentations',
            payload: {
                challengeId: beforeRotation.challenge.id,
                holderDid: holder.did,
                credentialJwt: credential.credentialJwt,
            },
        });
        expect(rotatedPresentation.statusCode).toBe(201);
        const accepted = await app.inject({
            method: 'POST',
            url: '/api/verifications',
            payload: {
                challengeId: beforeRotation.challenge.id,
                presentationJwt: (rotatedPresentation.json() as { presentationJwt: string }).presentationJwt,
            },
        });
        expect(accepted.statusCode).toBe(200);
        expect(accepted.json()).toMatchObject({ verified: true, holderDid: holder.did });

        const logResponse = await app.inject({ method: 'GET', url: holder.logPath });
        expect(logResponse.body.trim().split('\n')).toHaveLength(2);
    });

    test('migrates a persisted legacy Multikey issuer to JsonWebKey on restart', async () => {
        const first = await fixture();
        const issuer = first.services.issuer;
        const legacyKey = generateEd25519Key('assertionMethod');
        const legacyUpdate = await updateDID({
            log: issuer.log,
            signer: new Ed25519WebVhCrypto(issuer.key.publicKeyMultibase, issuer.key.privateJwk),
            verifier: first.services.webvh.verifier,
            updateKeys: [legacyKey.publicKeyMultibase],
            verificationMethods: [{
                type: 'Multikey',
                publicKeyMultibase: legacyKey.publicKeyMultibase,
                purpose: 'assertionMethod',
            }],
        });
        const legacyMethod = legacyUpdate.doc.verificationMethod?.[0];
        expect(legacyMethod).toMatchObject({ type: 'Multikey' });
        expect(legacyMethod?.id).toEqual(expect.any(String));
        await first.services.store.update({
            ...issuer,
            didDocument: legacyUpdate.doc,
            log: legacyUpdate.log,
            key: {
                kid: legacyMethod!.id!,
                publicKeyMultibase: legacyKey.publicKeyMultibase,
                publicJwk: legacyKey.publicJwk,
                privateJwk: legacyKey.privateJwk,
            },
            updatedAt: new Date().toISOString(),
        });

        fixtures.splice(fixtures.indexOf(first), 1);
        await first.app.close();
        const reopened = await createApp(first.services.webvh.config);
        const second = { ...reopened, dataDir: first.dataDir };
        fixtures.push(second);

        expect(second.services.issuer.did).toBe(issuer.did);
        expect(second.services.issuer.log).toHaveLength(3);
        expect(second.services.issuer.didDocument.verificationMethod?.[0]).toMatchObject({
            type: 'JsonWebKey',
            publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: expect.any(String) },
        });

        const holder = await createHolder(second.app);
        const credential = await issue(second.app, holder.did);
        const verification = await second.app.inject({
            method: 'POST',
            url: '/api/credentials/verify',
            payload: { credentialJwt: credential.credentialJwt },
        });
        expect(verification.statusCode).toBe(200);
        expect(verification.json()).toMatchObject({ verified: true, issuerDid: issuer.did });
    });
});
