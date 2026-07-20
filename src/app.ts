import { readFile } from 'node:fs/promises';
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import { ChallengeStore } from './challenges.js';
import type { AppConfig } from './config.js';
import { CredentialService } from './credentials.js';
import { AppError } from './errors.js';
import { PendingHolderKeyStore, publicPendingKey } from './holder-keys.js';
import { IdentityStore } from './store.js';
import type { DIDLog, StoredIdentity } from './types.js';
import { WebVhService } from './webvh.js';

export interface AppServices {
  store: IdentityStore;
  webvh: WebVhService;
  credentials: CredentialService;
  holderKeys: PendingHolderKeyStore;
  issuer: StoredIdentity;
}

export interface CreatedApp {
  app: FastifyInstance;
  services: AppServices;
}

function requireRecord(value: unknown, name = 'body'): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AppError(400, 'invalid_request', `${name} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new AppError(400, 'invalid_request', `${name} must be a non-empty string`);
  }
  return value;
}

function optionalClaims(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  return requireRecord(value, 'claims');
}

function publicIdentity(identity: StoredIdentity, webvh: WebVhService) {
  const latestEntry = identity.log.at(-1);
  return {
    role: identity.role,
    pathId: identity.role === 'holder' ? identity.path : identity.slug,
    logPath: `/${identity.path}/did.jsonl`,
    did: identity.did,
    logUrl: webvh.logUrl(identity),
    didDocument: identity.didDocument,
    createdAt: identity.createdAt,
    updatedAt: identity.updatedAt ?? null,
    currentKid: identity.key.kid,
    currentPublicKeyMultibase: identity.key.publicKeyMultibase,
    versionId: latestEntry?.versionId ?? null,
    logEntries: identity.log.length,
  };
}

export async function createApp(config: AppConfig, options: { logger?: boolean } = {}): Promise<CreatedApp> {
  const store = new IdentityStore(config.dataDir);
  await store.init();
  const webvh = new WebVhService(config, store);
  const issuer = await webvh.ensureIssuer();
  const challenges = new ChallengeStore(config.challengeTtlSeconds);
  const holderKeys = new PendingHolderKeyStore();
  const credentials = new CredentialService(config, webvh, challenges, issuer);
  const app = Fastify({ logger: options.logger ?? false, bodyLimit: 1024 * 1024 });
  const viewerHtml = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const apiDocHtml = await readFile(new URL('../public/api-doc.html', import.meta.url), 'utf8');

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({ error: { code: error.code, message: error.message } });
    }
    app.log.error(error);
    return reply.status(500).send({ error: { code: 'internal_error', message: 'Internal server error' } });
  });

  app.get('/', async (_request, reply) => reply.type('text/html; charset=utf-8').send(viewerHtml));
  app.get('/viewer', async (_request, reply) => reply.type('text/html; charset=utf-8').send(viewerHtml));
  app.get('/api-doc', async (_request, reply) => reply.type('text/html; charset=utf-8').send(apiDocHtml));
  app.get('/health', async () => ({ status: 'ok', issuerDid: issuer.did }));

  app.get('/api/issuer', async () => publicIdentity(issuer, webvh));

  app.post('/api/keys', async (_request, reply) => {
    const pending = holderKeys.generate();
    return reply.status(201).send(publicPendingKey(pending));
  });

  app.get('/api/dids', async () => ({
    items: store.list().map((identity) => publicIdentity(identity, webvh)),
  }));

  app.post('/api/dids', async (request, reply) => {
    const body = requireRecord(request.body);
    const pending = holderKeys.consume(requireString(body.keyId, 'keyId'));
    const identity = await webvh.createHolderIdentity(pending.key);
    return reply.status(201).send({
      ...publicIdentity(identity, webvh),
      sourceKeyId: pending.keyId,
      pathDerivedFromInitialPublicKey: identity.path === pending.pathId,
    });
  });

  app.get('/api/dids/resolve', async (request) => {
    const query = requireRecord(request.query, 'query');
    return webvh.resolveStored(requireString(query.did, 'did'));
  });

  app.post('/api/dids/validate', async (request) => {
    const body = requireRecord(request.body);
    const did = requireString(body.did, 'did');
    if (!Array.isArray(body.log)) throw new AppError(400, 'invalid_request', 'log must be a JSON array');
    return webvh.validateLog(did, body.log as DIDLog);
  });

  app.post('/api/dids/rotate', async (request) => {
    const body = requireRecord(request.body);
    const rotated = await webvh.rotateIdentity(requireString(body.did, 'did'));
    return {
      ...publicIdentity(rotated.identity, webvh),
      rotation: {
        previousKid: rotated.previousKid,
        currentKid: rotated.currentKid,
        previousPublicKeyMultibase: rotated.previousPublicKeyMultibase,
        currentPublicKeyMultibase: rotated.currentPublicKeyMultibase,
        didChanged: false,
        pathChanged: false,
        versionId: rotated.versionId,
      },
    };
  });

  app.post('/api/credentials', async (request, reply) => {
    const body = requireRecord(request.body);
    const issued = await credentials.issueCredential(
      requireString(body.holderDid, 'holderDid'),
      optionalClaims(body.claims),
    );
    return reply.status(201).send({ ...issued, issuerDid: issuer.did, type: 'WebVHExampleCredential' });
  });

  app.post('/api/credentials/verify', async (request) => {
    const body = requireRecord(request.body);
    const result = await credentials.verifyCredential(requireString(body.credentialJwt, 'credentialJwt'));
    return {
      verified: true,
      credentialId: result.credentialId,
      issuerDid: result.issuerDid,
      subjectDid: result.subjectDid,
      credentialType: result.types,
    };
  });

  app.post('/api/presentations/challenges', async (request, reply) => {
    const body = requireRecord(request.body);
    const challenge = credentials.createChallenge(requireString(body.holderDid, 'holderDid'));
    return reply.status(201).send(challenge);
  });

  app.post('/api/presentations', async (request, reply) => {
    const body = requireRecord(request.body);
    const presentation = await credentials.createPresentation(
      requireString(body.challengeId, 'challengeId'),
      requireString(body.holderDid, 'holderDid'),
      requireString(body.credentialJwt, 'credentialJwt'),
    );
    return reply.status(201).send(presentation);
  });

  app.post('/api/verifications', async (request) => {
    const body = requireRecord(request.body);
    return credentials.verifyPresentation(
      requireString(body.challengeId, 'challengeId'),
      requireString(body.presentationJwt, 'presentationJwt'),
    );
  });

  app.post('/api/demo/run', async () => {
    const pending = holderKeys.generate();
    const identity = await webvh.createHolderIdentity(holderKeys.consume(pending.keyId).key);
    const resolution = await webvh.resolveStored(identity.did);
    const credential = await credentials.issueCredential(identity.did, {
      name: 'WebVH PoC Holder',
      participation: 'active',
    });
    const credentialVerification = await credentials.verifyCredential(credential.credentialJwt);
    const challenge = credentials.createChallenge(identity.did);
    const presentation = await credentials.createPresentation(challenge.id, identity.did, credential.credentialJwt);
    const verification = await credentials.verifyPresentation(challenge.id, presentation.presentationJwt);
    return {
      key: publicPendingKey(pending),
      did: publicIdentity(identity, webvh),
      resolution,
      credential: {
        credentialJwt: credential.credentialJwt,
        credentialId: credentialVerification.credentialId,
        verified: true,
      },
      presentation: { presentationJwt: presentation.presentationJwt, verification },
    };
  });

  async function sendDidLog(path: string, reply: FastifyReply) {
    const identity = store.getByPath(path);
    if (!identity) throw new AppError(404, 'did_not_found', 'DID log not found');
    return reply.type('text/jsonl; charset=utf-8').send(webvh.serializeLog(identity.log));
  }

  app.get<{ Params: { pathId: string } }>('/:pathId/did.jsonl', async (request, reply) =>
    sendDidLog(request.params.pathId, reply),
  );
  app.get<{ Params: { slug: string } }>('/issuer/:slug/did.jsonl', async (request, reply) =>
    sendDidLog(`issuer/${request.params.slug}`, reply),
  );

  return { app, services: { store, webvh, credentials, holderKeys, issuer } };
}
