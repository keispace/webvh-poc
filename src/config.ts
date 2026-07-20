import { resolve } from 'node:path';

export interface AppConfig {
    host: string;
    port: number;
    didDomain: string;
    dataDir: string;
    issuerSlug: string;
    verifierAudience: string;
    challengeTtlSeconds: number;
    vcTtlSeconds: number;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
    if (value === undefined) return fallback;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new Error(`${name} must be a positive integer`);
    }
    return parsed;
}

function validateDidDomain(value: string): string {
    const normalized = value.trim().toLowerCase();
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(normalized)) {
        throw new Error('DID_DOMAIN must be a DNS hostname without a scheme, port, path, query, or fragment');
    }
    return normalized;
}

function validateSlug(value: string): string {
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(normalized)) {
        throw new Error('ISSUER_SLUG must contain only lowercase letters, digits, and internal hyphens');
    }
    return normalized;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
    const didDomain = validateDidDomain(env.DID_DOMAIN ?? 'example.com');
    return {
        host: env.HOST ?? '127.0.0.1',
        port: positiveInteger(env.PORT, 3010, 'PORT'),
        didDomain,
        dataDir: resolve(env.DATA_DIR ?? `.data/${didDomain}`),
        issuerSlug: validateSlug(env.ISSUER_SLUG ?? 'poc'),
        verifierAudience: env.VERIFIER_AUDIENCE ?? 'https://example.com/verifier',
        challengeTtlSeconds: positiveInteger(env.CHALLENGE_TTL_SECONDS, 300, 'CHALLENGE_TTL_SECONDS'),
        vcTtlSeconds: positiveInteger(env.VC_TTL_SECONDS, 3600, 'VC_TTL_SECONDS'),
    };
}
