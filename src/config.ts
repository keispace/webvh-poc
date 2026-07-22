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

// PoC runtime settings. Edit these values directly before deploying.
const settings = {
    host: '127.0.0.1',
    port: 3000,
    didDomain: 'webvh-poc.vercel.app',
    dataDir: '/tmp/webvh-poc/webvh-poc.vercel.app',
    issuerSlug: 'poc',
    verifierAudience: 'https://webvh-poc.vercel.app/verifier',
    challengeTtlSeconds: 300,
    vcTtlSeconds: 3600,
} as const;

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

export function loadConfig(): AppConfig {
    const didDomain = validateDidDomain(settings.didDomain);
    return {
        host: process.env.HOST ?? settings.host,
        port: positiveInteger(process.env.PORT, settings.port, 'PORT'),
        didDomain,
        dataDir: resolve(settings.dataDir),
        issuerSlug: validateSlug(settings.issuerSlug),
        verifierAudience: settings.verifierAudience,
        challengeTtlSeconds: settings.challengeTtlSeconds,
        vcTtlSeconds: settings.vcTtlSeconds,
    };
}
