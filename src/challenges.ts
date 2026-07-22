import { randomBytes, randomUUID } from 'node:crypto';
import { AppError } from './errors';

export interface PresentationChallenge {
  id: string;
  nonce: string;
  audience: string;
  expectedHolderDid: string;
  expiresAt: string;
  status: 'open' | 'verifying' | 'used';
}

export class ChallengeStore {
  readonly #challenges = new Map<string, PresentationChallenge>();

  constructor(private readonly ttlSeconds: number) {}

  create(expectedHolderDid: string, audience: string): PresentationChallenge {
    const challenge: PresentationChallenge = {
      id: randomUUID(),
      nonce: randomBytes(24).toString('base64url'),
      audience,
      expectedHolderDid,
      expiresAt: new Date(Date.now() + this.ttlSeconds * 1000).toISOString(),
      status: 'open',
    };
    this.#challenges.set(challenge.id, challenge);
    return { ...challenge };
  }

  getOpen(id: string): PresentationChallenge {
    const challenge = this.#require(id);
    this.#assertUsable(challenge);
    return { ...challenge };
  }

  beginVerification(id: string): PresentationChallenge {
    const challenge = this.#require(id);
    this.#assertUsable(challenge);
    challenge.status = 'verifying';
    return { ...challenge };
  }

  finishVerification(id: string): void {
    const challenge = this.#require(id);
    if (challenge.status !== 'verifying') throw new AppError(409, 'challenge_state_invalid', 'Challenge is not being verified');
    challenge.status = 'used';
  }

  abortVerification(id: string): void {
    const challenge = this.#challenges.get(id);
    if (challenge?.status === 'verifying') challenge.status = 'open';
  }

  #require(id: string): PresentationChallenge {
    const challenge = this.#challenges.get(id);
    if (!challenge) throw new AppError(404, 'challenge_not_found', 'Unknown presentation challenge');
    return challenge;
  }

  #assertUsable(challenge: PresentationChallenge): void {
    if (challenge.status === 'used') throw new AppError(409, 'challenge_replayed', 'Presentation challenge has already been used');
    if (challenge.status === 'verifying') throw new AppError(409, 'challenge_in_use', 'Presentation challenge is already being verified');
    if (Date.parse(challenge.expiresAt) <= Date.now()) throw new AppError(410, 'challenge_expired', 'Presentation challenge has expired');
  }
}
