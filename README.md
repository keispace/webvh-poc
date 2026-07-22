# did:webvh VC/VP PoC

[한국어](./README.ko.md)

An independent proof-of-concept server for creating, publishing, resolving, and rotating `did:webvh` identifiers, issuing W3C VC Data Model 2.0 JWT Verifiable Credentials, and submitting challenge-bound JWT Verifiable Presentations.

The project is intentionally self-contained. It includes an embedded holder, issuer, verifier, JSONL log host, interactive PoC console, and a Swagger-like same-origin API explorer.

## What it demonstrates

- Holder DID: `did:webvh:{SCID}:webvh-poc.vercel.app:{SS58(initial-public-key)}`
- Issuer DID: `did:webvh:{SCID}:webvh-poc.vercel.app:issuer:poc`
- DID log URL: `https://webvh-poc.vercel.app/{SS58(initial-public-key)}/did.jsonl`
- `did:webvh` v1.0 history with `eddsa-jcs-2022` proofs and hash-chain validation
- Key-first creation: Ed25519 key generation followed by one-time `keyId` consumption during genesis
- VC issuance: VCDM 2.0 Ed25519 `vc+jwt` signed by the issuer `assertionMethod`
- VP submission: VCDM 2.0 Ed25519 `vp+jwt` signed by the holder `authentication` method
- Verification of DID logs, JWT signatures, expiry, audience, nonce, replay protection, and VC subject/VP holder binding
- Key rotation that changes the active public key and verification-method fragment while preserving the DID, SCID, and inception-key path

The final path segment is a project-specific convention, not a requirement of the `did:webvh` specification. It is the generic SS58 prefix `42` encoding of the initial Ed25519 public key and remains stable after rotation.

## VC/VP profile

The VC/VP flow follows W3C VC Data Model 2.0 and Securing Verifiable Credentials using JOSE and COSE:

- VC and VP properties are placed directly in the JWT Claims Set; legacy nested `vc` and `vp` claims are not used.
- Protected headers use `typ=vc+jwt, cty=vc` and `typ=vp+jwt, cty=vp`.
- DID Document authentication and assertion methods use `JsonWebKey` with a public Ed25519 `publicKeyJwk`. WebVH update authorization continues to use the Multikey required by the DID method.
- A secured VC inside a VP is represented as an `EnvelopedVerifiableCredential` whose `id` is a `data:application/vc+jwt,...` URL.
- VC validity is expressed with `validFrom` and `validUntil`; JWT `iat` and `exp` describe the signature lifetime.
- The mock credential type and arbitrary subject claims use the standard `https://www.w3.org/ns/credentials/undefined-terms/v2` fallback context. A real interoperable credential should replace it with a published, stable application vocabulary/context.

## User interfaces

After starting the Next.js app, open:

- [http://127.0.0.1:3000/](http://127.0.0.1:3000/) — step-by-step DID, VC, VP, and rotation console
- [http://127.0.0.1:3000/api-doc](http://127.0.0.1:3000/api-doc) — API descriptions, request/response examples, editable requests, and direct same-origin calls

The API explorer carries response values such as `keyId`, holder DID, credential JWT, challenge ID, and presentation JWT into dependent requests in browser memory. Its recommended E2E action runs the complete key → DID → VC → VP → rotation sequence.

## Requirements and commands

Node.js 22 or later is required.

```bash
npm install
npm run check
npm test
npm run build
npm run demo
npm run dev
```

The default app address is `http://127.0.0.1:3000`. `npm run demo` executes the full flow through the in-process API router and prints the signed JWTs and verification results.

## Docker

Docker is optional. It pins Node.js and production dependencies so the PoC can be reproduced without installing Node.js on the host.

```bash
docker build -t webvh-poc .
docker run --rm -p 3000:3000 webvh-poc
```

The container listens on `0.0.0.0:3000`; open `http://127.0.0.1:3000`. The first `3000` in `-p 3000:3000` is the host port, so `-p 8080:3000` exposes the same container at `http://127.0.0.1:8080`.

The container writes issuer and holder private state under `/tmp/webvh-poc/webvh-poc.vercel.app`. It is disposable PoC state and is removed with `--rm`.

## API overview

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/`, `/viewer` | Interactive step-by-step PoC console |
| `GET` | `/api-doc` | Interactive API reference and shared-context explorer |
| `GET` | `/health` | Server and issuer readiness |
| `GET` | `/api/issuer` | Issuer DID and current public document |
| `POST` | `/api/keys` | Generate an Ed25519 holder key, private/public JWK, SS58 path, and one-time `keyId` |
| `GET` | `/api/dids` | List stored public identity projections |
| `POST` | `/api/dids` | Consume a `keyId` and create a holder WebVH genesis log |
| `GET` | `/api/dids/resolve?did=...` | Resolve and verify a stored DID history |
| `POST` | `/api/dids/validate` | Verify a client-supplied DID log |
| `POST` | `/api/dids/rotate` | Rotate holder update/authentication keys |
| `GET` | `/:ss58/did.jsonl` | Serve a public holder DID log |
| `GET` | `/issuer/:slug/did.jsonl` | Serve the public issuer DID log |
| `POST` | `/api/credentials` | Issue a `WebVHExampleCredential` |
| `POST` | `/api/credentials/verify` | Verify a credential independently |
| `POST` | `/api/presentations/challenges` | Create an audience/nonce challenge |
| `POST` | `/api/presentations` | Create a holder-signed VP |
| `POST` | `/api/verifications` | Verify a VP and consume its challenge |
| `POST` | `/api/demo/run` | Run the complete flow in one request |

## Minimal manual flow

Generate a holder key:

```bash
curl -sS -X POST http://127.0.0.1:3000/api/keys
```

Use the returned `keyId` to create a DID:

```bash
curl -sS http://127.0.0.1:3000/api/dids \
  -H 'content-type: application/json' \
  -d '{"keyId":"<pending-key-id>"}'
```

Use the returned DID to issue a credential:

```bash
curl -sS http://127.0.0.1:3000/api/credentials \
  -H 'content-type: application/json' \
  -d '{"holderDid":"<holder-did>","claims":{"name":"Alice","status":"active"}}'
```

Continue with `/api/presentations/challenges`, `/api/presentations`, and `/api/verifications`, or call `POST /api/demo/run` for the complete flow.

## Configuration

Next.js handles the listener port itself. Edit the `settings` constant in `src/config.ts` before running or deploying:

- `didDomain` — DNS hostname embedded in DIDs; set this to the deployed domain without `https://`
- `dataDir` — private key and DID log storage; the PoC default is `/tmp/webvh-poc/webvh-poc.vercel.app`
- `verifierAudience` — exact VP audience, normally `https://<didDomain>/verifier`
- `issuerSlug`, `challengeTtlSeconds`, and `vcTtlSeconds` — PoC runtime settings

For public resolution, configure TLS and reverse-proxy routing for:

```text
https://webvh-poc.vercel.app/*/did.jsonl
https://webvh-poc.vercel.app/issuer/*/did.jsonl
```

The PoC is configured for the Vercel production hostname `webvh-poc.vercel.app`.

## Security limitations

This is an interoperability PoC, not a production identity service.

- `POST /api/keys` and both UIs deliberately return and display the private JWK so the key flow is observable. Remove this behavior outside an isolated PoC.
- A newly generated pending holder key stays in memory for up to ten minutes. Once it is consumed to create a DID, the active issuer/holder private key and DID history are stored as mode `0600` files under `DATA_DIR`; they are not encrypted or protected by a KMS/HSM.
- The holder is embedded in the server and signs VPs on behalf of the caller; it is not a wallet architecture.
- Registration APIs have no authentication, authorization, rate limiting, or audit trail.
- Key recovery, credential status/revocation, witnesses, and pre-rotation recovery are not implemented.
- VC/VP transport uses direct REST and JWT, not OID4VCI or OID4VP.
- Resolution is limited to logs stored by this server and does not fetch arbitrary WebVH hosts.
- The PoC combines the WebVH update key and holder authentication key. Production deployments should separate their custody and rotation policies.

## References

### Standards and specifications

- [`did:webvh` DID Method Specification v1.0](https://identity.foundation/didwebvh/v1.0/)
- [`did:webvh` specification source repository](https://github.com/decentralized-identity/didwebvh)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/)
- [W3C Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/2025/REC-vc-jose-cose-20250515/)
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/2025/REC-cid-1.0-20250515/)
- [W3C Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/2025/REC-vc-di-eddsa-20250515/)

### Implementation libraries

- [`didwebvh-ts` 2.8.0](https://github.com/decentralized-identity/didwebvh-ts) — WebVH DID creation, update, and log resolution
- [`jose` 6.2.3](https://github.com/panva/jose) — JWT/JWS/JWK signing and verification
- [`@noble/curves` 2.2.0](https://github.com/paulmillr/noble-curves) — Ed25519 key generation and signatures
- [`fastify` 5.10.0](https://github.com/fastify/fastify) — HTTP server and API routes

## License

Released under the permissive [Zero-Clause BSD license](./LICENSE).
