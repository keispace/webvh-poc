# did:webvh VC/VP PoC

[English](./README.md)

`did:webvh` DID 생성·공개·조회·회전, W3C VC Data Model 2.0 JWT VC 발급, challenge 기반 JWT VP 제출·검증을 확인하는 독립 PoC 서버입니다.

Embedded holder, issuer, verifier, JSONL log host, 단계별 Console과 Swagger 스타일의 same-origin API Explorer를 한 프로젝트에 포함합니다.

## 확인 범위

- Holder DID: `did:webvh:{SCID}:example.com:{SS58(initial-public-key)}`
- Issuer DID: `did:webvh:{SCID}:example.com:issuer:poc`
- DID log URL: `https://example.com/{SS58(initial-public-key)}/did.jsonl`
- `eddsa-jcs-2022` proof와 hash chain을 사용하는 `did:webvh` v1.0 history 검증
- Key-first 생성: Ed25519 key 생성 후 one-time `keyId`를 DID genesis에서 소비
- Issuer `assertionMethod`로 서명한 VCDM 2.0 Ed25519 `vc+jwt` 발급
- Holder `authentication` method로 서명한 VCDM 2.0 Ed25519 `vp+jwt` 제출
- DID log, JWT signature, expiry, audience, nonce, replay 및 VC subject/VP holder binding 검증
- Active public key와 verification-method fragment를 변경하면서 DID, SCID, 최초 키 기반 path를 유지하는 key rotation

마지막 path segment는 `did:webvh` 표준 요구사항이 아니라 이 PoC에서 정한 규칙입니다. 최초 Ed25519 공개키를 generic SS58 prefix `42`로 인코딩하며 rotation 이후에도 유지합니다.

## VC/VP 프로파일

VC/VP 흐름은 W3C VC Data Model 2.0과 Securing Verifiable Credentials using JOSE and COSE를 따릅니다.

- VC와 VP 속성을 JWT Claims Set 최상위에 배치하며 기존 `vc`, `vp` 중첩 claim은 사용하지 않습니다.
- Protected header는 `typ=vc+jwt, cty=vc`와 `typ=vp+jwt, cty=vp`를 사용합니다.
- DID Document의 authentication/assertion method는 Ed25519 `publicKeyJwk`를 가진 `JsonWebKey`로 표현합니다. WebVH update authorization은 DID method가 요구하는 Multikey를 계속 사용합니다.
- VP 내부의 보안 처리된 VC는 `data:application/vc+jwt,...` URL을 가진 `EnvelopedVerifiableCredential`로 표현합니다.
- VC 유효기간은 `validFrom`, `validUntil`로, JWT 서명 유효기간은 `iat`, `exp`로 표현합니다.
- 목업 credential type과 임의 subject claim에는 표준 fallback context인 `https://www.w3.org/ns/credentials/undefined-terms/v2`를 사용합니다. 실제 상호운용 credential에서는 이를 공개된 안정적 application vocabulary/context로 교체해야 합니다.

## 화면

서버 실행 후 다음 주소를 엽니다.

- [http://127.0.0.1:3010/](http://127.0.0.1:3010/) — DID, VC, VP, rotation 단계별 Console
- [http://127.0.0.1:3010/api-doc](http://127.0.0.1:3010/api-doc) — API 설명, 요청/응답 예제, 요청 편집 및 직접 호출

API Explorer는 응답의 `keyId`, holder DID, credential JWT, challenge ID, presentation JWT를 브라우저 메모리에서 다음 요청에 연결합니다. `권장 E2E 호출` 버튼은 key → DID → VC → VP → rotation 전체 흐름을 실행합니다.

## 실행

Node.js 22 이상이 필요합니다.

```bash
npm install
npm run check
npm test
npm run build
npm run demo
npm run dev
```

기본 주소는 `http://127.0.0.1:3010`입니다. `npm run demo`는 Fastify injection으로 전체 흐름을 실행하고 실제 JWT와 검증 결과를 출력합니다.

## Docker

Docker는 선택 사항입니다. Host에 Node.js를 직접 설치하지 않아도 같은 Node.js 및 production dependency 환경에서 PoC를 재현할 수 있도록 제공합니다.

```bash
docker build -t webvh-poc .
docker run --rm -p 3010:3010 webvh-poc
```

Container는 `0.0.0.0:3010`에서 수신합니다. 실행 후 `http://127.0.0.1:3010`을 엽니다. `-p 3010:3010`의 첫 번째 `3010`은 host port이므로 `-p 8080:3010`으로 실행하면 `http://127.0.0.1:8080`에서 접근할 수 있습니다.

Issuer/holder private state는 container의 `/app/.data`에 기록됩니다. Volume 없이 `--rm`으로 실행하면 container 제거 시 함께 없어지며, 명시적으로 유지하려면 다음처럼 volume을 사용합니다.

```bash
docker run --rm -p 3010:3010 -v webvh-poc-data:/app/.data webvh-poc
```

## API

| Method | Path | 역할 |
| --- | --- | --- |
| `GET` | `/`, `/viewer` | 단계별 PoC Console |
| `GET` | `/api-doc` | 전체 요청/응답 설명과 shared-context API Explorer |
| `GET` | `/health` | 서버 및 issuer 상태 확인 |
| `GET` | `/api/issuer` | Issuer DID와 현재 public document 조회 |
| `POST` | `/api/keys` | Ed25519 holder key, private/public JWK, SS58 path와 one-time `keyId` 생성 |
| `GET` | `/api/dids` | 저장된 identity public projection 조회 |
| `POST` | `/api/dids` | `keyId`를 소비해 holder WebVH genesis 생성 |
| `GET` | `/api/dids/resolve?did=...` | 저장된 DID history 조회·검증 |
| `POST` | `/api/dids/validate` | Client가 보낸 DID log 검증 |
| `POST` | `/api/dids/rotate` | Holder update/authentication key 회전 |
| `GET` | `/:ss58/did.jsonl` | Public holder DID log 제공 |
| `GET` | `/issuer/:slug/did.jsonl` | Public issuer DID log 제공 |
| `POST` | `/api/credentials` | `WebVHExampleCredential` 발급 |
| `POST` | `/api/credentials/verify` | VC 단독 검증 |
| `POST` | `/api/presentations/challenges` | Audience/nonce challenge 생성 |
| `POST` | `/api/presentations` | Holder-signed VP 생성 |
| `POST` | `/api/verifications` | VP 검증 및 challenge 소비 |
| `POST` | `/api/demo/run` | 전체 흐름을 한 요청으로 실행 |

## 수동 호출 예시

Holder key를 생성합니다.

```bash
curl -sS -X POST http://127.0.0.1:3010/api/keys
```

응답의 `keyId`로 DID를 생성합니다.

```bash
curl -sS http://127.0.0.1:3010/api/dids \
  -H 'content-type: application/json' \
  -d '{"keyId":"<pending-key-id>"}'
```

응답의 DID로 VC를 발급합니다.

```bash
curl -sS http://127.0.0.1:3010/api/credentials \
  -H 'content-type: application/json' \
  -d '{"holderDid":"<holder-did>","claims":{"name":"Alice","status":"active"}}'
```

이후 `/api/presentations/challenges` → `/api/presentations` → `/api/verifications` 순서로 호출합니다. 전체 결과는 `POST /api/demo/run`으로 확인할 수 있습니다.

## 설정

애플리케이션은 process environment를 읽으며 `.env` 파일을 자동으로 로드하지 않습니다.

- `HOST`: bind host, 기본 `127.0.0.1`
- `PORT`: bind port, 기본 `3010`
- `DID_DOMAIN`: DID에 들어갈 DNS hostname, 기본 `example.com`
- `DATA_DIR`: private key와 DID log 저장 위치, 기본 `.data/{DID_DOMAIN}`
- `ISSUER_SLUG`: issuer path slug, 기본 `poc`
- `VERIFIER_AUDIENCE`: VP audience exact match, 기본 `https://example.com/verifier`
- `CHALLENGE_TTL_SECONDS`: challenge 유효기간
- `VC_TTL_SECONDS`: VC 유효기간

Public resolution에는 다음 경로를 제공하는 TLS/reverse proxy가 필요합니다.

```text
https://example.com/*/did.jsonl
https://example.com/issuer/*/did.jsonl
```

`example.com`은 문서용 도메인이므로 public resolution을 시험할 때는 소유한 hostname으로 교체해야 합니다.

## 보안 및 범위 제한

이 서버는 상호운용성 확인용 PoC이며 production identity service가 아닙니다.

- `POST /api/keys`와 두 UI는 key 흐름 관찰을 위해 private JWK를 평문으로 반환·표시합니다. 격리된 PoC 밖에서는 반드시 제거해야 합니다.
- 새로 만든 pending holder key는 최대 10분간 메모리에만 있습니다. DID 생성에 사용된 이후에는 active issuer/holder private key와 DID history가 `DATA_DIR` 아래 mode `0600` file로 저장되며 암호화나 KMS/HSM 보호는 없습니다.
- Holder가 서버에 내장되어 호출자를 대신해 VP를 서명하므로 wallet 구조가 아닙니다.
- 등록 API에 authentication, authorization, rate limit, audit log가 없습니다.
- Key recovery, credential status/revocation, witness, pre-rotation recovery를 구현하지 않습니다.
- VC/VP는 직접 REST와 JWT로 전달하며 OID4VCI/OID4VP 방식이 아닙니다.
- 이 서버가 저장한 DID log만 resolve하며 외부의 임의 WebVH host를 fetch하지 않습니다.
- PoC는 WebVH update key와 holder authentication key를 함께 사용합니다. Production에서는 custody와 rotation 정책을 분리해야 합니다.

## 참고 자료

### 표준 및 사양

- [`did:webvh` DID Method Specification v1.0](https://identity.foundation/didwebvh/v1.0/)
- [`did:webvh` specification source repository](https://github.com/decentralized-identity/didwebvh)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/)
- [W3C Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/2025/REC-vc-jose-cose-20250515/)
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/2025/REC-cid-1.0-20250515/)
- [W3C Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/2025/REC-vc-di-eddsa-20250515/)

### 구현 라이브러리

- [`didwebvh-ts` 2.8.0](https://github.com/decentralized-identity/didwebvh-ts) — WebVH DID 생성·업데이트·log resolution
- [`jose` 6.2.3](https://github.com/panva/jose) — JWT/JWS/JWK 서명 및 검증
- [`@noble/curves` 2.2.0](https://github.com/paulmillr/noble-curves) — Ed25519 키 생성 및 서명
- [`fastify` 5.10.0](https://github.com/fastify/fastify) — HTTP 서버 및 API route

## 라이선스

제약이 매우 적은 [Zero-Clause BSD 라이선스](./LICENSE)로 공개합니다.
