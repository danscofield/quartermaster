# Quartermaster — Workload Identity Federation Broker

**Version:** 0.1.0-draft
**Date:** 2026-06-19

## 1. Overview

Quartermaster is a workload identity federation broker that sits between platform-native attestation (SPIRE) and cloud provider IAM systems. It introduces **billets** — an intermediate authorization abstraction that decouples workload identity from cloud role assignment.

A workload proves its identity via SPIRE, Quartermaster evaluates Cedar policies (via Amazon Verified Permissions) to determine which billets the workload holds, and issues a signed JWT containing those billets. Cloud providers trust Quartermaster as an OIDC IdP, enabling workloads to assume roles across any cloud using a single token.

### 1.1 Goals

- Provide a single trust root for cross-cloud workload identity
- Decouple workload identity from cloud-specific role bindings
- Enable policy-as-code billet assignment with formal verification
- Minimize operational overhead by leveraging SPIRE and AVP as managed/established components

### 1.2 Non-Goals

- User (human) identity management
- Secrets management or credential vaulting
- Replacing SPIRE's attestation or key management

---

## 2. Concepts

### 2.1 Workload

A running process or service instance that holds a SPIFFE identity (SVID) issued by SPIRE. Identified by a SPIFFE ID, e.g. `spiffe://example.com/ns/finance/workload/payments`.

### 2.2 Billet

A named authorization role within Quartermaster's domain. Billets are the unit of authorization — they represent a "post" or "position" that a workload can be assigned to. A workload may hold zero or more billets simultaneously.

Examples: `billing-writer`, `audit-reader`, `prod-deployer`, `incident-escalation`.

Billets are **not** cloud IAM roles. They are an abstraction layer that maps to one or more cloud IAM roles via trust policy conditions.

### 2.3 Billet Policy

A Cedar policy evaluated by Amazon Verified Permissions that determines whether a workload may assume a given billet. Policies can reference workload attributes, namespace groupings, and contextual signals.

### 2.4 Quartermaster Credentials

Quartermaster issues two credential types per token exchange, enabling both bearer-token and mTLS use cases:

- **Quartermaster JWT** — A short-lived signed JWT containing the workload's identity and resolved billets. Used for cloud provider role assumption (OIDC federation) and service-to-service authorization where JWTs are expected.

- **Quartermaster Certificate** — A short-lived X.509 certificate encoding the workload's SPIFFE ID and billets. Used for mTLS between workloads, where the billet information is embedded in the certificate's URI SANs and custom extensions. Quartermaster acts as a subordinate CA (or delegates to an upstream CA like SPIRE's CA or AWS Private CA).

Both credentials share the same billet resolution — a single AVP evaluation produces both artifacts.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Quartermaster                                    │
│                                                                          │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │ Token        │    │ Billet Resolver   │    │ OIDC Provider         │  │
│  │ Exchange     │───▶│ (AVP client)      │───▶│ (.well-known, JWKS)   │  │
│  │ Endpoint     │    │                   │    │                       │  │
│  └──────┬───────┘    └──────────────────┘    └───────────────────────┘  │
│         │                                                                │
└─────────┼────────────────────────────────────────────────────────────────┘
          │ validates
          ▼
┌──────────────────┐         ┌──────────────────────────────────────┐
│ SPIRE            │         │ Amazon Verified Permissions           │
│ (attestation,    │         │ (Cedar policy store)                  │
│  SVID issuance)  │         │                                       │
└──────────────────┘         └──────────────────────────────────────┘
```

### 3.1 Components

| Component | Responsibility |
|-----------|---------------|
| **Token Exchange Endpoint** | Accepts SPIRE JWT-SVIDs, validates them, orchestrates billet resolution, issues Quartermaster JWT + certificate |
| **Billet Resolver** | Calls AVP `BatchIsAuthorized` to determine which billets a workload holds |
| **Certificate Authority** | Issues short-lived X.509 certificates embedding workload identity and billets for mTLS |
| **OIDC Provider** | Serves `/.well-known/openid-configuration` and `/jwks.json` so cloud providers can verify Quartermaster tokens |
| **CA Trust Bundle Endpoint** | Serves the Quartermaster CA certificate chain for mTLS peer verification |
| **Signing Key Manager** | Manages JWT signing keys and CA private keys (rotation, JWKS publication) |
| **Cache** | Short-lived cache of billet resolution results, keyed by workload SPIFFE ID, TTL = token lifetime |

### 3.2 External Dependencies

| Dependency | Role |
|------------|------|
| **SPIRE** | Workload attestation, SVID issuance, trust bundle management |
| **Amazon Verified Permissions** | Cedar policy evaluation for billet assignment |
| **Cloud IAM** (AWS, GCP, etc.) | Consumes Quartermaster tokens as a trusted OIDC IdP |

---

## 4. Data Model

### 4.1 AVP Schema (Cedar Entity Types)

```cedar
namespace Quartermaster {
    entity Workload = {
        spiffe_id: String,
        namespace: String,
        service: String,
        environment: String,
        labels: Set<String>,
    };

    entity Namespace in [Namespace] = {
        name: String,
    };

    entity Billet = {
        name: String,
        description: String,
        max_holders: Long,       // optional: cap concurrent holders
    };

    action assumeBillet appliesTo {
        principal: [Workload],
        resource: [Billet],
        context: {
            request_time: String,
            source_cloud: String,
            incident_active: Bool,
        }
    };
}
```

### 4.2 Quartermaster Token (JWT Claims)

```json
{
  "iss": "https://quartermaster.example.com",
  "sub": "spiffe://example.com/ns/finance/workload/payments",
  "aud": "sts.amazonaws.com",
  "billets": ["billing-writer", "audit-reader"],
  "iat": 1750370000,
  "exp": 1750370300,
  "jti": "unique-token-id"
}
```

| Claim | Description |
|-------|-------------|
| `iss` | Quartermaster's issuer URL (must match OIDC discovery) |
| `sub` | The workload's SPIFFE ID |
| `aud` | Target audience (cloud STS endpoint or service) |
| `billets` | Array of billet names the workload currently holds |
| `iat` / `exp` | Issued-at and expiry (short-lived, e.g. 5 minutes) |
| `jti` | Unique token identifier for audit/replay prevention |

### 4.3 Quartermaster Certificate (X.509)

Issued alongside the JWT for mTLS use cases.

```
Certificate:
    Subject: CN=spiffe://example.com/ns/finance/workload/payments
    Issuer:  CN=Quartermaster CA, O=example.com
    Validity:
        Not Before: 2026-06-19T21:00:00Z
        Not After:  2026-06-19T21:05:00Z
    Subject Alternative Names:
        URI: spiffe://example.com/ns/finance/workload/payments
        URI: qm-billet://example.com/billing-writer
        URI: qm-billet://example.com/audit-reader
    X509v3 Extensions:
        X509v3 Key Usage: Digital Signature, Key Encipherment
        X509v3 Extended Key Usage: TLS Client Authentication, TLS Server Authentication
        Quartermaster Billets (OID 1.3.6.1.4.1.XXXXX.1):
            billing-writer, audit-reader
```

| Field | Description |
|-------|-------------|
| Subject CN | Workload's SPIFFE ID |
| URI SANs | SPIFFE ID + one `qm-billet://` URI per billet |
| Billet extension | Custom X.509 extension with ASN.1-encoded billet list (for parsers that don't inspect SANs) |
| Validity | Matches JWT TTL (default 5 minutes) |
| Key Usage | Client and server auth for bidirectional mTLS |

**Trust chain:** Workload cert → Quartermaster intermediate CA → SPIRE root CA (or standalone Quartermaster root).

### 4.4 OIDC Discovery Document

`GET https://quartermaster.example.com/.well-known/openid-configuration`

```json
{
  "issuer": "https://quartermaster.example.com",
  "jwks_uri": "https://quartermaster.example.com/jwks.json",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "billets", "jti"]
}
```

---

## 5. Flows

### 5.1 Token Exchange (Primary Flow)

```
Workload                    Quartermaster                    AVP
   │                              │                           │
   │─── POST /token ──────────────▶                           │
   │    (grant_type=token-exchange,                           │
   │     subject_token=<JWT-SVID>,                            │
   │     audience=sts.amazonaws.com,                          │
   │     csr=<optional PKCS#10>)                              │
   │                              │                           │
   │                              │── validate SVID ──────────│
   │                              │   (verify sig via SPIRE   │
   │                              │    trust bundle)           │
   │                              │                           │
   │                              │── cache lookup ───────────│
   │                              │   (hit? skip to sign)     │
   │                              │                           │
   │                              │── BatchIsAuthorized ──────▶
   │                              │   principal: workload     │
   │                              │   action: assumeBillet    │
   │                              │   resources: [all billets]│
   │                              │                           │
   │                              │◀── decisions ─────────────│
   │                              │                           │
   │                              │── sign JWT ───────────────│
   │                              │── sign certificate ───────│
   │                              │   (billets = allowed set) │
   │                              │                           │
   │◀── 200 {access_token,       ─│                           │
   │         certificate_chain}    │                           │
   │                              │                           │
```

### 5.2 Cross-Cloud Role Assumption

```
Workload                    AWS STS                     Quartermaster OIDC
   │                          │                              │
   │─ AssumeRoleWithWebIdentity ▶                            │
   │  (RoleArn=...,            │                             │
   │   WebIdentityToken=QM JWT)│                             │
   │                           │── GET /jwks.json ───────────▶
   │                           │◀── public keys ─────────────│
   │                           │                             │
   │                           │── verify signature          │
   │                           │── check trust policy        │
   │                           │   (billets contains         │
   │                           │    required billet?)         │
   │                           │                             │
   │◀── temporary credentials ─│                             │
```

### 5.4 Service-to-Service mTLS with Billet Verification

```
Workload A                                      Workload B
(holds cert with billet: billing-writer)        (verifies peers)
   │                                                │
   │──── TLS ClientHello ──────────────────────────▶│
   │◀─── TLS ServerHello + server cert ────────────│
   │──── client cert (QM-issued) ─────────────────▶│
   │                                                │
   │                                   verify cert chain against QM CA
   │                                   extract billets from URI SANs
   │                                   check: peer holds required billet?
   │                                                │
   │◀─── TLS established / rejected ───────────────│
```

Workload B's TLS verifier:
1. Validates the certificate chain up to the Quartermaster CA trust anchor
2. Extracts `qm-billet://` URIs from the peer's SAN extension
3. Applies local authorization logic: does the peer hold a billet that grants access to this service?

This enables **billet-gated mTLS** — connections are accepted or rejected based on the peer's billets, not just their identity.

### 5.5 Workload Bootstrap

1. Workload starts on a platform (EKS pod, GCE VM, EC2 instance, etc.)
2. SPIRE agent on the node attests the workload via platform-specific attestor (k8s workload attestor, AWS IID attestor, etc.)
3. Workload receives a JWT-SVID from SPIRE via the Workload API
4. Workload generates an ephemeral key pair and CSR
5. Workload calls Quartermaster's token exchange endpoint with the SVID + CSR
6. Workload receives a Quartermaster JWT (for cloud role assumption) and certificate (for mTLS)

---

## 6. API

### 6.1 POST /token

Token exchange endpoint (modeled on RFC 8693).

**Request:**

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<JWT-SVID>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&audience=sts.amazonaws.com
&csr=<base64-encoded PKCS#10 CSR>
```

The `csr` parameter is optional. If provided, Quartermaster signs a certificate using the workload's public key from the CSR. If omitted, only a JWT is returned.

**Response (200):**

```json
{
  "access_token": "<quartermaster-jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 300,
  "certificate_chain": "<PEM-encoded certificate chain (leaf + intermediate)>",
  "certificate_chain_url": "https://quartermaster.example.com/ca/chain.pem"
}
```

The `certificate_chain` field is present only when a CSR was submitted. It contains the leaf certificate followed by the Quartermaster intermediate CA certificate in PEM format.

**Errors:**

| Code | Condition |
|------|-----------|
| 401 | SVID validation failed (expired, bad signature, unknown trust domain) |
| 403 | Workload holds no billets (all AVP decisions denied) |
| 400 | Malformed request |
| 503 | AVP unavailable, cache miss |

### 6.2 GET /.well-known/openid-configuration

Standard OIDC discovery document. See §4.3.

### 6.3 GET /jwks.json

JSON Web Key Set containing Quartermaster's current (and recently rotated) public signing keys.

### 6.4 GET /ca/chain.pem

Returns the Quartermaster CA certificate chain in PEM format. Workloads use this as the trust anchor for verifying peer certificates during mTLS.

### 6.5 GET /healthz

Health check. Returns 200 if SPIRE trust bundle is loaded and AVP is reachable.

---

## 7. Cedar Policy Examples

### 7.1 Direct Assignment

```cedar
permit(
    principal == Quartermaster::Workload::"spiffe://example.com/ns/finance/workload/payments",
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"billing-writer"
);
```

### 7.2 Namespace-Based Assignment

```cedar
permit(
    principal in Quartermaster::Namespace::"finance",
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"audit-reader"
);
```

### 7.3 Conditional Assignment

```cedar
permit(
    principal == Quartermaster::Workload::"spiffe://example.com/ns/ops/workload/oncall-tool",
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"incident-escalation"
) when {
    context.incident_active == true
};
```

### 7.4 Separation of Duty (Forbid)

```cedar
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"prod-writer"
) when {
    principal in Quartermaster::Namespace::"dev"
};
```

---

## 8. Cloud IAM Integration

### 8.1 AWS

**Register Quartermaster as OIDC provider:**

```bash
aws iam create-open-id-connect-provider \
  --url https://quartermaster.example.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list <tls-cert-thumbprint>
```

**IAM role trust policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/quartermaster.example.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "quartermaster.example.com:aud": "sts.amazonaws.com"
      },
      "ForAnyValue:StringEquals": {
        "quartermaster.example.com:billets": "billing-writer"
      }
    }
  }]
}
```

### 8.2 GCP

**Workload Identity Federation pool:**

```bash
gcloud iam workload-identity-pools create quartermaster-pool \
  --location="global"

gcloud iam workload-identity-pools providers create-oidc quartermaster-provider \
  --location="global" \
  --workload-identity-pool="quartermaster-pool" \
  --issuer-uri="https://quartermaster.example.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.billets=assertion.billets"
```

**Service account binding (conditioned on billet):**

```bash
gcloud iam service-accounts add-iam-policy-binding \
  billing-sa@project.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT/locations/global/workloadIdentityPools/quartermaster-pool/attribute.billets/billing-writer"
```

---

## 9. Security Considerations

### 9.1 Token Lifetime

Quartermaster tokens MUST be short-lived (default: 5 minutes). This bounds the blast radius of a leaked token and limits the window where a revoked billet is still usable.

### 9.2 Audience Binding

Tokens MUST include an `aud` claim scoped to the target cloud's STS endpoint. Quartermaster MUST NOT issue tokens with wildcard or multi-audience claims to prevent token relay attacks.

### 9.3 Key Rotation

Signing keys SHOULD be rotated on a regular cadence (e.g., every 24 hours). The JWKS endpoint MUST serve both the current and previous key to allow for propagation delay.

### 9.4 SVID Validation

Quartermaster MUST validate incoming SVIDs against the SPIRE trust bundle, including:
- Signature verification
- Expiry check
- Issuer (trust domain) check
- Audience check (SVID audience should be Quartermaster)

### 9.5 Billet Resolution Integrity

AVP policy evaluation results MUST NOT be cached beyond the issued token's lifetime. Cache keys MUST include the full SPIFFE ID and any context parameters that affect policy evaluation.

### 9.6 Denial-of-Service

Rate-limit the `/token` endpoint per SPIFFE ID to prevent a compromised workload from exhausting AVP quota.

### 9.7 Audit

All token issuance events MUST be logged with: SPIFFE ID, resolved billets, target audience, timestamp, and JTI. AVP provides its own decision audit trail.

### 9.8 Certificate Authority Security

- Quartermaster's CA private key MUST be stored in an HSM or cloud KMS (never on disk in plaintext).
- The CA SHOULD operate as a subordinate/intermediate CA, with the root held offline or in SPIRE's upstream CA.
- Issued certificates MUST have a validity period equal to the JWT TTL (default 5 minutes). No long-lived certificates.
- CSR validation: Quartermaster MUST ignore the Subject and SANs in the submitted CSR and populate them from the authenticated SPIFFE ID and resolved billets. The CSR only contributes the public key.
- Certificate serial numbers MUST be cryptographically random to prevent predictability attacks.

### 9.9 mTLS Trust Distribution

- Workloads obtain the Quartermaster CA trust bundle from `GET /ca/chain.pem` or via a sidecar/init container.
- Trust bundle rotation: serve overlapping CA certs during rotation windows (same pattern as JWKS).

---

## 10. Deployment

### 10.1 Topology

```
┌─────────────────────────────────────────────────────┐
│ Kubernetes Cluster (or VM fleet)                     │
│                                                      │
│  ┌─────────────┐   ┌─────────────────────────────┐  │
│  │ SPIRE       │   │ Quartermaster               │  │
│  │ Server      │   │ (Deployment, 2+ replicas)   │  │
│  └─────────────┘   └─────────────────────────────┘  │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │ SPIRE Agents (DaemonSet / per-node)             │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Workloads                                        │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
          │                          │
          │ SPIRE Federation         │ HTTPS
          ▼                          ▼
  ┌──────────────┐         ┌─────────────────────┐
  │ Other SPIRE  │         │ AWS / GCP IAM       │
  │ trust domains│         │ (OIDC federation)   │
  └──────────────┘         └─────────────────────┘
```

### 10.2 Quartermaster Service Requirements

- **Stateless** — all state lives in SPIRE (trust bundles) and AVP (policies). Cache is ephemeral.
- **High availability** — run 2+ replicas behind a load balancer. All replicas share the same signing key (stored in AWS KMS, GCP Cloud KMS, or a SPIRE-issued X.509).
- **Public OIDC endpoint** — `/.well-known/openid-configuration` and `/jwks.json` must be reachable by cloud provider STS services (public internet or via VPC endpoints with appropriate routing).
- **Private token endpoint** — `/token` should only be reachable from within the workload network.

### 10.3 Configuration

```yaml
quartermaster:
  issuer: "https://quartermaster.example.com"
  token_ttl: 300  # seconds

  spire:
    trust_domain: "example.com"
    workload_api_socket: "/run/spire/agent/sockets/api.sock"

  avp:
    policy_store_id: "ps-xxxxxxxx"
    region: "us-east-1"
    # Quartermaster uses its own SPIRE identity to auth to AVP via IRSA/pod identity

  signing:
    algorithm: "ES256"
    key_rotation_interval: "24h"
    kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/..."

  ca:
    backend: "kms"  # "kms", "local" (prototype only), or "aws-pca"
    kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/ca-key-..."
    issuer_cn: "Quartermaster CA"
    cert_ttl: 300  # matches token_ttl
    # For aws-pca backend:
    # pca_arn: "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/..."

  cache:
    backend: "memory"  # or "redis" for multi-replica consistency
    ttl: 300  # matches token_ttl

  rate_limit:
    per_workload: 10  # requests per minute per SPIFFE ID
```

---

## 11. Prototype Scope

For the initial prototype, implement:

1. **Token exchange endpoint** (`POST /token`) — validate SVID, call AVP, sign and return JWT + optional certificate
2. **OIDC discovery** (`GET /.well-known/openid-configuration`, `GET /jwks.json`)
3. **CA trust bundle** (`GET /ca/chain.pem`)
4. **Certificate issuance** — local in-memory CA, sign certs with billets in URI SANs
5. **In-memory cache** — keyed by SPIFFE ID + audience
6. **Static signing key** (defer KMS integration and rotation)
7. **AVP integration** — Cedar schema + sample policies, `BatchIsAuthorized` call
8. **Demo flow** — workload in EKS obtains SVID → exchanges for Quartermaster JWT + cert → assumes AWS role in another account AND establishes mTLS with a peer service

### 11.1 Tech Stack (Prototype)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go | SPIRE ecosystem is Go, good SPIFFE library support |
| SVID validation | `github.com/spiffe/go-spiffe/v2` | Official SPIFFE library |
| AVP client | AWS SDK for Go v2 | Native AVP support |
| HTTP framework | stdlib `net/http` | Minimal dependencies |
| JWT signing | `github.com/go-jose/go-jose/v4` | Well-maintained JOSE library |
| Certificate issuance | stdlib `crypto/x509` | Native X.509 support, no external deps |
| Deployment | Kubernetes (Helm chart) | Co-locate with SPIRE |

---

## 12. Future Considerations

- **Billet quotas** — Cedar policies referencing `max_holders` to enforce concurrent holder limits
- **Token revocation** — publish a revocation list or integrate with cloud provider token revocation
- **CRL / OCSP** — certificate revocation for mTLS (short TTL makes this less critical but useful for immediate revocation)
- **AWS Private CA backend** — delegate certificate signing to ACM PCA for HSM-grade key protection
- **Multi-region** — replicate signing keys and OIDC endpoints across regions
- **Observability** — OpenTelemetry traces for the full token exchange flow
- **CLI tooling** — `qm billets list`, `qm token exchange`, `qm policy simulate`
- **SPIRE plugin** — implement as a SPIRE credential composer plugin to embed billets directly in SVIDs (eliminating the separate exchange step)
- **Envoy integration** — SDS (Secret Discovery Service) provider so Envoy sidecars can fetch Quartermaster certs automatically for mesh-wide billet-gated mTLS
