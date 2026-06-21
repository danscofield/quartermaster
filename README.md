# Quartermaster

An identity federation broker that introduces **billets** — an intermediate authorization abstraction between identity and cloud IAM. Workloads and humans prove their identity through any supported source, Quartermaster evaluates Cedar policies to determine which billets they hold, and issues signed JWTs and X.509 certificates for cross-cloud role assumption and mTLS.

## Key Concepts

- **Billet**: A named authorization role. Workloads and humans can hold multiple billets simultaneously. Billets are the unit of authorization — they decouple identity from cloud-specific role bindings.
- **Cedar Policies**: Billet assignment is governed by [Cedar](https://www.cedarpolicy.com/) policies evaluated locally. Policies can condition on workload selectors, IdP group claims, cloud account IDs, tags, and more.
- **Guardrails**: Global `forbid` policies that enforce invariants (e.g., "no workload can hold a human-only billet"). Cedar's deny-overrides semantics make these inviolable.
- **Multi-Source Identity**: Accepts SPIRE SVIDs, corporate OIDC tokens (Okta, Azure AD), AWS presigned STS, and GCP identity tokens — all evaluated through the same policy engine.

## Architecture

```
Identity Sources                Quartermaster                    Cloud IAM
┌──────────────┐               ┌──────────────────────┐        ┌─────────────┐
│ SPIRE SVID   │──┐            │                      │        │ AWS Roles   │
│ Okta OIDC    │──┤  POST      │ Validate → Cedar     │  JWT   │ (OIDC       │
│ AWS STS      │──┼──/token───▶│ Eval → Issue JWT +   │───────▶│  federation)│
│ GCP Identity │──┘            │ Cert                 │        │ GCP SAs     │
└──────────────┘               │                      │        └─────────────┘
                               │ /.well-known/oidc    │
                               │ /jwks.json           │
                               │ /ca/chain.pem        │
                               └──────────────────────┘
```

## Features

- **Unified billet resolution** — one Cedar policy engine for all identity sources
- **Cross-cloud role assumption** — issued JWTs work with AWS `AssumeRoleWithWebIdentity` and GCP Workload Identity Federation
- **mTLS certificates** — short-lived certs with billets encoded as URI SANs for billet-gated mTLS
- **Scoped admin authorization** — per-billet admin access, governed by the same Cedar engine (dogfooding)
- **Implicit billet mapping** — optionally map IdP group claims to prefixed billets without writing policies
- **Billet tags** — attach metadata to billets for category-based guardrail policies
- **Pluggable backends** — DynamoDB or Firestore for storage, KMS-delegated ephemeral keys for signing
- **Audit logging** — structured events with pluggable sinks (stdout, file, Kinesis Firehose, GCP Pub/Sub)

## How It Works

1. A workload (or human) presents an identity token to `POST /token`
2. Quartermaster validates the token against the appropriate source (SPIRE JWKS, IdP JWKS, presigned STS call, etc.)
3. Cedar policies are evaluated locally to determine which billets the caller holds
4. A signed JWT (and optionally an X.509 certificate) is issued containing the resolved billets
5. The workload uses the JWT to assume cloud IAM roles or the cert for mTLS

## Quick Start

```bash
# Generate signing and CA keys
openssl ecparam -genkey -name prime256v1 -noout -out signing.pem
openssl ecparam -genkey -name prime256v1 -noout -out ca.key.pem
openssl req -new -x509 -key ca.key.pem -out ca.cert.pem -days 365 -subj "/CN=Quartermaster CA"

# Configure (see config.example.toml)
export QUARTERMASTER_CONFIG=./config.toml

# Run
cargo run
```

## Configuration

See [`config.example.toml`](config.example.toml) for a full configuration reference. Key sections:

```toml
[quartermaster]
issuer = "https://quartermaster.example.com"
token_ttl = "1h"

[datastore]
backend = "dynamodb"  # or "firestore"

[signing]
backend = "memory"  # or "kms_delegated"

[identity.spire]
trust_domain = "example.com"

[[identity.oidc]]
prefix = "okta"
issuer = "https://mycompany.okta.com/oauth2/default"

[[audit.sinks]]
type = "stdout"
```

## Admin API

Policies are nested under billets:

```
POST   /admin/billets                          # create billet
GET    /admin/billets                          # list billets
GET    /admin/billets/{name}                   # get billet + policies
PUT    /admin/billets/{name}                   # update metadata
DELETE /admin/billets/{name}                   # cascade delete

POST   /admin/billets/{name}/policies          # attach policy
GET    /admin/billets/{name}/policies          # list policies
PUT    /admin/billets/{name}/policies/{id}     # update policy
DELETE /admin/billets/{name}/policies/{id}     # delete policy
```

All admin operations are authorized via Cedar — the caller's billets are evaluated as principals against the target billet as resource.

## Cedar Policy Examples

```cedar
// Workloads in the finance namespace get billing-writer
permit(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"billing-writer"
) when {
    context.selectors.contains("k8s:ns:finance")
};

// Humans in the billing-ops Okta group get billing-writer
permit(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource == Quartermaster::Billet::"billing-writer"
) when {
    context.source_type == "oidc" &&
    principal.groups.contains("billing-ops")
};

// Guardrail: no workload can hold a human-only billet
forbid(
    principal,
    action == Quartermaster::Action::"assumeBillet",
    resource
) when {
    context.source_type == "spire" &&
    resource.tags.contains("human-only")
};
```

## Cloud IAM Integration

### AWS

```bash
# Register Quartermaster as OIDC provider
aws iam create-open-id-connect-provider \
  --url https://quartermaster.example.com \
  --client-id-list sts.amazonaws.com

# IAM role trust policy conditions on billets
"Condition": {
  "ForAnyValue:StringEquals": {
    "quartermaster.example.com:billets": "billing-writer"
  }
}
```

### GCP

```bash
# Workload Identity Federation pool
gcloud iam workload-identity-pools providers create-oidc quartermaster \
  --issuer-uri="https://quartermaster.example.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.billets=assertion.billets"
```

## Project Structure

```
src/
  domain/          # Core business logic (identity, billet resolution, token/cert issuance)
  cedar/           # Local Cedar policy evaluator
  handler/         # HTTP handlers (axum)
  server/          # Server setup, middleware
  dynamo/          # DataStore implementation (DynamoDB)
  sync/            # PolicySyncService (background data refresh)
  signing/         # KeyManager implementations
  oidc/            # OIDC discovery document builder
  config/          # Configuration loading
```

## Specs

Design specifications are in `.kiro/specs/`:

| Spec | Description |
|------|-------------|
| `quartermaster/` | Core system — token exchange, Cedar eval, cert issuance |
| `nested-billets/` | Policies nested under billets, cascade delete, scoped admin |
| `multi-source-identity/` | Pluggable identity sources, implicit billet mapping |
| `guardrails/` | Billet tags, global forbid policies |
| `audit-logging/` | Structured events, pluggable sinks |
| `cross-cloud-backends/` | DataStore + KeyManager abstraction (AWS/GCP portable) |

## License

[TBD]
